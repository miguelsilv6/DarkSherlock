"""
Home.py — Página principal da aplicação DarkSherlock.

Este módulo constitui o ponto de entrada da interface Streamlit do DarkSherlock,
uma ferramenta de OSINT (Open Source Intelligence) orientada para a dark web,
desenvolvida no âmbito de uma dissertação de Mestrado em Cibersegurança.

A aplicação orquestra um pipeline de seis etapas para responder a consultas
sobre conteúdo da dark web:

    1. Carregamento do modelo de linguagem (LLM) selecionado pelo utilizador.
    2. Refinamento automático da pesquisa com recurso ao LLM.
    3. Pesquisa distribuída em múltiplos motores da dark web via proxy Tor.
    4. Filtragem por relevância dos resultados brutos, também com o LLM.
    5. Extração (scraping) do conteúdo das páginas mais relevantes.
    6. Geração de um relatório de inteligência em modo de streaming.

As investigações concluídas são guardadas em disco (pasta `investigations/`)
em formato JSON, permitindo ao utilizador recarregá-las sem repetir o pipeline.

Dependências principais:
    - Streamlit  : framework de interface web.
    - LangChain  : abstração sobre múltiplos fornecedores de LLM.
    - Tor proxy  : necessário para aceder a domínios .onion.
"""

import json
import re
import streamlit as st
import pipeline
import settings_state
from datetime import datetime, timezone
from pathlib import Path
from llm_utils import get_model_choices
from report import generate_forensic_pdf, investigation_pdf_data
from ui_pipeline import complete_dict, run_with_ui
from audit import log_investigation, setup_file_logging

# Configura o logging para ficheiro (captura debug/info de todos os módulos)
setup_file_logging()
from health import check_search_engines, check_tor_proxy
from ui_theme import inject_theme


# ---------------------------------------------------------------------------
# Utilitários de formatação
# ---------------------------------------------------------------------------

def _fmt_ms(ms: int) -> str:
    """Formata uma duração em milissegundos numa cadeia de texto legível.

    Converte milissegundos para o formato "XmYYs" quando a duração é igual
    ou superior a um minuto, "Xs" quando é inferior a um minuto mas igual ou
    superior a um segundo, ou "Xms" para durações abaixo de um segundo.
    Esta função é utilizada em todas as etiquetas de estado do pipeline para
    mostrar ao utilizador o tempo gasto em cada fase.

    Args:
        ms: Duração em milissegundos.

    Returns:
        Cadeia formatada, por exemplo "1m03s", "45s" ou "780ms".
    """
    total_s = ms // 1000
    m, s = divmod(total_s, 60)
    if m > 0:
        return f"{m}m{s:02d}s"
    return f"{total_s}s" if total_s >= 1 else f"{ms}ms"


# ---------------------------------------------------------------------------
# Tratamento de erros do pipeline
# ---------------------------------------------------------------------------

def _render_pipeline_error(stage: str, err: Exception) -> None:
    """Apresenta uma mensagem de erro estruturada ao utilizador e interrompe a execução.

    Quando qualquer etapa do pipeline falha, esta função é invocada para:
      1. Exibir o erro original e sugestões de diagnóstico contextuais.
      2. Chamar `st.stop()`, que encerra imediatamente o restante processamento
         da página — evitando que etapas subsequentes tentem correr com dados
         inválidos ou ausentes.

    As dicas de diagnóstico são escolhidas com base em palavras-chave presentes
    na mensagem de erro, identificando o fornecedor de LLM mais provável que
    originou o problema (Anthropic, OpenRouter, OpenAI ou Google).

    Args:
        stage: Descrição textual da etapa que falhou (usada na mensagem de erro).
        err:   Excepção capturada durante a execução da etapa.
    """
    # Normaliza a mensagem de erro; sanitiza tokens/credenciais antes de mostrar.
    raw_message = str(err).strip() or err.__class__.__name__
    message = _scrub_secrets(raw_message)

    # Dicas de diagnóstico — o projecto suporta apenas Ollama local. Outras
    # providers podem ser reintroduzidos no futuro via llm_utils.resolve_model_config.
    hints = [
        "- Ensure Ollama is running: `ollama serve` (default: http://localhost:11434).",
        "- Confirm `OLLAMA_BASE_URL` is set in `.env` and matches the running daemon.",
        "- Pull the model first: `ollama pull <model-name>`.",
        "- Restart the app after updating `.env` so the new values are picked up.",
    ]

    # Mostra o painel de erro na interface e interrompe o pipeline
    st.error(
        "Failed to {}.\n\nError: {}\n\n{}".format(
            stage,
            message,
            "\n".join(hints),
        )
    )
    st.stop()


# ---------------------------------------------------------------------------
# Sanitização de credenciais em mensagens de erro
# ---------------------------------------------------------------------------

# Padrões de credenciais que podem aparecer em str(exception) de bibliotecas
# HTTP (requests, urllib3, langchain). Capturamos por prefixo + valor.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9_\-\.=]+"),
    re.compile(r"(?i)(api[_-]?key[=:\s]+)[\"']?[A-Za-z0-9_\-]+[\"']?"),
    re.compile(r"(?i)(authorization[=:\s]+)[\"']?[^\s\"'&]+[\"']?"),
    re.compile(r"(?i)(password[=:\s]+)[\"']?[^\s\"'&]+[\"']?"),
    re.compile(r"(?i)(token[=:\s]+)[\"']?[A-Za-z0-9_\-\.]+[\"']?"),
]


def _scrub_secrets(text: str) -> str:
    """Substitui valores de credenciais em mensagens de erro por '***'."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub(r"\1***", text)
    return text


# ---------------------------------------------------------------------------
# Renderização do resultado do pipeline
# ---------------------------------------------------------------------------

def _render_sources_expander(filtered: list, count_label: str | None = None) -> None:
    """Render do expander de Sources com tratamento .onion vs clearnet."""
    title = count_label or f"Sources ({len(filtered)} results)"
    with st.expander(title, expanded=False):
        st.caption("🧅 Links .onion: copia e abre no Tor Browser")
        for i, item in enumerate(filtered, 1):
            link = item.get("link", "")
            title_text = item.get("title", "Untitled")
            if ".onion" in link:
                st.markdown(f"**{i}. {title_text}**")
                st.code(link, language=None)
            else:
                st.markdown(f"{i}. [{title_text}]({link})")


def _render_pipeline_result(
    pc: dict,
    *,
    findings_container=None,
    download_key_prefix: str = "",
) -> None:
    """Renderiza Notes, Sources, Findings e download buttons.

    Centraliza a apresentação para evitar duplicação entre o bloco
    "imediato" (durante o run do pipeline) e o bloco "persistente" (após
    reruns provocados por download_button). Os dois blocos divergiam
    subtilmente nos `key=` dos download buttons; este helper torna isso
    explícito via `download_key_prefix`.

    Args:
        pc: dict com chaves audit_id, query, refined, model, preset_label,
            filtered, results_count, scraped_count, summary, integrity,
            active_engines.
        findings_container: opcional. Se passado, o relatório já está nesse
            container (escrito durante o streaming) e não é repetido. Senão,
            renderiza-o inline.
        download_key_prefix: prefixo para as `key=` dos download buttons,
            necessário para evitar colisão entre múltiplas renderizações.
    """
    # --- Notes ---
    with st.expander("Notes", expanded=False):
        st.markdown(f"**Refined Query:** `{pc['refined']}`")
        st.markdown(f"**Model:** `{pc['model']}` | **Domain:** {pc['preset_label']}")
        st.markdown(
            f"**Results found:** {pc['results_count']} | "
            f"**Filtered to:** {len(pc['filtered'])} | "
            f"**Scraped:** {pc['scraped_count']}"
        )

    # --- Sources ---
    _render_sources_expander(pc["filtered"])

    # --- Findings (markdown) ---
    if findings_container is not None:
        # O relatório já foi escrito neste container durante o streaming (com o
        # texto final); voltar a escrevê-lo aqui duplicava-o no ecrã.
        with findings_container:
            st.divider()
    else:
        st.subheader(":red[Findings]", anchor=None, divider="gray")
        st.markdown(pc["summary"])
        st.divider()

    # --- PDF + Markdown downloads ---
    pdf_data = {
        "audit_id": pc["audit_id"],
        "query": pc["query"],
        "refined_query": pc["refined"],
        "model": pc["model"],
        "preset": pc["preset_label"],
        "timestamp_utc": pc.get("timestamp_utc") or datetime.now(timezone.utc).isoformat(),
        "active_engines": pc["active_engines"],
        "sources": pc["filtered"],
        "integrity": pc["integrity"],
        "summary": pc["summary"],
        "results_found": pc["results_count"],
        "results_scraped": pc["scraped_count"],
        "scraped_content": pc.get("scraped_content", {}),
    }
    pdf_bytes = generate_forensic_pdf(pdf_data)
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    dl1, dl2 = st.columns(2)
    dl1.download_button(
        label="⬇ Download Relatório PDF",
        data=pdf_bytes,
        file_name=f"relatorio_{pc['audit_id'][:8]}_{now}.pdf",
        mime="application/pdf",
        use_container_width=True,
        key=f"{download_key_prefix}dl_pdf" if download_key_prefix else None,
    )
    dl2.download_button(
        label="⬇ Download Summary MD",
        data=pc["summary"].encode(),
        file_name=f"summary_{now}.md",
        mime="text/markdown",
        use_container_width=True,
        key=f"{download_key_prefix}dl_md" if download_key_prefix else None,
    )


# ---------------------------------------------------------------------------
# Persistência de investigações
# ---------------------------------------------------------------------------

# Diretório onde os ficheiros JSON das investigações são guardados em disco.
# O uso de `pathlib.Path` garante compatibilidade entre sistemas operativos.
INVESTIGATIONS_DIR = Path("investigations")


def load_investigations() -> list:
    """Carrega todas as investigações guardadas em disco, ordenadas da mais recente para a mais antiga.

    A ordenação por nome de ficheiro (descendente) equivale a ordenação
    cronológica porque o timestamp faz parte do nome (`investigation_YYYYMMDD_HHMMSS.json`).

    Ficheiros corrompidos ou ilegíveis são silenciosamente ignorados (`continue`),
    para que um único ficheiro inválido não impeça o carregamento dos restantes.

    Returns:
        Lista de dicionários, cada um representando uma investigação guardada.
        A chave `_filename` é acrescentada a cada entrada para permitir
        apresentar o nome do ficheiro na interface sem lógica adicional.
        Devolve uma lista vazia se o diretório não existir ou não contiver
        ficheiros válidos.
    """
    if not INVESTIGATIONS_DIR.exists():
        return []
    # `reverse=True` garante que a investigação mais recente aparece primeiro
    files = sorted(INVESTIGATIONS_DIR.glob("investigation_*.json"), reverse=True)
    investigations = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            # Anexa o nome do ficheiro ao dicionário para uso na barra lateral
            data["_filename"] = f.name
            investigations.append(data)
        except Exception:
            # Ficheiro corrompido ou com JSON inválido — ignorar e continuar
            continue
    return investigations


# ---------------------------------------------------------------------------
# Cache de chamadas dispendiosas ao backend
# ---------------------------------------------------------------------------

# `@st.cache_data` memoriza o resultado da função com base nos seus argumentos.
# `ttl=200` (segundos) limita a validade da cache para evitar resultados
# desatualizados, particularmente importante quando as páginas da dark web
# mudam frequentemente ou o estado do motor de pesquisa se altera.
# `show_spinner=False` delega o feedback visual ao código do pipeline principal.

# Não se guardam em cache pesquisas sem resultados ou com motores em falha, nem
# recolhas com falhas de rede: repetir a investigação deve voltar a tentar. As
# funções devolvem também o detalhe da execução (estado por motor, desfecho por
# página), que de outro modo se perdia num acerto de cache. A hora de recolha de
# cada resultado é a da recolha real, mesmo quando vem da cache.

class _NotCached(Exception):
    """Levantada dentro da função em cache para o Streamlit não guardar o resultado."""

    def __init__(self, value):
        super().__init__("not cached")
        self.value = value


@st.cache_data(ttl=200, show_spinner=False)
def _cached_search(refined_query: str, _threads: int):
    out = pipeline.search_with_stats(refined_query, _threads)
    if not pipeline.search_is_cacheable(out):
        raise _NotCached(out)
    return out


def cached_search_results(refined_query: str, threads: int):
    """pipeline.search_with_stats com cache de 200 s (o n.º de threads não entra na chave)."""
    try:
        return _cached_search(refined_query, threads)
    except _NotCached as e:
        return e.value


@st.cache_data(ttl=200, show_spinner=False)
def _cached_scrape(filtered: list, _threads: int):
    out = pipeline.scrape_with_details(filtered, _threads)
    if not pipeline.scrape_is_cacheable(out):
        raise _NotCached(out)
    return out


def cached_scrape_multiple(filtered: list, threads: int):
    """pipeline.scrape_with_details com cache de 200 s (a recolha via Tor é lenta)."""
    try:
        return _cached_scrape(filtered, threads)
    except _NotCached as e:
        return e.value


# ---------------------------------------------------------------------------
# Configuração da página Streamlit
# ---------------------------------------------------------------------------

# `set_page_config` deve ser a primeira chamada Streamlit no script.
# O título e o ícone aparecem no separador do navegador.
# `initial_sidebar_state="expanded"` garante que a barra lateral está
# visível por omissão, expondo as definições ao utilizador imediatamente.
st.set_page_config(
    page_title="DarkSherlock — Home",
    page_icon="🕵️‍♂️",
    initial_sidebar_state="expanded",
)

# Tema visual centralizado em ui_theme.inject_theme — ver ui_theme.py.
inject_theme()


# ---------------------------------------------------------------------------
# Barra lateral — apenas investigações anteriores
# (configurações movidas para pages/5_🛠️_Settings.py)
# ---------------------------------------------------------------------------

st.sidebar.title("DarkSherlock")
st.sidebar.text("AI-Powered Dark Web OSINT Tool")

st.sidebar.divider()
st.sidebar.subheader("Past Investigations")

saved_investigations = load_investigations()
if saved_investigations:
    inv_labels = [
        f"{inv['_filename'].replace('investigation_','').replace('.json','')} — {inv['query'][:40]}"
        for inv in saved_investigations
    ]
    selected_inv_label = st.sidebar.selectbox(
        "Load investigation", ["(none)"] + inv_labels, key="inv_select"
    )
    if selected_inv_label != "(none)":
        selected_inv_idx = inv_labels.index(selected_inv_label)
        if st.sidebar.button("Load", use_container_width=True, key="load_inv_btn"):
            st.session_state["loaded_investigation"] = saved_investigations[selected_inv_idx]
            st.session_state.pop("pipeline_complete", None)
            st.rerun()
else:
    st.sidebar.caption("No saved investigations yet.")

# ---------------------------------------------------------------------------
# Lê configurações do session_state (definidas em Settings)
# ---------------------------------------------------------------------------
# As chaves dos widgets da página Settings são apagadas pelo Streamlit ao mudar
# de página; settings_state guarda cópias persistentes (ver settings_state.py).
_settings = settings_state.current(get_model_choices())
model                 = _settings["model"]
threads               = _settings["threads"]
max_results           = _settings["max_results"]
max_scrape            = _settings["max_scrape"]
selected_preset_label = _settings["selected_preset_label"]
selected_preset       = _settings["selected_preset"]
custom_instructions   = _settings["custom_instructions"]


# ---------------------------------------------------------------------------
# Área principal — Logótipo e formulário de pesquisa
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Verificação automática dos motores na primeira execução
# ---------------------------------------------------------------------------

# Na primeira vez que a aplicação é carregada (ou após uma reinicialização
# da sessão), verifica automaticamente o estado dos motores de pesquisa.
# Desta forma o utilizador vê imediatamente o banner de estado sem ter de
# clicar no botão "Check Search Engines" manualmente.
# O resultado é guardado em `last_engine_check` para persistir durante toda
# a sessão e evitar verificações repetidas a cada re-render da página.
if "last_engine_check" not in st.session_state:
    with st.spinner("Checking search engines..."):
        tor_result = check_tor_proxy()
        if tor_result["status"] == "up":
            engine_results = check_search_engines()
            st.session_state["last_engine_check"] = {
                "results": engine_results,
                "timestamp": datetime.now().isoformat(),
            }
            # `st.rerun()` força um novo ciclo de renderização para que o
            # banner de estado apareça com os resultados acabados de obter.
            st.rerun()

# ---------------------------------------------------------------------------
# Banner de estado dos motores de pesquisa
# ---------------------------------------------------------------------------

# Apresenta um resumo visual do estado dos motores obtido na verificação mais
# recente (automática ou manual). Indica quantos motores estão em linha e
# lista os que estão indisponíveis para que o utilizador saiba de antemão
# que alguns resultados podem estar em falta.
if "last_engine_check" in st.session_state:
    check_data = st.session_state["last_engine_check"]
    results = check_data["results"]
    # Formata o timestamp removendo a parte dos segundos e substituindo o
    # separador ISO 8601 "T" por um espaço para maior legibilidade.
    check_time = check_data["timestamp"][:16].replace("T", " ")
    up = sum(1 for r in results if r["status"] == "up")
    down_engines = [r for r in results if r["status"] == "down"]
    total = len(results)

    if down_engines:
        down_names = ", ".join(r["name"] for r in down_engines)
        st.warning(
            f"**{up}/{total}** engines online (last check: {check_time})\n\n"
            f"Offline: {down_names}"
        )
    else:
        st.success(f"All {total} engines online (last check: {check_time})")

# ---------------------------------------------------------------------------
# Selector de domínio de investigação (preset)
# ---------------------------------------------------------------------------
# Apresentado visualmente na página principal antes do formulário de pesquisa,
# permitindo ao utilizador escolher o contexto de análise antes de submeter.
# A selecção sincroniza-se com o selector da sidebar via `st.session_state`
# (chave partilhada "preset_select"), de forma que ambos ficam sempre em sync.

_PRESET_LABELS = [
    "Dark Web Threat Intel",
    "Ransomware / Malware Focus",
    "Personal / Identity Investigation",
    "Corporate Espionage / Data Leaks",
]
_PRESET_ICONS = ["🌐", "🦠", "🪪", "🏢"]
_PRESET_PILLS = [f"{icon}  {label}" for icon, label in zip(_PRESET_ICONS, _PRESET_LABELS)]


def _sync_preset_from_pills():
    """Callback on_change das pills → sincroniza com o selectbox da sidebar.

    Os callbacks do Streamlit correm no INÍCIO do próximo ciclo de render,
    antes de qualquer widget ser instanciado. Por isso é seguro escrever em
    'preset_select' aqui — o selectbox ainda não existe nesse momento.
    """
    val = st.session_state.get("preset_pills")
    if val:
        label = val.split("  ", 1)[1]
        st.session_state["preset_select"] = label
        st.session_state[settings_state.PREFIX + "preset_select"] = label


# Deriva o preset por defeito do estado da sidebar (se já foi seleccionado
# numa visita anterior) ou usa o primeiro como fallback.
_current_sidebar_label = settings_state.get("preset_select", _PRESET_LABELS[0])
_default_pill_index = (
    _PRESET_LABELS.index(_current_sidebar_label)
    if _current_sidebar_label in _PRESET_LABELS
    else 0
)

st.markdown("##### Investigation Domain")
st.pills(
    label="Investigation Domain",
    options=_PRESET_PILLS,
    default=_PRESET_PILLS[_default_pill_index],
    selection_mode="single",
    label_visibility="collapsed",
    key="preset_pills",
    on_change=_sync_preset_from_pills,
)

# ---------------------------------------------------------------------------
# Formulário de pesquisa principal
# ---------------------------------------------------------------------------

# O uso de `st.form` agrupa o campo de texto e o botão num único componente
# que só envia os dados ao servidor quando o utilizador clica em "Run"
# (ou prime Enter). Isto evita re-renders parciais enquanto o utilizador
# está a digitar a consulta, o que seria ineficiente e confuso.
# `clear_on_submit=True` limpa o campo após submissão para indicar visualmente
# que a pesquisa foi iniciada.
with st.form("search_form", clear_on_submit=True):
    col_input, col_button = st.columns([10, 1])
    query = col_input.text_input(
        "Enter Dark Web Search Query",
        placeholder="Enter Dark Web Search Query",
        label_visibility="collapsed",
        key="query_input",
    )
    run_button = col_button.form_submit_button("Run")

# ---------------------------------------------------------------------------
# Apresentação de investigação carregada (modo de consulta de histórico)
# ---------------------------------------------------------------------------

# Se o utilizador carregou uma investigação anterior pela barra lateral e
# não submeteu uma nova pesquisa, apresenta os detalhes da investigação
# guardada em vez de executar o pipeline.
if "loaded_investigation" in st.session_state and not run_button:
    inv = st.session_state["loaded_investigation"]

    # Cabeçalho com a consulta original e o timestamp da investigação
    st.info(f"**{inv['query']}** — {inv['timestamp'][:16]}")

    # Metadados da investigação: consulta refinada, modelo usado e número
    # de fontes — úteis para avaliar a qualidade e âmbito da investigação.
    with st.expander("Notes", expanded=False):
        st.markdown(f"**Refined Query:** `{inv['refined_query']}`")
        st.markdown(f"**Model:** `{inv['model']}` | **Domain:** {inv['preset']}")
        st.markdown(f"**Sources:** {len(inv['sources'])}")

    # Lista de fontes consultadas durante a investigação. Os URLs .onion são
    # apresentados como texto simples (não como hiperligações) porque os
    # navegadores normais não conseguem resolver domínios .onion — o Tor
    # Browser é necessário para aceder a estes endereços.
    with st.expander(f"Sources ({len(inv['sources'])} results)", expanded=False):
        for i, item in enumerate(inv["sources"], 1):
            title = item.get("title", "Untitled")
            link = item.get("link", "")
            st.markdown(f"{i}. [{title}]({link})")

    # Apresenta o relatório de inteligência gerado originalmente pelo LLM.
    st.subheader(":red[Findings]", anchor=None, divider="gray")
    st.markdown(inv["summary"])
    st.divider()

    # Botões de download — regenera o PDF a partir dos dados guardados
    _inv_pdf_data = investigation_pdf_data(inv)
    _inv_pdf_bytes = generate_forensic_pdf(_inv_pdf_data)
    _inv_now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    _dl1, _dl2 = st.columns(2)
    _dl1.download_button(
        "⬇ Download Relatório PDF",
        data=_inv_pdf_bytes,
        file_name=f"relatorio_{inv.get('audit_id', 'inv')[:8]}_{_inv_now}.pdf",
        mime="application/pdf",
        use_container_width=True,
        key="loaded_dl_pdf",
    )
    _dl2.download_button(
        "⬇ Download Summary MD",
        data=inv["summary"].encode(),
        file_name=f"summary_{_inv_now}.md",
        mime="text/markdown",
        use_container_width=True,
        key="loaded_dl_md",
    )

    # Permite ao utilizador limpar a investigação carregada para voltar ao
    # estado inicial da página e executar uma nova pesquisa.
    if st.button("Clear"):
        del st.session_state["loaded_investigation"]
        st.rerun()


# ---------------------------------------------------------------------------
# Pipeline principal de investigação (6 etapas)
# ---------------------------------------------------------------------------

# O pipeline só é executado quando o utilizador submete o formulário com
# uma consulta não vazia. A verificação de `query` evita execuções acidentais
# se o utilizador clicar em "Run" com o campo vazio.
if run_button and query:

    # Limpa a investigação carregada e o resultado anterior antes de começar.
    st.session_state.pop("loaded_investigation", None)
    st.session_state.pop("pipeline_complete", None)

    # As 6 etapas, com um painel de estado cada (ui_pipeline.py); a lógica é a
    # de pipeline.py, a mesma que a avaliação usa.
    run, findings_container = run_with_ui(
        query, _settings,
        on_error=_render_pipeline_error,
        search_fn=cached_search_results,
        scrape_fn=cached_scrape_multiple,
    )

    # Persistência (JSON da investigação) e audit trail, no formato único de pipeline.py.
    _fname = pipeline.save_investigation(
        pipeline.investigation_record(run, preset_label=selected_preset_label), INVESTIGATIONS_DIR)
    log_investigation(pipeline.audit_record(run, preset_label=selected_preset_label))

    st.success(f"Pipeline completed in {_fmt_ms(run.total_ms)} — saved as `{_fname}`")

    # Dados para voltar a desenhar o resultado nos reruns (p. ex. após um download).
    st.session_state["pipeline_complete"] = complete_dict(run, selected_preset_label, _fname)

    # O relatório já está no findings_container (streaming); o helper acrescenta
    # Notes, Sources e os downloads.
    _render_pipeline_result(
        st.session_state["pipeline_complete"],
        findings_container=findings_container,
    )


# ---------------------------------------------------------------------------
# Apresentação persistente de resultados (sobrevive a reruns do Streamlit)
# ---------------------------------------------------------------------------
# Quando o utilizador clica num botão de download, o Streamlit faz rerun.
# Nesse rerun, `run_button` é False e o bloco do pipeline não executa.
# Este bloco independente renderiza os resultados a partir dos dados
# guardados em `pipeline_complete`, garantindo que Notes, Sources, Findings
# e botões de download permanecem visíveis após o download.

if "pipeline_complete" in st.session_state and not run_button and "loaded_investigation" not in st.session_state:
    _pc = st.session_state["pipeline_complete"]
    st.success(f"Pipeline completed in {_fmt_ms(_pc['pipeline_ms'])} — saved as `{_pc['fname']}`")
    # `download_key_prefix="pc_"` evita colisão de keys com os botões
    # equivalentes renderizados durante o run do pipeline.
    _render_pipeline_result(_pc, download_key_prefix="pc_")
