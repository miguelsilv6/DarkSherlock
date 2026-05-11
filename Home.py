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

import base64
import json
import time
import uuid
import streamlit as st
from datetime import datetime, timezone
from pathlib import Path
from scrape import scrape_multiple
from search import get_search_results
from llm_utils import BufferedStreamingHandler, get_model_choices
from llm import get_llm, refine_query, filter_results, generate_summary, filter_scraped_by_relevance, detect_ioc, PRESET_PROMPTS
from engine_manager import get_active_engines
from report import compute_integrity_hashes, generate_forensic_pdf
from audit import log_investigation, setup_file_logging
from hitl import (
    render_stage2_review,
    render_stage4_review,
    render_stage5_review,
    _reset_hitl_state,
)
from theme import apply_theme, render_metrics, render_brand_lockup

# Configura o logging para ficheiro (captura debug/info de todos os módulos)
setup_file_logging()
from health import check_search_engines, check_tor_proxy


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
    # Normaliza a mensagem de erro para comparação insensível a maiúsculas
    message = str(err).strip() or err.__class__.__name__
    lower_msg = message.lower()

    # Dicas genéricas apresentadas independentemente do fornecedor
    hints = [
        "- Confirm the relevant API key is set in your `.env` or shell before launching Streamlit.",
        "- Keys copied from dashboards often include hidden spaces; re-copy if authentication keeps failing.",
        "- Restart the app after updating environment variables so the new values are picked up.",
    ]

    # Acrescenta uma dica específica para Ollama
    if any(token in lower_msg for token in ("ollama", "connection refused", "connect")):
        hints.insert(0, "- Ensure Ollama is running: `ollama serve`")

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
# Persistência de investigações
# ---------------------------------------------------------------------------

# Diretório onde os ficheiros JSON das investigações são guardados em disco.
# O uso de `pathlib.Path` garante compatibilidade entre sistemas operativos.
INVESTIGATIONS_DIR = Path("investigations")


def save_investigation(
    query: str,
    refined_query: str,
    model: str,
    preset_label: str,
    sources: list,
    summary: str,
    audit_id: str = "",
    active_engines: list = None,
    integrity: dict = None,
) -> str:
    """Guarda uma investigação completa em disco no formato JSON. Retorna o nome do ficheiro.

    Para além dos dados da investigação, guarda campos forenses:
    - audit_id: identificador único UUID4 para rastreabilidade
    - timestamp_utc: timestamp em UTC para correlação temporal
    - active_engines: engines utilizadas na pesquisa
    - integrity: hashes SHA-256 por fonte e hash global (cadeia de custódia)
    """
    INVESTIGATIONS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"investigation_{timestamp}.json"
    data = {
        # Identificação e rastreabilidade
        "audit_id": audit_id,
        "timestamp": datetime.now().isoformat(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        # Dados da investigação
        "query": query,
        "refined_query": refined_query,
        "model": model,
        "preset": preset_label,
        "active_engines": active_engines or [],
        "sources": sources,
        "summary": summary,
        # Cadeia de custódia digital (hashes SHA-256)
        "integrity": integrity or {},
    }
    (INVESTIGATIONS_DIR / fname).write_text(json.dumps(data, indent=2))
    return fname


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
            data = json.loads(f.read_text())
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


def _forum_cookie_overrides_json() -> str:
    """Serializa overrides de cookie (Settings → DarkForums) para chave de cache."""
    dc = (st.session_state.get("darkforums_cookie") or "").strip()
    return json.dumps({"DarkForums": dc} if dc else {}, sort_keys=True)


@st.cache_data(ttl=200, show_spinner=False)
def cached_search_results(refined_query: str, forum_cookie_overrides_json: str):
    """Executa a pesquisa nos motores da dark web com cache por 200 segundos.

    O espaço é substituído por `+` para conformidade com a codificação
    de parâmetros de pesquisa esperada pelos motores .onion suportados.

    Nota: o número de threads não faz parte da chave de cache porque não
    afecta os resultados — apenas a velocidade de obtenção. Incluí-lo
    causava cache misses desnecessários quando o utilizador ajustava o
    slider de threads entre execuções com a mesma query.

    Args:
        refined_query: Consulta refinada pelo LLM.
        forum_cookie_overrides_json: JSON com cookies opcionais (ex.: DarkForums).

    Returns:
        Lista de resultados brutos (dicionários com `title` e `link`).
    """
    overrides = json.loads(forum_cookie_overrides_json) if forum_cookie_overrides_json else {}
    return get_search_results(
        refined_query.replace(" ", "+"),
        max_workers=4,
        forum_cookie_overrides=overrides if overrides else None,
    )


@st.cache_data(ttl=200, show_spinner=False)
def cached_scrape_multiple(filtered: list, threads: int, forum_cookie_overrides_json: str):
    """Extrai o conteúdo textual das páginas filtradas com cache por 200 segundos.

    A cache é especialmente valiosa aqui porque o scraping de páginas .onion
    através do Tor pode ser muito lento (latências de vários segundos por
    página). Se o utilizador reexecutar o pipeline com a mesma lista de URLs
    filtrados dentro de 200 segundos, o conteúdo é devolvido imediatamente.

    Args:
        filtered: Lista de resultados filtrados (devolvida pela etapa 4).
        threads:  Número de fios de execução paralela para o scraping.
        forum_cookie_overrides_json: cookies opcionais para fóruns autenticados.

    Returns:
        Dicionário `{url: conteúdo_textual}` para cada página processada.
    """
    overrides = json.loads(forum_cookie_overrides_json) if forum_cookie_overrides_json else {}
    return scrape_multiple(
        filtered,
        max_workers=threads,
        forum_cookie_overrides=overrides if overrides else None,
    )


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

# DarkSherlock Design System — tokens, chrome CSS e componentes custom.
# `apply_theme()` injecta o :root de variáveis CSS e as overrides de Streamlit
# (botões, pills, expanders, status, alertas). Ver `theme.py` para detalhe.
apply_theme()


# ---------------------------------------------------------------------------
# Barra lateral — apenas investigações anteriores
# (configurações movidas para pages/4_🛠️_Settings.py)
# ---------------------------------------------------------------------------

st.sidebar.title("DarkSherlock")
st.sidebar.text("AI-Powered Dark Web OSINT Tool")

# Toggle Human-in-the-Loop (HITL) — opt-in, default False
# Quando activo, o pipeline pausa em 3 checkpoints (Stage 2, 4, 5) permitindo
# ao analista rever/editar outputs intermédios antes de alimentar as etapas
# seguintes. O estado vive em st.session_state["hitl_mode"].
st.sidebar.toggle(
    "🤝 Human-in-the-Loop",
    key="hitl_mode",
    help=(
        "Pausa o pipeline para revisão humana após:\n"
        "• Query refinada (Stage 2)\n"
        "• URLs filtrados (Stage 4)\n"
        "• Conteúdo scrapeado (Stage 5)"
    ),
)

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
            st.session_state.pop("pipeline_no_match", None)
            st.rerun()
else:
    st.sidebar.caption("No saved investigations yet.")

# ---------------------------------------------------------------------------
# Lê configurações do session_state (definidas em Settings)
# ---------------------------------------------------------------------------
_preset_options = {
    "Dark Web Threat Intel":             "threat_intel",
    "Ransomware / Malware Focus":        "ransomware_malware",
    "Personal / Identity Investigation": "personal_identity",
    "Corporate Spy / Data Leaks":  "corporate_espionage",
}
_model_options = get_model_choices()
model               = st.session_state.get("model_select",       _model_options[0] if _model_options else None)
threads             = st.session_state.get("thread_slider",      4)
max_results         = st.session_state.get("max_results_slider", 50)
max_scrape          = st.session_state.get("max_scrape_slider",  10)
selected_preset_label = st.session_state.get("preset_select",   "Dark Web Threat Intel")
selected_preset     = _preset_options.get(selected_preset_label, "threat_intel")
custom_instructions = st.session_state.get("custom_instructions", "")


# ---------------------------------------------------------------------------
# Área principal — Brand lockup e formulário de pesquisa
# ---------------------------------------------------------------------------
# O brand lockup canónico (glifo SVG "forensic-magnifier-meets-terminal" +
# wordmark Dark/Sherlock com caret a piscar + tagline "AI · DARK WEB · OSINT")
# é renderizado via helper do theme.py. Tradução directa de
# preview/brand-logo.html do DarkSherlock Design System.
render_brand_lockup()

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
            _fd_co = {}
            if (dc := (st.session_state.get("darkforums_cookie") or "").strip()):
                _fd_co["DarkForums"] = dc
            engine_results = check_search_engines(
                forum_cookie_overrides=_fd_co if _fd_co else None,
            )
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
    "Corporate Spy / Data Leaks",
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
        st.session_state["preset_select"] = val.split("  ", 1)[1]


# Deriva o preset por defeito do estado da sidebar (se já foi seleccionado
# numa visita anterior) ou usa o primeiro como fallback.
_current_sidebar_label = st.session_state.get("preset_select", _PRESET_LABELS[0])
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
    _inv_pdf_data = {
        "audit_id": inv.get("audit_id", ""),
        "query": inv["query"],
        "refined_query": inv["refined_query"],
        "model": inv["model"],
        "preset": inv["preset"],
        "timestamp_utc": inv.get("timestamp_utc", inv["timestamp"]),
        "active_engines": inv.get("active_engines", []),
        "sources": inv["sources"],
        "integrity": inv.get("integrity", {}),
        "summary": inv["summary"],
        "results_found": len(inv["sources"]),
        "results_scraped": len(inv["sources"]),
    }
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
# Pipeline principal de investigação (6 etapas) — com suporte Human-in-the-Loop
# ---------------------------------------------------------------------------
#
# O pipeline corre como uma máquina de estados cujos outputs intermédios vivem
# em `st.session_state`. Quando o modo HITL está ligado, entre etapas críticas
# há um "checkpoint" que pausa a execução via `st.stop()` e renderiza uma UI
# de revisão — o próximo rerun retoma exactamente onde parou porque os outputs
# anteriores já estão em session_state (idempotência) e as funções
# `@st.cache_data` evitam repetir chamadas caras.
#
# Checkpoints activos quando `hitl_mode=True`:
#   • Stage 2 → 3: revisão / edição da query refinada
#   • Stage 4 → 5: selecção dos URLs a scrapear (antes do Tor)
#   • Stage 5 → 6: selecção das fontes scrapeadas (antes do LLM gerar sumário)
#
# Quando `hitl_mode=False` o pipeline corre as 6 etapas de uma só vez, como
# antes (compatibilidade total com o comportamento autónomo).

# ---------- Arranque de uma nova pesquisa ----------
# Ao submeter o formulário, limpa estado residual e marca pipeline em curso.
if run_button and query:
    _reset_hitl_state()
    st.session_state.pop("loaded_investigation", None)
    st.session_state.pop("pipeline_complete", None)
    st.session_state.pop("pipeline_no_match", None)
    st.session_state["hitl_in_progress"] = True
    st.session_state["hitl_query"] = query
    st.session_state["hitl_preset"] = selected_preset
    st.session_state["hitl_preset_label"] = selected_preset_label
    st.session_state["hitl_pipeline_start"] = time.time()

# Lê flag HITL uma só vez para uso pelos gates abaixo.
hitl_on = st.session_state.get("hitl_mode", False)

# ---------- Execução gated do pipeline ----------
# Só entra aqui se houver um pipeline em curso (quer tenha acabado de arrancar,
# quer esteja a ser retomado de um rerun após um checkpoint).
if st.session_state.get("hitl_in_progress"):
    # Valores persistidos no arranque — sobrevivem a reruns.
    q                    = st.session_state["hitl_query"]
    preset               = st.session_state["hitl_preset"]
    preset_label         = st.session_state["hitl_preset_label"]
    pipeline_start       = st.session_state["hitl_pipeline_start"]

    # Obtém a lista de motores de pesquisa activos para uso na Etapa 3
    active_engines = get_active_engines()

    # Após um checkpoint ser aprovado, o rerun salta as etapas já executadas
    # e, em vez de re-renderizar o `st.status` expandido (caro e ruidoso),
    # mostra um `st.success` compacto *inline* — na mesma posição vertical que
    # a etapa ocuparia se estivesse a correr agora. Isto preserva a ordem
    # visual Stage 1 → Stage 2 → Stage 3 → ... no ecrã, em vez de agrupar
    # todos os indicadores num strip no topo (o que dava a falsa impressão
    # de a etapa ter "desaparecido").
    def _show_completed(label: str) -> None:
        """Indicador compacto de etapa já concluída, renderizado inline."""
        st.success(label, icon="✅")

    # ------------------------------------------------------------------
    # Etapa 1/6 — Carregamento do modelo de linguagem (sempre executada)
    # ------------------------------------------------------------------
    # O objecto `llm` é um cliente LangChain com callbacks e potencialmente
    # conexões HTTP — não é facilmente serializável para session_state.
    # Por isso é instanciado em TODOS os reruns (barato para Ollama local).
    with st.status("**Stage 1/6** — Loading LLM...", expanded=True) as status:
        t0 = time.time()
        try:
            llm = get_llm(model)
            elapsed = round((time.time() - t0) * 1000)
            st.write(f"Model: `{model}`")
            status.update(label=f"**Stage 1/6** — LLM loaded ({_fmt_ms(elapsed)})", state="complete")
        except Exception as e:
            status.update(label="**Stage 1/6** — LLM failed", state="error")
            _render_pipeline_error("load the selected LLM", e)

    # ------------------------------------------------------------------
    # Etapa 2/6 — Refinamento da consulta com o LLM (gated)
    # ------------------------------------------------------------------
    # Só executa se `refined` ainda não estiver em session_state. Ao retomar
    # o pipeline após um checkpoint, o valor persiste e esta etapa é saltada.
    if "refined" not in st.session_state:
        with st.status("**Stage 2/6** — Refining query...", expanded=True) as status:
            t0 = time.time()
            try:
                st.session_state.refined = refine_query(llm, q, preset=preset)
                elapsed = round((time.time() - t0) * 1000)
                st.session_state["hitl_refine_ms"] = elapsed
                st.write(f"Original: `{q}`")
                st.write(f"Refined: `{st.session_state.refined}`")
                status.update(label=f"**Stage 2/6** — Query refined ({_fmt_ms(elapsed)})", state="complete")
            except Exception as e:
                status.update(label="**Stage 2/6** — Query refinement failed", state="error")
                _render_pipeline_error("refine the query", e)
    else:
        _show_completed(
            f"**Stage 2/6** — Query refined ({_fmt_ms(st.session_state.get('hitl_refine_ms', 0))}): "
            f"`{st.session_state.refined}`"
        )

    # ------------------------------------------------------------------
    # Checkpoint 1/3 — Revisão da query refinada (HITL)
    # ------------------------------------------------------------------
    # Se o modo HITL está ligado e o checkpoint 1 ainda não foi aprovado,
    # renderiza a UI de revisão e suspende o pipeline via `st.stop()`.
    # A aprovação guarda `hitl_stage2_approved=True` + a query editada em
    # `st.session_state.refined` e chama `st.rerun()` para retomar.
    if hitl_on and not st.session_state.get("hitl_stage2_approved"):
        render_stage2_review(q, st.session_state.refined)
        st.stop()

    # ------------------------------------------------------------------
    # Etapa 3/6 — Pesquisa distribuída nos motores da dark web
    # ------------------------------------------------------------------
    # A consulta refinada é enviada em paralelo a todos os motores de
    # pesquisa .onion activos (ex.: Ahmia, Torch, DarkSearch) via proxy Tor.
    # O paralelismo é controlado pelo parâmetro `threads` definido na barra
    # lateral. Os resultados brutos são truncados ao limite `max_results`
    # e deduplicados por URL para evitar que a mesma fonte seja processada
    # várias vezes nas etapas seguintes.
    # ------------------------------------------------------------------
    # Etapa 3/6 — Pesquisa distribuída nos motores da dark web (gated)
    # ------------------------------------------------------------------
    if "results" not in st.session_state:
        with st.status(f"**Stage 3/6** — Searching {len(active_engines)} engines...", expanded=True) as status:
            t0 = time.time()
            # search.py já deduplica os resultados por URL.
            st.session_state.results = cached_search_results(
                st.session_state.refined,
                _forum_cookie_overrides_json(),
            )

            if len(st.session_state.results) > max_results:
                st.session_state.results = st.session_state.results[:max_results]

            elapsed = round((time.time() - t0) * 1000)
            st.session_state["hitl_search_ms"] = elapsed

            # Estampar cada resultado com o timestamp UTC de recolha (imutável)
            retrieved_at_utc = datetime.now(timezone.utc).isoformat()
            for r in st.session_state.results:
                r["retrieved_at_utc"] = retrieved_at_utc

            st.write(f"Found **{len(st.session_state.results)}** results across {len(active_engines)} engines")
            status.update(
                label=f"**Stage 3/6** — {len(st.session_state.results)} results found ({_fmt_ms(elapsed)})",
                state="complete",
            )
    else:
        _show_completed(
            f"**Stage 3/6** — {len(st.session_state.results)} results found "
            f"({_fmt_ms(st.session_state.get('hitl_search_ms', 0))})"
        )

    # ------------------------------------------------------------------
    # Etapa 4/6 — Filtragem por relevância com o LLM (gated)
    # ------------------------------------------------------------------
    if "filtered" not in st.session_state:
        with st.status("**Stage 4/6** — Filtering results with LLM...", expanded=True) as status:
            t0 = time.time()
            st.session_state.filtered = filter_results(
                llm, st.session_state.refined, st.session_state.results
            )

            if len(st.session_state.filtered) > max_scrape:
                st.session_state.filtered = st.session_state.filtered[:max_scrape]

            elapsed = round((time.time() - t0) * 1000)
            st.session_state["hitl_filter_ms"] = elapsed
            st.write(f"Filtered to **{len(st.session_state.filtered)}** most relevant results")

            with st.expander("View filtered results"):
                st.caption("🧅 Links .onion: copia e abre no Tor Browser")
                for i, item in enumerate(st.session_state.filtered, 1):
                    title = item.get("title", "Untitled")
                    link = item.get("link", "")
                    if ".onion" in link:
                        st.markdown(f"**{i}. {title}**")
                        st.code(link, language=None)
                    else:
                        st.markdown(f"{i}. [{title}]({link})")

            status.update(
                label=f"**Stage 4/6** — Filtered to {len(st.session_state.filtered)} results ({_fmt_ms(elapsed)})",
                state="complete",
            )
    else:
        _show_completed(
            f"**Stage 4/6** — Filtered to {len(st.session_state.filtered)} results "
            f"({_fmt_ms(st.session_state.get('hitl_filter_ms', 0))})"
        )

    # ------------------------------------------------------------------
    # Checkpoint 2/3 — Revisão dos URLs filtrados (HITL)
    # ------------------------------------------------------------------
    # Oportunidade de desmarcar URLs obviamente irrelevantes antes do scraping
    # via Tor (operação cara). Ao aprovar, `st.session_state.filtered` fica
    # reduzido à lista seleccionada pelo utilizador.
    if hitl_on and not st.session_state.get("hitl_stage4_approved"):
        _ioc_type_s4, _ = detect_ioc(q)
        render_stage4_review(
            st.session_state.filtered,
            raw_count=len(st.session_state.results),
            ioc_type=_ioc_type_s4,
        )
        st.stop()

    # ------------------------------------------------------------------
    # Etapa 5/6 — Extracção de conteúdo (scraping) (gated)
    # ------------------------------------------------------------------
    if "meaningful_scraped" not in st.session_state:
        with st.status(f"**Stage 5/6** — Scraping {len(st.session_state.filtered)} pages...", expanded=True) as status:
            t0 = time.time()
            st.session_state.scraped = cached_scrape_multiple(
                st.session_state.filtered,
                threads,
                _forum_cookie_overrides_json(),
            )

            # Filtra páginas com pouco conteúdo (< 150 chars) — tipicamente erros.
            meaningful_scraped = {
                url: content
                for url, content in st.session_state.scraped.items()
                if len(content) > 150
            }

            # Filtra por relevância: descarta fontes sem keywords da query original.
            pre_relevance_count = len(meaningful_scraped)
            meaningful_scraped = filter_scraped_by_relevance(q, meaningful_scraped)
            relevance_removed = pre_relevance_count - len(meaningful_scraped)

            # Estampar cada fonte com o timestamp UTC de scraping
            scraped_at_utc = datetime.now(timezone.utc).isoformat()
            for item in st.session_state.filtered:
                if item.get("link", "") in meaningful_scraped:
                    item["scraped_at_utc"] = scraped_at_utc

            # Hashes SHA-256 para cadeia de custódia forense
            integrity = compute_integrity_hashes(meaningful_scraped)
            st.session_state.integrity = integrity
            st.session_state["meaningful_scraped"] = meaningful_scraped

            elapsed = round((time.time() - t0) * 1000)
            st.session_state["hitl_scrape_ms"] = elapsed
            scraped_count = len(meaningful_scraped)
            failed_count = len(st.session_state.scraped) - scraped_count
            st.session_state["hitl_failed_count"] = failed_count
            st.session_state["hitl_relevance_removed"] = relevance_removed

            note = f" ({failed_count} inaccessible pages removed)" if failed_count else ""
            relevance_note = f" ({relevance_removed} irrelevant pages removed)" if relevance_removed else ""
            st.write(f"Scraped **{scraped_count}** pages with content{note}{relevance_note}")
            st.caption(f"Hash global SHA-256: `{integrity['overall_sha256'][:16]}...`")

            # --------------------------------------------------------
            # Paragem defensiva: se a query é um IOC e o filtro estrito
            # rejeitou TODAS as fontes (i.e. nenhuma contém o indicador
            # literal), não faz sentido invocar o LLM — produziria uma
            # análise alucinada. Aborta o pipeline com mensagem clara.
            # --------------------------------------------------------
            ioc_type, ioc_value = detect_ioc(q)
            if ioc_type and scraped_count == 0:
                status.update(
                    label=f"**Stage 5/6** — 0 sources contain the {ioc_type} IOC",
                    state="error",
                )
                st.error(
                    f"**Pipeline interrompido — sem correspondência para o IOC.**\n\n"
                    f"A query é um indicador técnico específico do tipo "
                    f"`{ioc_type}` (`{ioc_value}`), mas **nenhuma das "
                    f"{pre_relevance_count} fontes recolhidas contém esse "
                    f"indicador no seu conteúdo**.\n\n"
                    f"Gerar um sumário LLM com fontes que não contêm o IOC "
                    f"produziria análise alucinada. Sugestões:\n"
                    f"• Refinar a query (ex.: para emails, pesquisar apenas "
                    f"a parte local: `{ioc_value.split('@')[0] if ioc_type == 'email' else '…'}`)\n"
                    f"• Experimentar outros motores de pesquisa na sidebar\n"
                    f"• Adicionar contexto textual à query (ex.: nome do "
                    f"grupo ransomware, família de malware, data)"
                )
                # Marca o pipeline como terminado sem sumário para evitar
                # que o rerun seguinte re-execute tudo. `pipeline_no_match`
                # sobrevive aos reruns e é lido pelo bloco de apresentação
                # persistente mais abaixo para re-render do banner.
                st.session_state["hitl_in_progress"] = False
                st.session_state["pipeline_no_match"] = {
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "sources_analysed": pre_relevance_count,
                    "query": q,
                }
                st.stop()

            with st.expander(f"📄 Conteúdo recolhido por fonte ({scraped_count})", expanded=False):
                st.caption("Texto extraído de cada página — o LLM lê e analisa este conteúdo na Etapa 6/6")
                for url, content in list(meaningful_scraped.items()):
                    title = next(
                        (r.get("title", "Sem título") for r in st.session_state.filtered
                         if r.get("link") == url),
                        "Sem título",
                    )
                    st.markdown(f"**{title}**")
                    if ".onion" in url:
                        st.code(url, language=None)
                    else:
                        st.markdown(f"`{url}`")
                    excerpt = content[:500].strip()
                    if len(content) > 500:
                        excerpt += " …"
                    st.markdown(f"*{excerpt}*")
                    st.divider()

            status.update(
                label=f"**Stage 5/6** — {scraped_count} pages scraped ({_fmt_ms(elapsed)})",
                state="complete",
            )
    else:
        meaningful_scraped = st.session_state["meaningful_scraped"]
        scraped_count = len(meaningful_scraped)
        _show_completed(
            f"**Stage 5/6** — {scraped_count} pages scraped "
            f"({_fmt_ms(st.session_state.get('hitl_scrape_ms', 0))})"
        )

    # ------------------------------------------------------------------
    # Checkpoint 3/3 — Revisão do conteúdo scrapeado (HITL)
    # ------------------------------------------------------------------
    # Último filtro antes do LLM gerar o sumário. O utilizador vê um excerto
    # de cada fonte e pode desmarcar as que têm conteúdo irrelevante.
    if hitl_on and not st.session_state.get("hitl_stage5_approved"):
        _ioc_type_s5, _ = detect_ioc(q)
        render_stage5_review(
            st.session_state["meaningful_scraped"],
            st.session_state.filtered,
            relevance_removed=st.session_state.get("hitl_relevance_removed", 0),
            failed_count=st.session_state.get("hitl_failed_count", 0),
            ioc_type=_ioc_type_s5,
        )
        st.stop()

    # Resolve o conjunto final de fontes que alimentam o Stage 6:
    #   • HITL ON + aprovado → só as fontes escolhidas pelo utilizador
    #   • HITL OFF          → todas as que passaram nos filtros automáticos
    final_scraped = st.session_state.get(
        "hitl_approved_scraped",
        st.session_state["meaningful_scraped"],
    )
    # Recalcula integrity sobre as fontes finalmente aprovadas (cadeia de custódia)
    integrity = compute_integrity_hashes(final_scraped)
    st.session_state.integrity = integrity
    scraped_count = len(final_scraped)

    # ------------------------------------------------------------------
    # Etapa 6/6 — Geração do relatório de inteligência (streaming)
    # ------------------------------------------------------------------
    # O LLM analisa o conteúdo extraído e gera um relatório estruturado
    # de inteligência adaptado ao domínio de investigação e às instruções
    # personalizadas do utilizador.
    #
    # O relatório é apresentado em modo de streaming: cada fragmento de
    # texto gerado pelo LLM é imediatamente adicionado ao ecrã em vez de
    # aguardar a conclusão completa. Isto melhora significativamente a
    # experiência percebida porque o utilizador começa a ler os resultados
    # enquanto o LLM ainda está a gerar o restante texto.
    #
    # A implementação usa um `BufferedStreamingHandler` (callback LangChain)
    # que acumula os fragmentos em `streamed_summary` e actualiza o
    # componente `summary_slot` (um `st.empty`) a cada novo fragmento.

    # Inicializa a string do relatório no session_state (apagada a cada nova pesquisa).
    st.session_state.streamed_summary = ""

    findings_container = st.container()
    with findings_container:
        st.subheader(":red[Findings]", anchor=None, divider="gray")
        summary_slot = st.empty()

    def ui_emit(chunk: str):
        """Callback do BufferedStreamingHandler — acumula e re-renderiza o markdown."""
        st.session_state.streamed_summary += chunk
        summary_slot.markdown(st.session_state.streamed_summary)

    with st.status("**Stage 6/6** — Generating intelligence summary...", expanded=True) as status:
        t0 = time.time()
        stream_handler = BufferedStreamingHandler(ui_callback=ui_emit)
        llm.callbacks = [stream_handler]

        # `final_scraped` reflecte a selecção do utilizador (se HITL ON) ou
        # todas as fontes automáticas (se HITL OFF).
        _ = generate_summary(
            llm, q, final_scraped,
            preset=preset, custom_instructions=custom_instructions,
        )
        elapsed = round((time.time() - t0) * 1000)
        status.update(
            label=f"**Stage 6/6** — Summary generated ({_fmt_ms(elapsed)})",
            state="complete",
        )

    # ------------------------------------------------------------------
    # Persistência e apresentação final dos resultados
    # ------------------------------------------------------------------

    # Apenas as fontes efectivamente usadas no sumário são guardadas
    # como "sources" da investigação (respeita a selecção do utilizador).
    final_urls = set(final_scraped.keys())
    sources_used = [r for r in st.session_state.filtered if r.get("link") in final_urls]
    if not sources_used:
        # Fallback: se por alguma razão não houver match por URL, guarda a lista toda.
        sources_used = st.session_state.filtered

    total_elapsed = round(time.time() - pipeline_start, 1)
    pipeline_ms = int(total_elapsed * 1000)

    audit_id = str(uuid.uuid4())

    _fname = save_investigation(
        query=q,
        refined_query=st.session_state.refined,
        model=model,
        preset_label=preset_label,
        sources=sources_used,
        summary=st.session_state.streamed_summary,
        audit_id=audit_id,
        active_engines=[e["name"] for e in active_engines],
        integrity=integrity,
    )

    log_investigation({
        "audit_id": audit_id,
        "query": q,
        "refined_query": st.session_state.refined,
        "model": model,
        "preset": preset_label,
        "engines_active": [e["name"] for e in active_engines],
        "results_found": len(st.session_state.results),
        "results_filtered": len(st.session_state.filtered),
        "results_scraped": scraped_count,
        "summary_length_chars": len(st.session_state.streamed_summary),
        "pipeline_duration_ms": pipeline_ms,
        "hitl_mode": hitl_on,
        "errors": [],
    })

    st.success(f"Pipeline completed in {_fmt_ms(pipeline_ms)} — saved as `{_fname}`")

    # Guarda dados para apresentação persistente (sobrevive a reruns).
    st.session_state["pipeline_complete"] = {
        "audit_id": audit_id,
        "query": q,
        "refined": st.session_state.refined,
        "model": model,
        "preset_label": preset_label,
        "filtered": sources_used,
        "results_count": len(st.session_state.results),
        "scraped_count": scraped_count,
        "summary": st.session_state.streamed_summary,
        "integrity": integrity,
        "active_engines": [e["name"] for e in active_engines],
        "pipeline_ms": pipeline_ms,
        "fname": _fname,
    }

    # Apresentação inline imediata (neste rerun)
    with st.expander("Notes", expanded=False):
        st.markdown(f"**Refined Query:** `{st.session_state.refined}`")
        st.markdown(f"**Model:** `{model}` | **Domain:** {preset_label}")
        st.markdown(
            f"**Results found:** {len(st.session_state.results)} | "
            f"**Filtered to:** {len(st.session_state.filtered)} | "
            f"**Scraped:** {scraped_count}"
            + (" | **HITL:** on" if hitl_on else "")
        )

    with st.expander(f"Sources ({len(sources_used)} results)", expanded=False):
        st.caption("🧅 Links .onion: copia e abre no Tor Browser")
        for i, item in enumerate(sources_used, 1):
            title = item.get("title", "Untitled")
            link = item.get("link", "")
            if ".onion" in link:
                st.markdown(f"**{i}. {title}**")
                st.code(link, language=None)
            else:
                st.markdown(f"{i}. [{title}]({link})")

    with findings_container:
        st.markdown(st.session_state.streamed_summary)
        st.divider()

        pdf_data = {
            "audit_id": audit_id,
            "query": q,
            "refined_query": st.session_state.refined,
            "model": model,
            "preset": preset_label,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "active_engines": [e["name"] for e in active_engines],
            "sources": sources_used,
            "integrity": integrity,
            "summary": st.session_state.streamed_summary,
            "results_found": len(st.session_state.results),
            "results_scraped": scraped_count,
        }
        pdf_bytes = generate_forensic_pdf(pdf_data)

        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        dl_col1, dl_col2 = st.columns(2)
        dl_col1.download_button(
            label="⬇ Download Relatório PDF",
            data=pdf_bytes,
            file_name=f"relatorio_{audit_id[:8]}_{now}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
        dl_col2.download_button(
            label="⬇ Download Summary MD",
            data=st.session_state.streamed_summary.encode(),
            file_name=f"summary_{now}.md",
            mime="text/markdown",
            use_container_width=True,
        )

    # Pipeline concluído — libertar o flag HITL para permitir nova pesquisa.
    st.session_state["hitl_in_progress"] = False


# ---------------------------------------------------------------------------
# Apresentação persistente de resultados (sobrevive a reruns do Streamlit)
# ---------------------------------------------------------------------------
# Quando o utilizador clica num botão de download, o Streamlit faz rerun.
# Nesse rerun, `run_button` é False e o bloco do pipeline não executa.
# Este bloco independente renderiza os resultados a partir dos dados
# guardados em `pipeline_complete`, garantindo que Notes, Sources, Findings
# e botões de download permanecem visíveis após o download.

# Banner persistente para o caso "IOC sem correspondência" — produzido pelo
# filtro estrito (filter_scraped_by_relevance em modo IOC) quando nenhuma
# fonte contém literalmente o indicador pesquisado. Sobrevive a reruns até
# que o utilizador inicie nova pesquisa ou carregue uma investigação antiga.
if (
    "pipeline_no_match" in st.session_state
    and not run_button
    and "loaded_investigation" not in st.session_state
):
    _nm = st.session_state["pipeline_no_match"]
    _suggestion = ""
    if _nm["ioc_type"] == "email" and "@" in _nm["ioc_value"]:
        _local = _nm["ioc_value"].split("@")[0]
        _suggestion = f"\n• Para emails, tenta pesquisar apenas a parte local: `{_local}`"
    st.error(
        f"**Pipeline interrompido — sem correspondência para o IOC.**\n\n"
        f"A query `{_nm['query']}` é um indicador técnico do tipo "
        f"`{_nm['ioc_type']}`, mas **nenhuma das {_nm['sources_analysed']} "
        f"fontes recolhidas contém esse indicador no seu conteúdo**.\n\n"
        f"Gerar um sumário LLM sobre fontes que não contêm o IOC produziria "
        f"análise alucinada. Sugestões:"
        f"{_suggestion}\n"
        f"• Experimentar outros motores de pesquisa na sidebar\n"
        f"• Adicionar contexto textual à query (ex.: nome do grupo ransomware, "
        f"família de malware, ou data relevante)"
    )

if "pipeline_complete" in st.session_state and not run_button and "loaded_investigation" not in st.session_state:
    _pc = st.session_state["pipeline_complete"]

    st.success(f"Pipeline completed in {_fmt_ms(_pc['pipeline_ms'])} — saved as `{_pc['fname']}`")

    with st.expander("Notes", expanded=False):
        st.markdown(f"**Refined Query:** `{_pc['refined']}`")
        st.markdown(f"**Model:** `{_pc['model']}` | **Domain:** {_pc['preset_label']}")
        st.markdown(
            f"**Results found:** {_pc['results_count']} | "
            f"**Filtered to:** {len(_pc['filtered'])} | "
            f"**Scraped:** {_pc['scraped_count']}"
        )

    with st.expander(f"Sources ({len(_pc['filtered'])} results)", expanded=False):
        st.caption("🧅 Links .onion: copia e abre no Tor Browser")
        for _i, _item in enumerate(_pc["filtered"], 1):
            _title = _item.get("title", "Untitled")
            _link = _item.get("link", "")
            if ".onion" in _link:
                st.markdown(f"**{_i}. {_title}**")
                st.code(_link, language=None)
            else:
                st.markdown(f"{_i}. [{_title}]({_link})")

    st.subheader(":red[Findings]", anchor=None, divider="gray")
    st.markdown(_pc["summary"])
    st.divider()

    _pc_pdf_data = {
        "audit_id": _pc["audit_id"],
        "query": _pc["query"],
        "refined_query": _pc["refined"],
        "model": _pc["model"],
        "preset": _pc["preset_label"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "active_engines": _pc["active_engines"],
        "sources": _pc["filtered"],
        "integrity": _pc["integrity"],
        "summary": _pc["summary"],
        "results_found": _pc["results_count"],
        "results_scraped": _pc["scraped_count"],
    }
    _pc_pdf_bytes = generate_forensic_pdf(_pc_pdf_data)

    _pc_now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    _pc_dl1, _pc_dl2 = st.columns(2)
    _pc_dl1.download_button(
        label="⬇ Download Relatório PDF",
        data=_pc_pdf_bytes,
        file_name=f"relatorio_{_pc['audit_id'][:8]}_{_pc_now}.pdf",
        mime="application/pdf",
        use_container_width=True,
        key="pc_dl_pdf",
    )
    _pc_dl2.download_button(
        label="⬇ Download Summary MD",
        data=_pc["summary"].encode(),
        file_name=f"summary_{_pc_now}.md",
        mime="text/markdown",
        use_container_width=True,
        key="pc_dl_md",
    )
