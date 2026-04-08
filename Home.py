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
from llm import get_llm, refine_query, filter_results, generate_summary, PRESET_PROMPTS
from engine_manager import get_active_engines
from report import compute_integrity_hashes, generate_forensic_pdf
from audit import log_investigation, setup_file_logging

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

@st.cache_data(ttl=200, show_spinner=False)
def cached_search_results(refined_query: str):
    """Executa a pesquisa nos motores da dark web com cache por 200 segundos.

    O espaço é substituído por `+` para conformidade com a codificação
    de parâmetros de pesquisa esperada pelos motores .onion suportados.

    Nota: o número de threads não faz parte da chave de cache porque não
    afecta os resultados — apenas a velocidade de obtenção. Incluí-lo
    causava cache misses desnecessários quando o utilizador ajustava o
    slider de threads entre execuções com a mesma query.

    Args:
        refined_query: Consulta refinada pelo LLM.

    Returns:
        Lista de resultados brutos (dicionários com `title` e `link`).
    """
    return get_search_results(refined_query.replace(" ", "+"), max_workers=4)


@st.cache_data(ttl=200, show_spinner=False)
def cached_scrape_multiple(filtered: list, threads: int):
    """Extrai o conteúdo textual das páginas filtradas com cache por 200 segundos.

    A cache é especialmente valiosa aqui porque o scraping de páginas .onion
    através do Tor pode ser muito lento (latências de vários segundos por
    página). Se o utilizador reexecutar o pipeline com a mesma lista de URLs
    filtrados dentro de 200 segundos, o conteúdo é devolvido imediatamente.

    Args:
        filtered: Lista de resultados filtrados (devolvida pela etapa 4).
        threads:  Número de fios de execução paralela para o scraping.

    Returns:
        Dicionário `{url: conteúdo_textual}` para cada página processada.
    """
    return scrape_multiple(filtered, max_workers=threads)


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

# CSS futurista — tema cyber/terminal para o DarkSherlock.
# Injeta estilos globais para tipografia monoespaçada, glow no input de pesquisa,
# botões com estilo neon, pills de preset com highlight, e containers do pipeline.
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace !important;
    }

    h1 {
        font-size: 1.55rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.12em !important;
        text-transform: uppercase !important;
        color: #00ff9f !important;
        border-bottom: 1px solid #00ff9f33 !important;
        padding-bottom: 0.4rem !important;
        margin-bottom: 1.4rem !important;
    }
    h2, h3 { letter-spacing: 0.06em; color: #a0f0c8; }

    /* Input de pesquisa com glow neon */
    input[type="text"] {
        background-color: #0d0d14 !important;
        border: 1px solid #00ff9f55 !important;
        border-radius: 4px !important;
        color: #e2e8f0 !important;
        caret-color: #00ff9f !important;
        transition: border-color 0.25s ease, box-shadow 0.25s ease !important;
        font-family: inherit !important;
    }
    input[type="text"]:focus {
        border-color: #00ff9f !important;
        box-shadow: 0 0 0 1px #00ff9f, 0 0 14px #00ff9f55 !important;
        outline: none !important;
    }

    /* Botão primário (Run / form submit) */
    button[kind="primaryFormSubmit"],
    button[data-testid="baseButton-primary"],
    .stButton > button[kind="primary"] {
        background-color: #00ff9f14 !important;
        color: #00ff9f !important;
        border: 1px solid #00ff9f !important;
        border-radius: 4px !important;
        font-weight: 600 !important;
        transition: background-color 0.2s ease, box-shadow 0.2s ease !important;
    }
    button[kind="primaryFormSubmit"]:hover,
    button[data-testid="baseButton-primary"]:hover,
    .stButton > button[kind="primary"]:hover {
        background-color: #00ff9f2a !important;
        box-shadow: 0 0 10px #00ff9f55 !important;
    }

    /* Botões secundários (download, load, etc.) */
    .stButton > button, .stDownloadButton > button {
        background-color: transparent !important;
        color: #a0f0c8 !important;
        border: 1px solid #a0f0c833 !important;
        border-radius: 4px !important;
        transition: border-color 0.2s ease !important;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        border-color: #00ff9f !important;
        color: #00ff9f !important;
    }

    /* Containers das etapas do pipeline e expanders */
    [data-testid="stStatusWidget"], div[data-testid="stExpander"] {
        border: 1px solid #00ff9f22 !important;
        border-radius: 6px !important;
        background-color: #0d0d18 !important;
    }

    /* Pills do selector de preset */
    div[data-testid="stPillsButton"] button {
        background-color: #0d0d18 !important;
        border: 1px solid #00ff9f33 !important;
        color: #7a9e8e !important;
        border-radius: 4px !important;
        font-weight: 500 !important;
        letter-spacing: 0.04em !important;
        transition: all 0.2s ease !important;
    }
    div[data-testid="stPillsButton"] button[aria-checked="true"] {
        background-color: #00ff9f18 !important;
        border-color: #00ff9f !important;
        color: #00ff9f !important;
        box-shadow: 0 0 8px #00ff9f44 !important;
    }
    div[data-testid="stPillsButton"] button:hover {
        border-color: #00ff9f88 !important;
        color: #c0ffe0 !important;
    }

    /* Sidebar com borda neon subtil */
    [data-testid="stSidebar"] { border-right: 1px solid #00ff9f1a !important; }

    /* Alertas com borda esquerda colorida */
    [data-testid="stAlertContainer"][kind="success"] {
        border-left: 3px solid #00ff9f !important;
        background-color: #00ff9f0d !important;
    }
    [data-testid="stAlertContainer"][kind="warning"] { border-left: 3px solid #ffcc00 !important; }
    [data-testid="stAlertContainer"][kind="error"]   { border-left: 3px solid #ff4444 !important; }

    /* Hiperligação de download legacy */
    .aStyle {
        font-size: 18px; font-weight: bold;
        padding: 5px; padding-left: 0px;
        text-align: left; color: #00ff9f;
    }
    </style>""",
    unsafe_allow_html=True,
)


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
    "Corporate Espionage / Data Leaks":  "corporate_espionage",
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

    # Limpa qualquer investigação carregada e os dados residuais de um
    # pipeline anterior para garantir um estado limpo antes de começar.
    # Sem esta limpeza, dados de uma pesquisa anterior poderiam contaminar
    # os resultados da pesquisa atual se alguma etapa falhasse.
    st.session_state.pop("loaded_investigation", None)
    for k in ["refined", "results", "filtered", "scraped", "streamed_summary"]:
        st.session_state.pop(k, None)

    # Obtém a lista de motores de pesquisa activos para uso na Etapa 3
    active_engines = get_active_engines()

    # Marca o início do pipeline para calcular o tempo total no final
    pipeline_start = time.time()

    # ------------------------------------------------------------------
    # Etapa 1/6 — Carregamento do modelo de linguagem
    # ------------------------------------------------------------------
    # `st.status` cria um painel expansível com indicadores visuais de
    # progresso (em curso / concluído / erro). `expanded=True` mantém o
    # painel aberto durante a execução para que o utilizador veja os
    # detalhes em tempo real; após conclusão, o painel pode ser colapsado.
    # Esta etapa instancia o cliente do LLM selecionado — pode incluir
    # validação da chave de API e estabelecimento de ligação com o servidor.
    with st.status("**Stage 1/6** — Loading LLM...", expanded=True) as status:
        t0 = time.time()
        try:
            llm = get_llm(model)
            elapsed = round((time.time() - t0) * 1000)
            st.write(f"Model: `{model}`")
            status.update(label=f"**Stage 1/6** — LLM loaded ({_fmt_ms(elapsed)})", state="complete")
        except Exception as e:
            status.update(label="**Stage 1/6** — LLM failed", state="error")
            # `_render_pipeline_error` mostra a mensagem e chama `st.stop()`,
            # interrompendo a execução das etapas seguintes.
            _render_pipeline_error("load the selected LLM", e)

    # ------------------------------------------------------------------
    # Etapa 2/6 — Refinamento da consulta com o LLM
    # ------------------------------------------------------------------
    # A consulta original do utilizador é reformulada pelo LLM para ser
    # mais eficaz nos motores de pesquisa da dark web. Por exemplo, termos
    # vagos são enriquecidos com vocabulário técnico ou operacional
    # característico dos fóruns e mercados que se pretende pesquisar.
    # O resultado refinado é guardado em `st.session_state` para ser
    # reutilizado nas etapas seguintes sem necessidade de o recalcular.
    with st.status("**Stage 2/6** — Refining query...", expanded=True) as status:
        t0 = time.time()
        try:
            st.session_state.refined = refine_query(llm, query, preset=selected_preset)
            elapsed = round((time.time() - t0) * 1000)
            st.write(f"Original: `{query}`")
            st.write(f"Refined: `{st.session_state.refined}`")
            status.update(label=f"**Stage 2/6** — Query refined ({_fmt_ms(elapsed)})", state="complete")
        except Exception as e:
            status.update(label="**Stage 2/6** — Query refinement failed", state="error")
            _render_pipeline_error("refine the query", e)

    # ------------------------------------------------------------------
    # Etapa 3/6 — Pesquisa distribuída nos motores da dark web
    # ------------------------------------------------------------------
    # A consulta refinada é enviada em paralelo a todos os motores de
    # pesquisa .onion activos (ex.: Ahmia, Torch, DarkSearch) via proxy Tor.
    # O paralelismo é controlado pelo parâmetro `threads` definido na barra
    # lateral. Os resultados brutos são truncados ao limite `max_results`
    # e deduplicados por URL para evitar que a mesma fonte seja processada
    # várias vezes nas etapas seguintes.
    with st.status(f"**Stage 3/6** — Searching {len(active_engines)} engines...", expanded=True) as status:
        t0 = time.time()
        # search.py já deduplica os resultados por URL — não é necessário
        # repetir o processo aqui. A deduplicação dupla era redundante e O(2n).
        st.session_state.results = cached_search_results(st.session_state.refined)

        # Aplica o limite máximo de resultados configurado na barra lateral
        if len(st.session_state.results) > max_results:
            st.session_state.results = st.session_state.results[:max_results]

        elapsed = round((time.time() - t0) * 1000)

        # Estampar cada resultado com o timestamp UTC de recolha (imutável)
        retrieved_at_utc = datetime.now(timezone.utc).isoformat()
        for r in st.session_state.results:
            r["retrieved_at_utc"] = retrieved_at_utc

        st.write(f"Found **{len(st.session_state.results)}** results across {len(active_engines)} engines")
        status.update(
            label=f"**Stage 3/6** — {len(st.session_state.results)} results found ({_fmt_ms(elapsed)})",
            state="complete",
        )

    # ------------------------------------------------------------------
    # Etapa 4/6 — Filtragem por relevância com o LLM
    # ------------------------------------------------------------------
    # O LLM avalia cada resultado bruto (título e URL) e seleciona os que
    # são mais relevantes para a consulta e para o domínio de investigação
    # escolhido. Esta filtragem é necessária porque os motores de pesquisa
    # da dark web têm menor precisão do que os motores da web convencional —
    # muitos resultados são spam, páginas de erro ou conteúdo não relacionado.
    # Os resultados filtrados são ainda truncados ao limite `max_scrape`
    # para controlar o tempo e o custo da etapa de extração seguinte.
    with st.status("**Stage 4/6** — Filtering results with LLM...", expanded=True) as status:
        t0 = time.time()
        st.session_state.filtered = filter_results(
            llm, st.session_state.refined, st.session_state.results
        )

        # Aplica o limite máximo de páginas a extrair configurado na barra lateral
        if len(st.session_state.filtered) > max_scrape:
            st.session_state.filtered = st.session_state.filtered[:max_scrape]

        elapsed = round((time.time() - t0) * 1000)
        st.write(f"Filtered to **{len(st.session_state.filtered)}** most relevant results")

        # Apresenta os URLs filtrados num expansor. Os URLs .onion não podem
        # ser abertos como hiperligações normais — são apresentados como bloco
        # de código copiável para que o utilizador os possa colar no Tor Browser.
        with st.expander("View filtered results"):
            st.caption("🧅 Links .onion: copia e abre no Tor Browser")
            for i, item in enumerate(st.session_state.filtered, 1):
                title = item.get("title", "Untitled")
                link = item.get("link", "")
                if ".onion" in link:
                    # URL .onion: apresenta como texto copiável, não como
                    # hiperligação, porque os navegadores normais não resolvem
                    # domínios .onion sem o proxy Tor configurado.
                    st.markdown(f"**{i}. {title}**")
                    st.code(link, language=None)
                else:
                    # URL convencional (ex.: i2p ou clearnet): pode ser uma
                    # hiperligação clicável directamente no navegador.
                    st.markdown(f"{i}. [{title}]({link})")

        status.update(
            label=f"**Stage 4/6** — Filtered to {len(st.session_state.filtered)} results ({_fmt_ms(elapsed)})",
            state="complete",
        )

    # ------------------------------------------------------------------
    # Etapa 5/6 — Extracção de conteúdo (scraping)
    # ------------------------------------------------------------------
    # As páginas filtradas são acedidas via proxy Tor e o seu conteúdo
    # textual é extraído. O scraping é feito em paralelo (controlado por
    # `threads`) para mitigar a latência inerente à rede Tor.
    # Após a extracção, as páginas com conteúdo muito curto (menos de 150
    # caracteres) são descartadas — tipicamente correspondem a páginas de
    # erro, redireccionamentos ou domínios que já não estão activos.
    # O limiar de 150 caracteres é suficiente para filtrar respostas de erro
    # genéricas (ex.: "403 Forbidden") mas suficientemente baixo para não
    # descartar páginas legítimas com conteúdo escasso.
    with st.status(f"**Stage 5/6** — Scraping {len(st.session_state.filtered)} pages...", expanded=True) as status:
        t0 = time.time()
        st.session_state.scraped = cached_scrape_multiple(
            st.session_state.filtered, threads
        )

        # Filtra resultados com conteúdo insuficiente (páginas inacessíveis
        # ou que devolveram apenas o título sem corpo de texto significativo)
        meaningful_scraped = {
            url: content
            for url, content in st.session_state.scraped.items()
            if len(content) > 150
        }

        # Estampar cada fonte com o timestamp UTC de scraping
        scraped_at_utc = datetime.now(timezone.utc).isoformat()
        for item in st.session_state.filtered:
            if item.get("link", "") in meaningful_scraped:
                item["scraped_at_utc"] = scraped_at_utc

        # Calcular hashes SHA-256 para cadeia de custódia forense
        integrity = compute_integrity_hashes(meaningful_scraped)
        st.session_state.integrity = integrity

        elapsed = round((time.time() - t0) * 1000)
        scraped_count = len(meaningful_scraped)
        failed_count = len(st.session_state.scraped) - scraped_count

        note = f" ({failed_count} inaccessible pages removed)" if failed_count else ""
        st.write(f"Scraped **{scraped_count}** pages with content{note}")
        st.caption(f"Hash global SHA-256: `{integrity['overall_sha256'][:16]}...`")

        # Expande para mostrar o conteúdo efectivamente recolhido em cada fonte.
        # Permite ao utilizador verificar o que foi raspado antes do Stage 6,
        # tornando o pipeline transparente e auditável.
        # O LLM analisa este mesmo conteúdo em detalhe na Etapa 6/6.
        with st.expander(f"📄 Conteúdo recolhido por fonte ({scraped_count})", expanded=False):
            st.caption("Texto extraído de cada página — o LLM lê e analisa este conteúdo na Etapa 6/6")
            for url, content in list(meaningful_scraped.items()):
                # Recupera o título a partir dos resultados filtrados
                title = next(
                    (r.get("title", "Sem título") for r in st.session_state.filtered
                     if r.get("link") == url),
                    "Sem título",
                )
                st.markdown(f"**{title}**")
                # Links .onion como bloco copiável; clearweb como inline code
                if ".onion" in url:
                    st.code(url, language=None)
                else:
                    st.markdown(f"`{url}`")
                # Excerto dos primeiros 500 caracteres do conteúdo raspado
                excerpt = content[:500].strip()
                if len(content) > 500:
                    excerpt += " …"
                st.markdown(f"*{excerpt}*")
                st.divider()

        status.update(
            label=f"**Stage 5/6** — {scraped_count} pages scraped ({_fmt_ms(elapsed)})",
            state="complete",
        )

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

    # Inicializa a cadeia de texto do relatório no estado de sessão para
    # que o callback `ui_emit` possa acumular os fragmentos incrementalmente.
    st.session_state.streamed_summary = ""

    # Cria o contentor do relatório acima do painel de estado da Etapa 6.
    # Desta forma o relatório aparece visualmente antes do painel de estado,
    # proporcionando uma leitura mais natural do topo para o fundo.
    findings_container = st.container()
    with findings_container:
        st.subheader(":red[Findings]", anchor=None, divider="gray")
        # `st.empty()` cria um espaço reservado que pode ser actualizado
        # repetidamente sem adicionar novos elementos à página — essencial
        # para o efeito de streaming incremental.
        summary_slot = st.empty()

    def ui_emit(chunk: str):
        """Callback invocado pelo `BufferedStreamingHandler` a cada fragmento do LLM.

        Acumula o texto gerado em `streamed_summary` e actualiza o componente
        `summary_slot` com o texto completo acumulado até ao momento.
        A substituição completa do texto (em vez de apenas acrescentar o
        fragmento) garante que o Markdown é renderizado correctamente mesmo
        quando os fragmentos dividem elementos de formatação (ex.: `**negrito**`
        dividido entre dois fragmentos consecutivos).

        Args:
            chunk: Fragmento de texto devolvido pelo LLM nesta iteração.
        """
        st.session_state.streamed_summary += chunk
        summary_slot.markdown(st.session_state.streamed_summary)

    # O painel de estado da Etapa 6 fica visível enquanto o LLM está a gerar
    # o relatório, indicando ao utilizador que o pipeline ainda está em curso.
    with st.status("**Stage 6/6** — Generating intelligence summary...", expanded=True) as status:
        t0 = time.time()

        # Configura o handler de streaming e associa-o ao cliente do LLM.
        # O `BufferedStreamingHandler` garante que fragmentos muito pequenos
        # são agrupados antes de actualizar a interface, reduzindo o número
        # de re-renders e melhorando o desempenho visual.
        stream_handler = BufferedStreamingHandler(ui_callback=ui_emit)
        llm.callbacks = [stream_handler]

        # Invoca a geração do relatório. O resultado da função não é usado
        # directamente porque o texto já foi acumulado em `streamed_summary`
        # pelo callback `ui_emit` durante o streaming.
        _ = generate_summary(
            llm, query, meaningful_scraped,
            preset=selected_preset, custom_instructions=custom_instructions,
        )
        elapsed = round((time.time() - t0) * 1000)
        status.update(
            label=f"**Stage 6/6** — Summary generated ({_fmt_ms(elapsed)})",
            state="complete",
        )

    # ------------------------------------------------------------------
    # Persistência e apresentação final dos resultados
    # ------------------------------------------------------------------

    total_elapsed = round(time.time() - pipeline_start, 1)
    pipeline_ms = int(total_elapsed * 1000)

    # Gerar ID único para esta investigação (usado no PDF e no log de auditoria)
    audit_id = str(uuid.uuid4())
    integrity = st.session_state.get("integrity", {})

    # Guardar investigação em disco com campos forenses completos
    _fname = save_investigation(
        query=query,
        refined_query=st.session_state.refined,
        model=model,
        preset_label=selected_preset_label,
        sources=st.session_state.filtered,
        summary=st.session_state.streamed_summary,
        audit_id=audit_id,
        active_engines=[e["name"] for e in active_engines],
        integrity=integrity,
    )

    # Registar no log de auditoria
    log_investigation({
        "audit_id": audit_id,
        "query": query,
        "refined_query": st.session_state.refined,
        "model": model,
        "preset": selected_preset_label,
        "engines_active": [e["name"] for e in active_engines],
        "results_found": len(st.session_state.results),
        "results_filtered": len(st.session_state.filtered),
        "results_scraped": scraped_count,
        "summary_length_chars": len(st.session_state.streamed_summary),
        "pipeline_duration_ms": pipeline_ms,
        "errors": [],
    })

    st.success(f"Pipeline completed in {_fmt_ms(pipeline_ms)} — saved as `{_fname}`")

    # Expansor com metadados da investigação: permite ao utilizador verificar
    # rapidamente os parâmetros usados sem ter de reler o relatório completo.
    with st.expander("Notes", expanded=False):
        st.markdown(f"**Refined Query:** `{st.session_state.refined}`")
        st.markdown(f"**Model:** `{model}` | **Domain:** {selected_preset_label}")
        st.markdown(
            f"**Results found:** {len(st.session_state.results)} | "
            f"**Filtered to:** {len(st.session_state.filtered)} | "
            f"**Scraped:** {scraped_count}"
        )

    # Lista de fontes utilizadas na geração do relatório.
    # Os URLs .onion são tratados da mesma forma que na Etapa 4: apresentados
    # como texto copiável em vez de hiperligações, dado que requerem o
    # Tor Browser para serem acedidos.
    with st.expander(f"Sources ({len(st.session_state.filtered)} results)", expanded=False):
        st.caption("🧅 Links .onion: copia e abre no Tor Browser")
        for i, item in enumerate(st.session_state.filtered, 1):
            title = item.get("title", "Untitled")
            link = item.get("link", "")
            if ".onion" in link:
                st.markdown(f"**{i}. {title}**")
                st.code(link, language=None)
            else:
                st.markdown(f"{i}. [{title}]({link})")

    # Apresenta o relatório final no contentor criado antes da Etapa 6 e
    # acrescenta uma hiperligação de transferência em Base64.
    # A codificação Base64 é necessária porque o Streamlit não oferece um
    # mecanismo nativo de transferência de ficheiros gerados dinamicamente;
    # a abordagem com `data:` URI é a alternativa mais simples e portátil.
    with findings_container:
        st.markdown(st.session_state.streamed_summary)
        st.divider()

        # Gerar PDF forense e oferecer botões de download
        pdf_data = {
            "audit_id": audit_id,
            "query": query,
            "refined_query": st.session_state.refined,
            "model": model,
            "preset": selected_preset_label,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "active_engines": [e["name"] for e in active_engines],
            "sources": st.session_state.filtered,
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
        md_bytes = st.session_state.streamed_summary.encode()
        dl_col2.download_button(
            label="⬇ Download Summary MD",
            data=md_bytes,
            file_name=f"summary_{now}.md",
            mime="text/markdown",
            use_container_width=True,
        )
