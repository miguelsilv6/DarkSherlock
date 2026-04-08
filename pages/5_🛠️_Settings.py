"""
5_🛠️_Settings.py — Página de configuração global do DarkSherlock.

Centraliza todas as definições do pipeline numa página dedicada:
  - Modelo LLM e threads de scraping
  - Limites de resultados e páginas
  - Domínio de investigação (preset) e instruções personalizadas
  - Estado dos providers de LLM
  - Health checks (LLM, motores de pesquisa, circuito Tor)

Todas as definições são guardadas em st.session_state com chaves estáveis,
permitindo que Home.py e Investigation.py as leiam sem precisar de as
re-renderizar nas respectivas sidebars.
"""

import streamlit as st
from llm_utils import get_model_choices
from llm import PRESET_PROMPTS
from health import check_llm_health, check_search_engines, check_tor_proxy, rotate_tor_circuit
from config import OLLAMA_BASE_URL
from sidebar import render_sidebar
from audit import setup_file_logging

setup_file_logging()

st.set_page_config(
    page_title="DarkSherlock — Settings",
    page_icon="🛠️",
    initial_sidebar_state="expanded",
)

render_sidebar()

# CSS futurista — idêntico ao Home.py
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');
    html, body, [class*="css"] {
        font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace !important;
    }
    h1 {
        font-size: 1.55rem !important; font-weight: 700 !important;
        letter-spacing: 0.12em !important; text-transform: uppercase !important;
        color: #00ff9f !important; border-bottom: 1px solid #00ff9f33 !important;
        padding-bottom: 0.4rem !important; margin-bottom: 1.4rem !important;
    }
    h2, h3 { letter-spacing: 0.06em; color: #a0f0c8; }
    input[type="text"] {
        background-color: #0d0d14 !important; border: 1px solid #00ff9f55 !important;
        border-radius: 4px !important; color: #e2e8f0 !important;
        caret-color: #00ff9f !important; font-family: inherit !important;
        transition: border-color 0.25s ease, box-shadow 0.25s ease !important;
    }
    input[type="text"]:focus {
        border-color: #00ff9f !important;
        box-shadow: 0 0 0 1px #00ff9f, 0 0 14px #00ff9f55 !important;
        outline: none !important;
    }
    .stButton > button, .stDownloadButton > button {
        background-color: transparent !important; color: #a0f0c8 !important;
        border: 1px solid #a0f0c833 !important; border-radius: 4px !important;
        transition: border-color 0.2s ease !important;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        border-color: #00ff9f !important; color: #00ff9f !important;
    }
    [data-testid="stStatusWidget"], div[data-testid="stExpander"] {
        border: 1px solid #00ff9f22 !important; border-radius: 6px !important;
        background-color: #0d0d18 !important;
    }
    [data-testid="stSidebar"] { border-right: 1px solid #00ff9f1a !important; }
    [data-testid="stAlertContainer"][kind="success"] {
        border-left: 3px solid #00ff9f !important; background-color: #00ff9f0d !important;
    }
    [data-testid="stAlertContainer"][kind="warning"] { border-left: 3px solid #ffcc00 !important; }
    [data-testid="stAlertContainer"][kind="error"]   { border-left: 3px solid #ff4444 !important; }
    </style>""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
st.title("Settings")
st.caption("Configurações globais do pipeline — persistidas na sessão actual")

# ---------------------------------------------------------------------------
# LLM Model
# ---------------------------------------------------------------------------
st.divider()
st.header("LLM Model")

model_options = get_model_choices()

default_model_index = (
    next(
        (idx for idx, name in enumerate(model_options) if name.lower() == "gpt4o"),
        0,
    )
    if model_options
    else 0
)

if not model_options:
    st.error(
        "Nenhum modelo LLM disponível.\n\n"
        "Configura pelo menos uma API key no ficheiro `.env` e reinicia o DarkSherlock.\n\n"
        "Consulta a secção **Provider Configuration** abaixo."
    )
else:
    st.selectbox(
        "Select LLM Model",
        model_options,
        index=default_model_index,
        key="model_select",
        help="Modelo utilizado em todas as etapas do pipeline: refinamento, filtragem e geração de relatório.",
    )
    if any(
        name not in {"gpt4o", "gpt-4.1", "claude-3-5-sonnet-latest", "llama3.1", "gemini-2.5-flash"}
        for name in model_options
    ):
        st.caption("Modelos Ollama locais são detectados automaticamente.")

# ---------------------------------------------------------------------------
# Pipeline Settings
# ---------------------------------------------------------------------------
st.divider()
st.header("Pipeline")

col1, col2, col3 = st.columns(3)

with col1:
    st.slider(
        "Scraping Threads",
        min_value=1,
        max_value=16,
        value=4,
        key="thread_slider",
        help="Threads paralelas para pesquisa e scraping. Mais threads = mais rápido, mas aumenta a carga no Tor.",
    )

with col2:
    st.slider(
        "Max Results to Filter",
        min_value=10,
        max_value=100,
        value=50,
        key="max_results_slider",
        help="Limite de resultados brutos enviados ao LLM na fase de filtragem.",
    )

with col3:
    st.slider(
        "Max Pages to Scrape",
        min_value=3,
        max_value=20,
        value=10,
        key="max_scrape_slider",
        help="Número máximo de páginas .onion a fazer scrape após a filtragem.",
    )

# ---------------------------------------------------------------------------
# Prompt Settings
# ---------------------------------------------------------------------------
st.divider()
st.header("Prompt Settings")
st.caption("Define o domínio de investigação e as instruções enviadas ao LLM na análise final.")

_preset_options = {
    "Dark Web Threat Intel": "threat_intel",
    "Ransomware / Malware Focus": "ransomware_malware",
    "Personal / Identity Investigation": "personal_identity",
    "Corporate Espionage / Data Leaks": "corporate_espionage",
}
_preset_placeholders = {
    "threat_intel": "e.g. Pay extra attention to cryptocurrency wallet addresses and exchange names.",
    "ransomware_malware": "e.g. Highlight any references to double-extortion tactics or known ransomware-as-a-service affiliates.",
    "personal_identity": "e.g. Flag any passport or government ID numbers and note which country they appear to be from.",
    "corporate_espionage": "e.g. Prioritize any mentions of source code repositories, API keys, or internal Slack/email dumps.",
}

selected_preset_label = st.selectbox(
    "Research Domain",
    list(_preset_options.keys()),
    key="preset_select",
    help="Determina o system prompt enviado ao LLM — orienta a análise para o contexto OSINT relevante.",
)
selected_preset = _preset_options[selected_preset_label]

with st.expander("System Prompt (read-only)"):
    st.text_area(
        "System Prompt",
        value=PRESET_PROMPTS[selected_preset].strip(),
        height=220,
        disabled=True,
        key="system_prompt_display",
        label_visibility="collapsed",
    )

st.text_area(
    "Custom Instructions (optional)",
    placeholder=_preset_placeholders[selected_preset],
    height=100,
    key="custom_instructions",
    help="Instruções adicionais anexadas ao system prompt. Permitem focar a análise em artefactos específicos.",
)

# ---------------------------------------------------------------------------
# Provider Configuration
# ---------------------------------------------------------------------------
st.divider()
st.header("Provider Configuration")
st.caption("Estado do servidor Ollama local configurado no `.env`")

if OLLAMA_BASE_URL:
    st.success(f"**Ollama** — {OLLAMA_BASE_URL}", icon="✅")
else:
    st.warning("**Ollama** — `OLLAMA_BASE_URL` não definido no `.env`", icon="⚠️")

# ---------------------------------------------------------------------------
# Health Checks
# ---------------------------------------------------------------------------
st.divider()
st.header("Health Checks")
st.caption("Testa a conectividade com o LLM, os motores de pesquisa via Tor, e o circuito Tor.")

_current_model = st.session_state.get("model_select", model_options[0] if model_options else "")

hc1, hc2, hc3 = st.columns(3)

# LLM Connection
with hc1:
    if st.button("Check LLM Connection", use_container_width=True):
        with st.spinner(f"Testing {_current_model}..."):
            result = check_llm_health(_current_model)
        if result["status"] == "up":
            st.success(f"**{result['provider']}** — {result['latency_ms']}ms")
        else:
            st.error(f"**{result['provider']}** — Failed\n\n{result['error']}")

# Search Engines
with hc2:
    if st.button("Check Search Engines", use_container_width=True):
        with st.spinner("Checking Tor proxy..."):
            tor_result = check_tor_proxy()
        if tor_result["status"] == "down":
            st.error(
                f"**Tor Proxy** — Not reachable\n\n{tor_result['error']}\n\n"
                "Run: `brew services start tor`"
            )
        else:
            st.success(f"**Tor Proxy** — {tor_result['latency_ms']}ms")
            with st.spinner("Pinging active search engines via Tor..."):
                engine_results = check_search_engines()
            up_count = sum(1 for r in engine_results if r["status"] == "up")
            total = len(engine_results)
            if up_count == total:
                st.success(f"All {total} engines reachable")
            elif up_count > 0:
                st.warning(f"{up_count}/{total} engines reachable")
            else:
                st.error(f"0/{total} engines reachable")
            with st.expander("Detalhes por motor"):
                for r in engine_results:
                    if r["status"] == "up":
                        st.markdown(f"🟢 **{r['name']}** — {r['latency_ms']}ms")
                    else:
                        st.markdown(f"🔴 **{r['name']}** — {r['error']}")

# Tor Circuit Rotation
with hc3:
    if st.button("Rodar Circuito Tor", use_container_width=True):
        with st.spinner("A solicitar novo circuito Tor..."):
            result = rotate_tor_circuit()
        if result["status"] == "rotated":
            st.success(result["message"])
        else:
            st.warning(result["message"])
