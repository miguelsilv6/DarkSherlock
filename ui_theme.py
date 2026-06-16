"""
ui_theme.py — Tema visual partilhado do DarkSherlock (Streamlit).

Centraliza o CSS futurista/terminal (verde neon #00ff9f + JetBrains Mono) que
antes estava duplicado em Home.py, Settings.py e pages/1_⚙️_Search_Engines.py.

Uso:
    from ui_theme import inject_theme
    inject_theme()   # chamar logo após st.set_page_config(...)

Mudanças ao tema só precisam de ser feitas aqui — todas as páginas que
chamam `inject_theme()` reflectem a mudança automaticamente.
"""

import streamlit as st


_THEME_CSS = """
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

[data-testid="stStatusWidget"], div[data-testid="stExpander"] {
    border: 1px solid #00ff9f22 !important;
    border-radius: 6px !important;
    background-color: #0d0d18 !important;
}

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

[data-testid="stSidebar"] { border-right: 1px solid #00ff9f1a !important; }

[data-testid="stAlertContainer"][kind="success"] {
    border-left: 3px solid #00ff9f !important;
    background-color: #00ff9f0d !important;
}
[data-testid="stAlertContainer"][kind="warning"] { border-left: 3px solid #ffcc00 !important; }
[data-testid="stAlertContainer"][kind="error"]   { border-left: 3px solid #ff4444 !important; }

.aStyle {
    font-size: 18px; font-weight: bold;
    padding: 5px; padding-left: 0px;
    text-align: left; color: #00ff9f;
}
</style>
"""


def inject_theme() -> None:
    """Injecta o CSS global do DarkSherlock na página actual.

    Chamar logo após `st.set_page_config(...)`. Idempotente: o Streamlit
    aplica o último bloco CSS injectado, pelo que múltiplas chamadas não
    causam problemas.
    """
    st.markdown(_THEME_CSS, unsafe_allow_html=True)
