"""
sidebar.py — Barra lateral partilhada entre todas as páginas do DarkSherlock.

Após a introdução da página Settings, a sidebar foi simplificada:
  - Mostra apenas o título/subtítulo da aplicação
  - Não renderiza widgets de configuração (esses estão em pages/5_🛠️_Settings.py)
  - Lê as configurações do st.session_state, onde a página Settings as guarda

Todas as páginas que chamam render_sidebar() obtêm o mesmo dicionário de
configurações, lido do session_state em vez de widgets inline.
"""

import streamlit as st
from llm_utils import get_model_choices
import settings_state


def render_sidebar() -> dict:
    """Renderiza o cabeçalho da sidebar e devolve as configurações actuais.

    As configurações são lidas do st.session_state, onde foram guardadas pela
    página Settings (pages/5_🛠️_Settings.py). Se o utilizador ainda não
    visitou a página Settings, são usados os valores por omissão.

    Retorna:
        dict com as chaves:
            model, threads, max_results, max_scrape,
            selected_preset, selected_preset_label, custom_instructions
    """
    st.sidebar.title("DarkSherlock")
    st.sidebar.text("AI-Powered Dark Web OSINT Tool")

    # Lê as definições guardadas pela página Settings (settings_state.py): as
    # chaves dos widgets são apagadas pelo Streamlit ao mudar de página, mas as
    # cópias persistentes não.
    return settings_state.current(get_model_choices())
