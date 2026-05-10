"""
sidebar.py — Barra lateral partilhada entre todas as páginas do DarkSherlock.

Após a introdução da página Settings, a sidebar foi simplificada:
  - Mostra apenas o título/subtítulo da aplicação
  - Não renderiza widgets de configuração (esses estão em pages/4_🛠️_Settings.py)
  - Lê as configurações do st.session_state, onde a página Settings as guarda

Todas as páginas que chamam render_sidebar() obtêm o mesmo dicionário de
configurações, lido do session_state em vez de widgets inline.
"""

import streamlit as st
from llm_utils import get_model_choices


def render_sidebar() -> dict:
    """Renderiza o cabeçalho da sidebar e devolve as configurações actuais.

    As configurações são lidas do st.session_state, onde foram guardadas pela
    página Settings (pages/4_🛠️_Settings.py). Se o utilizador ainda não
    visitou a página Settings, são usados os valores por omissão.

    Retorna:
        dict com as chaves:
            model, threads, max_results, max_scrape,
            selected_preset, selected_preset_label, custom_instructions
    """
    st.sidebar.title("DarkSherlock")
    st.sidebar.text("AI-Powered Dark Web OSINT Tool")

    # ---------------------------------------------------------------------------
    # Toggle Human-in-the-Loop (HITL) — opt-in, default False
    # ---------------------------------------------------------------------------
    # Quando activo, o pipeline pausa em 3 checkpoints (Stage 2, 4 e 5) para
    # permitir ao analista rever, editar ou excluir outputs intermédios.
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

    # ---------------------------------------------------------------------------
    # Lê configurações do session_state (guardadas pela página Settings)
    # ---------------------------------------------------------------------------
    _preset_options = {
        "Dark Web Threat Intel":          "threat_intel",
        "Ransomware / Malware Focus":     "ransomware_malware",
        "Personal / Identity Investigation": "personal_identity",
        "Corporate Espionage / Data Leaks":  "corporate_espionage",
    }

    model_options = get_model_choices()
    _default_model = model_options[0] if model_options else None

    model               = st.session_state.get("model_select",      _default_model)
    threads             = st.session_state.get("thread_slider",     4)
    max_results         = st.session_state.get("max_results_slider", 50)
    max_scrape          = st.session_state.get("max_scrape_slider",  10)
    selected_preset_label = st.session_state.get("preset_select", "Dark Web Threat Intel")
    selected_preset     = _preset_options.get(selected_preset_label, "threat_intel")
    custom_instructions = st.session_state.get("custom_instructions", "")

    return {
        "model":                  model,
        "threads":                threads,
        "max_results":            max_results,
        "max_scrape":             max_scrape,
        "selected_preset":        selected_preset,
        "selected_preset_label":  selected_preset_label,
        "custom_instructions":    custom_instructions,
        "hitl_mode":              st.session_state.get("hitl_mode", False),
    }
