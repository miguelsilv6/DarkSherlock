"""
settings_state.py — Persistência das definições da página Settings entre páginas.

O Streamlit apaga do `st.session_state` a chave de um widget quando corre uma
página que não desenha esse widget. Como os widgets das definições só existem
na página Settings, ao voltar à Home as chaves `model_select`, `thread_slider`,
etc. desapareciam e a investigação corria com os valores por omissão — o modelo
e os parâmetros escolhidos pelo utilizador eram ignorados.

Solução: cada valor é copiado para uma chave "persistente" (prefixo `cfg_`), que
não pertence a nenhum widget e por isso não é apagada. A página Settings repõe o
valor guardado antes de desenhar cada widget e volta a guardá-lo no fim; as
outras páginas leem com `get()`.

As funções aceitam um `state` (dicionário) para poderem ser testadas sem
Streamlit; por omissão usam `st.session_state`.
"""

from __future__ import annotations

PREFIX = "cfg_"

# chave do widget -> valor por omissão (o do modelo é calculado à parte)
DEFAULTS = {
    "model_select": None,
    "thread_slider": 4,
    "max_results_slider": 50,
    "max_scrape_slider": 10,
    "preset_select": "Dark Web Threat Intel",
    "custom_instructions": "",
}

PRESET_OPTIONS = {
    "Dark Web Threat Intel": "threat_intel",
    "Ransomware / Malware Focus": "ransomware_malware",
    "Personal / Identity Investigation": "personal_identity",
    "Corporate Espionage / Data Leaks": "corporate_espionage",
}


def _state(state=None):
    if state is not None:
        return state
    import streamlit as st
    return st.session_state


def default_model(options: list[str]):
    """Modelo por omissão: o embutido por omissão, senão um 'dolphin' do Ollama, senão o primeiro."""
    if not options:
        return None
    try:
        import local_models
        if local_models.DEFAULT_BUILTIN_MODEL in options:
            return local_models.DEFAULT_BUILTIN_MODEL
    except Exception:  # noqa: BLE001 — sem llama.cpp continua a haver Ollama
        pass
    for name in options:
        if "dolphin" in name.lower():
            return name
    return options[0]


def get(key: str, default=None, state=None):
    """Valor atual de uma definição: o do widget (se estiver desenhado), senão o persistido, senão o default."""
    s = _state(state)
    if key in s:
        return s[key]
    if PREFIX + key in s:
        return s[PREFIX + key]
    return DEFAULTS.get(key) if default is None else default


def restore(key: str, default=None, valid=None, state=None) -> None:
    """Antes de desenhar o widget: põe na chave do widget o valor persistido (ou o default).

    `valid`: lista de valores aceitáveis (p. ex. modelos disponíveis); um valor
    persistido que já não seja válido é substituído pelo default.
    """
    s = _state(state)
    if key in s:
        return
    value = s.get(PREFIX + key, DEFAULTS.get(key) if default is None else default)
    if valid is not None and value not in valid:
        value = DEFAULTS.get(key) if default is None else default
    s[key] = value


def persist(keys=None, state=None) -> None:
    """Depois de desenhar os widgets: copia os valores para as chaves persistentes."""
    s = _state(state)
    for key in keys or DEFAULTS:
        if key in s:
            s[PREFIX + key] = s[key]


def current(model_options: list[str], state=None) -> dict:
    """Todas as definições, já resolvidas, para o pipeline."""
    model = get("model_select", default_model(model_options), state)
    if model_options and model not in model_options:
        model = default_model(model_options)
    label = get("preset_select", state=state)
    return {
        "model": model,
        "threads": int(get("thread_slider", state=state)),
        "max_results": int(get("max_results_slider", state=state)),
        "max_scrape": int(get("max_scrape_slider", state=state)),
        "selected_preset_label": label,
        "selected_preset": PRESET_OPTIONS.get(label, "threat_intel"),
        "custom_instructions": get("custom_instructions", state=state) or "",
    }
