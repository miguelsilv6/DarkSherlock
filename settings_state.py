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

Os valores ficam também gravados em `config/ui_settings.json` (fora do Git):
sem isto, cada reinício da app (p. ex. pelo update.sh) apagava as definições e
as investigações voltavam a correr com o modelo por omissão sem o utilizador
dar por isso.

As funções aceitam um `state` (dicionário) para poderem ser testadas sem
Streamlit; por omissão usam `st.session_state`.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

PREFIX = "cfg_"
SETTINGS_FILE = Path("config") / "ui_settings.json"

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


def load_file() -> dict:
    """Definições gravadas em disco ({} se não houver ficheiro ou estiver corrompido)."""
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        return {k: v for k, v in data.items() if k in DEFAULTS} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_file(values: dict) -> None:
    """Grava as definições (escrita atómica: um ficheiro temporário substitui o antigo)."""
    values = {k: v for k, v in values.items() if k in DEFAULTS}
    if values == load_file():
        return
    try:
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=SETTINGS_FILE.parent, suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(values, f, ensure_ascii=False, indent=2)
        os.replace(tmp, SETTINGS_FILE)
    except OSError:
        pass  # as definições continuam válidas nesta sessão


def save_value(key: str, value) -> None:
    """Grava uma definição isolada (p. ex. o domínio escolhido nos botões da Home)."""
    save_file({**load_file(), key: value})


def default_model(options: list[str]):
    """Modelo por omissão: o maior embutido já descarregado (local_models.preferred_default_model),
    senão um 'dolphin' do Ollama, senão o primeiro."""
    if not options:
        return None
    try:
        import local_models
        preferred = local_models.preferred_default_model()
        if preferred in options:
            return preferred
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
    saved = load_file()
    if key in saved:
        return saved[key]
    return DEFAULTS.get(key) if default is None else default


def restore(key: str, default=None, valid=None, state=None) -> None:
    """Antes de desenhar o widget: põe na chave do widget o valor persistido (ou o default).

    `valid`: lista de valores aceitáveis (p. ex. modelos disponíveis); um valor
    persistido que já não seja válido é substituído pelo default.
    """
    s = _state(state)
    if key in s:
        return
    fallback = DEFAULTS.get(key) if default is None else default
    value = s[PREFIX + key] if PREFIX + key in s else load_file().get(key, fallback)
    if valid is not None and value not in valid:
        value = DEFAULTS.get(key) if default is None else default
    s[key] = value


def persist(keys=None, state=None) -> None:
    """Depois de desenhar os widgets: copia os valores para as chaves persistentes."""
    s = _state(state)
    for key in keys or DEFAULTS:
        if key in s:
            s[PREFIX + key] = s[key]
    save_file({**load_file(), **{k: s[PREFIX + k] for k in DEFAULTS if PREFIX + k in s}})


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
