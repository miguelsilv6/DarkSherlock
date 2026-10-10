"""As escolhas da página Settings sobrevivem à mudança de página (Streamlit apaga as chaves dos widgets)."""

import settings_state as ss


def simulate_navigation(state):
    """O Streamlit apaga as chaves dos widgets que não são desenhados na página corrente."""
    for k in list(state):
        if k in ss.DEFAULTS:
            del state[k]


def test_choices_survive_navigation():
    state = {}
    options = ["Modelo A", "Modelo B"]
    # 1.ª visita à Settings: repõe defaults, o utilizador muda valores, a página persiste.
    ss.restore("model_select", ss.default_model(options), valid=options, state=state)
    ss.restore("thread_slider", state=state)
    state["model_select"] = "Modelo B"
    state["thread_slider"] = 8
    state["preset_select"] = "Ransomware / Malware Focus"
    ss.persist(state=state)
    simulate_navigation(state)          # vai para a Home
    cfg = ss.current(options, state=state)
    assert cfg["model"] == "Modelo B" and cfg["threads"] == 8
    assert cfg["selected_preset"] == "ransomware_malware"
    # volta à Settings: o widget aparece com o valor guardado, não com o default
    ss.restore("model_select", ss.default_model(options), valid=options, state=state)
    assert state["model_select"] == "Modelo B"


def test_defaults_without_visiting_settings():
    cfg = ss.current(["X", "Y"], state={})
    assert cfg["model"] == "X" and cfg["threads"] == 4 and cfg["max_results"] == 50 and cfg["max_scrape"] == 10
    assert cfg["selected_preset"] == "threat_intel" and cfg["custom_instructions"] == ""


def test_stale_model_falls_back_to_default():
    state = {"cfg_model_select": "Modelo que já não existe"}
    assert ss.current(["X"], state=state)["model"] == "X"
    ss.restore("model_select", "X", valid=["X"], state=state)
    assert state["model_select"] == "X"


def test_no_models():
    assert ss.current([], state={})["model"] is None
