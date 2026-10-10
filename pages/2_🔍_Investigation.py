"""Investigation Pipeline — full visibility into each stage."""

import json
import streamlit as st
import settings_state
from datetime import datetime, timezone
from pathlib import Path


def _fmt_ms(ms: int) -> str:
    """Format milliseconds as Xm YYs or Xs."""
    total_s = ms // 1000
    m, s = divmod(total_s, 60)
    if m > 0:
        return f"{m}m{s:02d}s"
    return f"{total_s}s" if total_s >= 1 else f"{ms}ms"

import pipeline
from engine_manager import get_active_engines
from report import generate_forensic_pdf, investigation_pdf_data
from ui_pipeline import complete_dict, render_links, run_with_ui
from audit import log_investigation, setup_file_logging

# Configura o logging para ficheiro (captura debug/info de todos os módulos)
setup_file_logging()
from sidebar import render_sidebar
from ui_theme import inject_theme

st.set_page_config(
    page_title="DarkSherlock — Investigation Pipeline",
    page_icon="🔍",
    initial_sidebar_state="expanded",
)


def _stage_error(stage: str, err: Exception) -> None:
    """Mostra o erro de uma etapa e para a execução (em vez de um traceback)."""
    st.error(f"Failed to {stage}.\n\nError: {str(err).strip() or err.__class__.__name__}")
    st.stop()

settings = render_sidebar()
model = settings["model"]
threads = settings["threads"]
max_results = settings["max_results"]
max_scrape = settings["max_scrape"]
selected_preset = settings["selected_preset"]
selected_preset_label = settings["selected_preset_label"]
custom_instructions = settings["custom_instructions"]

inject_theme()

# --- Past Investigations (sidebar) ---
INVESTIGATIONS_DIR = Path("investigations")


def load_investigations():
    if not INVESTIGATIONS_DIR.exists():
        return []
    files = sorted(INVESTIGATIONS_DIR.glob("investigation_*.json"), reverse=True)
    investigations = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            data["_filename"] = f.name
            investigations.append(data)
        except Exception:
            continue
    return investigations


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


# --- Main Content ---
st.title("Investigation Pipeline")

active_engines = get_active_engines()
st.caption(f"{len(active_engines)} search engines ativos")

# --- Engine status notification ---
if "last_engine_check" in st.session_state:
    check_data = st.session_state["last_engine_check"]
    results = check_data["results"]
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
# Selector de domínio de investigação (preset pills)
# ---------------------------------------------------------------------------
_PRESET_LABELS_INV = [
    "Dark Web Threat Intel",
    "Ransomware / Malware Focus",
    "Personal / Identity Investigation",
    "Corporate Espionage / Data Leaks",
]
_PRESET_MAP_INV = {
    "Dark Web Threat Intel": "threat_intel",
    "Ransomware / Malware Focus": "ransomware_malware",
    "Personal / Identity Investigation": "personal_identity",
    "Corporate Espionage / Data Leaks": "corporate_espionage",
}
_PRESET_ICONS_INV = ["🌐", "🦠", "🪪", "🏢"]
_PRESET_PILLS_INV = [f"{icon}  {label}" for icon, label in zip(_PRESET_ICONS_INV, _PRESET_LABELS_INV)]


def _sync_preset_inv():
    """Callback on_change das pills → sincroniza com o selectbox da sidebar."""
    val = st.session_state.get("preset_pills")
    if val:
        label = val.split("  ", 1)[1]
        st.session_state["preset_select"] = label
        st.session_state[settings_state.PREFIX + "preset_select"] = label
        settings_state.save_value("preset_select", label)


_current_label_inv = settings_state.get("preset_select", _PRESET_LABELS_INV[0])
_default_idx_inv = (
    _PRESET_LABELS_INV.index(_current_label_inv)
    if _current_label_inv in _PRESET_LABELS_INV
    else 0
)

st.markdown("##### Investigation Domain")
st.pills(
    label="Investigation Domain",
    options=_PRESET_PILLS_INV,
    default=_PRESET_PILLS_INV[_default_idx_inv],
    selection_mode="single",
    label_visibility="collapsed",
    key="preset_pills",
    on_change=_sync_preset_inv,
)

# Sobrepõe o preset com o valor das pills (se já foi seleccionado via callback)
_pills_val = st.session_state.get("preset_pills")
if _pills_val:
    _pills_label = _pills_val.split("  ", 1)[1]
    selected_preset = _PRESET_MAP_INV.get(_pills_label, selected_preset)
    selected_preset_label = _pills_label

# Query input
with st.form("pipeline_search_form", clear_on_submit=True):
    col_input, col_button = st.columns([10, 1])
    query = col_input.text_input(
        "Enter Dark Web Search Query",
        placeholder="Enter Dark Web Search Query",
        label_visibility="collapsed",
        key="pipeline_query_input",
    )
    run_button = col_button.form_submit_button("Run")


# --- Display loaded investigation ---
if "loaded_investigation" in st.session_state and not run_button:
    inv = st.session_state["loaded_investigation"]
    st.info(f"**{inv['query']}** — {inv['timestamp'][:16]}")
    with st.expander("Notes", expanded=False):
        st.markdown(f"**Refined Query:** `{inv['refined_query']}`")
        st.markdown(f"**Model:** `{inv['model']}` | **Domain:** {inv['preset']}")
        st.markdown(f"**Sources:** {len(inv['sources'])}")
    with st.expander(f"Sources ({len(inv['sources'])} results)", expanded=False):
        for i, item in enumerate(inv["sources"], 1):
            title = item.get("title", "Untitled")
            link = item.get("link", "")
            st.markdown(f"{i}. [{title}]({link})")
    st.subheader("Findings", divider="gray")
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

    if st.button("Clear"):
        del st.session_state["loaded_investigation"]
        st.rerun()


def _render_result(pc: dict, *, summary_shown: bool, key_prefix: str) -> None:
    """Notes, Sources, Findings e downloads de uma investigação acabada de correr.

    summary_shown: o relatório já está no ecrã (escrito durante o streaming) e não se repete.
    key_prefix: evita colisão das keys dos botões entre o desenho imediato e o persistente.
    """
    with st.expander("Notes", expanded=False):
        st.markdown(f"**Refined Query:** `{pc['refined']}`")
        st.markdown(f"**Model:** `{pc['model']}` | **Domain:** {pc['preset_label']}")
        st.markdown(
            f"**Results found:** {pc['results_count']} | "
            f"**Filtered to:** {len(pc['filtered'])} | "
            f"**Scraped:** {pc['scraped_count']}"
        )
    with st.expander(f"Sources ({len(pc['filtered'])} results)", expanded=False):
        render_links(pc["filtered"])
    if not summary_shown:
        st.subheader("Findings", divider="gray")
        st.markdown(pc["summary"])
    st.divider()

    pdf_bytes = generate_forensic_pdf({
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
    })
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dl1, dl2 = st.columns(2)
    dl1.download_button(
        label="⬇ Download Relatório PDF",
        data=pdf_bytes,
        file_name=f"relatorio_{pc['audit_id'][:8]}_{now}.pdf",
        mime="application/pdf",
        use_container_width=True,
        key=f"{key_prefix}dl_pdf",
    )
    dl2.download_button(
        label="⬇ Download Summary MD",
        data=pc["summary"].encode(),
        file_name=f"summary_{now}.md",
        mime="text/markdown",
        use_container_width=True,
        key=f"{key_prefix}dl_md",
    )


# --- Pipeline Execution ---
if run_button and query:
    st.session_state.pop("loaded_investigation", None)
    st.session_state.pop("pipeline_complete", None)

    # As 6 etapas (ui_pipeline.py), com a lógica de pipeline.py — a mesma da Home e da avaliação.
    run, findings_container = run_with_ui(query, settings, on_error=_stage_error)

    _fname = pipeline.save_investigation(
        pipeline.investigation_record(run, preset_label=selected_preset_label), INVESTIGATIONS_DIR)
    log_investigation(pipeline.audit_record(run, preset_label=selected_preset_label))

    st.success(f"Pipeline completed in {_fmt_ms(run.total_ms)} — saved as `{_fname}`")
    st.session_state["pipeline_complete"] = complete_dict(run, selected_preset_label, _fname)
    with findings_container:
        _render_result(st.session_state["pipeline_complete"], summary_shown=True, key_prefix="run_")


# ---------------------------------------------------------------------------
# Apresentação persistente de resultados (sobrevive a reruns do Streamlit)
# ---------------------------------------------------------------------------
if "pipeline_complete" in st.session_state and not run_button and "loaded_investigation" not in st.session_state:
    _pc = st.session_state["pipeline_complete"]
    st.success(f"Pipeline completed in {_fmt_ms(_pc['pipeline_ms'])} — saved as `{_pc['fname']}`")
    _render_result(_pc, summary_shown=False, key_prefix="pc_")
