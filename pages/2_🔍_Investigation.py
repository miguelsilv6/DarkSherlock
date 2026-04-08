"""Investigation Pipeline — full visibility into each stage."""

import base64
import json
import time
import uuid
import streamlit as st
from datetime import datetime, timezone
from pathlib import Path


def _fmt_ms(ms: int) -> str:
    """Format milliseconds as Xm YYs or Xs."""
    total_s = ms // 1000
    m, s = divmod(total_s, 60)
    if m > 0:
        return f"{m}m{s:02d}s"
    return f"{total_s}s" if total_s >= 1 else f"{ms}ms"

from scrape import scrape_multiple
from search import get_search_results
from llm_utils import BufferedStreamingHandler, get_model_choices
from llm import get_llm, refine_query, filter_results, generate_summary, PRESET_PROMPTS
from engine_manager import get_active_engines
from report import compute_integrity_hashes, generate_forensic_pdf
from audit import log_investigation, setup_file_logging

# Configura o logging para ficheiro (captura debug/info de todos os módulos)
setup_file_logging()
from sidebar import render_sidebar

st.set_page_config(
    page_title="DarkSherlock — Investigation Pipeline",
    page_icon="🔍",
    initial_sidebar_state="expanded",
)

settings = render_sidebar()
model = settings["model"]
threads = settings["threads"]
max_results = settings["max_results"]
max_scrape = settings["max_scrape"]
selected_preset = settings["selected_preset"]
selected_preset_label = settings["selected_preset_label"]
custom_instructions = settings["custom_instructions"]

# CSS futurista — idêntico ao Home.py para paridade visual entre páginas.
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
    button[kind="primaryFormSubmit"],
    button[data-testid="baseButton-primary"],
    .stButton > button[kind="primary"] {
        background-color: #00ff9f14 !important; color: #00ff9f !important;
        border: 1px solid #00ff9f !important; border-radius: 4px !important;
        font-weight: 600 !important; letter-spacing: 0.08em !important;
        text-transform: uppercase !important;
    }
    button[kind="primaryFormSubmit"]:hover,
    button[data-testid="baseButton-primary"]:hover,
    .stButton > button[kind="primary"]:hover {
        background-color: #00ff9f2a !important; box-shadow: 0 0 10px #00ff9f55 !important;
    }
    .stButton > button, .stDownloadButton > button {
        background-color: transparent !important; color: #a0f0c8 !important;
        border: 1px solid #a0f0c833 !important; border-radius: 4px !important;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        border-color: #00ff9f !important; color: #00ff9f !important;
    }
    [data-testid="stStatusWidget"], div[data-testid="stExpander"] {
        border: 1px solid #00ff9f22 !important; border-radius: 6px !important;
        background-color: #0d0d18 !important;
    }
    div[data-testid="stPillsButton"] button {
        background-color: #0d0d18 !important; border: 1px solid #00ff9f33 !important;
        color: #7a9e8e !important; border-radius: 4px !important;
        font-weight: 500 !important; letter-spacing: 0.04em !important;
        transition: all 0.2s ease !important;
    }
    div[data-testid="stPillsButton"] button[aria-checked="true"] {
        background-color: #00ff9f18 !important; border-color: #00ff9f !important;
        color: #00ff9f !important; box-shadow: 0 0 8px #00ff9f44 !important;
    }
    div[data-testid="stPillsButton"] button:hover {
        border-color: #00ff9f88 !important; color: #c0ffe0 !important;
    }
    [data-testid="stSidebar"] { border-right: 1px solid #00ff9f1a !important; }
    </style>""",
    unsafe_allow_html=True,
)

# --- Past Investigations (sidebar) ---
INVESTIGATIONS_DIR = Path("investigations")


def load_investigations():
    if not INVESTIGATIONS_DIR.exists():
        return []
    files = sorted(INVESTIGATIONS_DIR.glob("investigation_*.json"), reverse=True)
    investigations = []
    for f in files:
        try:
            data = json.loads(f.read_text())
            data["_filename"] = f.name
            investigations.append(data)
        except Exception:
            continue
    return investigations


def save_investigation(
    query, refined_query, model_name, preset_label, sources, summary,
    audit_id="", active_engines=None, integrity=None,
):
    """Guarda investigação completa com campos forenses (hashes, timestamps, audit_id)."""
    INVESTIGATIONS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"investigation_{timestamp}.json"
    data = {
        "audit_id": audit_id,
        "timestamp": datetime.now().isoformat(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "query": query,
        "refined_query": refined_query,
        "model": model_name,
        "preset": preset_label,
        "active_engines": active_engines or [],
        "sources": sources,
        "summary": summary,
        "integrity": integrity or {},
    }
    (INVESTIGATIONS_DIR / fname).write_text(json.dumps(data, indent=2))
    return fname


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

_current_label_inv = st.session_state.get("preset_select", _PRESET_LABELS_INV[0])
_default_idx_inv = (
    _PRESET_LABELS_INV.index(_current_label_inv)
    if _current_label_inv in _PRESET_LABELS_INV
    else 0
)

st.markdown("##### Investigation Domain")
_selected_pill_inv = st.pills(
    label="Investigation Domain",
    options=_PRESET_PILLS_INV,
    default=_PRESET_PILLS_INV[_default_idx_inv],
    selection_mode="single",
    label_visibility="collapsed",
    key="preset_pills",
)

# Sincroniza com a sidebar e sobrepõe o preset retornado por render_sidebar()
if _selected_pill_inv is not None:
    _synced_label_inv = _selected_pill_inv.split("  ", 1)[1]
    st.session_state["preset_select"] = _synced_label_inv
    selected_preset = _PRESET_MAP_INV.get(_synced_label_inv, selected_preset)
    selected_preset_label = _synced_label_inv

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
    if st.button("Clear"):
        del st.session_state["loaded_investigation"]
        st.rerun()


# --- Pipeline Execution ---
if run_button and query:
    st.session_state.pop("loaded_investigation", None)
    for k in ["refined", "results", "filtered", "scraped", "streamed_summary"]:
        st.session_state.pop(k, None)

    pipeline_start = time.time()

    # Stage 1 — Load LLM
    with st.status("**Stage 1/6** — Loading LLM...", expanded=True) as status:
        t0 = time.time()
        try:
            llm = get_llm(model)
            elapsed = round((time.time() - t0) * 1000)
            status.update(label=f"**Stage 1/6** — LLM loaded: `{model}` ({_fmt_ms(elapsed)})", state="complete")
        except Exception as e:
            status.update(label=f"**Stage 1/6** — LLM failed", state="error")
            st.error(f"Failed to load LLM: {e}")
            st.stop()

    # Stage 2 — Refine Query
    with st.status("**Stage 2/6** — Refining query...", expanded=True) as status:
        t0 = time.time()
        try:
            st.session_state.refined = refine_query(llm, query, preset=selected_preset)
            elapsed = round((time.time() - t0) * 1000)
            st.write(f"Original: `{query}`")
            st.write(f"Refined: `{st.session_state.refined}`")
            status.update(label=f"**Stage 2/6** — Query refined ({_fmt_ms(elapsed)})", state="complete")
        except Exception as e:
            status.update(label=f"**Stage 2/6** — Query refinement failed", state="error")
            st.error(f"Failed to refine query: {e}")
            st.stop()

    # Stage 3 — Search Dark Web
    with st.status(f"**Stage 3/6** — Searching {len(active_engines)} engines...", expanded=True) as status:
        t0 = time.time()
        # search.py já deduplica os resultados por URL — não é necessário
        # repetir o processo aqui. A deduplicação dupla era redundante e O(2n).
        st.session_state.results = get_search_results(
            st.session_state.refined.replace(" ", "+"), max_workers=threads
        )
        if len(st.session_state.results) > max_results:
            st.session_state.results = st.session_state.results[:max_results]
        # Estampar timestamp UTC de recolha em cada resultado
        retrieved_at_utc = datetime.now(timezone.utc).isoformat()
        for r in st.session_state.results:
            r["retrieved_at_utc"] = retrieved_at_utc
        elapsed = round((time.time() - t0) * 1000)
        st.write(f"Found **{len(st.session_state.results)}** results across {len(active_engines)} engines")
        status.update(
            label=f"**Stage 3/6** — {len(st.session_state.results)} results found ({_fmt_ms(elapsed)})",
            state="complete",
        )

    # Stage 4 — Filter Results
    with st.status("**Stage 4/6** — Filtering results with LLM...", expanded=True) as status:
        t0 = time.time()
        st.session_state.filtered = filter_results(
            llm, st.session_state.refined, st.session_state.results
        )
        if len(st.session_state.filtered) > max_scrape:
            st.session_state.filtered = st.session_state.filtered[:max_scrape]
        elapsed = round((time.time() - t0) * 1000)
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

    # Stage 5 — Scrape Content
    with st.status(f"**Stage 5/6** — Scraping {len(st.session_state.filtered)} pages...", expanded=True) as status:
        t0 = time.time()
        st.session_state.scraped = scrape_multiple(
            st.session_state.filtered, max_workers=threads
        )
        # Filter out failed scrapes (returned only the page title, no actual content)
        meaningful_scraped = {
            url: content
            for url, content in st.session_state.scraped.items()
            if len(content) > 150
        }
        # Estampar timestamp UTC de scraping e calcular hashes de integridade
        scraped_at_utc = datetime.now(timezone.utc).isoformat()
        for item in st.session_state.filtered:
            if item.get("link", "") in meaningful_scraped:
                item["scraped_at_utc"] = scraped_at_utc
        integrity = compute_integrity_hashes(meaningful_scraped)
        st.session_state.integrity = integrity

        elapsed = round((time.time() - t0) * 1000)
        scraped_count = len(meaningful_scraped)
        failed_count = len(st.session_state.scraped) - scraped_count
        note = f" ({failed_count} inaccessible pages removed)" if failed_count else ""
        st.write(f"Scraped **{scraped_count}** pages with content{note}")
        st.caption(f"Hash global SHA-256: `{integrity['overall_sha256'][:16]}...`")

        # Expander com conteúdo recolhido por fonte — auditabilidade e transparência
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

    # Stage 6 — Generate Summary
    st.session_state.streamed_summary = ""

    findings_container = st.container()
    with findings_container:
        st.subheader("Findings", divider="gray")
        summary_slot = st.empty()

    def ui_emit(chunk):
        st.session_state.streamed_summary += chunk
        summary_slot.markdown(st.session_state.streamed_summary)

    with st.status("**Stage 6/6** — Generating intelligence summary...", expanded=True) as status:
        t0 = time.time()
        stream_handler = BufferedStreamingHandler(ui_callback=ui_emit)
        llm.callbacks = [stream_handler]
        _ = generate_summary(
            llm,
            query,
            meaningful_scraped,
            preset=selected_preset,
            custom_instructions=custom_instructions,
        )
        elapsed = round((time.time() - t0) * 1000)
        status.update(
            label=f"**Stage 6/6** — Summary generated ({_fmt_ms(elapsed)})",
            state="complete",
        )

    total_elapsed = round(time.time() - pipeline_start, 1)
    pipeline_ms = int(total_elapsed * 1000)
    audit_id = str(uuid.uuid4())
    integrity = st.session_state.get("integrity", {})

    _fname = save_investigation(
        query=query,
        refined_query=st.session_state.refined,
        model_name=model,
        preset_label=selected_preset_label,
        sources=st.session_state.filtered,
        summary=st.session_state.streamed_summary,
        audit_id=audit_id,
        active_engines=[e["name"] for e in active_engines],
        integrity=integrity,
    )

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

    # Notes
    with st.expander("Notes", expanded=False):
        st.markdown(f"**Refined Query:** `{st.session_state.refined}`")
        st.markdown(f"**Model:** `{model}` | **Domain:** {selected_preset_label}")
        st.markdown(
            f"**Results found:** {len(st.session_state.results)} | "
            f"**Filtered to:** {len(st.session_state.filtered)} | "
            f"**Scraped:** {scraped_count}"
        )

    # Final findings display com botões de download
    with findings_container:
        st.markdown(st.session_state.streamed_summary)
        st.divider()

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
        dl_col2.download_button(
            label="⬇ Download Summary MD",
            data=st.session_state.streamed_summary.encode(),
            file_name=f"summary_{now}.md",
            mime="text/markdown",
            use_container_width=True,
        )
