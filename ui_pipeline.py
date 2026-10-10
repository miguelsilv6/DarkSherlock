"""
ui_pipeline.py — Execução do pipeline na interface Streamlit (Home e Investigation).

As duas páginas tinham cópias quase iguais do código das 6 etapas. Agora ambas
chamam run_with_ui(), que desenha um painel de estado por etapa e delega a
lógica em pipeline.py — a mesma que a avaliação (evaluation/run_scenarios.py)
usa, para os números da avaliação corresponderem ao que a app faz.
"""

from __future__ import annotations

import time

import streamlit as st

import pipeline
from llm import get_llm
from llm_utils import BufferedStreamingHandler


def fmt_ms(ms: int) -> str:
    """Milissegundos como "1m03s", "45s" ou "780ms"."""
    total_s = ms // 1000
    m, s = divmod(total_s, 60)
    if m > 0:
        return f"{m}m{s:02d}s"
    return f"{total_s}s" if total_s >= 1 else f"{ms}ms"


def render_links(items: list) -> None:
    """Lista de resultados: .onion como texto copiável (o browser normal não os abre)."""
    st.caption("🧅 Links .onion: copia e abre no Tor Browser")
    for i, item in enumerate(items, 1):
        title = item.get("title", "Untitled")
        link = item.get("link", "")
        if ".onion" in link:
            st.markdown(f"**{i}. {title}**")
            st.code(link, language=None)
        else:
            st.markdown(f"{i}. [{title}]({link})")


def _show_new_warnings(r: pipeline.PipelineResult, already: int) -> int:
    """Mostra os avisos ainda não mostrados (Tor em baixo, motores em falha, sem evidência)."""
    for w in r.warnings[already:]:
        st.warning(f"⚠️ {w}")
    return len(r.warnings)


def _fail(status, label: str, on_error, what: str, err: Exception, r: pipeline.PipelineResult):
    r.errors.append(f"{what}: {err}")
    status.update(label=label, state="error")
    on_error(what, err)  # mostra o erro e chama st.stop()
    st.stop()


def run_with_ui(query: str, settings: dict, *, on_error, search_fn=pipeline.search_with_stats,
                scrape_fn=pipeline.scrape_with_details):
    """Corre as 6 etapas com um painel por etapa. Devolve (PipelineResult, findings_container).

    on_error(what, exc): mostra o erro (a página decide como) — a execução para a seguir.
    search_fn / scrape_fn: permitem à página usar versões em cache.
    """
    r = pipeline.PipelineResult(query=query, preset=settings["selected_preset"], model=settings["model"])
    t_start = time.time()
    threads = settings["threads"]

    # Etapa 1 — modelo
    with st.status("**Stage 1/6** — Loading LLM...", expanded=True) as status:
        t0 = time.time()
        try:
            llm = get_llm(r.model)
        except Exception as e:  # noqa: BLE001
            _fail(status, "**Stage 1/6** — LLM failed", on_error, "load the selected LLM", e, r)
        r.timings_ms["load_llm"] = round((time.time() - t0) * 1000)
        st.write(f"Model: `{r.model}`")
        status.update(label=f"**Stage 1/6** — LLM loaded ({fmt_ms(r.timings_ms['load_llm'])})", state="complete")

    # Etapa 2 — refinamento da query (só para a pesquisa; as etapas 4–6 usam a original)
    with st.status("**Stage 2/6** — Refining query...", expanded=True) as status:
        try:
            pipeline.stage_refine(r, llm)
        except Exception as e:  # noqa: BLE001
            _fail(status, "**Stage 2/6** — Query refinement failed", on_error, "refine the query", e, r)
        st.write(f"Original: `{r.query}`")
        st.write(f"Refined: `{r.refined_query}`")
        status.update(label=f"**Stage 2/6** — Query refined ({fmt_ms(r.timings_ms['refine_query'])})",
                      state="complete")

    # Etapa 3 — pesquisa nos motores .onion, via Tor (avisa se o Tor estiver em baixo)
    with st.status("**Stage 3/6** — Searching the dark web engines...", expanded=True) as status:
        try:
            pipeline.stage_search(r, settings["max_results"], threads, search_fn)
        except Exception as e:  # noqa: BLE001
            _fail(status, "**Stage 3/6** — Search failed", on_error, "search the dark web (Stage 3)", e, r)
        failed = sum(1 for v in r.engine_status.values() if v == "failed")
        st.write(f"Found **{len(r.search_results)}** results across {len(r.active_engines)} engines"
                 + (f" ({failed} engines failed)" if failed else ""))
        status.update(label=f"**Stage 3/6** — {len(r.search_results)} results found "
                            f"({fmt_ms(r.timings_ms['search'])})", state="complete")
    shown = _show_new_warnings(r, 0)

    # Etapa 4 — seleção pelo LLM (títulos/URLs)
    with st.status("**Stage 4/6** — Filtering results with LLM...", expanded=True) as status:
        try:
            pipeline.stage_filter(r, llm, settings["max_scrape"])
        except Exception as e:  # noqa: BLE001
            _fail(status, "**Stage 4/6** — Filtering failed", on_error, "filter the results (Stage 4)", e, r)
        note = "" if r.stage4_outcome == "ranked" else f" (LLM ranking not used: `{r.stage4_outcome}`)"
        st.write(f"Filtered to **{len(r.filtered)}** most relevant results{note}")
        with st.expander("View filtered results"):
            render_links(r.filtered)
        status.update(label=f"**Stage 4/6** — Filtered to {len(r.filtered)} results "
                            f"({fmt_ms(r.timings_ms['filter_results'])})", state="complete")

    # Etapa 5 — recolha das páginas e relevância sobre o texto
    with st.status(f"**Stage 5/6** — Scraping {len(r.filtered)} pages...", expanded=True) as status:
        try:
            pipeline.stage_scrape(r, threads, scrape_fn)
        except Exception as e:  # noqa: BLE001
            _fail(status, "**Stage 5/6** — Scraping failed", on_error, "scrape the selected pages (Stage 5)", e, r)
        n = len(r.scraped_content)
        note = f" ({r.pages_failed} inaccessible/error pages removed)" if r.pages_failed else ""
        if r.safety_blocked:
            note += f" ({r.safety_blocked} blocked by the ethics safeguard — logged for referral, never requested)"
        removed = r.pages_valid - n
        if removed:
            note += f" ({removed} pages that do not mention the query terms removed)"
        st.write(f"Scraped **{n}** pages with content{note}")
        st.caption(f"Hash global SHA-256: `{r.integrity['overall_sha256'][:16]}...`")
        titles = {it.get("link"): it.get("title", "Sem título") for it in r.filtered}
        with st.expander(f"📄 Conteúdo recolhido por fonte ({n})", expanded=False):
            st.caption("Texto extraído de cada página, pela ordem de relevância — "
                       "é este o conteúdo (e esta a numeração [FONTE N]) que o LLM analisa na Etapa 6/6")
            for i, (url, content) in enumerate(r.scraped_content.items(), 1):
                st.markdown(f"**[FONTE {i}] {titles.get(url, 'Sem título')}**")
                if ".onion" in url:
                    st.code(url, language=None)
                else:
                    st.markdown(f"`{url}`")
                excerpt = content[:500].strip() + (" …" if len(content) > 500 else "")
                st.markdown(f"*{excerpt}*")
                st.divider()
        status.update(label=f"**Stage 5/6** — {n} pages scraped ({fmt_ms(r.timings_ms['scrape'])})",
                      state="complete")

    _show_new_warnings(r, shown)

    # Etapa 6 — relatório (em streaming; o texto final é o devolvido, com os avisos)
    findings_container = st.container()
    with findings_container:
        st.subheader(":red[Findings]", anchor=None, divider="gray")
        summary_slot = st.empty()
    streamed = {"text": ""}

    def ui_emit(chunk: str):
        streamed["text"] += chunk
        summary_slot.markdown(streamed["text"])

    with st.status("**Stage 6/6** — Generating intelligence summary...", expanded=True) as status:
        llm.callbacks = [BufferedStreamingHandler(ui_callback=ui_emit)]
        try:
            pipeline.stage_summary(r, llm, settings.get("custom_instructions", ""))
        except Exception as e:  # noqa: BLE001
            _fail(status, "**Stage 6/6** — Report failed", on_error, "generate the report (Stage 6)", e, r)
        finally:
            llm.callbacks = []
        if r.summary != streamed["text"]:
            summary_slot.markdown(r.summary)
        status.update(label=f"**Stage 6/6** — Summary generated ({fmt_ms(r.timings_ms['generate_summary'])})",
                      state="complete")

    pipeline.finish(r, t_start)
    return r, findings_container


def complete_dict(r: pipeline.PipelineResult, preset_label: str, fname: str) -> dict:
    """O que a página guarda em session_state["pipeline_complete"] para voltar a desenhar o resultado."""
    return {
        "audit_id": r.audit_id,
        "query": r.query,
        "refined": r.refined_query,
        "model": r.model,
        "preset_label": preset_label,
        "filtered": r.filtered,
        "results_count": len(r.search_results),
        "scraped_count": len(r.scraped_content),
        "summary": r.summary,
        "integrity": r.integrity,
        "active_engines": r.active_engines,
        "pipeline_ms": r.total_ms,
        "fname": fname,
        "timestamp_utc": r.timestamp_utc,
        "scraped_content": r.scraped_content,
    }
