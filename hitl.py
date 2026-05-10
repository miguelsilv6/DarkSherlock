"""hitl.py — Human-in-the-Loop review UIs for the DarkSherlock investigation pipeline.

Este módulo contém os três *checkpoints* onde o analista pode rever, editar ou
excluir outputs intermédios do pipeline antes que sejam usados nas etapas
seguintes:

    1. render_stage2_review — Revisão / edição da query refinada pelo LLM.
    2. render_stage4_review — Selecção dos URLs a scrapear (antes de Tor).
    3. render_stage5_review — Selecção das fontes scrapeadas (antes do LLM).

Cada função renderiza um `st.form` com as opções relevantes e, ao aprovar,
actualiza `st.session_state` e chama `st.rerun()` para retomar a execução do
pipeline exactamente onde parou. Os outputs anteriores ficam guardados em
session_state — as funções gated em Home.py detectam-nos e saltam as etapas
já executadas.
"""

import streamlit as st


# ---------------------------------------------------------------------------
# Checkpoint 1/3 — Stage 2 → 3
# ---------------------------------------------------------------------------

def render_stage2_review(original_query: str, refined_query: str) -> None:
    """Permite ao analista editar a query refinada pelo LLM antes da pesquisa.

    O LLM por vezes produz queries demasiado genéricas ou demasiado
    específicas. Dando ao utilizador a oportunidade de ajustar a query antes
    da pesquisa na dark web melhora substancialmente a pertinência dos
    resultados devolvidos pelos motores.

    Se o utilizador aprovar, a query editada é gravada em
    `st.session_state.refined` e `hitl_stage2_approved` é marcado como True,
    após o que se chama `st.rerun()` para retomar o pipeline.

    Args:
        original_query: Consulta introduzida pelo utilizador.
        refined_query:  Consulta gerada pelo LLM no Stage 2.
    """
    placeholder = st.empty()
    with placeholder.container():
        st.info(
            "🤝 **Checkpoint 1/3** — Revê a query refinada antes da pesquisa"
        )
        with st.form("hitl_stage2_form"):
            st.markdown(f"**Query original:** `{original_query}`")
            edited = st.text_input(
                "Query refinada (edita se necessário)",
                value=refined_query,
                key="hitl_stage2_edit",
            )
            col1, col2 = st.columns([1, 1])
            approve = col1.form_submit_button(
                "✅ Aprovar e continuar",
                type="primary",
                use_container_width=True,
            )
            cancel = col2.form_submit_button(
                "✖ Cancelar pipeline",
                use_container_width=True,
            )
    if approve:
        st.session_state.refined = edited.strip() or refined_query
        st.session_state["hitl_stage2_approved"] = True
        placeholder.empty()
        st.rerun()
    if cancel:
        placeholder.empty()
        _reset_hitl_state()
        st.rerun()


# ---------------------------------------------------------------------------
# Checkpoint 2/3 — Stage 4 → 5
# ---------------------------------------------------------------------------

def render_stage4_review(
    filtered_results: list,
    raw_count: int | None = None,
    ioc_type: str | None = None,
) -> None:
    """Permite escolher quais URLs filtrados serão scrapeados.

    O scraping via Tor é a operação mais cara do pipeline (latências altas
    por página). Permitir ao analista desmarcar URLs obviamente irrelevantes
    antes do scraping reduz o tempo de execução e evita contaminar o sumário
    com conteúdo fora do tema.

    Args:
        filtered_results: Lista de dicts (com `title` e `link`) filtrados pelo
            LLM no Stage 4.
        raw_count: Total de resultados brutos antes da filtragem LLM (Stage 3).
            Se fornecido, renderiza um aviso com a razão de corte.
        ioc_type: Tipo de IOC detectado para a query original (se aplicável).
            Se presente, o banner lembra o utilizador que o filtro está em
            modo estrito e que o LLM foi instruído a exigir match literal.
    """
    placeholder = st.empty()
    with placeholder.container():
        st.info(
            f"🤝 **Checkpoint 2/3** — Revê os {len(filtered_results)} URLs antes do scraping"
        )
        # ----------------------------------------------------------
        # Avisos de contexto do filtro LLM (Stage 4)
        # ----------------------------------------------------------
        if ioc_type:
            st.warning(
                f"🎯 **Filtro em modo IOC (`{ioc_type}`)** — O LLM foi "
                f"instruído a exigir match literal do indicador no título "
                f"ou URL. Se algum resultado relevante for ignorado por o "
                f"match estar apenas no conteúdo da página, adiciona-o "
                f"manualmente na próxima investigação."
            )
        if raw_count is not None and raw_count > 0:
            kept_ratio = len(filtered_results) / raw_count
            if len(filtered_results) == 0:
                st.error(
                    f"⚠️ **O filtro LLM rejeitou todos os {raw_count} "
                    f"resultados brutos.** Nenhum URL está disponível para "
                    f"scraping. Cancela o pipeline e refina a query."
                )
            elif kept_ratio < 0.1 and raw_count >= 20:
                # Redução muito agressiva (< 10% mantido em >= 20 resultados)
                st.warning(
                    f"⚠️ **Filtragem agressiva:** o LLM passou de "
                    f"{raw_count} → {len(filtered_results)} resultados "
                    f"({kept_ratio:.0%} mantidos). Verifica a lista abaixo "
                    f"— se algum relevante foi cortado, esta é a tua "
                    f"última oportunidade de recuperá-lo (não é possível "
                    f"neste checkpoint, mas podes refinar a query)."
                )
            else:
                st.caption(
                    f"Filtro LLM: {raw_count} → {len(filtered_results)} "
                    f"resultados ({kept_ratio:.0%} mantidos)."
                )
        with st.form("hitl_stage4_form"):
            st.caption(
                "🧅 Desmarca URLs irrelevantes antes do scraping (operação cara via Tor)"
            )
            keep_flags = []
            for i, item in enumerate(filtered_results):
                title = item.get("title", "Untitled")
                link = item.get("link", "")
                flag = st.checkbox(
                    f"**{i+1}. {title}**",
                    value=True,
                    key=f"hitl_s4_keep_{i}",
                    help=link,
                )
                # Para URLs .onion mostra bloco de código (copiável); clearweb
                # aparece inline apenas para contexto visual.
                if ".onion" in link:
                    st.code(link, language=None)
                else:
                    st.caption(f"`{link}`")
                keep_flags.append(flag)
            col1, col2 = st.columns([1, 1])
            approve = col1.form_submit_button(
                "✅ Continuar com selecionados",
                type="primary",
                use_container_width=True,
            )
            cancel = col2.form_submit_button(
                "✖ Cancelar pipeline",
                use_container_width=True,
            )
    if approve:
        kept = [r for r, keep in zip(filtered_results, keep_flags) if keep]
        if not kept:
            st.warning("Pelo menos 1 URL tem de ser selecionado.")
            return
        st.session_state.filtered = kept
        st.session_state["hitl_stage4_approved"] = True
        placeholder.empty()
        st.rerun()
    if cancel:
        placeholder.empty()
        _reset_hitl_state()
        st.rerun()


# ---------------------------------------------------------------------------
# Checkpoint 3/3 — Stage 5 → 6
# ---------------------------------------------------------------------------

def render_stage5_review(
    meaningful_scraped: dict,
    filtered: list,
    relevance_removed: int = 0,
    failed_count: int = 0,
    ioc_type: str | None = None,
) -> None:
    """Permite excluir fontes com conteúdo scrapeado irrelevante antes do sumário.

    Mesmo após as filtragens anteriores, o conteúdo efectivamente scrapeado
    pode ser ruído (páginas de erro em múltiplas línguas, captchas, etc.).
    Este checkpoint apresenta um excerto de cada fonte com um checkbox,
    permitindo desmarcar fontes cujo conteúdo não tem relação com o tema.

    As fontes aprovadas são guardadas em `hitl_approved_scraped` e usadas
    pelo Stage 6 em vez do `meaningful_scraped` original.

    Args:
        meaningful_scraped: Dict `{url: content}` com o conteúdo scrapeado
            que já passou nos filtros automáticos (comprimento + keyword).
        filtered: Lista de resultados filtrados (usada para obter títulos).
        relevance_removed: Nº de fontes que o filtro de relevância automático
            (`filter_scraped_by_relevance`) removeu. Se > 0 renderiza um aviso.
        failed_count: Nº de páginas que falharam o scraping (inacessíveis,
            captcha, login wall, timeout Tor). Contextualiza taxas de
            sucesso baixas.
        ioc_type: Tipo de IOC detectado, se a query original for um indicador.
            Em modo IOC o banner clarifica que as fontes listadas **contêm
            literalmente** o IOC — filtradas pelo modo estrito de
            `filter_scraped_by_relevance`.
    """
    placeholder = st.empty()
    url_to_title = {
        r.get("link"): r.get("title", "Sem título") for r in filtered
    }
    with placeholder.container():
        st.info(
            "🤝 **Checkpoint 3/3** — Revê o conteúdo scrapeado antes do sumário final"
        )
        # ----------------------------------------------------------
        # Avisos de contexto dos filtros automáticos do Stage 5
        # ----------------------------------------------------------
        if ioc_type:
            st.success(
                f"🎯 **Filtro IOC (`{ioc_type}`) activo:** as "
                f"{len(meaningful_scraped)} fonte(s) listada(s) abaixo "
                f"contêm literalmente o indicador pesquisado no seu "
                f"conteúdo. Match garantido — este é o material certo "
                f"para alimentar o sumário final."
            )
        elif relevance_removed > 0:
            st.warning(
                f"🧹 **Filtro de relevância automático removeu "
                f"{relevance_removed} fonte(s)** por não conterem as "
                f"keywords da query original. Se achas que alguma foi "
                f"injustamente rejeitada, cancela o pipeline e refina "
                f"a query com termos mais específicos ou adiciona "
                f"sinónimos."
            )
        if failed_count > 0:
            st.caption(
                f"ℹ️ {failed_count} página(s) falharam o scraping "
                f"(inacessíveis, captchas, login walls ou timeouts Tor) "
                f"e não aparecem abaixo."
            )
        if len(meaningful_scraped) == 0:
            # Fallback defensivo — em teoria Home.py já parou antes, mas
            # garante que o form não arranca vazio.
            st.error(
                "Nenhuma fonte sobreviveu aos filtros automáticos. "
                "Cancela o pipeline e ajusta a query."
            )
        with st.form("hitl_stage5_form"):
            st.caption(
                "Desmarca fontes com conteúdo irrelevante — só as aprovadas "
                "vão alimentar o sumário do LLM"
            )
            keep_urls = {}
            for url, content in list(meaningful_scraped.items()):
                title = url_to_title.get(url, "Sem título")
                flag = st.checkbox(
                    f"**{title}** ({len(content)} chars)",
                    value=True,
                    key=f"hitl_s5_keep_{hash(url)}",
                )
                if ".onion" in url:
                    st.code(url, language=None)
                else:
                    st.caption(f"`{url}`")
                excerpt = content[:400].strip()
                if len(content) > 400:
                    excerpt += " …"
                st.markdown(f"*{excerpt}*")
                st.divider()
                keep_urls[url] = flag
            col1, col2 = st.columns([1, 1])
            approve = col1.form_submit_button(
                "✅ Gerar sumário com selecionadas",
                type="primary",
                use_container_width=True,
            )
            cancel = col2.form_submit_button(
                "✖ Cancelar pipeline",
                use_container_width=True,
            )
    if approve:
        kept = {
            url: c
            for url, c in meaningful_scraped.items()
            if keep_urls.get(url)
        }
        if not kept:
            st.warning("Pelo menos 1 fonte tem de ser selecionada.")
            return
        st.session_state["hitl_approved_scraped"] = kept
        st.session_state["hitl_stage5_approved"] = True
        placeholder.empty()
        st.rerun()
    if cancel:
        placeholder.empty()
        _reset_hitl_state()
        st.rerun()


# ---------------------------------------------------------------------------
# Helper para limpar estado (Cancelar pipeline)
# ---------------------------------------------------------------------------

def _reset_hitl_state() -> None:
    """Remove todo o estado HITL + outputs intermédios do pipeline.

    Chamado quando o utilizador clica em "Cancelar pipeline" em qualquer
    checkpoint, ou quando arranca uma nova pesquisa do zero. Garante que
    nenhum dado residual de um pipeline anterior contamina a próxima
    execução.
    """
    for key in [
        # Flags de estado HITL
        "hitl_stage2_approved",
        "hitl_stage4_approved",
        "hitl_stage5_approved",
        "hitl_approved_scraped",
        "hitl_in_progress",
        "hitl_query",
        "hitl_preset",
        "hitl_preset_label",
        "hitl_pipeline_start",
        "hitl_llm_ms",
        "hitl_refine_ms",
        "hitl_search_ms",
        "hitl_filter_ms",
        "hitl_scrape_ms",
        # Outputs das etapas do pipeline
        "refined",
        "results",
        "filtered",
        "scraped",
        "meaningful_scraped",
        "streamed_summary",
        "integrity",
        # Valores auxiliares
        "hitl_relevance_removed",
        "hitl_failed_count",
    ]:
        st.session_state.pop(key, None)
