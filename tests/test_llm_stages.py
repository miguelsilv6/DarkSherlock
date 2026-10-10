"""PR 3 — refinação da query, Etapa 4 e Etapa 5."""

import llm


# ------------------------------------------------------------------ refinação
def test_refine_keeps_original_terms(fake_llm):
    assert llm.refine_query(fake_llm("LockBit leak site ransomware"), "lockbit leak site") == "LockBit leak site ransomware"


def test_refine_falls_back_when_terms_are_dropped(fake_llm):
    # o caso real: "lockbit leak site" -> "LockBit leak forum" perdia "site"? site é genérico;
    # aqui o modelo perde "akira", que é o alvo.
    assert llm.refine_query(fake_llm("ransomware leak forum"), "Akira ransomware") == "Akira ransomware"


def test_refine_cleans_prefix_and_takes_first_line(fake_llm):
    assert llm.refine_query(fake_llm('Refined query: "Cobalt Strike beacon"\nExplanation: ...'),
                            "cobalt strike beacon") == "Cobalt Strike beacon"


def test_refine_rejects_long_paragraphs(fake_llm):
    out = llm.refine_query(fake_llm("lockbit leak site with many many extra words appended here"), "lockbit leak site")
    assert out == "lockbit leak site"


# ------------------------------------------------------------------ Etapa 4
RES = [{"title": f"Item {i}", "link": f"http://a{i}.onion"} for i in range(1, 11)]
RES[4] = {"title": "LockBit victims list", "link": "http://lb.onion"}


def test_none_must_be_the_whole_answer(fake_llm):
    out = llm.filter_results(fake_llm("None of these look relevant, but 2 and 3 might."), "lockbit", RES)
    # não é NONE: lê-se uma linha de índices? a linha tem prosa -> parse_fallback
    assert llm.last_filter_outcome == "parse_fallback" and len(out) == 10


def test_indices_line_with_label(fake_llm):
    out = llm.filter_results(fake_llm("Here are the results.\nIndices: 5, 2"), "lockbit", RES)
    assert llm.last_filter_outcome == "ranked" and [r["link"] for r in out] == ["http://lb.onion", "http://a2.onion"]


def test_numbers_in_prose_are_ignored(fake_llm):
    out = llm.filter_results(fake_llm("LockBit 3.0 appears in result number 5."), "lockbit", RES)
    assert llm.last_filter_outcome == "parse_fallback"


def test_none_keyword_fallback_uses_key_terms(fake_llm):
    res = [{"title": "leak forum market", "link": "http://spam.onion"},
           {"title": "LockBit victims list", "link": "http://lb.onion"}]
    out = llm.filter_results(fake_llm("NONE"), "lockbit leak site", res)
    assert llm.last_filter_outcome == "none_keyword" and [r["link"] for r in out] == ["http://lb.onion"]


def test_none_without_key_term_matches(fake_llm):
    res = [{"title": "leak forum market", "link": "http://spam.onion"}]
    assert llm.filter_results(fake_llm("NONE."), "lockbit leak site", res) == [] and llm.last_filter_outcome == "none"


# ------------------------------------------------------------------ Etapa 5
def test_relevance_filter_uses_key_terms_and_ranks():
    scraped = {"u1": "leak leak forum", "u2": "LockBit leak site with the victim list", "u3": "lockbit mention"}
    out = llm.filter_scraped_by_relevance("lockbit leak site", scraped)
    assert list(out) == ["u2", "u3"] and llm.last_relevance_outcome == "kept"


def test_relevance_filter_returns_empty_instead_of_everything():
    out = llm.filter_scraped_by_relevance("lockbit leak site", {"u1": "nada a ver", "u2": "outra coisa"})
    assert out == {} and llm.last_relevance_outcome == "empty"


def test_relevance_filter_without_terms_keeps_all():
    assert llm.filter_scraped_by_relevance("the site", {"u1": "x"}) == {"u1": "x"}
    assert llm.last_relevance_outcome == "no_terms"
