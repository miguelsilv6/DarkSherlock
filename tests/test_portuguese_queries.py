"""Queries em português: palavras genéricas como contexto, variantes de países,
refinação para inglês e relatório "sem evidência" com diagnóstico."""

import llm
import pipeline
import text_match as tm


def _keys(q):
    return sorted(t.text for t in tm.query_terms(q) if t.key)


def test_generic_portuguese_words_are_not_key_terms():
    assert _keys("Ransomware Akira alvos em Portugal") == ["akira", "portugal"]
    assert _keys("ataques do ransomware Akira a empresas portuguesas") == ["akira", "portugal"]
    assert _keys("lockbit leak site") == ["lockbit"]


def test_country_variants():
    terms = tm.query_terms("Akira Portugal")
    for text in ("Akira listed a Portuguese logistics company", "victim: acme.pt (Akira)",
                 "Akira: empresa portuguesa", "Akira e uma vítima em Portugal"):
        assert tm.is_relevant(tm.match(text, terms), terms), text
    for text in ("Akira hit a company in Spain", "ataques a empresas em Portugal", "Akira optimization.ptx"):
        assert not tm.is_relevant(tm.match(text, terms), terms), text


def test_generic_words_alone_are_not_evidence():
    q = "ataques do ransomware Akira a empresas portuguesas"
    noticia = "Ataques informáticos a empresas portuguesas aumentaram este ano, segundo o relatório. " * 4
    akira = "Akira ransomware group published a Portuguese company on its leak site with sample files. " * 4
    kept = llm.filter_scraped_by_relevance(q, {"http://n.onion": noticia, "http://a.onion": akira})
    assert list(kept) == ["http://a.onion"]


def test_refine_may_translate_generic_words(fake_llm):
    q = "ataques do ransomware Akira a empresas portuguesas"
    assert llm.refine_query(fake_llm("Akira ransomware Portugal companies"), q) == "Akira ransomware Portugal companies"
    assert llm.refine_query(fake_llm("Akira ransomware Portuguese victims"), q) == "Akira ransomware Portuguese victims"
    # perdeu o nome do grupo -> fica a query original
    assert llm.refine_query(fake_llm("ransomware Portugal companies"), q) == q


def test_no_evidence_report_explains_and_skips_llm(fake_llm, monkeypatch):
    r = pipeline.PipelineResult(query="Ransomware Akira alvos em Portugal", refined_query="Akira ransomware Portugal")
    r.engine_status = {"E1": "ok", "E2": "ok", "E3": "failed"}
    r.search_stats = {"E1": {"status": "ok_results"}, "E2": {"status": "ok_empty"}}
    r.search_results = [{"link": "x"}] * 12
    r.filtered = [{"link": "a"}, {"link": "b"}, {"link": "c"}]
    r.stage4_outcome = "ranked"
    r.scrape_outcomes = {"timeout": 2, "too_short": 1}

    def must_not_call(*a, **k):
        raise AssertionError("o LLM não pode ser usado sem evidência")
    monkeypatch.setattr(llm, "generate_summary", must_not_call)
    pipeline.stage_summary(r, fake_llm("nunca usado"))
    text = r.summary
    assert text.startswith("## Sem evidência suficiente")
    assert "2 de 3 motores responderam, 1 com resultados" in text
    assert "`Akira ransomware Portugal`" in text
    assert "2 sem resposta a tempo" in text and "1 texto curto demais" in text
    assert "outro circuito Tor" in text and "Tor Browser" in text
    assert r.summary_quality == {"ok": False, "problems": ["no_evidence"]}


def test_no_evidence_report_when_pages_miss_terms():
    r = pipeline.PipelineResult(query="Akira Portugal")
    r.search_results = [{"link": "x"}]
    r.filtered = [{"link": "a"}]
    r.scrape_outcomes = {"ok": 1}
    r.pages_valid = 1
    r.relevance_scores = {"a": {"found": ["portugal"], "key_found": 1}}
    text = pipeline.no_evidence_report(r)
    assert "akira: 0 de 1 páginas; portugal: 1 de 1 páginas" in text
    assert "- a — akira ✗ · portugal ✓" in text and "evidência parcial no Tor Browser" in text
