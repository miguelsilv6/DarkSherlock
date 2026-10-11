"""Etapa 4 com vagas por preencher e relatório sem evidência com páginas parciais
("Ransomware Akira alvos em Portugal": 4 de 48 escolhidos, 2 páginas só com "akira")."""

import json

import eq02_eq03
import llm
import pipeline

Q = "Ransomware Akira alvos em Portugal"
AKIRA = "The Akira ransomware group lists new victims every week with sample files and negotiation chat. " * 4
OTHER = "Marketplace with cards, accounts and tutorials for beginners, escrow available. " * 4

RESULTS = [
    {"title": "Hidden wiki links", "link": "http://wiki.onion/"},
    {"title": "Akira blog mirror", "link": "http://akira1.onion/"},
    {"title": "Cheap cards market", "link": "http://cards.onion/"},
    {"title": "Akira ransomware victims Portugal", "link": "http://akira2.onion/"},
    {"title": "Ransomware news", "link": "http://news.onion/"},
    {"title": "akira leaks", "link": "http://akira3.onion/"},
]


def _search_fn(query, threads):
    return [dict(r) for r in RESULTS], {"E1": "ok"}, {"E1": {"status": "ok_results"}}, "2026-10-11T00:00:00+00:00"


def _scrape_fn(pages):
    def fn(filtered, threads):
        got = {x["link"]: pages[x["link"]] for x in filtered if x["link"] in pages}
        return got, {x["link"]: {"status": "ok" if x["link"] in pages else "timeout"} for x in filtered}, 0
    return fn


def _run(fake_llm, ranking, max_scrape, pages):
    return pipeline.run_pipeline(Q, "ransomware_malware", fake_llm("Akira ransomware Portugal", ranking, "nunca"),
                                 model="m", max_results=50, max_scrape=max_scrape, threads=1,
                                 search_fn=_search_fn, scrape_fn=_scrape_fn(pages))


def test_empty_slots_are_filled_with_key_term_matches(fake_llm, monkeypatch):
    monkeypatch.setattr(pipeline, "tor_available", lambda *a, **k: True)
    monkeypatch.setattr(pipeline, "get_active_engines", lambda: [{"name": "E1"}])
    r = _run(fake_llm, "5", 4, {})
    assert r.stage4_outcome == "ranked" and r.stage4_padded == 3
    # o do LLM primeiro; depois por n.º de termos-chave (akira+portugal antes de só akira), depois a ordem original
    assert [x["link"] for x in r.filtered] == ["http://news.onion/", "http://akira2.onion/",
                                               "http://akira1.onion/", "http://akira3.onion/"]
    assert [x["selected_by"] for x in r.filtered] == ["llm", "terms", "terms", "terms"]
    assert "selected_by" not in r.search_results[0]  # cópias: a lista recuperada não é alterada
    rec = pipeline.investigation_record(r)
    assert rec["stage4_padded"] == 3 and pipeline.audit_record(r)["results_padded"] == 3


def test_no_padding_when_llm_fills_the_slots_or_not_ranked(monkeypatch):
    sel = [{"link": "a"}, {"link": "b"}]
    assert llm.pad_with_term_matches(Q, sel, RESULTS, 2) == []
    assert llm.pad_with_term_matches("ransomware news", [], RESULTS, 5) == []  # só termos de contexto

    def none_keyword(_llm, q, results):
        llm.last_filter_outcome = "none_keyword"
        return [results[1]]
    monkeypatch.setattr(llm, "filter_results", none_keyword)
    r = pipeline.PipelineResult(query=Q, search_results=[dict(x) for x in RESULTS])
    pipeline.stage_filter(r, None, 5)
    assert r.stage4_padded == 0 and [x["selected_by"] for x in r.filtered] == ["none_keyword"]


def test_report_lists_partial_pages(fake_llm, monkeypatch):
    monkeypatch.setattr(pipeline, "tor_available", lambda *a, **k: True)
    monkeypatch.setattr(pipeline, "get_active_engines", lambda: [{"name": "E1"}])
    spam = "akira leak akira leak akira leak " * 40
    r = _run(fake_llm, "1, 5", 6, {"http://akira1.onion/": AKIRA, "http://akira3.onion/": AKIRA,
                                "http://news.onion/": OTHER, "http://wiki.onion/": spam})
    assert not r.scraped_content
    text = r.summary
    assert "5 resultado(s) escolhido(s) para recolha (2 pelo modelo + 3 por termos da query; desfecho: `ranked`)" in text
    section = text.split("### Páginas com evidência parcial", 1)[1].split("###", 1)[0]
    assert "[Akira blog mirror](http://akira1.onion/) — akira ✓ · portugal ✗" in section
    assert "[akira leaks](http://akira3.onion/) — akira ✓ · portugal ✗" in section
    assert "news.onion" not in section and "wiki.onion" not in section  # sem termos-chave / spam
    assert "evidência parcial no Tor Browser" in text and "não falam do alvo" not in text


def test_no_partial_section_without_key_terms():
    r = pipeline.PipelineResult(query="Akira Portugal")
    r.search_results, r.filtered = [{"link": "x"}], [{"link": "a", "title": "t"}]
    r.scrape_outcomes, r.pages_valid = {"ok": 1}, 1
    r.relevance_scores = {"a": {"found": [], "key_found": 0, "score": 0}}
    text = pipeline.no_evidence_report(r)
    assert "evidência parcial" not in text and "alias do grupo" in text


def test_partial_title_cannot_break_markdown():
    r = pipeline.PipelineResult(query="Akira Portugal")
    r.filtered = [{"link": "http://a.onion/", "title": "Akira [leak](http://evil)"}]
    r.relevance_scores = {"http://a.onion/": {"found": ["akira"], "key_found": 1, "score": .5}}
    assert pipeline._partial_pages(r) == [("- [Akira  leak  http://evil](http://a.onion/) — akira ✓ · portugal ✗", False)]


def _real_run_1141():
    """A execução de 11/10 às 11:41 (reduzida): só homónimos e um bloqueio da salvaguarda."""
    r = pipeline.PipelineResult(query=Q, refined_query="Akira ransomware Portugal companies")
    r.engine_status, r.search_stats = {"E1": "ok"}, {"E1": {"status": "ok_results"}}
    r.search_results = [{"link": "x"}] * 47
    toriyama, debconf, other = "http://cgx.onion/toriyama-akira", "http://mk5.onion/", "http://z.onion/"
    r.filtered = [{"link": toriyama, "title": "Akira Toriyama ✏️  Wiki CgX"},
                  {"link": debconf, "title": "MiniDebConf Portugal 2023"}, {"link": other, "title": "z"}]
    r.stage4_outcome, r.stage4_padded = "ranked", 1
    r.scrape_outcomes = {"ok": 3, "timeout": 2, "blocked_safety": 1, "too_short": 1}
    r.safety_blocked, r.pages_valid = 1, 3
    r.relevance_scores = {toriyama: {"found": ["akira"], "key_found": 1, "score": .3},
                          debconf: {"found": ["portugal"], "key_found": 1, "score": .3},
                          other: {"found": [], "key_found": 0, "score": 0}}
    return r


def test_homonyms_are_flagged_not_hidden():
    text = pipeline.no_evidence_report(_real_run_1141())
    section = text.split("### Páginas com evidência parcial", 1)[1].split("###", 1)[0]
    lines = [x for x in section.splitlines() if x.startswith("- ")]
    assert len(lines) == 2 and all("possível homónimo" in x for x in lines)
    assert "akira ✓ · portugal ✗ · contexto: ransomware ✗, alvos ✗" in lines[0]
    assert "alias do grupo" in text  # só homónimos: volta a sugestão de reformular


def test_page_with_context_term_comes_before_homonym():
    r = _real_run_1141()
    r.filtered.append({"link": "http://ak.onion/", "title": "Akira"})
    r.relevance_scores["http://ak.onion/"] = {"found": ["akira", "ransomware"], "key_found": 1, "score": .4}
    rows = pipeline._partial_pages(r)
    assert rows[0] == ("- [Akira](http://ak.onion/) — akira ✓ · portugal ✗ · contexto: ransomware ✓, alvos ✗", False)
    assert [h for _, h in rows] == [False, True, True]
    assert "alias do grupo" not in pipeline.no_evidence_report(r)


def test_no_homonym_flag_without_context_terms():
    r = pipeline.PipelineResult(query="Akira Portugal")
    r.relevance_scores = {"http://a.onion/": {"found": ["akira"], "key_found": 1, "score": .5}}
    [(line, homonym)] = pipeline._partial_pages(r)
    assert not homonym and "homónimo" not in line and "contexto" not in line


def test_safety_block_is_counted_once():
    text = pipeline.no_evidence_report(_real_run_1141())
    recolha = next(x for x in text.splitlines() if x.startswith("- **Recolha"))
    assert "blocked_safety" not in recolha
    assert recolha.count("salvaguarda") == 1 and "1 bloqueada(s) pela salvaguarda ética" in recolha


def test_eq03_ignores_term_padded_sources(tmp_path):
    U = lambda i: f"http://site{i}.onion/p"  # noqa: E731
    run = {"scenario_id": "A1", "model": "M", "pipeline_version": "2.3",
           "search_results": [{"title": "t", "link": U(i), "found_by": ["E"]} for i in range(5)],
           "sources": [{"link": U(0), "selected_by": "llm"}, {"link": U(1), "selected_by": "terms"},
                       {"link": U(2)}]}
    (tmp_path / "eval_A1_20261011_100000.json").write_text(json.dumps(run), encoding="utf-8")
    runs = eq02_eq03.load_darksherlock_runs(str(tmp_path / "eval_A1_*.json"), "A1")
    assert runs[0]["top20"] == [eq02_eq03.normalize_url(U(0)), eq02_eq03.normalize_url(U(2))]
