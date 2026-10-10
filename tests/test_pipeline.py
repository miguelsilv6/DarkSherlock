"""PR 5 — pipeline partilhado (pipeline.py): ponta a ponta com LLM, pesquisa e recolha falsos."""

import json
import os
import re

import pytest

import pipeline

_REAL_TOR_CHECK = pipeline.tor_available  # antes de a fixture o substituir

BODY = ("O grupo LockBit publicou no seu leak site a lista de vítimas da semana, com datas, "
        "montantes exigidos e amostras dos ficheiros. A página inclui instruções de negociação. ") * 3

RESULTS = [
    {"title": "LockBit leak site mirror", "link": "http://aaaa.onion/a", "found_by": ["E1"]},
    {"title": "LockBit victims blog", "link": "http://bbbb.onion/b", "found_by": ["E2"]},
    {"title": "Random market", "link": "http://cccc.onion/c", "found_by": ["E1"]},
]


def _search_fn(query, threads):
    res = [dict(r, retrieved_at_utc="2026-10-01T00:00:00+00:00") for r in RESULTS]
    return res, {"E1": "ok", "E2": "ok", "E3": "failed"}, {"E1": {"status": "ok_results"}}, "2026-10-01T00:00:00+00:00"


def _scrape_fn(filtered, threads):
    pages = {"http://aaaa.onion/a": BODY, "http://bbbb.onion/b": "pagina sem o termo " * 30}
    scraped = {it["link"]: pages[it["link"]] for it in filtered if it["link"] in pages}
    details = {it["link"]: {"status": "ok" if it["link"] in pages else "timeout"} for it in filtered}
    return scraped, details, 0


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr(pipeline, "get_active_engines", lambda: [{"name": "E1"}, {"name": "E2"}, {"name": "E3"}])
    monkeypatch.setattr(pipeline, "tor_available", lambda *a, **k: True)


def _llm(fake_llm, summary="## 1. Query: lockbit leak site\n\nO LockBit [FONTE 1]."):
    return fake_llm("lockbit leak site", "2, 1, 3", summary)


def test_run_pipeline_end_to_end(fake_llm):
    r = pipeline.run_pipeline("lockbit leak site", "threat_intel", _llm(fake_llm), model="m",
                              max_results=50, max_scrape=3, threads=2,
                              search_fn=_search_fn, scrape_fn=_scrape_fn)
    assert r.pipeline_version == "2.0"
    assert r.refined_query == "lockbit leak site"
    assert r.stage4_outcome == "ranked"
    assert [x["link"] for x in r.filtered] == ["http://bbbb.onion/b", "http://aaaa.onion/a", "http://cccc.onion/c"]
    assert r.scrape_outcomes == {"ok": 2, "timeout": 1}
    assert r.pages_valid == 2 and r.pages_failed == 1
    # a página b não menciona "lockbit" no texto (só no título): fica de fora
    assert list(r.scraped_content) == ["http://aaaa.onion/a"]
    assert r.stage5_outcome == "kept"
    assert set(r.integrity["sources"]) == {"http://aaaa.onion/a"}
    assert any("scraped_at_utc" in x for x in r.filtered if x["link"] == "http://aaaa.onion/a")
    assert not any("scraped_at_utc" in x for x in r.filtered if x["link"] != "http://aaaa.onion/a")
    assert "Evidência limitada" in r.summary  # uma única fonte
    assert set(r.timings_ms) == {"refine_query", "search", "filter_results", "scrape", "generate_summary"}
    assert r.timestamp_utc and r.total_ms >= 0 and not r.errors


def test_max_limits_applied(fake_llm):
    r = pipeline.run_pipeline("lockbit leak site", "threat_intel", _llm(fake_llm), max_results=2, max_scrape=1,
                              search_fn=_search_fn, scrape_fn=_scrape_fn)
    assert len(r.search_results) == 2 and len(r.filtered) == 1


def test_record_has_every_field_and_roundtrips(fake_llm, tmp_path):
    r = pipeline.run_pipeline("lockbit leak site", "threat_intel", _llm(fake_llm), model="m",
                              search_fn=_search_fn, scrape_fn=_scrape_fn)
    rec = pipeline.investigation_record(r, preset_label="Dark Web Threat Intel", scenario_id="A1")
    for k in ("audit_id", "timestamp_utc", "pipeline_version", "query", "refined_query", "model", "preset",
              "preset_key", "active_engines", "sources", "search_results", "engine_status", "search_stats",
              "stage4_outcome", "scrape_outcomes", "safety_blocked", "stage5_outcome", "relevance_scores",
              "summary", "ioc_check", "integrity", "scraped_content", "warnings", "errors", "timings_ms",
              "total_ms", "scenario_id"):
        assert k in rec, k
    assert rec["preset"] == "Dark Web Threat Intel" and rec["preset_key"] == "threat_intel"
    fname = pipeline.save_investigation(rec, tmp_path, prefix="eval_A1")
    assert re.fullmatch(r"eval_A1_\d{8}_\d{6}\.json", fname)  # formato que as ferramentas de avaliação leem
    assert json.loads((tmp_path / fname).read_text(encoding="utf-8"))["audit_id"] == r.audit_id
    if os.name == "posix":
        assert (tmp_path.stat().st_mode & 0o777) == 0o700
    audit = pipeline.audit_record(r)
    assert audit["engines_attempted"] == 3 and audit["engines_failed"] == 1
    assert audit["results_scraped"] == 1


def test_save_never_overwrites(tmp_path):
    names = {pipeline.save_investigation({"n": i}, tmp_path, prefix="x") for i in range(2)}
    assert len(names) == 2


def test_failure_keeps_partial_result(fake_llm):
    def broken_scrape(filtered, threads):
        raise RuntimeError("tor caiu")

    with pytest.raises(pipeline.PipelineError) as ei:
        pipeline.run_pipeline("lockbit leak site", "threat_intel", _llm(fake_llm),
                              search_fn=_search_fn, scrape_fn=broken_scrape)
    e = ei.value
    assert e.stage == "scrape" and "tor caiu" in str(e)
    assert e.result.search_results and e.result.filtered and e.result.errors == ["scrape: tor caiu"]


def test_warnings_tor_down_and_all_engines_failed(monkeypatch, fake_llm):
    monkeypatch.setattr(pipeline, "tor_available", lambda *a, **k: False)
    r = pipeline.PipelineResult(query="lockbit")
    pipeline.stage_search(r, 50, 1, search_fn=lambda q, t: ([], {"E1": "failed", "E2": "failed"}, {}, ""))
    assert any("Tor inacessível" in w for w in r.warnings)
    assert any("Todos os motores" in w for w in r.warnings)


def test_warning_when_no_page_mentions_the_query(fake_llm):
    r = pipeline.PipelineResult(query="akira")
    r.filtered = [{"title": "Akira", "link": "http://aaaa.onion/a"}]
    pipeline.stage_scrape(r, 1, scrape_fn=_scrape_fn)
    assert r.stage5_outcome == "empty" and not r.scraped_content
    assert any("menciona os termos" in w for w in r.warnings)


def test_cacheability():
    assert pipeline.search_is_cacheable(([{"link": "x"}], {"E1": "ok"}, {}, ""))
    assert not pipeline.search_is_cacheable(([], {"E1": "ok"}, {}, ""))
    assert not pipeline.search_is_cacheable(([{"link": "x"}], {"E1": "ok", "E2": "failed"}, {}, ""))
    assert pipeline.scrape_is_cacheable(({}, {"u": {"status": "http_error"}}, 0))
    assert not pipeline.scrape_is_cacheable(({}, {"u": {"status": "timeout"}}, 0))


def test_search_with_stats_stamps_retrieval_time(monkeypatch):
    import search as search_module
    monkeypatch.setattr(search_module, "get_search_results",
                        lambda q, max_workers=5: ([{"title": "t", "link": "http://aaaa.onion"}], {"E1": "ok"}))
    monkeypatch.setattr(search_module, "last_search_stats", {"E1": {"status": "ok_results"}})
    res, status, stats, at = pipeline.search_with_stats("q", 1)
    assert res[0]["retrieved_at_utc"] == at and stats == {"E1": {"status": "ok_results"}}


def test_tor_available_false_on_closed_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert _REAL_TOR_CHECK("127.0.0.1", port, timeout=0.5) is False
