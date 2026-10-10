"""Medição v1 -> v2 (evaluation/compare_pipelines.py) sobre execuções fictícias."""

import json

import pytest

import compare_pipelines as C

ENGINE_HOST = "e" * 56 + ".onion"


def _onion(c):
    return f"http://{c * 56}.onion/p"


def _run(tmp, name, sc, version, results, sources, scraped, ioc=None, stage5=None):
    d = {"model": "M", "scenario_id": sc, "search_results": results, "sources": sources,
         "scraped_content": scraped, "stage4_outcome": "ranked"}
    if version:
        d["pipeline_version"] = version
    if ioc is not None:
        d["ioc_check"] = ioc
    if stage5:
        d["stage5_outcome"] = stage5
    (tmp / name).write_text(json.dumps(d), encoding="utf-8")


@pytest.fixture
def runs(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "_excluded_hosts", lambda: {ENGINE_HOST})
    v1_pool = [
        {"title": "LockBit leak", "link": _onion("a"), "found_by": ["E1"]},
        {"title": "darkmarketdarkmarketdarkmarket", "link": _onion("b"), "found_by": ["E1"]},  # spam
        {"title": "Marketplaces", "link": _onion("c"), "found_by": ["E2"]},                     # navegação
        {"title": "Home", "link": f"http://{ENGINE_HOST}/", "found_by": ["E2"]},               # motor
    ] + [{"title": f"Mirror {i}", "link": f"http://{'d' * 56}.onion/{i}", "found_by": ["E1"]} for i in range(5)]
    for sc, i in (("A1", 0), ("A2", 1)):
        _run(tmp_path, f"eval_{sc}_20261001_10000{i}.json", sc, None, v1_pool,
             [{"link": _onion("b")}, {"link": _onion("a")}], {_onion("a"): "x"})
        _run(tmp_path, f"eval_{sc}_20261011_10000{i}.json", sc, "2.0", v1_pool[:1],
             [{"link": _onion("a")}], {_onion("a"): "x", _onion("f"): "y", _onion("g"): "z"},
             ioc={"total": 4, "verified": 3, "unverified": ["1.2.3.4"]}, stage5="kept")
    return tmp_path


def test_replay_counts_what_v2_filters_drop(runs, capsys):
    rc = C.main(["replay", "--investigations", str(runs / "eval_*.json"), "--model", "M"])
    out = capsys.readouterr().out
    assert rc == 0
    a1 = next(ln for ln in out.splitlines() if ln.startswith("| A1 |"))
    cells = [c.strip() for c in a1.strip("|").split("|")]
    # n, pool antes, pool depois, spam, nav, motor, hosts únicos, máx./host, Top-K, Top-K descartável
    assert cells[1:7] == ["1", "9.0", "4.0", "1.0", "2.0", "1.0"]  # "Home" é nav e motor (não exclusivas)
    assert cells[8] == "5.0 / 3.0"        # 5 mirrors do mesmo host -> máx. 3
    assert cells[9:] == ["2.0", "1.0"]    # o item de spam do Top-K seria descartado
    assert "Total: 2 execuções" in out
    assert "onion" not in out             # sem URLs na saída


def test_compare_two_versions(runs, capsys):
    rc = C.main(["compare", "--investigations", str(runs / "eval_*.json"), "--model", "M"])
    out = capsys.readouterr().out
    assert rc == 0
    a1 = next(ln for ln in out.splitlines() if ln.startswith("| A1 |"))
    cells = [c.strip() for c in a1.strip("|").split("|")]
    assert cells[1:5] == ["1/1", "1.0", "3.0", "100"]
    assert cells[10] == "75"              # 3 de 4 IOCs verificados
    assert "fontes finais: n = 2 cenários" in out


def test_compare_without_new_runs_explains(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(C, "_excluded_hosts", lambda: set())
    _run(tmp_path, "eval_A1_20261001_100000.json", "A1", None, [], [], {})
    assert C.main(["compare", "--investigations", str(tmp_path / "eval_*.json"), "--model", "M"]) == 1
    assert "Repete a bateria" in capsys.readouterr().out
