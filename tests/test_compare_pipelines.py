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
    rc = C.main(["compare", "--investigations", str(runs / "eval_*.json"), "--model", "M", "--new", "2.0"])
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


def _set(path, **fields):
    d = json.loads(path.read_text(encoding="utf-8"))
    d.update(fields)
    path.write_text(json.dumps(d), encoding="utf-8")


def test_compare_skips_scenarios_whose_query_changed(runs, capsys, monkeypatch):
    import run_kinds
    monkeypatch.setattr(run_kinds, "RESULTS_DIR", runs / "results")
    for f in runs.glob("eval_A1_*.json"):
        _set(f, query="lockbit leak site")
    _set(runs / "eval_A2_20261001_100001.json", query="credential dump forum 2026")   # sintética (v1)
    _set(runs / "eval_A2_20261011_100001.json", query="RockYou2024 password leak")     # caso real (v2)
    assert C.main(["compare", "--investigations", str(runs / "eval_*.json"), "--model", "M", "--new", "2.0"]) == 0
    out = capsys.readouterr().out
    a2 = next(ln for ln in out.splitlines() if ln.startswith("| A2 |"))
    assert "não comparável" in a2
    assert "Cenários comparáveis (a mesma query nas duas versões): 1 de 2" in out
    assert "rockyou" not in out.lower() and "credential" not in out.lower()   # as queries nunca saem


def test_compare_excludes_induced_resilience_runs(runs, capsys, monkeypatch):
    import run_kinds
    monkeypatch.setattr(run_kinds, "RESULTS_DIR", runs / "results")
    _set(runs / "eval_A1_20261011_100000.json", eval_run_kind="induced_resilience")
    C.main(["compare", "--investigations", str(runs / "eval_*.json"), "--model", "M", "--new", "2.0"])
    a1 = next(ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("| A1 |"))
    assert "| 1/0 |" in a1


def test_fisher_exact_by_hand():
    assert C.fisher_exact(3, 0, 0, 3) == pytest.approx(0.1)          # 2 / C(6,3) bilateral
    assert C.fisher_exact(1, 1, 1, 1) == pytest.approx(1.0)
    assert C.fisher_exact(2, 1, 0, 3) == pytest.approx(0.4)


def test_negative_control_section(tmp_path, capsys, monkeypatch):
    """Entidades fictícias: v1 com fontes (falsos positivos), v2 sem; os temas reais ficam à parte."""
    import run_kinds
    monkeypatch.setattr(run_kinds, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(C, "_excluded_hosts", lambda: set())
    pool = [{"title": "x", "link": _onion("a"), "found_by": ["E1"]}]
    rows = [("C1", "john.doe@example-corp.test breach", {_onion("a"): "x", _onion("b"): "y"}, {}),
            ("D2", "example-corp API key dump", {_onion("a"): "x"}, {}),
            ("A1", "lockbit leak site", {_onion("a"): "x"}, {_onion("a"): "x", _onion("b"): "y"})]
    for i, (sc, q, v1, v2) in enumerate(rows):
        for j, (ver, scraped) in enumerate(((None, v1), ("2.0", v2))):
            name = f"eval_{sc}_2026100{j + 1}_10000{i}.json"
            _run(tmp_path, name, sc, ver, pool, [], scraped)
            d = json.loads((tmp_path / name).read_text(encoding="utf-8"))
            d["query"] = q
            (tmp_path / name).write_text(json.dumps(d), encoding="utf-8")
    assert C.main(["compare", "--investigations", str(tmp_path / "eval_*.json"), "--model", "M", "--new", "2.0"]) == 0
    out = capsys.readouterr().out
    section = out.split("Controlo negativo", 1)[1]
    assert "- 1.0-legacy: 2 de 2 execuções (100%) com ≥ 1 fonte final; média 1.5" in section
    assert "- 2.0: 0 de 2 execuções (0%) com ≥ 1 fonte final" in section
    assert "Fisher (bilateral, execuções independentes): p = 0.3333" in section
    assert "example-corp" not in out and "lockbit" not in out.lower()      # as queries nunca saem
