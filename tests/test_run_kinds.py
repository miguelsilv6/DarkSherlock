"""evaluation/run_kinds.py — tipo de recolha de cada investigação de avaliação."""

import csv
import json
import runpy
import sys
from pathlib import Path

import run_kinds as K

CHECK_RUNS = Path(__file__).resolve().parent.parent / "evaluation" / "check_runs.py"


def _csv(path, files):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["scenario_id", "investigation_file"])
        w.writeheader()
        for f in files:
            w.writerow({"scenario_id": "A1", "investigation_file": f})


def test_index_from_csvs_and_priority(tmp_path):
    _csv(tmp_path / "raw_runs_20261011_1.csv", ["eval_A1_20261011_000001.json"])
    _csv(tmp_path / "multi_model_runs_20261011_2.csv", ["eval_A1_20261011_000002.json"])
    _csv(tmp_path / "induced_resilience_20261011_3.csv", ["eval_A1_20261011_000003.json"])
    idx = K.index(tmp_path)
    assert idx == {"eval_A1_20261011_000001.json": "scenarios", "eval_A1_20261011_000002.json": "multi_model",
                   "eval_A1_20261011_000003.json": "induced_resilience"}
    assert K.kind_of({}, "investigations/eval_A1_20261011_000003.json", idx) == "induced_resilience"
    assert K.kind_of({"eval_run_kind": "multi_model"}, "eval_A1_20261011_000001.json", idx) == "multi_model"
    assert K.kind_of({}, "eval_A1_antigo.json", idx) == "scenarios"          # anterior ao campo: como até aqui
    assert K.keep({}, "eval_A1_20261011_000003.json", idx, "scenarios") is False
    assert K.keep({}, "eval_A1_20261011_000003.json", idx, "any") is True


def test_check_runs_counts_only_protocol_runs(tmp_path, monkeypatch, capsys):
    inv, res = tmp_path / "investigations", tmp_path / "results"
    inv.mkdir()
    res.mkdir()
    names = [f"eval_A1_20261011_00000{i}.json" for i in range(3)]
    for n in names:
        (inv / n).write_text(json.dumps({"model": "M", "scenario_id": "A1", "pipeline_version": "2.3",
                                         "search_results": [], "sources": [], "scraped_content": {},
                                         "stage4_outcome": "ranked"}), encoding="utf-8")
    _csv(res / "raw_runs_x.csv", names[:2])
    _csv(res / "induced_resilience_x.csv", names[2:])
    monkeypatch.setattr(K, "RESULTS_DIR", res)
    monkeypatch.setattr(sys, "argv", ["check_runs", "--model", "M", "--dir", str(inv), "--expected", "2"])
    try:
        runpy.run_path(str(CHECK_RUNS), run_name="__main__")
    except SystemExit:
        pass
    out = capsys.readouterr().out
    a1 = next(ln for ln in out.splitlines() if ln.startswith("A1"))
    assert a1.split()[1] == "2"
    assert "Execuções por tipo de recolha: induced_resilience 1, scenarios 2" in out


def test_run_one_records_the_run_kind(tmp_path, monkeypatch):
    import pipeline
    import run_scenarios as RS
    monkeypatch.setattr(RS, "INVESTIGATIONS_DIR", tmp_path)
    monkeypatch.setattr(RS, "log_investigation", lambda rec: None)
    monkeypatch.setattr(RS.pipeline, "run_pipeline", lambda q, p, llm, **k: pipeline.PipelineResult(query=q))
    sc = {"id": "A1", "domain": "Threat Intel", "preset": "threat_intel", "query": "lockbit"}
    row = RS.run_one(sc, "M", None, run_kind="induced_resilience", disabled_engine="Ahmia")
    rec = json.loads((tmp_path / row["investigation_file"]).read_text(encoding="utf-8"))
    assert rec["eval_run_kind"] == "induced_resilience" and rec["disabled_engine"] == "Ahmia"
    row = RS.run_one(sc, "M", None)
    assert json.loads((tmp_path / row["investigation_file"]).read_text(encoding="utf-8"))["eval_run_kind"] == "scenarios"
