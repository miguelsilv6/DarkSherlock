import csv
import json

import true_negatives as TN

MODEL = "Phi X"
NO_EV = "## Sem evidência suficiente para análise\n\nnada"
WITH_EV = "## 1. Query: x\n\n## 2. Análise por Fonte\n[FONTE 1] y"


def _inv(folder, sc, k, summary, version="2.3", model=MODEL):
    json.dump({"scenario_id": sc, "model": model, "pipeline_version": version, "summary": summary},
              open(folder / f"eval_{sc}_20261110_1{k}0000.json", "w", encoding="utf-8"))


def _pool(gt, sc, labels):
    for who in ("A", "B"):
        with open(gt / f"review_{sc}_{who}.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["n", "url", "title", "label", "notes"])
            for i, label in enumerate(labels):
                w.writerow([i, f"http://{sc.lower()}{i}.onion/", "", label, ""])


def test_classification_with_pool_and_manual(tmp_path):
    inv, man, gt = tmp_path / "inv", tmp_path / "man", tmp_path / "gt"
    for d in (inv, man / "reports", gt):
        d.mkdir(parents=True)
    for k in range(3):
        _inv(inv, "A1", k, WITH_EV)                       # positivo, pool com relevantes -> VP
        _inv(inv, "A2", k, NO_EV)                         # negativo, pool sem relevantes -> VN
        _inv(inv, "B1", k, NO_EV)                         # negativo, pool com relevantes -> FN
        _inv(inv, "B2", k, NO_EV)                         # negativo, sem pool, manual 0 fontes -> VN (provável)
        _inv(inv, "C1", k, NO_EV if k < 2 else WITH_EV)   # maioria negativa, sem referência -> por determinar
    _inv(inv, "D1", 0, NO_EV, version="1.0-legacy")       # outra versão: ignorada com --pipeline-version
    _inv(inv, "D2", 0, NO_EV, model="Outro")              # outro modelo: ignorado
    _pool(gt, "A1", ["relevant", "not_relevant"])
    _pool(gt, "A2", ["not_relevant", "inaccessible"])
    _pool(gt, "B1", ["relevant"])
    (man / "sources" / "B2").mkdir(parents=True)
    runs = TN.load_runs(str(inv / "eval_*.json"), MODEL, "20261101", "2.3")
    assert set(runs) == {"A1", "A2", "B1", "B2", "C1"}
    rows = {r["scenario"]: r for r in TN.build(runs, man, gt)}
    assert rows["A1"]["label"] == "Verdadeiro positivo"
    assert rows["A2"]["label"] == "Verdadeiro negativo"
    assert rows["B1"]["label"] == "Falso negativo"
    assert rows["B2"]["label"] == "Verdadeiro negativo (provável)"
    assert rows["C1"]["label"] == "por determinar" and rows["C1"]["no_evidence"] == 2
    md = TN.render(list(rows.values()), {"model": MODEL, "since": "20261101", "pipeline_version": "2.3"})
    assert "| Verdadeiro negativo | 2 (A2, B2) |" in md
    assert "2 de 3 com referência são verdadeiros negativos" in md


def test_mixed_versions_refused(tmp_path):
    _inv(tmp_path, "A1", 0, NO_EV, version="2.3")
    _inv(tmp_path, "A2", 0, NO_EV, version="1.0-legacy")
    assert TN.main(["--investigations", str(tmp_path / "eval_*.json"), "--model", MODEL,
                    "--out", str(tmp_path / "o.md")]) == 2
    assert TN.main(["--investigations", str(tmp_path / "eval_*.json"), "--model", MODEL, "--pipeline-version", "2.3",
                    "--ground-truth", str(tmp_path / "nada"), "--out", str(tmp_path / "o.md")]) == 0
    assert "| A1 | 1 | 1/1 |" in (tmp_path / "o.md").read_text(encoding="utf-8")


def test_half_and_half_is_mixed(tmp_path):
    _inv(tmp_path, "A1", 0, NO_EV)
    _inv(tmp_path, "A1", 1, WITH_EV)
    rows = TN.build(TN.load_runs(str(tmp_path / "eval_*.json"), MODEL, "0", None), tmp_path, None)
    assert rows[0]["label"] == "misto"
