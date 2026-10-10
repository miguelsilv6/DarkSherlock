import csv
import json
import math
import random
import subprocess
import sys
from pathlib import Path

import pytest

import eq04_review as E

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "evaluation" / "eq04_review.py")
SC = [f"{x}{n}" for x in "ABCD" for n in "123"]


def test_stats_against_scipy_and_sklearn():
    stats = pytest.importorskip("scipy.stats")
    sk = pytest.importorskip("sklearn.metrics")
    rng = random.Random(3)
    for df in (1, 2, 5, 11, 29):
        for t in (-3.1, -0.4, 0, 0.7, 2.2, 5.5):
            assert abs(E.t_sf(t, df) - stats.t.sf(t, df)) < 1e-9
    for _ in range(100):
        v = [rng.choice([1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5]) for _ in range(rng.randint(3, 15))]
        if len(set(v)) == 1:
            continue
        r, ref = E.one_sample_t(v, 3.0, "greater"), stats.ttest_1samp(v, 3.0, alternative="greater")
        assert abs(r["p"] - ref.pvalue) < 1e-9
    for _ in range(200):
        n = rng.randint(4, 40)
        a = [rng.randint(1, 5) for _ in range(n)]
        b = [x if rng.random() < .6 else rng.randint(1, 5) for x in a]
        k = E.weighted_kappa(a, b)
        ref = sk.cohen_kappa_score(a, b, weights="linear", labels=[1, 2, 3, 4, 5])
        assert (math.isnan(k) and math.isnan(ref)) or abs(k - ref) < 1e-9


def test_end_to_end(tmp_path):
    inv, man, out = tmp_path / "inv", tmp_path / "man", tmp_path / "out"
    inv.mkdir(); (man / "reports").mkdir(parents=True); (man / "sources").mkdir()
    for sc in SC:
        for k, stamp in enumerate(("20261009_150000", "20261009_160000")):
            banner = "> ⚠️ **Aviso de qualidade:** x\n\n" if (sc == "A1" and k == 0) else ""
            json.dump({"scenario_id": sc, "model": "Phi X", "summary": banner + f"## 1. Query: {sc}\n\n## 2. Análise\n",
                       "scraped_content": {f"http://{sc}{k}.onion": "texto"}}, open(inv / f"eval_{sc}_{stamp}.json", "w"))
        json.dump({"scenario_id": sc, "model": "Other", "summary": "x"}, open(inv / f"eval_{sc}_20261009_170000.json", "w"))
        (man / "reports" / f"report_{sc}.md").write_text(
            f"<!-- i -->\n# Baseline\n\n## Metadados\n- **Investigador:** eu\n\n## 1. Query: {sc}\n\n"
            "### Fonte 1\n- **URL:** http://m.onion\n- **SHA-256** (`x`): abc\n- **Timestamp de recolha (UTC):** 2026\n",
            encoding="utf-8")
        (man / "sources" / sc).mkdir()
        (man / "sources" / sc / "fonte1.txt").write_text("conteudo", encoding="utf-8")
    run = lambda *a: subprocess.run([sys.executable, SCRIPT, *a], capture_output=True, text=True)  # noqa: E731
    r = run("build", "--investigations", str(inv / "eval_*.json"), "--model", "Phi X", "--since", "20261001",
            "--manual-dir", str(man), "--out", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    key = json.load(open(out / "private" / "key.json"))["reports"]
    assert len(key) == 24
    assert all("_150000" in v["source_file"] for v in key.values() if v["condition"] == "DarkSherlock")
    for rid in key:
        t = (out / "reviewer_A" / "reports" / f"{rid}.md").read_text(encoding="utf-8")
        assert not any(s in t for s in ("⚠", "SHA-256", "Timestamp", "Metadados", "Investigador"))
    oa = [r["id"] for r in csv.DictReader(open(out / "reviewer_A" / "scores_A.csv", encoding="utf-8-sig"))]
    ob = [r["id"] for r in csv.DictReader(open(out / "reviewer_B" / "scores_B.csv", encoding="utf-8-sig"))]
    assert sorted(oa) == sorted(ob) and oa != ob
    assert run("analyze", "--out", str(out)).returncode == 1
    for who, dev in (("A", False), ("B", True)):
        p = out / f"reviewer_{who}" / f"scores_{who}.csv"
        rows = list(csv.DictReader(open(p, encoding="utf-8-sig")))
        for r in rows:
            s = [4, 4, 4, 4] if key[r["id"]]["condition"] == "DarkSherlock" else [3, 3, 3, 3]
            if dev and r["id"] == "R01":
                s[0] = 1 if s[0] >= 3 else 5
            for d, v in zip(E.DIMENSIONS, s):
                r[d] = v
            r["afirmacoes_verificaveis"], r["afirmacoes_citacao_valida"] = 10, 8
        with open(p, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    r = run("analyze", "--out", str(out))
    assert r.returncode == 1 and "divergência" in r.stdout
    div = list(csv.DictReader(open(out / "divergences.csv", encoding="utf-8-sig")))
    assert len(div) == 1
    div[0]["score_final"] = "3"
    with open(out / "divergences.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=div[0].keys()); w.writeheader(); w.writerows(div)
    r = run("analyze", "--out", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Global (H1 principal)" in r.stdout
