import csv
import json
import math
import random
import subprocess
import sys
from pathlib import Path

import pytest

import eq02_eq03 as m

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "evaluation" / "eq02_eq03.py")
U = lambda i: f"http://site{i}.onion/p"  # noqa: E731


def sh(*args):
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)


def fill(path, labeler):
    rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
    for r in rows:
        r["label"] = labeler(m.normalize_url(r["url"]))
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)


def test_kappa_against_sklearn():
    sk = pytest.importorskip("sklearn.metrics")
    rng = random.Random(1)
    for _ in range(200):
        n = rng.randint(5, 60)
        a = [rng.choice(m.LABELS) for _ in range(n)]
        b = [x if rng.random() < .7 else rng.choice(m.LABELS) for x in a]
        k, ref = m.cohen_kappa(a, b), sk.cohen_kappa_score(a, b)
        assert (math.isnan(k) and math.isnan(ref)) or abs(k - ref) < 1e-9


def test_precision_recall_f1_by_hand():
    h, n, p, r, f = m.precision_recall_f1(list("abcde"), set("acxy"), {"b"})
    assert (h, n, p, r, f) == (2, 4, .5, .5, .5)
    h, n, p, r, _ = m.precision_recall_f1(list("aab"), {"a"}, set(), k=2)
    assert (h, n, p, r) == (1, 2, .5, 1.0)
    assert math.isnan(m.precision_recall_f1([], {"a"}, set())[2])


def _run_json(model, ids, top, nav=()):
    sr = [{"title": f"t{i}", "link": U(i), "found_by": ["E"]} for i in ids]
    sr += [{"title": f"cat{i}", "link": f"http://amndirxyz.onion/?cat={i}", "found_by": ["Amnesia"]} for i in nav]
    return {"scenario_id": "A1", "model": model, "search_results": sr, "sources": [{"link": l} for l in top]}


def test_end_to_end_with_reconciliation(tmp_path):
    inv, gt, man = tmp_path / "inv", tmp_path / "gt", tmp_path / "man"
    inv.mkdir(); man.mkdir()
    json.dump(_run_json("M", range(1, 31), [U(i) for i in (1, 2, 3, 4, 5, 25, 26)]), open(inv / "eval_A1_20261009_100000.json", "w"))
    json.dump(_run_json("M", range(1, 31), [U(i) for i in (1, 2, 3, 40)]), open(inv / "eval_A1_20261009_110000.json", "w"))
    (man / "manual_sources_A1.csv").write_text("url,title,engine,selected\n" + "".join(
        f"{U(i)},m{i},Torch,{0 if i == 51 else 1}\n" for i in (1, 2, 50, 51)), encoding="utf-8")
    r = sh("build", "--scenario", "A1", "--darksherlock", str(inv / "eval_A1_*.json"),
           "--manual", str(man / "manual_sources_A1.csv"), "--out", str(gt), "--model", "M")
    assert r.returncode == 0, r.stdout + r.stderr
    relev = {m.normalize_url(U(i)) for i in (1, 2, 3, 25, 50)}
    inacc = {m.normalize_url(U(4))}
    lab = lambda u: "relevant" if u in relev else "inaccessible" if u in inacc else "not_relevant"  # noqa: E731
    fill(gt / "review_A1_A.csv", lab)
    fill(gt / "review_A1_B.csv", lambda u: "not_relevant" if u == m.normalize_url(U(3)) else lab(u))
    args = ("analyze", "--ground-truth", str(gt), "--investigations", str(inv / "eval_*.json"),
            "--manual-dir", str(man), "--model", "M")
    r = sh(*args)
    assert r.returncode == 1 and "discord" in r.stdout
    (gt / "review_A1_final.csv").write_text("url,label\n" + U(3) + ",relevant\n", encoding="utf-8")
    r = sh(*args)
    assert r.returncode == 0, r.stdout + r.stderr
    # recall 4/5 = 0.80 em ambas; manual 3/5 = 0.60; P@20 LLM média (4/6, 3/4) = 0.71; 1.os 20: 3/19 = 0.16
    assert "0.80 ± 0.00 (2)" in r.stdout and "| 0.60 |" in r.stdout
    assert "| A1 | 0.71 | 0.16 | 1.00 |" in r.stdout


def test_prelabel_and_model_filter(tmp_path):
    inv, gt = tmp_path / "inv", tmp_path / "gt"
    inv.mkdir()
    json.dump(_run_json("Phi", range(1, 11), [U(1), U(2), "http://amndirxyz.onion/?cat=1"], nav=range(1, 6)),
              open(inv / "eval_A1_20261009_150000.json", "w"))
    json.dump(_run_json("Qwen", range(100, 110), [U(100)]), open(inv / "eval_A1_20261009_120000.json", "w"))
    json.dump(_run_json("Phi", range(200, 210), [U(200)]), open(inv / "eval_A1_20260901_120000.json", "w"))
    (tmp_path / "manual_sources_A1.csv").write_text("url,title,engine,selected\n" + U(1) + ",x,T,1\n" + U(50) + ",y,T,1\n",
                                                   encoding="utf-8")
    r = sh("build", "--scenario", "A1", "--darksherlock", str(inv / "eval_A1_*.json"), "--manual",
           str(tmp_path / "manual_sources_A1.csv"), "--out", str(gt), "--model", "Phi", "--since", "20261001",
           "--prelabel-regex", r"amndir\w+\.onion/\?cat=")
    assert r.returncode == 0, r.stdout + r.stderr
    rows = list(csv.DictReader(open(gt / "review_A1_A.csv", encoding="utf-8-sig")))
    assert len(rows) == 11 and not any("amndir" in x["url"] for x in rows)
    assert len(list(csv.DictReader(open(gt / "prelabel_A1.csv", encoding="utf-8-sig")))) == 5
    relev = {m.normalize_url(U(i)) for i in (1, 3, 50)}
    for w in "AB":
        fill(gt / f"review_A1_{w}.csv", lambda u: "relevant" if u in relev else "not_relevant")
    r = sh("analyze", "--ground-truth", str(gt), "--investigations", str(inv / "eval_*.json"),
           "--manual-dir", str(tmp_path), "--model", "Phi", "--since", "20261001")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "| A1 | 16 | 5 | 3 | 0 |" in r.stdout          # pool 11 revistas + 5 pré-rotuladas
    assert "| A1 | 0.33 | 0.13 |" in r.stdout              # Top-K 1/3; 1.os 20: 2/15
    r = sh("build", "--scenario", "A1", "--darksherlock", str(inv / "eval_A1_*.json"), "--manual",
           str(tmp_path / "manual_sources_A1.csv"), "--out", str(tmp_path / "gt3"), "--model", "Inexistente")
    assert r.returncode == 1 and "Inexistente" in r.stdout
