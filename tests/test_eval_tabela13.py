import csv
import itertools
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

import tabela13 as T

ROOT = Path(__file__).resolve().parent.parent
SC = [f"{x}{n}" for x in "ABCD" for n in "123"]


def test_wilcoxon_against_scipy():
    stats = pytest.importorskip("scipy.stats")
    rng = random.Random(11)
    for _ in range(300):
        d = [rng.uniform(-100, 100) for _ in range(rng.randint(2, 12))]
        for alt in ("less", "greater", "two-sided"):
            assert abs(T.wilcoxon_signed_rank(d, alt)["p"] - stats.wilcoxon(d, alternative=alt, method="exact").pvalue) < 1e-12


def test_wilcoxon_ties_brute_force():
    d = [3, -3, 5, 1, -1, 2, 2, -4]
    absd = [abs(x) for x in d]
    ranks = [sum(1 for b in absd if b < a) + (sum(1 for b in absd if b == a) + 1) / 2 for a in absd]
    obs = sum(rk for rk, x in zip(ranks, d) if x > 0)
    cnt = sum(1 for s in itertools.product((0, 1), repeat=len(d))
              if sum(rk for rk, si in zip(ranks, s) if si) <= obs + 1e-9)
    assert abs(cnt / 2 ** len(d) - T.wilcoxon_signed_rank(d, "less")["p"]) < 1e-12


def test_end_to_end(tmp_path):
    inv, res = tmp_path / "inv", tmp_path / "res"
    inv.mkdir(); res.mkdir()
    rows = []
    for i, sc in enumerate(SC):
        for k in range(3):
            fn = f"eval_{sc}_20261009_1{k}{i:02d}00.json"
            json.dump({"model": "M", "scenario_id": sc}, open(inv / fn, "w"))
            rows.append({"scenario_id": sc, "investigation_file": fn, "total_ms": 600000 + k * 1000 + i * 10000,
                         "refine_query_ms": 2000, "search_ms": 30000, "filter_results_ms": 100000,
                         "scrape_ms": 40000, "generate_summary_ms": 400000, "run_idx": k + 1})
    json.dump({"model": "Outro", "scenario_id": "A1"}, open(inv / "eval_A1_20261009_230000.json", "w"))
    rows.append({**rows[0], "investigation_file": "eval_A1_20261009_230000.json", "total_ms": 1})
    half = len(rows) // 2
    for name, chunk in (("raw_runs_1.csv", rows[:half]), ("raw_runs_2.csv", rows[half:])):
        with open(res / name, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(chunk[0].keys())); w.writeheader(); w.writerows(chunk)
    tl = tmp_path / "timing_log.csv"
    with open(tl, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario_id", "stage_num", "stage_name", "start_utc", "end_utc", "duration_s"])
        w.writeheader()
        for sc in SC[:10]:
            for st, dur in ((1, 300), (2, 900), (3, 1200), (4, 2400), (5, 1800)):
                w.writerow({"scenario_id": sc, "stage_num": st, "stage_name": "x", "start_utc": "", "end_utc": "", "duration_s": dur})
        w.writerow({"scenario_id": "A1", "stage_num": 3, "stage_name": "x", "start_utc": "", "end_utc": "", "duration_s": 1000})
    r = subprocess.run([sys.executable, str(ROOT / "evaluation" / "tabela13.py"), "--model", "M", "--since", "20261009",
                        "--raw", str(res / "raw_runs_*.csv"), "--investigations", str(inv), "--timing-log", str(tl),
                        "--out", str(tmp_path / "o.md")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Global (n = 10)" in r.stdout and "etapa 3: 2 registos" in r.stdout
    assert "| A1 | 3 | 601.0 | 1.0 | 6400.0 | 10.65 |" in r.stdout
