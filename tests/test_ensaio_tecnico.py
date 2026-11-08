import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import ensaio_tecnico as T

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "evaluation" / "ensaio_tecnico.py")
MODEL = "Phi X"
STAGE_COLS = ["refine_query_ms", "search_ms", "filter_results_ms", "scrape_ms", "generate_summary_ms"]


def make_investigations(tmp_path: Path, scenarios=("A1", "B2"), runs=3, no_evidence=()) -> tuple[Path, Path]:
    inv = tmp_path / "inv"
    inv.mkdir()
    raw_rows = []
    for sc in scenarios:
        for k in range(runs):
            stamp = f"20261010_1{k}0000"
            results = [{"link": f"http://{sc.lower()}r{i}.onion/p", "title": f"t{i}", "found_by": ["Ahmia"]}
                       for i in range(12)]
            name = f"eval_{sc}_{stamp}.json"
            json.dump({
                "scenario_id": sc, "model": MODEL, "pipeline_version": "2.3", "query": f"consulta {sc}",
                "search_results": results,
                "sources": [{"link": r["link"], "selected_by": "llm"} for r in results[:5]],
                "scraped_content": {r["link"]: f"texto {r['title']}" for r in results[:3]},
                "summary": ("## Sem evidência suficiente para análise\n\nnada\n" if sc in no_evidence else
                            f"## 1. Query: x\n\n## 2. Análise por Fonte\n\n[FONTE 1] algo {sc}\n"),
                "stage4_outcome": "ranked",
            }, open(inv / name, "w", encoding="utf-8"))
            raw_rows.append({"scenario_id": sc, "investigation_file": name, "total_ms": 100000 + 1000 * k,
                             **{c: 20000 for c in STAGE_COLS}})
    raw = tmp_path / "raw_runs_20261010_000000.csv"
    with open(raw, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(raw_rows[0]))
        w.writeheader()
        w.writerows(raw_rows)
    return inv, raw


def _digest(folder: Path) -> dict:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.iterdir())}


def _protected_state():
    paths = [ROOT / "evaluation" / "baseline_manual" / "timing_log.csv", ROOT / "evaluation" / "ground_truth",
             ROOT / "evaluation" / "baseline_manual" / "reports"]
    return {str(p): (p.exists(), p.stat().st_mtime if p.exists() else None) for p in paths}


def test_out_dir_rules(tmp_path):
    assert T.out_dir_problem(tmp_path / "x") is None
    assert T.out_dir_problem(ROOT / "evaluation" / "ensaio" / "ENSAIO_FICTICIO_1") is None
    assert T.out_dir_problem(ROOT / "evaluation" / "ensaio") is not None
    assert T.out_dir_problem(ROOT / "evaluation" / "ground_truth" / "x") is not None
    assert T.out_dir_problem(ROOT / "evaluation" / "baseline_manual") is not None


def test_refuses_out_inside_repo():
    r = subprocess.run([sys.executable, SCRIPT, "--model", MODEL, "--out", str(ROOT / "evaluation" / "ground_truth" / "x")],
                       capture_output=True, text=True)
    assert r.returncode == 2
    assert "fora de evaluation/ensaio" in r.stdout
    assert not (ROOT / "evaluation" / "ground_truth" / "x").exists()


def test_end_to_end_with_watermark_and_isolation(tmp_path):
    inv, raw = make_investigations(tmp_path)
    before_inv, before_repo = _digest(inv), _protected_state()
    out = tmp_path / "ENSAIO_FICTICIO_test"
    r = subprocess.run([sys.executable, SCRIPT, "--model", MODEL, "--since", "20261001", "--investigations", str(inv),
                        "--raw", str(tmp_path / "raw_runs_*.csv"), "--out", str(out), "--seed", "3"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    for rel in ("LEIA-ME.md", "eq01_tabela13.md", "eq02_eq03/eq02_eq03_summary.md", "eq04/eq04_summary.md"):
        assert (out / rel).is_file(), rel
    tab = (out / "eq01_tabela13.md").read_text(encoding="utf-8")
    assert "| A1 | 3 |" in tab and "*por completar*" not in tab.split("| B2 |")[1].split("\n")[0]
    eq04 = (out / "eq04" / "eq04_summary.md").read_text(encoding="utf-8")
    assert "Relatórios avaliados: 4" in eq04
    for p in out.rglob("*"):
        if p.is_file() and p.suffix in (".md", ".csv"):
            assert T.WATERMARK in p.read_text(encoding="utf-8").split("\n", 1)[0], p
    readme = (out / "LEIA-ME.md").read_text(encoding="utf-8")
    assert "Cenários sem execuções" in readme and "FALHOU" not in readme
    # nenhuma query real entra nos ficheiros do baseline fictício
    for p in (out / "baseline_manual").rglob("*"):
        if p.is_file():
            assert "consulta" not in p.read_text(encoding="utf-8")
    assert _digest(inv) == before_inv
    assert _protected_state() == before_repo


def test_refuses_existing_non_empty_out(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    (out / "x").write_text("x")
    assert T.main(["--model", MODEL, "--out", str(out), "--investigations", str(tmp_path)]) == 2


def test_fake_reviews_agreement_and_final(tmp_path):
    import random
    gt = tmp_path
    with open(gt / "review_A1_A.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["n", "url", "title", "label", "notes"])
        for i in range(400):
            w.writerow([i + 1, f"http://u{i}.onion", "t", "", ""])
    (gt / "review_A1_B.csv").write_bytes((gt / "review_A1_A.csv").read_bytes())
    n = T.fill_pool_reviews(gt, "A1", random.Random(1))
    a = list(csv.DictReader(open(gt / "review_A1_A.csv", encoding="utf-8-sig")))
    b = list(csv.DictReader(open(gt / "review_A1_B.csv", encoding="utf-8-sig")))
    agree = sum(x["label"] == y["label"] for x, y in zip(a, b)) / len(a)
    assert 0.7 < agree < 0.9
    final = list(csv.DictReader(open(gt / "review_A1_final.csv", encoding="utf-8-sig")))
    assert len(final) == n == sum(x["label"] != y["label"] for x, y in zip(a, b))


def test_flags_no_evidence_reports(tmp_path):
    inv, raw = make_investigations(tmp_path, no_evidence=("B2",))
    out = tmp_path / "ENSAIO_FICTICIO_ne"
    assert T.main(["--model", MODEL, "--since", "20261001", "--investigations", str(inv),
                   "--raw", str(tmp_path / "raw_runs_*.csv"), "--out", str(out)]) == 0
    readme = (out / "LEIA-ME.md").read_text(encoding="utf-8")
    assert "B2: o relatório do DarkSherlock escolhido para a EQ-04 é um relatório sem evidência" in readme
    assert "A1: o relatório" not in readme
    # a EQ-04 exclui o cenário inteiro (as duas condições) e regista-o na chave e no resumo
    key = json.loads((out / "eq04" / "private" / "key.json").read_text(encoding="utf-8"))
    assert set(key["excluded_no_evidence"]) == {"B2"}
    assert sorted(v["scenario"] for v in key["reports"].values()) == ["A1", "A1"]
    assert "Cenários excluídos" in (out / "eq04" / "eq04_summary.md").read_text(encoding="utf-8")
    tn = (out / "true_negatives.md").read_text(encoding="utf-8")
    assert "| B2 | 3 | 3/3 |" in tn and "| A1 | 3 | 0/3 |" in tn


SC12 = tuple(f"{d}{n}" for d in "ABCD" for n in "123")
NO_EV = ("A2", "B2", "B3", "C1", "C3", "D2", "D3")


def test_realistic_profile_end_to_end(tmp_path):
    inv, raw = make_investigations(tmp_path, scenarios=SC12, no_evidence=NO_EV)
    out = tmp_path / "SIMULADO_REALISTA_t"
    assert T.main(["--model", MODEL, "--since", "20261001", "--investigations", str(inv),
                   "--raw", str(tmp_path / "raw_runs_*.csv"), "--out", str(out), "--perfil", "realista"]) == 0
    # rodapé só nos .md; .csv sem marca; nenhuma marca d'água no topo
    for p in out.rglob("*"):
        if p.suffix == ".md":
            text = p.read_text(encoding="utf-8")
            assert text.rstrip().endswith(T.FOOTER), p
            assert T.WATERMARK not in text, p
        elif p.suffix == ".csv":
            assert T.WATERMARK not in p.read_text(encoding="utf-8-sig") and T.FOOTER not in p.read_text(encoding="utf-8-sig")
    # tempos dentro dos intervalos do perfil, por tipo de cenário
    with open(out / "baseline_manual" / "timing_log.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            kind = "sem" if r["scenario_id"] in NO_EV else "evid"
            lo, hi = T.REALISTA["stage_s"][kind][int(r["stage_num"])]
            assert lo <= float(r["duration_s"]) <= hi
    # nenhuma fonte recolhida nos cenários sem evidência; 3–8 nos outros
    for sc in SC12:
        n = len(list((out / "baseline_manual" / "sources" / sc).glob("*.txt")))
        assert (n == 0) if sc in NO_EV else (3 <= n <= 8), (sc, n)
    readme = (out / "LEIA-ME.md").read_text(encoding="utf-8")
    assert "Pressupostos do perfil realista" in readme and "FALHOU" not in readme
    assert len(list(out.glob("SIMULADO_Cap6_*.docx"))) == 1


def test_realistic_reviews_agreement_and_likert(tmp_path):
    import random
    import statistics
    gt = tmp_path / "gt"
    gt.mkdir()
    urls = [f"http://u{i}.onion/" for i in range(3000)]
    with open(gt / "review_A1_A.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["n", "url", "title", "label", "notes"])
        w.writerows([i, u, "", "", ""] for i, u in enumerate(urls))
    with open(gt / "pool_A1.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["url", "ds_top20_runs", "manual_top20"])
        w.writerows([u, "1" if i % 2 else "", 0] for i, u in enumerate(urls))
    T.fill_pool_reviews(gt, "A1", random.Random(5), "realista")
    a = [r["label"] for r in csv.DictReader(open(gt / "review_A1_A.csv", encoding="utf-8-sig"))]
    b = [r["label"] for r in csv.DictReader(open(gt / "review_A1_B.csv", encoding="utf-8-sig"))]
    assert 0.8 < sum(x == y for x, y in zip(a, b)) / len(a) < 0.95
    rel = sum(x == "relevant" for x in a) / len(a)
    assert 0.2 < rel < 0.35  # média de 0,15 e 0,45, vezes 0,9 acessíveis

    eq = tmp_path / "eq04"
    (eq / "private").mkdir(parents=True)
    key = {f"R{i:03d}": {"condition": "DarkSherlock" if i % 2 else "manual"} for i in range(400)}
    (eq / "private" / "key.json").write_text(json.dumps({"reports": key}), encoding="utf-8")
    for who in ("A", "B"):
        (eq / f"reviewer_{who}").mkdir()
        with open(eq / f"reviewer_{who}" / f"scores_{who}.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["id"])
            w.writerows([rid] for rid in key)
    T.fill_eq04_scores(eq, random.Random(5), "realista")
    rows = list(csv.DictReader(open(eq / "reviewer_A" / "scores_A.csv", encoding="utf-8-sig")))
    for cond, means in T.REALISTA["likert"].items():
        sel = [r for r in rows if key[r["id"]]["condition"] == cond]
        for d, m in means.items():
            assert abs(statistics.mean(int(r[d]) for r in sel) - m) < 0.2, (cond, d)
        rate = sum(int(r["afirmacoes_citacao_valida"]) for r in sel) / sum(int(r["afirmacoes_verificaveis"]) for r in sel)
        assert abs(rate - T.REALISTA["citations"][cond][1]) < 0.04
