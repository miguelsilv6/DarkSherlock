"""
evaluation/true_negatives.py — Cenários sem evidência (Capítulo 6): verdadeiros
negativos vs. falsos negativos do DarkSherlock, contra o baseline manual e o pool.

Os cenários cujo relatório do DarkSherlock é um relatório sem evidência saem da
revisão Likert (eq04_review.py build --exclude-no-evidence). Este script mostra
se essa ausência de evidência é correta (não havia nada a encontrar: a
ferramenta não inventou conteúdo) ou uma falha de recuperação.

Por cenário:
  - DarkSherlock: n.º de execuções e quantas terminaram num relatório sem
    evidência (eq04_review.is_no_evidence). O cenário conta como "negativo" se
    a maioria das execuções for sem evidência; metade/metade é "misto".
  - Baseline manual: n.º de fontes recolhidas (sources/<ID>/*.txt) e vistas
    (reports/manual_sources_<ID>.csv).
  - Pool (EQ-02/03): n.º de fontes relevantes segundo os rótulos humanos finais
    (eq02_eq03.resolve_labels), quando já existem.

Referência para a classificação (por esta ordem):
  1. o pool rotulado pelos revisores: 0 relevantes = negativo;
  2. sem rótulos, o baseline manual: 0 fontes recolhidas = negativo, e a
     classificação leva "(provável)";
  3. sem nenhum dos dois: "por determinar".

Uso:
    python evaluation/true_negatives.py --investigations "investigations/eval_*.json" \\
        --model "Phi-3.5-mini (embutido, médio)" --since 20261110 --pipeline-version 2.3 \\
        --manual-dir evaluation/baseline_manual --ground-truth evaluation/ground_truth
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import eq02_eq03  # noqa: E402
import eq04_review  # noqa: E402
import run_kinds  # noqa: E402
import versions  # noqa: E402

CLASSES = ("Verdadeiro negativo", "Falso negativo", "Verdadeiro positivo", "Falso positivo")


def load_runs(pattern: str, model: str, since: str, pipeline_version: str | None,
              run_kind: str = run_kinds.DEFAULT) -> dict[str, list[bool]]:
    """{cenário: [execução sem evidência?, ...]} das execuções selecionadas (ValueError se misturarem versões)."""
    out: dict[str, list[bool]] = {}
    invs = []
    kinds = run_kinds.index()
    for path in sorted(glob.glob(pattern)):
        stamp = eq04_review._file_stamp(path)
        if not stamp or stamp[:8] < since:
            continue
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("model") != model or data.get("scenario_id") not in eq04_review.SCENARIO_IDS:
            continue
        if not versions.keep(data, pipeline_version) or not run_kinds.keep(data, path, kinds, run_kind):
            continue
        summary, _ = eq04_review.strip_darksherlock_banners(data.get("summary") or "")
        out.setdefault(data["scenario_id"], []).append(eq04_review.is_no_evidence(summary) or not summary)
        invs.append(data)
    mixed = versions.mixed_error(invs, pipeline_version)
    if mixed:
        raise ValueError(mixed)
    return out


def manual_counts(manual_dir: Path, sc: str) -> tuple[int | None, int | None]:
    """(fontes recolhidas, fontes vistas) do baseline manual; None quando não há dados."""
    src = manual_dir / "sources" / sc
    collected = len(list(src.glob("*.txt"))) if src.is_dir() else None
    seen = None
    csv_path = manual_dir / "reports" / f"manual_sources_{sc}.csv"
    if csv_path.is_file():
        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            seen = sum(1 for r in csv.DictReader(f) if (r.get("url") or "").strip())
    return collected, seen


def pool_relevant(gt: Path | None, sc: str) -> int | None:
    if gt is None:
        return None
    try:
        final, _, _, _ = eq02_eq03.resolve_labels(sc, gt, allow_unresolved=True)
    except (ValueError, FileNotFoundError):
        return None
    return sum(1 for label in final.values() if label == "relevant")


def classify(ds_negative: bool | None, ref_negative: bool | None) -> str:
    if ds_negative is None:
        return "misto"
    if ref_negative is None:
        return "por determinar"
    if ds_negative:
        return CLASSES[0] if ref_negative else CLASSES[1]
    return CLASSES[3] if ref_negative else CLASSES[2]


def build(runs: dict[str, list[bool]], manual_dir: Path, gt: Path | None) -> list[dict]:
    rows = []
    for sc in eq04_review.SCENARIO_IDS:
        flags = runs.get(sc, [])
        if not flags:
            continue
        neg = sum(flags)
        ds_negative = True if 2 * neg > len(flags) else (False if 2 * neg < len(flags) else None)
        collected, seen = manual_counts(manual_dir, sc)
        relevant = pool_relevant(gt, sc)
        if relevant is not None:
            ref, ref_negative, probable = "pool (revisores)", relevant == 0, False
        elif collected is not None:
            ref, ref_negative, probable = "baseline manual", collected == 0, True
        else:
            ref, ref_negative, probable = "—", None, False
        label = classify(ds_negative, ref_negative)
        if probable and label in CLASSES:
            label += " (provável)"
        rows.append({"scenario": sc, "n_runs": len(flags), "no_evidence": neg, "ds_negative": ds_negative,
                     "collected": collected, "seen": seen, "relevant": relevant, "reference": ref, "label": label})
    return rows


def _n(v) -> str:
    return "—" if v is None else str(v)


def render(rows: list[dict], meta: dict) -> str:
    L = ["# Cenários sem evidência — verdadeiros e falsos negativos\n",
         f"Modelo: `{meta['model']}` · execuções desde {meta['since']}"
         + (f" · pipeline {meta['pipeline_version']}" if meta.get("pipeline_version") else "") + ".\n",
         "| Cenário | Execuções DS | Sem evidência (DS) | Fontes manuais recolhidas / vistas | Relevantes no pool | "
         "Referência | Classificação |",
         "|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['scenario']} | {r['n_runs']} | {r['no_evidence']}/{r['n_runs']} | "
                 f"{_n(r['collected'])} / {_n(r['seen'])} | {_n(r['relevant'])} | {r['reference']} | {r['label']} |")
    L.append("\n## Resumo\n")
    L.append("| Classificação | Cenários |")
    L.append("|---|---|")
    for c in (*CLASSES, "misto", "por determinar"):
        hits = [r["scenario"] for r in rows if r["label"].startswith(c)]
        if hits:
            L.append(f"| {c} | {len(hits)} ({', '.join(hits)}) |")
    neg = [r for r in rows if r["ds_negative"]]
    tn = sum(1 for r in neg if r["label"].startswith(CLASSES[0]))
    decided = sum(1 for r in neg if r["label"].startswith(CLASSES[:2]))
    if decided:
        L.append(f"\nDos {len(neg)} cenários em que o DarkSherlock não encontrou evidência, {tn} de {decided} com "
                 "referência são verdadeiros negativos"
                 + (": nesses, a ferramenta não produziu análise sem fontes (não inventou conteúdo)." if tn else "."))
        if decided > tn:
            L.append("Num falso negativo havia fontes relevantes que o DarkSherlock não aproveitou: ver no pool se as "
                     "recuperou na pesquisa e falhou a recolha (Tor/scraping) ou se nem as encontrou.")
    L.append("\n*Notas: «sem evidência» = relatório de pipeline.no_evidence_report ou llm.generate_summary sem "
             "conteúdo. Referência = rótulos humanos finais do pool quando existem; senão, o baseline manual "
             "(«provável»: o investigador pode ter falhado fontes que existiam). «misto» = metade das execuções "
             "com e metade sem evidência.*")
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--investigations", required=True, help='Glob das investigações (ex.: "investigations/eval_*.json").')
    ap.add_argument("--model", required=True)
    ap.add_argument("--since", default="00000000", help="Só execuções com data de ficheiro >= AAAAMMDD.")
    versions.add_argument(ap)
    run_kinds.add_argument(ap)
    ap.add_argument("--manual-dir", default=str(HERE / "baseline_manual"))
    ap.add_argument("--ground-truth", default=str(eq02_eq03.DEFAULT_OUT_DIR),
                    help="Pasta das folhas de revisão do pool (vazia ou inexistente = sem rótulos).")
    ap.add_argument("--out", default=str(HERE / "results" / "true_negatives.md"))
    args = ap.parse_args(argv)

    try:
        runs = load_runs(args.investigations, args.model, args.since, args.pipeline_version, args.run_kind)
    except ValueError as e:
        print(f"ERRO: {e}")
        return 2
    if not runs:
        print(f"ERRO: nenhuma execução de {args.model!r} desde {args.since} em {args.investigations}.")
        return 1
    gt = Path(args.ground_truth)
    md = render(build(runs, Path(args.manual_dir), gt if gt.is_dir() else None),
                {"model": args.model, "since": args.since, "pipeline_version": args.pipeline_version})
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(md)
    print(f"\nEscrito: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
