"""
evaluation/check_runs.py — Verificação rápida das execuções de avaliação gravadas.

Para um modelo e uma data mínima, mostra por cenário: n.º de execuções
(esperado: 3), quantas têm "search_results" e "found_by" em todas as fontes
(necessários para EQ-02/EQ-03), o desfecho da Etapa 4 ("stage4_outcome"),
o tamanho do Top-K e o n.º de fontes finais raspadas. Não altera nada.

Uso:
    python evaluation/check_runs.py --model "Phi-3.5-mini (embutido, médio)" --since 20261009
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import re
import sys
from pathlib import Path

import versions

SCENARIOS = [f"{d}{n}" for d in "ABCD" for n in "123"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="Etiqueta exata do modelo (campo 'model' das investigações).")
    ap.add_argument("--since", default="00000000", help="Só ficheiros com data >= AAAAMMDD.")
    ap.add_argument("--dir", default=str(Path(__file__).resolve().parent.parent / "investigations"))
    ap.add_argument("--expected", type=int, default=3, help="Execuções esperadas por cenário (default: 3).")
    versions.add_argument(ap)
    args = ap.parse_args()

    runs: dict[str, list[dict]] = collections.defaultdict(list)
    for path in sorted(glob.glob(str(Path(args.dir) / "eval_*.json"))):
        m = re.search(r"_(\d{8})_\d{6}\.json$", path)
        if not m or m.group(1) < args.since:
            continue
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("model") == args.model and data.get("scenario_id") and versions.keep(data, args.pipeline_version):
            runs[data["scenario_id"]].append(data)
    versions.exit_if_mixed([d for rs in runs.values() for d in rs], args.pipeline_version)

    if not runs:
        print(f"Nenhuma execução de {args.model!r} desde {args.since} em {args.dir}.")
        return 1

    print(f"{'cenário':8}{'runs':>5}{'c/search_res.':>15}{'c/found_by':>12}   {'stage4_outcome':36}{'Top-K':>8}{'fontes finais':>15}")
    problems = []
    for sc in SCENARIOS:
        rs = runs.get(sc, [])
        if not rs:
            print(f"{sc:8}{0:>5}   (sem execuções)")
            problems.append(f"{sc}: sem execuções")
            continue
        with_sr = [r for r in rs if r.get("search_results")]
        with_fb = [r for r in with_sr if all(x.get("found_by") for x in r["search_results"])]
        outcomes = collections.Counter(r.get("stage4_outcome", "AUSENTE") for r in rs)
        topk = [len(r.get("sources", [])) for r in rs]
        final = [len(r.get("scraped_content", {})) for r in rs]
        print(f"{sc:8}{len(rs):>5}{len(with_sr):>15}{len(with_fb):>12}   {str(dict(outcomes)):36}"
              f"{min(topk)}-{max(topk):>3}{min(final):>10}-{max(final)}")
        if len(rs) != args.expected:
            problems.append(f"{sc}: {len(rs)} execuções (esperadas {args.expected})")
        if len(with_sr) != len(rs) or len(with_fb) != len(rs):
            problems.append(f"{sc}: faltam search_results/found_by em {len(rs) - min(len(with_sr), len(with_fb))} execução(ões)")
        if outcomes.get("AUSENTE"):
            problems.append(f"{sc}: {outcomes['AUSENTE']} execução(ões) sem stage4_outcome")
        non_ranked = {k: v for k, v in outcomes.items() if k not in ("ranked", "AUSENTE")}
        if non_ranked:
            problems.append(f"{sc}: Etapa 4 sem ranking do LLM em {sum(non_ranked.values())} execução(ões) {non_ranked}")

    print()
    if problems:
        print("A rever:")
        for p in problems:
            print("  -", p)
    else:
        print("Tudo em ordem: todas as execuções têm search_results, found_by e stage4_outcome 'ranked'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
