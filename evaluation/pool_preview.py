"""
evaluation/pool_preview.py — Pré-visualização do pool de EQ-02/EQ-03 só com os
dados do DarkSherlock (sem baseline manual, sem revisores). Só leitura.

Por cenário mostra: n.º de execuções, tamanho do pool do DarkSherlock (união das
fontes recuperadas pelas execuções), n.º comum a todas as execuções, estabilidade
da pesquisa (Jaccard médio entre pares de execuções), tamanho do Top-K (LLM) e a
sua união, e os motores que contribuíram com fontes. No fim, a carga de revisão
estimada por revisor (o pool final acrescenta as fontes do baseline manual).

Serve para planear o trabalho dos revisores e para descrever a variabilidade da
pesquisa Tor (EQ-02). Usa o mesmo URL normalizado que evaluation/eq02_eq03.py.

Uso:
    python evaluation/pool_preview.py --model "Phi-3.5-mini (embutido, médio)" --since 20261009
"""

from __future__ import annotations

import argparse
import collections
import glob
import itertools
import json
import re
import statistics
import sys
from pathlib import Path
from urllib.parse import urlsplit

import versions

SCENARIOS = [f"{d}{n}" for d in "ABCD" for n in "123"]


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path.rstrip('/')}{query}"


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a | b) else float("nan")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True)
    ap.add_argument("--since", default="00000000")
    ap.add_argument("--dir", default=str(Path(__file__).resolve().parent.parent / "investigations"))
    versions.add_argument(ap)
    args = ap.parse_args()

    runs: dict[str, list[dict]] = collections.defaultdict(list)
    for path in sorted(glob.glob(str(Path(args.dir) / "eval_*.json"))):
        m = re.search(r"_(\d{8})_\d{6}\.json$", path)
        if not m or m.group(1) < args.since:
            continue
        try:
            d = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if d.get("model") == args.model and d.get("search_results") and versions.keep(d, args.pipeline_version):
            runs[d["scenario_id"]].append(d)
    versions.exit_if_mixed([d for rs in runs.values() for d in rs], args.pipeline_version)
    if not runs:
        print(f"Nenhuma execução de {args.model!r} com search_results desde {args.since}.")
        return 1

    print(f"{'cen.':5}{'runs':>5}{'pool':>6}{'comuns':>8}{'Jaccard':>9}{'Top-K':>11}{'U(Top-K)':>10}  fontes distintas por motor (top 4)")
    total_pool, jacs = 0, []
    for sc in SCENARIOS:
        rs = runs.get(sc, [])
        if not rs:
            print(f"{sc:5}{0:>5}   (sem execuções)")
            continue
        sets = [{normalize_url(r["link"]) for r in d["search_results"]} for d in rs]
        tops = [{normalize_url(r["link"]) for r in d.get("sources", [])} for d in rs]
        pool = set().union(*sets)
        common = set.intersection(*sets)
        pj = [jaccard(a, b) for a, b in itertools.combinations(sets, 2)]
        jmean = statistics.mean(pj) if pj else float("nan")
        engines: collections.Counter = collections.Counter()
        seen: set[str] = set()
        for d in rs:
            for r in d["search_results"]:
                u = normalize_url(r["link"])
                if u in seen:
                    continue
                seen.add(u)
                for e in r.get("found_by", []):
                    engines[e] += 1
        top_engines = ", ".join(f"{e} {n}" for e, n in engines.most_common(4))
        sizes = [len(t) for t in tops]
        total_pool += len(pool)
        if pj:
            jacs.append(jmean)
        print(f"{sc:5}{len(rs):>5}{len(pool):>6}{len(common):>8}{jmean:>9.2f}{min(sizes):>6}-{max(sizes):<4}{len(set().union(*tops)):>10}  {top_engines}")

    print(f"\nPool total do DarkSherlock: {total_pool} fontes distintas nos {len([s for s in SCENARIOS if runs.get(s)])} cenários.")
    if jacs:
        print(f"Estabilidade média da pesquisa (Jaccard entre pares de execuções): {statistics.mean(jacs):.2f} "
              f"(mín. {min(jacs):.2f}, máx. {max(jacs):.2f}).")
    print("Carga por revisor ≈ pool do DarkSherlock + fontes do baseline manual (a acrescentar, sem as repetidas).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
