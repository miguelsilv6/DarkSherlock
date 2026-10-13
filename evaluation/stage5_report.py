"""
evaluation/stage5_report.py — Porque é que a Etapa 5 ficou (ou não) sem evidência, por cenário.

Uma Etapa 5 vazia pode ser um verdadeiro negativo (o alvo não está na dark web
indexada) ou uma falha do pipeline (a pesquisa não o encontrou, a recolha não
trouxe texto, ou o critério de todos os termos-chave bloqueou páginas sobre o
alvo). Este relatório separa os casos, a partir do que cada investigação gravou:

  - páginas recolhidas com texto (scrape_outcomes["ok"]) e avaliadas (relevance_scores);
  - cobertura de cada termo-chave nas páginas avaliadas — T1, T2, ... pela ordem
    da query (o texto dos termos NÃO aparece: as queries dos cenários reais não
    podem sair na saída);
  - execuções com páginas parciais e quantas dessas são possíveis homónimos
    (a mesma lógica do relatório "sem evidência", pipeline._partial_pages).

Leitura automática por cenário: com evidência; poucas páginas recolhidas
(recolha); nenhum termo-chave nas páginas (provável verdadeiro negativo ou
falta de recall da pesquisa); alguns termos presentes e outros nunca (o
critério de todos os termos bloqueia); todos presentes mas nunca juntos.

Uso:
    python evaluation/stage5_report.py --model "Phi-3.5-mini (embutido, médio)" --since 20261011 \\
        --pipeline-version 2.3 --out evaluation/results/stage5_report.md
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import re
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE.parent, HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import run_kinds  # noqa: E402
import versions  # noqa: E402

SCENARIOS = [f"{d}{n}" for d in "ABCD" for n in "123"]
FEW_PAGES = 2.0   # média de páginas com texto por execução abaixo da qual a recolha é o problema


def load(pattern: str, model: str, since: str, pipeline_version: str | None, run_kind: str) -> list[dict]:
    kinds, out = run_kinds.index(), []
    for path in sorted(glob.glob(pattern)):
        m = re.search(r"_(\d{8})_\d{6}\.json$", path)
        if not m or m.group(1) < since:
            continue
        try:
            d = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (d.get("model") == model and d.get("scenario_id") in SCENARIOS and versions.keep(d, pipeline_version)
                and run_kinds.keep(d, path, kinds, run_kind)):
            out.append(d)
    versions.exit_if_mixed(out, pipeline_version)
    return out


def _partial(inv: dict) -> list[tuple[str, bool]]:
    import pipeline
    r = pipeline.PipelineResult(query=inv.get("query", ""))
    r.relevance_scores = inv.get("relevance_scores") or {}
    r.scraped_content = inv.get("scraped_content") or {}
    r.filtered = inv.get("sources") or []
    return pipeline._partial_pages(r)


def scenario_stats(invs: list[dict]) -> dict:
    import text_match as tm
    keys = [t.text for t in tm.query_terms(invs[0].get("query", "")) if t.key]
    pages_ok, pages_eval, with_evidence, with_partial, homonym_only = [], 0, 0, 0, 0
    key_hits = collections.Counter()
    for inv in invs:
        pages_ok.append((inv.get("scrape_outcomes") or {}).get("ok", 0))
        scores = [v for v in (inv.get("relevance_scores") or {}).values() if not v.get("degenerate")]
        pages_eval += len(scores)
        for v in scores:
            for k in keys:
                if k in v.get("found", []):
                    key_hits[k] += 1
        if inv.get("scraped_content"):
            with_evidence += 1
        else:
            partial = _partial(inv)
            if partial:
                with_partial += 1
                homonym_only += all(h for _, h in partial)
    cover = [(f"T{i}", key_hits[k] / pages_eval if pages_eval else 0.0) for i, k in enumerate(keys, 1)]
    return {"runs": len(invs), "with_evidence": with_evidence, "pages_ok": statistics.mean(pages_ok),
            "pages_eval": pages_eval / len(invs), "cover": cover, "with_partial": with_partial,
            "homonym_only": homonym_only}


def reading(st: dict) -> str:
    if st["with_evidence"]:
        return f"com evidência em {st['with_evidence']} de {st['runs']} execuções."
    if st["pages_ok"] < FEW_PAGES:
        return (f"poucas páginas recolhidas com texto ({st['pages_ok']:.1f} por execução): o problema é a recolha "
                "(serviços em baixo, timeouts, páginas só de JavaScript), não a relevância.")
    present = [t for t, c in st["cover"] if c > 0]
    absent = [t for t, c in st["cover"] if c == 0]
    if not present:
        return ("nenhum termo-chave nas páginas recolhidas: o alvo não aparece no que a pesquisa trouxe — "
                "verdadeiro negativo provável, ou falta de recall da pesquisa (confirmar no baseline manual).")
    if absent:
        hom = f", {st['homonym_only']} só com possíveis homónimos" if st["homonym_only"] else ""
        return (f"{', '.join(present)} presente(s), {', '.join(absent)} nunca: o critério de todos os termos é que "
                f"bloqueia ({st['with_partial']} execução(ões) com páginas parciais{hom}).")
    return "todos os termos-chave aparecem, mas nunca na mesma página: o alvo e o contexto estão em páginas diferentes."


def render(invs: list[dict], header: str) -> str:
    groups = collections.defaultdict(list)
    for inv in invs:
        groups[(inv["scenario_id"], inv.get("query", ""))].append(inv)
    per_sc = collections.Counter(sc for sc, _ in groups)
    lines = [header, "",
             "Termos-chave identificados por posição na query (T1, T2, ...); cobertura = % das páginas avaliadas "
             "que contêm o termo.", "",
             "| Cenário | Execuções | Com evidência | Páginas c/ texto (média) | Páginas avaliadas (média) "
             "| Cobertura dos termos-chave | C/ páginas parciais | Leitura |",
             "|---|---|---|---|---|---|---|---|"]
    seen = collections.Counter()
    for (sc, _q), rs in sorted(groups.items(), key=lambda kv: SCENARIOS.index(kv[0][0])):
        seen[sc] += 1
        label = sc if per_sc[sc] == 1 else f"{sc} (query {seen[sc]})"
        st = scenario_stats(rs)
        cover = ", ".join(f"{t} {100 * c:.0f}%" for t, c in st["cover"]) or "—"
        lines.append(f"| {label} | {st['runs']} | {st['with_evidence']} | {st['pages_ok']:.1f} | {st['pages_eval']:.1f} "
                     f"| {cover} | {st['with_partial']} | {reading(st)} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True)
    ap.add_argument("--since", default="00000000")
    ap.add_argument("--investigations", default=str(HERE.parent / "investigations" / "eval_*.json"))
    ap.add_argument("--out", default=None)
    versions.add_argument(ap)
    run_kinds.add_argument(ap)
    args = ap.parse_args(argv)
    invs = load(args.investigations, args.model, args.since, args.pipeline_version, args.run_kind)
    if not invs:
        print(f"Nenhuma investigação de {args.model!r} desde {args.since} ({args.run_kind}).")
        return 1
    text = render(invs, f"# Etapa 5 por cenário — modelo `{args.model}`, desde {args.since}, "
                        f"execuções `{args.run_kind}`")
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Escrito em {args.out}")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
