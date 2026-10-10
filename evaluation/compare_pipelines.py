"""
evaluation/compare_pipelines.py — Mede o efeito da revisão do pipeline (1.0-legacy -> 2.0).

Dois modos (só contagens e IDs de cenário na saída — sem queries nem URLs):

  replay   OFFLINE, sobre execuções já gravadas da versão antiga: reaplica os
           filtros novos da pesquisa (páginas dos próprios motores e irmãos,
           títulos de navegação e de spam, máx. 3 resultados por host) aos
           "search_results" gravados e compara o pool antes/depois, e quantos
           itens do Top-K antigo os filtros novos teriam descartado.
           Limite: só vê o que a versão antiga gravou — não mede a nova
           extração de HTML (sem <nav>/<header>/<footer>), nem as Etapas 4–6.

  compare  Execuções das duas versões (depois de repetir a bateria em 2.0):
           por cenário, fontes finais, % de execuções com <= 2 fontes, spam
           no pool, hosts únicos, desfechos das Etapas 4 e 5, IOCs
           verificados (só 2.0); Wilcoxon emparelhado (bilateral) entre as
           médias por cenário das duas versões.

Uso:
    python evaluation/compare_pipelines.py replay  --investigations "investigations/eval_*.json" --model "<modelo>"
    python evaluation/compare_pipelines.py compare --investigations "investigations/eval_*.json" --model "<modelo>" \\
        --old 1.0-legacy --new 2.1 --out evaluation/results/compare_pipelines.md
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
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import versions  # noqa: E402
from config import PIPELINE_VERSION  # noqa: E402

SCENARIO_IDS = [f"{d}{n}" for d in "ABCD" for n in "123"]


def _date(path: str) -> str:
    m = re.search(r"_(\d{8})_\d{6}\.json$", path)
    return m.group(1) if m else ""


def load_runs(pattern: str, model: str, since: str = "00000000") -> list[dict]:
    runs = []
    for path in sorted(glob.glob(pattern)):
        if _date(path) < since:
            continue
        try:
            d = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if d.get("model") == model and d.get("scenario_id") in SCENARIO_IDS:
            d["_file"] = Path(path).name
            runs.append(d)
    return runs


# ---------------------------------------------------------------------------
# Métricas do pool de resultados
# ---------------------------------------------------------------------------
def pool_metrics(results: list[dict], excluded_hosts: set) -> dict:
    import search_filters as sf
    from search import _is_other_engine_search

    hosts = collections.Counter(sf.onion_host(r.get("link", "")) for r in results)
    return {
        "pool": len(results),
        "spam": sum(1 for r in results if sf.is_spam_title(r.get("title", ""))),
        "nav": sum(1 for r in results if sf.is_nav_title(r.get("title", ""))),
        "engine_pages": sum(1 for r in results if sf.onion_host(r.get("link", "")) in excluded_hosts
                            or _is_other_engine_search(r.get("link", ""))),
        "unique_hosts": len([h for h in hosts if h]),
        "max_per_host": max(hosts.values(), default=0),
    }


def replay_v2_filters(results: list[dict], excluded_hosts: set) -> tuple[list[dict], set]:
    """Os filtros novos da Etapa 3 aplicados a um pool gravado. Devolve (pool novo, URLs descartados)."""
    import search
    import search_filters as sf

    per_engine: dict[str, list[dict]] = collections.defaultdict(list)
    for r in results:
        engine = (r.get("found_by") or ["?"])[0]
        per_engine[engine].append({"title": r.get("title", ""), "link": r["link"]})
    cleaned = []
    for name, rs in per_engine.items():
        kept, _ = search._clean_engine_results(name, rs, excluded_hosts)
        cleaned.append((name, kept))
    new_pool = sf.interleave(cleaned, per_host_cap=search.PER_HOST_CAP)
    kept_urls = {sf.normalize_url(r["link"]) for r in new_pool}
    dropped = {sf.normalize_url(r["link"]) for r in results} - kept_urls
    return new_pool, dropped


def _excluded_hosts() -> set:
    import search
    from engine_manager import load_engines
    return search._excluded_hosts(load_engines())


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return statistics.mean(xs) if xs else float("nan")


def _fmt(x, nd=1):
    return "—" if x != x else f"{x:.{nd}f}"  # NaN -> —


def cmd_replay(args) -> int:
    import search_filters as sf

    runs = [r for r in load_runs(args.investigations, args.model, args.since)
            if versions.version_of(r) == args.old and r.get("search_results")]
    if not runs:
        print(f"Nenhuma execução {args.old} de {args.model!r} com search_results.")
        return 1
    excluded = _excluded_hosts()
    by_sc = collections.defaultdict(list)
    for r in runs:
        before = pool_metrics(r["search_results"], excluded)
        new_pool, dropped = replay_v2_filters(r["search_results"], excluded)
        after = pool_metrics(new_pool, excluded)
        topk = [sf.normalize_url(s["link"]) for s in r.get("sources", [])]
        by_sc[r["scenario_id"]].append({
            "before": before, "after": after,
            "topk": len(topk), "topk_dropped": sum(1 for u in topk if u in dropped),
        })

    lines = [f"# Replay offline dos filtros 2.0 sobre execuções {args.old} — modelo `{args.model}`", "",
             "Médias por execução. *Pool* = resultados da Etapa 3; *spam*/*nav*/*motor* = títulos de spam, "
             "rótulos de navegação e páginas dos próprios motores no pool (categorias não exclusivas); *Top-K descartável* = itens do "
             "Top-K antigo que os filtros novos teriam retirado antes da Etapa 4.", "",
             "| Cenário | n | Pool antes | Pool depois | Spam antes | Nav antes | Motor antes | Hosts únicos antes/depois "
             "| Máx./host antes/depois | Top-K | Top-K descartável |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    tot = collections.Counter()
    for sc in SCENARIO_IDS:
        rs = by_sc.get(sc)
        if not rs:
            continue
        m = lambda f: _mean([f(x) for x in rs])  # noqa: E731
        lines.append(
            f"| {sc} | {len(rs)} | {_fmt(m(lambda x: x['before']['pool']))} | {_fmt(m(lambda x: x['after']['pool']))} "
            f"| {_fmt(m(lambda x: x['before']['spam']))} | {_fmt(m(lambda x: x['before']['nav']))} "
            f"| {_fmt(m(lambda x: x['before']['engine_pages']))} "
            f"| {_fmt(m(lambda x: x['before']['unique_hosts']))} / {_fmt(m(lambda x: x['after']['unique_hosts']))} "
            f"| {_fmt(m(lambda x: x['before']['max_per_host']))} / {_fmt(m(lambda x: x['after']['max_per_host']))} "
            f"| {_fmt(m(lambda x: x['topk']))} | {_fmt(m(lambda x: x['topk_dropped']))} |")
        for x in rs:
            tot["runs"] += 1
            tot["pool_before"] += x["before"]["pool"]
            tot["pool_after"] += x["after"]["pool"]
            tot["topk"] += x["topk"]
            tot["topk_dropped"] += x["topk_dropped"]
    if tot["pool_before"]:
        lines += ["", f"Total: {tot['runs']} execuções; o pool passa de {tot['pool_before']} para "
                      f"{tot['pool_after']} resultados ({100 * (1 - tot['pool_after'] / tot['pool_before']):.1f}% "
                      f"descartados); {tot['topk_dropped']} de {tot['topk']} itens do Top-K "
                      f"({100 * tot['topk_dropped'] / max(1, tot['topk']):.1f}%) seriam descartados.",
                  "", "Limite: o replay só vê o que a versão antiga gravou; não mede a nova extração de HTML "
                      "nem as Etapas 4–6 (para isso, `compare` sobre execuções 2.0)."]
    _emit(lines, args.out)
    return 0


def _run_metrics(r: dict, excluded: set) -> dict:
    sources = len(r.get("scraped_content") or {})
    ioc = r.get("ioc_check") or {}
    pm = pool_metrics(r.get("search_results") or [], excluded)
    return {
        "sources": sources,
        "le2": int(sources <= 2),
        "spam_pct": 100 * pm["spam"] / pm["pool"] if pm["pool"] else None,
        "unique_hosts": pm["unique_hosts"],
        "ioc_verified_pct": 100 * ioc["verified"] / ioc["total"] if ioc.get("total") else None,
        "stage4": r.get("stage4_outcome") or "?",
        "stage5": r.get("stage5_outcome") or "—",
    }


def cmd_compare(args) -> int:
    from tabela13 import wilcoxon_signed_rank

    runs = load_runs(args.investigations, args.model, args.since)
    excluded = _excluded_hosts()
    data = {v: collections.defaultdict(list) for v in (args.old, args.new)}
    for r in runs:
        v = versions.version_of(r)
        if v in data:
            data[v][r["scenario_id"]].append(_run_metrics(r, excluded))
    if not data[args.new]:
        print(f"Nenhuma execução {args.new} de {args.model!r}. Repete a bateria com a versão nova primeiro.")
        return 1

    def agg(rs, key):
        return _mean([x[key] for x in rs]) if rs else float("nan")

    lines = [f"# {args.old} vs {args.new} — modelo `{args.model}`", "",
             "| Cenário | n (v1/v2) | Fontes finais v1 | v2 | % ≤ 2 fontes v1 | v2 | % spam no pool v1 | v2 "
             "| Hosts únicos v1 | v2 | % IOCs verificados v2 | Etapa 4 v2 | Etapa 5 v2 |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    paired = {"sources": [], "spam_pct": [], "unique_hosts": []}
    for sc in SCENARIO_IDS:
        a, b = data[args.old].get(sc, []), data[args.new].get(sc, [])
        if not a and not b:
            continue
        s4 = collections.Counter(x["stage4"] for x in b)
        s5 = collections.Counter(x["stage5"] for x in b)
        lines.append(
            f"| {sc} | {len(a)}/{len(b)} | {_fmt(agg(a, 'sources'))} | {_fmt(agg(b, 'sources'))} "
            f"| {_fmt(100 * agg(a, 'le2'), 0)} | {_fmt(100 * agg(b, 'le2'), 0)} "
            f"| {_fmt(agg(a, 'spam_pct'))} | {_fmt(agg(b, 'spam_pct'))} "
            f"| {_fmt(agg(a, 'unique_hosts'))} | {_fmt(agg(b, 'unique_hosts'))} "
            f"| {_fmt(agg(b, 'ioc_verified_pct'), 0)} "
            f"| {', '.join(f'{k} {v}' for k, v in s4.most_common())} | {', '.join(f'{k} {v}' for k, v in s5.most_common())} |")
        if a and b:
            for key in paired:
                x, y = agg(b, key), agg(a, key)
                if x == x and y == y:
                    paired[key].append(x - y)
    lines += ["", "Wilcoxon emparelhado por cenário (média v2 − média v1, bilateral):", ""]
    for key, label in (("sources", "fontes finais"), ("spam_pct", "% spam no pool"), ("unique_hosts", "hosts únicos")):
        d = paired[key]
        if len(d) < 2:
            lines.append(f"- {label}: cenários emparelhados insuficientes (n = {len(d)}).")
            continue
        w = wilcoxon_signed_rank(d, "two-sided")
        lines.append(f"- {label}: n = {len(d)} cenários, mediana da diferença = {statistics.median(d):+.2f}, "
                     f"p = {w['p']:.4f}")
    lines += ["", "Nota: execuções da mesma configuração (modelo, motores, Tor) em datas diferentes; a dark web "
                  "muda entre execuções, por isso parte da diferença não se deve ao código."]
    _emit(lines, args.out)
    return 0


def _emit(lines, out):
    text = "\n".join(lines) + "\n"
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text, encoding="utf-8")
        print(f"Escrito em {out}")
    print(text)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("replay", cmd_replay), ("compare", cmd_compare)):
        p = sub.add_parser(name)
        p.add_argument("--investigations", required=True, help='Glob, p. ex. "investigations/eval_*.json".')
        p.add_argument("--model", required=True, help="Etiqueta exata do modelo.")
        p.add_argument("--since", default="00000000", help="Só ficheiros com data >= AAAAMMDD.")
        p.add_argument("--old", default=versions.LEGACY)
        p.add_argument("--out", default=None)
        if name == "compare":
            p.add_argument("--new", default=PIPELINE_VERSION, help=f"Versão nova (default: {PIPELINE_VERSION}).")
        p.set_defaults(func=fn)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
