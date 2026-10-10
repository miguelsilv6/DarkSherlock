"""
evaluation/tabela13.py — Eficiência operacional (EQ-01): Tabela 13 (tempo
end-to-end e speedup) e tempo por etapa, com o teste de H1.

Junta as execuções do DarkSherlock (raw_runs_*.csv de TODOS os lotes) com a
cronometragem do baseline manual (baseline_manual/timing_log.csv):

  - Tabela 13: por cenário, tempo end-to-end do DarkSherlock (média ± DP de
    n execuções), tempo do baseline (valor único), speedup = baseline /
    DarkSherlock; mais agregados por domínio e global.
  - Tempo por etapa (as 5 etapas do protocolo manual vs. as etapas
    equivalentes do pipeline).
  - H1 da EQ-01: o DarkSherlock é significativamente mais rápido que o
    baseline (Wilcoxon signed-rank emparelhado por cenário, unilateral,
    α = 0,05; p exato).

Correspondência de etapas (manual -> pipeline):
  1 Refinamento da query  -> refine_query
  2 Pesquisa              -> search
  3 Triagem               -> filter_results
  4 Recolha               -> scrape
  5 Redação               -> generate_summary
O tempo de carregamento do modelo (Etapa 1/Load LLM do pipeline) é amortizado
e não entra no total por execução (ver run_scenarios.py).

Decisões de operacionalização (documentar na metodologia):
  - Só entram execuções do modelo indicado (--model), a partir de --since; o
    modelo lê-se da investigação gravada (campo "model").
  - Se houver mais de --runs execuções por cenário, usam-se as primeiras (por
    data) e avisa-se.
  - No baseline, se uma etapa tiver mais de um registo, vale o ÚLTIMO e avisa-se;
    um cenário só entra na comparação com as 5 etapas registadas.
  - O teste emparelha, por cenário, a média do DarkSherlock com o tempo único do
    baseline (n = n.º de cenários completos).

Uso:
    python evaluation/tabela13.py --model "Phi-3.5-mini (embutido, médio)" --since 20261009
"""

from __future__ import annotations

import argparse
import csv
import glob
import itertools
import json
import math
import re
import statistics
import sys
from pathlib import Path

import versions

BASE = Path(__file__).resolve().parent
DOMAINS = {"A": "Threat Intel", "B": "Ransomware/Malware", "C": "Identidade Pessoal", "D": "Espionagem Corporativa"}
SCENARIO_IDS = [f"{d}{n}" for d in "ABCD" for n in "123"]
STAGES = [  # (n.º manual, nome, coluna no raw_runs)
    (1, "Refinamento da query", "refine_query_ms"),
    (2, "Pesquisa", "search_ms"),
    (3, "Triagem / filtragem", "filter_results_ms"),
    (4, "Recolha / raspagem", "scrape_ms"),
    (5, "Redação / relatório", "generate_summary_ms"),
]


# ---------------------------------------------------------------------------
# Estatística
# ---------------------------------------------------------------------------
def wilcoxon_signed_rank(diffs: list[float], alternative: str = "less") -> dict:
    """
    Wilcoxon signed-rank sobre as diferenças (x - y). p exato por enumeração das
    atribuições de sinal sobre os postos (empates: postos médios). Zeros são
    descartados (procedimento de Wilcoxon). alternative: "less" (x < y),
    "greater" ou "two-sided".
    """
    d = [x for x in diffs if x != 0 and not math.isnan(x)]
    n = len(d)
    if n == 0:
        return {"n": 0, "w_plus": float("nan"), "p": float("nan")}
    order = sorted(range(n), key=lambda i: abs(d[i]))
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(d[order[j + 1]]) == abs(d[order[i]]):
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    w_plus = sum(r for r, x in zip(ranks, d) if x > 0)
    total = sum(ranks)
    # distribuição exata de W+ sob H0 (cada posto entra com sinal + ou - com prob. 1/2)
    # programação dinâmica sobre os postos duplicados (x2) para manter inteiros
    r2 = [int(round(2 * r)) for r in ranks]
    dist = {0: 1}
    for r in r2:
        new: dict[int, int] = {}
        for s, c in dist.items():
            new[s] = new.get(s, 0) + c
            new[s + r] = new.get(s + r, 0) + c
        dist = new
    denom = 2 ** n
    obs = int(round(2 * w_plus))
    p_le = sum(c for s, c in dist.items() if s <= obs) / denom   # P(W+ <= obs)
    p_ge = sum(c for s, c in dist.items() if s >= obs) / denom   # P(W+ >= obs)
    if alternative == "less":      # x < y  =>  W+ pequeno
        p = p_le
    elif alternative == "greater":
        p = p_ge
    else:
        p = min(1.0, 2 * min(p_le, p_ge))
    return {"n": n, "w_plus": w_plus, "w_total": total, "p": p}


def _mean(v):
    v = [x for x in v if not math.isnan(x)]
    return statistics.mean(v) if v else float("nan")


def _sd(v):
    v = [x for x in v if not math.isnan(x)]
    return statistics.stdev(v) if len(v) > 1 else (0.0 if v else float("nan"))


def _fmt(v, d=1):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "—"
    if isinstance(v, float) and math.isinf(v):
        return "∞"
    return f"{v:.{d}f}"


def _fmt_p(p):
    if p is None or math.isnan(p):
        return "—"
    return "< 0.001" if p < 0.001 else f"{p:.3f}"


def _hms(seconds: float) -> str:
    if math.isnan(seconds):
        return "—"
    s = int(round(seconds))
    return f"{s // 3600}h{(s % 3600) // 60:02d}m{s % 60:02d}s" if s >= 3600 else f"{s // 60}m{s % 60:02d}s"


# ---------------------------------------------------------------------------
# Leitura dos dados
# ---------------------------------------------------------------------------
def _file_stamp(name: str) -> str:
    m = re.search(r"_(\d{8})_(\d{6})\.json$", name)
    return f"{m.group(1)}{m.group(2)}" if m else ""


def load_darksherlock(raw_glob: str, inv_dir: Path, model: str, since: str, runs: int,
                      pipeline_version: str | None = None):
    """Devolve ({cenário: [linhas]}, avisos). Linhas de todos os lotes, dedupadas pela investigação.

    Levanta ValueError se as execuções misturarem versões do pipeline e não tiver sido escolhida uma.
    """
    rows, seen, warnings, no_model, invs = [], set(), [], 0, []
    for path in sorted(glob.glob(raw_glob)):
        with open(path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                inv = (r.get("investigation_file") or "").strip()
                if not inv or not r.get("total_ms") or inv in seen:
                    continue
                stamp = _file_stamp(inv)
                if not stamp or stamp[:8] < since:
                    continue
                try:
                    data = json.loads((inv_dir / inv).read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    no_model += 1
                    continue
                if data.get("model") != model or not versions.keep(data, pipeline_version):
                    continue
                invs.append(data)
                seen.add(inv)
                r["_stamp"] = stamp
                rows.append(r)
    mixed = versions.mixed_error(invs, pipeline_version)
    if mixed:
        raise ValueError(mixed)
    if no_model:
        warnings.append(f"{no_model} linha(s) de raw_runs cuja investigação não foi encontrada em {inv_dir} (ignoradas).")
    by_sc: dict[str, list[dict]] = {}
    for r in sorted(rows, key=lambda x: x["_stamp"]):
        by_sc.setdefault(r["scenario_id"], []).append(r)
    for sc, lst in by_sc.items():
        if len(lst) > runs:
            warnings.append(f"{sc}: {len(lst)} execuções; usadas as primeiras {runs}.")
            by_sc[sc] = lst[:runs]
        elif len(lst) < runs:
            warnings.append(f"{sc}: só {len(lst)} execução(ões) (esperadas {runs}).")
    return by_sc, warnings


def load_baseline(path: Path):
    """Devolve ({cenário: {etapa: duração_s}}, avisos)."""
    out: dict[str, dict[int, float]] = {}
    warnings: list[str] = []
    if not path.is_file():
        return out, [f"{path} não existe: sem baseline."]
    counts: dict[tuple[str, int], int] = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            sc, st = r["scenario_id"], int(r["stage_num"])
            out.setdefault(sc, {})[st] = float(r["duration_s"])  # o último prevalece
            counts[(sc, st)] = counts.get((sc, st), 0) + 1
    for (sc, st), c in sorted(counts.items()):
        if c > 1:
            warnings.append(f"{sc} etapa {st}: {c} registos no baseline; usado o último.")
    return out, warnings


# ---------------------------------------------------------------------------
# Relatório
# ---------------------------------------------------------------------------
def build(ds: dict, base: dict) -> dict:
    per = []
    for sc in SCENARIO_IDS:
        rows = ds.get(sc, [])
        times = [float(r["total_ms"]) / 1000 for r in rows]
        stage_means = {}
        for n, _, col in STAGES:
            vals = [float(r[col]) / 1000 for r in rows if r.get(col) not in (None, "")]
            stage_means[n] = _mean(vals)
        b = base.get(sc, {})
        complete = all(n in b for n, _, _ in STAGES)
        b_total = sum(b[n] for n, _, _ in STAGES) if complete else float("nan")
        mean = _mean(times)
        per.append({
            "scenario": sc, "domain": DOMAINS[sc[0]], "n": len(times), "ds_mean": mean, "ds_sd": _sd(times),
            "baseline": b_total, "baseline_complete": complete, "stage_ds": stage_means,
            "stage_base": {n: b.get(n, float("nan")) for n, _, _ in STAGES},
            "speedup": (b_total / mean) if (complete and times and mean > 0) else float("nan"),
        })
    return {"per": per}


def render(res: dict, meta: dict, warnings: list[str]) -> str:
    per = res["per"]
    L = [f"# EQ-01 — eficiência operacional\n",
         f"Modelo: `{meta['model']}` · execuções desde {meta['since']} · n por cenário: {meta['runs']}.\n"]

    L.append("## Tabela 13 — tempo end-to-end e speedup\n")
    L.append("| Cenário | Execuções | DarkSherlock — média (s) | DP (s) | Baseline (s) | Speedup (×) |")
    L.append("|---|---|---|---|---|---|")
    for p in per:
        b = _fmt(p["baseline"]) if p["baseline_complete"] else "*por completar*"
        L.append(f"| {p['scenario']} | {p['n']} | {_fmt(p['ds_mean'])} | {_fmt(p['ds_sd'])} | {b} | {_fmt(p['speedup'], 2)} |")
    paired = [p for p in per if p["baseline_complete"] and p["n"] > 0]
    sp = [p["speedup"] for p in paired]
    if sp:
        gm = math.exp(statistics.mean(math.log(x) for x in sp if x > 0))
        L.append(f"| **Global (n = {len(paired)})** | — | {_fmt(_mean([p['ds_mean'] for p in paired]))} | "
                 f"{_fmt(_sd([p['ds_mean'] for p in paired]))} | {_fmt(_mean([p['baseline'] for p in paired]))} | "
                 f"mediana {_fmt(statistics.median(sp), 2)} · média geom. {_fmt(gm, 2)} |")
    L.append("\nO DP é entre execuções do mesmo cenário (DarkSherlock); o baseline é um valor único por cenário. "
             "O global é a média das médias por cenário. Tempos médios em horas: "
             f"DarkSherlock {_hms(_mean([p['ds_mean'] for p in paired]))}, "
             f"baseline {_hms(_mean([p['baseline'] for p in paired]))}." if paired else "")

    L.append("\n## Speedup por domínio\n")
    L.append("| Domínio | Cenários completos | Speedup — mediana (×) | Speedup — mín.–máx. (×) |")
    L.append("|---|---|---|---|")
    for letter, name in DOMAINS.items():
        s = [p["speedup"] for p in per if p["scenario"][0] == letter and not math.isnan(p["speedup"])]
        L.append(f"| {name} | {len(s)} | {_fmt(statistics.median(s), 2) if s else '—'} | "
                 f"{(_fmt(min(s), 2) + '–' + _fmt(max(s), 2)) if s else '—'} |")

    L.append("\n## Tempo por etapa (média entre cenários completos, em s)\n")
    L.append("| Etapa (manual ↔ pipeline) | DarkSherlock | Baseline | Razão baseline / DarkSherlock |")
    L.append("|---|---|---|---|")
    for n, name, _ in STAGES:
        d = _mean([p["stage_ds"][n] for p in paired])
        b = _mean([p["stage_base"][n] for p in paired])
        L.append(f"| {n}. {name} | {_fmt(d)} | {_fmt(b)} | {_fmt(b / d, 2) if d and not math.isnan(d) and not math.isnan(b) else '—'} |")

    L.append("\n## Teste de H1 — o DarkSherlock é mais rápido (Wilcoxon signed-rank, unilateral)\n")
    if len(paired) >= 2:
        w = wilcoxon_signed_rank([p["ds_mean"] - p["baseline"] for p in paired], "less")
        faster = sum(1 for p in paired if p["ds_mean"] < p["baseline"])
        L.append(f"- Pares (cenários completos): {len(paired)} · DarkSherlock mais rápido em {faster} de {len(paired)}.")
        L.append(f"- W⁺ = {_fmt(w['w_plus'], 1)} (de {_fmt(w.get('w_total', float('nan')), 1)}), "
                 f"n efetivo = {w['n']}, **p (exato, unilateral) = {_fmt_p(w['p'])}**; α = 0.05.")
        if w["n"] and 0.5 ** w["n"] > 0.05:
            L.append(f"- Atenção: com {w['n']} pares efetivos o menor p possível ({0.5 ** w['n']:.3f}) excede 0.05; "
                     "o teste não pode rejeitar H0.")
    else:
        L.append("- Menos de 2 cenários com baseline completo: teste não calculável.")

    if warnings:
        L.append("\n**Avisos:**")
        L.extend(f"- {w}" for w in warnings)
    L.append("\n*Notas: o tempo de carregamento do modelo (Etapa 1/Load LLM do pipeline) não entra no total por execução. "
             "O hardware e o ambiente são os da máquina de avaliação (ver secção de ambiente experimental).*")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True)
    ap.add_argument("--since", default="00000000", help="Só execuções com data de ficheiro >= AAAAMMDD.")
    ap.add_argument("--runs", type=int, default=3)
    versions.add_argument(ap)
    ap.add_argument("--raw", default=str(BASE / "results" / "raw_runs_*.csv"))
    ap.add_argument("--investigations", default=str(BASE.parent / "investigations"))
    ap.add_argument("--timing-log", default=str(BASE / "baseline_manual" / "timing_log.csv"))
    ap.add_argument("--out", default=str(BASE / "results" / "eq01_tabela13.md"))
    args = ap.parse_args()

    try:
        ds, w1 = load_darksherlock(args.raw, Path(args.investigations), args.model, args.since, args.runs,
                                   args.pipeline_version)
    except ValueError as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return 2
    if not ds:
        print(f"ERRO: nenhuma execução de {args.model!r} desde {args.since} (raw: {args.raw}).")
        return 1
    base, w2 = load_baseline(Path(args.timing_log))
    md = render(build(ds, base), {"model": args.model, "since": args.since, "runs": args.runs}, w1 + w2)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(md, encoding="utf-8")
    print(md)
    print(f"\nEscrito: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
