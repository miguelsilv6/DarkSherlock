"""
evaluation/eq02_eq03.py — Cobertura (EQ-02) e qualidade da filtragem (EQ-03)
do Capítulo 6, secções 6.4.2 e 6.4.3.

Protocolo (pooling, Voorhees 2002): a união das fontes recuperadas pelas duas
condições (DarkSherlock e baseline manual) constitui o pool; dois revisores
independentes classificam cada fonte do pool como relevante / não relevante /
inacessível; a concordância mede-se pelo κ de Cohen (aceitável a partir de
0,6). Daí saem o recall de cada condição (EQ-02) e Precision@20, Recall@20 e
F1@20 do Top-20 (EQ-03), comparando o Top-20 escolhido pelo LLM com os 20
primeiros resultados sem ranking e com a seleção do investigador.

Dois subcomandos:

  build    Constrói o pool de um cenário e gera as folhas de revisão.
  analyze  Lê as folhas preenchidas e calcula κ, recall, P@20, R@20 e F1@20.

Entradas
  - Investigações do DarkSherlock (evaluation/run_scenarios.py), uma por
    execução (3 por cenário no protocolo), com "search_results" (fontes
    recuperadas, cada uma com "found_by") e "sources" (o Top-20 do LLM).
    Investigações anteriores a esse campo não servem e são ignoradas com
    aviso.
  - Fontes da condição manual, num CSV por cenário
    (evaluation/baseline_manual/templates/manual_sources_template.csv):
    url, title, engine, selected. "selected" = 1 nas (até 20) escolhidas na
    triagem (Etapa 3), que formam o Top-20 manual.

Decisões de operacionalização (documentar na metodologia):
  - Identidade das fontes: URL normalizado (esquema e anfitrião em
    minúsculas, sem fragmento nem "/" final).
  - O pool junta as fontes recuperadas por TODAS as execuções do
    DarkSherlock desse cenário e pela condição manual; o recall de cada
    execução calcula-se depois contra o mesmo conjunto de relevantes, e
    reporta-se a média e o desvio-padrão entre execuções.
  - As folhas de revisão não indicam que condição recuperou cada fonte, e as
    linhas vão em ordem aleatória (--seed): o revisor não sabe a origem.
  - "Inacessível" não conta como relevante e é retirada de um Top-20 antes de
    calcular a Precision (a precisão é sobre as fontes que foi possível julgar).
  - P@20 divide pelo n.º de fontes efetivamente listadas (no máximo 20), e
    não por 20, quando há menos de 20; os acertos vão no CSV para quem
    preferir recalcular com k fixo.
  - Discordâncias entre A e B têm de ser resolvidas num ficheiro
    review_<ID>_final.csv (url,label); sem isso a análise recusa-se a correr
    (ou, com --allow-unresolved, exclui-as e avisa).
  - Controlo de EQ-03: os 20 primeiros de "search_results" (a ordem em que o
    pipeline os devolveu, sem ranking pelo LLM).

Uso:
    python evaluation/eq02_eq03.py build --scenario A1 \\
        --darksherlock "investigations/eval_A1_*.json" \\
        --manual evaluation/baseline_manual/reports/manual_sources_A1.csv
    # os dois revisores preenchem review_A1_A.csv e review_A1_B.csv
    python evaluation/eq02_eq03.py analyze \\
        --investigations "investigations/eval_*.json" \\
        --manual-dir evaluation/baseline_manual/reports
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import random
import statistics
import sys
from pathlib import Path
from urllib.parse import urlsplit

DOMAINS = {
    "A": "Threat Intel",
    "B": "Ransomware/Malware",
    "C": "Identidade Pessoal",
    "D": "Espionagem Corporativa",
}
LABELS = ("relevant", "not_relevant", "inaccessible")
_LABEL_ALIASES = {
    "relevant": "relevant", "relevante": "relevant", "r": "relevant", "1": "relevant",
    "not_relevant": "not_relevant", "nao_relevante": "not_relevant", "não_relevante": "not_relevant",
    "nr": "not_relevant", "n": "not_relevant", "0": "not_relevant",
    "inaccessible": "inaccessible", "inacessivel": "inaccessible", "inacessível": "inaccessible", "i": "inaccessible",
}
DEFAULT_OUT_DIR = Path(__file__).resolve().parent / "ground_truth"
KAPPA_THRESHOLD = 0.6
TOP_K = 20


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------
def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    path = parts.path.rstrip("/")
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}{query}"


def _norm_label(raw: str, where: str) -> str | None:
    value = (raw or "").strip().lower()
    if not value:
        return None
    if value not in _LABEL_ALIASES:
        raise ValueError(f"{where}: rótulo desconhecido {raw!r}. Válidos: relevant (r), not_relevant (n), inaccessible (i).")
    return _LABEL_ALIASES[value]


def _is_truthy(raw: str) -> bool:
    return (raw or "").strip().lower() in {"1", "y", "yes", "s", "sim", "x", "true"}


def cohen_kappa(a: list[str], b: list[str]) -> float:
    """κ de Cohen para duas listas de rótulos pareadas. NaN se vazio; 1,0 se ambos constantes e iguais."""
    n = len(a)
    if n == 0 or n != len(b):
        return float("nan")
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    cats = set(a) | set(b)
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    if pe == 1.0:
        return 1.0 if po == 1.0 else float("nan")
    return (po - pe) / (1 - pe)


def precision_recall_f1(top: list[str], relevant: set[str], inaccessible: set[str], k: int = TOP_K):
    """Devolve (hits, n_listadas, P, R, F1) para o Top-k; NaN onde não é definido."""
    seen, items = set(), []
    for u in top:
        if u not in seen:
            seen.add(u)
            items.append(u)
    items = [u for u in items[:k] if u not in inaccessible]
    hits = sum(1 for u in items if u in relevant)
    p = hits / len(items) if items else float("nan")
    r = hits / len(relevant) if relevant else float("nan")
    if math.isnan(p) or math.isnan(r):
        f1 = float("nan")
    else:
        f1 = 0.0 if (p + r) == 0 else 2 * p * r / (p + r)
    return hits, len(items), p, r, f1


def _mean(values: list[float]) -> float:
    vals = [v for v in values if not math.isnan(v)]
    return statistics.mean(vals) if vals else float("nan")


def _sd(values: list[float]) -> float:
    vals = [v for v in values if not math.isnan(v)]
    return statistics.stdev(vals) if len(vals) > 1 else (0.0 if vals else float("nan"))


def _fmt(v: float, digits: int = 2) -> str:
    return "—" if v is None or (isinstance(v, float) and math.isnan(v)) else f"{v:.{digits}f}"


def _fmt_ms(values: list[float]) -> str:
    """média ± desvio-padrão; sem ± quando só há uma execução."""
    vals = [v for v in values if not math.isnan(v)]
    if not vals:
        return "—"
    if len(vals) == 1:
        return f"{vals[0]:.2f}"
    return f"{statistics.mean(vals):.2f} ± {statistics.stdev(vals):.2f}"


def _scenario_domain(scenario_id: str) -> str:
    return DOMAINS.get(scenario_id[:1].upper(), "Outro")


# ---------------------------------------------------------------------------
# Leitura das condições
# ---------------------------------------------------------------------------
def load_darksherlock_runs(pattern: str, scenario: str) -> list[dict]:
    """Uma entrada por execução do DarkSherlock do cenário: retrieved, top20 (LLM), first20, found_by."""
    runs, skipped = [], 0
    for path in sorted(glob.glob(pattern)):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("scenario_id") != scenario:
            continue
        if "search_results" not in data:
            skipped += 1
            continue
        retrieved, found_by, titles = [], {}, {}
        for r in data["search_results"]:
            u = normalize_url(r["link"])
            if u not in found_by:
                retrieved.append(u)
                found_by[u] = set()
                titles[u] = (r.get("title") or "", r["link"])
            found_by[u].update(r.get("found_by", []))
        top20 = [normalize_url(s["link"]) for s in data.get("sources", [])][:TOP_K]
        runs.append({
            "file": Path(path).name, "retrieved": retrieved, "top20": top20,
            "first20": retrieved[:TOP_K], "found_by": found_by, "titles": titles,
        })
    if skipped:
        print(f"AVISO [{scenario}]: {skipped} investigação(ões) sem 'search_results' (anteriores ao campo) ignorada(s).")
    return runs


def load_manual(path: Path) -> dict | None:
    if not path.is_file():
        return None
    rows, order = {}, []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            if not (r.get("url") or "").strip():
                continue
            u = normalize_url(r["url"])
            if u not in rows:
                order.append(u)
                rows[u] = {
                    "url": r["url"].strip(), "title": (r.get("title") or "").strip(),
                    "engine": (r.get("engine") or "").strip(), "selected": False,
                }
            rows[u]["selected"] = rows[u]["selected"] or _is_truthy(r.get("selected", ""))
    top20 = [u for u in order if rows[u]["selected"]][:TOP_K]
    return {"retrieved": order, "top20": top20, "rows": rows}


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def cmd_build(args) -> int:
    scenario = args.scenario.upper()
    runs = load_darksherlock_runs(args.darksherlock, scenario)
    manual = load_manual(Path(args.manual))
    if not runs:
        print(f"ERRO: nenhuma investigação do DarkSherlock com 'search_results' para {scenario} em {args.darksherlock}.")
        return 1
    if manual is None:
        print(f"ERRO: ficheiro de fontes manuais não encontrado: {args.manual}")
        return 1

    pool: dict[str, dict] = {}
    for i, run in enumerate(runs, 1):
        for u in run["retrieved"]:
            e = pool.setdefault(u, {"url": run["titles"][u][1], "title": run["titles"][u][0], "ds_runs": set(),
                                    "found_by": set(), "ds_top20_runs": set(), "in_manual": False,
                                    "manual_engine": "", "manual_top20": False})
            e["ds_runs"].add(i)
            e["found_by"].update(run["found_by"][u])
        for u in run["top20"]:
            # o Top-20 sai de search_results, mas garante-se que entra no pool mesmo que não saia
            e = pool.setdefault(u, {"url": u, "title": "", "ds_runs": set(), "found_by": set(), "ds_top20_runs": set(),
                                    "in_manual": False, "manual_engine": "", "manual_top20": False})
            e["ds_runs"].add(i)
            e["ds_top20_runs"].add(i)
    for u in manual["retrieved"]:
        row = manual["rows"][u]
        e = pool.setdefault(u, {"url": row["url"], "title": row["title"], "ds_runs": set(), "found_by": set(),
                                "ds_top20_runs": set(), "in_manual": False, "manual_engine": "", "manual_top20": False})
        e["in_manual"] = True
        e["manual_engine"] = row["engine"]
        e["manual_top20"] = u in set(manual["top20"])
        if not e["title"]:
            e["title"] = row["title"]

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    with open(out / f"pool_{scenario}.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["url", "title", "in_darksherlock", "ds_runs", "ds_top20_runs", "found_by",
                    "in_manual", "manual_engine", "manual_top20"])
        for u in sorted(pool):
            e = pool[u]
            w.writerow([e["url"], e["title"], int(bool(e["ds_runs"])), "|".join(map(str, sorted(e["ds_runs"]))),
                        "|".join(map(str, sorted(e["ds_top20_runs"]))), "|".join(sorted(e["found_by"])),
                        int(e["in_manual"]), e["manual_engine"], int(e["manual_top20"])])

    order = sorted(pool)
    random.Random(args.seed).shuffle(order)
    for reviewer in ("A", "B"):
        with open(out / f"review_{scenario}_{reviewer}.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["n", "url", "title", "label", "notes"])
            for n, u in enumerate(order, 1):
                w.writerow([n, pool[u]["url"], pool[u]["title"], "", ""])

    only_ds = sum(1 for e in pool.values() if e["ds_runs"] and not e["in_manual"])
    only_manual = sum(1 for e in pool.values() if e["in_manual"] and not e["ds_runs"])
    both = sum(1 for e in pool.values() if e["in_manual"] and e["ds_runs"])
    print(f"[{scenario}] pool: {len(pool)} fontes ({len(runs)} execução(ões) DarkSherlock + manual). "
          f"Só DarkSherlock: {only_ds} · só manual: {only_manual} · ambos: {both}.")
    print(f"Folhas de revisão (ordem aleatória, sem indicar a origem): {out}/review_{scenario}_A.csv e _B.csv")
    print("Rótulos: relevant (r) / not_relevant (n) / inaccessible (i). Cada revisor preenche a sua folha sem ver a do outro.")
    return 0


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------
def _read_labels(path: Path, scenario: str, who: str) -> dict[str, str | None]:
    labels: dict[str, str | None] = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        for i, r in enumerate(csv.DictReader(f), 2):
            u = (r.get("url") or "").strip()
            if u:
                labels[normalize_url(u)] = _norm_label(r.get("label", ""), f"{path.name} linha {i}")
    return labels


def resolve_labels(scenario: str, gt_dir: Path, allow_unresolved: bool) -> tuple[dict[str, str], list, list]:
    """Rótulo final por URL. Devolve (final, pares (a, b) para o κ, discordâncias não resolvidas)."""
    pa, pb = gt_dir / f"review_{scenario}_A.csv", gt_dir / f"review_{scenario}_B.csv"
    if not (pa.is_file() and pb.is_file()):
        raise FileNotFoundError(f"faltam as folhas de revisão de {scenario} ({pa.name}, {pb.name}) em {gt_dir}")
    a, b = _read_labels(pa, scenario, "A"), _read_labels(pb, scenario, "B")
    if set(a) != set(b):
        raise ValueError(f"{scenario}: as folhas A e B não têm as mesmas URLs.")
    blank = [u for u in a if a[u] is None or b[u] is None]
    if blank:
        raise ValueError(f"{scenario}: {len(blank)} URL(s) sem rótulo (ex.: {blank[0]}). Os dois revisores têm de rotular tudo.")

    final_path = gt_dir / f"review_{scenario}_final.csv"
    resolved = _read_labels(final_path, scenario, "final") if final_path.is_file() else {}
    final, unresolved, pairs = {}, [], []
    for u in a:
        pairs.append((a[u], b[u]))
        if a[u] == b[u]:
            final[u] = a[u]
        elif resolved.get(u):
            final[u] = resolved[u]
        else:
            unresolved.append((u, a[u], b[u]))
    if unresolved and not allow_unresolved:
        lines = "\n".join(f"  {u}  A={x}  B={y}" for u, x, y in unresolved[:10])
        raise ValueError(
            f"{scenario}: {len(unresolved)} discordância(s) sem rótulo final. Resolve-as em {final_path.name} "
            f"(colunas url,label) ou usa --allow-unresolved para as excluir.\n{lines}"
        )
    return final, pairs, unresolved


def analyze_scenario(scenario: str, gt_dir: Path, investigations: str, manual_dir: Path, allow_unresolved: bool,
                     allow_unlabeled: bool) -> dict:
    final, pairs, unresolved = resolve_labels(scenario, gt_dir, allow_unresolved)
    relevant = {u for u, l in final.items() if l == "relevant"}
    inaccessible = {u for u, l in final.items() if l == "inaccessible"}
    runs = load_darksherlock_runs(investigations, scenario)
    manual = load_manual(manual_dir / f"manual_sources_{scenario}.csv")
    if not runs:
        raise ValueError(f"{scenario}: nenhuma execução do DarkSherlock com 'search_results'.")

    all_urls = set().union(*(set(r["retrieved"]) | set(r["top20"]) for r in runs))
    if manual:
        all_urls |= set(manual["retrieved"])
    unlabeled = {u for u in all_urls if u not in final} - {u for u, _, _ in unresolved}
    if unlabeled and not allow_unlabeled:
        raise ValueError(
            f"{scenario}: {len(unlabeled)} URL(s) recuperada(s) sem rótulo (pool desatualizado?), ex.: "
            f"{sorted(unlabeled)[0]}. Reconstrói o pool com 'build' ou usa --allow-unlabeled (conta como não relevantes)."
        )

    per_run = []
    for i, run in enumerate(runs, 1):
        retrieved_hits = len(set(run["retrieved"]) & relevant)
        recall = retrieved_hits / len(relevant) if relevant else float("nan")
        _, _, p_llm, r_llm, f_llm = precision_recall_f1(run["top20"], relevant, inaccessible)
        _, _, p_f20, r_f20, f_f20 = precision_recall_f1(run["first20"], relevant, inaccessible)
        per_run.append({
            "scenario_id": scenario, "domain": _scenario_domain(scenario), "run": i, "file": run["file"],
            "n_retrieved": len(run["retrieved"]), "relevant_retrieved": retrieved_hits, "n_relevant": len(relevant),
            "recall": recall, "p20_llm": p_llm, "r20_llm": r_llm, "f1_llm": f_llm,
            "p20_first20": p_f20, "r20_first20": r_f20, "f1_first20": f_f20,
        })

    manual_row = None
    if manual:
        hits = len(set(manual["retrieved"]) & relevant)
        _, _, p_m, r_m, f_m = precision_recall_f1(manual["top20"], relevant, inaccessible)
        manual_row = {
            "recall": hits / len(relevant) if relevant else float("nan"),
            "p20": p_m, "r20": r_m, "f1": f_m, "n_retrieved": len(manual["retrieved"]),
        }

    ds_relevant = set().union(*(set(r["retrieved"]) for r in runs)) & relevant
    man_relevant = (set(manual["retrieved"]) & relevant) if manual else set()
    ds_engines = {e for r in runs for u in ds_relevant for e in r["found_by"].get(u, set())}
    man_engines = {manual["rows"][u]["engine"] for u in man_relevant if manual["rows"][u]["engine"]} if manual else set()

    labels_a, labels_b = [p[0] for p in pairs], [p[1] for p in pairs]
    return {
        "scenario": scenario, "domain": _scenario_domain(scenario), "n_pool": len(final) + len(unresolved),
        "n_relevant": len(relevant), "n_inaccessible": len(inaccessible), "n_unresolved": len(unresolved),
        "n_unlabeled": len(unlabeled), "kappa_3": cohen_kappa(labels_a, labels_b),
        "kappa_bin": cohen_kappa([("relevant" if x == "relevant" else "other") for x in labels_a],
                                 [("relevant" if x == "relevant" else "other") for x in labels_b]),
        "pairs": pairs, "per_run": per_run, "manual": manual_row,
        "unique_relevant_ds": len(ds_relevant - man_relevant) if manual else None,
        "unique_relevant_manual": len(man_relevant - ds_relevant) if manual else None,
        "productive_engines_ds": len(ds_engines), "productive_engines_manual": len(man_engines) if manual else None,
    }


def render_summary(results: list[dict]) -> str:
    lines = ["# EQ-02 e EQ-03 — cobertura e qualidade da filtragem\n"]

    lines.append("## Concordância entre revisores (κ de Cohen)\n")
    lines.append("| Cenário | Fontes no pool | Relevantes | Inacessíveis | κ (3 classes) | κ (relevante vs. resto) | Aceitável (≥ 0,6) |")
    lines.append("|---|---|---|---|---|---|---|")
    all_pairs = []
    for r in results:
        all_pairs.extend(r["pairs"])
        ok = "sim" if (not math.isnan(r["kappa_3"]) and r["kappa_3"] >= KAPPA_THRESHOLD) else "não"
        lines.append(f"| {r['scenario']} | {r['n_pool']} | {r['n_relevant']} | {r['n_inaccessible']} | "
                     f"{_fmt(r['kappa_3'])} | {_fmt(r['kappa_bin'])} | {ok} |")
    k_all = cohen_kappa([p[0] for p in all_pairs], [p[1] for p in all_pairs])
    lines.append(f"| **Global** | {sum(r['n_pool'] for r in results)} | {sum(r['n_relevant'] for r in results)} | "
                 f"{sum(r['n_inaccessible'] for r in results)} | **{_fmt(k_all)}** | "
                 f"{_fmt(cohen_kappa([('relevant' if p[0] == 'relevant' else 'other') for p in all_pairs], [('relevant' if p[1] == 'relevant' else 'other') for p in all_pairs]))} | "
                 f"{'sim' if (not math.isnan(k_all) and k_all >= KAPPA_THRESHOLD) else 'não'} |")

    lines.append("\n## EQ-02 — recall sobre as fontes relevantes (por cenário)\n")
    lines.append("Recall do DarkSherlock: média ± desvio-padrão entre execuções (n execuções entre parênteses).\n")
    lines.append("| Cenário | Relevantes | Recall DarkSherlock | Recall manual | Só DarkSherlock | Só manual | Motores produtivos (DS / manual) |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in results:
        rec = [x["recall"] for x in r["per_run"]]
        m = r["manual"]
        lines.append(
            f"| {r['scenario']} | {r['n_relevant']} | {_fmt_ms(rec)} ({len(rec)}) | {_fmt(m['recall']) if m else '—'} | "
            f"{r['unique_relevant_ds'] if m else '—'} | {r['unique_relevant_manual'] if m else '—'} | "
            f"{r['productive_engines_ds']} / {r['productive_engines_manual'] if m else '—'} |"
        )

    lines.append("\n## EQ-03 — Precision@20, Recall@20 e F1@20 (por cenário)\n")
    lines.append("Top-20 do LLM (etapa 4) · 20 primeiros resultados sem ranking · seleção do investigador (média das execuções do DarkSherlock).\n")
    lines.append("| Cenário | P@20 LLM | P@20 1.os 20 | P@20 manual | R@20 LLM | R@20 1.os 20 | R@20 manual | F1@20 LLM | F1@20 1.os 20 | F1@20 manual |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in results:
        pr = r["per_run"]
        m = r["manual"]
        lines.append(
            f"| {r['scenario']} | {_fmt(_mean([x['p20_llm'] for x in pr]))} | {_fmt(_mean([x['p20_first20'] for x in pr]))} | "
            f"{_fmt(m['p20']) if m else '—'} | {_fmt(_mean([x['r20_llm'] for x in pr]))} | "
            f"{_fmt(_mean([x['r20_first20'] for x in pr]))} | {_fmt(m['r20']) if m else '—'} | "
            f"{_fmt(_mean([x['f1_llm'] for x in pr]))} | {_fmt(_mean([x['f1_first20'] for x in pr]))} | "
            f"{_fmt(m['f1']) if m else '—'} |"
        )

    lines.append("\n## Agregado por domínio (média das médias por cenário)\n")
    lines.append("| Domínio | Cenários | Recall DS | Recall manual | P@20 LLM | P@20 1.os 20 | P@20 manual | R@20 LLM | R@20 manual | F1@20 LLM | F1@20 manual |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for domain in sorted({r["domain"] for r in results}):
        rs = [r for r in results if r["domain"] == domain]
        mans = [r["manual"] for r in rs if r["manual"]]
        lines.append(
            f"| {domain} | {len(rs)} | {_fmt(_mean([_mean([x['recall'] for x in r['per_run']]) for r in rs]))} | "
            f"{_fmt(_mean([m['recall'] for m in mans])) if mans else '—'} | "
            f"{_fmt(_mean([_mean([x['p20_llm'] for x in r['per_run']]) for r in rs]))} | "
            f"{_fmt(_mean([_mean([x['p20_first20'] for x in r['per_run']]) for r in rs]))} | "
            f"{_fmt(_mean([m['p20'] for m in mans])) if mans else '—'} | "
            f"{_fmt(_mean([_mean([x['r20_llm'] for x in r['per_run']]) for r in rs]))} | "
            f"{_fmt(_mean([m['r20'] for m in mans])) if mans else '—'} | "
            f"{_fmt(_mean([_mean([x['f1_llm'] for x in r['per_run']]) for r in rs]))} | "
            f"{_fmt(_mean([m['f1'] for m in mans])) if mans else '—'} |"
        )

    notes = []
    if any(r["n_unresolved"] for r in results):
        notes.append("há discordâncias não resolvidas, excluídas (--allow-unresolved)")
    if any(r["n_unlabeled"] for r in results):
        notes.append("há URLs recuperadas sem rótulo, contadas como não relevantes (--allow-unlabeled)")
    if notes:
        lines.append("\n**Avisos:** " + "; ".join(notes) + ".")
    lines.append(
        "\n*Notas: P@20 usa o n.º de fontes efetivamente listadas (≤ 20) e exclui as inacessíveis; recall e R@20 usam "
        "como denominador as fontes finalmente relevantes do pool. Cenários com 0 relevantes não têm recall definido (—).*"
    )
    return "\n".join(lines)


def cmd_analyze(args) -> int:
    gt_dir = Path(args.ground_truth)
    scenarios = [s.strip().upper() for s in args.scenarios.split(",")] if args.scenarios else sorted(
        {p.name.split("_")[1] for p in gt_dir.glob("review_*_A.csv")}
    )
    if not scenarios:
        print(f"ERRO: nenhuma folha de revisão encontrada em {gt_dir}.")
        return 1

    results, errors = [], 0
    for sc in scenarios:
        try:
            results.append(analyze_scenario(sc, gt_dir, args.investigations, Path(args.manual_dir),
                                            args.allow_unresolved, args.allow_unlabeled))
        except (ValueError, FileNotFoundError) as e:
            print(f"ERRO [{sc}]: {e}")
            errors += 1
    if not results:
        return 1

    out = Path(args.out) if args.out else gt_dir
    out.mkdir(parents=True, exist_ok=True)
    fields = ["scenario_id", "domain", "run", "file", "n_retrieved", "relevant_retrieved", "n_relevant", "recall",
              "p20_llm", "r20_llm", "f1_llm", "p20_first20", "r20_first20", "f1_first20"]
    with open(out / "eq02_eq03_per_run.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerows(r["per_run"])
    md = render_summary(results)
    (out / "eq02_eq03_summary.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"\nEscrito: {out / 'eq02_eq03_summary.md'} e {out / 'eq02_eq03_per_run.csv'}")
    return 1 if errors else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="Constrói o pool e as folhas de revisão de um cenário.")
    b.add_argument("--scenario", required=True)
    b.add_argument("--darksherlock", required=True, help="Glob das investigações do DarkSherlock (ex.: investigations/eval_A1_*.json).")
    b.add_argument("--manual", required=True, help="CSV de fontes da condição manual (url,title,engine,selected).")
    b.add_argument("--out", default=str(DEFAULT_OUT_DIR))
    b.add_argument("--seed", type=int, default=42, help="Semente da ordem aleatória das folhas (default: 42).")
    b.set_defaults(func=cmd_build)

    a = sub.add_parser("analyze", help="Calcula κ, recall, P@20, R@20 e F1@20 a partir das folhas preenchidas.")
    a.add_argument("--ground-truth", default=str(DEFAULT_OUT_DIR), help="Diretório das folhas de revisão.")
    a.add_argument("--investigations", required=True, help="Glob das investigações do DarkSherlock (ex.: investigations/eval_*.json).")
    a.add_argument("--manual-dir", required=True, help="Diretório com manual_sources_<ID>.csv.")
    a.add_argument("--scenarios", default=None, help="IDs separados por vírgula (default: todos com folhas).")
    a.add_argument("--out", default=None)
    a.add_argument("--allow-unresolved", action="store_true", help="Exclui discordâncias sem rótulo final em vez de falhar.")
    a.add_argument("--allow-unlabeled", action="store_true", help="Conta URLs recuperadas sem rótulo como não relevantes.")
    a.set_defaults(func=cmd_analyze)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
