"""
evaluation/eq04_review.py — Qualidade analítica dos relatórios (EQ-04) do
Capítulo 6, secção 6.4.4: revisão cega por rubric Likert.

Protocolo (secção 6.4.4 / 6.6.4 do relatório):
  - 24 relatórios = 12 cenários x 2 condições (DarkSherlock, manual).
  - Rubric Likert 1-5 em quatro dimensões: (i) correção técnica, (ii)
    auditabilidade, (iii) utilidade operacional, (iv) ausência de
    hallucinations.
  - Dois revisores em modo cego, cada um com os 24 relatórios em ordem
    aleatória, sem indicação da origem. Divergência > 1 ponto (numa dimensão)
    -> um terceiro revisor reconcilia.
  - Taxa de citação correta = afirmações com referência válida / afirmações
    verificáveis; taxa de hallucinations = o complementar (1 - taxa de
    citação correta), conforme o texto do relatório.
  - H0: pontuação média humana da análise do LLM <= 3; H1: > 3 (teste t
    unilateral, sobre a pontuação global por relatório do DarkSherlock).

Dois subcomandos:

  build    Anonimiza e baralha os relatórios; gera, para cada revisor, os
           relatórios, a evidência (texto das fontes) e a folha de pontuação.
           A chave (ID -> cenário/condição) fica em private/key.json e NÃO
           deve ser dada aos revisores.
  analyze  Lê as folhas preenchidas (e as reconciliações) e calcula
           concordância, médias por dimensão e condição, teste de H1 e taxas
           de citação/hallucination.

Decisões de operacionalização (documentar na metodologia):
  - Execução do DarkSherlock usada por cenário: a PRIMEIRA (por data) entre as
    do modelo indicado (--model), a partir de --since. A regra é fixada antes
    de ver os relatórios, para não haver escolha seletiva (--run-rule).
  - Anonimização: remove-se o aviso de qualidade/recusa do DarkSherlock e, nos
    relatórios manuais, o bloco de metadados e as linhas de SHA-256/timestamp
    da "Análise por Fonte". O estilo de redação pode ainda denunciar a origem
    (p. ex. "[FONTE N]"); a cegagem é por isso parcial e deve ser declarada
    como ameaça à validade.
  - Divergência = |A - B| >= 2 numa dimensão. Nas dimensões sem divergência, a
    pontuação final é a média dos dois revisores; nas divergentes, é o valor
    reconciliado pelo 3.º revisor.
  - Os contadores de citações (verificáveis / válidas) são feitos por cada
    revisor sobre o mesmo relatório; as taxas calculam-se por revisor e
    reporta-se a média dos dois.
  - A evidência de cada relatório DarkSherlock é o texto integral das fontes
    raspadas (o modelo viu no máximo 1 500 caracteres por fonte); a do manual
    é o conteúdo de sources/<ID>/*.txt.

Uso:
    python evaluation/eq04_review.py build \\
        --investigations "investigations/eval_*.json" \\
        --model "Phi-3.5-mini (embutido, médio)" --since 20261009 \\
        --manual-dir evaluation/baseline_manual
    # cada revisor preenche reviewer_A/scores_A.csv e reviewer_B/scores_B.csv
    python evaluation/eq04_review.py analyze
    # preencher score_final em divergences.csv (3.º revisor) e repetir analyze
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import random
import re
import statistics
import sys
from pathlib import Path

import versions

DIMENSIONS = ["correcao_tecnica", "auditabilidade", "utilidade_operacional", "ausencia_alucinacoes"]
DIM_LABELS = {
    "correcao_tecnica": "Correção técnica",
    "auditabilidade": "Auditabilidade",
    "utilidade_operacional": "Utilidade operacional",
    "ausencia_alucinacoes": "Ausência de hallucinations",
}
RUBRIC = {
    "correcao_tecnica": "1 = grosseiramente errado; 5 = tecnicamente irrepreensível.",
    "auditabilidade": "Todas as afirmações têm fonte identificável (1 = nenhuma; 5 = todas).",
    "utilidade_operacional": "O relatório forneceria valor real ao investigador (1 = nenhum; 5 = muito).",
    "ausencia_alucinacoes": "Inexistência de afirmações sem suporte nas fontes (1 = muitas; 5 = nenhuma).",
}
CONDITIONS = ("DarkSherlock", "manual")
DOMAINS = {"A": "Threat Intel", "B": "Ransomware/Malware", "C": "Identidade Pessoal", "D": "Espionagem Corporativa"}
SCENARIO_IDS = [f"{d}{n}" for d in "ABCD" for n in "123"]
DEFAULT_OUT = Path(__file__).resolve().parent / "ground_truth" / "eq04"
DIVERGENCE_MIN = 2  # |A - B| >= 2, i.e. "> 1 ponto"
SCORE_FIELDS = ["id", *DIMENSIONS, "afirmacoes_verificaveis", "afirmacoes_citacao_valida", "notas"]


# ---------------------------------------------------------------------------
# Estatística (stdlib)
# ---------------------------------------------------------------------------
def _betacf(a: float, b: float, x: float) -> float:
    """Fração contínua da beta incompleta (Numerical Recipes, modified Lentz)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = tiny if abs(d) < tiny else d
    d = 1.0 / d
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = tiny if abs(d) < tiny else d
        c = 1.0 + aa / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = tiny if abs(d) < tiny else d
        c = 1.0 + aa / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-16:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """Beta incompleta regularizada I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_front = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1.0 - x)
    front = math.exp(ln_front)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def t_sf(t: float, df: float) -> float:
    """P(T > t) para a distribuição t de Student com df graus de liberdade."""
    x = df / (df + t * t)
    tail = 0.5 * betainc(df / 2.0, 0.5, x)  # P(T > |t|)
    return tail if t >= 0 else 1.0 - tail


def one_sample_t(values: list[float], mu0: float, alternative: str = "greater") -> dict:
    n = len(values)
    if n < 2:
        return {"n": n, "mean": values[0] if values else float("nan"), "sd": float("nan"),
                "t": float("nan"), "df": n - 1, "p": float("nan"), "d": float("nan")}
    mean, sd = statistics.mean(values), statistics.stdev(values)
    if sd == 0:
        t = float("inf") if mean > mu0 else (float("-inf") if mean < mu0 else 0.0)
    else:
        t = (mean - mu0) / (sd / math.sqrt(n))
    df = n - 1
    if math.isinf(t):
        p = 0.0 if (t > 0) == (alternative == "greater") else 1.0
    elif alternative == "greater":
        p = t_sf(t, df)
    elif alternative == "less":
        p = t_sf(-t, df)
    else:
        p = min(1.0, 2 * t_sf(abs(t), df))
    d = (mean - mu0) / sd if sd > 0 else float("nan")
    return {"n": n, "mean": mean, "sd": sd, "t": t, "df": df, "p": p, "d": d}


def weighted_kappa(a: list[int], b: list[int], categories: tuple[int, ...] = (1, 2, 3, 4, 5)) -> float:
    """κ ponderado linear para duas listas de pontuações ordinais pareadas."""
    n = len(a)
    if n == 0 or n != len(b):
        return float("nan")
    k = len(categories)
    idx = {c: i for i, c in enumerate(categories)}
    obs = [[0.0] * k for _ in range(k)]
    for x, y in zip(a, b):
        obs[idx[x]][idx[y]] += 1.0 / n
    row = [sum(obs[i]) for i in range(k)]
    col = [sum(obs[i][j] for i in range(k)) for j in range(k)]
    num = den = 0.0
    for i in range(k):
        for j in range(k):
            w = abs(i - j) / (k - 1)
            num += w * obs[i][j]
            den += w * row[i] * col[j]
    if den == 0:
        return 1.0 if num == 0 else float("nan")
    return 1.0 - num / den


def _mean(vals: list[float]) -> float:
    v = [x for x in vals if not math.isnan(x)]
    return statistics.mean(v) if v else float("nan")


def _sd(vals: list[float]) -> float:
    v = [x for x in vals if not math.isnan(x)]
    return statistics.stdev(v) if len(v) > 1 else (0.0 if v else float("nan"))


def _fmt(v: float, digits: int = 2) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "—"
    if isinstance(v, float) and math.isinf(v):
        return "∞" if v > 0 else "−∞"
    return f"{v:.{digits}f}"


def _fmt_ms(vals: list[float]) -> str:
    v = [x for x in vals if not math.isnan(x)]
    if not v:
        return "—"
    return f"{statistics.mean(v):.2f} ± {_sd(v):.2f} (n={len(v)})" if len(v) > 1 else f"{v[0]:.2f} (n=1)"


def _fmt_p(p: float) -> str:
    if p is None or math.isnan(p):
        return "—"
    return "< 0.001" if p < 0.001 else f"{p:.3f}"


# ---------------------------------------------------------------------------
# Anonimização
# ---------------------------------------------------------------------------
_BANNER_RE = re.compile(r"\A(?:\s*>[^\n]*\n)+\s*", re.UNICODE)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_MANUAL_LEAK_RE = re.compile(r"(?im)^\s*[-*]\s*\**\s*(sha-?256|timestamp de recolha)[^\n]*\n?")


def strip_darksherlock_banners(summary: str) -> tuple[str, bool]:
    """Remove avisos de qualidade/recusa antepostos pelo DarkSherlock. Devolve (texto, havia_aviso)."""
    m = _BANNER_RE.match(summary)
    if m and "⚠" in m.group(0):
        return summary[m.end():].lstrip(), True
    return summary.strip(), False


def anonymize_manual(text: str) -> tuple[str, list[str]]:
    """Remove metadados e campos que denunciam o baseline manual. Devolve (texto, avisos)."""
    warnings: list[str] = []
    text = _COMMENT_RE.sub("", text)
    m = re.search(r"(?m)^##\s*1\.", text)
    if m:
        text = text[m.start():]
    else:
        warnings.append("cabeçalho '## 1.' não encontrado; metadados não removidos")
    text = _MANUAL_LEAK_RE.sub("", text)
    return text.strip(), warnings


# ---------------------------------------------------------------------------
# Seleção das execuções / leitura dos relatórios
# ---------------------------------------------------------------------------
def _file_stamp(path: str) -> str:
    m = re.search(r"_(\d{8})_(\d{6})\.json$", path)
    return f"{m.group(1)}{m.group(2)}" if m else ""


def pick_darksherlock_runs(pattern: str, model: str, since: str, rule: str,
                           pipeline_version: str | None = None) -> dict[str, dict]:
    """Uma execução por cenário (regra `rule`). ValueError se misturarem versões do pipeline sem escolha."""
    runs: dict[str, list[tuple[str, dict]]] = {}
    for path in sorted(glob.glob(pattern)):
        stamp = _file_stamp(path)
        if not stamp or stamp[:8] < since:
            continue
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("model") != model or data.get("scenario_id") not in SCENARIO_IDS or not data.get("summary"):
            continue
        if not versions.keep(data, pipeline_version):
            continue
        runs.setdefault(data["scenario_id"], []).append((path, data))
    mixed = versions.mixed_error([d for items in runs.values() for _, d in items], pipeline_version)
    if mixed:
        raise ValueError(mixed)
    chosen = {}
    for sc, items in runs.items():
        items.sort(key=lambda it: _file_stamp(it[0]))
        if rule == "first":
            path, data = items[0]
        else:  # median_sources: mediana do n.º de fontes finais; empates -> a mais antiga
            ranked = sorted(items, key=lambda it: (len(it[1].get("scraped_content", {})), _file_stamp(it[0])))
            path, data = ranked[(len(ranked) - 1) // 2]
        chosen[sc] = {"path": path, "data": data, "n_runs": len(items)}
    return chosen


def read_manual(manual_dir: Path, scenario: str) -> dict | None:
    rpt = manual_dir / "reports" / f"report_{scenario}.md"
    if not rpt.is_file():
        return None
    sources_dir = manual_dir / "sources" / scenario
    sources = {}
    if sources_dir.is_dir():
        for p in sorted(sources_dir.glob("*.txt")):
            sources[p.name] = p.read_text(encoding="utf-8", errors="replace")
    return {"report": rpt.read_text(encoding="utf-8"), "sources": sources, "path": str(rpt)}


def evidence_darksherlock(scraped: dict) -> str:
    parts = ["# Evidência — texto integral das fontes raspadas\n"]
    for i, (url, text) in enumerate(scraped.items(), 1):
        parts.append(f"\n---\n\n## [FONTE {i}]\nURL: {url}\n\n{text}\n")
    return "".join(parts)


def evidence_manual(sources: dict) -> str:
    parts = ["# Evidência — texto das fontes recolhidas\n"]
    for name, text in sources.items():
        parts.append(f"\n---\n\n## Ficheiro: {name}\n\n{text}\n")
    return "".join(parts)


INSTRUCTIONS = """# Instruções de revisão (EQ-04)

Vais avaliar {n} relatórios de investigação (R01 ... R{n:02d}), em **ordem
aleatória** e **sem saber como foram produzidos**. Não tentes descobrir a
origem e não discutas as pontuações com o outro revisor antes de terminarem.

## Material
- `reports/Rxx.md` — o relatório a avaliar.
- `evidence/Rxx.md` — o texto das fontes em que o relatório se apoia. É o
  critério para decidir se uma afirmação tem suporte.
- `scores_{reviewer}.csv` — a tua folha de pontuação, **por esta ordem**.

## Rubric (escala 1-5, 5 = melhor)
{rubric}

## Contagem de citações (por relatório)
- `afirmacoes_verificaveis`: n.º de afirmações factuais do relatório que se
  podem confrontar com as fontes (ignora opinião, recomendações e próximos
  passos).
- `afirmacoes_citacao_valida`: dessas, quantas têm uma referência à fonte
  **e** a fonte indicada suporta de facto a afirmação.
- Uma afirmação sem referência, ou cuja fonte não a suporta, **não** conta
  como citação válida. A taxa de hallucinations é calculada como o
  complementar da taxa de citação correta.

## Regras
- Preenche todas as células das 4 dimensões e os dois contadores
  (`valida` <= `verificaveis`; ambos inteiros >= 0).
- Usa a coluna `notas` para justificar pontuações extremas (1 ou 5).
- Não alteres a coluna `id` nem a ordem das linhas.
"""


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def cmd_build(args) -> int:
    out = Path(args.out)
    if (out / "private" / "key.json").exists() and not args.force:
        print(f"ERRO: {out / 'private' / 'key.json'} já existe. Reconstruir muda os IDs e invalida as folhas "
              "já preenchidas; usa --force se é isso mesmo que queres.")
        return 1

    try:
        ds = pick_darksherlock_runs(args.investigations, args.model, args.since, args.run_rule,
                                    args.pipeline_version)
    except ValueError as e:
        print(f"ERRO: {e}")
        return 2
    manual_dir = Path(args.manual_dir)
    items, problems = [], []
    for sc in SCENARIO_IDS:
        if sc in ds:
            summary, had_banner = strip_darksherlock_banners(ds[sc]["data"]["summary"])
            if summary.startswith("## Sem dados suficientes"):
                problems.append(f"{sc} (DarkSherlock): relatório é o aviso 'Sem dados suficientes' — não é avaliável.")
            items.append({"scenario": sc, "condition": "DarkSherlock", "text": summary,
                          "evidence": evidence_darksherlock(ds[sc]["data"].get("scraped_content", {})),
                          "source_file": ds[sc]["path"], "n_candidate_runs": ds[sc]["n_runs"],
                          "had_quality_banner": had_banner, "n_sources": len(ds[sc]["data"].get("scraped_content", {}))})
        else:
            problems.append(f"{sc} (DarkSherlock): nenhuma execução de '{args.model}' desde {args.since}.")
        man = read_manual(manual_dir, sc)
        if man is None:
            problems.append(f"{sc} (manual): {manual_dir / 'reports' / f'report_{sc}.md'} não encontrado.")
        else:
            text, warns = anonymize_manual(man["report"])
            problems.extend(f"{sc} (manual): {w}" for w in warns)
            items.append({"scenario": sc, "condition": "manual", "text": text,
                          "evidence": evidence_manual(man["sources"]), "source_file": man["path"],
                          "n_sources": len(man["sources"])})

    if problems:
        print("AVISOS:")
        for p in problems:
            print("  -", p)
    missing = [p for p in problems if "nenhuma execução" in p or "não encontrado" in p]
    if missing and not args.allow_incomplete:
        print("\nERRO: faltam relatórios (ver acima). Completa-os ou usa --allow-incomplete para um ensaio parcial.")
        return 1
    if not items:
        print("ERRO: nenhum relatório disponível.")
        return 1

    rng = random.Random(args.seed)
    order = list(range(len(items)))
    rng.shuffle(order)
    n = len(items)
    key = {}
    for new_id, idx in enumerate(order, 1):
        rid = f"R{new_id:02d}"
        it = items[idx]
        key[rid] = {k: it[k] for k in ("scenario", "condition", "source_file", "n_sources")}
        key[rid].update({k: it[k] for k in ("n_candidate_runs", "had_quality_banner") if k in it})
        it["rid"] = rid

    (out / "private").mkdir(parents=True, exist_ok=True)
    (out / "private" / "key.json").write_text(
        json.dumps({"seed": args.seed, "model": args.model, "run_rule": args.run_rule, "since": args.since,
                    "pipeline_versions": sorted({versions.version_of(c["data"]) for c in ds.values()}),
                    "reports": key}, ensure_ascii=False, indent=2), encoding="utf-8")

    rubric_txt = "\n".join(f"- **{DIM_LABELS[d]}** (`{d}`): {RUBRIC[d]}" for d in DIMENSIONS)
    for reviewer in ("A", "B"):
        rdir = out / f"reviewer_{reviewer}"
        (rdir / "reports").mkdir(parents=True, exist_ok=True)
        (rdir / "evidence").mkdir(parents=True, exist_ok=True)
        for it in items:
            (rdir / "reports" / f"{it['rid']}.md").write_text(f"# Relatório {it['rid']}\n\n{it['text']}\n", encoding="utf-8")
            (rdir / "evidence" / f"{it['rid']}.md").write_text(it["evidence"], encoding="utf-8")
        (rdir / "INSTRUCOES.md").write_text(INSTRUCTIONS.format(n=n, rubric=rubric_txt, reviewer=reviewer),
                                            encoding="utf-8")
        rng_r = random.Random(f"{args.seed}-{reviewer}")
        rids = [it["rid"] for it in items]
        rng_r.shuffle(rids)
        with open(rdir / f"scores_{reviewer}.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(SCORE_FIELDS)
            for rid in rids:
                w.writerow([rid, "", "", "", "", "", "", ""])

    n_ds = sum(1 for it in items if it["condition"] == "DarkSherlock")
    print(f"{n} relatórios anonimizados ({n_ds} DarkSherlock, {n - n_ds} manual), seed={args.seed}.")
    print(f"Pastas para os revisores: {out}/reviewer_A e {out}/reviewer_B (cada uma com a sua ordem).")
    print(f"Chave (NÃO partilhar): {out}/private/key.json")
    for it in items:
        if it["condition"] == "DarkSherlock":
            extra = " (aviso de qualidade removido)" if it.get("had_quality_banner") else ""
            print(f"  {it['rid']}  <- {it['scenario']} DarkSherlock: {Path(it['source_file']).name}"
                  f" · {it['n_sources']} fonte(s) · {it['n_candidate_runs']} execução(ões) candidata(s){extra}")
    return 0


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------
def read_scores(path: Path, who: str, valid_ids: set[str]) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        for i, r in enumerate(csv.DictReader(f), 2):
            rid = (r.get("id") or "").strip()
            if not rid:
                continue
            if rid not in valid_ids:
                raise ValueError(f"{path.name} linha {i}: id desconhecido {rid!r}.")
            rec: dict = {}
            for d in DIMENSIONS:
                raw = (r.get(d) or "").strip()
                if raw == "":
                    raise ValueError(f"{path.name} linha {i} ({rid}): '{d}' por preencher.")
                try:
                    v = int(raw)
                except ValueError:
                    raise ValueError(f"{path.name} linha {i} ({rid}): '{d}'={raw!r} não é um inteiro 1-5.")
                if not 1 <= v <= 5:
                    raise ValueError(f"{path.name} linha {i} ({rid}): '{d}'={v} fora de 1-5.")
                rec[d] = v
            for c in ("afirmacoes_verificaveis", "afirmacoes_citacao_valida"):
                raw = (r.get(c) or "").strip()
                if raw == "":
                    raise ValueError(f"{path.name} linha {i} ({rid}): '{c}' por preencher.")
                try:
                    v = int(raw)
                except ValueError:
                    raise ValueError(f"{path.name} linha {i} ({rid}): '{c}'={raw!r} não é um inteiro.")
                if v < 0:
                    raise ValueError(f"{path.name} linha {i} ({rid}): '{c}' negativo.")
                rec[c] = v
            if rec["afirmacoes_citacao_valida"] > rec["afirmacoes_verificaveis"]:
                raise ValueError(f"{path.name} linha {i} ({rid}): citações válidas > verificáveis.")
            rows[rid] = rec
    missing = valid_ids - set(rows)
    if missing:
        raise ValueError(f"{path.name}: faltam {len(missing)} relatório(s), ex.: {sorted(missing)[0]}.")
    return rows


def read_reconciliation(path: Path) -> dict[tuple[str, str], int]:
    out: dict[tuple[str, str], int] = {}
    if not path.is_file():
        return out
    with open(path, newline="", encoding="utf-8-sig") as f:
        for i, r in enumerate(csv.DictReader(f), 2):
            raw = (r.get("score_final") or "").strip()
            if not raw:
                continue
            try:
                v = int(raw)
            except ValueError:
                raise ValueError(f"{path.name} linha {i}: score_final={raw!r} não é um inteiro 1-5.")
            if not 1 <= v <= 5:
                raise ValueError(f"{path.name} linha {i}: score_final={v} fora de 1-5.")
            out[((r.get("id") or "").strip(), (r.get("dimension") or "").strip())] = v
    return out


def compute(key: dict, A: dict, B: dict, recon: dict, allow_unresolved: bool) -> dict:
    ids = sorted(key)
    final: dict[str, dict[str, float]] = {rid: {} for rid in ids}
    divergences = []
    for rid in ids:
        for d in DIMENSIONS:
            a, b = A[rid][d], B[rid][d]
            if abs(a - b) >= DIVERGENCE_MIN:
                divergences.append({"id": rid, "dimension": d, "score_A": a, "score_B": b,
                                    "score_final": recon.get((rid, d), "")})
                final[rid][d] = float(recon[(rid, d)]) if (rid, d) in recon else float("nan")
            else:
                final[rid][d] = (a + b) / 2.0
    unresolved = [x for x in divergences if x["score_final"] == ""]
    if unresolved and not allow_unresolved:
        raise ValueError(f"{len(unresolved)} divergência(s) (> 1 ponto) por reconciliar.")

    agreement = {}
    for d in DIMENSIONS:
        a = [A[r][d] for r in ids]
        b = [B[r][d] for r in ids]
        agreement[d] = {
            "kappa_w": weighted_kappa(a, b),
            "exact": sum(1 for x, y in zip(a, b) if x == y) / len(ids),
            "within1": sum(1 for x, y in zip(a, b) if abs(x - y) <= 1) / len(ids),
        }
    all_a = [A[r][d] for r in ids for d in DIMENSIONS]
    all_b = [B[r][d] for r in ids for d in DIMENSIONS]
    agreement["global"] = {
        "kappa_w": weighted_kappa(all_a, all_b),
        "exact": sum(1 for x, y in zip(all_a, all_b) if x == y) / len(all_a),
        "within1": sum(1 for x, y in zip(all_a, all_b) if abs(x - y) <= 1) / len(all_a),
    }

    per_report = []
    for rid in ids:
        dims = final[rid]
        overall = _mean(list(dims.values())) if all(not math.isnan(v) for v in dims.values()) else float("nan")
        rec = {"id": rid, "scenario": key[rid]["scenario"], "condition": key[rid]["condition"], **dims, "overall": overall}
        for who, S in (("A", A), ("B", B)):
            ver, val = S[rid]["afirmacoes_verificaveis"], S[rid]["afirmacoes_citacao_valida"]
            rec[f"verif_{who}"], rec[f"valid_{who}"] = ver, val
            rec[f"cit_rate_{who}"] = val / ver if ver else float("nan")
        rec["cit_rate"] = _mean([rec["cit_rate_A"], rec["cit_rate_B"]])
        per_report.append(rec)
    return {"final": final, "divergences": divergences, "unresolved": unresolved,
            "agreement": agreement, "per_report": per_report}


def render_summary(res: dict, key_meta: dict) -> str:
    rows = res["per_report"]
    L = ["# EQ-04 — qualidade analítica (revisão cega, rubric Likert 1–5)\n"]
    L.append(f"Execução do DarkSherlock por cenário: regra `{key_meta.get('run_rule')}` "
             f"(modelo `{key_meta.get('model')}`, desde {key_meta.get('since')}). "
             f"Relatórios avaliados: {len(rows)}.\n")

    L.append("## Concordância entre os dois revisores (pontuações brutas)\n")
    L.append("| Dimensão | κ ponderado (linear) | Concordância exata | Diferença ≤ 1 |")
    L.append("|---|---|---|---|")
    for d in DIMENSIONS + ["global"]:
        a = res["agreement"][d]
        name = DIM_LABELS.get(d, "**Global (4 dimensões)**")
        L.append(f"| {name} | {_fmt(a['kappa_w'])} | {a['exact'] * 100:.0f} % | {a['within1'] * 100:.0f} % |")
    n_div = len(res["divergences"])
    L.append(f"\nDivergências > 1 ponto: {n_div} de {len(rows) * len(DIMENSIONS)} pontuações"
             f" ({len(res['unresolved'])} por reconciliar).\n")

    L.append("## Pontuação final por dimensão e condição (média ± desvio-padrão entre relatórios)\n")
    L.append("| Dimensão | DarkSherlock | Manual | Diferença (DS − manual)* |")
    L.append("|---|---|---|---|")
    by_cond = {c: [r for r in rows if r["condition"] == c] for c in CONDITIONS}
    for d in DIMENSIONS + ["overall"]:
        name = DIM_LABELS.get(d, "**Global (média das 4)**")
        cells = [_fmt_ms([r[d] for r in by_cond[c]]) for c in CONDITIONS]
        diffs = []
        man = {r["scenario"]: r[d] for r in by_cond["manual"]}
        for r in by_cond["DarkSherlock"]:
            if r["scenario"] in man and not math.isnan(r[d]) and not math.isnan(man[r["scenario"]]):
                diffs.append(r[d] - man[r["scenario"]])
        L.append(f"| {name} | {cells[0]} | {cells[1]} | {_fmt_ms(diffs)} |")
    L.append("\n*Diferença emparelhada por cenário; descritiva (sem hipótese pré-especificada para a comparação direta).\n")

    L.append("## Teste de H1 (DarkSherlock): média > 3 (t de Student unilateral, μ₀ = 3)\n")
    L.append("| Medida | n | Média | DP | t | gl | p (unilateral) | d de Cohen |")
    L.append("|---|---|---|---|---|---|---|---|")
    for d in ["overall"] + DIMENSIONS:
        vals = [r[d] for r in by_cond["DarkSherlock"] if not math.isnan(r[d])]
        t = one_sample_t(vals, 3.0, "greater")
        name = "**Global (H1 principal)**" if d == "overall" else DIM_LABELS[d]
        L.append(f"| {name} | {t['n']} | {_fmt(t['mean'])} | {_fmt(t['sd'])} | {_fmt(t['t'])} | {t['df']} | "
                 f"{_fmt_p(t['p'])} | {_fmt(t['d'])} |")
    L.append("\nO teste global é o da hipótese do Capítulo 6; os quatro testes por dimensão são exploratórios "
             "(sem correção para comparações múltiplas). A escala Likert é ordinal e n é pequeno: interpretar com cautela.\n")

    L.append("## Taxa de citação correta e taxa de hallucinations\n")
    L.append("Taxa de hallucinations = 1 − taxa de citação correta (definição do relatório); inclui afirmações "
             "sem qualquer referência. Média dos dois revisores.\n")
    L.append("| Condição | Citação correta (média por relatório) | Hallucinations | Citação correta (revisor A, agregado) | (revisor B, agregado) |")
    L.append("|---|---|---|---|---|")
    for c in CONDITIONS:
        rs = by_cond[c]
        mean_rate = _mean([r["cit_rate"] for r in rs])
        agg = []
        for who in ("A", "B"):
            ver = sum(r[f"verif_{who}"] for r in rs)
            val = sum(r[f"valid_{who}"] for r in rs)
            agg.append(f"{val / ver * 100:.1f} % ({val}/{ver})" if ver else "—")
        L.append(f"| {c} | {_fmt(mean_rate * 100, 1)} % | {_fmt((1 - mean_rate) * 100, 1)} % | {agg[0]} | {agg[1]} |")

    L.append("\n## Relatórios por cenário\n")
    L.append("| Cenário | Condição | Correção | Auditab. | Utilidade | Sem halluc. | Global | Citação correta |")
    L.append("|---|---|---|---|---|---|---|---|")
    for r in sorted(rows, key=lambda x: (x["scenario"], x["condition"])):
        L.append(f"| {r['scenario']} | {r['condition']} | " + " | ".join(_fmt(r[d]) for d in DIMENSIONS) +
                 f" | {_fmt(r['overall'])} | {_fmt(r['cit_rate'] * 100, 0)} % |")
    if res["unresolved"]:
        L.append("\n**Aviso:** há divergências por reconciliar, excluídas dos agregados (--allow-unresolved).")
    L.append("\n*Notas: pontuação final = média dos dois revisores, exceto nas dimensões com divergência > 1 ponto, "
             "onde vale o valor reconciliado pelo 3.º revisor. A cegagem é parcial (ver cabeçalho do script).*")
    return "\n".join(L)


def cmd_analyze(args) -> int:
    out = Path(args.out)
    key_path = out / "private" / "key.json"
    if not key_path.is_file():
        print(f"ERRO: {key_path} não existe. Corre 'build' primeiro.")
        return 1
    meta = json.loads(key_path.read_text(encoding="utf-8"))
    key = meta["reports"]
    ids = set(key)
    try:
        A = read_scores(out / "reviewer_A" / "scores_A.csv", "A", ids)
        B = read_scores(out / "reviewer_B" / "scores_B.csv", "B", ids)
        recon = read_reconciliation(out / "divergences.csv")
        res = compute(key, A, B, recon, args.allow_unresolved)
    except (ValueError, FileNotFoundError) as e:
        # Se o erro foi de divergências por reconciliar, escreve o ficheiro para o 3.º revisor.
        if "reconciliar" in str(e):
            try:
                A = read_scores(out / "reviewer_A" / "scores_A.csv", "A", ids)
                B = read_scores(out / "reviewer_B" / "scores_B.csv", "B", ids)
                res = compute(key, A, B, read_reconciliation(out / "divergences.csv"), True)
                _write_divergences(out / "divergences.csv", res["divergences"])
                print(f"ERRO: {e}\nO 3.º revisor deve preencher 'score_final' em {out / 'divergences.csv'} "
                      "e depois repetir 'analyze' (ou usar --allow-unresolved).")
                return 1
            except (ValueError, FileNotFoundError):
                pass
        print(f"ERRO: {e}")
        return 1

    _write_divergences(out / "divergences.csv", res["divergences"])
    fields = ["id", "scenario", "condition", *DIMENSIONS, "overall", "verif_A", "valid_A", "verif_B", "valid_B", "cit_rate"]
    with open(out / "eq04_scores.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(res["per_report"])
    md = render_summary(res, meta)
    (out / "eq04_summary.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"\nEscrito: {out / 'eq04_summary.md'}, {out / 'eq04_scores.csv'}, {out / 'divergences.csv'}")
    return 0


def _write_divergences(path: Path, divergences: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["id", "dimension", "score_A", "score_B", "score_final"])
        w.writeheader()
        w.writerows(divergences)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="Anonimiza e baralha os relatórios e gera as pastas dos revisores.")
    b.add_argument("--investigations", required=True, help='Glob das investigações (ex.: "investigations/eval_*.json").')
    b.add_argument("--model", required=True, help="Etiqueta exata do modelo cujas execuções entram na EQ-04.")
    b.add_argument("--since", default="00000000", help="Só execuções com data de ficheiro >= AAAAMMDD.")
    versions.add_argument(b)
    b.add_argument("--run-rule", choices=["first", "median_sources"], default="first",
                   help="Execução por cenário: a primeira (por data) ou a mediana do n.º de fontes finais.")
    b.add_argument("--manual-dir", default=str(Path(__file__).resolve().parent / "baseline_manual"))
    b.add_argument("--out", default=str(DEFAULT_OUT))
    b.add_argument("--seed", type=int, default=42)
    b.add_argument("--allow-incomplete", action="store_true", help="Ensaio parcial: permite cenários/condições em falta.")
    b.add_argument("--force", action="store_true", help="Reconstrói mesmo que já exista uma chave (invalida as folhas).")
    b.set_defaults(func=cmd_build)

    a = sub.add_parser("analyze", help="Calcula concordância, médias, teste de H1 e taxas de citação.")
    a.add_argument("--out", default=str(DEFAULT_OUT))
    a.add_argument("--allow-unresolved", action="store_true", help="Exclui divergências por reconciliar em vez de falhar.")
    a.set_defaults(func=cmd_analyze)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
