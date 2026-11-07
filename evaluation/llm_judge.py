"""
evaluation/llm_judge.py — Revisor LLM complementar para a EQ-02/EQ-03 (rótulos
do pool) e para a EQ-04 (rubric Likert), e concordância LLM–humano.

É uma análise ADICIONAL: os revisores humanos continuam obrigatórios e as
saídas deste script nunca são lidas por eq02_eq03.py nem por eq04_review.py
(ficam em <pasta>/llm_judge/, com nomes diferentes de review_<ID>_A/B.csv e
scores_A/B.csv). Na tese reporta-se como "concordância entre um juiz LLM e os
revisores humanos", nunca em substituição destes.

Subcomandos:

  eq0203   Rotula as fontes das folhas de revisão do pool (review_<ID>_A.csv,
           de que só lê as colunas url e title — nunca os rótulos humanos).
           Evidência: o texto raspado dessa URL (scraped_content das
           investigações do cenário); sem texto, só o título
           ("title_only"). Saída: llm_judge/review_<ID>_LLM.csv.
  eq04     Pontua os relatórios anonimizados de reviewer_A/ (reports/Rxx.md e
           evidence/Rxx.md) com a mesma rubric e as mesmas regras de contagem
           de citações dos humanos. Não lê private/key.json (o juiz fica cego
           à condição). Saída: <eq04>/llm_judge/scores_LLM.csv.
  compare  Concordância com os humanos:
             - EQ-02/03: κ de Cohen (3 classes e relevante vs. resto) entre o
               rótulo do LLM e o rótulo humano final, por cenário, global e
               por tipo de evidência (texto vs. só título), e matriz de confusão;
             - EQ-04: κ ponderado (linear) LLM–A e LLM–B ao lado de A–B,
               diferença média absoluta e viés (LLM − pontuação final humana)
               por dimensão, e taxa de citação correta.
           Saída: llm_judge/llm_judge_summary.md.

Decisões de operacionalização (documentar na metodologia):
  - Temperatura 0 (default de llm_utils); um prompt fixo por tarefa, cujo
    SHA-256 fica registado (meta_*.json e resumo), para reprodutibilidade.
  - Resposta inválida -> uma nova tentativa com um lembrete do formato; se
    falhar outra vez, fica sem rótulo/pontuação e conta como "inválida".
  - Evidência cortada ao orçamento de contexto do modelo (llm._context_budget_chars,
    o mesmo cálculo da Etapa 6) e a --max-chars; os cortes ficam contados.
  - "inaccessible" para o LLM significa "sem texto e o título não chega para
    decidir"; os humanos podem abrir a página, o LLM não. Por isso o κ é
    reportado também separado por tipo de evidência.
  - Viés de auto-preferência: usar como juiz um modelo diferente do que gerou
    os relatórios; o script avisa quando é o mesmo.
  - O terminal mostra só IDs e contagens (nenhuma query nem URL).

Uso:
    python evaluation/llm_judge.py eq0203 --ground-truth evaluation/ground_truth \\
        --investigations "investigations/eval_*.json" --model "Llama-3.2-3B (embutido, ...)"
    python evaluation/llm_judge.py eq04 --out evaluation/ground_truth/eq04 --model "..."
    python evaluation/llm_judge.py compare --ground-truth evaluation/ground_truth \\
        --eq04-out evaluation/ground_truth/eq04
"""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import math
import re
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for _p in (ROOT, HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import eq02_eq03  # noqa: E402
import eq04_review  # noqa: E402

JUDGE_DIR = "llm_judge"
LABELS = eq02_eq03.LABELS
DEFAULT_MAX_CHARS = 6000

SYSTEM = ("És um revisor rigoroso de uma avaliação académica de uma ferramenta de investigação forense. "
          "Julgas apenas com base no material fornecido e respondes exatamente no formato pedido, sem comentários.")

POOL_PROMPT = """Tarefa: decidir se uma fonte encontrada na dark web é relevante para uma investigação.

Query da investigação: {query}
Título da fonte: {title}
Texto da fonte ({evidence}):
<<<
{text}
>>>

Rótulos possíveis:
- relevant: a fonte trata do alvo da query e daria informação útil à investigação.
- not_relevant: a fonte não trata do alvo (outro tema, homónimo, página de navegação de um motor, spam).
- inaccessible: não há texto da página e o título não chega para decidir.

Responde só com uma palavra: relevant, not_relevant ou inaccessible."""

POOL_RETRY = "\n\nA resposta anterior não foi válida. Responde APENAS com uma palavra: relevant, not_relevant ou inaccessible."

REPORT_PROMPT = """Tarefa: avaliar um relatório de investigação com a rubric abaixo (escala 1-5, 5 = melhor),
usando a evidência como critério para decidir se uma afirmação tem suporte.

Rubric:
{rubric}

Contagem de citações:
- afirmacoes_verificaveis: n.º de afirmações factuais do relatório que se podem confrontar com a evidência
  (ignora opinião, recomendações e próximos passos).
- afirmacoes_citacao_valida: dessas, quantas têm referência à fonte E a fonte indicada suporta de facto a afirmação.
  Uma afirmação sem referência, ou cuja fonte não a suporta, não conta como citação válida.

RELATÓRIO:
<<<
{report}
>>>

EVIDÊNCIA:
<<<
{evidence}
>>>

Responde só com um objeto JSON numa linha, com estas chaves e valores inteiros:
{keys}"""

REPORT_RETRY = ("\n\nA resposta anterior não foi um JSON válido (inteiros 1-5 nas dimensões; contadores inteiros "
                ">= 0; afirmacoes_citacao_valida <= afirmacoes_verificaveis). Responde APENAS com o objeto JSON.")

_LABEL_RE = re.compile(r"not[_ ]relevant|irrelevant|n[ãa]o[_ ]relevante|inaccessible|inacess[íi]vel|relevante?",
                       re.IGNORECASE)
_LABEL_MAP = {"not_relevant": "not_relevant", "not relevant": "not_relevant", "irrelevant": "not_relevant",
              "não relevante": "not_relevant", "nao relevante": "not_relevant", "não_relevante": "not_relevant",
              "nao_relevante": "not_relevant", "inaccessible": "inaccessible", "inacessível": "inaccessible",
              "inacessivel": "inaccessible", "relevant": "relevant", "relevante": "relevant"}
SCORE_KEYS = [*eq04_review.DIMENSIONS, "afirmacoes_verificaveis", "afirmacoes_citacao_valida"]


def prompt_sha(*parts: str) -> str:
    return hashlib.sha256("\n".join((SYSTEM, *parts)).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Interpretação das respostas
# ---------------------------------------------------------------------------
def parse_label(text: str) -> str | None:
    m = _LABEL_RE.search(text or "")
    return _LABEL_MAP.get(m.group(0).lower()) if m else None


def parse_scores(text: str) -> dict | None:
    """Pontuações válidas de uma resposta (JSON ou "chave: n"), ou None."""
    text = text or ""
    rec: dict = {}
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict):
                rec = {k: obj.get(k) for k in SCORE_KEYS}
        except json.JSONDecodeError:
            rec = {}
    if not rec or any(rec.get(k) is None for k in SCORE_KEYS):
        for k in SCORE_KEYS:
            km = re.search(rf'"?{k}"?\s*[:=]\s*"?(-?\d+)', text)
            if km:
                rec[k] = km.group(1)
    try:
        out = {k: int(rec[k]) for k in SCORE_KEYS}
    except (KeyError, TypeError, ValueError):
        return None
    if any(not 1 <= out[d] <= 5 for d in eq04_review.DIMENSIONS):
        return None
    if out["afirmacoes_verificaveis"] < 0 or out["afirmacoes_citacao_valida"] < 0:
        return None
    if out["afirmacoes_citacao_valida"] > out["afirmacoes_verificaveis"]:
        return None
    return out


# ---------------------------------------------------------------------------
# Chamada ao modelo
# ---------------------------------------------------------------------------
def _ask(llm_obj, message: str) -> str:
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import ChatPromptTemplate

    import llm as llm_mod

    chain = ChatPromptTemplate([("system", SYSTEM), ("user", "{message}")]) | llm_obj | StrOutputParser()
    return llm_mod._strip_reasoning(chain.invoke({"message": message}))


def _budget(llm_obj, fixed_chars: int, max_chars: int) -> int:
    import llm as llm_mod

    return min(max_chars, llm_mod._context_budget_chars(llm_obj, fixed_chars))


def _cut(text: str, limit: int) -> tuple[str, bool]:
    return (text, False) if len(text) <= limit else (text[:limit] + "\n[... cortado ...]", True)


def _short(raw: str) -> str:
    return " ".join((raw or "").split())[:200]


# ---------------------------------------------------------------------------
# eq0203
# ---------------------------------------------------------------------------
def _scenario_material(inv_glob: str, scenario: str) -> tuple[str | None, dict[str, str], set[str]]:
    """(query, {url normalizado: texto raspado}, modelos das investigações) de um cenário."""
    query, texts, models = None, {}, set()
    for path in sorted(glob.glob(inv_glob)):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("scenario_id") != scenario:
            continue
        query = query or data.get("query")
        if data.get("model"):
            models.add(data["model"])
        for url, text in (data.get("scraped_content") or {}).items():
            u = eq02_eq03.normalize_url(url)
            if text and not texts.get(u):
                texts[u] = text
    return query, texts, models


def judge_pool(gt: Path, inv_glob: str, scenarios: list[str], llm_obj, model: str, limit: int | None = None,
               max_chars: int = DEFAULT_MAX_CHARS) -> dict:
    out_dir = gt / JUDGE_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {"model": model, "prompt_sha256": prompt_sha(POOL_PROMPT, POOL_RETRY), "limit": limit, "scenarios": {}}
    for sc in scenarios:
        sheet = gt / f"review_{sc}_A.csv"
        if not sheet.is_file():
            print(f"[{sc}] AVISO: {sheet.name} não existe — corre 'eq02_eq03.py build' primeiro.")
            continue
        with open(sheet, newline="", encoding="utf-8-sig") as f:
            rows = [{"n": r.get("n", ""), "url": (r.get("url") or "").strip(), "title": r.get("title") or ""}
                    for r in csv.DictReader(f) if not (r.get("n") or "").startswith("#")]
        rows = [r for r in rows if r["url"]]
        if limit is not None:
            rows = rows[:limit]
        query, texts, models = _scenario_material(inv_glob, sc)
        if not query:
            print(f"[{sc}] AVISO: nenhuma investigação com a query do cenário em {inv_glob} — saltado.")
            continue
        same = model in models
        if same:
            print(f"[{sc}] AVISO: o juiz é o mesmo modelo das investigações (viés de auto-preferência).")
        fixed = len(POOL_PROMPT) + len(query) + 300
        budget = _budget(llm_obj, fixed, max_chars)
        stats = {"n": 0, "text": 0, "title_only": 0, "truncated": 0, "invalid": 0, "same_model": same}
        out_rows = []
        for r in rows:
            text = texts.get(eq02_eq03.normalize_url(r["url"]), "")
            kind = "text" if text.strip() else "title_only"
            body, cut = _cut(text, budget) if kind == "text" else ("(sem texto recolhido)", False)
            msg = POOL_PROMPT.format(query=query, title=r["title"] or "(sem título)", evidence=kind, text=body)
            raw = _ask(llm_obj, msg)
            label = parse_label(raw)
            if label is None:
                raw = _ask(llm_obj, msg + POOL_RETRY)
                label = parse_label(raw)
            stats["n"] += 1
            stats[kind] += 1
            stats["truncated"] += int(cut)
            stats["invalid"] += int(label is None)
            out_rows.append({"n": r["n"], "url": r["url"], "title": r["title"], "label": label or "",
                             "evidence": kind, "truncated": int(cut), "raw": _short(raw)})
        with open(out_dir / f"review_{sc}_LLM.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["n", "url", "title", "label", "evidence", "truncated", "raw"])
            w.writeheader()
            w.writerows(out_rows)
        meta["scenarios"][sc] = stats
        print(f"[{sc}] {stats['n']} fonte(s): {stats['text']} com texto, {stats['title_only']} só título, "
              f"{stats['truncated']} cortada(s), {stats['invalid']} sem rótulo válido.")
    (out_dir / "meta_eq0203.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


# ---------------------------------------------------------------------------
# eq04
# ---------------------------------------------------------------------------
def judge_reports(eq04: Path, llm_obj, model: str, limit: int | None = None,
                  max_chars: int = DEFAULT_MAX_CHARS * 2) -> dict:
    rdir = eq04 / "reviewer_A"
    if not (rdir / "reports").is_dir():
        raise FileNotFoundError(f"{rdir / 'reports'} não existe — corre 'eq04_review.py build' primeiro.")
    rids = sorted(p.stem for p in (rdir / "reports").glob("R*.md"))
    if limit is not None:
        rids = rids[:limit]
    rubric = "\n".join(f"- {d} ({eq04_review.DIM_LABELS[d]}): {eq04_review.RUBRIC[d]}" for d in eq04_review.DIMENSIONS)
    keys = json.dumps({k: 0 for k in SCORE_KEYS})
    budget = _budget(llm_obj, len(REPORT_PROMPT) + len(rubric) + len(keys), max_chars)
    out_dir = eq04 / JUDGE_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {"model": model, "prompt_sha256": prompt_sha(REPORT_PROMPT, REPORT_RETRY), "limit": limit,
            "n": 0, "truncated": 0, "invalid": 0}
    rows = []
    for rid in rids:
        report = (rdir / "reports" / f"{rid}.md").read_text(encoding="utf-8")
        ev_path = rdir / "evidence" / f"{rid}.md"
        evidence = ev_path.read_text(encoding="utf-8") if ev_path.is_file() else ""
        report_cut, c1 = _cut(report, int(budget * 0.4))
        evidence_cut, c2 = _cut(evidence, budget - len(report_cut))
        msg = REPORT_PROMPT.format(rubric=rubric, report=report_cut, evidence=evidence_cut, keys=keys)
        raw = _ask(llm_obj, msg)
        scores = parse_scores(raw)
        if scores is None:
            raw = _ask(llm_obj, msg + REPORT_RETRY)
            scores = parse_scores(raw)
        meta["n"] += 1
        meta["truncated"] += int(c1 or c2)
        meta["invalid"] += int(scores is None)
        rows.append({"id": rid, **(scores or {k: "" for k in SCORE_KEYS}), "notas": _short(raw),
                     "truncado": int(c1 or c2)})
        print(f"  {rid}: {'OK' if scores else 'resposta inválida'}{' (evidência cortada)' if (c1 or c2) else ''}")
    with open(out_dir / "scores_LLM.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=[*eq04_review.SCORE_FIELDS, "truncado"])
        w.writeheader()
        w.writerows(rows)
    (out_dir / "meta_eq04.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{meta['n']} relatório(s) pontuado(s): {meta['invalid']} inválido(s), {meta['truncated']} com corte.")
    return meta


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------
def _fmt(v, d=2):
    return "—" if v is None or (isinstance(v, float) and math.isnan(v)) else f"{v:.{d}f}"


def _binary(labels):
    return ["relevant" if x == "relevant" else "other" for x in labels]


def _read_meta(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        return [r for r in csv.DictReader(line for line in f if not line.startswith("#"))]


def compare_pool(gt: Path) -> list[str]:
    L = ["## EQ-02/EQ-03 — rótulos do pool (LLM vs. rótulo humano final)\n"]
    jdir = gt / JUDGE_DIR
    files = sorted(jdir.glob("review_*_LLM.csv"))
    if not files:
        return L + ["Sem rótulos do LLM (corre `llm_judge.py eq0203`).\n"]
    meta = _read_meta(jdir / "meta_eq0203.json")
    L.append(f"Juiz: `{meta.get('model', '?')}` · prompt SHA-256 `{meta.get('prompt_sha256', '?')[:16]}…`"
             + (f" · limite de {meta['limit']} fontes por cenário (ensaio)" if meta.get("limit") else "") + "\n")
    if any(s.get("same_model") for s in meta.get("scenarios", {}).values()):
        L.append("**Aviso:** o juiz é o mesmo modelo das investigações (viés de auto-preferência).\n")
    L.append("| Cenário | Fontes comparadas | Sem rótulo LLM | Só título | Acordo | κ (3 classes) | κ (relevante vs. resto) |")
    L.append("|---|---|---|---|---|---|---|")
    all_h, all_l, kinds, notes = [], [], [], []
    for path in files:
        sc = path.name.split("_")[1]
        try:
            final, _, unresolved, _ = eq02_eq03.resolve_labels(sc, gt, allow_unresolved=True)
        except (ValueError, FileNotFoundError) as e:
            notes.append(f"{sc}: folhas humanas indisponíveis ({str(e).splitlines()[0]})")
            continue
        h, l_, k, no_label = [], [], [], 0
        for r in _read_csv(path):
            u = eq02_eq03.normalize_url(r["url"])
            if u not in final:
                continue
            if not r.get("label"):
                no_label += 1
                continue
            h.append(final[u])
            l_.append(r["label"])
            k.append(r.get("evidence", ""))
        acc = sum(1 for x, y in zip(h, l_) if x == y) / len(h) if h else float("nan")
        L.append(f"| {sc} | {len(h)} | {no_label} | {sum(1 for x in k if x == 'title_only')} | {_fmt(acc * 100, 0)} % | "
                 f"{_fmt(eq02_eq03.cohen_kappa(h, l_))} | {_fmt(eq02_eq03.cohen_kappa(_binary(h), _binary(l_)))} |")
        all_h += h
        all_l += l_
        kinds += k
    if all_h:
        acc = sum(1 for x, y in zip(all_h, all_l) if x == y) / len(all_h)
        L.append(f"| **Global** | {len(all_h)} | — | {sum(1 for x in kinds if x == 'title_only')} | {acc * 100:.0f} % | "
                 f"**{_fmt(eq02_eq03.cohen_kappa(all_h, all_l))}** | "
                 f"{_fmt(eq02_eq03.cohen_kappa(_binary(all_h), _binary(all_l)))} |")
        L.append("\n### Por tipo de evidência\n")
        L.append("| Evidência | n | κ (3 classes) | κ (relevante vs. resto) |")
        L.append("|---|---|---|---|")
        for kind in ("text", "title_only"):
            idx = [i for i, x in enumerate(kinds) if x == kind]
            h = [all_h[i] for i in idx]
            l_ = [all_l[i] for i in idx]
            L.append(f"| {kind} | {len(idx)} | {_fmt(eq02_eq03.cohen_kappa(h, l_))} | "
                     f"{_fmt(eq02_eq03.cohen_kappa(_binary(h), _binary(l_)))} |")
        L.append("\n### Matriz de confusão (linhas: humano · colunas: LLM)\n")
        L.append("| Humano \\ LLM | " + " | ".join(LABELS) + " |")
        L.append("|---|" + "---|" * len(LABELS))
        for a in LABELS:
            L.append(f"| {a} | " + " | ".join(str(sum(1 for x, y in zip(all_h, all_l) if x == a and y == b))
                                              for b in LABELS) + " |")
    if notes:
        L.append("\n**Notas:** " + "; ".join(notes) + ".")
    return L + [""]


def compare_reports(eq04: Path) -> list[str]:
    L = ["## EQ-04 — rubric Likert (LLM vs. revisores humanos)\n"]
    path = eq04 / JUDGE_DIR / "scores_LLM.csv"
    if not path.is_file():
        return L + ["Sem pontuações do LLM (corre `llm_judge.py eq04`).\n"]
    key_path = eq04 / "private" / "key.json"
    if not key_path.is_file():
        return L + [f"Sem {key_path.name} (corre `eq04_review.py build`).\n"]
    key_meta = json.loads(key_path.read_text(encoding="utf-8"))
    key = key_meta["reports"]
    jmeta = _read_meta(eq04 / JUDGE_DIR / "meta_eq04.json")
    L.append(f"Juiz: `{jmeta.get('model', '?')}` · prompt SHA-256 `{jmeta.get('prompt_sha256', '?')[:16]}…` · "
             f"relatórios pontuados: {jmeta.get('n', '?')} ({jmeta.get('invalid', '?')} inválidos, "
             f"{jmeta.get('truncated', '?')} com evidência cortada)\n")
    if jmeta.get("model") and jmeta.get("model") == key_meta.get("model"):
        L.append("**Aviso:** o juiz é o mesmo modelo que gerou os relatórios do DarkSherlock (viés de auto-preferência).\n")
    try:
        ids = set(key)
        A = eq04_review.read_scores(eq04 / "reviewer_A" / "scores_A.csv", "A", ids)
        B = eq04_review.read_scores(eq04 / "reviewer_B" / "scores_B.csv", "B", ids)
        res = eq04_review.compute(key, A, B, eq04_review.read_reconciliation(eq04 / "divergences.csv"), True)
    except (ValueError, FileNotFoundError) as e:
        return L + [f"Folhas humanas indisponíveis: {str(e).splitlines()[0]}\n"]
    llm_rows = {}
    for r in _read_csv(path):
        try:
            llm_rows[r["id"]] = {k: int(r[k]) for k in SCORE_KEYS}
        except (KeyError, ValueError):
            continue
    rids = sorted(set(llm_rows) & set(key))
    if not rids:
        return L + ["Nenhum relatório com pontuação válida do LLM e dos humanos.\n"]
    L.append(f"Relatórios comparados: {len(rids)}.\n")
    L.append("| Dimensão | κ_w A–B (humanos) | κ_w LLM–A | κ_w LLM–B | Dif. média absoluta (LLM vs. final) | Viés (LLM − final) |")
    L.append("|---|---|---|---|---|---|")
    for d in eq04_review.DIMENSIONS:
        a = [A[r][d] for r in rids]
        b = [B[r][d] for r in rids]
        m = [llm_rows[r][d] for r in rids]
        fin = [res["final"][r][d] for r in rids]
        pairs = [(x, y) for x, y in zip(m, fin) if not math.isnan(y)]
        mad = statistics.mean(abs(x - y) for x, y in pairs) if pairs else float("nan")
        bias = statistics.mean(x - y for x, y in pairs) if pairs else float("nan")
        L.append(f"| {eq04_review.DIM_LABELS[d]} | {_fmt(eq04_review.weighted_kappa(a, b))} | "
                 f"{_fmt(eq04_review.weighted_kappa(m, a))} | {_fmt(eq04_review.weighted_kappa(m, b))} | "
                 f"{_fmt(mad)} | {_fmt(bias)} |")
    by_id = {r["id"]: r for r in res["per_report"]}
    L.append("\n### Taxa de citação correta por condição\n")
    L.append("| Condição | Humanos (média A/B) | LLM |")
    L.append("|---|---|---|")
    for cond in eq04_review.CONDITIONS:
        sel = [r for r in rids if key[r]["condition"] == cond]
        hum = [by_id[r]["cit_rate"] for r in sel if not math.isnan(by_id[r]["cit_rate"])]
        llm_rates = [llm_rows[r]["afirmacoes_citacao_valida"] / llm_rows[r]["afirmacoes_verificaveis"]
                     for r in sel if llm_rows[r]["afirmacoes_verificaveis"]]
        L.append(f"| {cond} | {_fmt(statistics.mean(hum) * 100, 1) if hum else '—'} % | "
                 f"{_fmt(statistics.mean(llm_rates) * 100, 1) if llm_rates else '—'} % |")
    L.append("\n*κ_w = κ ponderado linear; «final» = pontuação humana final (média de A e B, ou o valor reconciliado). "
             "Se κ_w LLM–humano estiver ao nível de κ_w A–B, o juiz concorda com os humanos tanto quanto estes entre si.*")
    return L + [""]


def compare(gt: Path | None, eq04: Path | None) -> str:
    L = ["# Revisor LLM complementar — concordância com os revisores humanos\n",
         "Análise **complementar**: não substitui os revisores humanos nem entra nas EQ-02/03/04. "
         "Mede até que ponto um modelo local reproduz o juízo humano.\n"]
    if gt is not None:
        L += compare_pool(gt)
    if eq04 is not None:
        L += compare_reports(eq04)
    return "\n".join(L)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("eq0203", help="Rotula as fontes das folhas de revisão do pool.")
    p.add_argument("--ground-truth", default=str(eq02_eq03.DEFAULT_OUT_DIR))
    p.add_argument("--investigations", required=True, help='Glob das investigações (ex.: "investigations/eval_*.json").')
    p.add_argument("--scenarios", default=None, help="IDs separados por vírgula (default: todos com folhas).")
    p.add_argument("--model", required=True, help="Modelo do juiz (de preferência diferente do que gerou os relatórios).")
    p.add_argument("--limit", type=int, default=None, help="Só as primeiras N fontes por cenário (ensaio).")
    p.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS, help="Máximo de caracteres de texto por fonte.")

    r = sub.add_parser("eq04", help="Pontua os relatórios anonimizados da EQ-04.")
    r.add_argument("--out", default=str(eq04_review.DEFAULT_OUT), help="Pasta do eq04_review.py build.")
    r.add_argument("--model", required=True)
    r.add_argument("--limit", type=int, default=None, help="Só os primeiros N relatórios (ensaio).")
    r.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS * 2)

    c = sub.add_parser("compare", help="Concordância LLM–humano.")
    c.add_argument("--ground-truth", default=None)
    c.add_argument("--eq04-out", default=None)
    c.add_argument("--out", default=None, help="Ficheiro do resumo (default: <pasta>/llm_judge/llm_judge_summary.md).")

    args = ap.parse_args(argv)
    if args.command == "compare":
        if not args.ground_truth and not args.eq04_out:
            print("ERRO: indica --ground-truth e/ou --eq04-out.")
            return 2
        gt = Path(args.ground_truth) if args.ground_truth else None
        eq04 = Path(args.eq04_out) if args.eq04_out else None
        md = compare(gt, eq04)
        out = Path(args.out) if args.out else (gt or eq04) / JUDGE_DIR / "llm_judge_summary.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(md)
        print(f"\nEscrito: {out}")
        return 0

    import llm as llm_mod

    try:
        llm_obj = llm_mod.get_llm(args.model)
    except Exception as e:  # noqa: BLE001 — mensagem para o utilizador
        print(f"ERRO ao carregar o modelo {args.model!r}: {e}")
        return 1
    if args.command == "eq0203":
        gt = Path(args.ground_truth)
        scenarios = ([s.strip().upper() for s in args.scenarios.split(",")] if args.scenarios else
                     sorted({p.name.split("_")[1] for p in gt.glob("review_*_A.csv")}))
        if not scenarios:
            print(f"ERRO: nenhuma folha review_<ID>_A.csv em {gt}.")
            return 1
        judge_pool(gt, args.investigations, scenarios, llm_obj, args.model, args.limit, args.max_chars)
        return 0
    try:
        judge_reports(Path(args.out), llm_obj, args.model, args.limit, args.max_chars)
    except FileNotFoundError as e:
        print(f"ERRO: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
