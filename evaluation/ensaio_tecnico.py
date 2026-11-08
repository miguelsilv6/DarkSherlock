"""
evaluation/ensaio_tecnico.py — Ensaio técnico das análises que dependem de
pessoas (EQ-01 Tabela 13, EQ-02/EQ-03 pooling, EQ-04 revisão cega), com
DADOS FICTÍCIOS, antes de investir horas no baseline manual e nos revisores.

O que faz:
  1. Gera um baseline manual fictício (timing_log.csv, manual_sources_<ID>.csv,
     report_<ID>.md, sources/<ID>/*.txt) a partir das investigações reais do
     DarkSherlock (só os URLs recuperados; nenhuma query entra nos ficheiros).
  2. Corre os CLIs reais — tabela13.py, eq02_eq03.py build/analyze,
     true_negatives.py e eq04_review.py build --exclude-no-evidence/analyze —
     com caminhos explícitos para essa pasta.
  3. Preenche as folhas dos "revisores" com rótulos e pontuações aleatórios
     (concordância controlada) e as reconciliações, para exercitar o κ, as
     divergências e o 3.º revisor.
  4. Opcional (--with-llm-judge): corre o evaluation/llm_judge.py sobre as
     mesmas folhas, para testar esse circuito.
  5. Marca TODOS os .md e .csv produzidos com a marca d'água abaixo e escreve
     LEIA-ME.md com os passos e os avisos dos scripts.
  6. Gera o rascunho Word do Capítulo 6 (rascunho_cap6.py), com rodapé de
     dados simulados em todas as páginas.

Perfis (--perfil):
  - aleatorio (default): valores uniformes, sem relação entre si; marca
    d'água no topo de cada .md e .csv.
  - realista: valores plausíveis, com os pressupostos de REALISTA (tempos por
    etapa, sobreposição de fontes, relevância latente, notas Likert por
    condição) para ver como o capítulo se lê. Pasta SIMULADO_REALISTA_<data>,
    rodapé de dados simulados nos .md e no .docx; os .csv ficam sem marca.
    Os números continuam a ser inventados e não podem entrar na tese.

Os números produzidos NÃO têm significado e NÃO podem entrar na tese: servem
só para ver o formato final das tabelas e apanhar erros (cenários sem
execuções, relatórios sem evidência, mistura de versões, ...).

Isolamento:
  - Saída em evaluation/ensaio/ENSAIO_FICTICIO_<data>/ (no .gitignore e nos
    caminhos proibidos de redact.py). Recusa uma pasta dentro do repositório
    fora de evaluation/ensaio/; fora do repositório (p. ex. /tmp) é aceite.
  - Nunca escreve em evaluation/baseline_manual/, evaluation/ground_truth/ nem
    em investigations/: os dados reais só são lidos.
  - URLs fictícios usam o anfitrião ensaio-ficticio-N.onion; datas fictícias
    são de 2000-01-01, para não se confundirem com dados reais.

Uso:
    python evaluation/ensaio_tecnico.py --model "Phi-3.5-mini (embutido, médio)" --since 20261009
    python evaluation/ensaio_tecnico.py --model "..." --since 20261009 --with-llm-judge \\
        --judge-model "Llama-3.2-3B (embutido, ...)" --judge-limit 5
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import random
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "baseline_manual"))

import eq02_eq03  # noqa: E402
import eq04_review  # noqa: E402
from baseline_helper import STAGE_NAMES  # noqa: E402

ENSAIO_ROOT = HERE / "ensaio"
WATERMARK = "⚠️ ENSAIO TÉCNICO — DADOS FICTÍCIOS. NÃO USAR NA TESE."
FOOTER = "*Dados simulados (ensaio técnico, perfil realista) — não usar na tese.*"
FAKE_URL = "http://ensaio-ficticio-{n}.onion/"
FAKE_EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)
ENGINES = ("Ahmia", "Tor66", "The Deep Searches")
# Durações fictícias por etapa (s): intervalos plausíveis, só para o formato.
STAGE_RANGES = {1: (120, 600), 2: (600, 1800), 3: (600, 1800), 4: (1800, 5400), 5: (1200, 3600)}
LABEL_WEIGHTS = (("relevant", 0.3), ("not_relevant", 0.55), ("inaccessible", 0.15))
AGREEMENT = 0.8

# Perfil realista: pressupostos para valores plausíveis (não são medições). Tempos por etapa em
# segundos, para cenários com e sem evidência no DarkSherlock (sem evidência: triagem, recolha e
# relatório curtos); fontes manuais = parte das URLs reais do DarkSherlock + só manuais; relevância
# latente de cada URL do pool; notas Likert por condição (média, DP comum) e taxa de citação válida.
REALISTA = {
    "stage_s": {
        "evid": {1: (180, 480), 2: (900, 1800), 3: (900, 2100), 4: (2400, 5400), 5: (1800, 3600)},
        "sem": {1: (180, 480), 2: (900, 1800), 3: (600, 1200), 4: (600, 1500), 5: (600, 1200)},
    },
    "share_real": 0.4,           # fração das URLs do DarkSherlock que o investigador também vê
    "manual_only": (0.3, 0.5),   # fração da lista manual que só o investigador encontrou
    "collected": {"evid": (3, 8), "sem": (0, 0)},
    "p_rel": {"base": 0.15, "ds_top20": 0.30, "manual_sel": 0.35, "sem": 0.01},
    "p_inaccessible": 0.10,
    "agree_b": 0.88,             # revisor B igual ao rótulo latente (A)
    "likert": {
        "DarkSherlock": {"correcao_tecnica": 3.6, "auditabilidade": 3.9, "utilidade_operacional": 3.3,
                         "ausencia_alucinacoes": 3.4},
        "manual": {"correcao_tecnica": 4.1, "auditabilidade": 4.2, "utilidade_operacional": 3.9,
                   "ausencia_alucinacoes": 4.6},
    },
    "likert_sd": 0.7,
    "b_delta": ((0, 0.70), (1, 0.125), (-1, 0.125), (2, 0.025), (-2, 0.025)),
    "citations": {"DarkSherlock": ((8, 18), 0.78), "manual": ((5, 12), 0.93)},
}
PROTECTED = ("evaluation/baseline_manual", "evaluation/ground_truth", "investigations", "evaluation/results")


# ---------------------------------------------------------------------------
# Pasta de saída
# ---------------------------------------------------------------------------
def out_dir_problem(out: Path) -> str | None:
    """Motivo para recusar a pasta de saída, ou None se for aceitável."""
    out = out.resolve()
    try:
        rel = out.relative_to(ROOT)
    except ValueError:
        return None  # fora do repositório: não pode ir para o Git
    if rel.parts[:2] == ("evaluation", "ensaio") and len(rel.parts) > 2:
        return None
    return (f"{rel} fica dentro do repositório mas fora de evaluation/ensaio/: o ensaio só escreve lá "
            f"(ou fora do repositório), para nunca se misturar com dados reais ({', '.join(PROTECTED)}).")


# ---------------------------------------------------------------------------
# Baseline fictício
# ---------------------------------------------------------------------------
def _pick_label(rng: random.Random) -> str:
    x, acc = rng.random(), 0.0
    for label, w in LABEL_WEIGHTS:
        acc += w
        if x < acc:
            return label
    return LABEL_WEIGHTS[-1][0]


def _weighted(rng: random.Random, pairs) -> object:
    x, acc = rng.random(), 0.0
    for value, w in pairs:
        acc += w
        if x < acc:
            return value
    return pairs[-1][0]


def write_fake_baseline(base: Path, chosen: dict, rng: random.Random, perfil: str = "aleatorio",
                        no_evidence: set[str] = frozenset()) -> dict[str, int]:
    """Escreve o baseline fictício em `base`. Devolve {cenário: n.º de fontes manuais}."""
    real_profile = perfil == "realista"
    (base / "reports").mkdir(parents=True, exist_ok=True)
    counts = {}
    t = FAKE_EPOCH
    with open(base / "timing_log.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["scenario_id", "stage_num", "stage_name", "start_utc", "end_utc", "duration_s"])
        w.writeheader()
        for sc in sorted(chosen):
            ranges = REALISTA["stage_s"]["sem" if sc in no_evidence else "evid"] if real_profile else STAGE_RANGES
            for n in sorted(STAGE_NAMES):
                dur = round(rng.uniform(*ranges[n]), 1)
                end = t + timedelta(seconds=dur)
                w.writerow({"scenario_id": sc, "stage_num": n, "stage_name": STAGE_NAMES[n],
                            "start_utc": t.isoformat(), "end_utc": end.isoformat(), "duration_s": dur})
                t = end + timedelta(minutes=5)
    fake_n = 0
    for sc in sorted(chosen):
        data = chosen[sc]["data"]
        real, seen = [], set()
        for r in data.get("search_results", []):
            u = eq02_eq03.normalize_url(r.get("link", ""))
            if r.get("link") and u not in seen:
                seen.add(u)
                real.append(r["link"])
        if real_profile:
            n_real = min(30, max(1, round(REALISTA["share_real"] * len(real)))) if real else 0
            share = rng.uniform(*REALISTA["manual_only"])
            n_fake = max(1, round(n_real * share / (1 - share)))
        else:
            n_real, n_fake = min(15, len(real)), 5
        rows = [(u, "[ENSAIO FICTÍCIO] título") for u in rng.sample(real, n_real)]
        for _ in range(n_fake):
            fake_n += 1
            rows.append((FAKE_URL.format(n=fake_n), "[ENSAIO FICTÍCIO] fonte inventada"))
        rng.shuffle(rows)
        n_sel = min(20, max(1, int(len(rows) * (0.5 if real_profile else 0.6))))
        selected = set(rng.sample(range(len(rows)), n_sel))
        with open(base / "reports" / f"manual_sources_{sc}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url", "title", "engine", "selected"])
            for i, (u, title) in enumerate(rows):
                w.writerow([u, title, rng.choice(ENGINES), int(i in selected)])
        if real_profile:
            n_src = rng.randint(*REALISTA["collected"]["sem" if sc in no_evidence else "evid"])
        else:
            n_src = rng.randint(1, 4)
        (base / "sources" / sc).mkdir(parents=True, exist_ok=True)
        for k in range(1, n_src + 1):
            (base / "sources" / sc / f"fonte{k}.txt").write_text(
                f"[ENSAIO FICTÍCIO] conteúdo de exemplo da fonte {k} do cenário {sc}.\n", encoding="utf-8")
        fontes = "\n".join(
            f"### Fonte {k}\n\n- **URL:** {FAKE_URL.format(n=k)}\n- **SHA-256:** 0\n"
            f"- **Timestamp de recolha (UTC):** {FAKE_EPOCH.isoformat()}\n"
            f"- **Excerto citado:** \"[ENSAIO FICTÍCIO] conteúdo de exemplo da fonte {k}\"\n"
            f"- **Relevância:** [ENSAIO FICTÍCIO]\n" for k in range(1, n_src + 1))
        (base / "reports" / f"report_{sc}.md").write_text(
            f"# Baseline Manual — Investigação {sc}\n\n## Metadados\n\n- **Cenário:** {sc} [ENSAIO FICTÍCIO]\n\n"
            f"## 1. Query: [ENSAIO FICTÍCIO]\n\n## 2. Análise por Fonte\n\n{fontes}\n"
            "## 3. Artefactos / IOCs\n\nNenhum identificado. [ENSAIO FICTÍCIO]\n\n"
            "## 4. Insights Chave\n\n[ENSAIO FICTÍCIO]\n\n## 5. Próximos Passos\n\n[ENSAIO FICTÍCIO]\n",
            encoding="utf-8")
        counts[sc] = len(rows)
    return counts


# ---------------------------------------------------------------------------
# Revisores fictícios
# ---------------------------------------------------------------------------
def _latent_label(rng: random.Random, pool_row: dict | None, no_evidence: bool) -> str:
    """Rótulo "verdadeiro" do perfil realista, a partir da posição da URL no pool."""
    pr = REALISTA["p_rel"]
    if rng.random() < REALISTA["p_inaccessible"]:
        return "inaccessible"
    if no_evidence:
        p = pr["sem"]
    else:
        p = pr["base"]
        if pool_row and (pool_row.get("ds_top20_runs") or "").strip():
            p += pr["ds_top20"]
        if pool_row and (pool_row.get("manual_top20") or "").strip() == "1":
            p += pr["manual_sel"]
    return "relevant" if rng.random() < min(p, 0.9) else "not_relevant"


def fill_pool_reviews(gt: Path, scenario: str, rng: random.Random, perfil: str = "aleatorio",
                      no_evidence: bool = False) -> int:
    """Preenche review_<ID>_A/B.csv e _final.csv. Devolve n.º de discordâncias.

    aleatorio: rótulos uniformes, concordância ≈ AGREEMENT. realista: o revisor A segue a relevância latente
    (REALISTA["p_rel"], lida de pool_<ID>.csv) e o B concorda com ele em ≈ REALISTA["agree_b"].
    """
    pa, pb = gt / f"review_{scenario}_A.csv", gt / f"review_{scenario}_B.csv"
    with open(pa, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    pool = {}
    if perfil == "realista" and (gt / f"pool_{scenario}.csv").is_file():
        with open(gt / f"pool_{scenario}.csv", newline="", encoding="utf-8-sig") as f:
            pool = {eq02_eq03.normalize_url(r["url"]): r for r in csv.DictReader(f)}
    agreement = REALISTA["agree_b"] if perfil == "realista" else AGREEMENT
    labels_a, labels_b, disagreements = [], [], []
    for r in rows:
        if perfil == "realista":
            a = _latent_label(rng, pool.get(eq02_eq03.normalize_url(r["url"])), no_evidence)
        else:
            a = _pick_label(rng)
        b = a if rng.random() < agreement else rng.choice([x for x, _ in LABEL_WEIGHTS if x != a])
        labels_a.append(a)
        labels_b.append(b)
        if a != b:
            disagreements.append((r["url"], a))
    for path, labels in ((pa, labels_a), (pb, labels_b)):
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["n", "url", "title", "label", "notes"])
            w.writeheader()
            for r, label in zip(rows, labels):
                w.writerow({"n": r["n"], "url": r["url"], "title": r["title"], "label": label, "notes": "ensaio"})
    with open(gt / f"review_{scenario}_final.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(disagreements)
    return len(disagreements)


def fill_eq04_scores(eq04: Path, rng: random.Random, perfil: str = "aleatorio") -> None:
    """Preenche scores_A/B.csv. realista: notas por condição (REALISTA["likert"]), lida de private/key.json."""
    rids = []
    with open(eq04 / "reviewer_A" / "scores_A.csv", newline="", encoding="utf-8-sig") as f:
        rids = [r["id"] for r in csv.DictReader(f)]
    key = {}
    if perfil == "realista":
        key = json.loads((eq04 / "private" / "key.json").read_text(encoding="utf-8"))["reports"]
    a_scores = {}
    for rid in rids:
        if perfil == "realista":
            cond = key[rid]["condition"]
            means = REALISTA["likert"][cond]
            (lo, hi), rate = REALISTA["citations"][cond]
            ver = rng.randint(lo, hi)
            dims = {d: min(5, max(1, round(rng.gauss(means[d], REALISTA["likert_sd"])))) for d in eq04_review.DIMENSIONS}
            val = min(ver, max(0, round(ver * min(1.0, max(0.0, rng.gauss(rate, 0.08))))))
            a_scores[rid] = {"dims": dims, "ver": ver, "val": val}
        else:
            ver = rng.randint(3, 15)
            a_scores[rid] = {"dims": {d: rng.randint(1, 5) for d in eq04_review.DIMENSIONS}, "ver": ver,
                             "val": rng.randint(0, ver)}
    delta = REALISTA["b_delta"] if perfil == "realista" else ((0, .5), (1, 1 / 6), (-1, 1 / 6), (2, 1 / 6))
    for who in ("A", "B"):
        path = eq04 / f"reviewer_{who}" / f"scores_{who}.csv"
        with open(path, newline="", encoding="utf-8-sig") as f:
            order = [r["id"] for r in csv.DictReader(f)]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=eq04_review.SCORE_FIELDS)
            w.writeheader()
            for rid in order:
                s = a_scores[rid]
                dims = s["dims"] if who == "A" else {
                    d: min(5, max(1, v + _weighted(rng, delta))) for d, v in s["dims"].items()}
                ver = s["ver"] if who == "A" else max(0, s["ver"] + rng.choice((0, 1, -1)))
                val = min(ver, s["val"] if who == "A" else max(0, s["val"] + rng.choice((0, 1, -1))))
                w.writerow({"id": rid, **dims, "afirmacoes_verificaveis": ver, "afirmacoes_citacao_valida": val,
                            "notas": "ensaio"})


def fill_reconciliation(eq04: Path) -> int:
    path = eq04 / "divergences.csv"
    if not path.is_file():
        return 0
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["score_final"] = round((int(r["score_A"]) + int(r["score_B"])) / 2)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["id", "dimension", "score_A", "score_B", "score_final"])
        w.writeheader()
        w.writerows(rows)
    return len(rows)


# ---------------------------------------------------------------------------
# Passos
# ---------------------------------------------------------------------------
class Runner:
    def __init__(self, out: Path):
        self.out = out
        self.logs = out / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.steps: list[dict] = []

    def run(self, name: str, args: list[str], ok_codes=(0,)) -> int:
        log = self.logs / f"{len(self.steps) + 1:02d}_{name}.log"
        t0 = time.time()
        with open(log, "w", encoding="utf-8") as fh:
            proc = subprocess.run([sys.executable, *args], cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT, text=True)
        status = "OK" if proc.returncode in ok_codes else f"FALHOU ({proc.returncode})"
        self.steps.append({"name": name, "status": status, "seconds": round(time.time() - t0, 1), "log": log,
                           "code": proc.returncode})
        print(f"  {name:<28} {status:<14} {self.steps[-1]['seconds']:>7.1f} s")
        return proc.returncode

    def note(self, name: str, status: str) -> None:
        self.steps.append({"name": name, "status": status, "seconds": 0.0, "log": None, "code": 0})
        print(f"  {name:<28} {status}")


def _filters(args) -> list[str]:
    extra = ["--model", args.model, "--since", args.since]
    if args.pipeline_version:
        extra += ["--pipeline-version", args.pipeline_version]
    return extra


def _watermark(out: Path, perfil: str = "aleatorio") -> int:
    """aleatorio: marca d'água no topo de .md e .csv. realista: rodapé só nos .md (os .csv ficam limpos)."""
    n = 0
    for p in sorted(out.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in (".md", ".csv"):
            continue
        text = p.read_text(encoding="utf-8-sig")
        if perfil == "realista":
            if p.suffix.lower() == ".md" and FOOTER not in text:
                p.write_text(text.rstrip("\n") + f"\n\n---\n\n{FOOTER}\n", encoding="utf-8")
                n += 1
            continue
        if WATERMARK in text.split("\n", 1)[0]:
            continue
        prefix = f"> {WATERMARK}\n\n" if p.suffix.lower() == ".md" else f"# {WATERMARK}\n"
        p.write_text(prefix + text, encoding="utf-8")
        n += 1
    return n


def _log_warnings(step: dict, skip_scenarios: set[str], limit: int = 15) -> list[str]:
    """Avisos e erros do log de um passo: linhas AVISO/ERRO e os itens "- " de um bloco de avisos.

    Omite os avisos de cenários já listados como sem execuções e a divergência esperada do eq04_analyze_1.
    """
    if not step["log"] or not Path(step["log"]).is_file():
        return []
    out, in_block = [], False
    for ln in (x.strip() for x in Path(step["log"]).read_text(encoding="utf-8").splitlines()):
        if ln.upper().startswith(("AVISO", "**AVISO")):
            in_block = ln.rstrip("*").endswith(":")
            if not in_block:
                out.append(ln)
            continue
        if ln.startswith("ERRO"):
            if not (step["name"] == "eq04_analyze_1" and "por reconciliar" in ln):
                out.append(ln)
            continue
        if in_block and ln.startswith("- "):
            if ln[2:4] not in skip_scenarios:
                out.append(ln[2:])
            continue
        in_block = False
    return out[:limit]


def _assumptions() -> list[str]:
    r = REALISTA
    st = r["stage_s"]
    L = ["## Pressupostos do perfil realista\n",
         "| Etapa | Com evidência (s) | Sem evidência (s) |", "|---|---|---|"]
    for n in sorted(STAGE_NAMES):
        L.append(f"| {n}. {STAGE_NAMES[n]} | {st['evid'][n][0]}–{st['evid'][n][1]} | {st['sem'][n][0]}–{st['sem'][n][1]} |")
    pr = r["p_rel"]
    L += ["",
          f"- Fontes manuais: {r['share_real']:.0%} das URLs do DarkSherlock + {r['manual_only'][0]:.0%}–"
          f"{r['manual_only'][1]:.0%} só manuais; recolhidas {r['collected']['evid'][0]}–{r['collected']['evid'][1]} "
          "com evidência e 0 sem evidência.",
          f"- Relevância latente: {pr['base']} + {pr['ds_top20']} (Top-20 do DarkSherlock) + {pr['manual_sel']} "
          f"(selecionada à mão); {pr['sem']} nos cenários sem evidência; {r['p_inaccessible']:.0%} inacessíveis; "
          f"revisor B concorda com A em {r['agree_b']:.0%}.",
          "- Likert (média, DP " + str(r["likert_sd"]) + "): " + "; ".join(
              f"{c}: " + ", ".join(f"{k} {v}" for k, v in m.items()) for c, m in r["likert"].items()) + ".",
          "- Citação válida: " + "; ".join(f"{c} {v[1]:.0%} de {v[0][0]}–{v[0][1]} afirmações"
                                           for c, v in r["citations"].items()) + ".\n"]
    return L


def write_readme(out: Path, runner: Runner, args, problems: list[str], missing: set[str]) -> None:
    realista = getattr(args, "perfil", "aleatorio") == "realista"
    if realista:
        head = ["# Ensaio técnico — perfil realista\n",
                "Baseline manual, rótulos e pontuações dos revisores são **simulados** com os pressupostos abaixo. "
                "Os valores são plausíveis mas inventados: servem para ver como o capítulo se lê e não podem entrar "
                "na tese.\n"]
    else:
        head = [f"> {WATERMARK}\n", "# Ensaio técnico das análises humanas\n",
                "Baseline manual, rótulos e pontuações dos revisores são **aleatórios**. Os números das tabelas não "
                "têm significado: o ensaio serve para ver o formato final e apanhar erros antes da recolha real.\n"]
    L = [*head,
         f"- Gerado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
         f"- Modelo das execuções: `{args.model}` · desde {args.since} · semente {args.seed}",
         f"- Investigações lidas (só leitura): `{args.investigations}`\n",
         *(_assumptions() if realista else []),
         "## Passos\n", "| # | Passo | Estado | Tempo (s) | Log |", "|---|---|---|---|---|"]
    for i, s in enumerate(runner.steps, 1):
        log = Path(s["log"]).relative_to(out) if s["log"] else "—"
        L.append(f"| {i} | {s['name']} | {s['status']} | {s['seconds']} | {log} |")
    L.append("\n## Problemas e avisos\n")
    if problems:
        L.extend(f"- {p}" for p in problems)
    warned = [(s["name"], w) for s in runner.steps for w in _log_warnings(s, missing)]
    if warned:
        L.extend(f"- [{name}] {w}" for name, w in warned)
    if not problems and not warned:
        L.append("- Nenhum.")
    L.append("\n## Resultados (simulados)\n" if realista else "\n## Resultados (fictícios)\n")
    for rel in ("eq01_tabela13.md", "eq02_eq03/eq02_eq03_summary.md", "true_negatives.md", "eq04/eq04_summary.md",
                "ground_truth/llm_judge/llm_judge_summary.md"):
        if (out / rel).is_file():
            L.append(f"- `{rel}`")
    for p in sorted(out.glob("SIMULADO_Cap6_*.docx")):
        L.append(f"- `{p.name}` (rascunho Word do Capítulo 6, com rodapé de dados simulados)")
    if realista:
        L.append(f"\n---\n\n{FOOTER}")
    (out / "LEIA-ME.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="Etiqueta exata do modelo das execuções do DarkSherlock.")
    ap.add_argument("--since", default="00000000", help="Só execuções com data de ficheiro >= AAAAMMDD.")
    ap.add_argument("--pipeline-version", default=None, help="Passa a --pipeline-version aos scripts de análise.")
    ap.add_argument("--investigations", default=str(ROOT / "investigations"), help="Pasta das investigações reais.")
    ap.add_argument("--raw", default=str(HERE / "results" / "raw_runs_*.csv"), help="CSVs do run_scenarios (Tabela 13).")
    ap.add_argument("--out", default=None, help="Pasta de saída (default: evaluation/ensaio/ENSAIO_FICTICIO_<data>).")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--perfil", choices=("aleatorio", "realista"), default="aleatorio",
                    help="aleatorio: valores uniformes com marca d'água; realista: valores plausíveis (REALISTA), "
                         "com rodapé de dados simulados (default: aleatorio).")
    ap.add_argument("--with-llm-judge", action="store_true", help="Corre também o llm_judge.py sobre as folhas fictícias.")
    ap.add_argument("--judge-model", default=None, help="Modelo do juiz (default: --model; de preferência outro).")
    ap.add_argument("--judge-limit", type=int, default=5,
                    help="No ensaio, o juiz só avalia as primeiras N fontes por cenário e N relatórios (default: 5).")
    args = ap.parse_args(argv)

    prefix = "SIMULADO_REALISTA" if args.perfil == "realista" else "ENSAIO_FICTICIO"
    out = Path(args.out) if args.out else ENSAIO_ROOT / f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    problem = out_dir_problem(out)
    if problem:
        print(f"ERRO: {problem}")
        return 2
    if out.exists() and any(out.iterdir()):
        print(f"ERRO: {out} já existe e não está vazia; escolhe outra pasta.")
        return 2
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    inv_glob = str(Path(args.investigations) / "eval_*.json")
    problems: list[str] = []

    try:
        chosen = eq04_review.pick_darksherlock_runs(inv_glob, args.model, args.since, "first", args.pipeline_version)
    except ValueError as e:
        print(f"ERRO: {e}")
        return 2
    chosen = {sc: c for sc, c in chosen.items() if "search_results" in c["data"]}
    if not chosen:
        print(f"ERRO: nenhuma investigação de {args.model!r} desde {args.since} com 'search_results' em {inv_glob}.")
        return 1
    missing = [sc for sc in eq04_review.SCENARIO_IDS if sc not in chosen]
    if missing:
        problems.append(f"Cenários sem execuções utilizáveis do modelo (ficam fora do ensaio): {', '.join(missing)}.")
    no_evidence = set()
    for sc, c in sorted(chosen.items()):
        summary, _ = eq04_review.strip_darksherlock_banners(c["data"].get("summary", ""))
        if eq04_review.is_no_evidence(summary):
            no_evidence.add(sc)
            problems.append(f"{sc}: o relatório do DarkSherlock escolhido para a EQ-04 é um relatório sem evidência "
                            "— excluído da EQ-04 (--exclude-no-evidence) e analisado em true_negatives.md.")

    print(f"Ensaio técnico ({'dados simulados, perfil realista' if args.perfil == 'realista' else 'DADOS FICTÍCIOS'}) em {out}")
    print(f"Cenários com execuções: {', '.join(sorted(chosen))}\n")
    base = out / "baseline_manual"
    write_fake_baseline(base, chosen, rng, args.perfil, no_evidence)
    runner = Runner(out)
    runner.note("baseline_ficticio", f"OK ({len(chosen)} cenários)")
    filters = _filters(args)

    runner.run("tabela13", [str(HERE / "tabela13.py"), *filters, "--raw", args.raw, "--investigations",
                            args.investigations, "--timing-log", str(base / "timing_log.csv"),
                            "--out", str(out / "eq01_tabela13.md")])

    gt = out / "ground_truth"
    built = []
    for sc in sorted(chosen):
        code = runner.run(f"eq02_build_{sc}", [str(HERE / "eq02_eq03.py"), "build", "--scenario", sc,
                                                "--darksherlock", str(Path(args.investigations) / f"eval_{sc}_*.json"),
                                                "--manual", str(base / "reports" / f"manual_sources_{sc}.csv"),
                                                "--out", str(gt), "--seed", str(args.seed), *filters])
        if code == 0:
            fill_pool_reviews(gt, sc, rng, args.perfil, sc in no_evidence)
            built.append(sc)
    if built:
        runner.run("eq02_eq03_analyze", [str(HERE / "eq02_eq03.py"), "analyze", "--ground-truth", str(gt),
                                         "--investigations", inv_glob, "--manual-dir", str(base / "reports"),
                                         "--scenarios", ",".join(built), "--out", str(out / "eq02_eq03"), *filters])
    runner.run("true_negatives", [str(HERE / "true_negatives.py"), "--investigations", inv_glob, *filters,
                                  "--manual-dir", str(base), "--ground-truth", str(gt),
                                  "--out", str(out / "true_negatives.md")])

    eq04 = out / "eq04"
    if runner.run("eq04_build", [str(HERE / "eq04_review.py"), "build", "--investigations", inv_glob, *filters,
                                 "--manual-dir", str(base), "--out", str(eq04), "--seed", str(args.seed),
                                 "--allow-incomplete", "--exclude-no-evidence"]) == 0:
        fill_eq04_scores(eq04, rng, args.perfil)
        analyze = [str(HERE / "eq04_review.py"), "analyze", "--out", str(eq04)]
        if runner.run("eq04_analyze_1", analyze, ok_codes=(0, 1)) == 1:
            n = fill_reconciliation(eq04)
            runner.note("eq04_reconciliacao", f"OK ({n} divergências)")
            runner.run("eq04_analyze_2", analyze)

    if args.with_llm_judge:
        judge = args.judge_model or args.model
        if judge == args.model:
            problems.append("O juiz LLM usou o mesmo modelo que gerou os relatórios (viés de auto-preferência); "
                            "na análise real usa outro com --judge-model.")
        jargs = ["--model", judge, "--limit", str(args.judge_limit)]
        if built:
            runner.run("llm_judge_eq0203", [str(HERE / "llm_judge.py"), "eq0203", "--ground-truth", str(gt),
                                            "--investigations", inv_glob, "--scenarios", ",".join(built), *jargs])
        if (eq04 / "reviewer_A").is_dir():
            runner.run("llm_judge_eq04", [str(HERE / "llm_judge.py"), "eq04", "--out", str(eq04), *jargs])
        runner.run("llm_judge_compare", [str(HERE / "llm_judge.py"), "compare", "--ground-truth", str(gt),
                                         "--eq04-out", str(eq04)])

    runner.run("rascunho_cap6", [str(HERE / "rascunho_cap6.py"), "--ensaio", str(out)])
    n = _watermark(out, args.perfil)
    write_readme(out, runner, args, problems, set(missing))
    failed = [s for s in runner.steps if not s["status"].startswith("OK")]
    what = "Rodapé de dados simulados aplicado" if args.perfil == "realista" else "Marca d'água aplicada"
    print(f"\n{what} a {n} ficheiro(s). Resumo: {out / 'LEIA-ME.md'}")
    if problems:
        print(f"{len(problems)} problema(s) assinalado(s) no LEIA-ME.md.")
    print("FALHOU: " + ", ".join(s["name"] for s in failed) if failed else "Todos os passos correram.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
