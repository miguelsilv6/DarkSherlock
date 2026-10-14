"""
evaluation/run_battery.py — Bateria completa de testes do Capítulo 6, com os
cenários reais (casos públicos) de evaluation/scenarios.local.json.

Corre, por ordem e sem intervenção, os scripts de avaliação que já existem
(não duplica lógica: cada etapa é o script respetivo, num subprocesso) e
junta tudo numa pasta da bateria, evaluation/results/battery_<AAAAMMDD_HHMMSS>/:
um log por etapa e um README.md com o estado de cada uma e o que falta fazer
à mão.

Fases:
  preflight  testes unitários (pytest), cenários reais válidos e sem campos
             por preencher, Tor, modelos descarregados, hook pre-commit, disco.
  collect    (Tor, horas) run_scenarios (EQ-01/02/03/05/06, 3x por cenário,
             modelo principal), run_multi_model_eval (fiabilidade por modelo),
             run_refusal_ablation (EQ-07), run_induced_resilience (EQ-06).
  analyze    (offline) check_runs, pool_preview, analyze_resilience,
             analyze_engine_failures, analyze_refusal_ablation,
             verify_forensics (EQ-05), tabela13 (EQ-01, se houver baseline
             manual), compare_pipelines (se houver execuções 1.0-legacy),
             eq02_eq03 build e eq04_review build (se houver baseline manual).
  redact     rasura (redact.py) de tudo o que esta bateria produziu para
             evaluation/redacted/battery_<...>/ e verificação (--check).

O que não se automatiza (baseline manual, revisores de EQ-02/03/04) fica
listado no README.md da bateria, como "pendente".

Os casos públicos estão em evaluation/scenarios.public.json (versionado, com
C1/C3 por preencher); a cópia de trabalho, com os dados do investigador, é
evaluation/scenarios.local.json, fora do Git, tal como investigations/ e
evaluation/results/. No terminal e nos logs desta bateria só aparecem os IDs
e os pseudónimos dos cenários.

Uso:
    ./evaluation/run_battery.sh --dry-run               # mostra o plano, não corre nada
    ./evaluation/run_battery.sh                         # corrida longa, em segundo plano: sobrevive
                                                        # ao fecho do terminal e bloqueia a suspensão
    ./evaluation/run_battery.sh status | log | stop     # acompanhar ou parar
    .venv/bin/python evaluation/run_battery.py --yes    # o mesmo, em primeiro plano
    ./evaluation/run_battery.sh --phases analyze,redact --since 20261012
    ./evaluation/run_battery.sh --scenarios A1,B2 --runs 1 --multi-runs 1     # ensaio curto
    ./evaluation/run_battery.sh --synthetic --skip multi_model,refusal_ablation,induced_resilience
                                    # sintéticos em 2.x, para comparar com 1.0 (as mesmas queries)

Opções úteis: --main-model "<label>", --models "<label1>;<label2>" (separados
por ';'), --skip multi_model,refusal_ablation, --no-tests.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for _p in (ROOT, HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    import scenarios as scenarios_mod  # noqa: E402
    import versions  # noqa: E402
    from config import PIPELINE_VERSION  # noqa: E402
except ModuleNotFoundError as _e:  # Python do sistema em vez do .venv
    sys.exit(f"ERRO: falta o módulo '{_e.name}'. Corre com o Python do virtualenv: "
             ".venv/bin/python evaluation/run_battery.py ... (ou ./evaluation/run_battery.sh, "
             "que também sobrevive ao fecho do terminal).")

PY = sys.executable
PHASES = ("preflight", "collect", "analyze", "redact")
PLACEHOLDER = "PREENCHER"
MIN_FREE_GB = 5


@dataclass
class Step:
    name: str
    phase: str
    what: str
    cmd: list | None = None
    pending: str = ""          # não corre: falta algo (normalmente trabalho manual)
    fatal: bool = False        # se falhar, a bateria para
    status: str = "por correr"
    seconds: float = 0.0
    log: str = ""


class Battery:
    def __init__(self, args, root: Path = ROOT):
        self.args = args
        self.root = root
        self.started = datetime.now()
        self.t0 = time.time()
        self.stamp = self.started.strftime("%Y%m%d_%H%M%S")
        self.since = args.since or self.started.strftime("%Y%m%d")
        self.investigations = root / "investigations"
        self.results = root / "evaluation" / "results"
        self.manual = root / "evaluation" / "baseline_manual"
        self.out = self.results / f"battery_{self.stamp}"
        self.redacted = root / "evaluation" / "redacted" / f"battery_{self.stamp}"
        self.steps: list[Step] = []
        self.problems: list[str] = []      # do preflight: impedem a bateria
        self.notes: list[str] = []         # do preflight: avisos
        self.scenarios, self.source = [], "?"
        self.main_model, self.models = args.main_model, []
        if args.synthetic:  # herdado por todas as etapas (subprocessos): ver scenarios.load()
            os.environ["DARKSHERLOCK_SCENARIOS"] = "synthetic"

    # ------------------------------------------------------------------ preflight
    def check_scenarios(self) -> None:
        try:
            scs, self.source = scenarios_mod.load()
        except (ValueError, json.JSONDecodeError) as e:
            self.problems.append(f"Cenários inválidos: {e}")
            return
        local = scenarios_mod.local_path()
        backup = local.with_name(local.name + ".bak")
        if self.source != "local" and not (self.args.allow_synthetic or self.args.synthetic):
            if backup.is_file():
                self.problems.append(f"Não há {local}, mas existe {backup.name}: repõe-no com "
                                     f"`mv {backup} {local}`. Para correr os cenários sintéticos sem mexer nele, "
                                     "usa --synthetic.")
            else:
                self.problems.append(f"Não há {local}: a bateria usa dados reais. Copia os casos públicos "
                                     "(cp evaluation/scenarios.public.json evaluation/scenarios.local.json) e "
                                     "preenche C1/C3, ou usa --synthetic para correr os cenários sintéticos.")
        if self.args.scenarios:
            wanted = {s.strip().upper() for s in self.args.scenarios.split(",")}
            scs = [s for s in scs if s["id"] in wanted]
        unfilled = [s["id"] for s in scs if PLACEHOLDER in json.dumps(s, ensure_ascii=False)]
        if unfilled:
            self.problems.append(f"Cenários por preencher ({', '.join(unfilled)}): substitui os campos "
                                 f"\"{PLACEHOLDER}…\" em {scenarios_mod.local_path()} pelos teus próprios dados.")
        missing = [i for i in scenarios_mod.IDS if i not in {s["id"] for s in scs}]
        if missing and not self.args.scenarios:
            self.notes.append(f"Cenários em falta no ficheiro (não correm): {', '.join(missing)}.")
        self.scenarios = scs

    def check_models(self) -> None:
        try:
            import local_models
            downloaded = [k for k in local_models.BUILTIN_MODELS if local_models.is_downloaded(k)]
            preferred = local_models.preferred_default_model()
        except Exception as e:  # noqa: BLE001
            downloaded, preferred = [], None
            self.notes.append(f"Não foi possível ver os modelos embutidos ({e}).")
        if not self.main_model:
            self.main_model = preferred if preferred in downloaded else (downloaded[-1] if downloaded else None)
        if self.args.models:
            self.models = [m.strip() for m in self.args.models.split(";") if m.strip()]
        else:
            self.models = downloaded
        if self.main_model:  # o principal primeiro
            self.models = [self.main_model] + [x for x in self.models if x != self.main_model]
        if not self.main_model:
            self.problems.append("Nenhum modelo descarregado: escolhe um com --main-model ou descarrega-o na app.")

    def check_environment(self) -> None:
        try:
            import pipeline
            if not pipeline.tor_available():
                msg = "Tor não responde em 127.0.0.1:9050."
                (self.problems if "collect" in self.phases else self.notes).append(msg)
        except Exception as e:  # noqa: BLE001
            self.notes.append(f"Não foi possível verificar o Tor ({e}).")
        hooks = subprocess.run(["git", "config", "core.hooksPath"], cwd=self.root,
                               capture_output=True, text=True).stdout.strip()
        if hooks != ".githooks":
            self.notes.append("O hook pre-commit não está ativo: corre `git config core.hooksPath .githooks`.")
        free_gb = shutil.disk_usage(self.root).free / 1e9
        if free_gb < MIN_FREE_GB:
            self.notes.append(f"Só {free_gb:.1f} GB livres em disco (recomendado ≥ {MIN_FREE_GB} GB).")

    @property
    def phases(self) -> list[str]:
        wanted = [p.strip() for p in (self.args.phases or ",".join(PHASES)).split(",") if p.strip()]
        bad = [p for p in wanted if p not in PHASES]
        if bad:
            raise SystemExit(f"Fases desconhecidas: {', '.join(bad)} (usa {', '.join(PHASES)}).")
        return [p for p in PHASES if p in wanted]

    # ------------------------------------------------------------------ etapas
    def _py(self, script: str, *args) -> list:
        return [PY, str(HERE / script), *[str(a) for a in args]]

    def _ids(self) -> list:
        return ["--scenarios", ",".join(s["id"] for s in self.scenarios)] if self.args.scenarios else []

    def new_files(self, pattern: str) -> list[str]:
        """Ficheiros criados ou alterados durante esta bateria (ou desde --since, se só se analisa)."""
        if self.args.dry_run and "collect" in self.phases:
            return [f"<{pattern} desta bateria>"]   # o plano, antes de a recolha os criar
        if "collect" in self.phases:
            cutoff = self.t0
        else:
            cutoff = datetime.strptime(self.since, "%Y%m%d").timestamp()
        return sorted(f for f in glob.glob(str(self.root / pattern)) if os.path.getmtime(f) >= cutoff)

    def preflight_steps(self) -> list[Step]:
        if self.args.no_tests:
            return []
        return [Step("unit_tests", "preflight", "Testes unitários da aplicação (pytest).",
                     [PY, "-m", "pytest", "-q"], fatal=True)]

    def collect_steps(self) -> list[Step]:
        m, models = self.main_model, ";".join(self.models)
        ids = {s["id"] for s in self.scenarios}
        induced = [i for i in ("A1", "B2", "C3") if i in ids] or sorted(ids)[:1]
        return [
            Step("run_scenarios", "collect",
                 f"EQ-01/02/03/05/06 — {len(ids)} cenários × {self.args.runs} execuções com o modelo principal.",
                 self._py("run_scenarios.py", "--runs", self.args.runs, "--model", m, *self._ids())),
            Step("multi_model", "collect",
                 f"Fiabilidade por modelo — {len(self.models)} modelo(s) × {self.args.multi_runs} execuções.",
                 self._py("run_multi_model_eval.py", "--models", models, "--runs", self.args.multi_runs,
                          *self._ids())),
            Step("refusal_ablation", "collect", "EQ-07 — 4 variantes de prompt por cenário e modelo.",
                 self._py("run_refusal_ablation.py", "--models", models, *self._ids())),
            Step("induced_resilience", "collect", f"EQ-06 — motor desativado à força ({', '.join(induced)}).",
                 self._py("run_induced_resilience.py", "--model", m, "--scenarios", ",".join(induced))),
        ]

    def analyze_steps(self) -> list[Step]:
        m, v, since = self.main_model, PIPELINE_VERSION, self.since
        # Só as execuções do protocolo (run_scenarios): sem as de multi-modelo nem as de falha induzida.
        sel = ["--model", m, "--since", since, "--pipeline-version", v, "--run-kind", "scenarios"]
        evals = self.new_files("investigations/eval_*.json")
        run_csvs = self.new_files("evaluation/results/raw_runs_*.csv") + \
            self.new_files("evaluation/results/multi_model_runs_*.csv")
        ablation = self.new_files("evaluation/results/refusal_ablation_*.csv")
        steps = [
            Step("check_runs", "analyze", "Execuções gravadas por cenário (esperado: --runs).",
                 self._py("check_runs.py", *sel, "--expected", self.args.runs)),
            Step("pool_preview", "analyze", "EQ-02 — pool e estabilidade da pesquisa (só DarkSherlock).",
                 self._py("pool_preview.py", *sel)),
            Step("stage5_report", "analyze", "Etapa 5 por cenário: verdadeiro negativo, recolha ou critério de termos?",
                 self._py("stage5_report.py", *sel, "--out", self.out / "stage5_report.md")),
            Step("analyze_resilience", "analyze", "EQ-06 — taxa de scraping bem-sucedido.",
                 self._py("analyze_resilience.py", *run_csvs) if run_csvs else None,
                 pending="" if run_csvs else "sem CSVs de execuções desta bateria"),
            Step("engine_failures", "analyze", "EQ-06 — tolerância a motores caídos.",
                 self._py("analyze_engine_failures.py", "--audit-trail", self.root / "logs" / "audit.jsonl",
                          "--investigations", self.investigations / "eval_*.json")),
            Step("refusal_analysis", "analyze", "EQ-07 — Tabela 15 e teste de McNemar.",
                 self._py("analyze_refusal_ablation.py", *ablation) if ablation else None,
                 pending="" if ablation else "sem CSVs da ablação desta bateria"),
            Step("forensics_determinism", "analyze", "EQ-05.1 — determinismo do hash global.",
                 self._py("verify_forensics.py", "determinism", "--repeats", 5)),
            Step("forensics_integrity", "analyze", "EQ-05.2 — integridade SHA-256 por fonte.",
                 self._py("verify_forensics.py", "integrity", *evals) if evals else None,
                 pending="" if evals else "sem investigações desta bateria"),
            Step("forensics_audit", "analyze", "EQ-05.3 — completude do audit trail.",
                 self._py("verify_forensics.py", "audit-trail", self.root / "logs" / "audit.jsonl")),
        ]
        timing = self.manual / "timing_log.csv"
        steps.append(Step("tabela13", "analyze", "EQ-01 — Tabela 13 (DarkSherlock vs baseline manual).",
                          self._py("tabela13.py", *sel, "--runs", self.args.runs, "--out", self.out / "eq01_tabela13.md")
                          if timing.is_file() else None,
                          pending="" if timing.is_file() else
                          "falta o baseline manual cronometrado (evaluation/baseline_manual/timing_log.csv)"))
        legacy = self._has_legacy_runs()
        steps.append(Step("compare_pipelines", "analyze", f"Efeito da revisão do pipeline ({versions.LEGACY} → {v}).",
                          self._py("compare_pipelines.py", "compare", "--investigations",
                                   self.investigations / "eval_*.json", "--model", m, "--old", versions.LEGACY,
                                   "--new", v, "--run-kind", "scenarios", "--out", self.out / "compare_pipelines.md")
                          if legacy else None,
                          pending="" if legacy else f"sem execuções {versions.LEGACY} deste modelo para comparar"))
        reports = self.manual / "reports"
        for sc in self.scenarios:
            csv_path = reports / f"manual_sources_{sc['id']}.csv"
            steps.append(Step(f"eq02_build_{sc['id']}", "analyze", f"EQ-02/03 — pool e folhas de revisão de {sc['id']}.",
                              self._py("eq02_eq03.py", "build", "--scenario", sc["id"], "--darksherlock",
                                       self.investigations / f"eval_{sc['id']}_*.json", "--manual", csv_path, *sel)
                              if csv_path.is_file() else None,
                              pending="" if csv_path.is_file() else f"falta {csv_path.relative_to(self.root)} (baseline manual)"))
        missing_reports = [s["id"] for s in self.scenarios if not (reports / f"report_{s['id']}.md").is_file()]
        steps.append(Step("eq04_build", "analyze", "EQ-04 — relatórios anonimizados para a revisão cega.",
                          self._py("eq04_review.py", "build", "--investigations", self.investigations / "eval_*.json",
                                   *sel) if not missing_reports else None,
                          pending="" if not missing_reports else
                          f"faltam relatórios manuais ({', '.join(missing_reports)}) em baseline_manual/reports/"))
        return steps

    def redact_steps(self) -> list[Step]:
        produced = self.new_files("investigations/eval_*.json") + [
            f for f in self.new_files("evaluation/results/*") if Path(f).is_file()]
        sources = [str(self.out)] + produced
        # As regras dos termos reais vêm sempre do ficheiro local, se existir — também numa bateria --synthetic.
        local = scenarios_mod.local_path()
        rules = ["--scenarios", local] if local.is_file() else []
        return [
            Step("redact", "redact", "Rasura de tudo o que a bateria produziu.",
                 self._py("redact.py", *sources, "--out", self.redacted, *rules)),
            Step("redact_check", "redact", "Verificação: não pode restar nenhum termo real.",
                 self._py("redact.py", "--check", self.redacted, *rules)),
        ]

    def _has_legacy_runs(self) -> bool:
        for f in glob.glob(str(self.investigations / "eval_*.json")):
            try:
                inv = json.loads(Path(f).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if inv.get("model") == self.main_model and versions.version_of(inv) == versions.LEGACY:
                return True
        return False

    def build(self, phase: str) -> list[Step]:
        steps = getattr(self, f"{phase}_steps")()
        skip = {s.strip() for s in (self.args.skip or "").split(",") if s.strip()}
        for s in steps:
            if s.name in skip:
                s.cmd, s.pending, s.status = None, "", "saltada (--skip)"
            elif s.cmd is None:
                s.status = "pendente"
        return steps

    # ------------------------------------------------------------------ execução
    def run_step(self, step: Step) -> None:
        if step.cmd is None:
            return
        self.out.mkdir(parents=True, exist_ok=True)
        log = self.out / f"{len(self.steps):02d}_{step.name}.log"
        step.log = log.name
        print(f"\n▶ [{step.phase}] {step.name}: {step.what}", flush=True)
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        t = time.time()
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("$ " + " ".join(shlex.quote(str(c)) for c in step.cmd) + "\n\n")
            proc = subprocess.Popen([str(c) for c in step.cmd], cwd=self.root, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, errors="replace")
            try:
                for line in proc.stdout:
                    fh.write(line)
                    if not self.args.quiet:
                        print("   " + line, end="", flush=True)
                code = proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                proc.wait()
                step.seconds, step.status = time.time() - t, "interrompida"
                raise
        step.seconds = time.time() - t
        step.status = "ok" if code == 0 else f"falhou (código {code})"
        print(f"  → {step.status} em {_fmt_s(step.seconds)}", flush=True)

    def plan_text(self) -> str:
        n = len(self.scenarios)
        source = f"{self.source} (forçados com --synthetic)" if self.args.synthetic else self.source
        lines = [f"Bateria {self.stamp} — pipeline {PIPELINE_VERSION}, cenários {source} "
                 f"({', '.join(s['id'] for s in self.scenarios) or '-'})",
                 f"Modelo principal: {self.main_model or '-'}",
                 f"Modelos (multi-modelo e ablação): {'; '.join(self.models) or '-'}"]
        if "collect" in self.phases:
            lines.append(f"Investigações previstas: {n * self.args.runs} (principal) + "
                         f"{n * self.args.multi_runs * len(self.models)} (multi-modelo) + "
                         f"{n * len(self.models)} (ablação, 4 relatórios cada) + 3 (resiliência induzida). "
                         "Conta com várias horas.")
        return "\n".join(lines)

    def write_readme(self) -> Path:
        self.out.mkdir(parents=True, exist_ok=True)
        rows = ["| Etapa | Fase | Estado | Duração | Log |", "|---|---|---|---|---|"]
        for s in self.steps:
            rows.append(f"| {s.name} | {s.phase} | {s.status} | {_fmt_s(s.seconds) if s.seconds else '-'} | "
                        f"{s.log or '-'} |")
        pend = [f"- **{s.name}** — {s.what} Falta: {s.pending}." for s in self.steps if s.status == "pendente"]
        text = "\n".join([
            f"# Bateria de avaliação {self.stamp}", "",
            "```", self.plan_text(), "```", "",
            *(["## Avisos do preflight", ""] + [f"- {x}" for x in self.notes] + [""] if self.notes else []),
            "## Etapas", "", *rows, "",
            "## Pendente (trabalho manual)", "", *(pend or ["- Nada."]), "",
            "## Depois", "",
            "- Baseline manual: `evaluation/baseline_manual/README.md` (cronometragem, fontes e relatórios por cenário).",
            "- Com as folhas de revisão preenchidas: `eq02_eq03.py analyze` e `eq04_review.py analyze`.",
            f"- Para o relatório usa só `{self.redacted.relative_to(self.root)}` e lê o texto final antes de o colar.",
            f"- Volta a correr só a análise: `./evaluation/run_battery.sh --phases analyze,redact --since {self.since}`.",
            "",
        ])
        path = self.out / "README.md"
        path.write_text(text, encoding="utf-8")
        return path


def _fmt_s(s: float) -> str:
    s = int(s)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else (f"{m}m{sec:02d}s" if m else f"{sec}s")


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phases", default=None, help=f"Fases a correr, separadas por vírgula (default: {','.join(PHASES)}).")
    ap.add_argument("--skip", default=None, help="Etapas a saltar, por nome (ver --dry-run), separadas por vírgula.")
    ap.add_argument("--scenarios", default=None, help="Só estes IDs (ex.: A1,B2). Default: todos os do ficheiro.")
    ap.add_argument("--main-model", default=None, help="Modelo principal (label exata). Default: o maior descarregado.")
    ap.add_argument("--models", default=None, help="Modelos de multi-modelo e ablação, separados por ';'. "
                                                    "Default: todos os descarregados.")
    ap.add_argument("--runs", type=int, default=3, help="Execuções por cenário com o modelo principal (default: 3).")
    ap.add_argument("--multi-runs", type=int, default=5, help="Execuções por cenário e modelo em multi-modelo (default: 5).")
    ap.add_argument("--since", default=None, help="AAAAMMDD das execuções a analisar (default: hoje).")
    ap.add_argument("--no-tests", action="store_true", help="Não corre o pytest no preflight.")
    ap.add_argument("--allow-synthetic", action="store_true",
                    help="Aceita os cenários sintéticos quando não há ficheiro local (só para ensaios).")
    ap.add_argument("--synthetic", action="store_true",
                    help="Corre os 12 cenários sintéticos mesmo havendo scenarios.local.json, sem lhe mexer "
                         "(p. ex. para comparar 1.0 -> 2.x com as mesmas queries).")
    ap.add_argument("--dry-run", action="store_true", help="Mostra o plano e as verificações; não corre nada.")
    ap.add_argument("--yes", action="store_true", help="Não pede confirmação antes da recolha.")
    ap.add_argument("--quiet", action="store_true", help="Não repete no terminal o que vai para os logs.")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    b = Battery(args)
    phases = b.phases
    b.check_scenarios()
    b.check_models()
    b.check_environment()
    print(b.plan_text())
    for n in b.notes:
        print(f"AVISO: {n}")
    for p in b.problems:
        print(f"ERRO: {p}")

    if args.dry_run:
        for phase in phases:
            for s in b.build(phase):
                cmd = " ".join(shlex.quote(str(c)) for c in s.cmd) if s.cmd else f"[{s.status}] {s.pending}".rstrip()
                print(f"\n[{phase}] {s.name}: {s.what}\n    {cmd}")
        return 1 if b.problems else 0
    if b.problems:
        return 2

    if "collect" in phases and not args.yes:
        if not sys.stdin.isatty():
            print("ERRO: a recolha demora horas; confirma com --yes quando correres sem terminal (ex.: nohup).")
            return 2
        if input("\nComeçar a recolha? [s/N] ").strip().lower() not in ("s", "sim", "y", "yes"):
            return 1

    def _stop(signum, _frame):  # `run_battery.sh stop` (SIGTERM) termina como um Ctrl+C
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _stop)

    failed = False
    try:
        for phase in phases:
            for step in b.build(phase):
                b.steps.append(step)
                b.run_step(step)
                if step.status.startswith("falhou"):
                    failed = True
                    if step.fatal:
                        print(f"\nA etapa {step.name} falhou: a bateria para aqui (ver {b.out / step.log}).")
                        break
            else:
                continue
            break
    except KeyboardInterrupt:
        failed = True
        print("\nBateria interrompida: o resumo regista as etapas feitas até aqui.")
    readme = b.write_readme()
    print(f"\nResumo: {readme}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
