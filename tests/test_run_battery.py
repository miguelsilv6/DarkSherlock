"""evaluation/run_battery.py — plano, verificações do preflight e seleção dos ficheiros da bateria."""

import json
import os
import time

import pytest

import local_models
import run_battery as rb

PHI = "Phi-3.5-mini (embutido, médio)"
QWEN = "Qwen2.5-0.5B (embutido, ultraleve)"


def _scenarios(tmp_path, monkeypatch, *, fill=True):
    rows = [{"id": "A1", "domain": "Threat Intel", "preset": "threat_intel", "query": "lockbit leak site",
             "label": "Grupo-R1"},
            {"id": "C1", "domain": "Identidade Pessoal", "preset": "personal_identity",
             "query": "eu@exemplo.pt" if fill else "PREENCHER: o teu email", "label": "Investigador-I1"}]
    f = tmp_path / "scenarios.local.json"
    f.write_text(json.dumps({"scenarios": rows}), encoding="utf-8")
    monkeypatch.setenv("DARKSHERLOCK_SCENARIOS_FILE", str(f))


@pytest.fixture
def models(monkeypatch):
    monkeypatch.setattr(local_models, "is_downloaded", lambda k: k in {PHI, QWEN})
    monkeypatch.setattr(local_models, "_ENV_DEFAULT_MODEL", "")


def _battery(tmp_path, *argv):
    b = rb.Battery(rb.parse_args(list(argv)), root=tmp_path)
    b.check_scenarios()
    b.check_models()
    return b


def test_plan_uses_real_scenarios_and_downloaded_models(tmp_path, monkeypatch, models):
    _scenarios(tmp_path, monkeypatch)
    b = _battery(tmp_path, "--dry-run")
    assert not b.problems and b.source == "local"
    assert b.main_model == PHI and b.models == [PHI, QWEN]
    cmds = {s.name: s.cmd for s in b.build("collect")}
    assert cmds["run_scenarios"][-4:] == ["--runs", "3", "--model", PHI]
    assert cmds["multi_model"][cmds["multi_model"].index("--models") + 1] == f"{PHI};{QWEN}"
    assert cmds["induced_resilience"][-2:] == ["--scenarios", "A1"]
    analyze = {s.name: s for s in b.build("analyze")}
    assert analyze["check_runs"].cmd[-8:] == ["--since", b.since, "--pipeline-version", rb.PIPELINE_VERSION,
                                              "--run-kind", "scenarios", "--expected", "3"]
    assert analyze["stage5_report"].cmd[-1].endswith("stage5_report.md")
    assert "desta bateria>" in analyze["forensics_integrity"].cmd[-1]


def test_unfilled_and_synthetic_scenarios_are_refused(tmp_path, monkeypatch, models):
    _scenarios(tmp_path, monkeypatch, fill=False)
    b = _battery(tmp_path)
    assert any("C1" in p and "PREENCHER" in p for p in b.problems)
    monkeypatch.setenv("DARKSHERLOCK_SCENARIOS_FILE", str(tmp_path / "nao_existe.json"))
    assert any("dados reais" in p for p in _battery(tmp_path).problems)
    assert not _battery(tmp_path, "--allow-synthetic").problems


def test_manual_baseline_steps_are_pending_until_files_exist(tmp_path, monkeypatch, models):
    _scenarios(tmp_path, monkeypatch)
    steps = {s.name: s for s in _battery(tmp_path, "--phases", "analyze").build("analyze")}
    for name in ("tabela13", "eq02_build_A1", "eq04_build"):
        assert steps[name].cmd is None and steps[name].status == "pendente" and steps[name].pending
    reports = tmp_path / "evaluation" / "baseline_manual" / "reports"
    reports.mkdir(parents=True)
    (reports.parent / "timing_log.csv").write_text("x", encoding="utf-8")
    (reports / "manual_sources_A1.csv").write_text("x", encoding="utf-8")
    for sid in ("A1", "C1"):
        (reports / f"report_{sid}.md").write_text("x", encoding="utf-8")
    steps = {s.name: s for s in _battery(tmp_path, "--phases", "analyze").build("analyze")}
    assert all(steps[n].cmd for n in ("tabela13", "eq02_build_A1", "eq04_build"))
    assert steps["eq02_build_C1"].cmd is None


def test_skip_and_unknown_phase(tmp_path, monkeypatch, models):
    _scenarios(tmp_path, monkeypatch)
    steps = {s.name: s for s in _battery(tmp_path, "--skip", "multi_model").build("collect")}
    assert steps["multi_model"].cmd is None and "saltada" in steps["multi_model"].status
    with pytest.raises(SystemExit):
        _ = _battery(tmp_path, "--phases", "colect").phases


def test_new_files_are_only_this_battery(tmp_path, monkeypatch, models):
    _scenarios(tmp_path, monkeypatch)
    inv = tmp_path / "investigations"
    inv.mkdir()
    old, new = inv / "eval_A1_old.json", inv / "eval_A1_new.json"
    old.write_text("{}"), new.write_text("{}")
    past = time.time() - 86400 * 3
    os.utime(old, (past, past))
    b = _battery(tmp_path)
    b.t0 = time.time() - 60
    assert b.new_files("investigations/eval_*.json") == [str(new)]


def test_run_step_logs_and_readme(tmp_path, monkeypatch, models):
    _scenarios(tmp_path, monkeypatch)
    b = _battery(tmp_path, "--quiet")
    ok = rb.Step("ok", "analyze", "Passa.", [rb.PY, "-c", "print('olá')"])
    bad = rb.Step("bad", "analyze", "Falha.", [rb.PY, "-c", "import sys; sys.exit(3)"])
    pend = rb.Step("pend", "analyze", "Manual.", None, pending="falta X", status="pendente")
    for s in (ok, bad, pend):
        b.steps.append(s)
        b.run_step(s)
    assert ok.status == "ok" and bad.status == "falhou (código 3)" and pend.status == "pendente"
    assert "olá" in (b.out / ok.log).read_text(encoding="utf-8")
    readme = b.write_readme().read_text(encoding="utf-8")
    assert "| bad | analyze | falhou (código 3) |" in readme and "**pend** — Manual. Falta: falta X." in readme
    assert "lockbit" not in readme.lower()  # só IDs e pseudónimos, nunca as queries


def test_dry_run_main(tmp_path, monkeypatch, models, capsys):
    _scenarios(tmp_path, monkeypatch)
    import pipeline
    monkeypatch.setattr(pipeline, "tor_available", lambda *a, **k: True)
    assert rb.main(["--dry-run", "--no-tests"]) == 0
    out = capsys.readouterr().out
    assert "[collect] run_scenarios" in out and "[redact] redact_check" in out
    assert "lockbit" not in out.lower()


def test_shell_wrapper_syntax():
    import subprocess
    sh = rb.ROOT / "evaluation" / "run_battery.sh"
    assert os.access(sh, os.X_OK)
    assert subprocess.run(["bash", "-n", str(sh)]).returncode == 0


def test_sigterm_writes_readme_with_interrupted_step(tmp_path):
    """`run_battery.sh stop` envia SIGTERM: a etapa em curso fica "interrompida" e o README é escrito."""
    import signal
    import subprocess
    import sys
    script = tmp_path / "term.py"
    script.write_text(f"""
import sys; sys.path[:0] = [{str(rb.HERE)!r}, {str(rb.ROOT)!r}]
import run_battery as rb
from pathlib import Path
rb.Battery.build = lambda self, phase: [rb.Step("longa", phase, "Dorme.", [rb.PY, "-c", "import time; time.sleep(60)"])]
rb.Battery.check_models = lambda self: setattr(self, "main_model", "m")
rb.Battery.check_environment = lambda self: None
_init = rb.Battery.__init__
def init(self, args, root=rb.ROOT):
    _init(self, args, root=Path({str(tmp_path)!r}))
rb.Battery.__init__ = init
sys.exit(rb.main(["--phases", "analyze", "--allow-synthetic", "--no-tests", "--quiet"]))
""", encoding="utf-8")
    proc = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(100):
        time.sleep(0.1)
        logs = list(tmp_path.glob("evaluation/results/battery_*/01_longa.log"))
        if logs:
            break
    proc.send_signal(signal.SIGTERM)
    out, _ = proc.communicate(timeout=30)
    assert proc.returncode == 1, out
    readme = next(tmp_path.glob("evaluation/results/battery_*/README.md")).read_text(encoding="utf-8")
    assert "| longa | analyze | interrompida |" in readme


def test_synthetic_mode_leaves_local_file_alone(tmp_path, monkeypatch, models):
    _scenarios(tmp_path, monkeypatch)          # há um scenarios.local.json real
    monkeypatch.setenv("DARKSHERLOCK_SCENARIOS", "")
    b = _battery(tmp_path, "--synthetic")
    assert os.environ["DARKSHERLOCK_SCENARIOS"] == "synthetic"
    assert not b.problems and b.source == "synthetic" and len(b.scenarios) == 12
    assert "forçados com --synthetic" in b.plan_text()
    local = rb.scenarios_mod.local_path()
    assert rb.scenarios_mod.load(local)[1] == "local"            # caminho explícito: o ficheiro real
    redact = {s.name: s.cmd for s in b.build("redact")}
    for name in ("redact", "redact_check"):
        assert redact[name][-2:] == ["--scenarios", str(local)]  # rasura sempre com as regras reais


def test_missing_local_file_with_backup_suggests_restore(tmp_path, monkeypatch, models):
    monkeypatch.setenv("DARKSHERLOCK_SCENARIOS", "")
    local = tmp_path / "scenarios.local.json"
    (tmp_path / "scenarios.local.json.bak").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("DARKSHERLOCK_SCENARIOS_FILE", str(local))
    [problem] = [p for p in _battery(tmp_path).problems if "scenarios.local.json" in p]
    assert "mv " in problem and "--synthetic" in problem


def test_every_analyze_step_is_accepted_by_its_script(tmp_path, monkeypatch, models):
    """Cada script de análise aceita os argumentos que a bateria lhe passa (tabela13 rejeitava --run-kind)."""
    import subprocess
    _scenarios(tmp_path, monkeypatch)
    reports = tmp_path / "evaluation" / "baseline_manual" / "reports"
    reports.mkdir(parents=True)
    (reports.parent / "timing_log.csv").write_text("scenario_id,stage,duration_s\n", encoding="utf-8")
    (reports / "manual_sources_A1.csv").write_text("url,title,engine,selected\n", encoding="utf-8")
    for sid in ("A1", "C1"):
        (reports / f"report_{sid}.md").write_text("x", encoding="utf-8")
    b = _battery(tmp_path, "--phases", "analyze")
    b.out.mkdir(parents=True)
    monkeypatch.setattr(b, "_has_legacy_runs", lambda: True)
    steps = [s for s in b.build("analyze") if s.cmd]
    assert {"tabela13", "compare_pipelines", "eq02_build_A1", "eq04_build", "stage5_report"} <= {s.name for s in steps}
    for s in steps:
        r = subprocess.run([str(c) for c in s.cmd], capture_output=True, text=True, cwd=rb.ROOT, timeout=120)
        assert "unrecognized arguments" not in r.stderr and "invalid choice" not in r.stderr, (s.name, r.stderr)
        assert "the following arguments are required" not in r.stderr, (s.name, r.stderr)
