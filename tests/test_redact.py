"""PR 6 — cenários reais fora do Git e rasura antes do relatório (valores fictícios)."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import redact as R
import scenarios as S

ROOT = Path(__file__).resolve().parent.parent
ONION = "a" * 56 + ".onion"

LOCAL = {"scenarios": [
    {"id": "B1", "domain": "Ransomware/Malware", "preset": "ransomware_malware",
     "query": "grupoexemplo ransomware Empresa Exémplo", "label": "Vítima-V1",
     "redact": [{"term": "Empresa Exémplo", "label": "Vítima-V1"}, {"term": "grupoexemplo", "label": "Grupo-R1"}]},
    {"id": "C1", "domain": "Identidade Pessoal", "preset": "personal_identity",
     "query": "investigador.teste@example.invalid", "label": "Investigador-I1"},
    {"id": "C3", "domain": "Identidade Pessoal", "preset": "personal_identity",
     "query": "NIF 123456789", "label": "NIF-I1", "redact": ["123456789"]},
    {"id": "D1", "domain": "Espionagem Corporativa", "preset": "corporate_espionage",
     "query": "empresa-exemplo.invalid leak", "label": "Empresa-E1", "redact": ["empresa-exemplo.invalid"]},
]}


@pytest.fixture
def rules():
    return R.build_rules(LOCAL["scenarios"])


def test_terms_and_spelling_variants(rules):
    text = ("A EMPRESA EXEMPLO (empresa-exemplo, Empresa Exemplo) foi atacada pelo GrupoExemplo. "
            "Contacto: investigador.teste [at] example [dot] invalid e Investigador.Teste@Example.Invalid. "
            "NIF 123 456 789 / 123.456.789. Site: empresa-exemplo[.]invalid.")
    out = R.redact_text(text, rules)
    assert "[Vítima-V1]" in out and "[Grupo-R1]" in out and "[Investigador-I1]" in out
    assert "[NIF-I1]" in out and "[Empresa-E1]" in out
    low = re.sub(r"\[[^\]]+\]", " ", out).lower()  # sem os pseudónimos inseridos
    for leaked in ("empresa exemplo", "empresa-exemplo", "grupoexemplo", "investigador", "123", "example"):
        assert leaked not in low, leaked
    assert R.find_leftovers(out, rules) == []


def test_no_damage_to_unrelated_text(rules):
    text = "Hosted at site.com: o grupo publicou 12 ficheiros; IOC 10.0.0.5."
    assert R.redact_text(text, rules) == text


def test_onion_and_emails_hashed_consistently(rules):
    out1 = R.redact_text(f"http://{ONION}/x e terceiro@vitima.pt", rules)
    out2 = R.redact_text(f"mirror {ONION.upper()}", rules)
    code = R._sha8(ONION)
    assert f"[onion:{code}]" in out1 and f"[onion:{code}]" in out2
    assert "terceiro" not in out1 and "[email:" in out1
    assert "terceiro@vitima.pt" in R.redact_text("terceiro@vitima.pt", rules, emails=False)


def test_json_values_and_keys(rules):
    inv = {"query": "grupoexemplo ransomware Empresa Exémplo",
           "scraped_content": {f"http://{ONION}/p": "a Empresa Exemplo pagou"}}
    out = R.redact_obj(inv, rules)
    assert out["query"] == "[Grupo-R1] ransomware [Vítima-V1]"
    (key, val), = out["scraped_content"].items()
    assert ONION not in key and val == "a [Vítima-V1] pagou"


def test_default_terms_from_query_when_redact_missing():
    rules = R.build_rules([{"id": "A1", "domain": "x", "preset": "threat_intel",
                            "query": "grupoexemplo leak site", "label": "Grupo-R1"}])
    assert R.redact_text("o GrupoExemplo e o seu leak site", rules) == "o [Grupo-R1] e o seu leak site"


def test_check_cli_reports_without_revealing_term(tmp_path):
    local = tmp_path / "scenarios.local.json"
    local.write_text(json.dumps(LOCAL), encoding="utf-8")
    src = tmp_path / "in"
    src.mkdir()
    (src / "tabela.md").write_text("| B1 | Empresa Exemplo | ok |\n", encoding="utf-8")
    script = str(ROOT / "evaluation" / "redact.py")

    chk = subprocess.run([sys.executable, script, "--check", "--scenarios", str(local), str(src)],
                         capture_output=True, text=True)
    assert chk.returncode == 1 and "Vítima-V1" in chk.stdout
    assert "Empresa" not in chk.stdout and "exemplo" not in chk.stdout.lower()

    out = tmp_path / "out"
    red = subprocess.run([sys.executable, script, "--scenarios", str(local), "--out", str(out), str(src)],
                         capture_output=True, text=True)
    assert red.returncode == 0, red.stderr
    assert (out / "in" / "tabela.md").read_text(encoding="utf-8") == "| B1 | [Vítima-V1] | ok |\n"
    ok = subprocess.run([sys.executable, script, "--check", "--scenarios", str(local), str(out)],
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def test_check_staged_blocks_real_terms_and_forbidden_paths(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    local = tmp_path / "scenarios.local.json"
    local.write_text(json.dumps(LOCAL), encoding="utf-8")
    env = {**os.environ, "DARKSHERLOCK_SCENARIOS_FILE": str(local)}
    script = str(ROOT / "evaluation" / "redact.py")

    def staged_check():
        return subprocess.run([sys.executable, script, "--check-staged"], cwd=repo, env=env,
                              capture_output=True, text=True)

    (repo / "notas.md").write_text("tudo fictício\n", encoding="utf-8")
    _git(repo, "add", "notas.md")
    assert staged_check().returncode == 0

    (repo / "relatorio.md").write_text("vítima: Empresa Exemplo\n", encoding="utf-8")
    _git(repo, "add", "relatorio.md")
    r = staged_check()
    assert r.returncode == 1 and "relatorio.md" in r.stderr and "Empresa" not in r.stderr

    _git(repo, "reset", "-q", "relatorio.md")
    (repo / "investigations").mkdir()
    (repo / "investigations" / "x.json").write_text("{}", encoding="utf-8")
    _git(repo, "add", "-f", "investigations/x.json")
    r = staged_check()
    assert r.returncode == 1 and "investigations/x.json" in r.stderr


def test_scenarios_load_local_or_synthetic(tmp_path):
    sc, src = S.load(tmp_path / "missing.json")
    assert src == "synthetic" and [s["id"] for s in sc] == S.IDS
    p = tmp_path / "local.json"
    p.write_text(json.dumps(LOCAL), encoding="utf-8")
    sc, src = S.load(p)
    assert src == "local" and [s["id"] for s in sc] == ["B1", "C1", "C3", "D1"]
    bad = {"scenarios": [{"id": "Z9", "domain": "x", "preset": "nope", "query": ""}]}
    p.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError) as e:
        S.load(p)
    assert "id inválido" in str(e.value) and "preset inválido" in str(e.value) and "falta 'query'" in str(e.value)


def test_example_file_is_valid_and_fictitious():
    data = json.loads((ROOT / "evaluation" / "scenarios.example.json").read_text(encoding="utf-8"))
    assert S.validate(data["scenarios"]) == []
    blob = json.dumps(data)
    assert ".invalid" in blob and "exemplo" in blob  # só valores fictícios


def test_local_scenarios_file_is_gitignored():
    r = subprocess.run(["git", "check-ignore", "-q", "evaluation/scenarios.local.json"], cwd=ROOT)
    assert r.returncode == 0
