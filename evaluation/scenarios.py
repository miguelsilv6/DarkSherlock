"""
evaluation/scenarios.py — Cenários da avaliação (Capítulo 6): reais (locais) ou sintéticos.

A avaliação deve usar dados reais — casos públicos: grupos e vítimas já
noticiados ou anunciados em leak sites, fugas públicas, e dados do próprio
investigador no domínio Identidade —, rasurados no relatório. Esses dados
NUNCA entram no Git:

  - evaluation/scenarios.local.json   — cenários reais (no .gitignore; o
    caminho pode ser mudado com DARKSHERLOCK_SCENARIOS_FILE);
  - evaluation/scenarios.example.json — formato, com valores fictícios
    (versionado).

Se o ficheiro local existir, os cenários são os dele (os IDs A1–D3 que não
estiverem lá não correm); senão usam-se os 12 sintéticos da Tabela 12. Cada
investigação de avaliação grava "scenario_source" ("local"/"synthetic") e o
pseudónimo ("scenario_label"), para a análise e a rasura (redact.py).

Campos de cada cenário: id, domain, preset, query (obrigatórios); label
(pseudónimo usado na rasura, p. ex. "Vítima-V2"); redact (termos a rasurar,
strings ou {"term": ..., "label": ...}; se faltar, rasuram-se os termos-chave
da query); fonte_publica (onde o caso foi noticiado; só para o investigador).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCAL_FILE = HERE / "scenarios.local.json"
IDS = [f"{d}{n}" for d in "ABCD" for n in "123"]
PRESETS = {"threat_intel", "ransomware_malware", "personal_identity", "corporate_espionage"}

# Os 12 cenários sintéticos — Tabela 12 do relatório (query e preset tal como no Capítulo 6).
SYNTHETIC = [
    {"id": "A1", "domain": "Threat Intel",        "preset": "threat_intel",         "query": "lockbit leak site"},
    {"id": "A2", "domain": "Threat Intel",        "preset": "threat_intel",         "query": "credential dump forum 2026"},
    {"id": "A3", "domain": "Threat Intel",        "preset": "threat_intel",         "query": "bitcoin mixer service"},
    {"id": "B1", "domain": "Ransomware/Malware",  "preset": "ransomware_malware",   "query": "Akira ransomware"},
    {"id": "B2", "domain": "Ransomware/Malware",  "preset": "ransomware_malware",   "query": "cobalt strike beacon"},
    {"id": "B3", "domain": "Ransomware/Malware",  "preset": "ransomware_malware",   "query": "smokeloader access broker"},
    {"id": "C1", "domain": "Identidade Pessoal",  "preset": "personal_identity",    "query": "john.doe@example-corp.test breach"},
    {"id": "C2", "domain": "Identidade Pessoal",  "preset": "personal_identity",    "query": "example-corp.test data leak"},
    {"id": "C3", "domain": "Identidade Pessoal",  "preset": "personal_identity",    "query": "NIF 999999999 dark web"},
    {"id": "D1", "domain": "Espionagem Corporativa", "preset": "corporate_espionage", "query": "example-corp source code leak"},
    {"id": "D2", "domain": "Espionagem Corporativa", "preset": "corporate_espionage", "query": "example-corp API key dump"},
    {"id": "D3", "domain": "Espionagem Corporativa", "preset": "corporate_espionage", "query": "example-corp internal wiki dump"},
]


def local_path() -> Path:
    return Path(os.getenv("DARKSHERLOCK_SCENARIOS_FILE") or LOCAL_FILE)


def validate(scenarios: list) -> list:
    """Erros de formato (lista vazia se estiver tudo bem)."""
    errors, seen = [], set()
    for i, sc in enumerate(scenarios):
        where = sc.get("id") or f"#{i + 1}"
        for k in ("id", "domain", "preset", "query"):
            if not str(sc.get(k) or "").strip():
                errors.append(f"{where}: falta '{k}'")
        if sc.get("id") and sc["id"] not in IDS:
            errors.append(f"{where}: id inválido (usa {IDS[0]}–{IDS[-1]})")
        if sc.get("id") in seen:
            errors.append(f"{where}: id repetido")
        seen.add(sc.get("id"))
        if sc.get("preset") and sc["preset"] not in PRESETS:
            errors.append(f"{where}: preset inválido ({', '.join(sorted(PRESETS))})")
        if "redact" in sc and not isinstance(sc["redact"], list):
            errors.append(f"{where}: 'redact' tem de ser uma lista")
    return errors


def load(path: Path | None = None) -> tuple[list, str]:
    """(cenários, origem) — origem "local" (ficheiro real) ou "synthetic"."""
    p = path or local_path()
    if not p.is_file():
        return [dict(s) for s in SYNTHETIC], "synthetic"
    data = json.loads(p.read_text(encoding="utf-8"))
    scenarios = data["scenarios"] if isinstance(data, dict) else data
    errors = validate(scenarios)
    if errors:
        raise ValueError(f"{p}: " + "; ".join(errors))
    order = {sid: i for i, sid in enumerate(IDS)}
    return sorted((dict(s) for s in scenarios), key=lambda s: order[s["id"]]), "local"
