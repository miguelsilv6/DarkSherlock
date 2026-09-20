#!/usr/bin/env python3
"""
evaluation/baseline_manual/baseline_helper.py — Apoio à cronometragem e ao
cálculo de hashes do protocolo de Baseline Manual (Capítulo 6, secção 6.5).

Esta ferramenta é DELIBERADAMENTE independente do resto do código do
DarkSherlock: usa só a biblioteca padrão do Python (hashlib, csv, json,
datetime) e não invoca nenhum LLM nem lógica do pipeline. Isto não é um
acidente — a secção 6.5.2 do relatório proíbe explicitamente "uso de
qualquer LLM, mesmo em contexto offline" e "uso de outras ferramentas de
automação OSINT" no baseline manual. Esta ferramenta só cronometra e faz
hash do que o investigador já recolheu à mão; não pesquisa, não filtra e
não analisa nada.

Duas funções:
  1. Cronometragem por etapa (start/stop), gravada em timing_log.csv — a
     fonte de dados para a coluna "Baseline (s)" da Tabela 13 e para o
     "tempo por etapa" pedido nas métricas de EQ-01.
  2. Hash SHA-256 por fonte e hash global da investigação, replicando
     EXATAMENTE o algoritmo de report.compute_integrity_hashes() (hash
     individual do conteúdo de cada fonte + hash global da concatenação de
     todos os conteúdos, ordenados) — para que os artefactos do baseline
     sejam comparáveis aos do DarkSherlock nos critérios de equivalência de
     output (secção 6.5.4).

Uso:
    # Etapas: 1=Refinamento, 2=Pesquisa, 3=Triagem, 4=Recolha, 5=Redação
    python baseline_helper.py start A1 1
    python baseline_helper.py stop  A1 1
    python baseline_helper.py summary A1

    python baseline_helper.py hash sources/A1/fonte1.txt
    python baseline_helper.py hash-global sources/A1/
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / ".timer_state.json"
LOG_FILE = BASE_DIR / "timing_log.csv"

STAGE_NAMES = {
    1: "Refinamento manual da query",
    2: "Pesquisa manual (3 motores)",
    3: "Triagem manual (seleção até 20)",
    4: "Recolha manual (Tor Browser + hash)",
    5: "Redação do relatório",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}


def _save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def cmd_start(scenario: str, stage: int) -> None:
    if stage not in STAGE_NAMES:
        print(f"ERRO: etapa inválida ({stage}). Válidas: {sorted(STAGE_NAMES)}.")
        sys.exit(1)
    key = f"{scenario}:{stage}"
    state = _load_state()
    if key in state:
        print(f"AVISO: já havia um cronómetro ativo para {key} desde {state[key]} — a substituir.")
    state[key] = _now_iso()
    _save_state(state)
    print(f"[{scenario}] Etapa {stage} ({STAGE_NAMES[stage]}) — início registado: {state[key]}")


def cmd_stop(scenario: str, stage: int) -> None:
    key = f"{scenario}:{stage}"
    state = _load_state()
    if key not in state:
        print(f"ERRO: não há cronómetro ativo para {key}. Usa 'start' primeiro.")
        sys.exit(1)
    start_iso = state.pop(key)
    _save_state(state)
    end_iso = _now_iso()
    duration_s = (datetime.fromisoformat(end_iso) - datetime.fromisoformat(start_iso)).total_seconds()

    is_new = not LOG_FILE.exists()
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["scenario_id", "stage_num", "stage_name", "start_utc", "end_utc", "duration_s"]
        )
        if is_new:
            writer.writeheader()
        writer.writerow({
            "scenario_id": scenario, "stage_num": stage, "stage_name": STAGE_NAMES[stage],
            "start_utc": start_iso, "end_utc": end_iso, "duration_s": round(duration_s, 3),
        })
    print(f"[{scenario}] Etapa {stage} ({STAGE_NAMES[stage]}) — fim registado. Duração: {duration_s:.1f}s")


def cmd_summary(scenario: str | None) -> None:
    if not LOG_FILE.exists():
        print("Ainda não há dados em timing_log.csv.")
        return
    rows = list(csv.DictReader(LOG_FILE.open(encoding="utf-8")))
    if scenario:
        rows = [r for r in rows if r["scenario_id"] == scenario]
    if not rows:
        print(f"Sem registos para {scenario!r}." if scenario else "Sem registos.")
        return

    by_scenario: dict[str, float] = {}
    count_by_scenario: dict[str, int] = {}
    for r in rows:
        by_scenario[r["scenario_id"]] = by_scenario.get(r["scenario_id"], 0.0) + float(r["duration_s"])
        count_by_scenario[r["scenario_id"]] = count_by_scenario.get(r["scenario_id"], 0) + 1

    print(f"{'Cenário':<8} {'Etapas':<10} {'Total (s)':>10}")
    for sid in sorted(by_scenario):
        n_stages = count_by_scenario[sid]
        flag = "" if n_stages == 5 else f" (faltam {5 - n_stages})"
        print(f"{sid:<8} {n_stages}/5{flag:<10} {by_scenario[sid]:>10.1f}")


def cmd_hash(file_path: str) -> None:
    path = Path(file_path)
    if not path.is_file():
        print(f"ERRO: ficheiro não encontrado: {file_path}")
        sys.exit(1)
    content = path.read_text(encoding="utf-8", errors="replace")
    digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    print(f"SHA-256({path.name}) = {digest}")


def cmd_hash_global(dir_path: str) -> None:
    """
    Replica report.compute_integrity_hashes(): hash por ficheiro (fonte) e
    hash global da concatenação de todos os conteúdos, ordenados pelo nome
    do ficheiro (equivalente a ordenar por URL no pipeline automático, que
    itera sorted(scraped.items())).
    """
    d = Path(dir_path)
    if not d.is_dir():
        print(f"ERRO: diretório não encontrado: {dir_path}")
        sys.exit(1)
    files = sorted(p for p in d.iterdir() if p.is_file() and p.suffix == ".txt")
    if not files:
        print(f"ERRO: nenhum ficheiro .txt encontrado em {dir_path}.")
        sys.exit(1)

    sources = {}
    combined_parts = []
    for f in files:
        content = f.read_text(encoding="utf-8", errors="replace")
        sources[f.name] = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        combined_parts.append(content)

    overall = hashlib.sha256("".join(combined_parts).encode("utf-8", errors="replace")).hexdigest()

    print(f"Fontes ({len(files)}):")
    for name, h in sources.items():
        print(f"  SHA-256({name}) = {h}")
    print(f"\nHash global (SHA-256 da concatenação ordenada): {overall}")
    print(f"Calculado em (UTC): {_now_iso()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start", help="Inicia o cronómetro de uma etapa.")
    p_start.add_argument("scenario", help="ID do cenário (ex.: A1).")
    p_start.add_argument("stage", type=int, help="Nº da etapa (1-5).")

    p_stop = sub.add_parser("stop", help="Termina o cronómetro e regista a duração.")
    p_stop.add_argument("scenario")
    p_stop.add_argument("stage", type=int)

    p_summary = sub.add_parser("summary", help="Mostra o total acumulado por cenário.")
    p_summary.add_argument("scenario", nargs="?", default=None)

    p_hash = sub.add_parser("hash", help="Calcula o SHA-256 de um ficheiro de fonte individual.")
    p_hash.add_argument("file")

    p_hash_global = sub.add_parser(
        "hash-global", help="Calcula os hashes por fonte + hash global de um diretório de fontes .txt."
    )
    p_hash_global.add_argument("directory")

    args = parser.parse_args()

    if args.command == "start":
        cmd_start(args.scenario.upper(), args.stage)
    elif args.command == "stop":
        cmd_stop(args.scenario.upper(), args.stage)
    elif args.command == "summary":
        cmd_summary(args.scenario.upper() if args.scenario else None)
    elif args.command == "hash":
        cmd_hash(args.file)
    elif args.command == "hash-global":
        cmd_hash_global(args.directory)


if __name__ == "__main__":
    main()
