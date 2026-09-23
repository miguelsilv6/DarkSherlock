"""
evaluation/analyze_engine_failures.py — Mede a "Tolerância a motores caídos"
do EQ-06 (Capítulo 6, secção 6.4.6) a partir do audit trail e das
investigações persistidas.

Só produz dados úteis para execuções DEPOIS do fix que passou a registar
"engine_status" por execução (search.get_search_results, propagado a
Home.py, pages/2_🔍_Investigation.py e evaluation/run_scenarios.py).
Execuções anteriores ao fix não têm "engines_attempted"/"engines_failed"
em logs/audit.jsonl nem "engine_status" no investigation_*.json — são
contadas à parte, não tratadas como 0 falhas.

Duas fontes, dois níveis de detalhe:
  - logs/audit.jsonl: fração agregada de motores caídos por execução
    (campos "engines_attempted"/"engines_failed", já resumidos).
  - investigations/*.json / evaluation/results/investigations/*.json:
    o dicionário completo {motor: "ok"|"failed"} por execução, que permite
    o detalhe por motor (quais falham mais) que o audit trail não guarda.

Uso:
    python evaluation/analyze_engine_failures.py \
        --audit-trail logs/audit.jsonl \
        --investigations "investigations/*.json"
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics
import sys
from pathlib import Path


def analyze_audit_trail(path_str: str) -> None:
    path = Path(path_str)
    if not path.is_file():
        print(f"AVISO: audit trail não encontrado em {path_str} — a saltar esta parte.")
        return

    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    with_data = []
    without_data = 0
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "engines_attempted" in entry and "engines_failed" in entry:
            with_data.append(entry)
        else:
            without_data += 1

    print("=== EQ-06 — Tolerância a motores caídos (agregado, via audit trail) ===")
    print(f"Linhas no audit trail: {len(lines)}")
    print(f"Sem dados de motores (execuções anteriores ao fix): {without_data}")
    if not with_data:
        print("Nenhuma execução com dados de motores ainda — corre o pipeline pelo menos "
              "uma vez depois do fix antes de repetir esta análise.\n")
        return

    fractions = [
        e["engines_failed"] / e["engines_attempted"]
        for e in with_data if e["engines_attempted"] > 0
    ]
    zero_attempted = sum(1 for e in with_data if e["engines_attempted"] == 0)

    print(f"Execuções com dados de motores: {len(with_data)} "
          f"({zero_attempted} com 0 motores tentados, excluídas do rácio)")
    if fractions:
        print(f"Fração de motores caídos — média: {statistics.mean(fractions) * 100:.1f}%")
        print(f"Fração de motores caídos — máxima observada: {max(fractions) * 100:.1f}%")
        print(f"Fração de motores caídos — mínima observada: {min(fractions) * 100:.1f}%")

        # A tese espera "tolerância entre 30-50% de motores caídos sem
        # comprometer a conclusão da investigação" — cruza com results_found.
        high_failure = [e for e in with_data if e["engines_attempted"] > 0
                        and e["engines_failed"] / e["engines_attempted"] >= 0.30]
        completed_despite_failure = [e for e in high_failure if e.get("results_found", 0) > 0]
        print(f"\nExecuções com ≥30% de motores caídos: {len(high_failure)}")
        if high_failure:
            print(f"  ...das quais ainda produziram resultados (results_found > 0): "
                  f"{len(completed_despite_failure)}/{len(high_failure)} "
                  f"({100 * len(completed_despite_failure) / len(high_failure):.1f}%)")
    print()


def analyze_per_engine(patterns: list[str]) -> None:
    paths: list[Path] = []
    for pattern in patterns:
        matched = glob.glob(pattern)
        if not matched and Path(pattern).is_file():
            matched = [pattern]
        paths.extend(Path(p) for p in matched)

    print("=== EQ-06 — Detalhe por motor (via investigation_*.json / eval_*.json) ===")
    if not paths:
        print(f"AVISO: nenhum ficheiro encontrado para {patterns} — a saltar esta parte.\n")
        return

    engine_ok: dict[str, int] = {}
    engine_failed: dict[str, int] = {}
    files_with_data = 0

    for p in sorted(paths):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        engine_status = data.get("engine_status") or {}
        if not engine_status:
            continue
        files_with_data += 1
        for name, status in engine_status.items():
            if status == "ok":
                engine_ok[name] = engine_ok.get(name, 0) + 1
            else:
                engine_failed[name] = engine_failed.get(name, 0) + 1

    print(f"Ficheiros encontrados: {len(paths)} | com engine_status: {files_with_data}")
    if not files_with_data:
        print("Nenhuma investigação com dados de motores ainda.\n")
        return

    all_engines = sorted(set(engine_ok) | set(engine_failed))
    rows = []
    for name in all_engines:
        ok = engine_ok.get(name, 0)
        failed = engine_failed.get(name, 0)
        total = ok + failed
        rate = 100 * failed / total if total else 0.0
        rows.append((name, total, failed, rate))

    rows.sort(key=lambda r: r[3], reverse=True)  # piores motores primeiro

    print(f"\n{'Motor':<20} {'Tentativas':>10} {'Falhas':>8} {'Taxa de falha':>14}")
    for name, total, failed, rate in rows:
        print(f"{name:<20} {total:>10} {failed:>8} {rate:>13.1f}%")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--audit-trail", type=str, default="logs/audit.jsonl",
                        help="Caminho para logs/audit.jsonl (default: logs/audit.jsonl).")
    parser.add_argument("--investigations", type=str, default="investigations/*.json",
                        help="Padrão glob para os ficheiros de investigação (default: investigations/*.json).")
    args = parser.parse_args()

    analyze_audit_trail(args.audit_trail)
    analyze_per_engine([args.investigations])


if __name__ == "__main__":
    main()
