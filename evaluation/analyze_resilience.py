"""
evaluation/analyze_resilience.py — Mede a "Taxa de scraping bem-sucedido"
do EQ-06 (Capítulo 6, secção 6.4.6) a partir de dados já recolhidos.

Definição da métrica (secção 6.4.6): "fração de URLs filtradas que
produziram conteúdo significativo (> 150 caracteres) sobre o total de URLs
filtradas". Isto corresponde exatamente a results_pre_relevance /
results_filtered nos CSVs já gerados por run_scenarios.py e
run_multi_model_eval.py (results_pre_relevance = len(meaningful) ANTES do
filtro de relevância por keywords — ver run_one() em run_scenarios.py) —
não precisa de nenhuma execução nova nem de alterações ao pipeline.

Uso:
    python evaluation/analyze_resilience.py evaluation/results/*.csv
"""

from __future__ import annotations

import argparse
import csv
import glob
import statistics
import sys
from pathlib import Path


def load_rows(patterns: list[str]) -> list[dict]:
    rows = []
    for pattern in patterns:
        for path_str in glob.glob(pattern) or ([pattern] if Path(pattern).is_file() else []):
            path = Path(path_str)
            with open(path, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    if "results_filtered" not in row or "results_pre_relevance" not in row:
                        continue  # ficheiro sem as colunas necessárias (formato diferente) — ignora
                    try:
                        row["results_filtered"] = int(row["results_filtered"])
                        row["results_pre_relevance"] = int(row["results_pre_relevance"])
                    except ValueError:
                        continue
                    row["_source_file"] = path.name
                    rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv_files", nargs="+", help="CSVs de raw_runs_*.csv / multi_model_runs_*.csv (aceita padrões glob).")
    args = parser.parse_args()

    rows = load_rows(args.csv_files)
    if not rows:
        print("ERRO: nenhuma linha com as colunas 'results_filtered'/'results_pre_relevance' encontrada.")
        sys.exit(1)

    # Só faz sentido a fração quando havia pelo menos 1 URL filtrada para scraping
    valid_rows = [r for r in rows if r["results_filtered"] > 0]
    skipped = len(rows) - len(valid_rows)

    rates = [r["results_pre_relevance"] / r["results_filtered"] for r in valid_rows]

    print(f"Execuções carregadas: {len(rows)} (de {len(set(r['_source_file'] for r in rows))} ficheiro(s))")
    print(f"Execuções com 0 URLs filtradas (excluídas do rácio, divisão por zero): {skipped}")
    print(f"Execuções usadas no cálculo: {len(valid_rows)}\n")

    print("=== EQ-06 — Taxa de scraping bem-sucedido (global) ===")
    print(f"Média:  {statistics.mean(rates) * 100:.1f}%")
    print(f"DP:     {statistics.stdev(rates) * 100:.1f} pontos percentuais" if len(rates) > 1 else "")
    print(f"Mínimo: {min(rates) * 100:.1f}%")
    print(f"Máximo: {max(rates) * 100:.1f}%")

    # Por cenário, se a coluna existir
    if any("scenario_id" in r for r in valid_rows):
        print("\n=== Por cenário ===")
        scenarios = sorted({r["scenario_id"] for r in valid_rows if r.get("scenario_id")})
        print(f"{'Cenário':<10} {'n':>5} {'Média':>8} {'Mín':>8} {'Máx':>8}")
        for sid in scenarios:
            sc_rates = [
                r["results_pre_relevance"] / r["results_filtered"]
                for r in valid_rows if r.get("scenario_id") == sid
            ]
            if not sc_rates:
                continue
            print(f"{sid:<10} {len(sc_rates):>5} {statistics.mean(sc_rates) * 100:>7.1f}% "
                  f"{min(sc_rates) * 100:>7.1f}% {max(sc_rates) * 100:>7.1f}%")

    # Por modelo, se a coluna existir
    if any("model" in r for r in valid_rows):
        print("\n=== Por modelo ===")
        models = sorted({r["model"] for r in valid_rows if r.get("model")})
        print(f"{'Modelo':<40} {'n':>5} {'Média':>8}")
        for m in models:
            m_rates = [
                r["results_pre_relevance"] / r["results_filtered"]
                for r in valid_rows if r.get("model") == m
            ]
            if not m_rates:
                continue
            print(f"{m:<40} {len(m_rates):>5} {statistics.mean(m_rates) * 100:>7.1f}%")

    # Casos extremos (0% ou 100%) — interessantes para discussão qualitativa
    zero_cases = [r for r in valid_rows if r["results_pre_relevance"] == 0]
    full_cases = [r for r in valid_rows if r["results_pre_relevance"] == r["results_filtered"]]
    print(f"\nExecuções com 0% de sucesso (todas as URLs falharam o scraping): {len(zero_cases)}/{len(valid_rows)}")
    print(f"Execuções com 100% de sucesso (todas as URLs scraped com êxito): {len(full_cases)}/{len(valid_rows)}")


if __name__ == "__main__":
    main()
