"""
evaluation/pool_results.py — Agrega vários CSVs de multi_model_runs_*.csv
(de corridas sucessivas de run_multi_model_eval.py, possivelmente com
--scenarios diferentes em cada corrida) numa única tabela de fiabilidade
com o n real por célula.

Motivação: reforçar a amostra em cenários/modelos específicos ao longo de
várias corridas (ex.: 12 cenários × 5 execuções primeiro, depois mais 10
execuções só em A1/C3/D1) deixa os dados espalhados por vários ficheiros
CSV, com um n diferente por célula. Combinar isso à mão — somar, calcular
desvio padrão manualmente — é lento e sujeito a erro de aritmética; este
script faz a soma de forma determinística e reprodutível, e mostra o n de
cada célula explicitamente, para que fique documentado na metodologia que
o desenho é de amostragem adaptativa (mais execuções onde a variância
inicial era maior), não uma inconsistência escondida.

Cada linha de um CSV gerado por run_multi_model_eval.py corresponde sempre
a uma execução bem-sucedida (execuções falhadas ou saltadas por Tor em
baixo nunca chegam a ser escritas no ficheiro), pelo que todas as linhas
lidas aqui são diretamente agregáveis.

Uso:
    python evaluation/pool_results.py \
        evaluation/results/multi_model_runs_20260920_132614.csv \
        evaluation/results/multi_model_runs_20260920_213540.csv
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"

# Duplicado deliberadamente a partir de run_multi_model_eval.py em vez de
# importado: importar esse módulo arrasta run_scenarios -> llm -> langchain,
# uma cadeia de dependências pesada que esta ferramenta de análise pura (só
# lê CSVs já gerados) não precisa. Mantém isto sincronizado se as chaves lá
# mudarem — só as CHAVES importam aqui, não as mensagens de log associadas.
FALLBACK_MARKERS = (
    "refine_fallback", "filter_llm_call_failed", "filter_retry_failed_top20",
    "filter_unparseable_top20", "filter_none_keyword_override", "relevance_filter_kept_all",
)
ETAPA4_NO_RANKING_FLAGS = ("filter_retry_failed_top20", "filter_unparseable_top20")


def load_rows(paths: list[str]) -> list[dict]:
    rows: list[dict] = []
    for p in paths:
        path = Path(p)
        if not path.is_file():
            print(f"AVISO: ficheiro não encontrado, a ignorar: {p}")
            continue
        with open(path, newline="", encoding="utf-8") as f:
            file_rows = list(csv.DictReader(f))

        parsed = []
        for row in file_rows:
            try:
                row["total_ms"] = int(row["total_ms"])
                row["results_scraped"] = int(row["results_scraped"])
                for flag in FALLBACK_MARKERS:
                    row[flag] = int(row.get(flag, 0) or 0)
            except (KeyError, ValueError) as e:
                print(f"AVISO: linha inválida em {path.name} ignorada ({e}): {row}")
                continue
            parsed.append(row)

        print(f"  {path.name}: {len(parsed)}/{len(file_rows)} linhas válidas")
        rows.extend(parsed)
    return rows


def write_pooled_summary(out_path: Path, rows: list[dict], source_files: list[str]) -> None:
    models = sorted({r["model"] for r in rows if r.get("model")})
    scenarios = sorted({r["scenario_id"] for r in rows if r.get("scenario_id")})

    lines = ["# Resumo de fiabilidade — dados agregados (pooled) de múltiplas corridas\n"]
    lines.append(f"Ficheiros de origem: {', '.join(Path(p).name for p in source_files)}\n")
    lines.append(f"Total de execuções agregadas: {len(rows)}\n")

    lines.append("## Visão global por modelo\n")
    lines.append("| Modelo | n | Média total (s) | DP total (s) | Etapa 4 sem ranking (%) | Etapa 5 filtro anulado (%) |")
    lines.append("|---|---|---|---|---|---|")
    for model in models:
        m_rows = [r for r in rows if r["model"] == model]
        if not m_rows:
            continue
        times = [r["total_ms"] / 1000 for r in m_rows]
        mean_t = statistics.mean(times)
        stdev_t = statistics.stdev(times) if len(times) > 1 else 0.0
        etapa4_rate = 100 * sum(1 for r in m_rows if any(r.get(f) for f in ETAPA4_NO_RANKING_FLAGS)) / len(m_rows)
        etapa5_rate = 100 * sum(1 for r in m_rows if r.get("relevance_filter_kept_all")) / len(m_rows)
        lines.append(
            f"| {model} | {len(m_rows)} | {mean_t:.1f} | {stdev_t:.1f} | {etapa4_rate:.0f}% | {etapa5_rate:.0f}% |"
        )

    lines.append("\n## Detalhe por cenário × modelo (com n real por célula)\n")
    lines.append("| Cenário | Modelo | n | Média total (s) | DP (s) | Etapa 4 sem ranking | Etapa 5 filtro anulado |")
    lines.append("|---|---|---|---|---|---|---|")
    for scenario in scenarios:
        for model in models:
            cell = [r for r in rows if r["scenario_id"] == scenario and r["model"] == model]
            if not cell:
                continue
            n = len(cell)
            times = [r["total_ms"] / 1000 for r in cell]
            mean_t = statistics.mean(times)
            stdev_t = statistics.stdev(times) if n > 1 else 0.0
            etapa4_hits = sum(1 for r in cell if any(r.get(f) for f in ETAPA4_NO_RANKING_FLAGS))
            etapa5_hits = sum(1 for r in cell if r.get("relevance_filter_kept_all"))
            lines.append(
                f"| {scenario} | {model} | {n} | {mean_t:.1f} | {stdev_t:.1f} | "
                f"{etapa4_hits}/{n} | {etapa5_hits}/{n} |"
            )

    n_by_cell = {(r["scenario_id"], r["model"]) for r in rows}
    counts = {}
    for r in rows:
        key = (r["scenario_id"], r["model"])
        counts[key] = counts.get(key, 0) + 1
    distinct_ns = sorted(set(counts.values()))
    if len(distinct_ns) > 1:
        lines.append(
            f"\n**Nota metodológica:** o n varia por célula ({', '.join(str(n) for n in distinct_ns)}) — "
            "amostragem adaptativa, reforçada nos cenários que mostraram maior desvio padrão numa corrida "
            "inicial menor. Declarar isto explicitamente na secção de desenho experimental."
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv_files", nargs="+", help="Ficheiros multi_model_runs_*.csv a combinar.")
    parser.add_argument(
        "--output", type=str, default=None,
        help="Caminho do resumo Markdown pooled (default: evaluation/results/pooled_summary_<timestamp>.md).",
    )
    args = parser.parse_args()

    rows = load_rows(args.csv_files)
    if not rows:
        print("ERRO: nenhuma linha válida encontrada nos ficheiros indicados.")
        sys.exit(1)

    models = sorted({r["model"] for r in rows if r.get("model")})
    scenarios = sorted({r["scenario_id"] for r in rows if r.get("scenario_id")})
    print(f"\nTotal de execuções válidas: {len(rows)}")
    print(f"Modelos: {models}")
    print(f"Cenários: {scenarios}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(args.output) if args.output else RESULTS_DIR / f"pooled_summary_{ts}.md"
    write_pooled_summary(out_path, rows, args.csv_files)
    print(f"\nResumo pooled escrito em: {out_path}")


if __name__ == "__main__":
    main()
