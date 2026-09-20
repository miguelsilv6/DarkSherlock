"""
evaluation/run_multi_model_eval.py — Avaliação autónoma multi-modelo e
multi-repetição da fiabilidade do pipeline DarkSherlock (Capítulo 6).

Motivação: uma corrida com um único modelo (run_scenarios.py) revelou taxas
de fallback elevadas nos dois mecanismos de filtragem por LLM do pipeline:

  - Etapa 4 (filter_results — ranking de resultados de pesquisa): quando o
    LLM não devolve uma lista de índices no formato pedido, o código cai
    para "top-N sem ranking" (ver "Unable to interpret LLM result
    selection" em llm.py).
  - Etapa 5 (filter_scraped_by_relevance — filtro de relevância pós-scrape):
    quando nenhuma fonte scrapeada atinge o mínimo de keywords da query, o
    código cai para "mantém tudo sem filtrar" (ver "Post-scrape relevance
    filter removed ALL" em llm.py).

Isto é esperado e documentado no próprio código para o modelo mais leve
(Qwen2.5-0.5B), mas a pergunta relevante para a dissertação é: como varia a
taxa de fallback (e o tempo) consoante o modelo? Este script corre a mesma
bateria de cenários do Capítulo 6, várias vezes, para vários modelos, SEM
intervenção manual, e regista diretamente (sem precisar de grep ao
logs/app.log depois) se cada mecanismo caiu em fallback em cada execução.

Não duplica lógica do pipeline: reutiliza run_scenarios.run_one() tal-qual
(mesmas funções que Home.py invoca), apenas com um logging.Handler temporário
a "escutar" o logger do módulo llm durante a chamada.

Pré-requisitos: iguais a run_scenarios.py — Tor em 127.0.0.1:9050, e cada
modelo listado em --models já descarregado/acessível (corre `Check LLM
Connection` na app, ou já tenhas usado esse modelo antes, para o download
não entrar na cronometragem da 1ª execução).

Uso:
    # Compara dois modelos embutidos, 5 execuções por cenário cada
    python evaluation/run_multi_model_eval.py \\
        --models "Qwen2.5-0.5B (embutido, muito leve),Qwen2.5-1.5B (embutido, leve)" \\
        --runs 5

    # Só alguns cenários, teste rápido
    python evaluation/run_multi_model_eval.py --models "Qwen2.5-0.5B (embutido, muito leve)" \\
        --scenarios A1,B1,C1 --runs 2
"""

from __future__ import annotations

import argparse
import csv
import logging
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

# evaluation/ (para "import run_scenarios") e a raiz do projeto (para os
# módulos llm, llm_utils, audit que run_scenarios.py também importa).
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import run_scenarios as base  # noqa: E402 — import após ajuste de sys.path
from llm import get_llm  # noqa: E402
from llm_utils import get_model_choices  # noqa: E402
from audit import setup_file_logging  # noqa: E402


# ---------------------------------------------------------------------------
# Marcadores literais das mensagens WARNING emitidas por llm.py quando um
# mecanismo de filtragem por LLM cai em fallback. Mantidos como substrings
# (não regex) porque são excertos fixos das strings de log em llm.py — se
# esse texto for alterado lá, tem de ser espelhado aqui.
# ---------------------------------------------------------------------------
FALLBACK_MARKERS = {
    "refine_fallback": "refine_query devolveu output",
    "filter_llm_call_failed": "Filter LLM call falhou",
    "filter_retry_failed_top20": "Filter retry também falhou",
    "filter_unparseable_top20": "Unable to interpret LLM result selection",
    "filter_none_keyword_override": "LLM filter respondeu NONE mas",
    "relevance_filter_kept_all": "Post-scrape relevance filter removed ALL",
}

# Fallbacks que significam "nenhum ranking real do LLM aconteceu nesta
# etapa" (usados no agregado "Etapa 4 fallback %" do resumo). Ficam de fora
# filter_llm_call_failed (só indica um retry, pode ter sucesso a seguir) e
# filter_none_keyword_override (o pipeline recuperou via keyword match, não
# é um "sem filtragem nenhuma" tão cru como os outros dois).
ETAPA4_NO_RANKING_FLAGS = ("filter_retry_failed_top20", "filter_unparseable_top20")


class _FallbackCapture(logging.Handler):
    """Handler temporário que regista mensagens WARNING do logger 'llm' durante uma execução."""

    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.messages.append(record.getMessage())
        except Exception:
            pass


def run_one_with_capture(scenario: dict, model_choice: str, llm) -> dict:
    """Corre run_scenarios.run_one() capturando os WARNINGs de fallback do módulo llm."""
    handler = _FallbackCapture()
    llm_logger = logging.getLogger("llm")
    llm_logger.addHandler(handler)
    try:
        row = base.run_one(scenario, model_choice, llm)
    finally:
        llm_logger.removeHandler(handler)

    for flag, marker in FALLBACK_MARKERS.items():
        row[flag] = int(any(marker in msg for msg in handler.messages))
    row["model"] = model_choice
    return row


def _write_reliability_summary(path: Path, models: list[str], scenarios: list[dict], all_rows: list[dict]) -> None:
    """Escreve um Markdown com o resumo de fiabilidade (tempos + taxas de fallback) por modelo e por cenário×modelo."""
    lines = ["# Resumo de fiabilidade — avaliação multi-modelo\n"]

    lines.append("## Visão global por modelo (todas as execuções, todos os cenários)\n")
    lines.append(
        "| Modelo | Execuções OK | Falhas | Média total (s) | DP total (s) | "
        "Média fontes | Etapa 4 sem ranking (%) | Etapa 5 filtro anulado (%) |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for model in models:
        rows = [r for r in all_rows if r.get("model") == model and "total_ms" in r]
        failed = [r for r in all_rows if r.get("model") == model and "error" in r]
        if not rows:
            lines.append(f"| {model} | 0 | {len(failed)} | — | — | — | — | — |")
            continue
        times = [r["total_ms"] / 1000 for r in rows]
        mean_t = statistics.mean(times)
        stdev_t = statistics.stdev(times) if len(times) > 1 else 0.0
        mean_sources = statistics.mean(r["results_scraped"] for r in rows)
        etapa4_rate = 100 * sum(1 for r in rows if any(r.get(f) for f in ETAPA4_NO_RANKING_FLAGS)) / len(rows)
        etapa5_rate = 100 * sum(1 for r in rows if r.get("relevance_filter_kept_all")) / len(rows)
        lines.append(
            f"| {model} | {len(rows)} | {len(failed)} | {mean_t:.1f} | {stdev_t:.1f} | "
            f"{mean_sources:.1f} | {etapa4_rate:.0f}% | {etapa5_rate:.0f}% |"
        )

    lines.append("\n## Detalhe por cenário × modelo\n")
    lines.append("| Cenário | Modelo | Execuções | Média total (s) | DP (s) | Etapa 4 sem ranking | Etapa 5 filtro anulado |")
    lines.append("|---|---|---|---|---|---|---|")
    for scenario in scenarios:
        for model in models:
            rows = [
                r for r in all_rows
                if r.get("model") == model and r.get("scenario_id") == scenario["id"] and "total_ms" in r
            ]
            if not rows:
                continue
            times = [r["total_ms"] / 1000 for r in rows]
            mean_t = statistics.mean(times)
            stdev_t = statistics.stdev(times) if len(times) > 1 else 0.0
            etapa4_hits = sum(1 for r in rows if any(r.get(f) for f in ETAPA4_NO_RANKING_FLAGS))
            etapa5_hits = sum(1 for r in rows if r.get("relevance_filter_kept_all"))
            lines.append(
                f"| {scenario['id']} | {model} | {len(rows)} | {mean_t:.1f} | {stdev_t:.1f} | "
                f"{etapa4_hits}/{len(rows)} | {etapa5_hits}/{len(rows)} |"
            )

    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--models", type=str, required=True,
        help="Lista separada por vírgulas de modelos a testar (labels exatas da UI, ver Settings).",
    )
    parser.add_argument(
        "--scenarios", type=str, default=None,
        help="Lista separada por vírgulas de IDs de cenário a correr (ex.: A1,B2). Omitir corre os 12.",
    )
    parser.add_argument(
        "--runs", type=int, default=5,
        help="Execuções por cenário por modelo (default: 5 — mais que os 3 do protocolo de eficiência, "
             "para dar poder estatístico à taxa de fallback observada).",
    )
    parser.add_argument(
        "--output-dir", type=str, default=None,
        help="Diretório de saída para o CSV e o resumo Markdown (default: evaluation/results/).",
    )
    args = parser.parse_args()

    if args.runs < 1:
        print("ERRO: --runs tem de ser >= 1.")
        sys.exit(1)

    if not base._check_tor():
        print("ERRO: Tor não está acessível em 127.0.0.1:9050. Arranca o Tor antes de correr a avaliação.")
        sys.exit(1)

    setup_file_logging()

    scenarios = base.SCENARIOS
    if args.scenarios:
        wanted = {s.strip().upper() for s in args.scenarios.split(",")}
        scenarios = [s for s in base.SCENARIOS if s["id"] in wanted]
        missing = wanted - {s["id"] for s in scenarios}
        if missing:
            print(f"AVISO: IDs de cenário desconhecidos ignorados: {missing}")
    if not scenarios:
        print("ERRO: nenhum cenário selecionado.")
        sys.exit(1)

    requested_models = [m.strip() for m in args.models.split(",") if m.strip()]
    available_models = set(get_model_choices())
    unknown_models = [m for m in requested_models if m not in available_models]
    if unknown_models:
        print(f"AVISO: modelos desconhecidos ignorados (não constam em get_model_choices()): {unknown_models}")
    models = [m for m in requested_models if m in available_models]
    if not models:
        print(f"ERRO: nenhum modelo válido em --models. Modelos disponíveis: {sorted(available_models)}")
        sys.exit(1)

    out_dir = Path(args.output_dir) if args.output_dir else base.RESULTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = out_dir / f"multi_model_runs_{ts}.csv"

    total_runs = len(models) * len(scenarios) * args.runs
    print(f"Modelos: {models}")
    print(f"Cenários: {[s['id'] for s in scenarios]}")
    print(f"{len(models)} modelos × {len(scenarios)} cenários × {args.runs} execuções = {total_runs} investigações no total.\n")

    all_rows: list[dict] = []
    writer = None
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        for model_choice in models:
            print(f"\n=== Modelo: {model_choice} ===")
            try:
                t0 = time.time()
                llm = get_llm(model_choice)
                load_ms = round((time.time() - t0) * 1000)
                print(f"Etapa 1 (Load LLM): {load_ms} ms (amortizado nas execuções seguintes deste modelo)")
            except Exception as e:
                print(f"ERRO ao carregar o modelo '{model_choice}': {e} — a saltar este modelo por completo.")
                continue

            for scenario in scenarios:
                for run_idx in range(1, args.runs + 1):
                    print(
                        f"[{model_choice}][{scenario['id']}] execução {run_idx}/{args.runs} "
                        f"— query: '{scenario['query']}' ...",
                        end=" ", flush=True,
                    )
                    try:
                        row = run_one_with_capture(scenario, model_choice, llm)
                        row["run_idx"] = run_idx
                        all_rows.append(row)
                        if writer is None:
                            writer = csv.DictWriter(f, fieldnames=list(row.keys()))
                            writer.writeheader()
                        writer.writerow(row)
                        f.flush()
                        flags_hit = [k for k in FALLBACK_MARKERS if row.get(k)]
                        flag_note = f", fallback: {','.join(flags_hit)}" if flags_hit else ""
                        print(f"OK ({row['total_ms']} ms, {row['results_scraped']} fontes{flag_note})")
                    except Exception as e:
                        print(f"FALHOU: {e}")
                        all_rows.append({
                            "model": model_choice, "scenario_id": scenario["id"],
                            "run_idx": run_idx, "error": str(e),
                        })

    print(f"\nDados brutos por execução (todos os modelos): {csv_path}")

    summary_path = out_dir / f"summary_fiabilidade_{ts}.md"
    _write_reliability_summary(summary_path, models, scenarios, all_rows)
    print(f"Resumo de fiabilidade (tempos + taxa de fallback por modelo/cenário): {summary_path}")


if __name__ == "__main__":
    main()
