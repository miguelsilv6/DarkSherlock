"""
evaluation/run_scenarios.py — Executa os 12 cenários do Capítulo 6 (Avaliação
Empírica) contra o pipeline real do DarkSherlock, 3 vezes cada, e produz:

  1. Um JSON de investigação por execução em ./investigations/ (mesmo formato
     que a app gera), para poder ser recarregado na página Home.
  2. Uma linha no audit trail (./logs/audit.jsonl), como uma investigação normal.
  3. Um CSV detalhado por execução com o tempo de CADA etapa (o audit trail de
     produção só regista o total em pipeline_duration_ms — o relatório pede
     "tempo por etapa", daí este script medir e persistir isso à parte).
  4. Uma tabela Markdown pronta a colar na Tabela 13 (Eficiência Operacional)
     do relatório: média e desvio padrão do tempo end-to-end por cenário.

Não altera nem duplica a lógica do pipeline: chama pipeline.run_pipeline,
as mesmas funções que a Home e a Investigation usam (pipeline.py), para que
os números recolhidos sejam representativos do comportamento real da app,
não de uma reimplementação. Cada investigação grava "pipeline_version".

Pré-requisitos:
  - Tor a correr em 127.0.0.1:9050 (obrigatório — sem Tor, Stage 3/5 falham
    e os tempos não são representativos).
  - Modelo LLM já descarregado/acessível (corre `Check LLM Connection` na
    app primeiro se usares o modelo embutido, para o download não entrar
    na cronometragem da 1ª execução).

Uso:
    python evaluation/run_scenarios.py                     # todos os 12, 3x cada
    python evaluation/run_scenarios.py --scenarios A1,B2    # só alguns
    python evaluation/run_scenarios.py --runs 1             # 1 execução por cenário (teste rápido)
    python evaluation/run_scenarios.py --model "Qwen2.5-1.5B (embutido, leve)"
"""

from __future__ import annotations

import argparse
import csv
import logging
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm import get_llm
import pipeline
import scenarios as scenarios_mod
from llm_utils import get_model_choices
from audit import log_investigation, setup_file_logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cenários: os reais de evaluation/scenarios.local.json (fora do Git) se o
# ficheiro existir, senão os 12 sintéticos da Tabela 12 (ver scenarios.py).
# ---------------------------------------------------------------------------
SCENARIOS, SCENARIO_SOURCE = scenarios_mod.load()



def shown_query(scenario: dict) -> str:
    """O que se mostra no terminal: a query sintética, ou só o pseudónimo se o cenário for real."""
    if SCENARIO_SOURCE == "local":
        return f"[{scenario.get('label') or 'cenário real'}]"
    return f"'{scenario['query']}'"


RESULTS_DIR = Path(__file__).resolve().parent / "results"
INVESTIGATIONS_DIR = Path("investigations")

# Limites alinhados com os defaults da UI (sidebar.py) — mantidos aqui
# explicitamente para que a execução em lote seja reprodutível independente
# de session_state do Streamlit.
MAX_RESULTS = 50
MAX_SCRAPE = 20
THREADS = 8


def _check_tor() -> bool:
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=3)
        s.close()
        return True
    except OSError:
        return False


def _restart_tor() -> bool:
    """
    Tenta reiniciar o serviço Tor via systemctl (systemd) ou service
    (sysvinit/OpenRC) como fallback. Requer privilégios suficientes (root,
    ou sudo sem password configurado) — se não os houver, o comando falha
    silenciosamente (returncode != 0 ou binário inexistente) e quem chamou
    (ensure_tor) simplesmente continua a aguardar/reportar falha.

    Devolve True se algum dos comandos correu com sucesso (returncode 0) —
    não garante que o Tor fique operacional, isso é verificado à parte por
    _check_tor() no polling de ensure_tor().
    """
    for cmd in (["systemctl", "restart", "tor"], ["service", "tor", "restart"]):
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def ensure_tor(max_wait_s: int = 60, poll_interval_s: int = 3) -> tuple[bool, bool]:
    """
    Garante que o Tor está acessível em 127.0.0.1:9050 antes de uma
    execução, tentando recuperar automaticamente se não estiver.

    Numa corrida longa (várias horas, múltiplos cenários/execuções), o Tor
    pode cair a meio sem isso ser óbvio — as etapas de busca/scraping que
    dependem dele simplesmente devolveriam 0 resultados ou erros de rede,
    contaminando silenciosamente as métricas em vez de a corrida recuperar
    ou falhar de forma explícita. Por isso esta verificação corre antes de
    CADA execução (não só uma vez no arranque do script).

    Devolve (ok, restart_tentado):
      - ok: True se o Tor está acessível (de início, ou após recuperar).
      - restart_tentado: True se foi necessário tentar reiniciar o serviço
        (útil para assinalar no CSV que esta execução decorreu depois de
        uma falha de infraestrutura, não é uma corrida "limpa").
    """
    if _check_tor():
        return True, False

    logger.warning("Tor inacessível em 127.0.0.1:9050 — a tentar reiniciar o serviço...")
    _restart_tor()

    waited = 0
    while waited < max_wait_s:
        time.sleep(poll_interval_s)
        waited += poll_interval_s
        if _check_tor():
            logger.info("Tor recuperado após ~%ds de espera/reinício.", waited)
            return True, True

    logger.error("Tor continua inacessível após %ds — a reportar falha para esta execução.", max_wait_s)
    return False, True


def run_one(scenario: dict, model_choice: str, llm) -> dict:
    """Executa o pipeline completo para um cenário e devolve métricas + artefactos.

    Usa pipeline.run_pipeline — as mesmas funções que a Home e a Investigation
    chamam —, com os limites fixos acima (independentes das definições da UI).
    O LLM já carregado (Etapa 1) é reutilizado nas 3 execuções, como numa sessão da app.
    """
    try:
        r = pipeline.run_pipeline(
            scenario["query"], scenario["preset"], llm, model=model_choice,
            max_results=MAX_RESULTS, max_scrape=MAX_SCRAPE, threads=THREADS,
        )
    except pipeline.PipelineError as e:
        # Grava o que foi feito até à falha (para diagnóstico) e propaga.
        _save(scenario, e.result)
        raise

    inv_fname = _save(scenario, r)
    log_investigation(pipeline.audit_record(r, scenario_id=scenario["id"]))

    return {
        "scenario_id": scenario["id"],
        "domain": scenario["domain"],
        "audit_id": r.audit_id,
        "investigation_file": inv_fname,
        "stage4_outcome": r.stage4_outcome,
        "stage5_outcome": r.stage5_outcome,
        "safety_blocked": r.safety_blocked,
        "results_found": len(r.search_results),
        "results_filtered": len(r.filtered),
        "results_pre_relevance": r.pages_valid,
        "results_scraped": len(r.scraped_content),
        "summary_length_chars": len(r.summary),
        "total_ms": r.total_ms,
        "engines_attempted": len(r.engine_status),
        "engines_failed": sum(1 for v in r.engine_status.values() if v == "failed"),
        **{f"{k}_ms": r.timings_ms.get(k, 0) for k in ("refine_query", "search", "filter_results",
                                                     "scrape", "generate_summary")},
    }


def _save(scenario: dict, r: "pipeline.PipelineResult") -> str:
    """JSON da investigação no formato da app (recarregável na Home), com o cenário do Cap. 6."""
    record = pipeline.investigation_record(r, scenario_id=scenario["id"], domain=scenario["domain"],
                                           scenario_source=SCENARIO_SOURCE,
                                           scenario_label=scenario.get("label", ""))
    return pipeline.save_investigation(record, INVESTIGATIONS_DIR, prefix=f"eval_{scenario['id']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenarios", type=str, default=None,
                        help="Lista separada por vírgulas de IDs a correr (ex.: A1,B2). Omitir corre os 12.")
    parser.add_argument("--runs", type=int, default=3, help="Execuções por cenário (default: 3, conforme o relatório).")
    parser.add_argument("--model", type=str, default=None,
                        help="Modelo a usar (label exata da UI). Omitir usa o primeiro disponível.")
    args = parser.parse_args()

    setup_file_logging()

    tor_ok, _ = ensure_tor()
    if not tor_ok:
        print("ERRO: Tor não está acessível em 127.0.0.1:9050 e a tentativa automática de reinício "
              "(systemctl/service) falhou. Arranca o Tor manualmente antes de correr a avaliação.")
        sys.exit(1)

    scenarios = SCENARIOS
    if args.scenarios:
        wanted = {s.strip().upper() for s in args.scenarios.split(",")}
        scenarios = [s for s in SCENARIOS if s["id"] in wanted]
        missing = wanted - {s["id"] for s in scenarios}
        if missing:
            print(f"AVISO: IDs desconhecidos ignorados: {missing}")

    model_choice = args.model
    if not model_choice:
        choices = get_model_choices()
        if not choices:
            print("ERRO: nenhum modelo LLM disponível (Ollama offline e llama-cpp-python não instalado?).")
            sys.exit(1)
        model_choice = choices[0]

    print(f"Modelo: {model_choice}")
    if SCENARIO_SOURCE == "local":
        print("Cenários REAIS (scenarios.local.json): no terminal mostra-se o pseudónimo, não a query; "
              "rasura os resultados com evaluation/redact.py antes de os usar no relatório.")
    else:
        print("Cenários sintéticos (sem evaluation/scenarios.local.json).")
    print(f"Cenários: {[s['id'] for s in scenarios]} × {args.runs} execuções cada = {len(scenarios) * args.runs} investigações\n")

    # Uma única instância do LLM reutilizada em todas as execuções — replica
    # o comportamento real da app numa sessão (o modelo é carregado uma vez
    # e reutilizado nas etapas 2/4/6, ver secção 5.15 "Etapa 1" do relatório).
    # O tempo de carregamento do modelo NÃO entra nos tempos por cenário
    # abaixo — é reportado à parte, uma vez, como corresponde à Etapa 1.
    t0 = time.time()
    llm = get_llm(model_choice)
    load_ms = round((time.time() - t0) * 1000)
    print(f"Etapa 1 (Load LLM): {load_ms} ms (uma vez, amortizado nas execuções seguintes)\n")

    RESULTS_DIR.mkdir(exist_ok=True)
    csv_path = RESULTS_DIR / f"raw_runs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    all_rows = []

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = None
        for scenario in scenarios:
            for run_idx in range(1, args.runs + 1):
                # Verifica (e tenta recuperar) o Tor antes de CADA execução — não
                # só uma vez no arranque — para que uma queda a meio de uma
                # corrida longa não contamine silenciosamente os resultados.
                tor_ok, tor_restart_needed = ensure_tor()
                if not tor_ok:
                    msg = "Tor inacessível (reinício automático falhou) — execução saltada."
                    print(f"[{scenario['id']}] execução {run_idx}/{args.runs} — SALTADA: {msg}")
                    all_rows.append({"scenario_id": scenario["id"], "run_idx": run_idx, "error": msg})
                    continue

                print(f"[{scenario['id']}] execução {run_idx}/{args.runs} — query: {shown_query(scenario)} ...",
                      end=" ", flush=True)
                try:
                    row = run_one(scenario, model_choice, llm)
                    row["run_idx"] = run_idx
                    row["tor_restart_needed"] = int(tor_restart_needed)
                    all_rows.append(row)
                    if writer is None:
                        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
                        writer.writeheader()
                    writer.writerow(row)
                    f.flush()
                    restart_note = " [Tor teve de ser reiniciado antes desta execução]" if tor_restart_needed else ""
                    print(f"OK ({row['total_ms']} ms, {row['results_scraped']} fontes){restart_note}")
                except Exception as e:
                    print(f"FALHOU: {e}")
                    all_rows.append({"scenario_id": scenario["id"], "run_idx": run_idx, "error": str(e)})

    print(f"\nDados brutos por execução: {csv_path}")

    # Tabela 13 do relatório: média e desvio padrão do tempo end-to-end por cenário.
    md_path = RESULTS_DIR / f"tabela13_eficiencia_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    lines = [
        "| Cenário | DarkSherlock — média (s) | DarkSherlock — DP (s) | Baseline (s) | Speedup (×) |",
        "|---|---|---|---|---|",
    ]
    for scenario in scenarios:
        times = [r["total_ms"] / 1000 for r in all_rows if r.get("scenario_id") == scenario["id"] and "total_ms" in r]
        if not times:
            lines.append(f"| {scenario['id']} | (falhou) | — | *preencher manualmente* | — |")
            continue
        mean = statistics.mean(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0.0
        lines.append(f"| {scenario['id']} | {mean:.1f} | {stdev:.1f} | *preencher manualmente* | *calcular após baseline* |")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Tabela 13 (pronta a colar, falta a coluna Baseline do teu protocolo manual): {md_path}")

    print("\nPróximo passo: preenche a coluna 'Baseline (s)' com a cronometragem manual "
          "(secção 6.5 do relatório) e calcula o Speedup = Baseline / DarkSherlock.")


if __name__ == "__main__":
    main()
