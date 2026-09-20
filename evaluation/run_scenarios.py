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

Não altera nem duplica a lógica do pipeline: chama exatamente as mesmas
funções que Home.py invoca (get_llm, refine_query, get_search_results,
filter_results, scrape_multiple, filter_scraped_by_relevance,
generate_summary, compute_integrity_hashes), para que os números recolhidos
sejam representativos do comportamento real da app, não de uma reimplementação.

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
import json
import logging
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm import (
    get_llm, refine_query, filter_results, generate_summary,
    filter_scraped_by_relevance,
)
from llm_utils import get_model_choices
from search import get_search_results
from scrape import scrape_multiple
from report import compute_integrity_hashes
from engine_manager import get_active_engines
from audit import log_investigation, setup_file_logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Os 12 cenários — Tabela 12 do relatório, reproduzidos literalmente
# (query e preset exatamente como especificados no Capítulo 6).
# ---------------------------------------------------------------------------
SCENARIOS = [
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
    """Executa o pipeline completo para um cenário e devolve métricas + artefactos."""
    audit_id = str(uuid.uuid4())
    query = scenario["query"]
    preset = scenario["preset"]
    timings_ms: dict[str, int] = {}
    errors: list[str] = []
    t_start = time.time()

    # Etapa 2 — Refinamento de query (Etapa 1/Load LLM já ocorreu antes do loop,
    # e é amortizada — ver nota no __main__ sobre reutilização do mesmo LLM
    # nas 3 execuções, replicando o comportamento real da app numa sessão).
    t0 = time.time()
    refined = refine_query(llm, query, preset=preset)
    timings_ms["refine_query"] = round((time.time() - t0) * 1000)

    # Etapa 3 — Pesquisa via Tor
    t0 = time.time()
    active_engines = [e["name"] for e in get_active_engines()]
    results = get_search_results(refined, max_workers=THREADS)
    if len(results) > MAX_RESULTS:
        results = results[:MAX_RESULTS]
    retrieved_at = datetime.now(timezone.utc).isoformat()
    for r in results:
        r["retrieved_at_utc"] = retrieved_at
    timings_ms["search"] = round((time.time() - t0) * 1000)

    # Etapa 4 — Filtragem por relevância (LLM)
    t0 = time.time()
    filtered = filter_results(llm, refined, results)
    if len(filtered) > MAX_SCRAPE:
        filtered = filtered[:MAX_SCRAPE]
    timings_ms["filter_results"] = round((time.time() - t0) * 1000)

    # Etapa 5 — Scraping + filtro de relevância pós-scrape
    t0 = time.time()
    scraped = scrape_multiple(filtered, max_workers=THREADS)
    meaningful = {u: c for u, c in scraped.items() if len(c) > 150}
    pre_relevance = len(meaningful)
    meaningful = filter_scraped_by_relevance(query, meaningful)
    scraped_at = datetime.now(timezone.utc).isoformat()
    for item in filtered:
        if item.get("link", "") in meaningful:
            item["scraped_at_utc"] = scraped_at
    integrity = compute_integrity_hashes(meaningful)
    timings_ms["scrape"] = round((time.time() - t0) * 1000)

    # Etapa 6 — Geração do relatório
    t0 = time.time()
    summary = generate_summary(llm, refined, meaningful, preset=preset)
    timings_ms["generate_summary"] = round((time.time() - t0) * 1000)

    total_ms = round((time.time() - t_start) * 1000)

    # Persistência: mesmo formato que Home.py grava, para poder ser
    # recarregado na app e incluído no PDF/JSON usados na revisão cega (EQ-04).
    INVESTIGATIONS_DIR.mkdir(exist_ok=True)
    inv_data = {
        "audit_id": audit_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "query": query,
        "refined_query": refined,
        "model": model_choice,
        "preset": preset,
        "active_engines": active_engines,
        "sources": filtered,
        "summary": summary,
        "integrity": integrity,
        "scenario_id": scenario["id"],   # extra: rastreável ao cenário do Cap. 6
        "domain": scenario["domain"],
    }
    inv_fname = f"eval_{scenario['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    (INVESTIGATIONS_DIR / inv_fname).write_text(
        json.dumps(inv_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # Audit trail — mesma função que a app usa
    log_investigation({
        "audit_id": audit_id,
        "query": query,
        "refined_query": refined,
        "model": model_choice,
        "preset": preset,
        "engines_active": active_engines,
        "results_found": len(results),
        "results_filtered": len(filtered),
        "results_scraped": len(meaningful),
        "summary_length_chars": len(summary),
        "pipeline_duration_ms": total_ms,
        "errors": errors,
        "scenario_id": scenario["id"],
    })

    return {
        "scenario_id": scenario["id"],
        "domain": scenario["domain"],
        "audit_id": audit_id,
        "investigation_file": inv_fname,
        "results_found": len(results),
        "results_filtered": len(filtered),
        "results_pre_relevance": pre_relevance,
        "results_scraped": len(meaningful),
        "summary_length_chars": len(summary),
        "total_ms": total_ms,
        **{f"{k}_ms": v for k, v in timings_ms.items()},
    }


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

                print(f"[{scenario['id']}] execução {run_idx}/{args.runs} — query: '{scenario['query']}' ...", end=" ", flush=True)
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
