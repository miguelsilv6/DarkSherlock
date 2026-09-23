"""
evaluation/run_induced_resilience.py — "Resiliência induzida" do EQ-06
(Capítulo 6, secção 6.4.6): em N cenários experimentais, desativa-se
deliberadamente um motor de pesquisa importante durante a execução e
mede-se o "tempo de recuperação" — o tempo até o pipeline completar sem
esse motor.

Mecanismo de indução de falha:
  get_search_results() despacha todos os motores em paralelo num único
  round (sem retentativas entre motores) — não existe um instante "a meio"
  da execução em que desligar um motor cancele um pedido já em curso.
  Reproduz-se por isso a falha da forma que é externamente indistinguível
  de uma falha real (a mesma que a resiliência OBSERVADA mede quando ocorre
  espontaneamente): intercepta-se search.fetch_search_results só para o
  URL do motor-alvo (devolvendo ([], False) — o mesmo formato que uma falha
  real de rede produz), delegando na função real para todos os outros
  motores. run_one() do pipeline real corre inalterado; o URL original nunca
  é tocado e o monkey-patch é revertido no final, mesmo em caso de erro ou
  interrupção.

  Uma alternativa mais óbvia — substituir temporariamente o URL do motor em
  config/search_engines.json por um endereço morto — foi tentada e
  descartada: engine_manager.load_engines() sincroniza builtins por URL, não
  por nome, e ao deixar de encontrar o URL real do motor na configuração
  volta a adicioná-lo como uma entrada NOVA (duplicada, activa) na primeira
  chamada a get_active_engines() dentro do próprio pipeline — mascarando a
  falha induzida com um "gémeo" funcional do mesmo motor. Intercetar a
  função de fetch evita esta interação com a sincronização de builtins e
  não escreve nada em disco.

  Cada execução só conta para a métrica se engine_status confirmar que o
  motor-alvo de facto falhou (induction_confirmed) — sem essa confirmação,
  o "tempo de recuperação" registado não seria atribuível à falha induzida.

Uso:
    python evaluation/run_induced_resilience.py
    python evaluation/run_induced_resilience.py --scenarios A1,B2,C3 --engine Ahmia
    python evaluation/run_induced_resilience.py --model "Qwen2.5-1.5B (embutido, leve)"
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import engine_manager
import search as search_module
from run_scenarios import SCENARIOS, RESULTS_DIR, ensure_tor, run_one
from llm import get_llm
from llm_utils import get_model_choices

# Um cenário por domínio (Threat Intel, Ransomware/Malware, Identidade
# Pessoal) — três no total, conforme o texto do Capítulo 6 ("em três
# cenários experimentais"). Configurável via --scenarios.
DEFAULT_SCENARIOS = ["A1", "B2", "C3"]

# Ahmia: motor de referência mais citado na literatura OSINT dark web,
# listado em primeiro em SEARCH_ENGINES, e com 0% de falhas na amostra real
# de resiliência OBSERVADA (evaluation/analyze_engine_failures.py) — um bom
# candidato a "motor importante" precisamente por normalmente ser fiável.
DEFAULT_ENGINE = "Ahmia"


@contextmanager
def _induced_engine_failure(engine_name: str):
    """Força o motor indicado a falhar durante a janela do 'with', sem tocar
    em config/search_engines.json nem no URL do motor.

    Intercepta search.fetch_search_results: para o URL exacto do motor-alvo
    devolve ([], False) — o mesmo formato de retorno de uma falha real de
    rede (timeout, 5xx, circuito Tor degradado) — delegando na função real
    para todos os outros motores. Restaura a função original no final,
    mesmo em caso de excepção.
    """
    active = engine_manager.get_active_engines()
    target = next((e for e in active if e["name"] == engine_name), None)
    if target is None:
        raise ValueError(f"Motor '{engine_name}' não encontrado ou não está activo em config/search_engines.json.")
    if target.get("type", "simple") != "simple":
        raise ValueError(f"Motor '{engine_name}' é do tipo '{target.get('type')}' — este teste só suporta "
                          "motores 'simple' (contrato GET com {query}), que são os despachados via "
                          "fetch_search_results.")
    target_url = target["url"]

    real_fetch = search_module.fetch_search_results

    def _patched_fetch(endpoint, query, session=None):
        if endpoint == target_url:
            return [], False
        return real_fetch(endpoint, query, session)

    search_module.fetch_search_results = _patched_fetch
    try:
        yield
    finally:
        search_module.fetch_search_results = real_fetch


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenarios", type=str, default=",".join(DEFAULT_SCENARIOS),
                        help=f"IDs separados por vírgula (default: {','.join(DEFAULT_SCENARIOS)} — um por domínio).")
    parser.add_argument("--engine", type=str, default=DEFAULT_ENGINE,
                        help=f"Motor a desativar deliberadamente (default: {DEFAULT_ENGINE}).")
    parser.add_argument("--model", type=str, default=None, help="Modelo a usar (label exata da UI).")
    args = parser.parse_args()

    wanted = {s.strip().upper() for s in args.scenarios.split(",")}
    scenarios = [s for s in SCENARIOS if s["id"] in wanted]
    missing = wanted - {s["id"] for s in scenarios}
    if missing:
        print(f"AVISO: IDs desconhecidos ignorados: {missing}")
    if not scenarios:
        print("ERRO: nenhum cenário válido em --scenarios.")
        sys.exit(1)

    tor_ok, _ = ensure_tor()
    if not tor_ok:
        print("ERRO: Tor não está acessível em 127.0.0.1:9050 — arranca o Tor manualmente antes de correr este teste.")
        sys.exit(1)

    model_choice = args.model
    if not model_choice:
        choices = get_model_choices()
        if not choices:
            print("ERRO: nenhum modelo LLM disponível (Ollama offline e llama-cpp-python não instalado?).")
            sys.exit(1)
        model_choice = choices[0]

    print(f"Motor deliberadamente desativado: {args.engine}")
    print(f"Modelo: {model_choice}")
    print(f"Cenários: {[s['id'] for s in scenarios]}\n")

    t0 = time.time()
    llm = get_llm(model_choice)
    print(f"Etapa 1 (Load LLM): {round((time.time() - t0) * 1000)} ms\n")

    RESULTS_DIR.mkdir(exist_ok=True)
    csv_path = RESULTS_DIR / f"induced_resilience_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    rows = []

    for scenario in scenarios:
        tor_ok, _ = ensure_tor()
        if not tor_ok:
            print(f"[{scenario['id']}] SALTADO: Tor inacessível.")
            continue

        print(f"[{scenario['id']}] a desativar '{args.engine}' e a correr a investigação...", end=" ", flush=True)
        try:
            with _induced_engine_failure(args.engine):
                row = run_one(scenario, model_choice, llm)
        except Exception as e:
            print(f"FALHOU: {e}")
            rows.append({"scenario_id": scenario["id"], "engine_disabled": args.engine, "error": str(e)})
            continue

        row["engine_disabled"] = args.engine

        # Confirma que a falha foi de facto induzida (o motor-alvo aparece
        # como "failed" no engine_status desta execução) — sem isto o tempo
        # medido não seria atribuível à falha induzida.
        inv_files = sorted(Path("investigations").glob(f"eval_{scenario['id']}_*.json"))
        target_status = None
        if inv_files:
            data = json.loads(inv_files[-1].read_text(encoding="utf-8"))
            target_status = data.get("engine_status", {}).get(args.engine)
        row["target_engine_status"] = target_status
        row["induction_confirmed"] = target_status == "failed"
        rows.append(row)

        note = "indução confirmada" if row["induction_confirmed"] else \
            "AVISO: motor não reportou falha — execução não conta para a métrica"
        print(f"OK ({row['total_ms']} ms, {row['results_found']} resultados, {note})")

    if not rows:
        print("\nNenhuma execução completada.")
        sys.exit(1)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = sorted({k for r in rows for k in r.keys()})
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nDados brutos: {csv_path}")

    valid = [r for r in rows if r.get("induction_confirmed")]
    print("\n=== EQ-06 — Resiliência induzida: tempo de recuperação ===")
    print(f"Execuções com falha induzida confirmada: {len(valid)}/{len(rows)}")
    if valid:
        for r in valid:
            print(f"  {r['scenario_id']}: {r['total_ms'] / 1000:.1f}s, {r['results_found']} resultados, "
                  f"{r['engines_failed']}/{r['engines_attempted']} motores falhados no total")
        times_s = [r["total_ms"] / 1000 for r in valid]
        print(f"  Tempo de recuperação médio: {statistics.mean(times_s):.1f}s"
              + (f" (DP: {statistics.stdev(times_s):.1f}s)" if len(times_s) > 1 else ""))
        completed = [r for r in valid if r.get("results_found", 0) > 0]
        print(f"  Pipeline completou com resultados apesar da falha induzida: "
              f"{len(completed)}/{len(valid)} ({100 * len(completed) / len(valid):.1f}%) "
              "— evidência de graceful degradation (RNF-09).")
    else:
        print("Nenhuma execução confirmou a falha induzida — não repetir sem investigar a causa "
              "(o motor-alvo já estava indisponível por outra razão? o URL usado na verificação de "
              "engine_status não corresponde ao motor efetivamente intercetado?).")
    print()


if __name__ == "__main__":
    main()
