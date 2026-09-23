"""
evaluation/run_refusal_ablation.py — Protocolo ablativo de mitigação de
recusas do EQ-07 (Capítulo 6, secção 6.4.7).

Cada cenário é executado numa única passagem pelas etapas 2-5 do pipeline
(refine_query, get_search_results, filter_results, scrape_multiple,
filter_scraped_by_relevance) — reutilizadas tal-qual de run_scenarios.py,
sem duplicar lógica — e o conteúdo scrapeado resultante é depois passado a
generate_summary() QUATRO vezes, uma por variante de mitigação:

    (i)   baseline      — sem persona, sem autorização, sem anti-recusa
    (ii)  persona        — só persona DFIR
    (iii) persona_auth   — persona + cadeia de autorização explícita
    (iv)  full            — persona + autorização + reframing (completo)

Correr a pesquisa/scraping uma única vez por cenário×modelo (em vez de uma
vez por variante) garante o desenho emparelhado que o protocolo exige
("mesmo modelo, mesma query, prompts diferentes" — Capítulo 6) e evita que
variação de rede/Tor entre chamadas confunda o efeito do prompt: as 4
variantes recebem exactamente o mesmo `content`, isolando a única variável
que muda.

A deteção de recusa reutiliza a MESMA lógica que já corre em produção
(llm._classify_refusal, chamada dentro de generate_summary() e exposta via
um WARNING no logger 'llm') — não uma reimplementação à parte — para que a
taxa medida aqui corresponda exactamente ao que um utilizador real veria.

Pré-requisitos: iguais a run_scenarios.py — Tor em 127.0.0.1:9050.

Uso:
    python evaluation/run_refusal_ablation.py
    python evaluation/run_refusal_ablation.py --scenarios A1,B2,C3
    python evaluation/run_refusal_ablation.py \\
        --models "Qwen2.5-0.5B (embutido, ultraleve);Llama-3.2-3B (embutido, médio)"
"""

from __future__ import annotations

import argparse
import csv
import logging
import re
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import run_scenarios as base  # noqa: E402
import llm  # noqa: E402
from llm_utils import get_model_choices  # noqa: E402
from search import get_search_results  # noqa: E402
from scrape import scrape_multiple  # noqa: E402
from audit import setup_file_logging  # noqa: E402

# Slug seguro para nomes de ficheiro a partir do label do modelo (que contém
# parênteses, vírgulas e espaços, ex. "Qwen2.5-0.5B (embutido, ultraleve)").
_RE_SLUG = re.compile(r"[^a-zA-Z0-9]+")


def _slug(text: str) -> str:
    return _RE_SLUG.sub("_", text).strip("_").lower()


class _RefusalCapture(logging.Handler):
    """Handler temporário: regista se generate_summary() emitiu o WARNING de
    recusa (llm._flag_refusal) durante uma única chamada, e qual o tipo."""

    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.messages.append(record.getMessage())
        except Exception:
            pass

    @property
    def refusal_type(self) -> str:
        for msg in self.messages:
            if "recusa total detectada" in msg:
                return "total"
            if "recusa partial detectada" in msg:
                return "partial"
        return "none"


def _prepare_content(scenario: dict, llm_instance) -> tuple[str, dict]:
    """Corre as etapas 2-5 do pipeline uma única vez, devolve (refined_query, meaningful)."""
    refined = llm.refine_query(llm_instance, scenario["query"], preset=scenario["preset"])
    results, _engine_status = get_search_results(refined, max_workers=base.THREADS)
    if len(results) > base.MAX_RESULTS:
        results = results[:base.MAX_RESULTS]
    filtered = llm.filter_results(llm_instance, refined, results)
    if len(filtered) > base.MAX_SCRAPE:
        filtered = filtered[:base.MAX_SCRAPE]
    scraped = scrape_multiple(filtered, max_workers=base.THREADS)
    meaningful = {u: c for u, c in scraped.items() if len(c) > 150}
    meaningful = llm.filter_scraped_by_relevance(scenario["query"], meaningful)
    return refined, meaningful


def run_one_ablation(scenario: dict, model_choice: str, llm_instance, out_dir: Path) -> list[dict]:
    """Executa as 4 variantes de mitigação para um cenário×modelo. Devolve uma linha por variante."""
    refined, meaningful = _prepare_content(scenario, llm_instance)

    rows = []
    for level in llm.MITIGATION_LEVELS:
        handler = _RefusalCapture()
        llm_logger = logging.getLogger("llm")
        llm_logger.addHandler(handler)
        t0 = time.time()
        try:
            summary = llm.generate_summary(
                llm_instance, refined, dict(meaningful),
                preset=scenario["preset"], mitigation_level=level,
            )
        finally:
            llm_logger.removeHandler(handler)
        duration_ms = round((time.time() - t0) * 1000)

        refusal_type = handler.refusal_type
        rows.append({
            "scenario_id": scenario["id"],
            "domain": scenario["domain"],
            "model": model_choice,
            "mitigation_level": level,
            "refusal_type": refusal_type,
            "refused": int(refusal_type != "none"),
            "summary_length_chars": len(summary),
            "duration_ms": duration_ms,
            "sources_used": len(meaningful),
        })

        # Guarda o texto completo para auditoria manual — a classificação por
        # substring (llm._classify_refusal) pode ter falsos positivos/negativos
        # e a única forma honesta de o confirmar é ler o output real.
        out_path = out_dir / f"{scenario['id']}_{_slug(model_choice)}_{level}.md"
        out_path.write_text(summary, encoding="utf-8")

    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenarios", type=str, default=None,
                        help="Lista separada por vírgulas de IDs a correr (ex.: A1,B2). Omitir corre os 12.")
    parser.add_argument("--models", type=str, default=None,
                        help="Modelos separados por ';' (não ','). Omitir usa apenas o primeiro disponível.")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Diretório de saída (default: evaluation/results/).")
    args = parser.parse_args()

    setup_file_logging()

    tor_ok, _ = base.ensure_tor()
    if not tor_ok:
        print("ERRO: Tor não está acessível em 127.0.0.1:9050 — arranca o Tor manualmente antes de correr a avaliação.")
        sys.exit(1)

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

    available_models = get_model_choices()
    if not available_models:
        print("ERRO: nenhum modelo LLM disponível (Ollama offline e llama-cpp-python não instalado?).")
        sys.exit(1)
    if args.models:
        requested = [m.strip() for m in args.models.split(";") if m.strip()]
        unknown = [m for m in requested if m not in available_models]
        if unknown:
            print(f"AVISO: modelos desconhecidos ignorados: {unknown}")
        models = [m for m in requested if m in available_models]
        if not models:
            print(f"ERRO: nenhum modelo válido em --models. Disponíveis: {available_models}")
            sys.exit(1)
    else:
        models = [available_models[0]]

    out_dir = Path(args.output_dir) if args.output_dir else base.RESULTS_DIR
    reports_dir = out_dir / "refusal_ablation"
    reports_dir.mkdir(parents=True, exist_ok=True)

    total_calls = len(models) * len(scenarios) * len(llm.MITIGATION_LEVELS)
    print(f"Modelos: {models}")
    print(f"Cenários: {[s['id'] for s in scenarios]}")
    print(f"Variantes de mitigação: {llm.MITIGATION_LEVELS}")
    print(f"{len(models)} modelos × {len(scenarios)} cenários × {len(llm.MITIGATION_LEVELS)} variantes "
          f"= {total_calls} chamadas a generate_summary() no total "
          f"(pesquisa/scraping correm só {len(models) * len(scenarios)} vezes, uma por cenário×modelo).\n")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = out_dir / f"refusal_ablation_{ts}.csv"
    all_rows: list[dict] = []

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = None
        for model_choice in models:
            print(f"\n=== Modelo: {model_choice} ===")
            try:
                t0 = time.time()
                llm_instance = llm.get_llm(model_choice)
                print(f"Etapa 1 (Load LLM): {round((time.time() - t0) * 1000)} ms")
            except Exception as e:
                print(f"ERRO ao carregar o modelo '{model_choice}': {e} — a saltar.")
                continue

            for scenario in scenarios:
                tor_ok, _ = base.ensure_tor()
                if not tor_ok:
                    print(f"[{model_choice}][{scenario['id']}] SALTADO: Tor inacessível.")
                    continue

                print(f"[{model_choice}][{scenario['id']}] a preparar conteúdo (etapas 2-5, uma vez)...", end=" ", flush=True)
                try:
                    rows = run_one_ablation(scenario, model_choice, llm_instance, reports_dir)
                except Exception as e:
                    print(f"FALHOU: {e}")
                    all_rows.append({"scenario_id": scenario["id"], "model": model_choice, "error": str(e)})
                    continue
                print("OK")

                for row in rows:
                    all_rows.append(row)
                    if writer is None:
                        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
                        writer.writeheader()
                    writer.writerow(row)
                    f.flush()
                    note = f" [{row['refusal_type']}]" if row["refused"] else ""
                    print(f"    {row['mitigation_level']:<12} {row['duration_ms']:>7} ms "
                          f"{row['summary_length_chars']:>6} chars{note}")

    print(f"\nDados brutos: {csv_path}")
    print(f"Relatórios completos por execução (para auditoria manual): {reports_dir}/")

    valid = [r for r in all_rows if "refused" in r]
    if not valid:
        print("\nNenhuma execução válida — nada a resumir.")
        return

    print("\n=== EQ-07 — Taxa de recusa por modelo × variante (Tabela 15) ===")
    header = f"| Modelo | " + " | ".join(llm.MITIGATION_LEVELS) + " |"
    print(header)
    print("|" + "---|" * (len(llm.MITIGATION_LEVELS) + 1))
    for model_choice in models:
        cells = []
        for level in llm.MITIGATION_LEVELS:
            rows = [r for r in valid if r["model"] == model_choice and r["mitigation_level"] == level]
            if not rows:
                cells.append("—")
                continue
            rate = 100 * sum(r["refused"] for r in rows) / len(rows)
            cells.append(f"{rate:.0f}% (n={len(rows)})")
        print(f"| {model_choice} | " + " | ".join(cells) + " |")

    print("\nPróximo passo: evaluation/analyze_refusal_ablation.py calcula o teste de "
          "McNemar (comparação emparelhada baseline vs. full, por modelo) sobre este CSV.")


if __name__ == "__main__":
    main()
