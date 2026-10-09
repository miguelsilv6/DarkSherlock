"""
evaluation/diag_stage4.py — Diagnóstico da Etapa 4 (filter_results) com um modelo.

Reexecuta APENAS a Etapa 4 sobre os "search_results" de uma investigação já
gravada e mostra a resposta crua do LLM (texto, motivo de paragem, n.º de
tokens), para perceber porque é que um modelo devolve NONE, texto ilegível ou
um ranking válido. Não acede à rede Tor nem toca nos ficheiros de investigação.

Uso:
    python evaluation/diag_stage4.py --model "gpt-oss-16k:latest" \\
        --file investigations/eval_A1_20261009_134507.json
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_core.callbacks.base import BaseCallbackHandler  # noqa: E402

from llm import filter_results, get_llm  # noqa: E402


class _RawOutput(BaseCallbackHandler):
    def __init__(self):
        self.calls = []

    def on_llm_end(self, response, **kwargs):
        for gens in response.generations:
            for g in gens:
                info = getattr(g, "generation_info", None) or {}
                msg = getattr(g, "message", None)
                self.calls.append({
                    "text": g.text,
                    "generation_info": info,
                    "additional_kwargs": getattr(msg, "additional_kwargs", {}) if msg else {},
                    "usage": getattr(msg, "usage_metadata", None) if msg else None,
                })


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True)
    ap.add_argument("--file", required=True, help="Investigação eval_*.json com 'search_results'.")
    ap.add_argument("--query", default=None, help="Query da Etapa 4 (por omissão, 'refined_query' do ficheiro).")
    ap.add_argument("--show-reasoning", action="store_true",
                    help="Modelos de raciocínio (Ollama): pede o raciocínio ao servidor e mostra-o em "
                         "additional_kwargs['reasoning_content']. Só para diagnóstico; não altera o pipeline.")
    args = ap.parse_args()

    data = json.loads(Path(args.file).read_text(encoding="utf-8"))
    results = data.get("search_results")
    if not results:
        print("ERRO: o ficheiro não tem 'search_results'.")
        return 1
    query = args.query or data.get("refined_query") or data["query"]

    llm = get_llm(args.model)
    if args.show_reasoning:
        if not hasattr(llm, "reasoning"):
            print("AVISO: este modelo não suporta 'reasoning' (só ChatOllama).")
        else:
            llm.reasoning = True
    handler = _RawOutput()
    llm.callbacks = [handler]

    print(f"Modelo: {args.model} · query: {query!r} · {len(results)} resultados")
    t0 = time.time()
    top = filter_results(llm, query, results)
    elapsed = time.time() - t0

    print(f"\nTempo: {elapsed:.0f} s · chamadas ao LLM: {len(handler.calls)} · devolvidos: {len(top)}")
    for i, c in enumerate(handler.calls, 1):
        print(f"\n--- chamada {i} ---")
        print("texto cru:", repr(c["text"][:1500]))
        print("generation_info:", {k: v for k, v in c["generation_info"].items() if k != "context"})
        kw = dict(c["additional_kwargs"])
        reasoning = kw.pop("reasoning_content", None)
        print("additional_kwargs:", kw)
        if reasoning:
            print("raciocínio (primeiros 3000 chars):", reasoning[:3000])
        print("usage:", c["usage"])

    first20 = [r["link"] for r in results[:20]]
    got = [r["link"] for r in top]
    print("\nIgual aos 20 primeiros (sem ranking)?", got == first20[:len(got)])
    return 0


if __name__ == "__main__":
    sys.exit(main())
