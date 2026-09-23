"""
evaluation/analyze_refusal_ablation.py — Agrega os CSVs produzidos por
run_refusal_ablation.py e calcula os dois resultados que o EQ-07 pede
(Capítulo 6, secções 6.4.7 e "Resultados — Mitigação de Recusas dos LLMs"):

  1. Tabela 15 — taxa de recusa (%) por modelo × variante de mitigação
     (baseline / persona / persona_auth / full), com n por célula.
  2. Teste de McNemar (1947) — compara a taxa de recusa em condições
     emparelhadas (mesmo modelo, mesmo cenário, prompts diferentes), para
     cada par consecutivo de variantes e para o par baseline vs. full (o
     "efeito conjunto das três camadas" que o texto do capítulo pede
     explicitamente).

Implementação do teste de McNemar sem dependências externas (sem scipy):
  - n = b + c < 25 (par discordante pequeno, o caso típico aqui com ≤12
    cenários): teste exacto via distribuição binomial (math.comb), que é a
    forma recomendada para amostras pequenas — a aproximação chi-quadrado
    não é fiável abaixo de ~25 pares discordantes.
  - n >= 25: chi-quadrado com correção de continuidade de Yates, a forma
    clássica do teste (McNemar, 1947).
Ambos são casos do mesmo teste (comparação de proporções emparelhadas
binárias); a escolha automática entre eles segue a prática estatística
padrão, não uma decisão ad-hoc para este trabalho.

Uso:
    python evaluation/analyze_refusal_ablation.py evaluation/results/refusal_ablation_*.csv
"""

from __future__ import annotations

import csv
import glob
import sys
from collections import defaultdict
from math import comb
from pathlib import Path

MITIGATION_LEVELS = ("baseline", "persona", "persona_auth", "full")


def _load_rows(patterns: list[str]) -> list[dict]:
    paths: list[Path] = []
    for pattern in patterns:
        matched = glob.glob(pattern)
        if not matched and Path(pattern).is_file():
            matched = [pattern]
        paths.extend(Path(p) for p in matched)

    rows = []
    for p in sorted(paths):
        with open(p, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if "refused" not in row or row["refused"] == "":
                    continue  # linha de erro (execução falhada), sem dados de recusa
                row["refused"] = int(row["refused"])
                rows.append(row)
    return rows


def mcnemar_exact_p(b: int, c: int) -> float:
    """P-value exacto (binomial, 2-sided) para b/c pares discordantes."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    cum = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * cum)


def mcnemar_chi2_p(b: int, c: int) -> tuple[float, float]:
    """Estatística chi-quadrado com correção de Yates e p-value aproximado (2 graus... 1 g.l.).

    Aproximação da função de distribuição chi-quadrado com 1 g.l. via a
    relação com a função erro (sem depender de scipy): p = erfc(sqrt(chi2/2)).
    """
    from math import erfc, sqrt
    n = b + c
    if n == 0:
        return 0.0, 1.0
    chi2 = ((abs(b - c) - 1) ** 2) / n
    p = erfc(sqrt(chi2 / 2))
    return chi2, p


def mcnemar_test(b: int, c: int) -> dict:
    n = b + c
    if n < 25:
        return {"method": "exact", "b": b, "c": c, "n_discordant": n, "p_value": mcnemar_exact_p(b, c)}
    chi2, p = mcnemar_chi2_p(b, c)
    return {"method": "chi2_yates", "b": b, "c": c, "n_discordant": n, "chi2": chi2, "p_value": p}


def refusal_rate_table(rows: list[dict]) -> None:
    models = sorted({r["model"] for r in rows})
    print("=== EQ-07 — Tabela 15: taxa de recusa (%) por modelo × variante ===\n")
    header = "| Modelo | " + " | ".join(MITIGATION_LEVELS) + " |"
    print(header)
    print("|" + "---|" * (len(MITIGATION_LEVELS) + 1))
    for model in models:
        cells = []
        for level in MITIGATION_LEVELS:
            subset = [r for r in rows if r["model"] == model and r["mitigation_level"] == level]
            if not subset:
                cells.append("—")
                continue
            rate = 100 * sum(r["refused"] for r in subset) / len(subset)
            cells.append(f"{rate:.0f}% (n={len(subset)})")
        print(f"| {model} | " + " | ".join(cells) + " |")
    print()


def mcnemar_report(rows: list[dict]) -> None:
    models = sorted({r["model"] for r in rows})
    print("=== EQ-07 — Teste de McNemar (comparações emparelhadas por cenário) ===\n")

    pairs = list(zip(MITIGATION_LEVELS, MITIGATION_LEVELS[1:])) + [(MITIGATION_LEVELS[0], MITIGATION_LEVELS[-1])]
    for model in models:
        print(f"--- {model} ---")
        # index por (scenario_id, mitigation_level) -> refused (0/1)
        by_key: dict[tuple[str, str], int] = {}
        for r in rows:
            if r["model"] != model:
                continue
            by_key[(r["scenario_id"], r["mitigation_level"])] = r["refused"]

        scenario_ids = sorted({sid for (sid, _lvl) in by_key})
        for level_a, level_b in pairs:
            paired = [
                (by_key[(sid, level_a)], by_key[(sid, level_b)])
                for sid in scenario_ids
                if (sid, level_a) in by_key and (sid, level_b) in by_key
            ]
            if not paired:
                continue
            b = sum(1 for a, bb in paired if a == 1 and bb == 0)  # refutou em A, não em B
            c = sum(1 for a, bb in paired if a == 0 and bb == 1)  # não refutou em A, refutou em B
            result = mcnemar_test(b, c)
            label = f"{level_a} → {level_b}"
            sig = " *" if result["p_value"] < 0.05 else ""
            print(f"  {label:<20} n={len(paired):>2}  b={b} c={c}  método={result['method']:<10} "
                  f"p={result['p_value']:.4f}{sig}")
        print()
    print("(* p < 0.05. Nota: com poucos cenários pareados, o teste exacto tem baixo poder — "
          "um p não-significativo não implica ausência de efeito, só que a amostra é pequena "
          "para o detectar com confiança.)\n")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    rows = _load_rows(sys.argv[1:])
    if not rows:
        print("Nenhuma linha válida encontrada nos CSVs indicados.")
        sys.exit(1)

    print(f"Linhas carregadas: {len(rows)}\n")
    refusal_rate_table(rows)
    mcnemar_report(rows)


if __name__ == "__main__":
    main()
