"""
evaluation/reclassify_refusals.py — Reaplica llm._classify_refusal() (versão
actual) aos relatórios já gerados por run_refusal_ablation.py, sem repetir
nenhuma chamada ao LLM.

Motivação: uma auditoria manual ao EQ-07 encontrou um falso positivo real —
o marcador "conteúdo ilegal" disparava em relatórios legítimos que descrevem
um marketplace da dark web como vendendo "conteúdo ilegal" (uma observação
forense correta, não uma recusa do modelo). O marcador foi removido de
llm._REFUSAL_MARKERS (ver comentário em llm.py), mas os CSVs já recolhidos
antes da correção ainda reflectem a classificação antiga.

Como os marcadores só foram REMOVIDOS (nunca adicionados), reclassificar só
pode DESCER uma execução de "total"/"partial" para "none" — nunca o
contrário. Não há risco de a correção introduzir um falso positivo novo.

Para cada linha com refused=1 (as únicas que podem mudar), lê o ficheiro
.md correspondente, remove um eventual banner de aviso já prepended (de uma
classificação antiga), reclassifica o texto original com a versão actual
do classificador, e:
  - Se a classificação mudar para "none": reescreve o .md sem o banner e
    sem o antigo aviso de recusa.
  - Se a classificação se mantiver: não toca no ficheiro.
Escreve um novo CSV "<original>_reclassified.csv" com os valores
corrigidos, preservando o CSV original tal como foi recolhido.

Uso:
    python evaluation/reclassify_refusals.py evaluation/results/refusal_ablation_*.csv
"""

from __future__ import annotations

import csv
import glob
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import llm  # noqa: E402
from run_refusal_ablation import _slug  # noqa: E402

_BANNER_RE = re.compile(r"^> ⚠️.*?\n\n", re.DOTALL)


def _strip_banner(text: str) -> str:
    """Remove um banner de aviso (_flag_refusal ou _flag_scaffold_echo) do início do texto, se existir."""
    return _BANNER_RE.sub("", text, count=1)


def _report_path(reports_dir: Path, scenario_id: str, model: str, level: str) -> Path:
    return reports_dir / f"{scenario_id}_{_slug(model)}_{level}.md"


def reclassify_csv(csv_path: Path, reports_dir: Path) -> None:
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print(f"{csv_path}: vazio, a saltar.")
        return
    fieldnames = list(rows[0].keys())

    changed = []
    for row in rows:
        if row.get("refused") != "1":
            continue  # só "total"/"partial" podem descer para "none" — "none" nunca muda

        path = _report_path(reports_dir, row["scenario_id"], row["model"], row["mitigation_level"])
        if not path.is_file():
            print(f"AVISO: relatório não encontrado para {row['scenario_id']}/{row['model']}/"
                  f"{row['mitigation_level']} em {path} — linha mantida sem alteração.")
            continue

        raw = _strip_banner(path.read_text(encoding="utf-8"))
        new_kind = llm._classify_refusal(raw)
        old_kind = row["refusal_type"]

        if new_kind == old_kind:
            continue

        changed.append((row["scenario_id"], row["model"], row["mitigation_level"], old_kind, new_kind))
        row["refusal_type"] = new_kind
        row["refused"] = "1" if new_kind != "none" else "0"

        if new_kind == "none":
            path.write_text(raw, encoding="utf-8")
        else:
            path.write_text(llm._flag_refusal(raw), encoding="utf-8")

    out_path = csv_path.with_name(csv_path.stem + "_reclassified.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"{csv_path.name} -> {out_path.name}: {len(changed)} linha(s) reclassificada(s).")
    for scenario_id, model, level, old_kind, new_kind in changed:
        print(f"  {scenario_id} / {model} / {level}: {old_kind!r} -> {new_kind!r}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    reports_dir = Path("evaluation/results/refusal_ablation")
    if not reports_dir.is_dir():
        print(f"ERRO: diretório de relatórios não encontrado em {reports_dir} "
              "— corre este script a partir da raiz do projeto.")
        sys.exit(1)

    paths: list[Path] = []
    for pattern in sys.argv[1:]:
        matched = glob.glob(pattern)
        if not matched and Path(pattern).is_file():
            matched = [pattern]
        paths.extend(Path(p) for p in matched)

    if not paths:
        print("Nenhum CSV encontrado para os padrões indicados.")
        sys.exit(1)

    for csv_path in sorted(paths):
        reclassify_csv(csv_path, reports_dir)


if __name__ == "__main__":
    main()
