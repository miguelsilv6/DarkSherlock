"""
evaluation/run_kinds.py — De que script de recolha veio cada investigação de avaliação.

run_scenarios, run_multi_model_eval e run_induced_resilience gravam todos
investigations/eval_<ID>_*.json. Só as de run_scenarios ("scenarios") seguem o
protocolo do Capítulo 6 (3 execuções por cenário); as de multi-modelo
("multi_model") repetem a bateria para medir a fiabilidade por modelo, e as
de resiliência induzida ("induced_resilience") correm com um motor desligado
de propósito. Misturá-las inflaciona o n e enviesa EQ-01..EQ-04.

Cada investigação nova grava "eval_run_kind". Para as que já existiam sem
esse campo, o tipo vem dos CSVs de cada script (coluna "investigation_file"),
sem alterar os JSONs, que são evidência. Sem nenhuma das duas fontes, conta
como "scenarios" (execuções anteriores a este campo, como até aqui).

As ferramentas de análise aceitam --run-kind (default "scenarios"; "any" para todas).
"""

from __future__ import annotations

import csv
import glob
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"
DEFAULT = "scenarios"
KINDS = ("scenarios", "multi_model", "induced_resilience")
_CSV_PREFIX = {"raw_runs_": "scenarios", "multi_model_runs_": "multi_model",
               "induced_resilience_": "induced_resilience"}


def index(results_dir: Path | str | None = None) -> dict[str, str]:
    """{nome do ficheiro da investigação: tipo}, a partir dos CSVs de cada script de recolha."""
    results_dir = RESULTS_DIR if results_dir is None else results_dir
    out: dict[str, str] = {}
    for prefix, kind in _CSV_PREFIX.items():
        for path in sorted(glob.glob(str(Path(results_dir) / f"{prefix}*.csv"))):
            try:
                with open(path, newline="", encoding="utf-8") as fh:
                    for row in csv.DictReader(fh):
                        name = Path(row.get("investigation_file") or "").name
                        if name:
                            out[name] = kind
            except (OSError, csv.Error):
                continue
    return out


def kind_of(inv: dict, filename: str, idx: dict[str, str]) -> str:
    return inv.get("eval_run_kind") or idx.get(Path(filename).name) or DEFAULT


def keep(inv: dict, filename: str, idx: dict[str, str], wanted: str | None) -> bool:
    return wanted == "any" or kind_of(inv, filename, idx) == (wanted or DEFAULT)


def add_argument(parser) -> None:
    parser.add_argument(
        "--run-kind", default=DEFAULT, choices=(*KINDS, "any"),
        help=f'Só investigações deste tipo de recolha (default: {DEFAULT}, as do protocolo; "any" = todas).',
    )
