"""
evaluation/versions.py — Versão do pipeline nas ferramentas de avaliação.

Cada investigação grava "pipeline_version" (config.PIPELINE_VERSION); as que
não têm o campo são anteriores à revisão geral ("1.0-legacy"). Resultados de
versões diferentes não são comparáveis, por isso as ferramentas de avaliação
(check_runs, pool_preview, tabela13, eq02_eq03, eq04_review):

  - aceitam --pipeline-version VERSAO (ou "any") para escolher a versão;
  - sem essa opção, recusam misturar versões: se as execuções selecionadas
    (modelo, data) tiverem mais do que uma versão, param com uma mensagem que
    as lista, em vez de produzir números que misturam código antigo e novo.
"""

from __future__ import annotations

import sys

LEGACY = "1.0-legacy"


def version_of(inv: dict) -> str:
    return inv.get("pipeline_version") or LEGACY


def add_argument(parser) -> None:
    parser.add_argument(
        "--pipeline-version", default=None,
        help=f'Só execuções desta versão do pipeline (p. ex. "2.0" ou "{LEGACY}"); "any" aceita todas. '
             "Sem esta opção, a ferramenta para se as execuções selecionadas misturarem versões.",
    )


def keep(inv: dict, wanted: str | None) -> bool:
    """A investigação entra na seleção? (None/"any" = todas, a mistura é verificada depois)."""
    return wanted in (None, "any") or version_of(inv) == wanted


def mixed_error(invs, wanted: str | None) -> str | None:
    """Mensagem de erro se `invs` misturam versões e não foi escolhida nenhuma; senão None."""
    if wanted is not None:
        return None
    counts: dict[str, int] = {}
    for inv in invs:
        v = version_of(inv)
        counts[v] = counts.get(v, 0) + 1
    if len(counts) <= 1:
        return None
    listing = ", ".join(f"{v}: {n}" for v, n in sorted(counts.items()))
    return (f"As execuções selecionadas misturam versões do pipeline ({listing}). "
            f'Escolhe uma com --pipeline-version (p. ex. --pipeline-version 2.0), ou "any" para as juntar.')


def exit_if_mixed(invs, wanted: str | None) -> None:
    msg = mixed_error(invs, wanted)
    if msg:
        print(f"ERRO: {msg}", file=sys.stderr)
        raise SystemExit(2)
