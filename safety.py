"""
safety.py — Salvaguarda ética antes da raspagem.

Uma ferramenta OSINT para a dark web encontra, inevitavelmente, ligações a
conteúdo ilegal, em particular material de abuso sexual de menores. Esta
salvaguarda impede que o raspador PEÇA a URL de uma fonte cujo título ou URL
indique esse tipo de conteúdo: o pedido nunca é feito, o texto nunca é
descarregado e nada é gravado.

Limites (declarar na metodologia):
  - É uma lista de padrões, uma salvaguarda de melhor esforço. Não deteta tudo
    (títulos enganadores, línguas não cobertas) e pode bloquear fontes legítimas
    (p. ex. páginas de prevenção ou denúncia que usam as mesmas palavras).
  - Não filtra a lista de resultados de pesquisa nem o Top-K: só impede o pedido.
  - O registo guarda apenas o padrão que casou, nunca o título bloqueado.

Configuração:
  - Padrões por omissão: DEFAULT_PATTERNS (expressões regulares, sem distinguir
    maiúsculas de minúsculas, aplicadas ao título e ao URL).
  - Padrões adicionais: config/blocked_terms.txt, um por linha (# comenta).
  - Desligar (só para diagnóstico, regista um aviso): DARKSHERLOCK_SAFETY_GUARD=off
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

EXTRA_PATTERNS_FILE = Path(__file__).resolve().parent / "config" / "blocked_terms.txt"

DEFAULT_PATTERNS = [
    r"child[\s_-]*porn",
    r"child[\s_-]*(abuse|sex|rape)",
    r"\bcsam\b",
    r"\bpedo(phil\w*|file\w*)?\b",
    r"pre[\s_-]?teen",
    r"jail[\s_-]?bait",
    r"\blolita\b",
    r"\bunderage\b",
    r"kidflix",
]


def _load_patterns() -> list[re.Pattern]:
    raw = list(DEFAULT_PATTERNS)
    if EXTRA_PATTERNS_FILE.is_file():
        for line in EXTRA_PATTERNS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                raw.append(line)
    compiled = []
    for p in raw:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error as e:
            logger.warning("Padrão de salvaguarda inválido ignorado (%s): %s", p, e)
    return compiled


def guard_enabled() -> bool:
    return os.getenv("DARKSHERLOCK_SAFETY_GUARD", "on").strip().lower() not in {"off", "0", "false", "no"}


def _match(item: dict, patterns: list[re.Pattern]) -> str | None:
    haystack = f"{item.get('title', '')} {item.get('link', '')}"
    for rx in patterns:
        if rx.search(haystack):
            return rx.pattern
    return None


def blocked_pattern(item: dict) -> str | None:
    """Devolve o padrão que casa com o título ou o URL do item, ou None se não for bloqueado."""
    if not guard_enabled():
        return None
    return _match(item, _load_patterns())


def split_blocked(items: list[dict]) -> tuple[list[dict], list[tuple[dict, str]]]:
    """Separa os itens em (permitidos, [(bloqueado, padrão)]). Avisa se a salvaguarda estiver desligada."""
    if not guard_enabled():
        logger.warning("Salvaguarda ética DESLIGADA (DARKSHERLOCK_SAFETY_GUARD=off).")
        return list(items), []
    allowed, blocked = [], []
    patterns = _load_patterns()  # uma vez por chamada
    for it in items:
        pat = _match(it, patterns)
        if pat:
            blocked.append((it, pat))
        else:
            allowed.append(it)
    return allowed, blocked
