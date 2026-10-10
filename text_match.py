"""
text_match.py — Correspondência entre a query e o texto (Etapas 4 e 5).

Substitui a comparação por subcadeia com tokenização só por espaços. Trata:
  - maiúsculas e acentos (NFKD), pontuação colada aos termos;
  - stopwords em português e inglês;
  - frases entre aspas ("cobalt strike") como um só termo;
  - entidades com variantes de escrita: emails ("user [at] dominio [dot] pt"),
    números de identificação com espaços/pontos/traços ("999 999 999"),
    domínios e endereços .onion;
  - termos-chave (nomes, entidades, palavras raras) vs. termos de contexto
    ("leak", "forum", "dump", ...), que aparecem em quase todas as páginas da
    dark web — incluindo o spam de SEO — e por isso pesam menos.

Funções principais:
  - query_terms(query) -> list[Term]
  - match(text, terms) -> Match (termos encontrados, termos-chave encontrados, pontuação)
  - is_relevant(match, terms) -> bool (limiar graduado, ver docstring)
  - best_window(text, terms, size) -> excerto de `size` caracteres com mais termos
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, field

STOPWORDS = {
    # inglês
    "the", "and", "for", "with", "from", "that", "this", "are", "was", "were", "has", "have", "not", "but",
    "you", "your", "our", "all", "any", "can", "how", "what", "who", "where", "when", "into", "about", "via",
    # português
    "para", "por", "com", "sem", "dos", "das", "nos", "nas", "uma", "uns", "umas", "que", "como", "mais",
    "sobre", "entre", "pelo", "pela", "pelos", "pelas", "este", "esta", "isto", "esse", "essa", "isso", "seu",
    "sua", "seus", "suas", "ser", "ter", "foi", "sao", "nao", "dados",
    # genéricos de páginas .onion
    "site", "sites", "www", "http", "https", "com", "org", "net", "onion", "page", "pages", "home", "index",
    "search", "link", "links", "list", "dark", "web", "darkweb", "deep", "deepweb", "tor",
}

# Termos de contexto: descrevem o tipo de conteúdo, não o alvo. Contam, mas
# pesam menos e não bastam sozinhos quando a query tem termos-chave.
CONTEXT = {
    "leak", "leaks", "leaked", "dump", "dumps", "forum", "forums", "market", "markets", "marketplace",
    "paste", "pastes", "breach", "breaches", "database", "databases", "db", "data", "service", "services",
    "group", "groups", "ransomware", "malware", "source", "code", "internal", "credential", "credentials",
    "api", "key", "keys", "wiki", "access", "broker", "brokers", "sale", "sell", "selling", "buy", "shop",
    "fuga", "fugas", "venda", "mercado", "grupo", "nif", "email", "mail", "password", "passwords", "login",
    "victim", "victims", "vitima", "vitimas", "blog", "news", "2024", "2025", "2026", "2027",
}

CONTEXT_WEIGHT = 0.5

_RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.UNICODE)
_RE_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:[a-z]{2,24})\b", re.IGNORECASE)
_RE_ID_DIGITS = re.compile(r"\d[\d\s.\-]{4,}\d")
_RE_QUOTED = re.compile(r"\"([^\"]+)\"|“([^”]+)”")
_RE_WORD = re.compile(r"[\w][\w\-]*", re.UNICODE)


def fold(text: str) -> str:
    """Minúsculas e sem acentos."""
    nfkd = unicodedata.normalize("NFKD", text or "")
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower()


def _normalize_text(text: str) -> str:
    t = fold(text)
    # emails ofuscados: "user [at] dominio [dot] pt", "user(at)dominio.pt"
    t = re.sub(r"\s*[\[\(\{]\s*(at|arroba)\s*[\]\)\}]\s*", "@", t)
    t = re.sub(r"\s*[\[\(\{]\s*(dot|ponto)\s*[\]\)\}]\s*", ".", t)
    return t


def _digits_only(text: str) -> str:
    """Junta sequências de dígitos separadas por espaço/ponto/traço ("999 999 999" -> "999999999")."""
    return re.sub(r"(?<=\d)[\s.\-](?=\d)", "", text)


@dataclass
class Term:
    text: str              # forma normalizada a procurar
    kind: str              # "phrase" | "email" | "id" | "domain" | "word"
    key: bool              # termo-chave (True) ou de contexto (False)

    @property
    def weight(self) -> float:
        return 1.0 if self.key else CONTEXT_WEIGHT


@dataclass
class Match:
    found: list = field(default_factory=list)
    key_found: int = 0
    key_total: int = 0
    context_found: int = 0
    context_total: int = 0
    score: float = 0.0


def query_terms(query: str) -> list[Term]:
    q = query or ""
    terms: list[Term] = []
    seen: set[str] = set()

    def add(text, kind, key):
        if text and text not in seen:
            seen.add(text)
            terms.append(Term(text, kind, key))

    rest = q
    for m in _RE_QUOTED.finditer(q):
        phrase = " ".join(fold(m.group(1) or m.group(2)).split())
        add(phrase, "phrase", True)
        rest = rest.replace(m.group(0), " ")
    for m in _RE_EMAIL.finditer(rest):
        add(fold(m.group(0)), "email", True)
        rest = rest.replace(m.group(0), " ")
    for m in _RE_ID_DIGITS.finditer(rest):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) >= 6:
            add(digits, "id", True)
            rest = rest.replace(m.group(0), " ")
    for m in _RE_DOMAIN.finditer(rest):
        add(fold(m.group(0)), "domain", True)
        rest = rest.replace(m.group(0), " ")
    for w in _RE_WORD.findall(fold(rest)):
        w = w.strip("-")
        if len(w) < 3 and not (len(w) == 2 and w.isalnum() and any(c.isdigit() for c in w)):
            continue  # descarta palavras curtas, exceto códigos como "c2"
        if w in STOPWORDS:
            continue
        add(w, "word", w not in CONTEXT)
    return terms


def _found(term: Term, text: str, digits: str) -> bool:
    if term.kind == "id":
        return term.text in digits
    if term.kind in ("email", "domain", "phrase"):
        return term.text in text
    # palavra: início de palavra (aceita sufixos: "lockbit3", "leaks")
    return re.search(rf"(?<![\w]){re.escape(term.text)}", text) is not None


def match(text: str, terms: list[Term]) -> Match:
    t = _normalize_text(text)
    d = _digits_only(t)
    m = Match(key_total=sum(1 for x in terms if x.key), context_total=sum(1 for x in terms if not x.key))
    total_w = sum(x.weight for x in terms) or 1.0
    got_w = 0.0
    for term in terms:
        if _found(term, t, d):
            m.found.append(term.text)
            got_w += term.weight
            if term.key:
                m.key_found += 1
            else:
                m.context_found += 1
    m.score = got_w / total_w
    return m


def required_hits(terms: list[Term]) -> tuple[int, bool]:
    """
    Limiar graduado: (n.º mínimo de termos, conta-se sobre termos-chave?).

    - Com termos-chave: metade deles, arredondada para cima (1 de 1, 1 de 2,
      2 de 3, 2 de 4, ...). Entidades (email, id, domínio, frase) contam como
      termos-chave; "lockbit leak site" exige "lockbit".
    - Sem termos-chave (só contexto): 2 termos de contexto (ou 1, se só houver 1).
    """
    n_key = sum(1 for t in terms if t.key)
    if n_key:
        return math.ceil(n_key / 2), True
    n_ctx = sum(1 for t in terms if not t.key)
    return min(2, n_ctx), False


def is_relevant(m: Match, terms: list[Term]) -> bool:
    need, on_keys = required_hits(terms)
    if need == 0:
        return True
    return (m.key_found if on_keys else m.context_found) >= need


def best_window(text: str, terms: list[Term], size: int) -> str:
    """Excerto de `size` caracteres com mais ocorrências dos termos (o início do texto se não houver nenhuma)."""
    if len(text) <= size or not terms:
        return text[:size]
    folded = _normalize_text(text)
    if len(folded) != len(text):  # NFKD pode mudar o comprimento; recua para o início
        return text[:size]
    positions = []
    for term in terms:
        if term.kind == "id":
            continue
        pat = re.escape(term.text) if term.kind != "word" else rf"(?<![\w]){re.escape(term.text)}"
        positions += [(mm.start(), term.weight) for mm in re.finditer(pat, folded)]
    if not positions:
        return text[:size]
    positions.sort()
    best_start, best_w, j, acc = 0, -1.0, 0, 0.0
    for i, (p, w) in enumerate(positions):
        acc += w
        while positions[j][0] < p - size + 1:
            acc -= positions[j][1]
            j += 1
        if acc > best_w:
            best_w, best_start = acc, max(0, positions[j][0] - 100)
    start = min(best_start, max(0, len(text) - size))
    return text[start:start + size]
