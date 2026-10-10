"""
search_filters.py — Extração e limpeza dos resultados dos motores de pesquisa .onion.

Funções puras (sem rede), usadas por search.py e testáveis offline:

  - extract_links(html, page_url): ligações .onion de uma página de resultados,
    ignorando <nav>/<header>/<footer>, resolvendo ligações relativas e
    redirecionamentos codificados (?url=http%3A%2F%2F...).
  - looks_like_results_page(html, query): a página ecoa a query? Uma página
    que não contém nenhum termo da query não é uma página de resultados
    (p. ex. redireção para a página inicial do motor).
  - is_nav_title(title): rótulos de navegação/categorias ("Marketplaces",
    "Directories", "Contact", ...), que alguns motores apresentam como links
    para outros domínios.
  - is_spam_title(title): títulos de SEO com palavras repetidas
    ("darkmarketplace|darkmarketplace|...", "⭐forumforumforum⭐").
  - normalize_url(url): chave de deduplicação.
  - interleave(per_engine, per_host_cap): junta os resultados dos motores em
    rodízio (ordem estável, cada motor contribui), acumula "found_by" nos
    duplicados e limita o n.º de resultados por host.
"""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

# Endereço .onion (v3: 56 caracteres base32; v2: 16), com caminho opcional.
RE_ONION_URL = re.compile(r"https?://(?:[a-z0-9-]+\.)*[a-z2-7]{16,56}\.onion(?:[/?#][^\s\"'<>]*)?", re.IGNORECASE)
RE_ONION_HOST = re.compile(r"((?:[a-z0-9-]+\.)*[a-z2-7]{16,56}\.onion)", re.IGNORECASE)

NAV_TITLES = {
    "marketplaces", "marketplace", "directories", "directory", "hacking", "porn", "cryptocurrency",
    "search engines", "search engine", "email services", "email", "forums", "forum", "social media",
    "hosting", "operating systems", "organizations", "other", "others", "home", "homepage", "about",
    "about us", "contact", "contact us", "login", "log in", "sign in", "register", "sign up", "next",
    "previous", "prev", "next page", "add link", "add site", "add url", "submit link", "advertise",
    "advertising", "last added", "faq", "help", "terms", "privacy", "donate", "news", "blog", "search",
    "categories", "category", "top", "random", "new", "popular", "more", "back",
}

# Parâmetros de rastreio removidos na normalização.
_TRACKING = re.compile(r"^(utm_\w+|ref|fbclid|gclid)$", re.IGNORECASE)


def onion_host(url: str) -> str:
    m = RE_ONION_HOST.search(url or "")
    return m.group(1).lower() if m else ""


def normalize_url(url: str) -> str:
    """Esquema e host em minúsculas, sem fragmento, sem porta por omissão, sem "/" final e sem parâmetros de rastreio."""
    parts = urlsplit((url or "").strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    netloc = host if port is None or (scheme, port) in {("http", 80), ("https", 443)} else f"{host}:{port}"
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not _TRACKING.match(k)])
    return urlunsplit((scheme, netloc, parts.path.rstrip("/"), query, ""))


def _candidate_urls(href: str, page_url: str):
    """URL absoluto da âncora e, se for um redirecionamento (?url=...), o destino embebido."""
    absolute = urljoin(page_url or "", href)
    yield absolute
    for _key, value in parse_qsl(urlsplit(absolute).query, keep_blank_values=False):
        m = RE_ONION_URL.match(unquote(value).strip())
        if m:
            yield m.group(0)


def extract_links(html: str, page_url: str = "") -> list[dict]:
    """Ligações .onion candidatas a resultado, com o texto da âncora como título."""
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["nav", "header", "footer", "script", "style", "noscript", "form"]):
        tag.decompose()
    out, seen = [], set()
    for a in soup.find_all("a", href=True):
        title = a.get_text(" ", strip=True) or (a.get("title") or "").strip()
        title = " ".join(title.split())
        target = None
        for cand in _candidate_urls(a["href"], page_url):
            m = RE_ONION_URL.match(cand)
            if m:
                target = m.group(0)
        if not target:
            continue
        key = normalize_url(target)
        if key in seen:
            continue
        seen.add(key)
        out.append({"title": title, "link": target})
    return out


def looks_like_results_page(html: str, query: str) -> bool:
    """True se algum termo da query (≥ 3 letras) aparece na página (caixa de pesquisa, cabeçalho, resultados)."""
    words = [w.lower() for w in re.findall(r"\w+", query or "", re.UNICODE) if len(w) >= 3]
    if not words:
        return True
    low = unquote((html or "").lower())
    return any(w in low for w in words)


def is_nav_title(title: str) -> bool:
    return " ".join((title or "").lower().split()).strip(" -|:·•") in NAV_TITLES


_RE_REPEATED_UNIT = re.compile(r"^(.{3,}?)\1{2,}$", re.IGNORECASE)


def is_spam_title(title: str) -> bool:
    """Título de SEO: a mesma palavra repetida, uma palavra feita da repetição de outra, ou excesso de separadores/emojis."""
    t = title or ""
    if t.count("|") > 3 or sum(t.count(c) for c in "⭐★✅✔🔥💯") > 4:
        return True
    tokens = [w.lower() for w in re.findall(r"\w+", t, re.UNICODE)]
    if not tokens:
        return False
    if any(len(w) >= 9 and _RE_REPEATED_UNIT.match(w) for w in tokens):
        return True
    if len(tokens) >= 4:
        top = Counter(tokens).most_common(1)[0][1]
        if top >= 4 or len(set(tokens)) / len(tokens) < 0.4:
            return True
    return False


def interleave(per_engine: list[tuple[str, list[dict]]], per_host_cap: int = 3) -> list[dict]:
    """
    Junta os resultados em rodízio: 1.º de cada motor, 2.º de cada motor, ...
    (motores por ordem alfabética, para a ordem não depender de qual respondeu
    primeiro). Duplicados acumulam o motor em "found_by"; cada host .onion
    contribui no máximo `per_host_cap` resultados.
    """
    ordered = sorted(per_engine, key=lambda x: x[0].lower())
    seen: dict[str, dict] = {}
    per_host: Counter = Counter()
    out: list[dict] = []
    depth = max((len(r) for _, r in ordered), default=0)
    for i in range(depth):
        for name, results in ordered:
            if i >= len(results):
                continue
            r = results[i]
            key = normalize_url(r["link"])
            if key in seen:
                kept = seen[key]
                if name not in kept.setdefault("found_by", []):
                    kept["found_by"].append(name)
                continue
            host = onion_host(r["link"])
            if host and per_host[host] >= per_host_cap:
                continue
            per_host[host] += 1
            item = dict(r)
            item["found_by"] = [name]
            seen[key] = item
            out.append(item)
    return out
