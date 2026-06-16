"""
forum_adapters — Registry de adapters para fóruns autenticados.

Os engines simples são descritos por um URL template (GET com {query}) e
processados directamente em search.py::fetch_search_results. Os fóruns
autenticados (DarkForums, etc.) são objectos com login + sessão persistente,
implementam a interface ForumAdapter e registam-se aqui pelo nome curto.

Acesso típico:
    from forum_adapters import get_adapter, get_adapter_for_url
    adapter = get_adapter("darkforums")
    if adapter and adapter.is_configured():
        results = adapter.search("ransomware")
"""

from urllib.parse import urlparse

from .base import ForumAdapter
from .darkforums import DarkForumsAdapter

# Instâncias singletons — adapters mantêm uma sessão (curl_cffi) e cookies
# em memória, pelo que partilhar a mesma instância entre chamadas evita
# logins repetidos e maximiza reutilização de sessão Tor.
_INSTANCES: dict[str, ForumAdapter] = {
    "darkforums": DarkForumsAdapter(),
}


def get_adapter(name: str) -> ForumAdapter | None:
    """Devolve o adapter registado com este nome curto, ou None."""
    return _INSTANCES.get(name)


def get_adapter_for_url(url: str) -> ForumAdapter | None:
    """
    Procura um adapter cujo conjunto de domínios contenha o host deste URL.
    Usado por scrape.py para encaminhar fetches de threads ao adapter correcto.
    """
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return None
    host = host.lower()
    if not host:
        return None
    for adapter in _INSTANCES.values():
        if host in {d.lower() for d in adapter.domains}:
            return adapter
    return None


def all_adapters() -> dict[str, ForumAdapter]:
    """Mapa nome → instância de todos os adapters registados (para a UI)."""
    return dict(_INSTANCES)


__all__ = ["ForumAdapter", "get_adapter", "get_adapter_for_url", "all_adapters"]
