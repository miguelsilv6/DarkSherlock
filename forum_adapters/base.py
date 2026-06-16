"""
forum_adapters/base.py — Interface abstracta para adapters de fórum autenticado.

Os engines simples do DarkSherlock seguem um contrato GET-com-{query}, sem
sessão nem credenciais. Fóruns como o DarkForums (MyBB clearnet, protegido
por Cloudflare) exigem:
    - login com cookies persistentes
    - POST de pesquisa com parsing específico ao layout do fórum
    - scraping de threads com sessão autenticada

Esta classe abstracta define o contrato comum que cada adapter deve cumprir,
para que o pipeline (search.py e scrape.py) os possa despachar uniformemente
sem conhecer as especificidades de cada fórum.
"""

from abc import ABC, abstractmethod
from typing import Iterable


class ForumAdapter(ABC):
    """Interface mínima que um adapter de fórum autenticado deve cumprir."""

    # Conjunto de domínios (lowercase, sem esquema) que este adapter reclama.
    # Usado por scrape.py para decidir se delega o fetch de um URL a este
    # adapter em vez do scraper genérico. Ex.: {"darkforums.st"}.
    domains: Iterable[str] = ()

    # Nome curto, usado no registry (engine config "adapter": "<name>").
    name: str = ""

    @abstractmethod
    def is_configured(self) -> bool:
        """True se credenciais (e config) necessárias estão presentes no ambiente."""

    @abstractmethod
    def ensure_session(self) -> bool:
        """
        Garante que existe uma sessão autenticada válida. Faz login se necessário.
        Devolve True em sucesso, False em falha (credenciais inválidas, CF block,
        Tor down, etc.). Não levanta excepção em condições esperadas.
        """

    @abstractmethod
    def search(self, query: str) -> list[dict]:
        """
        Executa pesquisa autenticada no fórum.
        Devolve lista de dicts {"title": str, "link": str} — mesmo shape que
        search.py::fetch_search_results, para que get_search_results os possa
        agregar uniformemente.
        Devolve lista vazia em qualquer falha (silencioso, alinhado com o
        comportamento dos engines simples).
        """

    @abstractmethod
    def fetch_thread(self, url: str) -> str:
        """
        Obtém o texto limpo de uma thread/página interna do fórum.
        Devolve texto pronto a entregar ao LLM (após normalização e truncagem).
        Devolve string vazia em caso de falha.
        """
