"""
Infraestrutura comum dos testes (offline: sem Tor, sem rede, sem LLM real).

- `FakeSession` / `FakeResponse`: substituem a sessão Tor do `requests`. Servem
  respostas por URL a partir de um dicionário (ou de ficheiros em
  tests/fixtures/) e registam os URLs pedidos, para provar o que foi ou não
  pedido (p. ex. pela salvaguarda ética).
- `fake_llm`: fábrica de `FakeListChatModel` (langchain_core) com respostas fixas.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
for p in (ROOT, ROOT / "evaluation"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


class FakeResponse:
    def __init__(self, text="", status_code=200, headers=None, url="", encoding="utf-8", content=None):
        self.status_code = status_code
        self.headers = {"Content-Type": "text/html; charset=utf-8", **(headers or {})}
        self.url = url
        self.encoding = encoding
        self.content = content if content is not None else text.encode(encoding or "utf-8", errors="replace")
        self._text = text

    @property
    def text(self):
        return self._text

    @property
    def apparent_encoding(self):
        return self.encoding or "utf-8"

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        pass


class FakeSession:
    """Sessão falsa: `routes` mapeia URL -> FakeResponse (ou Exception a lançar)."""

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.requested: list[str] = []
        self.proxies = {}
        self.headers = {}

    def get(self, url, **kwargs):
        self.requested.append(url)
        resp = self.routes.get(url)
        if resp is None:
            import requests
            raise requests.ConnectionError(f"sem rota para {url}")
        if isinstance(resp, Exception):
            raise resp
        if not resp.url:
            resp.url = url
        return resp

    def mount(self, *a, **k):
        pass

    def close(self):
        pass


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture
def fake_session():
    return FakeSession


@pytest.fixture
def fake_response():
    return FakeResponse


@pytest.fixture
def fake_llm():
    from langchain_core.language_models.fake_chat_models import FakeListChatModel

    def make(*responses):
        return FakeListChatModel(responses=list(responses))
    return make
