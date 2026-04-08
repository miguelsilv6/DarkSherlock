"""
llm_utils.py — Utilitários para gestão e instanciação de modelos de linguagem (LLMs).

O DarkSherlock utiliza exclusivamente modelos locais via Ollama. Os modelos
disponíveis são descobertos dinamicamente através da API do servidor Ollama.
"""

import requests
from urllib.parse import urljoin
from langchain_ollama import ChatOllama
from typing import Callable, Optional, List
from langchain_core.callbacks.base import BaseCallbackHandler
from config import OLLAMA_BASE_URL


class BufferedStreamingHandler(BaseCallbackHandler):
    """
    Handler de streaming com buffer para integração com o Streamlit.

    Acumula tokens num buffer e só os envia à UI quando se atinge um
    limiar de tamanho ou quando encontra uma quebra de linha, reduzindo
    o número de re-renderizações da interface.
    """

    def __init__(self, buffer_limit: int = 60, ui_callback: Optional[Callable[[str], None]] = None):
        self.buffer = ""
        self.buffer_limit = buffer_limit
        self.ui_callback = ui_callback

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        self.buffer += token
        if "\n" in token or len(self.buffer) >= self.buffer_limit:
            print(self.buffer, end="", flush=True)
            if self.ui_callback:
                self.ui_callback(self.buffer)
            self.buffer = ""

    def on_llm_end(self, response, **kwargs) -> None:
        if self.buffer:
            print(self.buffer, end="", flush=True)
            if self.ui_callback:
                self.ui_callback(self.buffer)
            self.buffer = ""


# Parâmetros comuns a todos os modelos LLM.
_common_callbacks = [BufferedStreamingHandler(buffer_limit=60)]

_common_llm_params = {
    "temperature": 0,
    "streaming": True,
    "callbacks": _common_callbacks,
}


def _normalize_model_name(name: str) -> str:
    return name.strip().lower()


def _get_ollama_base_url() -> Optional[str]:
    if not OLLAMA_BASE_URL:
        return None
    return OLLAMA_BASE_URL.rstrip("/") + "/"


def fetch_ollama_models() -> List[str]:
    """
    Devolve a lista de modelos Ollama instalados localmente.
    Retorna lista vazia se o servidor não estiver acessível.
    """
    base_url = _get_ollama_base_url()
    if not base_url:
        return []

    try:
        resp = requests.get(urljoin(base_url, "api/tags"), timeout=3)
        resp.raise_for_status()
        models = resp.json().get("models", [])
        available = []
        for m in models:
            name = m.get("name") or m.get("model")
            if name:
                available.append(name)
        return available
    except (requests.RequestException, ValueError):
        return []


def get_model_choices() -> List[str]:
    """
    Devolve a lista de modelos Ollama disponíveis localmente, ordenada alfabeticamente.
    """
    models = fetch_ollama_models()
    return sorted(models, key=_normalize_model_name)


def resolve_model_config(model_choice: str):
    """
    Dado o nome de um modelo Ollama, devolve a configuração para instanciar o LLM.
    Retorna None se o modelo não for encontrado.
    """
    model_choice_lower = _normalize_model_name(model_choice)

    for ollama_model in fetch_ollama_models():
        if _normalize_model_name(ollama_model) == model_choice_lower:
            return {
                "class": ChatOllama,
                "constructor_params": {"model": ollama_model, "base_url": OLLAMA_BASE_URL},
            }

    return None
