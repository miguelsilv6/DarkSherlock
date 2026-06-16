"""
llm_utils.py — Utilitários para gestão e instanciação de modelos de linguagem (LLMs).

O DarkSherlock suporta dois backends de LLM, por ordem de prioridade:

  1. Modelos LEVES EMBUTIDOS (in-process, via llama.cpp) — ver local_models.py.
     Correm em qualquer máquina, sem servidor, descarregados na 1ª utilização.
     Garantem que a app é funcional out-of-the-box, mesmo sem Ollama.

  2. Modelos locais via Ollama (opcional) — descobertos dinamicamente pela
     API do servidor Ollama, se este estiver a correr.
"""

import logging
import requests
from urllib.parse import urljoin
from langchain_ollama import ChatOllama
from typing import Callable, Optional, List
from langchain_core.callbacks.base import BaseCallbackHandler
from config import OLLAMA_BASE_URL
import local_models

logger = logging.getLogger(__name__)


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
            if self.ui_callback:
                self.ui_callback(self.buffer)
            self.buffer = ""

    def on_llm_end(self, response, **kwargs) -> None:
        if self.buffer:
            if self.ui_callback:
                self.ui_callback(self.buffer)
            self.buffer = ""


# Parâmetros comuns a todos os modelos LLM.
#
# NOTA: `callbacks` foi deliberadamente removido daqui — caso contrário, todas
# as instâncias `llm_class(**_common_llm_params)` partilhavam a MESMA referência
# de lista + handler, com estado mutável (`self.buffer`) entre chamadas e sem
# thread-safety. O consumidor que precisar de streaming (e.g., Stage 6/6 em
# Home.py) deve atribuir explicitamente `llm.callbacks = [BufferedStreamingHandler(...)]`
# após instanciação. `refine_query` e `filter_results` invocam `chain.invoke(...)`
# que devolve o resultado completo — não precisam de callbacks.
_common_llm_params = {
    "temperature": 0,
    "streaming": True,
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
    Devolve a lista de modelos disponíveis para selecção na UI.

    Ordem: modelos EMBUTIDOS leves primeiro (sempre disponíveis se
    llama-cpp-python estiver instalado), depois os modelos Ollama
    descobertos no servidor local. Os embutidos vêm primeiro para que o
    índice 0 (default da UI) seja sempre um modelo funcional sem setup.
    """
    builtin = local_models.list_builtin_labels()
    ollama = sorted(fetch_ollama_models(), key=_normalize_model_name)
    return builtin + ollama


def resolve_model_config(model_choice: str):
    """
    Dado o nome de um modelo, devolve a configuração para instanciar o LLM.

    Resolve primeiro contra os modelos embutidos (llama.cpp in-process);
    em fallback, contra os modelos Ollama. Para modelos embutidos, isto
    desencadeia o download do GGUF na primeira utilização (ver local_models).

    Retorna None se o modelo não for reconhecido em nenhum backend.
    """
    if model_choice and local_models.is_builtin(model_choice):
        return {
            "class": local_models.get_chat_llamacpp_class(),
            "constructor_params": local_models.build_constructor_params(model_choice),
        }

    model_choice_lower = _normalize_model_name(model_choice or "")
    for ollama_model in fetch_ollama_models():
        if _normalize_model_name(ollama_model) == model_choice_lower:
            return {
                "class": ChatOllama,
                "constructor_params": {"model": ollama_model, "base_url": OLLAMA_BASE_URL},
            }

    return None
