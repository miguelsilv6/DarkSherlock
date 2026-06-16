"""
local_models.py — Modelos LLM leves EMBUTIDOS (in-process via llama.cpp).

Motivação
---------
O DarkSherlock dependia exclusivamente do Ollama: sem um servidor Ollama a
correr e com um modelo puxado, o pipeline não tinha LLM e ficava inutilizável
("não funcional" out-of-the-box). Este módulo acrescenta modelos GGUF leves
que correm DENTRO do próprio processo Python (via `llama-cpp-python`), sem
servidor externo, descarregados automaticamente na primeira utilização.

Objetivo de design: "corre em qualquer máquina".
  - llama-cpp-python distribui wheels CPU pré-compiladas (sem GPU obrigatória).
  - Os modelos do registry são minúsculos (0.5B–1.5B), cabendo em <2 GB de RAM.
  - O download (via huggingface_hub) é feito uma única vez para `MODELS_DIR`.

Os imports de `llama_cpp` e `huggingface_hub` são TARDIOS (dentro das funções)
para que importar este módulo nunca falhe, mesmo que as libs não estejam
instaladas — `is_available()` reporta o estado e a UI degrada graciosamente.
"""

from __future__ import annotations

import logging
from typing import Optional

from config import MODELS_DIR, DEFAULT_BUILTIN_MODEL

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Registry de modelos embutidos
# ---------------------------------------------------------------------------
# Cada chave é também a label apresentada na UI (tem de round-trip:
# UI → session_state → get_llm → resolve_model_config). Modelos instruct
# pequenos com bom suporte multilingue (os relatórios são em PT-PT).
#
# n_ctx dimensionado para o pipeline: generate_summary envia até ~12k chars
# (~4-5k tokens) + formato; 8192 deixa folga para a resposta.
BUILTIN_MODELS: dict[str, dict] = {
    "Qwen2.5-0.5B (embutido, ultraleve)": {
        "repo_id": "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
        "filename": "qwen2.5-0.5b-instruct-q4_k_m.gguf",
        "n_ctx": 8192,
        "max_tokens": 2048,
        "size_label": "~400 MB",
        "desc": "O mais leve. Corre em qualquer máquina. Qualidade básica.",
    },
    "Qwen2.5-1.5B (embutido, leve)": {
        "repo_id": "Qwen/Qwen2.5-1.5B-Instruct-GGUF",
        "filename": "qwen2.5-1.5b-instruct-q4_k_m.gguf",
        "n_ctx": 8192,
        "max_tokens": 2048,
        "size_label": "~1.1 GB",
        "desc": "Melhor qualidade de análise, ainda leve. Recomendado se a máquina aguentar.",
    },
    "Llama-3.2-1B (embutido, leve)": {
        "repo_id": "bartowski/Llama-3.2-1B-Instruct-GGUF",
        "filename": "Llama-3.2-1B-Instruct-Q4_K_M.gguf",
        "n_ctx": 8192,
        "max_tokens": 2048,
        "size_label": "~0.8 GB",
        "desc": "Alternativa Meta Llama. Bom equilíbrio tamanho/qualidade.",
    },
}

# Modelo por omissão: respeita a env DARKSHERLOCK_DEFAULT_MODEL se for válida,
# senão usa o mais leve (corre garantidamente em qualquer máquina).
DEFAULT_BUILTIN_MODEL = (
    DEFAULT_BUILTIN_MODEL
    if DEFAULT_BUILTIN_MODEL in BUILTIN_MODELS
    else "Qwen2.5-0.5B (embutido, ultraleve)"
)


def is_available() -> bool:
    """True se `llama_cpp` e `huggingface_hub` estão instalados e importáveis."""
    try:
        import importlib.util as u
        return bool(u.find_spec("llama_cpp") and u.find_spec("huggingface_hub"))
    except Exception:  # noqa: BLE001
        return False


def is_builtin(model_choice: str) -> bool:
    """True se a label corresponde a um modelo embutido do registry."""
    return model_choice in BUILTIN_MODELS


def list_builtin_labels() -> list[str]:
    """Labels dos modelos embutidos (só se llama.cpp estiver disponível)."""
    return list(BUILTIN_MODELS.keys()) if is_available() else []


def is_downloaded(model_choice: str) -> bool:
    """Verifica se o GGUF já está em cache, SEM o descarregar."""
    spec = BUILTIN_MODELS.get(model_choice)
    if spec is None:
        return False
    try:
        from huggingface_hub import try_to_load_from_cache  # import tardio

        path = try_to_load_from_cache(
            repo_id=spec["repo_id"],
            filename=spec["filename"],
            cache_dir=str(MODELS_DIR),
        )
        # try_to_load_from_cache devolve o path (str) se existir, ou um
        # sentinel/None caso contrário.
        return isinstance(path, str)
    except Exception:  # noqa: BLE001
        return False


def ensure_downloaded(model_choice: str) -> str:
    """
    Garante que o GGUF do modelo está em disco e devolve o caminho local.

    Descarrega de Hugging Face na primeira utilização (pode demorar — ficheiros
    de centenas de MB). Chamadas seguintes resolvem da cache instantaneamente.

    Levanta:
        RuntimeError: se llama.cpp/huggingface_hub não estiverem instalados.
        KeyError:     se a label não existir no registry.
    """
    if not is_available():
        raise RuntimeError(
            "llama-cpp-python / huggingface_hub não instalados. "
            "Instala as dependências: pip install -r requirements.txt"
        )
    spec = BUILTIN_MODELS[model_choice]  # KeyError propositado se inválido

    from huggingface_hub import hf_hub_download  # import tardio

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(
        "A resolver modelo embutido '%s' (%s) de %s …",
        model_choice, spec["size_label"], spec["repo_id"],
    )
    path = hf_hub_download(
        repo_id=spec["repo_id"],
        filename=spec["filename"],
        cache_dir=str(MODELS_DIR),
    )
    return path


def build_constructor_params(model_choice: str) -> dict:
    """
    Constrói os kwargs para instanciar ChatLlamaCpp para este modelo embutido.
    Inclui o download do GGUF (via ensure_downloaded).
    """
    spec = BUILTIN_MODELS[model_choice]
    model_path = ensure_downloaded(model_choice)
    return {
        "model_path": model_path,
        "n_ctx": spec["n_ctx"],
        "max_tokens": spec["max_tokens"],
        # n_threads=None → llama.cpp auto-deteta os cores disponíveis.
        "verbose": False,
    }


def get_chat_llamacpp_class():
    """
    Devolve a classe ChatLlamaCpp do langchain_community (import tardio).

    Tenta o caminho exposto no __init__ e, em fallback, o submódulo directo,
    para tolerar variações entre versões do langchain_community.
    """
    try:
        from langchain_community.chat_models import ChatLlamaCpp  # type: ignore
        return ChatLlamaCpp
    except Exception:  # noqa: BLE001
        from langchain_community.chat_models.llamacpp import ChatLlamaCpp  # type: ignore
        return ChatLlamaCpp
