"""
config.py — Configuração central da aplicação DarkSherlock.

Carrega variáveis de ambiente do ficheiro `.env` e expõe-as como constantes
reutilizáveis.

Modelos LLM suportados:
    - Modelo leve EMBUTIDO via llama.cpp (in-process, sem servidor) — corre
      em qualquer máquina, descarregado automaticamente na 1ª utilização.
    - Modelos locais via Ollama (opcional), descobertos dinamicamente.

Variáveis configuráveis:
    - OLLAMA_BASE_URL     : URL do servidor Ollama (opcional).
    - DARKSHERLOCK_MODELS_DIR : pasta de cache dos GGUF embutidos.
    - DARKSHERLOCK_DEFAULT_MODEL : chave do modelo embutido por omissão.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# URL base do servidor Ollama local (opcional — a app funciona sem Ollama
# graças ao modelo leve embutido). Exemplo: http://localhost:11434
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Parâmetros de inferência dos modelos Ollama (opcionais). Por omissão não se
# passa nada e vale o que o servidor Ollama definir (num_ctx pequeno, p.ex.).
# Para replicar os modelos embutidos (n_ctx 8192, max_tokens 2048,
# repeat_penalty 1.1 — ver local_models.py), definir:
#   OLLAMA_NUM_CTX=8192  OLLAMA_NUM_PREDICT=2048  OLLAMA_REPEAT_PENALTY=1.1
# OLLAMA_SEED fixa a semente (reprodutibilidade).
def _env_number(name: str, cast):
    raw = os.getenv(name, "").strip()
    return cast(raw) if raw else None


OLLAMA_NUM_CTX = _env_number("OLLAMA_NUM_CTX", int)
OLLAMA_NUM_PREDICT = _env_number("OLLAMA_NUM_PREDICT", int)
OLLAMA_REPEAT_PENALTY = _env_number("OLLAMA_REPEAT_PENALTY", float)
OLLAMA_SEED = _env_number("OLLAMA_SEED", int)

# Pasta onde os ficheiros GGUF dos modelos embutidos são guardados em cache.
# Pode ser sobreposta por ambiente (e.g., para montar um volume no Docker).
MODELS_DIR = Path(os.getenv("DARKSHERLOCK_MODELS_DIR", "models"))

# Chave (do registry em local_models.py) do modelo embutido por omissão.
# Vazio → usa o default definido em local_models.DEFAULT_BUILTIN_MODEL.
DEFAULT_BUILTIN_MODEL = os.getenv("DARKSHERLOCK_DEFAULT_MODEL", "").strip()
