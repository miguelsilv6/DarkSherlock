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

# Pasta onde os ficheiros GGUF dos modelos embutidos são guardados em cache.
# Pode ser sobreposta por ambiente (e.g., para montar um volume no Docker).
MODELS_DIR = Path(os.getenv("DARKSHERLOCK_MODELS_DIR", "models"))

# Chave (do registry em local_models.py) do modelo embutido por omissão.
# Vazio → usa o default definido em local_models.DEFAULT_BUILTIN_MODEL.
DEFAULT_BUILTIN_MODEL = os.getenv("DARKSHERLOCK_DEFAULT_MODEL", "").strip()
