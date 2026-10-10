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

# Versão do pipeline de investigação, gravada em cada investigação. Permite
# separar, na avaliação, resultados obtidos com versões diferentes do código
# ("1.0-legacy" = pipeline anterior à revisão geral de outubro de 2026; as
# investigações sem este campo são dessa versão. "2.0" = pipeline revisto:
# pesquisa limpa, relevância sobre o texto integral, relatório fundamentado,
# pipeline único em pipeline.py).
PIPELINE_VERSION = "2.0"

# Parâmetros de inferência dos modelos Ollama. num_ctx tem omissão 8192 (ver
# abaixo); os restantes só se passam se definidos. Para replicar por completo os
# modelos embutidos (n_ctx 8192, max_tokens 2048, repeat_penalty 1.1 — ver
# local_models.py), definir também:
#   OLLAMA_NUM_PREDICT=2048  OLLAMA_REPEAT_PENALTY=1.1
# OLLAMA_SEED fixa a semente (reprodutibilidade).
def _env_number(name: str, cast):
    raw = os.getenv(name, "").strip()
    return cast(raw) if raw else None


# num_ctx: por omissão 8192 (igual aos modelos embutidos). Sem isto o Ollama usa o
# seu contexto por omissão (2048–4096 conforme a versão) e corta o prompt das
# Etapas 4 e 6 sem avisar. Para modelos com mais contexto, definir OLLAMA_NUM_CTX.
OLLAMA_NUM_CTX = _env_number("OLLAMA_NUM_CTX", int) or 8192
OLLAMA_NUM_PREDICT = _env_number("OLLAMA_NUM_PREDICT", int)
OLLAMA_REPEAT_PENALTY = _env_number("OLLAMA_REPEAT_PENALTY", float)
OLLAMA_SEED = _env_number("OLLAMA_SEED", int)

# Pasta onde os ficheiros GGUF dos modelos embutidos são guardados em cache.
# Pode ser sobreposta por ambiente (e.g., para montar um volume no Docker).
# `or`: uma linha "DARKSHERLOCK_MODELS_DIR=" vazia no .env dava Path("") — a pasta
# atual — e os GGUF (centenas de MB) iam parar à raiz do projeto.
MODELS_DIR = Path(os.getenv("DARKSHERLOCK_MODELS_DIR", "").strip() or "models")

# Chave (do registry em local_models.py) do modelo embutido por omissão.
# Vazio → usa o default definido em local_models.DEFAULT_BUILTIN_MODEL.
DEFAULT_BUILTIN_MODEL = os.getenv("DARKSHERLOCK_DEFAULT_MODEL", "").strip()
