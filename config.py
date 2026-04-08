"""
config.py — Configuração central da aplicação DarkSherlock.

Carrega variáveis de ambiente do ficheiro `.env` e expõe-as como constantes
reutilizáveis. O DarkSherlock utiliza exclusivamente modelos locais via Ollama.

Variáveis configuráveis:
    - OLLAMA_BASE_URL : URL base do servidor Ollama local (ex: http://localhost:11434).
"""

import os
from dotenv import load_dotenv

load_dotenv()

# URL base do servidor Ollama local.
# Exemplo: http://localhost:11434
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
