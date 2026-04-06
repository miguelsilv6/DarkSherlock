"""
config.py — Configuração central da aplicação DarkSherlock.

Este módulo é responsável por carregar todas as variáveis de ambiente a partir
do ficheiro `.env` (localizado na raiz do projeto) e expô-las como constantes
Python reutilizáveis em todo o projeto.

Utilização do padrão dotenv:
    O ficheiro `.env` nunca deve ser submetido ao controlo de versões (git),
    pois contém chaves de API sensíveis. O ficheiro `.env.example` serve de
    modelo para os utilizadores saberem que variáveis configurar.

Variáveis obrigatórias (a aplicação não funcionará sem pelo menos uma):
    - OPENAI_API_KEY       : Chave de API da OpenAI (modelos GPT).
    - GOOGLE_API_KEY       : Chave de API do Google (modelos Gemini).
    - ANTHROPIC_API_KEY    : Chave de API da Anthropic (modelos Claude).
    - OPENROUTER_API_KEY   : Chave de API do OpenRouter (agregador multi-modelo).

Variáveis opcionais (para modelos locais):
    - OLLAMA_BASE_URL      : URL base do servidor Ollama local (ex: http://localhost:11434).
    - OPENROUTER_BASE_URL  : URL base do OpenRouter — tem valor por omissão.
    - LLAMA_CPP_BASE_URL   : URL base do servidor llama.cpp local (API compatível com OpenAI).
"""

import os
from dotenv import load_dotenv

# Carrega as variáveis definidas no ficheiro `.env` para o ambiente do processo.
# A função load_dotenv() lê o ficheiro `.env` na directoria actual (ou numa
# directoria pai) e injeta cada par chave=valor como variável de ambiente,
# sem sobrescrever variáveis já definidas no sistema operativo.
load_dotenv()

# --- Chaves de API para fornecedores de modelos de linguagem na nuvem ---

# Chave de API da OpenAI — necessária para usar modelos GPT (ex: gpt-4.1).
# OBRIGATÓRIA se se pretender utilizar modelos OpenAI.
# Obtém-se em: https://platform.openai.com/api-keys
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Chave de API do Google — necessária para usar modelos Gemini (ex: gemini-2.5-flash).
# OBRIGATÓRIA se se pretender utilizar modelos Google.
# Obtém-se em: https://aistudio.google.com/app/apikey
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Chave de API da Anthropic — necessária para usar modelos Claude (ex: claude-sonnet-4-5).
# OBRIGATÓRIA se se pretender utilizar modelos Anthropic.
# Obtém-se em: https://console.anthropic.com/settings/keys
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# --- Configuração do OpenRouter (agregador de múltiplos fornecedores) ---

# URL base do OpenRouter. Tem um valor por omissão para não quebrar a configuração
# caso a variável não esteja definida no `.env`. O OpenRouter expõe uma API
# compatível com a interface da OpenAI, pelo que é utilizado via ChatOpenAI.
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL")

# URL base do OpenRouter — tem valor por omissão aponta para a API oficial.
# OPCIONAL: só é necessário se o utilizador quiser usar um endpoint personalizado.
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

# Chave de API do OpenRouter — permite aceder a dezenas de modelos de diferentes
# fornecedores através de um único ponto de acesso (ex: Qwen, Grok, modelos gratuitos).
# OBRIGATÓRIA se se pretender utilizar modelos via OpenRouter.
# Obtém-se em: https://openrouter.ai/keys
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

# --- Configuração de servidores de modelos locais ---

# URL base do servidor llama.cpp — permite usar modelos GGUF localmente.
# O llama.cpp expõe uma API compatível com a da OpenAI (/v1/models, /v1/chat/completions).
# OPCIONAL: apenas necessário se o utilizador tiver um servidor llama.cpp em execução.
# Exemplo: http://localhost:8080
LLAMA_CPP_BASE_URL = os.getenv("LLAMA_CPP_BASE_URL")
