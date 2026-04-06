"""
llm_utils.py — Utilitários para gestão e instanciação de modelos de linguagem (LLMs).

Este módulo centraliza toda a lógica relacionada com os modelos de linguagem utilizados
pelo DarkSherlock. As suas responsabilidades principais são:

1. Registo de modelos (model registry):
   Define um dicionário `_llm_config_map` que mapeia nomes de modelos para as
   respectivas classes LangChain e parâmetros de construção. Adicionar suporte
   a um novo modelo resume-se a inserir uma nova entrada neste dicionário.

2. Parâmetros comuns a todos os LLMs (`_common_llm_params`):
   Define configurações partilhadas (temperatura, streaming, callbacks) que se
   aplicam a todos os modelos, evitando repetição de código.

3. Streaming com buffer (`BufferedStreamingHandler`):
   O Streamlit atualiza a interface gráfica de forma reactiva. Enviar cada token
   individualmente causaria demasiadas re-renderizações e degradaria o desempenho.
   O handler acumula tokens num buffer e só os envia à UI quando se atinge um
   limiar de tamanho ou quando encontra uma quebra de linha.

4. Resolução de modelos (`resolve_model_config`):
   Dado o nome de um modelo escolhido pelo utilizador, devolve a configuração
   necessária para instanciar o cliente LLM correspondente, suportando tanto
   modelos na nuvem como modelos locais (Ollama e llama.cpp).

5. Lista de modelos disponíveis (`get_model_choices`):
   Constrói dinamicamente a lista de modelos mostrada na sidebar da UI, incluindo
   apenas os modelos cujas chaves de API estão configuradas, e acrescentando
   automaticamente os modelos locais detectados via Ollama e llama.cpp.

Dependências externas:
    - LangChain (langchain_openai, langchain_ollama, langchain_anthropic, langchain_google_genai)
    - requests (para consultar APIs locais do Ollama e llama.cpp)
"""

import requests
from urllib.parse import urljoin
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from typing import Callable, Optional, List
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.callbacks.base import BaseCallbackHandler
import os
from config import (
    OLLAMA_BASE_URL,
    OPENROUTER_BASE_URL,
    OPENROUTER_API_KEY,
    GOOGLE_API_KEY,
    OPENAI_API_KEY,
    ANTHROPIC_API_KEY,
    LLAMA_CPP_BASE_URL,
)


class BufferedStreamingHandler(BaseCallbackHandler):
    """
    Handler de streaming com buffer para integração com o Streamlit.

    Problema que resolve:
        O LangChain emite cada token gerado pelo LLM individualmente através do
        método `on_llm_new_token`. Se cada token fosse enviado directamente ao
        Streamlit, provocaria uma re-renderização da interface por cada token,
        resultando em animações instáveis, elevado consumo de CPU e uma
        experiência de utilizador degradada.

    Solução implementada:
        Os tokens são acumulados num buffer interno (string). O buffer é
        descarregado (flush) para o callback da UI apenas quando:
          - Um token contém uma quebra de linha (`\\n`), sinalizando o fim
            de um parágrafo ou linha lógica; ou
          - O buffer atinge ou excede `buffer_limit` caracteres.
        Desta forma, a UI recebe blocos de texto coerentes em vez de caracteres
        isolados, reduzindo drasticamente o número de actualizações de ecrã.

    Atributos:
        buffer (str)            : Acumulador de tokens ainda não enviados à UI.
        buffer_limit (int)      : Número máximo de caracteres antes do flush forçado.
        ui_callback (Callable)  : Função da UI do Streamlit que recebe o texto acumulado.
    """

    def __init__(self, buffer_limit: int = 60, ui_callback: Optional[Callable[[str], None]] = None):
        """
        Inicializa o handler de streaming.

        Parâmetros:
            buffer_limit (int): Número de caracteres que dispara o flush do buffer.
                                Por omissão são 60 caracteres — valor empírico que
                                equilibra fluidez visual e eficiência de renderização.
            ui_callback (Callable, opcional): Função a invocar com o texto acumulado
                                              quando o buffer é descarregado. Tipicamente
                                              é o `st.write_stream` ou equivalente do Streamlit.
        """
        self.buffer = ""
        self.buffer_limit = buffer_limit
        self.ui_callback = ui_callback

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        """
        Invocado pelo LangChain cada vez que o LLM emite um novo token.

        Acrescenta o token ao buffer e verifica se é necessário fazer flush:
          - Se o token contém `\\n`: faz flush imediato para manter a estrutura
            de parágrafos intacta na UI.
          - Se o buffer atingiu `buffer_limit`: faz flush para evitar atrasos
            visíveis ao utilizador.

        Parâmetros:
            token (str): O token de texto gerado pelo LLM.
        """
        self.buffer += token
        # Descarrega o buffer se encontrou uma quebra de linha ou se atingiu o limite
        if "\n" in token or len(self.buffer) >= self.buffer_limit:
            # Imprime na consola (útil para depuração em modo de linha de comandos)
            print(self.buffer, end="", flush=True)
            # Envia o texto acumulado para a interface gráfica do Streamlit
            if self.ui_callback:
                self.ui_callback(self.buffer)
            # Reinicia o buffer após o flush
            self.buffer = ""

    def on_llm_end(self, response, **kwargs) -> None:
        """
        Invocado pelo LangChain quando o LLM termina a geração de texto.

        Garante que quaisquer tokens remanescentes no buffer (que não tenham
        atingido o limiar de flush) são enviados para a UI antes de terminar.
        Sem este método, o final da resposta do LLM poderia ser silenciosamente
        descartado se o buffer não estivesse vazio.

        Parâmetros:
            response: Objecto de resposta LangChain (não utilizado directamente).
        """
        # Envia os tokens restantes no buffer ao terminar a geração
        if self.buffer:
            print(self.buffer, end="", flush=True)
            if self.ui_callback:
                self.ui_callback(self.buffer)
            # Limpa o buffer para a próxima utilização
            self.buffer = ""


# --- Configuração Data ---

# Instancia a lista de callbacks uma única vez para ser partilhada por todos os LLMs.
# Utilizar uma instância partilhada evita criar múltiplos handlers redundantes.
# Nota: o ui_callback é None por omissão; cada página do Streamlit injectará
# o seu próprio callback quando instanciar o LLM.
_common_callbacks = [BufferedStreamingHandler(buffer_limit=60)]

# Parâmetros comuns a todos os modelos LLM.
# Estes parâmetros são passados como **kwargs ao construtor de cada classe LangChain:
#   - temperature=0  : Remove a aleatoriedade das respostas, garantindo determinismo.
#                      Para OSINT, a reprodutibilidade é preferível à criatividade.
#   - streaming=True : Activa o modo de streaming — o LLM emite tokens à medida que
#                      os gera, em vez de esperar pela resposta completa. Isso melhora
#                      a experiência do utilizador em consultas longas.
#   - callbacks      : Lista de handlers invocados durante a geração (ver BufferedStreamingHandler).
_common_llm_params = {
    "temperature": 0,
    "streaming": True,
    "callbacks": _common_callbacks,
}

# --- Registo de modelos (Model Registry) ---
#
# `_llm_config_map` é o coração do sistema de suporte a múltiplos fornecedores.
# É um dicionário que mapeia um nome de modelo (em minúsculas) para um dicionário
# de configuração com dois campos obrigatórios:
#
#   - 'class'             : A classe LangChain a instanciar (ex: ChatOpenAI, ChatAnthropic).
#   - 'constructor_params': Dicionário com os parâmetros específicos do modelo a passar
#                           ao construtor da classe, como o nome do modelo, a chave de API
#                           ou o URL base do servidor.
#
# Para adicionar um novo modelo basta inserir uma nova entrada neste dicionário.
# Os parâmetros comuns (_common_llm_params) são mesclados automaticamente na função
# resolve_model_config — não é necessário repeti-los aqui.
#
# Estrutura de exemplo:
#   'nome-do-modelo': {
#       'class': ClasseLangChain,
#       'constructor_params': {'model_name': 'nome-oficial', ...}
#   }
_llm_config_map = {
    # --- Modelos OpenAI (acesso directo via API da OpenAI) ---
    # Requerem OPENAI_API_KEY definida no .env

    'gpt-4.1': {
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-4.1'}
    },
    'gpt-5.2': {
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-5.2'}
    },
    'gpt-5.1': {
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-5.1'}
    },
    'gpt-5-mini': {
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-5-mini'}
    },
    'gpt-5-nano': {
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-5-nano'}
    },

    # --- Modelos Anthropic Claude (acesso directo via API da Anthropic) ---
    # Requerem ANTHROPIC_API_KEY definida no .env

    'claude-sonnet-4-5': {
        'class': ChatAnthropic,
        'constructor_params': {'model': 'claude-sonnet-4-5'}
    },
    'claude-sonnet-4-0': {
        'class': ChatAnthropic,
        'constructor_params': {'model': 'claude-sonnet-4-0'}
    },

    # --- Modelos Google Gemini (acesso directo via API do Google) ---
    # Requerem GOOGLE_API_KEY definida no .env
    # Nota: a google_api_key é passada explicitamente no constructor_params
    # porque a classe ChatGoogleGenerativeAI não lê automaticamente a variável
    # de ambiente GOOGLE_API_KEY — ao contrário das classes OpenAI e Anthropic.

    'gemini-2.5-flash': {
        'class': ChatGoogleGenerativeAI,
        'constructor_params': {'model': 'gemini-2.5-flash', 'google_api_key': GOOGLE_API_KEY }
    },
    'gemini-2.5-flash-lite': {
        'class': ChatGoogleGenerativeAI,
        'constructor_params': {'model': 'gemini-2.5-flash-lite', 'google_api_key': GOOGLE_API_KEY}
    },
    'gemini-2.5-pro': {
        'class': ChatGoogleGenerativeAI,
        'constructor_params': {'model': 'gemini-2.5-pro', 'google_api_key': GOOGLE_API_KEY}
    },

    # --- Modelos via OpenRouter (agregador multi-fornecedor) ---
    # Requerem OPENROUTER_API_KEY e OPENROUTER_BASE_URL definidas no .env.
    # O OpenRouter expõe uma API compatível com a OpenAI, por isso todos estes
    # modelos usam ChatOpenAI mas com base_url apontando para o OpenRouter.
    # Desta forma, é possível aceder a modelos de vários fornecedores com uma
    # única chave de API e sem instalar SDKs adicionais.

    'qwen3-80b-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'qwen/qwen3-next-80b-a3b-instruct:free',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'nemotron-nano-9b-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'nvidia/nemotron-nano-9b-v2:free',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'gpt-oss-120b-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'openai/gpt-oss-120b:free',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'gpt-5.1-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'openai/gpt-5.1',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'gpt-5-mini-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'openai/gpt-5-mini',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'claude-sonnet-4.5-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'anthropic/claude-sonnet-4.5',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'grok-4.1-fast-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'x-ai/grok-4.1-fast',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },

    # --- Modelos Ollama locais (comentados por omissão) ---
    # Estes modelos são detectados e adicionados dinamicamente pela função
    # fetch_ollama_models() — não é necessário registá-los manualmente.
    # As entradas abaixo servem apenas como referência de como os registar
    # de forma estática, caso se pretenda forçar a disponibilidade de um modelo.

    # 'llama3.2': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'llama3.2:latest', 'base_url': OLLAMA_BASE_URL}
    # },
    # 'llama3.1': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'llama3.1:latest', 'base_url': OLLAMA_BASE_URL}
    # },
    # 'gemma3': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'gemma3:latest', 'base_url': OLLAMA_BASE_URL}
    # },
    # 'deepseek-r1': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'deepseek-r1:latest', 'base_url': OLLAMA_BASE_URL}
    # },

    # Add more models here easily:
    # 'mistral7b': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'mistral:7b', 'base_url': OLLAMA_BASE_URL}
    # },
    # 'gpt3.5': {
    #      'class': ChatOpenAI,
    #      'constructor_params': {'model_name': 'gpt-3.5-turbo', 'base_url': OLLAMA_BASE_URL}
    # }
}


def _normalize_model_name(name: str) -> str:
    """
    Normaliza o nome de um modelo para comparações insensíveis a maiúsculas/minúsculas.

    Remove espaços em branco nas extremidades e converte para minúsculas.
    Usado internamente para garantir que "GPT-4.1", "gpt-4.1" e "  gpt-4.1  "
    são todos reconhecidos como o mesmo modelo.

    Parâmetros:
        name (str): Nome do modelo tal como fornecido pelo utilizador ou pela API.

    Retorna:
        str: Nome normalizado (sem espaços, em minúsculas).
    """
    return name.strip().lower()


def _get_ollama_base_url() -> Optional[str]:
    """
    Devolve o URL base do servidor Ollama formatado correctamente.

    Garante que o URL termina sempre com uma barra `/`, o que é necessário
    para que `urljoin` construa caminhos de API correctamente (ex: ao juntar
    com `api/tags`).

    Retorna:
        str  : URL base com barra final se OLLAMA_BASE_URL estiver configurado.
        None : Se OLLAMA_BASE_URL não estiver definido no `.env`.
    """
    if not OLLAMA_BASE_URL:
        return None
    return OLLAMA_BASE_URL.rstrip("/") + "/"


def fetch_ollama_models() -> List[str]:
    """
    Retrieve the list of locally available Ollama models by querying the Ollama HTTP API.
    Returns an empty list if the API isn't reachable or the base URL is not defined.

    Consulta o endpoint `/api/tags` do servidor Ollama local, que devolve a lista
    de modelos instalados na máquina. Esta função é chamada no arranque da sidebar
    para popular dinamicamente a lista de modelos disponíveis.

    O timeout de 3 segundos evita que a aplicação bloqueie por longos períodos
    caso o servidor Ollama não esteja em execução.

    Retorna:
        List[str]: Lista com os nomes dos modelos Ollama disponíveis localmente.
                   Devolve uma lista vazia se:
                     - OLLAMA_BASE_URL não estiver configurado;
                     - O servidor não estiver acessível;
                     - A resposta da API for inválida.
    """
    base_url = _get_ollama_base_url()
    if not base_url:
        # Ollama não está configurado — não há modelos locais a adicionar
        return []

    try:
        # Consulta o endpoint de listagem de modelos do Ollama
        resp = requests.get(urljoin(base_url, "api/tags"), timeout=3)
        resp.raise_for_status()
        models = resp.json().get("models", [])
        available = []
        for m in models:
            # O campo do nome pode ser "name" ou "model" dependendo da versão do Ollama
            name = m.get("name") or m.get("model")
            if name:
                available.append(name)
        return available
    except (requests.RequestException, ValueError):
        # Servidor inacessível ou resposta malformada — falha silenciosa
        return []


# Added Support for llama.cpp models since they use OpenAI-compatible API
def fetch_llama_cpp_models() -> List[str]:
    """
    Retrieve available models from an OpenAI-compatible llama.cpp server.
    Uses /v1/models.

    O servidor llama.cpp expõe o endpoint `/v1/models` compatível com a API da
    OpenAI. Esta função consulta esse endpoint para descobrir os modelos GGUF
    que estão carregados e disponíveis localmente.

    Tal como no Ollama, o timeout de 3 segundos evita bloqueios caso o servidor
    não esteja em execução.

    Retorna:
        List[str]: Lista com os IDs dos modelos disponíveis no servidor llama.cpp.
                   Devolve uma lista vazia se:
                     - LLAMA_CPP_BASE_URL não estiver configurado;
                     - O servidor não estiver acessível;
                     - A resposta da API for inválida ou não contiver IDs de modelos.
    """
    if not LLAMA_CPP_BASE_URL:
        # llama.cpp não está configurado — não há modelos locais a adicionar
        return []

    base = LLAMA_CPP_BASE_URL.rstrip("/")
    try:
        # Consulta o endpoint de listagem de modelos compatível com OpenAI
        resp = requests.get(f"{base}/v1/models", timeout=3)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        # Extrai o campo "id" de cada modelo listado
        return [m["id"] for m in data if "id" in m]
    except (requests.RequestException, ValueError, KeyError):
        # Servidor inacessível ou resposta malformada — falha silenciosa
        return []



def _is_set(v: Optional[str]) -> bool:
    """
    Verifica se uma variável de configuração tem um valor válido e utilizável.

    Uma variável é considerada não definida se:
      - For None ou uma string vazia;
      - Contiver apenas espaços em branco;
      - Contiver o prefixo "your_", que é o marcador de posição utilizado
        nos ficheiros `.env.example` (ex: "your_openai_key_here").

    Parâmetros:
        v (str, opcional): O valor da variável de configuração a verificar.

    Retorna:
        bool: True se a variável tiver um valor válido, False caso contrário.
    """
    return bool(v and str(v).strip() and "your_" not in str(v))


# Changed it so the GUI only loaded available models
def get_model_choices() -> List[str]:
    """
    Combine configured cloud models with locally available Ollama models.
    Cloud models are shown only if required API keys are present.

    Constrói a lista completa de modelos disponíveis para mostrar na sidebar da UI.
    A lógica aplica um sistema de "portões" (gating) baseado nas chaves de API
    configuradas no `.env`:

      1. Modelos na nuvem (OpenAI, Anthropic, Google, OpenRouter) são incluídos
         apenas se a respectiva chave de API estiver definida e válida.
         Desta forma, a UI nunca mostra modelos que o utilizador não pode usar.

      2. Modelos locais (Ollama, llama.cpp) são descobertos dinamicamente
         através de chamadas às respectivas APIs locais e adicionados à lista.

      3. Duplicados são eliminados por normalização dos nomes (minúsculas).

      4. Os modelos na nuvem aparecem primeiro (pela ordem do registo);
         os modelos locais aparecem a seguir, ordenados alfabeticamente.

    Retorna:
        List[str]: Lista ordenada de nomes de modelos disponíveis.
                   Pode ser uma lista vazia se não houver chaves configuradas
                   e nenhum servidor local estiver em execução.
    """
    gated_base_models: List[str] = []

    # Verifica quais os fornecedores de nuvem que têm chaves válidas configuradas
    openai_ok = _is_set(OPENAI_API_KEY)
    anthropic_ok = _is_set(ANTHROPIC_API_KEY)
    google_ok = _is_set(GOOGLE_API_KEY)
    # O OpenRouter requer tanto a chave de API como o URL base configurados
    openrouter_ok = _is_set(OPENROUTER_API_KEY) and _is_set(OPENROUTER_BASE_URL)

    # Itera sobre todos os modelos registados e filtra pelos fornecedores disponíveis
    for k, cfg in _llm_config_map.items():
        cls = cfg.get("class")
        ctor = cfg.get("constructor_params", {}) or {}

        # Modelos OpenRouter: identificados pelo base_url ou pela convenção de nome "-openrouter"
        if cls is ChatOpenAI and (ctor.get("base_url") == OPENROUTER_BASE_URL or "openrouter" in k):
            if openrouter_ok:
                gated_base_models.append(k)
            continue

        # Modelos OpenAI directos (sem base_url personalizado)
        if cls is ChatOpenAI:
            if openai_ok:
                gated_base_models.append(k)
            continue

        # Modelos Anthropic Claude
        if cls is ChatAnthropic:
            if anthropic_ok:
                gated_base_models.append(k)
            continue

        # Modelos Google Gemini
        if cls is ChatGoogleGenerativeAI:
            if google_ok:
                gated_base_models.append(k)
            continue

        # Qualquer outro tipo de modelo (ex: ChatOllama estático) é sempre incluído
        gated_base_models.append(k)

    # Local Models
    dynamic_models = []

    # Dynamic local models via Ollama-style API (/api/tags)
    dynamic_models += fetch_ollama_models()

    # Dynamic local models via llama.cpp which uses OpenAI style API
    dynamic_models += fetch_llama_cpp_models()

    # Constrói um dicionário normalizado para eliminar duplicados.
    # A chave é o nome normalizado; o valor é o nome original (preservando capitalização).
    normalized = {_normalize_model_name(m): m for m in gated_base_models}
    for dm in dynamic_models:
        key = _normalize_model_name(dm)
        # Apenas adiciona modelos locais que não sejam duplicados dos modelos na nuvem
        if key not in normalized:
            normalized[key] = dm

    # Separa os modelos locais dinâmicos e ordena-os alfabeticamente
    ordered_dynamic = sorted(
        [name for key, name in normalized.items() if name not in gated_base_models],
        key=_normalize_model_name,
    )
    # Modelos na nuvem primeiro, seguidos dos modelos locais ordenados
    return gated_base_models + ordered_dynamic




def resolve_model_config(model_choice: str):
    """
    Resolve a model choice (case-insensitive) to the corresponding configuration.
    Supports both the predefined remote models and any locally installed Ollama models.

    Dado o nome de um modelo escolhido pelo utilizador na sidebar, devolve o
    dicionário de configuração necessário para instanciar o cliente LLM:
      {'class': <ClasseLangChain>, 'constructor_params': {...}}

    A resolução segue esta ordem de prioridade:
      1. Procura no registo estático `_llm_config_map` (modelos na nuvem e estáticos).
      2. Se não encontrar, consulta o servidor llama.cpp e tenta correspondência.
      3. Se ainda não encontrar, consulta o servidor Ollama e tenta correspondência.

    Esta ordem garante que os modelos na nuvem têm precedência sobre modelos
    locais com nomes idênticos, e que modelos llama.cpp têm precedência sobre Ollama.

    Parâmetros:
        model_choice (str): Nome do modelo tal como seleccionado na UI (pode ter
                            maiúsculas/minúsculas mistas e espaços extra).

    Retorna:
        dict : Dicionário de configuração com 'class' e 'constructor_params'.
        None : Se o modelo não for encontrado em nenhuma das fontes.
    """
    # Normaliza o nome para comparação insensível a maiúsculas/minúsculas
    model_choice_lower = _normalize_model_name(model_choice)

    # 1ª tentativa: procura no registo estático de modelos configurados
    config = _llm_config_map.get(model_choice_lower)
    if config:
        return config

    # 2ª tentativa: verifica se é um modelo do servidor llama.cpp local.
    # O llama.cpp usa a API compatível com OpenAI, por isso usa-se ChatOpenAI
    # com o base_url apontando para o servidor local.
    # A api_key é necessária pelo protocolo OpenAI mas pode ser um valor fictício
    # para servidores locais que não exijam autenticação.
    for llama_model in fetch_llama_cpp_models():
        if _normalize_model_name(llama_model) == model_choice_lower:
            return {
                "class": ChatOpenAI,
                "constructor_params": {
                    "model_name": llama_model,
                    "base_url": LLAMA_CPP_BASE_URL,
                    # Usa a chave OpenAI se disponível; caso contrário usa um valor fictício
                    # que satisfaz o protocolo sem causar erros de autenticação no servidor local
                    "api_key": OPENAI_API_KEY or "sk-local",
                },
            }

    # 3ª tentativa: verifica se é um modelo Ollama instalado localmente.
    # O ChatOllama comunica directamente com o servidor Ollama via HTTP.
    for ollama_model in fetch_ollama_models():
        if _normalize_model_name(ollama_model) == model_choice_lower:
            return {
                "class": ChatOllama,
                "constructor_params": {"model": ollama_model, "base_url": OLLAMA_BASE_URL},
            }

    # Modelo não encontrado em nenhuma fonte — retorna None
    # O código chamador é responsável por tratar este caso (ex: mostrar erro na UI)
    return None
