"""
sidebar.py — Barra lateral partilhada entre todas as páginas da aplicação DarkSherlock.

Padrão de sidebar partilhada no Streamlit:
    O Streamlit trata cada ficheiro na pasta `pages/` como uma página independente
    com o seu próprio estado de execução. Para evitar duplicar o código da sidebar
    em cada página, este módulo centraliza toda a lógica de renderização da barra
    lateral na função `render_sidebar()`.

    Cada página da aplicação importa e chama `render_sidebar()` no início da sua
    execução, obtendo em troca um dicionário com as configurações seleccionadas
    pelo utilizador. Desta forma:
      - A sidebar tem sempre o mesmo aspecto e comportamento em todas as páginas;
      - As alterações de configuração (novo modelo, novos sliders, etc.) são feitas
        num único lugar;
      - O acoplamento entre páginas e configuração é mínimo — cada página apenas
        recebe o dicionário de configurações retornado.

Secções da sidebar:
    1. Título e subtítulo da aplicação
    2. Configurações (modelo LLM, threads, limites de resultados e páginas)
    3. Configuração de fornecedores (estado das chaves de API)
    4. Definições de prompt (domínio de investigação, prompt do sistema, instruções)
    5. Verificações de saúde (LLM e motores de pesquisa via Tor)

Retorno de render_sidebar():
    Dicionário com todas as configurações seleccionadas pelo utilizador, pronto
    a ser consumido pelas páginas de análise OSINT.
"""

"""Shared sidebar rendered on every page."""

import streamlit as st
from llm_utils import get_model_choices
from llm import PRESET_PROMPTS
from health import check_llm_health, check_search_engines, check_tor_proxy, rotate_tor_circuit
from config import (
    OPENAI_API_KEY,
    ANTHROPIC_API_KEY,
    GOOGLE_API_KEY,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OLLAMA_BASE_URL,
    LLAMA_CPP_BASE_URL,
)


def _env_is_set(value) -> bool:
    """
    Verifica se um valor de configuração está correctamente definido.

    Utilizada na secção "Provider Configuration" da sidebar para mostrar
    o estado de cada fornecedor (chave configurada, ausente, ou opcional).

    Uma variável é considerada não definida se:
      - For None ou string vazia;
      - Contiver apenas espaços em branco;
      - Contiver "your_", que é o marcador de posição nos ficheiros `.env.example`.

    Parâmetros:
        value: O valor da variável de configuração (normalmente uma string ou None).

    Retorna:
        bool: True se o valor for válido e utilizável, False caso contrário.
    """
    return bool(value and str(value).strip() and "your_" not in str(value))


def render_sidebar():
    """Render the full sidebar and return the user-selected settings.

    Renderiza a barra lateral completa do DarkSherlock e devolve um dicionário
    com todas as configurações seleccionadas pelo utilizador.

    Esta função deve ser chamada no início de cada página Streamlit. O Streamlit
    executa o script da página de cima para baixo a cada interacção do utilizador,
    pelo que a sidebar é re-renderizada automaticamente com os valores actuais
    do `st.session_state` (os widgets do Streamlit persistem os seus valores
    entre re-execuções através de chaves únicas — parâmetro `key`).

    Retorna:
        dict: Dicionário com as seguintes chaves:
            - "model"                (str)  : Nome do modelo LLM seleccionado.
            - "threads"              (int)  : Número de threads de scraping paralelas.
            - "max_results"          (int)  : Limite máximo de resultados a filtrar.
            - "max_scrape"           (int)  : Limite máximo de páginas a fazer scrape.
            - "selected_preset"      (str)  : Identificador interno do preset de prompt.
            - "selected_preset_label"(str)  : Etiqueta legível do preset seleccionado.
            - "custom_instructions"  (str)  : Instruções personalizadas do utilizador.
    """

    # --- Cabeçalho da aplicação ---
    # Nome e descrição da ferramenta mostrados no topo da sidebar em todas as páginas
    st.sidebar.title("DarkSherlock")
    st.sidebar.text("AI-Powered Dark Web OSINT Tool")

    # --- Secção: Configurações ---
    st.sidebar.subheader("Settings")

    # Obtém a lista de modelos disponíveis com base nas chaves de API configuradas
    # e nos servidores locais em execução (Ollama, llama.cpp).
    model_options = get_model_choices()

    # Tenta pré-seleccionar o modelo "gpt4o" por omissão, se estiver disponível.
    # Caso contrário, selecciona o primeiro modelo da lista (índice 0).
    default_model_index = (
        next(
            (idx for idx, name in enumerate(model_options) if name.lower() == "gpt4o"),
            0,
        )
        if model_options
        else 0
    )

    # Se não houver nenhum modelo disponível, mostra uma mensagem de erro orientativa
    # para que o utilizador saiba que precisa de configurar pelo menos uma chave de API
    # ou iniciar um servidor local antes de poder usar a ferramenta.
    if not model_options:
        st.sidebar.error(
            "No LLM models available.\n\n"
            "No API keys or local providers are configured. "
            "Set at least one in your `.env` file and restart DarkSherlock.\n\n"
            "See **Provider Configuration** below for details."
        )

    # Selector de modelo LLM — o utilizador escolhe com que modelo quer trabalhar.
    # A chave "model_select" garante que o Streamlit persiste a escolha entre
    # re-execuções da página sem repor o valor por omissão.
    model = st.sidebar.selectbox(
        "Select LLM Model",
        model_options,
        index=default_model_index,
        key="model_select",
    )

    # Nota informativa mostrada quando há modelos locais Ollama na lista,
    # para que o utilizador saiba que esses modelos foram detectados automaticamente.
    if any(
        name
        not in {
            "gpt4o",
            "gpt-4.1",
            "claude-3-5-sonnet-latest",
            "llama3.1",
            "gemini-2.5-flash",
        }
        for name in model_options
    ):
        st.sidebar.caption(
            "Locally detected Ollama models are automatically added to this list."
        )

    # Slider: número de threads de scraping paralelas.
    # Valores mais altos aumentam a velocidade mas também a carga na rede e no CPU.
    # Intervalo: 1 a 16 threads; valor por omissão: 4.
    threads = st.sidebar.slider("Scraping Threads", 1, 16, 4, key="thread_slider")

    # Slider: número máximo de resultados de pesquisa passados ao passo de filtragem LLM.
    # Limitar este valor reduz o custo de tokens e o tempo de processamento.
    # Intervalo: 10 a 100 resultados; valor por omissão: 50.
    max_results = st.sidebar.slider(
        "Max Results to Filter",
        10,
        100,
        50,
        key="max_results_slider",
        help="Cap the number of raw search results passed to the LLM filter step.",
    )

    # Slider: número máximo de páginas que passam à fase de scraping de conteúdo.
    # Após a filtragem LLM, apenas um subconjunto dos resultados é efectivamente
    # visitado e o seu conteúdo extraído. Este slider limita esse subconjunto.
    # Intervalo: 3 a 20 páginas; valor por omissão: 10.
    max_scrape = st.sidebar.slider(
        "Max Pages to Scrape",
        3,
        20,
        10,
        key="max_scrape_slider",
        help="Cap the number of filtered results that get scraped for content.",
    )

    # --- Secção: Configuração de Fornecedores ---
    # Mostra o estado de configuração de cada fornecedor de LLM.
    # Isto permite ao utilizador verificar rapidamente quais as integrações activas
    # sem ter de abrir o ficheiro .env.
    st.sidebar.divider()
    st.sidebar.subheader("Provider Configuration")

    # Lista de fornecedores: (nome_display, valor_configuração, é_serviço_cloud)
    # O campo `is_cloud` distingue fornecedores na nuvem (que requerem chave de API)
    # de fornecedores locais (que são opcionais e usam um URL base em vez de chave).
    _providers = [
        ("OpenAI", OPENAI_API_KEY, True),
        ("Anthropic", ANTHROPIC_API_KEY, True),
        ("Google", GOOGLE_API_KEY, True),
        ("OpenRouter", OPENROUTER_API_KEY, True),
        ("Ollama", OLLAMA_BASE_URL, False),       # Local — opcional
        ("llama.cpp", LLAMA_CPP_BASE_URL, False), # Local — opcional
    ]
    for name, value, is_cloud in _providers:
        if _env_is_set(value):
            # Fornecedor configurado correctamente
            st.sidebar.markdown(f"&ensp;✅ **{name}** — configured")
        elif is_cloud:
            # Serviço na nuvem sem chave de API — o utilizador não poderá usar estes modelos
            st.sidebar.markdown(f"&ensp;⚠️ **{name}** — API key not set")
        else:
            # Servidor local não configurado — é opcional, por isso apenas informativo
            st.sidebar.markdown(f"&ensp;🔵 **{name}** — not configured *(optional)*")

    # --- Secção: Definições de Prompt ---
    # Painel expansível que permite ao utilizador escolher o domínio de investigação
    # OSINT e personalizar as instruções enviadas ao modelo LLM.
    with st.sidebar.expander("Prompt Settings"):

        # Mapeamento entre etiquetas legíveis (mostradas na UI) e identificadores
        # internos dos presets de prompt (usados para aceder a PRESET_PROMPTS).
        preset_options = {
            "Dark Web Threat Intel": "threat_intel",
            "Ransomware / Malware Focus": "ransomware_malware",
            "Personal / Identity Investigation": "personal_identity",
            "Corporate Espionage / Data Leaks": "corporate_espionage",
        }

        # Textos de exemplo para o campo de instruções personalizadas.
        # O texto muda consoante o preset seleccionado, dando pistas contextuais
        # ao utilizador sobre que tipo de instruções adicionais fazem sentido.
        preset_placeholders = {
            "threat_intel": "e.g. Pay extra attention to cryptocurrency wallet addresses and exchange names.",
            "ransomware_malware": "e.g. Highlight any references to double-extortion tactics or known ransomware-as-a-service affiliates.",
            "personal_identity": "e.g. Flag any passport or government ID numbers and note which country they appear to be from.",
            "corporate_espionage": "e.g. Prioritize any mentions of source code repositories, API keys, or internal Slack/email dumps.",
        }

        # Selector do domínio de investigação (preset de prompt).
        # A selecção determina qual o prompt do sistema enviado ao LLM,
        # orientando a sua análise para o contexto OSINT relevante.
        selected_preset_label = st.selectbox(
            "Research Domain",
            list(preset_options.keys()),
            key="preset_select",
            help="Also selectable from the main page before running a query.",
        )
        # Converte a etiqueta seleccionada para o identificador interno do preset
        selected_preset = preset_options[selected_preset_label]

        # Mostra o prompt do sistema correspondente ao preset seleccionado.
        # O campo está desactivado (disabled=True) para deixar claro que é um
        # valor de referência, não editável directamente neste campo.
        # O utilizador pode estender o comportamento através das instruções personalizadas.
        st.text_area(
            "System Prompt",
            value=PRESET_PROMPTS[selected_preset].strip(),
            height=200,
            disabled=True,
            key="system_prompt_display",
        )

        # Campo de texto livre para instruções adicionais do utilizador.
        # Estas instruções são anexadas ao prompt do sistema antes de ser enviado
        # ao LLM, permitindo personalizar a análise sem alterar o preset base.
        # O placeholder muda consoante o preset para sugerir exemplos relevantes.
        custom_instructions = st.text_area(
            "Custom Instructions (optional)",
            placeholder=preset_placeholders[selected_preset],
            height=100,
            key="custom_instructions",
        )

    # --- Secção: Verificações de Saúde ---
    # Permite ao utilizador testar a conectividade com o LLM e com os motores
    # de pesquisa da dark web antes de iniciar uma investigação.
    st.sidebar.divider()
    st.sidebar.subheader("Health Checks")

    # Botão para testar a ligação ao modelo LLM actualmente seleccionado.
    # Envia um pedido de teste e mede a latência, confirmando que o modelo
    # está acessível e a responder correctamente.
    if st.sidebar.button("Check LLM Connection", use_container_width=True):
        with st.sidebar:
            with st.spinner(f"Testing {model}..."):
                result = check_llm_health(model)
            if result["status"] == "up":
                # Mostra o fornecedor, estado e latência em milissegundos
                st.sidebar.success(
                    f"**{result['provider']}** — Connected ({result['latency_ms']}ms)"
                )
            else:
                # Mostra o fornecedor e a mensagem de erro para diagnóstico
                st.sidebar.error(
                    f"**{result['provider']}** — Failed\n\n{result['error']}"
                )

    # Botão para verificar a conectividade com o proxy Tor e com os motores
    # de pesquisa da dark web (ex: Ahmia, Torch, Haystak).
    # A verificação ocorre em dois passos:
    #   1. Verifica se o proxy Tor está acessível — pré-requisito obrigatório.
    #   2. Só se o Tor estiver activo, testa cada motor de pesquisa individualmente.
    if st.sidebar.button("Check Search Engines", use_container_width=True):
        with st.sidebar:
            # Passo 1: verifica o proxy Tor
            with st.spinner("Checking Tor proxy..."):
                tor_result = check_tor_proxy()
            if tor_result["status"] == "down":
                # Tor não está em execução — mostra instrução para o iniciar
                st.sidebar.error(
                    f"**Tor Proxy** — Not reachable\n\n{tor_result['error']}\n\n"
                    "Ensure Tor is running: `sudo systemctl start tor`"
                )
            else:
                # Tor está acessível — passo 2: testa os motores de pesquisa
                st.sidebar.success(
                    f"**Tor Proxy** — Connected ({tor_result['latency_ms']}ms)"
                )
                with st.spinner("Pinging active search engines via Tor..."):
                    engine_results = check_search_engines()

                # Conta os motores acessíveis e mostra um resumo
                up_count = sum(1 for r in engine_results if r["status"] == "up")
                total = len(engine_results)
                if up_count == total:
                    # Todos os motores estão acessíveis
                    st.sidebar.success(f"All {total} engines reachable")
                elif up_count > 0:
                    # Apenas alguns motores estão acessíveis — aviso parcial
                    st.sidebar.warning(f"{up_count}/{total} engines reachable")
                else:
                    # Nenhum motor de pesquisa está acessível
                    st.sidebar.error(f"0/{total} engines reachable")

                # Mostra o estado individual de cada motor de pesquisa
                for r in engine_results:
                    if r["status"] == "up":
                        # Motor acessível — mostra nome e latência
                        st.sidebar.markdown(
                            f"&ensp;🟢 **{r['name']}** — {r['latency_ms']}ms"
                        )
                    else:
                        # Motor inacessível — mostra nome e motivo do erro
                        st.sidebar.markdown(
                            f"&ensp;🔴 **{r['name']}** — {r['error']}"
                        )

    # Botão para rodar o circuito Tor — solicita um novo circuito ao control port
    # (porta 9051), alterando o nó de saída e o IP aparente da ferramenta.
    # Requer ControlPort 9051 activo no torrc.
    if st.sidebar.button("Rodar Circuito Tor", use_container_width=True):
        with st.sidebar:
            with st.spinner("A solicitar novo circuito Tor..."):
                result = rotate_tor_circuit()
            if result["status"] == "rotated":
                st.sidebar.success(result["message"])
            else:
                st.sidebar.warning(result["message"])

    # Devolve todas as configurações seleccionadas na sidebar como um dicionário.
    # As páginas que chamam render_sidebar() utilizam este dicionário para
    # parametrizar as suas operações de pesquisa e análise OSINT.
    return {
        "model": model,                               # Modelo LLM seleccionado
        "threads": threads,                           # Threads de scraping paralelas
        "max_results": max_results,                   # Limite de resultados a filtrar
        "max_scrape": max_scrape,                     # Limite de páginas a scrape
        "selected_preset": selected_preset,           # Identificador interno do preset
        "selected_preset_label": selected_preset_label, # Etiqueta legível do preset
        "custom_instructions": custom_instructions,   # Instruções personalizadas
    }
