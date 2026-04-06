"""
scrape.py — Módulo de raspagem web para a ferramenta OSINT de dark web.

Este módulo é responsável por obter o conteúdo textual de URLs, incluindo
sites .onion da rede Tor. A comunicação com a rede Tor é feita através de
um proxy SOCKS5h local (Tor daemon), garantindo anonimato e a resolução
correta de nomes de domínio .onion dentro do próprio proxy.

O módulo expõe duas funções principais:
  - scrape_single: raspa uma única URL e devolve o texto limpo.
  - scrape_multiple: raspa várias URLs em paralelo usando um pool de threads.

Contexto académico: Dissertação de Mestrado em Cibersegurança — ferramenta
OSINT alimentada por IA para monitorização da dark web.
"""

import logging
import random
import requests
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

import warnings

# Logger deste módulo — permite rastrear falhas de scraping por URL
# sem interromper o pipeline (nível DEBUG por omissão).
logger = logging.getLogger(__name__)
# Suprime avisos de SSL e outros avisos não críticos do urllib3/requests
# que surgem frequentemente ao lidar com certificados em sites .onion ou
# configurações de proxy não convencionais.
warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Lista de User-Agents reais para rotação de identidade HTTP.
#
# A rotação de User-Agent é uma técnica fundamental de evasão de deteção:
# muitos servidores web (incluindo serviços ocultos Tor) bloqueiam ou
# limitam pedidos que apresentam sempre o mesmo identificador de cliente,
# ou que usam strings genéricas associadas a bots/crawlers automáticos.
# Ao selecionar aleatoriamente um User-Agent de uma lista de browsers reais
# e atualizados (Chrome, Firefox, Safari, Edge), os pedidos aparentam ser
# originados por utilizadores humanos, reduzindo a probabilidade de bloqueio.
# ---------------------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54"
]

def get_tor_session():
    """
    Cria e devolve uma sessão HTTP configurada para comunicar através do Tor.

    A sessão usa o protocolo SOCKS5h (e não SOCKS5 simples). A diferença é
    crítica: com SOCKS5h, a resolução DNS é delegada ao próprio proxy Tor,
    o que é obrigatório para aceder a domínios .onion — esses domínios não
    existem no DNS público e só são resolvíveis dentro da rede Tor. Com
    SOCKS5 simples, o cliente tentaria resolver o domínio localmente,
    falhando imediatamente para qualquer endereço .onion.

    É também configurada uma política de reenvio automático (retry) para
    lidar com a instabilidade inerente à rede Tor:
      - total=3: máximo de 3 tentativas por pedido.
      - read/connect=3: reenvio específico para falhas de leitura e ligação.
      - backoff_factor=0.3: espera progressiva entre tentativas
        (0.3 s, 0.6 s, 1.2 s), evitando sobrecarregar nós Tor já instáveis.
      - status_forcelist: reenvio automático para códigos de erro HTTP do
        lado do servidor (5xx), que são comuns em serviços ocultos com
        recursos limitados ou sobrecarga temporária.

    O adaptador com retry é montado tanto em http:// como em https://,
    cobrindo serviços ocultos com e sem TLS.

    Devolve:
        requests.Session: sessão configurada com proxy Tor e política de retry.
    """
    session = requests.Session()
    retry = Retry(
        total=3,           # Número máximo de tentativas globais por pedido
        read=3,            # Tentativas adicionais em caso de erro de leitura
        connect=3,         # Tentativas adicionais em caso de falha de ligação
        backoff_factor=0.3,            # Fator de espera exponencial entre tentativas
        status_forcelist=[500, 502, 503, 504]  # Códigos HTTP que ativam o reenvio
    )
    adapter = HTTPAdapter(max_retries=retry)

    # Monta o adaptador para ambos os esquemas URI utilizados por serviços ocultos
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Configura o proxy SOCKS5h apontando para o daemon Tor local.
    # A porta 9050 é a porta SOCKS padrão do Tor.
    # O prefixo "socks5h://" instrui a biblioteca a delegar a resolução DNS
    # ao proxy (o "h" significa "host resolution via proxy").
    session.proxies = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050"
    }
    return session

def _truncate_at_paragraph(text: str, max_chars: int) -> str:
    """Trunca o texto no último parágrafo ou frase completa antes de max_chars.

    A truncagem naïve por posição exacta (text[:n]) corta frases a meio,
    o que prejudica a compreensão pelo LLM. Esta função procura o último
    parágrafo ('\\n\\n') ou frase ('. ') antes do limite e trunca aí,
    produzindo um texto mais coerente. Se não encontrar uma fronteira
    adequada (i.e., a fronteira ficaria antes de 60% do limite), aplica
    truncagem simples com marcador '...' para evitar perda excessiva de
    conteúdo.

    Parâmetros:
        text:      Texto a truncar.
        max_chars: Número máximo de caracteres no texto devolvido.

    Devolve:
        Texto truncado (≤ max_chars caracteres).
    """
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars]
    last_para = truncated.rfind('\n\n')
    last_period = truncated.rfind('. ')
    boundary = max(last_para, last_period)
    # Só corta na fronteira se esta não estiver demasiado perto do início
    # (menos de 60% do limite seria perda excessiva de conteúdo)
    if boundary > max_chars * 0.6:
        return truncated[:boundary + 1].strip()
    return truncated.rstrip() + "..."


def scrape_single(url_data, session=None, rotate=False, rotate_interval=5, control_port=9051, control_password=None):
    """
    Raspa uma única URL e devolve o seu conteúdo textual limpo.

    A função deteta automaticamente se a URL é um endereço .onion e, nesse
    caso, encaminha o pedido pela rede Tor. Para URLs da clearweb, é usado
    um pedido direto como alternativa (embora o foco principal da ferramenta
    seja a dark web).

    O texto devolvido é pré-processado para remover ruído HTML (scripts,
    estilos, espaços em branco excessivos), produzindo conteúdo adequado
    para ingestão por um modelo de linguagem (LLM).

    Em caso de falha (timeout, erro de rede, código HTTP não-200), a função
    devolve apenas o título da página como conteúdo, garantindo que a
    referência à URL não se perde no pipeline de análise.

    Parâmetros:
        url_data (dict): dicionário com pelo menos as chaves 'link' (str) e
                         'title' (str), tipicamente proveniente dos resultados
                         de um motor de busca .onion.
        session (requests.Session | None): sessão Tor partilhada criada pelo
                         chamador. Se None, cria uma nova sessão dedicada.
                         Passar uma sessão partilhada elimina o overhead de
                         estabelecimento de circuito Tor por cada URL.
        rotate (bool): reservado para rotação de circuito Tor (não implementado
                       nesta versão).
        rotate_interval (int): intervalo de rotação em segundos (reservado).
        control_port (int): porta do controlador Tor para rotação de circuito
                            (reservado, padrão 9051).
        control_password (str | None): palavra-passe do controlador Tor
                                       (reservado).

    Devolve:
        tuple[str, str]: par (url, texto_raspado) onde url é o endereço
                         original e texto_raspado é o conteúdo limpo ou,
                         em caso de erro, apenas o título.
    """
    url = url_data['link']

    # Deteta se o destino é um serviço oculto Tor pelo sufixo ".onion".
    # Esta verificação determina se o pedido deve ser encaminhado pelo proxy
    # Tor ou enviado diretamente para a clearweb.
    use_tor = ".onion" in url

    # Seleciona aleatoriamente um User-Agent da lista global para este pedido,
    # simulando o comportamento de um browser real e dificultando a
    # correlação de múltiplos pedidos provenientes da mesma ferramenta.
    headers = {
        "User-Agent": random.choice(USER_AGENTS)
    }

    try:
        if use_tor:
            # Reutiliza a sessão Tor partilhada passada pelo chamador, ou
            # cria uma nova se nenhuma foi fornecida. A reutilização elimina
            # o overhead de ~300-500 ms de estabelecimento de circuito Tor
            # que ocorreria se cada worker criasse a sua própria sessão.
            tor_session = session if session is not None else get_tor_session()
            # O timeout para pedidos Tor é mais alto (45 s) do que para a
            # clearweb porque a rede Tor introduz latência significativa:
            # cada pedido percorre pelo menos 3 nós (circuito onion routing),
            # e serviços ocultos têm frequentemente recursos limitados.
            response = tor_session.get(url, headers=headers, timeout=45)
        else:
            # Alternativa para URLs da clearweb, caso a ferramenta seja
            # utilizada fora do contexto dark web. O timeout é menor (30 s)
            # pois a latência da clearweb é substancialmente mais baixa.
            response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            # Analisa o HTML da resposta com BeautifulSoup usando o parser
            # "html.parser" nativo do Python (sem dependências externas).
            soup = BeautifulSoup(response.text, "html.parser")

            # Remove blocos <script> e <style> do DOM antes de extrair texto.
            # Estes elementos contêm código JavaScript e regras CSS que,
            # se incluídos, poluiriam o texto com conteúdo não semântico,
            # reduzindo a qualidade da análise subsequente pelo LLM.
            for script in soup(["script", "style"]):
                script.extract()

            # Extrai o texto puro do DOM restante, usando espaço como
            # separador entre elementos para preservar legibilidade.
            text = soup.get_text(separator=' ')

            # Normaliza espaços em branco: colapsa múltiplos espaços,
            # tabulações e quebras de linha num único espaço, produzindo
            # uma string compacta e uniforme.
            text = ' '.join(text.split())

            # Combina o título (para contexto de identificação) com o corpo
            # textual da página numa única string para o pipeline de análise.
            scraped_text = f"{url_data['title']} - {text}"
        else:
            # Se o servidor devolver um código de erro HTTP (ex.: 403, 404),
            # usa apenas o título como conteúdo, mantendo a referência à URL
            # sem perder o resultado no pipeline.
            scraped_text = url_data['title']
    except requests.Timeout:
        # Timeout específico: regista o URL para diagnóstico, mas continua
        logger.debug("Timeout ao aceder a %s", url)
        scraped_text = url_data['title']
    except requests.ConnectionError as e:
        # Erro de ligação: circuito Tor falhado, serviço .onion offline, etc.
        logger.debug("Erro de ligação a %s: %s", url, e)
        scraped_text = url_data['title']
    except Exception as e:
        # Captura qualquer outra excepção (erro de parsing, SSL, etc.)
        # e devolve o título como fallback. Esta abordagem defensiva
        # garante que uma falha numa URL individual não interrompe o
        # processamento das restantes URLs no pipeline.
        logger.debug("Erro inesperado ao aceder a %s: %s", url, e)
        scraped_text = url_data['title']

    return url, scraped_text

def scrape_multiple(urls_data, max_workers=5):
    """
    Raspa múltiplas URLs em paralelo usando um pool de threads gerido.

    A concorrência é essencial neste contexto porque a latência da rede Tor
    é elevada e imprevisível: processar URLs de forma sequencial resultaria
    num tempo de espera acumulado inaceitável. Com um ThreadPoolExecutor,
    até `max_workers` pedidos decorrem em simultâneo, reduzindo o tempo
    total de raspagem de O(n * latência_média) para aproximadamente
    O(latência_máxima), limitado pelo URL mais lento do lote.

    O conteúdo de cada URL é truncado a `max_chars` caracteres antes de ser
    armazenado. Este limite protege o contexto do LLM: modelos de linguagem
    têm uma janela de contexto finita, e páginas muito longas (fóruns,
    marketplaces) excederiam facilmente esse limite, prejudicando a análise
    de outras URLs do mesmo lote. O sufixo "...(truncated)" sinaliza ao LLM
    que o conteúdo foi cortado.

    As exceções lançadas por futures individuais são silenciadas com
    `continue`, de modo a que uma falha isolada não interrompa a recolha
    dos restantes resultados.

    Parâmetros:
        urls_data (list[dict]): lista de dicionários de URL, cada um com
                                pelo menos as chaves 'link' e 'title'.
        max_workers (int): número máximo de threads paralelas (padrão: 5).
                           Valores mais elevados aumentam o throughput mas
                           podem sobrecarregar o daemon Tor local.

    Devolve:
        dict[str, str]: dicionário que mapeia cada URL ao seu conteúdo
                        textual raspado (ou título em caso de falha).
    """
    results = {}
    max_chars = 2000  # Limite máximo de caracteres por URL para proteger a janela de contexto do LLM

    # Cria UMA sessão Tor partilhada por todos os workers do pool.
    # Sem esta optimização, cada worker chamaria get_tor_session() internamente,
    # criando N sessões independentes — cada uma com overhead de ~300-500 ms de
    # estabelecimento de circuito Tor. Com uma sessão partilhada, esse overhead
    # ocorre apenas uma vez. As sessões requests.Session com proxies SOCKS são
    # thread-safe para operações de leitura concorrente.
    shared_session = get_tor_session()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submete todas as tarefas de raspagem ao pool de threads de uma só vez,
        # passando a sessão partilhada a cada worker.
        # O dicionário future_to_url permite recuperar os metadados originais
        # (url_data) a partir do future correspondente, se necessário para
        # diagnóstico ou logging futuro.
        future_to_url = {
            executor.submit(scrape_single, url_data, shared_session): url_data
            for url_data in urls_data
        }

        # `as_completed` devolve cada future assim que termina (por ordem de
        # conclusão, não de submissão), permitindo processar resultados
        # imediatamente sem esperar que todas as tarefas terminem.
        for future in as_completed(future_to_url):
            try:
                url, content = future.result()

                # Trunca o conteúdo ao último parágrafo ou frase completa
                # antes do limite, em vez de cortar a meio de uma frase.
                # A truncagem inteligente preserva a coerência do texto
                # para o LLM, melhorando a qualidade da análise.
                content = _truncate_at_paragraph(content, max_chars)

                results[url] = content
            except Exception:
                # Ignora silenciosamente falhas individuais para garantir
                # resiliência: uma URL inacessível não deve bloquear os
                # resultados das restantes URLs do lote.
                continue

    return results
