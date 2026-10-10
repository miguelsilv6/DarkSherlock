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
import re
import requests
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import warnings

import safety

# Logger deste módulo — permite rastrear falhas de scraping por URL
# sem interromper o pipeline (nível DEBUG por omissão).
logger = logging.getLogger(__name__)

# N.º de URLs que a salvaguarda ética impediu na última chamada a scrape_multiple (diagnóstico/avaliação).
last_blocked_count = 0
# Desfecho por URL da última chamada a scrape_multiple (sem o texto): status, http_code, ...
last_details: dict[str, dict] = {}
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
    # 1 retry (era 3): páginas .onion mortas/offline são a falha dominante e
    # repetir não as recupera — só multiplica a latência por host morto. 1 retry
    # cobre falhas transitórias reais sem penalizar o caso comum.
    retry = Retry(
        total=1,           # Número máximo de tentativas globais por pedido
        read=1,            # Tentativas adicionais em caso de erro de leitura
        connect=1,         # Tentativas adicionais em caso de falha de ligação
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


# Limites e heurísticas da raspagem.
MAX_BYTES = 2_000_000          # corpo máximo lido por página (o resto é ignorado)
MAX_REDIRECTS = 5
_ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")
_REDIRECT_CODES = {301, 302, 303, 307, 308}
# Páginas de desafio/erro: só se classificam assim quando são curtas (uma
# página longa que mencione "captcha" de passagem continua a ser conteúdo).
_CHALLENGE_OR_ERROR = re.compile(
    r"captcha|are you (a )?human|verify (that )?you are|ddos[- ]protection|checking your browser"
    r"|access denied|403 forbidden|404 not found|page not found|502 bad gateway|503 service"
    r"|site (is )?(down|offline)|under maintenance|you are in (the )?queue|enable javascript",
    re.IGNORECASE,
)
_CHALLENGE_MAX_CHARS = 2500
_MIN_TEXT_CHARS = 150


def _decode(raw: bytes, response) -> str:
    """Descodifica o corpo: charset do cabeçalho, senão UTF-8 estrito, senão o detetado."""
    ctype = (response.headers.get("Content-Type") or "").lower()
    m = re.search(r"charset=([\w\-]+)", ctype)
    if m:
        try:
            return raw.decode(m.group(1), errors="replace")
        except LookupError:
            pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        enc = getattr(response, "apparent_encoding", None) or "latin-1"
        return raw.decode(enc, errors="replace")


def _read_body(response) -> tuple[bytes, bool]:
    """Lê no máximo MAX_BYTES do corpo. Devolve (bytes, truncado)."""
    chunks, total = [], 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= MAX_BYTES:
            return b"".join(chunks)[:MAX_BYTES], True
    return b"".join(chunks), False


def _html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.extract()
    return " ".join(soup.get_text(separator=" ").split())


def fetch_page(url_data, session=None) -> dict:
    """
    Pede uma página e devolve um registo com o desfecho, sem nunca usar o
    título do resultado de pesquisa como conteúdo.

    - Todo o tráfego passa pela sessão Tor (incluindo endereços fora de
      .onion): nunca há pedidos diretos que exponham o IP do investigador.
    - Os redirecionamentos são seguidos à mão (no máximo MAX_REDIRECTS) e cada
      destino passa pela salvaguarda ética antes de ser pedido.
    - Só conta como evidência ("status": "ok") uma resposta 200, de tipo
      texto/HTML, com texto suficiente e que não seja uma página de desafio
      (captcha) ou de erro.

    Devolve dict com: url, final_url, status, http_code, content_type, error,
    bytes, truncated, text. Valores de status: ok, http_error, non_html,
    challenge_or_error, too_short, blocked_redirect, too_many_redirects,
    timeout, connection_error, error, adapter_failed.
    """
    url = url_data["link"]
    rec = {"url": url, "final_url": url, "status": "error", "http_code": None, "content_type": "",
           "error": None, "bytes": 0, "truncated": False, "text": ""}

    # Fóruns autenticados (DarkForums, …): o adapter tem sessão própria via Tor.
    try:
        from forum_adapters import get_adapter_for_url
        adapter = get_adapter_for_url(url)
    except Exception:  # noqa: BLE001 — import falha não deve quebrar o scrape
        adapter = None
    if adapter is not None and adapter.is_configured():
        text = adapter.fetch_thread(url)
        if text:
            rec.update(status="ok", text=" ".join(text.split()), content_type="adapter")
            return rec
        rec["status"] = "adapter_failed"

    headers = {"User-Agent": random.choice(USER_AGENTS)}
    tor_session = session if session is not None else get_tor_session()
    current = url
    try:
        for _hop in range(MAX_REDIRECTS + 1):
            # connect curto (15 s) para descartar rapidamente serviços offline;
            # read generoso (45 s) para a latência do onion routing.
            response = tor_session.get(current, headers=headers, timeout=(15, 45),
                                       allow_redirects=False, stream=True)
            rec["http_code"] = response.status_code
            if response.status_code in _REDIRECT_CODES and response.headers.get("Location"):
                nxt = urljoin(current, response.headers["Location"])
                response.close()
                pattern = safety.blocked_pattern({"title": "", "link": nxt})
                if pattern:
                    safety.log_referral(nxt, url_data.get("found_by"), pattern, source="redirect")
                    logger.warning("Salvaguarda ética: redirecionamento não seguido (padrão: %s).", pattern)
                    rec.update(status="blocked_redirect", final_url=nxt)
                    return rec
                current = nxt
                continue
            break
        else:
            rec.update(status="too_many_redirects", final_url=current)
            return rec

        rec["final_url"] = current
        ctype = (response.headers.get("Content-Type") or "text/html").split(";")[0].strip().lower()
        rec["content_type"] = ctype
        if response.status_code != 200:
            rec["status"] = "http_error"
            response.close()
            return rec
        if not ctype.startswith(_ALLOWED_CONTENT_TYPES):
            rec["status"] = "non_html"
            response.close()
            return rec
        raw, truncated = _read_body(response)
        response.close()
        rec["bytes"], rec["truncated"] = len(raw), truncated
        body = _decode(raw, response)
        text = _html_to_text(body) if ctype != "text/plain" else " ".join(body.split())
        if len(text) < _MIN_TEXT_CHARS:
            rec.update(status="too_short", text=text)
        elif len(text) <= _CHALLENGE_MAX_CHARS and _CHALLENGE_OR_ERROR.search(text):
            rec.update(status="challenge_or_error", text=text)
        else:
            rec.update(status="ok", text=text)
        return rec
    except requests.Timeout:
        logger.debug("Timeout ao aceder a %s", url)
        rec["status"] = "timeout"
    except requests.ConnectionError as e:
        logger.debug("Erro de ligação a %s: %s", url, e)
        rec.update(status="connection_error", error=str(e)[:200])
    except Exception as e:  # noqa: BLE001 — uma URL falhada não pode parar o lote
        logger.debug("Erro inesperado ao aceder a %s: %s", url, e)
        rec.update(status="error", error=str(e)[:200])
    return rec


def scrape_single(url_data, session=None, rotate=False, rotate_interval=5, control_port=9051, control_password=None):
    """
    Compatibilidade: devolve (url, texto) — texto vazio se a página não for
    evidência válida (ver fetch_page). O título do resultado de pesquisa já
    não é usado como conteúdo nem anteposto ao texto.
    """
    rec = fetch_page(url_data, session)
    return rec["url"], rec["text"] if rec["status"] == "ok" else ""

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

    # Salvaguarda ética (ver safety.py): URLs cujo título/URL indique conteúdo
    # de abuso sexual de menores nunca são pedidos. Só se regista o n.º de
    # bloqueios e o padrão que casou, nunca o título.
    global last_blocked_count, last_details
    details: dict[str, dict] = {}
    urls_data, blocked = safety.split_blocked(list(urls_data))
    last_blocked_count = len(blocked)
    for item, pattern in blocked:
        logger.warning("Salvaguarda ética: um URL não foi pedido (padrão: %s).", pattern)
        safety.log_referral(item.get("link", ""), item.get("found_by"), pattern, source="scrape")
        details[item.get("link", "")] = {"url": item.get("link", ""), "status": "blocked_safety"}

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
            executor.submit(fetch_page, url_data, shared_session): url_data
            for url_data in urls_data
        }

        # `as_completed` devolve cada future assim que termina (por ordem de
        # conclusão, não de submissão), permitindo processar resultados
        # imediatamente sem esperar que todas as tarefas terminem.
        for future in as_completed(future_to_url):
            url_data = future_to_url[future]
            try:
                rec = future.result()
            except Exception as e:  # noqa: BLE001
                rec = {"url": url_data["link"], "status": "error", "error": str(e)[:200], "text": ""}
            details[rec["url"]] = {k: v for k, v in rec.items() if k != "text"}
            if rec.get("status") != "ok":
                continue
            # Trunca ao último parágrafo/frase completa antes do limite.
            results[rec["url"]] = _truncate_at_paragraph(rec["text"], max_chars)

    last_details = details
    return results
