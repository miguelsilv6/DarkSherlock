"""
search.py — Motor de Pesquisa Distribuída na Dark Web

Este módulo é o núcleo de recolha de dados OSINT da ferramenta. A sua
responsabilidade é receber uma query refinada (já processada pelo LLM) e
devolver uma lista deduplicada de resultados .onion encontrados em múltiplos
motores de pesquisa da dark web.

Fluxo principal:
  1. A query é submetida em paralelo a todos os motores de pesquisa activos.
  2. Cada pedido HTTP é encaminhado através do proxy SOCKS5 do Tor (porta 9050),
     garantindo anonimato e capacidade de aceder a domínios .onion.
  3. As respostas HTML são analisadas com BeautifulSoup para extrair hiperligações
     .onion válidas.
  4. Os resultados de todos os motores são agregados e deduplicados antes de
     serem devolvidos ao módulo chamador.

Contexto académico:
  Inserido numa dissertação de Mestrado em Cibersegurança sobre ferramentas
  OSINT potenciadas por IA para investigação na dark web.
"""

import requests
import random, re
import json
import os
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import warnings
# Suprimir avisos SSL/TLS e de verificação de certificados — irrelevante no
# contexto .onion, onde os domínios são endereços criptográficos por natureza.
warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# User-Agents
# ---------------------------------------------------------------------------
# Lista de User-Agent strings de browsers reais e actualizados.
# O objectivo é imitar tráfego legítimo de utilizadores humanos, reduzindo a
# probabilidade de os motores de pesquisa .onion bloquearem os pedidos por
# identificarem um bot. A rotação aleatória por pedido dificulta a detecção
# de padrões de acesso automatizado.
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

# ---------------------------------------------------------------------------
# Motores de pesquisa embutidos (builtins)
# ---------------------------------------------------------------------------
# Cada entrada define o nome do motor e o template de URL.
# O placeholder {query} será substituído em tempo de execução pela query real
# (ver fetch_search_results). Esta abordagem permite adicionar novos motores
# sem alterar a lógica de pesquisa — basta acrescentar um dicionário a esta
# lista ou, preferencialmente, gerir os motores via engine_manager.py.
SEARCH_ENGINES = [
    # ---------------------------------------------------------------------------
    # Motores base (activos por omissão) — testados e verificados
    # ---------------------------------------------------------------------------
    {"name": "Ahmia",           "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"},
    {"name": "OnionLand",       "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}"},
    {"name": "Torgle",          "url": "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?query={query}"},
    {"name": "Amnesia",         "url": "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}"},
    {"name": "Kaizer",          "url": "http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q={query}"},
    {"name": "Anima",           "url": "http://anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid.onion/search?q={query}"},
    {"name": "Tornado",         "url": "http://tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd.onion/search?q={query}"},
    {"name": "TorNet",          "url": "http://tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid.onion/search?q={query}"},
    {"name": "Torland",         "url": "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}"},
    {"name": "Find Tor",        "url": "http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={query}"},
    {"name": "Excavator",       "url": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}"},
    {"name": "Onionway",        "url": "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}"},
    {"name": "Tor66",           "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}"},
    {"name": "OSS",             "url": "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}"},
    {"name": "Torgol",          "url": "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}"},
    {"name": "The Deep Searches","url": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}"},

    # ---------------------------------------------------------------------------
    # Motores adicionais — fonte: fastfire/deepdarkCTI (desactivados por omissão)
    #
    # Estes motores foram verificados como ONLINE no repositório deepdarkCTI.
    # Estão desactivados por omissão para não sobrecarregar o pipeline com
    # engines ainda não testadas neste contexto. O utilizador pode activá-los
    # individualmente na página "Search Engines".
    # ---------------------------------------------------------------------------
    {"name": "Haystak",         "url": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={query}",                        "default_enabled": False},
    {"name": "Torch",           "url": "http://torchqsxkllrj2eqaitp5xvcgfeg3g5dr3hr2wnuvnj76bbxkxfiwxqd.onion/search?q={query}",                   "default_enabled": False},
    {"name": "Tordex",          "url": "http://tordexu73joywapk2txdr54jed4imqledpcvcuf75qsas2gwdgksvnyd.onion/?q={query}",                         "default_enabled": False},
    {"name": "DarkSearch",      "url": "http://darkschn4iw2hxvpv2vy2uoxwkvs2padb56t3h4wqztre6upoc5qwgid.onion/search?q={query}",                   "default_enabled": False},
    {"name": "Bobby",           "url": "http://bobby64o755x3gsuznts6hf6agxqjcz5bop6hs7ejorekbm7omes34ad.onion/?q={query}",                         "default_enabled": False},
    {"name": "Evo Search",      "url": "http://wbr4bzzxbeidc6dwcqgwr3b6jl7ewtykooddsc5ztev3t3otnl45khyd.onion/evo/search.php?q={query}",           "default_enabled": False},
    {"name": "VisiTOR",         "url": "http://uzowkytjk4da724giztttfly4rugfnbqkexecotfp5wjc2uhpykrpryd.onion/search/?q={query}",                  "default_enabled": False},
    {"name": "SearX",           "url": "http://z5vawdol25vrmorm4yydmohsd4u6rdoj2sylvoi3e3nqvxkvpqul7bqd.onion/search?q={query}",                   "default_enabled": False},
    {"name": "Demon",           "url": "http://srcdemonm74icqjvejew6fprssuolyoc2usjdwflevbdpqoetw4x3ead.onion/search?q={query}",                   "default_enabled": False},
    {"name": "Deep Search",     "url": "http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion/search?q={query}",                   "default_enabled": False},
    {"name": "OnionSearch",     "url": "http://searchpxsd4vdpf35uk4ycgxolp732zhs7zr4qgftt6qvmgpo6mukbyd.onion/?q={query}",                        "default_enabled": False},
    {"name": "Kraken",          "url": "http://krakenai2gmgwwqyo7bcklv2lzcvhe7cxzzva2xpygyax5f33oqnxpad.onion/?q={query}",                        "default_enabled": False},
    {"name": "Hoodle",          "url": "http://nr2dvqdot7yw6b5poyjb7tzot7fjrrweb2fhugvytbbio7ijkrvicuid.onion/?q={query}",                        "default_enabled": False},
    {"name": "GDark",           "url": "http://zb2jtkhnbvhkya3d46twv3g7lkobi4s62tjffqmafjibixk6pmq75did.onion/?q={query}",                        "default_enabled": False},
    {"name": "Tornet Global",   "url": "http://xcprh4cjas33jnxgs3zhakof6mctilfxigwjcsevdfap7vtyj57lmjad.onion/tgs/?q={query}",                    "default_enabled": False},
    {"name": "DarkwebDaily",    "url": "http://dailydwusclfsu7fzwydc5emidexnesmdlzqmz2dxnx5x4thl42vj4qd.onion/?q={query}",                        "default_enabled": False},
    {"name": "Stealth",         "url": "http://stealth5wfeiuvmtgd2s3m2nx2bb3ywdo2yiklof77xf6emkwjqo53yd.onion/?q={query}",                        "default_enabled": False},
    {"name": "Snow Search",     "url": "http://snowsrchzbc2xdkmgvimetleohpnnnscnsgwmvneizcb34ywwocahiyd.onion/?q={query}",                        "default_enabled": False},
]

# Lista plana de URLs extraída de SEARCH_ENGINES, mantida para
# compatibilidade retroactiva com código existente que possa referenciar
# DEFAULT_SEARCH_ENGINES directamente (e.g., versões anteriores do projecto).
# A lógica de pesquisa actual lê os motores activos via engine_manager.py.
DEFAULT_SEARCH_ENGINES = [e["url"] for e in SEARCH_ENGINES]


def get_tor_session():
    """
    Cria e devolve uma sessão HTTP configurada para rotear tráfego pelo Tor.

    Porquê usar SOCKS5h em vez de SOCKS5?
      - 'socks5h' delega a resolução DNS ao proxy (o nó de saída do Tor),
        em vez de resolver localmente. Isto é essencial para domínios .onion,
        que não existem no DNS público e só podem ser resolvidos dentro da
        rede Tor.

    Política de retenativas (Retry):
      - A rede Tor é intrinsecamente instável: circuitos podem falhar,
        servidores .onion ficam offline com frequência e latências são
        elevadas. A política de retry com backoff exponencial (backoff_factor)
        torna a sessão mais resiliente a falhas transitórias sem sobrecarregar
        os servidores.
      - status_forcelist: códigos HTTP de erro de servidor que justificam
        uma nova tentativa (5xx indicam falha temporária do servidor remoto).

    Retorna:
        requests.Session: sessão configurada com proxy Tor e retry automático.
    """
    session = requests.Session()

    # Configuração de retenativas automáticas:
    #   total/read/connect=3  → até 3 tentativas por pedido
    #   backoff_factor=0.5    → espera 0.5s, 1s, 2s entre tentativas
    #   status_forcelist      → repetir apenas em erros de servidor (5xx)
    retry = Retry(
        total=3,
        read=3,
        connect=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)

    # Montar o adaptador para HTTP e HTTPS, garantindo que todos os pedidos
    # passam pela política de retry independentemente do esquema de URL.
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Proxy SOCKS5h apontando para o daemon Tor local na porta padrão 9050.
    # A opção 'h' em 'socks5h' é crítica: sem ela, a resolução DNS seria
    # feita localmente e os endereços .onion falhariam com NXDOMAIN.
    session.proxies = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050"
    }
    return session


def fetch_search_results(endpoint, query, session=None):
    """
    Envia uma query a um único motor de pesquisa .onion e extrai os resultados.

    Processo:
      1. Substituição do placeholder: o template de URL recebe a query real
         via str.format(query=query), produzindo o URL final de pesquisa.
      2. Pedido HTTP via sessão Tor com User-Agent aleatório.
      3. Parsing HTML com BeautifulSoup para identificar todas as âncoras <a>.
      4. Extracção de URLs .onion via expressão regular.
      5. Filtragem básica para eliminar auto-referências ao motor de pesquisa.

    Porquê capturar todas as excepções silenciosamente?
      - Motores .onion ficam offline com frequência (timeout, circuitos Tor
        degradados, serviço temporariamente indisponível). Uma excepção num
        único motor não deve interromper a pesquisa nos restantes. A thread
        que invoca esta função devolve simplesmente uma lista vazia.

    Argumentos:
        endpoint (str): template de URL do motor, com placeholder {query}.
        query (str): termo de pesquisa já refinado pelo LLM.
        session (requests.Session | None): sessão Tor partilhada. Se None,
            cria uma nova sessão dedicada para este motor. Passar uma sessão
            partilhada elimina o overhead de estabelecimento de circuito Tor
            multiplicado pelo número de motores pesquisados em paralelo.

    Retorna:
        list[dict]: lista de dicionários {"title": str, "link": str},
                    ou lista vazia em caso de falha ou ausência de resultados.
    """
    # Substituição do placeholder {query} no template de URL do motor.
    # Ex.: "http://ahmia.fi/search/?q={query}" → "http://ahmia.fi/search/?q=bitcoin"
    url = endpoint.format(query=query)

    # Seleccionar um User-Agent aleatório a cada pedido para evitar
    # bloqueios baseados em fingerprinting do browser.
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    # Reutiliza a sessão partilhada se disponível; cria uma nova caso contrário
    session = session if session is not None else get_tor_session()

    try:
        # Timeout de 40 segundos — valor elevado justificado pela alta latência
        # inerente à rede Tor (múltiplos saltos criptográficos entre nós).
        response = session.get(url, headers=headers, timeout=40)

        if response.status_code == 200:
            # Usar BeautifulSoup para parsing tolerante a HTML malformado,
            # comum em serviços .onion que não seguem standards rigorosamente.
            soup = BeautifulSoup(response.text, "html.parser")
            links = []

            # Iterar sobre todas as âncoras da página.
            # A abordagem genérica (sem selectores específicos por motor)
            # funciona na maioria dos layouts de motores de pesquisa .onion,
            # que tipicamente listam resultados como <a href="url.onion">título</a>.
            for a in soup.find_all('a'):
                try:
                    href = a['href']
                    title = a.get_text(strip=True)

                    # Expressão regular para extrair URLs .onion completos,
                    # incluindo path e query string se presentes.
                    # O padrão [a-z0-9\.]+ cobre o hash v2/v3 do endereço .onion.
                    link = re.findall(r'https?:\/\/[a-z0-9\.]+\.onion.*', href)

                    if len(link) != 0:
                        # Filtro de qualidade duplo:
                        #   1. Excluir links que contenham "search" no URL —
                        #      tipicamente são links internos do próprio motor
                        #      de pesquisa (ex.: paginação, formulários).
                        #   2. Exigir título com mais de 3 caracteres para
                        #      descartar âncoras sem texto significativo
                        #      (ícones, botões, etc.).
                        if "search" not in link[0] and len(title) > 3:
                            links.append({"title": title, "link": link[0]})
                except:
                    # Ignorar âncoras sem atributo href ou com atributos
                    # inesperados — erros individuais não devem travar o loop.
                    continue

            return links
        else:
            # Código HTTP diferente de 200 (ex.: 403, 404, 503) —
            # devolver lista vazia sem lançar excepção.
            return []
    except:
        # Qualquer excepção de rede (timeout, recusa de ligação, erro SSL,
        # circuito Tor falhado) resulta em lista vazia para esta thread.
        return []


def get_search_results(refined_query, max_workers=5):
    """
    Orquestra a pesquisa concorrente em todos os motores de pesquisa activos.

    Estratégia de concorrência:
      - ThreadPoolExecutor lança até max_workers threads em simultâneo, cada
        uma chamando fetch_search_results para um motor diferente.
      - as_completed() processa os resultados à medida que cada thread termina
        (em vez de esperar que todas terminem), reduzindo a latência percebida.
      - O número de workers (padrão: 5) equilibra paralelismo e carga no
        circuito Tor — demasiadas threads simultâneas podem saturar a largura
        de banda disponível ou levantar suspeitas nos nós de entrada.

    Deduplicação:
      - Múltiplos motores de pesquisa indexam frequentemente os mesmos sites
        .onion, pelo que é expectável obter URLs duplicados.
      - A deduplicação usa um conjunto (set) de URLs normalizados (sem barra
        final) como estrutura de lookup O(1).
      - A normalização remove a barra final (rstrip('/')) para tratar
        "http://exemplo.onion/" e "http://exemplo.onion" como o mesmo recurso.

    Argumentos:
        refined_query (str): query de pesquisa já refinada pelo LLM.
        max_workers (int): número máximo de threads concorrentes. Padrão: 5.

    Retorna:
        list[dict]: lista deduplicada de resultados {"title": str, "link": str}.
    """
    # Importação local para evitar importação circular — engine_manager importa
    # de search.py, por isso search.py não pode importar engine_manager ao
    # nível do módulo.
    from engine_manager import get_active_engine_urls
    active_urls = get_active_engine_urls()

    results = []

    # Cria UMA sessão Tor partilhada por todos os workers do pool.
    # Sem esta optimização, fetch_search_results() criaria uma sessão nova
    # para cada motor, resultando em N sessões e N handshakes Tor (~300-500 ms
    # cada). Com uma sessão partilhada, o overhead ocorre apenas uma vez.
    shared_session = get_tor_session()

    # Lançar todos os pedidos em paralelo usando um pool de threads.
    # Cada future representa a execução assíncrona de fetch_search_results
    # para um único motor de pesquisa, partilhando a mesma sessão Tor.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(fetch_search_results, endpoint, refined_query, shared_session)
                   for endpoint in active_urls]

        # Processar resultados à medida que cada thread conclui,
        # independentemente da ordem de submissão.
        for future in as_completed(futures):
            result_urls = future.result()
            results.extend(result_urls)

    # --- Deduplicação de resultados ---
    # Usar um set para rastrear URLs já vistos com complexidade O(1) por lookup.
    seen_links = set()
    unique_results = []

    for res in results:
        link = res.get("link")
        # Normalizar o URL removendo barra final para evitar duplicados
        # causados por inconsistência de formatação entre motores.
        # Ex.: "http://abc.onion/page/" e "http://abc.onion/page" → mesmo recurso.
        clean_link = link.rstrip('/')

        if clean_link not in seen_links:
            # Primeiro avistamento deste URL — registar e incluir nos resultados.
            seen_links.add(clean_link)
            unique_results.append(res)
        # Se já foi visto, descartar silenciosamente o duplicado.

    return unique_results
