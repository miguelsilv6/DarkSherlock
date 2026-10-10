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
from urllib.parse import quote_plus, urlsplit, parse_qs
import threading
import logging

import search_filters as sf
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
    # Motores confirmados como mortos (EQ-06 — evaluation/analyze_engine_failures.py)
    #
    # 100% de falhas em todas as execuções instrumentadas (n=6 cada, ver
    # Capítulo 6, secção 6.4.6): nunca contribuíram um único resultado,
    # apenas latência. Desactivados por omissão; engine_manager.py também
    # migra instalações já existentes (config/search_engines.json) na
    # primeira execução após esta alteração.
    # ---------------------------------------------------------------------------
    {"name": "Kaizer",          "url": "http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q={query}",           "default_enabled": False},
    {"name": "Anima",           "url": "http://anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid.onion/search?q={query}",            "default_enabled": False},
    {"name": "Tornado",         "url": "http://tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd.onion/search?q={query}",             "default_enabled": False},

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

    # ---------------------------------------------------------------------------
    # Fóruns autenticados (type=forum) — pesquisa via adapter dedicado
    #
    # Estes engines NÃO usam o contrato GET-com-{query}. O campo `url` é
    # informativo (mostrado na UI); o pipeline despacha pela chave `adapter`
    # para `forum_adapters.get_adapter(...)`, que gere login, cookies e
    # parsing específicos ao layout do fórum. Permanecem desactivados por
    # omissão e só ficam utilizáveis se as credenciais estiverem no .env.
    # ---------------------------------------------------------------------------
    {
        "name": "DarkForums",
        "url": "https://darkforums.st/search.php",
        "type": "forum",
        "adapter": "darkforums",
        "default_enabled": False,
    },
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
    #   total/read/connect=1  → no máximo 1 retry por pedido
    #   backoff_factor=0.5    → espera 0.5s antes do retry
    #   status_forcelist      → repetir apenas em erros de servidor (5xx)
    #
    # Porquê só 1 retry (era 3): a esmagadora maioria das falhas em motores
    # .onion é "host unreachable" / serviço offline — repetir 3× não recupera
    # nada e multiplica a latência por hosts mortos (com timeout de connect,
    # cada tentativa custa segundos). 1 retry cobre falhas transitórias reais
    # sem penalizar o caso comum (engine em baixo).
    retry = Retry(
        total=1,
        read=1,
        connect=1,
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
      3. Verificação de que é uma página de resultados (ecoa a query).
      4. Extração das ligações .onion fora de <nav>/<header>/<footer>, com
         ligações relativas e redirecionamentos resolvidos (search_filters).
      A limpeza (hosts dos motores, navegação, spam, quotas) é feita depois,
      em get_search_results.

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
        tuple[list[dict], bool]: (resultados, motor_respondeu_com_sucesso).
        `motor_respondeu_com_sucesso` distingue "o motor respondeu 200 OK"
        (mesmo que 0 links tenham sido extraídos — o motor está vivo, só não
        teve resultados) de "falha técnica" (timeout, excepção de rede,
        circuito Tor degradado, ou qualquer status HTTP != 200) — é esta
        distinção que EQ-06 (Capítulo 6, "Tolerância a motores caídos")
        precisa para calcular a fração de motores que falharam, e que antes
        não existia: ambos os casos devolviam apenas `[]`, indistinguíveis.
    """
    # Substituição do placeholder {query} no template de URL do motor.
    # quote_plus codifica espaços como '+' e escapa caracteres reservados — o
    # encoding fica isolado aqui em vez de ser aplicado pelo chamador, para que
    # adapters (forum_adapters/) recebam a query original e possam fazer o
    # encoding apropriado ao seu protocolo (form-urlencoded, multipart, etc.).
    # Ex.: "http://ahmia.fi/search/?q={query}" + "leak forum" → ".../?q=leak+forum"
    url = endpoint.format(query=quote_plus(query))

    # Seleccionar um User-Agent aleatório a cada pedido para evitar
    # bloqueios baseados em fingerprinting do browser.
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    # Reutiliza a sessão partilhada se disponível; cria uma nova caso contrário
    session = session if session is not None else get_tor_session()

    try:
        # Timeout (connect, read): connect curto (15s) para falhar rápido em
        # hosts .onion inacessíveis (muito comuns), read generoso (40s) para a
        # alta latência da rede Tor em hosts que respondem. Antes era um único
        # 40s, o que fazia esperar 40s só para descobrir que um host estava
        # morto.
        response = session.get(url, headers=headers, timeout=(15, 40))

        if response.status_code == 200:
            html = response.text
            final_url = getattr(response, "url", "") or url
            # Uma página que não ecoa nenhum termo da query não é uma página de
            # resultados (p. ex. o motor redirecionou para a página inicial):
            # as suas ligações são navegação, não resultados.
            if not sf.looks_like_results_page(html, query):
                _set_detail(endpoint, "not_results_page", 0)
                return [], True
            links = [l for l in sf.extract_links(html, final_url) if len(l["title"]) > 3]
            _set_detail(endpoint, "ok_results" if links else "ok_empty", len(links))
            return links, True
        # Código HTTP diferente de 200 (ex.: 403, 404, 503): falha técnica do motor.
        _set_detail(endpoint, "http_error", 0)
        return [], False
    except Exception:  # noqa: BLE001 — um motor em baixo não pode parar a pesquisa
        # Qualquer excepção de rede (timeout, recusa de ligação, erro SSL,
        # circuito Tor falhado) é uma falha técnica do motor.
        _set_detail(endpoint, "exception", 0)
        return [], False


# Detalhe do desfecho por motor (além de "ok"/"failed"): ok_results, ok_empty,
# nav_only, not_results_page, http_error, exception. Preenchido por
# fetch_search_results e lido por get_search_results.
_detail_lock = threading.Lock()
_fetch_detail: dict[str, tuple[str, int]] = {}


def _set_detail(endpoint: str, status: str, n: int) -> None:
    with _detail_lock:
        _fetch_detail[endpoint] = (status, n)


# Domínios "irmãos" de motores conhecidos que aparecem como ligações nas páginas
# de resultados mas não são resultados (p. ex. as categorias do diretório do
# Amnesia, servidas noutro domínio). Acrescentam-se aos de "exclude_hosts" da config.
KNOWN_SIBLING_HOSTS = {
    "amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion": [
        "amndir7jfxnt5glt2tsevwjlnwdvknttxygubw27ulq5c433en75piyd.onion",
    ],
}

PER_HOST_CAP = 3

# Estatísticas da última chamada a get_search_results, por motor:
# {"status": ..., "raw": n, "nav_dropped": n, "engine_host_dropped": n, "spam_dropped": n, "kept": n}
last_search_stats: dict[str, dict] = {}

logger = logging.getLogger(__name__)


def _excluded_hosts(all_engines: list[dict]) -> set[str]:
    """Hosts de TODOS os motores configurados (ativos ou não), dos seus irmãos e de exclude_hosts."""
    hosts = set()
    for e in all_engines:
        h = sf.onion_host(e.get("url", ""))
        if h:
            hosts.add(h)
            hosts.update(KNOWN_SIBLING_HOSTS.get(h, []))
        hosts.update(x.lower() for x in e.get("exclude_hosts", []) or [])
    return hosts


def _is_other_engine_search(link: str) -> bool:
    parts = urlsplit(link)
    return "search" in parts.path.lower() and any(k in parse_qs(parts.query) for k in ("q", "query", "s", "search"))


def _clean_engine_results(name: str, results: list[dict], excluded: set[str]) -> tuple[list[dict], dict]:
    stats = {"raw": len(results), "nav_dropped": 0, "engine_host_dropped": 0, "spam_dropped": 0}
    kept = []
    for r in results:
        if sf.onion_host(r["link"]) in excluded or _is_other_engine_search(r["link"]):
            stats["engine_host_dropped"] += 1
        elif sf.is_nav_title(r.get("title", "")):
            stats["nav_dropped"] += 1
        elif sf.is_spam_title(r.get("title", "")):
            stats["spam_dropped"] += 1
        else:
            kept.append(r)
    stats["kept"] = len(kept)
    return kept, stats


def get_search_results(refined_query, max_workers=5):
    """
    Orquestra a pesquisa concorrente em todos os motores de pesquisa activos.

    Inclui deduplicação por URL e exclusão de meta-resultados (resultados
    cujo domínio .onion pertence a um dos próprios motores de pesquisa).

    Argumentos:
        refined_query (str): query de pesquisa já refinada pelo LLM.
        max_workers (int): número máximo de threads concorrentes. Padrão: 5.

    Retorna:
        tuple[list[dict], dict[str, str]]:
          - lista deduplicada e filtrada de resultados;
          - engine_status: {nome_do_motor: "ok" | "failed"} para cada motor
            efetivamente tentado (motores de fórum não configurados, que
            nunca chegam a ser tentados, ficam de fora). Alimenta a métrica
            "Tolerância a motores caídos" do EQ-06 (Capítulo 6, secção 6.4.6).
    """
    from engine_manager import get_active_engines
    active_engines = get_active_engines()

    # Separar motores por tipo:
    #   - "simple" (ou type ausente) → contrato GET com {query}, fluxo actual
    #   - "forum"                    → adapter autenticado (forum_adapters/)
    # Os fóruns têm um custo por pedido muito superior (login + CF challenge)
    # e gerem a sua própria sessão, pelo que ficam fora do ThreadPool Tor.
    simple_engines = [e for e in active_engines if e.get("type", "simple") == "simple"]
    forum_engines = [e for e in active_engines if e.get("type") == "forum"]

    active_urls = [e["url"] for e in simple_engines]

    # Hosts a excluir: todos os motores configurados (ativos ou não) e os seus
    # domínios irmãos — as suas páginas são navegação, não resultados.
    try:
        from engine_manager import load_engines
        all_engines = load_engines()
    except Exception:  # noqa: BLE001
        all_engines = active_engines
    excluded = _excluded_hosts(all_engines)

    per_engine: list[tuple[str, list[dict]]] = []
    engine_status: dict[str, str] = {}
    stats_all: dict[str, dict] = {}

    shared_session = get_tor_session() if active_urls else None

    if active_urls:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_engine = {
                executor.submit(fetch_search_results, e["url"], refined_query, shared_session): e
                for e in simple_engines
            }
            for future in as_completed(future_to_engine):
                e = future_to_engine[future]
                name = e["name"]
                result_urls, ok = future.result()
                # "ok"/"failed" mede a disponibilidade do motor (EQ-06); a
                # qualidade da resposta fica no detalhe (stats).
                engine_status[name] = "ok" if ok else "failed"
                kept, stats = _clean_engine_results(name, result_urls, excluded)
                detail = _fetch_detail.get(e["url"], ("ok_results" if ok else "exception", 0))[0]
                if ok and result_urls and not kept:
                    detail = "nav_only"
                stats["status"] = detail
                stats_all[name] = stats
                per_engine.append((name, kept))

    # Despacho para forum adapters (sequencial — cada adapter gere o seu rate
    # limit interno e o número de fóruns activos é tipicamente pequeno).
    if forum_engines:
        try:
            from forum_adapters import get_adapter
        except Exception:  # noqa: BLE001 — import falha não deve quebrar pipeline simples
            get_adapter = None  # type: ignore[assignment]
        if get_adapter is not None:
            for engine in forum_engines:
                adapter = get_adapter(engine.get("adapter", ""))
                if adapter is None or not adapter.is_configured():
                    continue
                try:
                    forum_results = adapter.search(refined_query)
                    engine_status[engine["name"]] = "ok"
                    stats_all[engine["name"]] = {"status": "ok_results" if forum_results else "ok_empty",
                                                 "raw": len(forum_results), "kept": len(forum_results)}
                    per_engine.append((engine["name"], list(forum_results)))
                except Exception:
                    # Falhas de um fórum não devem partir o resto da pesquisa,
                    # mas o motor conta como falhado para efeitos de EQ-06.
                    engine_status[engine["name"]] = "failed"
                    stats_all[engine["name"]] = {"status": "exception", "raw": 0, "kept": 0}
                    continue

    # Junta os motores em rodízio (ordem estável; cada motor contribui antes
    # de qualquer um repetir), deduplica por URL normalizado acumulando os
    # motores em "found_by", e limita cada host a PER_HOST_CAP resultados.
    unique_results = sf.interleave(per_engine, per_host_cap=PER_HOST_CAP)

    global last_search_stats
    last_search_stats = stats_all
    dropped = sum(st.get("nav_dropped", 0) + st.get("engine_host_dropped", 0) + st.get("spam_dropped", 0)
                  for st in stats_all.values())
    logger.info("Pesquisa: %d resultados únicos; %d descartados (navegação/motores/spam).", len(unique_results), dropped)
    return unique_results, engine_status
