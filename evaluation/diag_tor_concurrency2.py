"""
Diagnóstico v2: reproduz FIELMENTE o que search.py faz — User-Agent de
browser aleatório por pedido (search.py sempre usa isto, então o diagnóstico
anterior sem UA estava a testar um cenário diferente: bloqueio ativo por
fingerprinting, não o bug real). Este script testa em escala real (35
conexões, como get_search_results faz) para reproduzir o padrão de "ondas de
timeout a cada 15s" observado nos logs do pipeline real.
"""
import random
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

URL = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=lockbit+leak+site"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
]


def get_tor_session():
    """Réplica exata de search.py:get_tor_session()."""
    session = requests.Session()
    retry = Retry(total=1, read=1, connect=1, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
    return session


def fetch(session, i):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    t0 = time.time()
    try:
        r = session.get(URL, headers=headers, timeout=(15, 40))
        return f"#{i:02d} OK status={r.status_code} tempo={time.time()-t0:.2f}s"
    except Exception as e:
        return f"#{i:02d} FALHOU tempo={time.time()-t0:.2f}s erro={type(e).__name__}: {e}"


for n_workers in [1, 5, 8, 16, 35]:
    print(f"\n=== {n_workers} pedidos, mesma sessão partilhada, max_workers={n_workers} ===")
    session = get_tor_session()
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=n_workers) as ex:
        futures = [ex.submit(fetch, session, i) for i in range(n_workers)]
        results = [f.result() for f in as_completed(futures)]
    ok = sum(1 for r in results if " OK " in r)
    print(f"  {ok}/{n_workers} OK — tempo total: {time.time()-t0:.2f}s")
    for r in sorted(results):
        print("  " + r)
