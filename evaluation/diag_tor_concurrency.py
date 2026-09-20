"""
Diagnóstico: isola se o problema de "todos os motores dão connect timeout"
está na sessão requests/PySocks partilhada entre threads (como search.py faz)
ou é específico de outra coisa. curl em paralelo já provou que o Tor aguenta
8 conexões simultâneas em <1s cada — este script reproduz o MESMO padrão que
search.py usa (uma única requests.Session com proxy socks5h, reutilizada por
várias threads) para ver se falha da mesma forma.
"""
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

URL = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/"


def fetch_with_shared_session(session, i):
    t0 = time.time()
    try:
        r = session.get(URL, timeout=(15, 40))
        return f"[shared #{i}] OK status={r.status_code} tempo={time.time()-t0:.2f}s"
    except Exception as e:
        return f"[shared #{i}] FALHOU tempo={time.time()-t0:.2f}s erro={type(e).__name__}: {e}"


def fetch_with_own_session(i):
    t0 = time.time()
    try:
        s = requests.Session()
        s.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        r = s.get(URL, timeout=(15, 40))
        return f"[own #{i}] OK status={r.status_code} tempo={time.time()-t0:.2f}s"
    except Exception as e:
        return f"[own #{i}] FALHOU tempo={time.time()-t0:.2f}s erro={type(e).__name__}: {e}"


print("=== Teste 1: 1 pedido sequencial com sessão dedicada (baseline) ===")
print(fetch_with_own_session(0))

print("\n=== Teste 2: 8 threads, SESSÃO PARTILHADA (padrão atual do search.py) ===")
session = requests.Session()
session.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
t0 = time.time()
with ThreadPoolExecutor(max_workers=8) as ex:
    futures = [ex.submit(fetch_with_shared_session, session, i) for i in range(8)]
    for f in as_completed(futures):
        print(f.result())
print(f"Tempo total: {time.time()-t0:.2f}s")

print("\n=== Teste 3: 8 threads, SESSÃO PRÓPRIA por thread ===")
t0 = time.time()
with ThreadPoolExecutor(max_workers=8) as ex:
    futures = [ex.submit(fetch_with_own_session, i) for i in range(8)]
    for f in as_completed(futures):
        print(f.result())
print(f"Tempo total: {time.time()-t0:.2f}s")
