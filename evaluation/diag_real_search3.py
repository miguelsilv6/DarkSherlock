"""
Diagnóstico v5: os MESMOS 8 motores do teste sequencial anterior
(diag_real_search2.py), mas desta vez em PARALELO via ThreadPoolExecutor
(como search.py realmente faz). Se a taxa de sucesso cair drasticamente
face ao teste sequencial, confirma que construir vários circuitos Tor para
hosts .onion DIFERENTES em simultâneo é o que está a falhar nesta VM —
não a disponibilidade dos motores em si.
"""
import random
import re
import sys
import time
sys.path.insert(0, ".")

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus
from bs4 import BeautifulSoup
from search import get_tor_session, USER_AGENTS, SEARCH_ENGINES

query = "lockbit leak site"
sample = [e for e in SEARCH_ENGINES if e.get("type", "simple") == "simple" and e.get("default_enabled", True) is not False][:8]


def fetch(session, e):
    url = e["url"].format(query=quote_plus(query))
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    t0 = time.time()
    try:
        response = session.get(url, headers=headers, timeout=(15, 40))
        dt = time.time() - t0
        soup = BeautifulSoup(response.text, "html.parser")
        links = []
        for a in soup.find_all('a'):
            href = a.get('href', '')
            title = a.get_text(strip=True)
            m = re.findall(r'https?:\/\/[a-z0-9\.]+\.onion.*', href)
            if m and "search" not in m[0] and len(title) > 3:
                links.append((title, m[0]))
        return f"{e['name']:<15} {dt:5.2f}s status={response.status_code} links_onion={len(links)}"
    except Exception as ex:
        dt = time.time() - t0
        return f"{e['name']:<15} {dt:5.2f}s ERRO {type(ex).__name__}: {str(ex)[:100]}"


session = get_tor_session()
t0 = time.time()
with ThreadPoolExecutor(max_workers=8) as ex:
    futures = [ex.submit(fetch, session, e) for e in sample]
    for f in as_completed(futures):
        print(f.result())
print(f"\nTempo total (paralelo, 8 workers): {time.time()-t0:.2f}s")
