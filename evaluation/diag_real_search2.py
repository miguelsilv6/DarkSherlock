"""
Diagnóstico v4: réplica de fetch_search_results() SEM o `except: return []`
que engole o erro real — para ver exatamente o que acontece por motor:
status HTTP, tamanho do body, nº de âncoras <a>, nº de links .onion extraídos,
ou a exceção exata em caso de falha de rede.
"""
import random
import re
import sys
import time
sys.path.insert(0, ".")

from urllib.parse import quote_plus
from bs4 import BeautifulSoup
from search import get_tor_session, USER_AGENTS, SEARCH_ENGINES

query = "lockbit leak site"
sample = [e for e in SEARCH_ENGINES if e.get("type", "simple") == "simple" and e.get("default_enabled", True) is not False][:8]

session = get_tor_session()

for e in sample:
    url = e["url"].format(query=quote_plus(query))
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    t0 = time.time()
    try:
        response = session.get(url, headers=headers, timeout=(15, 40))
        dt = time.time() - t0
        body_len = len(response.text)
        soup = BeautifulSoup(response.text, "html.parser")
        anchors = soup.find_all('a')
        links = []
        for a in anchors:
            href = a.get('href', '')
            title = a.get_text(strip=True)
            link = re.findall(r'https?:\/\/[a-z0-9\.]+\.onion.*', href)
            if link and "search" not in link[0] and len(title) > 3:
                links.append((title, link[0]))
        print(f"{e['name']:<15} {dt:5.2f}s status={response.status_code} body={body_len}B anchors={len(anchors)} links_onion={len(links)}")
        if anchors and not links:
            print(f"    (amostra de 2 hrefs: {[a.get('href','')[:60] for a in anchors[:2]]})")
    except Exception as ex:
        dt = time.time() - t0
        print(f"{e['name']:<15} {dt:5.2f}s ERRO {type(ex).__name__}: {str(ex)[:150]}")
