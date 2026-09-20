"""
Diagnóstico v3: chama diretamente search.fetch_search_results() — a função
REAL do pipeline, com parsing HTML incluído — para um pequeno conjunto de
motores individualmente (sequencial, sem ThreadPoolExecutor), para ver se o
problema é (a) rede/timeout, (b) parsing (motor responde mas 0 links
extraídos), ou (c) apenas os motores testados no run anterior estarem
mesmo offline hoje.
"""
import sys
import time
sys.path.insert(0, ".")

from search import fetch_search_results, get_tor_session, SEARCH_ENGINES

query = "lockbit leak site"

# Amostra: os motores "base" (ativos por omissão), que devem ser os mais fiáveis
sample = [e for e in SEARCH_ENGINES if e.get("type", "simple") == "simple" and e.get("default_enabled", True) is not False][:8]

session = get_tor_session()
for e in sample:
    t0 = time.time()
    try:
        results = fetch_search_results(e["url"], query, session=session)
        dt = time.time() - t0
        print(f"{e['name']:<15} {dt:5.2f}s  -> {len(results)} resultados" + (f"  ex: {results[0]}" if results else ""))
    except Exception as ex:
        dt = time.time() - t0
        print(f"{e['name']:<15} {dt:5.2f}s  -> ERRO {type(ex).__name__}: {ex}")
