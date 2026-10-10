"""
Testes de caracterização: registam o comportamento ATUAL (pipeline 1.0-legacy)
das partes que os PRs seguintes vão corrigir. Quando uma correção muda um
destes comportamentos, o teste correspondente é atualizado no mesmo PR — fica
assim explícito, no histórico, o que mudou e porquê.
"""

import llm


# (PR 1) Os dois testes de caracterização do raspador — título anteposto ao
# texto e título usado como conteúdo em caso de erro — foram substituídos por
# tests/test_scrape.py: o título já não entra no texto e uma página falhada não
# produz conteúdo.


def test_relevance_filter_keeps_all_when_nothing_matches():
    scraped = {"u1": "nada a ver", "u2": "outra coisa"}
    assert llm.filter_scraped_by_relevance("lockbit leak site", scraped) == scraped


def test_relevance_filter_strict_tier_drops_one_hit_sources():
    scraped = {"u1": "lockbit leak", "u2": "lockbit apenas", "u3": "nada"}
    assert set(llm.filter_scraped_by_relevance("lockbit leak site", scraped)) == {"u1"}


def test_keywords_whitespace_tokenisation_keeps_punctuation():
    # Legado: a pontuação fica colada ao termo, e "site" é descartado por genérico.
    assert llm._extract_query_keywords('"LockBit," leak site') == ['"lockbit,"', "leak"]


def test_filter_results_none_detected_by_substring(fake_llm):
    # Legado: qualquer resposta que contenha "none" é tratada como NONE.
    res = [{"title": f"other {i}", "link": f"http://x{i}.onion"} for i in range(5)]
    out = llm.filter_results(fake_llm("None of these look relevant, but 2 and 3 might."), "lockbit", res)
    assert out == [] and llm.last_filter_outcome == "none"
