"""
Testes de caracterização: registam o comportamento ATUAL (pipeline 1.0-legacy)
das partes que os PRs seguintes vão corrigir. Quando uma correção muda um
destes comportamentos, o teste correspondente é atualizado no mesmo PR — fica
assim explícito, no histórico, o que mudou e porquê.
"""

import llm
import scrape


def test_scraper_prepends_search_title_to_page_text(fake_session, fake_response):
    FakeResponse = fake_response
    # Legado: o título do resultado de pesquisa é anteposto ao texto da página,
    # pelo que basta o título conter as palavras da query para "passar" a Etapa 5.
    url = "http://aaaa.onion/p"
    s = fake_session({url: FakeResponse("<html><body>conteudo da pagina</body></html>")})
    got_url, text = scrape.scrape_single({"link": url, "title": "LockBit leak"}, session=s)
    assert got_url == url
    assert text.startswith("LockBit leak - ")
    assert "conteudo da pagina" in text


def test_scraper_returns_title_as_content_on_http_error(fake_session, fake_response):
    FakeResponse = fake_response
    url = "http://bbbb.onion/p"
    s = fake_session({url: FakeResponse("erro", status_code=503)})
    _, text = scrape.scrape_single({"link": url, "title": "Titulo do resultado"}, session=s)
    assert text == "Titulo do resultado"


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
