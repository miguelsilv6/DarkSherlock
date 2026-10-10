"""PR 2 — extração e limpeza dos resultados de pesquisa (sem rede)."""

import pytest

import search
import search_filters as sf
from tests.conftest import FakeResponse, FakeSession, load_fixture


def on(n):
    return (n + "a" * 56)[:56] + ".onion"


ENG, SIB = on("engineone"), on("enginedir")
R1, R2, R3 = on("resultone"), on("resulttwo"), on("resultthree")


# ---------------------------------------------------------------- funções puras
def test_extract_links_skips_header_footer_and_decodes_redirects():
    links = sf.extract_links(load_fixture("engines/normal.html"), f"http://{ENG}/search?q=lockbit")
    hosts = [sf.onion_host(l["link"]) for l in links]
    assert R1 in hosts and R2 in hosts and R3 in hosts          # R3 vem de /out?url=...
    assert f"http://{R3}/post/42" in [l["link"] for l in links]
    titles = [l["title"] for l in links]
    assert "Engine Home" not in titles and "Contact" not in titles  # header/footer


def test_results_page_detection():
    assert sf.looks_like_results_page(load_fixture("engines/normal.html"), "lockbit leak")
    assert not sf.looks_like_results_page(load_fixture("engines/homepage.html"), "lockbit leak")


@pytest.mark.parametrize("title", ["✅darkmarketplace|darkmarketplace|darkmarketplace|darkmarketplace|darkma",
                                   "⭐⭐⭐forumforumforumforumforumforumforum⭐⭐⭐", "leak leak leak leak leak",
                                   "a | b | c | d | e"])
def test_spam_titles(title):
    assert sf.is_spam_title(title)


@pytest.mark.parametrize("title", ["LockBit 3.0 leak announcements", "OnionLand Web Hosting",
                                   "Forum thread about LockBit affiliates", "Bitcoin mixer service review"])
def test_not_spam_titles(title):
    assert not sf.is_spam_title(title)


def test_nav_titles():
    assert sf.is_nav_title("Marketplaces") and sf.is_nav_title("  Other ") and sf.is_nav_title("Contact")
    assert not sf.is_nav_title("Hacking forum for LockBit affiliates")


def test_normalize_url():
    assert sf.normalize_url("HTTP://ABC.onion:80/x/?utm_source=a#frag") == "http://abc.onion/x"
    assert sf.normalize_url("http://abc.onion/x?b=1&utm_medium=2") == "http://abc.onion/x?b=1"


def test_interleave_round_robin_found_by_and_host_cap():
    a = [{"title": "a1", "link": f"http://{R1}/1"}, {"title": "a2", "link": f"http://{R1}/2"},
         {"title": "a3", "link": f"http://{R1}/3"}, {"title": "a4", "link": f"http://{R1}/4"}]
    b = [{"title": "b1", "link": f"http://{R2}/1"}, {"title": "dup", "link": f"http://{R1}/1/"}]
    out = sf.interleave([("Zeta", a), ("Alpha", b)], per_host_cap=3)
    assert [o["title"] for o in out] == ["b1", "a1", "a2", "a3"]     # Alpha primeiro; a4 cortado pelo limite por host
    assert out[1]["found_by"] == ["Zeta", "Alpha"]                     # duplicado acumula o motor


# ---------------------------------------------------------------- integração
@pytest.fixture
def engines(monkeypatch):
    cfg = [
        {"name": "Normal", "url": f"http://{ENG}/search?q={{query}}", "enabled": True},
        {"name": "AmnesiaLike", "url": f"http://{on('amnesialike')}/search?query={{query}}", "enabled": True,
         "exclude_hosts": [SIB]},
        {"name": "Spammy", "url": f"http://{on('spamengine')}/?q={{query}}", "enabled": True},
        {"name": "Home", "url": f"http://{on('homeengine')}/?q={{query}}", "enabled": True},
        {"name": "Down", "url": f"http://{on('downengine')}/?q={{query}}", "enabled": True},
        {"name": "Disabled", "url": f"http://{on('disabledengine')}/?q={{query}}", "enabled": False},
    ]
    import engine_manager
    monkeypatch.setattr(engine_manager, "get_active_engines", lambda: [e for e in cfg if e["enabled"]])
    monkeypatch.setattr(engine_manager, "load_engines", lambda: cfg)
    q = "lockbit+leak"
    sess = FakeSession({
        f"http://{ENG}/search?q={q}": FakeResponse(load_fixture("engines/normal.html")),
        f"http://{on('amnesialike')}/search?query={q}": FakeResponse(load_fixture("engines/amnesia_like.html")),
        f"http://{on('spamengine')}/?q={q}": FakeResponse(load_fixture("engines/spam.html")),
        f"http://{on('homeengine')}/?q={q}": FakeResponse(load_fixture("engines/homepage.html")),
        f"http://{on('downengine')}/?q={q}": FakeResponse("err", status_code=503),
    })
    monkeypatch.setattr(search, "get_tor_session", lambda: sess)
    return cfg


def test_get_search_results_end_to_end(engines):
    results, status = search.get_search_results("lockbit leak", max_workers=3)
    links = [r["link"] for r in results]
    hosts = {sf.onion_host(l) for l in links}
    # navegação, categorias do domínio irmão, anúncios e páginas do motor ficam de fora
    assert SIB not in hosts and ENG not in hosts and on("amnesialike") not in hosts
    # spam fora; resultado legítimo da página de spam fica
    assert f"http://{R1}/real" in links and not any("spamsite" in l for l in links)
    # página inicial (não ecoa a query) não contribui; R2 só aparece via motor Normal
    assert [r["found_by"] for r in results if sf.onion_host(r["link"]) == R2] == [["Normal"]]
    assert status == {"Normal": "ok", "AmnesiaLike": "ok", "Spammy": "ok", "Home": "ok", "Down": "failed"}
    st = search.last_search_stats
    assert st["AmnesiaLike"]["status"] == "nav_only" and st["AmnesiaLike"]["kept"] == 0
    assert st["Home"]["status"] == "not_results_page"
    assert st["Spammy"]["spam_dropped"] == 3
    assert st["Down"]["status"] == "http_error"


def test_disabled_engine_host_is_excluded_too(engines):
    # um resultado que aponte para um motor desativado continua a ser página de motor, não resultado
    assert on("disabledengine") in search._excluded_hosts(engines)
    assert SIB in search._excluded_hosts(engines)
