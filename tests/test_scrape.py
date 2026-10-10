"""Raspador (PR 1): só páginas válidas contam como evidência; tudo via Tor; redirecionamentos verificados."""

import json

import pytest

import safety
import scrape

LONG = "<html><body><p>" + ("Conteúdo real da página sobre o grupo e as suas fugas. " * 20) + "</p></body></html>"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("DARKSHERLOCK_SAFETY_GUARD", "on")
    monkeypatch.setattr(safety, "EXTRA_PATTERNS_FILE", tmp_path / "none.txt")
    monkeypatch.setattr(safety, "REFERRALS_FILE", tmp_path / "referrals" / "csam_referrals.jsonl")


def page(fake_session, routes, title="Titulo do resultado", url="http://aaaa.onion/p"):
    s = fake_session(routes)
    return scrape.fetch_page({"link": url, "title": title, "found_by": ["E1"]}, session=s), s


def test_ok_page_has_no_search_title(fake_session, fake_response):
    rec, _ = page(fake_session, {"http://aaaa.onion/p": fake_response(LONG)}, title="LockBit leak")
    assert rec["status"] == "ok" and "LockBit leak" not in rec["text"] and rec["text"].startswith("Conteúdo real")


def test_http_error_is_not_evidence(fake_session, fake_response):
    rec, _ = page(fake_session, {"http://aaaa.onion/p": fake_response(LONG, status_code=503)})
    assert rec["status"] == "http_error" and rec["http_code"] == 503
    assert scrape.scrape_single({"link": "http://aaaa.onion/p", "title": "T"},
                                session=fake_session({"http://aaaa.onion/p": fake_response(LONG, status_code=503)}))[1] == ""


def test_short_captcha_page_is_rejected_but_long_page_mentioning_captcha_is_kept(fake_session, fake_response):
    cap = "<html><body>" + "Please solve the CAPTCHA to continue. " * 5 + "</body></html>"
    rec, _ = page(fake_session, {"http://aaaa.onion/p": fake_response(cap)})
    assert rec["status"] == "challenge_or_error"
    long_cap = LONG.replace("</p>", " The forum uses a captcha at login.</p>") * 3
    rec, _ = page(fake_session, {"http://aaaa.onion/p": fake_response(long_cap)})
    assert rec["status"] == "ok"


def test_error_page_longer_than_150_chars_is_rejected(fake_session, fake_response):
    err = "<html><body><h1>502 Bad Gateway</h1>" + "The upstream onion service did not answer in time. " * 4 + "</body></html>"
    rec, _ = page(fake_session, {"http://aaaa.onion/p": fake_response(err)})
    assert rec["status"] == "challenge_or_error"


def test_non_html_is_rejected(fake_session, fake_response):
    rec, _ = page(fake_session, {"http://aaaa.onion/p": fake_response("%PDF-1.4 ...", headers={"Content-Type": "application/pdf"})})
    assert rec["status"] == "non_html"


def test_non_utf8_page_is_decoded(fake_session, fake_response):
    body = ("<html><body>" + "Informação sobre a fuga de dados da organização. " * 10 + "</body></html>").encode("latin-1")
    r = fake_response("", headers={"Content-Type": "text/html"}, encoding="latin-1", content=body)
    rec, _ = page(fake_session, {"http://aaaa.onion/p": r})
    assert rec["status"] == "ok" and "Informação" in rec["text"] and "organização" in rec["text"]


def test_redirect_followed_and_blocked_redirect_never_requested(fake_session, fake_response):
    routes = {"http://aaaa.onion/p": fake_response("", status_code=302, headers={"Location": "/q"}),
              "http://aaaa.onion/q": fake_response(LONG)}
    rec, s = page(fake_session, routes)
    assert rec["status"] == "ok" and rec["final_url"] == "http://aaaa.onion/q"
    blocked = "http://bbbb.onion/child-porn"
    routes = {"http://aaaa.onion/p": fake_response("", status_code=302, headers={"Location": blocked}),
              blocked: fake_response(LONG)}
    rec, s = page(fake_session, routes)
    assert rec["status"] == "blocked_redirect" and blocked not in s.requested
    lines = safety.REFERRALS_FILE.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[-1])
    assert entry["url"] == blocked and entry["source"] == "redirect" and entry["engines"] == ["E1"]
    assert set(entry) == {"ts_utc", "url", "engines", "pattern", "source"}   # nunca título nem conteúdo


def test_too_many_redirects(fake_session, fake_response):
    routes = {f"http://aaaa.onion/{i}": fake_response("", status_code=302, headers={"Location": f"/{i + 1}"})
              for i in range(10)}
    rec, _ = page(fake_session, routes, url="http://aaaa.onion/0")
    assert rec["status"] == "too_many_redirects"


def test_clearnet_goes_through_the_given_tor_session(fake_session, fake_response):
    rec, s = page(fake_session, {"https://example.org/x": fake_response(LONG)}, url="https://example.org/x")
    assert rec["status"] == "ok" and s.requested == ["https://example.org/x"]


def test_body_size_limit(fake_session, fake_response, monkeypatch):
    monkeypatch.setattr(scrape, "MAX_BYTES", 1000)
    rec, _ = page(fake_session, {"http://aaaa.onion/p": fake_response(LONG * 5)})
    assert rec["truncated"] and rec["bytes"] == 1000


def test_scrape_multiple_keeps_only_valid_pages_and_logs_referrals(fake_session, fake_response, monkeypatch):
    s = fake_session({"http://ok.onion": fake_response(LONG), "http://err.onion": fake_response("x", status_code=404)})
    monkeypatch.setattr(scrape, "get_tor_session", lambda: s)
    items = [{"link": "http://ok.onion", "title": "a"}, {"link": "http://err.onion", "title": "b"},
             {"link": "http://dead.onion", "title": "c"},
             {"link": "http://x.onion", "title": "Real Child Porn", "found_by": ["E9"]}]
    res = scrape.scrape_multiple(items, max_workers=2)
    assert set(res) == {"http://ok.onion"}
    st = {u: d["status"] for u, d in scrape.last_details.items()}
    assert st == {"http://ok.onion": "ok", "http://err.onion": "http_error",
                  "http://dead.onion": "connection_error", "http://x.onion": "blocked_safety"}
    assert "http://x.onion" not in s.requested and scrape.last_blocked_count == 1
    entry = json.loads(safety.REFERRALS_FILE.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["url"] == "http://x.onion" and entry["engines"] == ["E9"] and entry["source"] == "scrape"
