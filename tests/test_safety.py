import pytest

import safety
import scrape

OK = [{"title": "LockBit ransomware leak site", "link": "http://a.onion"},
      {"title": "Marketplaces", "link": "http://b.onion/?cat=1"},
      {"title": "Help the kids learn python", "link": "http://c.onion"},
      {"title": "Bitcoin mixer service", "link": "http://d.onion"},
      {"title": "Child safety online guide", "link": "http://e.onion"},
      {"title": "Stopwatch pedometer app", "link": "http://f.onion"}]
BAD = [{"title": "Real Child Porn videos", "link": "http://x.onion"},
       {"title": "stopCP Help STOP CHILD PORN", "link": "http://y.onion"},
       {"title": "CSAM archive", "link": "http://z.onion"},
       {"title": "nothing", "link": "http://q.onion/pedophile-forum"},
       {"title": "Preteen models", "link": "http://w.onion"}]


@pytest.fixture(autouse=True)
def _guard_on(monkeypatch, tmp_path):
    monkeypatch.setenv("DARKSHERLOCK_SAFETY_GUARD", "on")
    monkeypatch.setattr(safety, "EXTRA_PATTERNS_FILE", tmp_path / "none.txt")
    monkeypatch.setattr(safety, "REFERRALS_FILE", tmp_path / "referrals" / "csam_referrals.jsonl")


def test_split_blocked():
    allowed, blocked = safety.split_blocked(OK + BAD)
    assert allowed == OK
    assert [b[0] for b in blocked] == BAD


def test_guard_off(monkeypatch):
    monkeypatch.setenv("DARKSHERLOCK_SAFETY_GUARD", "off")
    allowed, blocked = safety.split_blocked(OK + BAD)
    assert len(allowed) == len(OK) + len(BAD) and not blocked


def test_extra_patterns_file(monkeypatch, tmp_path):
    f = tmp_path / "extra.txt"
    f.write_text("# comentario\nonly\\s*kids\n\n(invalido\n", encoding="utf-8")
    monkeypatch.setattr(safety, "EXTRA_PATTERNS_FILE", f)
    assert safety.blocked_pattern({"title": "Only Kids", "link": "http://k.onion"})
    assert not safety.blocked_pattern({"title": "Only fans of crypto", "link": "http://k.onion"})


def test_scrape_multiple_never_requests_blocked(monkeypatch):
    called = []

    def fake(url_data, session=None, *a, **k):
        called.append(url_data["link"])
        return {"url": url_data["link"], "status": "ok", "text": "texto " * 40}
    monkeypatch.setattr(scrape, "fetch_page", fake)
    monkeypatch.setattr(scrape, "get_tor_session", lambda: None)
    res = scrape.scrape_multiple(OK[:2] + BAD, max_workers=2)
    assert sorted(called) == sorted(i["link"] for i in OK[:2])
    assert set(res) == set(called) and scrape.last_blocked_count == len(BAD)


def test_referral_log_has_no_title_or_content(tmp_path):
    safety.log_referral("http://x.onion/a", ["E1"], "child[\\s_-]*porn")
    import json
    entry = json.loads(safety.REFERRALS_FILE.read_text(encoding="utf-8").splitlines()[-1])
    assert set(entry) == {"ts_utc", "url", "engines", "pattern", "source"}
    assert oct(safety.REFERRALS_FILE.stat().st_mode & 0o777) == "0o600"
