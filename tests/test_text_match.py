"""PR 3 — correspondência query ↔ texto (Etapas 4 e 5)."""

import pytest

import text_match as tm


def kinds(q):
    return {(t.text, t.kind, t.key) for t in tm.query_terms(q)}


def test_terms_lockbit():
    assert kinds("lockbit leak site") == {("lockbit", "word", True), ("leak", "word", False)}


def test_terms_entities_and_phrases():
    k = kinds('"Cobalt Strike" beacon john.doe@example-corp.test NIF 999 999 999 example-corp.test')
    assert ("cobalt strike", "phrase", True) in k and ("beacon", "word", True) in k
    assert ("john.doe@example-corp.test", "email", True) in k
    assert ("999999999", "id", True) in k and ("example-corp.test", "domain", True) in k
    assert ("nif", "word", False) in k


def test_short_codes_kept_and_pt_stopwords_dropped():
    k = {t.text for t in tm.query_terms("C2 servidor para dados")}
    assert "c2" in k and "para" not in k and "dados" not in k


@pytest.mark.parametrize("text", ["Contact: john.doe [at] example-corp [dot] test",
                                  "JOHN.DOE@EXAMPLE-CORP.TEST leaked", "mail john.doe(at)example-corp.test"])
def test_email_variants(text):
    m = tm.match(text, tm.query_terms("john.doe@example-corp.test breach"))
    assert "john.doe@example-corp.test" in m.found


@pytest.mark.parametrize("text", ["NIF: 999 999 999", "nif 999.999.999", "999-999-999 found", "id=999999999"])
def test_id_variants(text):
    assert "999999999" in tm.match(text, tm.query_terms("NIF 999999999 dark web")).found


def test_accents_and_punctuation():
    m = tm.match("A organização “LockBit,” publicou", tm.query_terms("organizacao lockbit"))
    assert m.key_found == 2


def test_required_hits():
    assert tm.required_hits(tm.query_terms("lockbit leak site")) == (1, True)
    assert tm.required_hits(tm.query_terms("cobalt strike beacon")) == (2, True)
    assert tm.required_hits(tm.query_terms("credential dump forum 2026")) == (2, False)


def test_relevance_needs_key_terms_not_context():
    terms = tm.query_terms("lockbit leak site")
    assert not tm.is_relevant(tm.match("leak leak leak forum market", terms), terms)
    assert tm.is_relevant(tm.match("LockBit 3.0 affiliates panel", terms), terms)


def test_best_window_finds_the_match_beyond_the_start():
    text = "menu " * 600 + "Here LockBit published the victim list. " + "footer " * 200
    w = tm.best_window(text, tm.query_terms("lockbit"), 300)
    assert "LockBit published" in w and len(w) <= 300
