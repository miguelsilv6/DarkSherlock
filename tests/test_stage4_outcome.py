import llm
from langchain_core.language_models.fake_chat_models import FakeListChatModel

RES = [{"title": f"lockbit page {i}", "link": f"http://a{i}.onion"} for i in range(1, 31)]
RES2 = [{"title": f"other {i}", "link": f"http://b{i}.onion"} for i in range(1, 31)]


def _run(fake_llm, resp, results=RES, q="lockbit leak"):
    out = llm.filter_results(fake_llm(resp), q, results)
    return llm.last_filter_outcome, len(out)


def test_ranked(fake_llm):
    assert _run(fake_llm, "3,7,1,15") == ("ranked", 4)


def test_none_with_keyword_fallback(fake_llm):
    assert _run(fake_llm, "NONE") == ("none_keyword", 20)


def test_none_without_matches(fake_llm):
    assert _run(fake_llm, "NONE", RES2) == ("none", 0)


def test_parse_fallback(fake_llm):
    assert _run(fake_llm, "I cannot help with that") == ("parse_fallback", 20)


def test_empty_input(fake_llm):
    assert llm.filter_results(fake_llm("x"), "q", []) == [] and llm.last_filter_outcome == "empty_input"


def test_error_fallback():
    class Boom(FakeListChatModel):
        def _call(self, *a, **k):
            raise RuntimeError("x")
    out = llm.filter_results(Boom(responses=["x"]), "q", RES)
    assert llm.last_filter_outcome == "error_fallback" and len(out) == 20
