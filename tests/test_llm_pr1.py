"""PR 1 — robustez das etapas LLM: raciocínio removido da resposta e evidência dentro do contexto."""

import llm


def test_strip_reasoning():
    assert llm._strip_reasoning("<think>pensar 1, 2, 3</think>\n3,7,1") == "3,7,1"
    assert llm._strip_reasoning("LockBit leak <think>corte a meio") == "LockBit leak"
    assert llm._strip_reasoning("  sem raciocínio  ") == "sem raciocínio"


def test_filter_results_ignores_numbers_inside_reasoning(fake_llm):
    res = [{"title": f"lockbit {i}", "link": f"http://a{i}.onion"} for i in range(1, 11)]
    out = llm.filter_results(fake_llm("<think>os resultados 9 e 10 parecem spam</think>2,3"), "lockbit", res)
    assert [r["link"] for r in out] == ["http://a2.onion", "http://a3.onion"]


class _Small:
    n_ctx = 4096
    max_tokens = 2048


def test_context_budget_shrinks_for_small_context():
    big = llm._context_budget_chars(object(), 3000)        # sem atributos -> 8192/2048
    small = llm._context_budget_chars(_Small(), 3000)
    assert small < big and small >= 1500


def test_summary_never_exceeds_budget(fake_llm, monkeypatch):
    seen = {}
    m = fake_llm("## 1. Query: x\n\nresposta")
    monkeypatch.setattr(llm, "_context_budget_chars", lambda *_a, **_k: 4000)
    orig = llm._format_content_for_llm

    def spy(content):
        seen["chars"] = sum(len(v) for v in content.values())
        return orig(content)
    monkeypatch.setattr(llm, "_format_content_for_llm", spy)
    content = {f"http://s{i}.onion": "x" * 3000 for i in range(10)}
    out = llm.generate_summary(m, "q", content)
    assert seen["chars"] <= 4000 and "resposta" in out
