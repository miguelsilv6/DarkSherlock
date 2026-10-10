"""PR 4 — relatório fundamentado: verificação de IOCs, spam fora da evidência, aviso de fonte única."""

import llm

ONION_A = "a" * 56 + ".onion"
ONION_B = "b" * 56 + ".onion"


def _text(*extra):
    base = ("O grupo publicou a lista de vitimas no seu blog com datas e montantes exigidos. "
            "A pagina descreve o processo de negociacao e os contactos do grupo. ")
    return base + " ".join(extra)


def test_verify_iocs_separates_verified_from_hallucinated():
    evidence = {"http://s1.onion": _text("Contacto: ops@example.org; servidor 10.0.0.5; mirror", ONION_A)}
    summary = ("IOCs: 10.0.0.5 [FONTE 1], ops@example.org [FONTE 1], " + ONION_A +
               " e ainda 203.0.113.9 e " + ONION_B)
    chk = llm.verify_iocs(summary, evidence)
    assert chk["total"] == 5
    assert chk["verified"] == 3
    assert set(chk["unverified"]) == {"203.0.113.9", ONION_B}


def test_verify_iocs_ignores_iocs_from_the_query():
    evidence = {"http://s1.onion": _text()}
    chk = llm.verify_iocs("O email alvo ops@example.org não aparece nas fontes.", evidence,
                          query="ops@example.org")
    assert chk == {"total": 0, "verified": 0, "unverified": []}


def test_verify_iocs_case_insensitive_for_hashes():
    h = "d41d8cd98f00b204e9800998ecf8427e"
    chk = llm.verify_iocs(f"hash {h.upper()}", {"u": _text(f"md5 {h}")})
    assert chk["verified"] == 1 and not chk["unverified"]


def test_is_degenerate():
    assert llm._is_degenerate("leak " * 100)
    assert llm._is_degenerate(" ".join(["darkweb", "market", "leak"] * 40))
    assert not llm._is_degenerate(_text() * 3)
    assert not llm._is_degenerate("leak leak leak")  # demasiado curto para julgar


def test_stage5_drops_degenerate_text_even_with_query_terms():
    scraped = {
        "http://spam.onion": "lockbit leak " * 200,
        "http://good.onion": _text("O LockBit reivindicou o ataque."),
    }
    kept = llm.filter_scraped_by_relevance("lockbit", scraped)
    assert list(kept) == ["http://good.onion"]
    assert llm.last_relevance_scores["http://spam.onion"].get("degenerate") is True


def test_summary_appends_ioc_check(fake_llm):
    content = {
        "http://s1.onion": _text("servidor 10.0.0.5"),
        "http://s2.onion": _text("outra fonte sem IOCs"),
    }
    out = llm.generate_summary(fake_llm("## 1. Query: x\n\nIOCs: 10.0.0.5 [FONTE 1] e 198.51.100.7"),
                               "grupo", content)
    assert "Verificação automática de IOCs" in out
    assert "`198.51.100.7`" in out
    assert llm.last_ioc_check == {"total": 2, "verified": 1, "unverified": ["198.51.100.7"]}
    assert "Evidência limitada" not in out


def test_summary_warns_on_single_source(fake_llm):
    out = llm.generate_summary(fake_llm("## 1. Query: x\n\nresposta"), "grupo", {"http://s1.onion": _text()})
    assert "Evidência limitada" in out and "única fonte" in out
    assert "Verificação automática de IOCs" not in out  # sem IOCs no relatório, sem nota


def test_prompt_numbering_follows_dict_order():
    content = {"http://z.onion": "texto z", "http://a.onion": "texto a"}
    block = llm._format_content_for_llm(content)
    assert block.index("[FONTE 1]\nURL: http://z.onion") < block.index("[FONTE 2]\nURL: http://a.onion")
