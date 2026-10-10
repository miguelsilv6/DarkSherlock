"""PR 5 — teste de fumo das páginas Home e Investigation (Streamlit AppTest), com LLM, pesquisa e recolha falsos.

Corre a página como o Streamlit a corre, clica em "Run" e verifica o resultado: sem
exceções, relatório mostrado uma vez, aviso de Tor em baixo, JSON v2.0 gravado, e
nenhum novo pipeline num rerun (p. ex. depois de um download).
"""

import json
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from config import PIPELINE_VERSION  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ONION_A = "http://" + "a" * 56 + ".onion/x"
ONION_B = "http://" + "b" * 56 + ".onion/y"
BODY = ("O grupo LockBit publicou no seu leak site a lista de vitimas, com datas e montantes. "
        "Servidor 10.0.0.5 mencionado. ") * 4
SUMMARY = ("## 1. Query: lockbit leak site\n\n## 2. Análise por Fonte\n\nO LockBit [FONTE 1]; IOC 10.0.0.5 "
           "e 203.0.113.9.\n\n## 3. Artefactos / IOCs\n\n- 10.0.0.5\n\n## 4. Insights Chave\n\n- x\n\n"
           "## 5. Próximos Passos\n\n- y")


@pytest.fixture
def fakes(monkeypatch, tmp_path):
    from langchain_core.language_models.fake_chat_models import FakeListChatModel

    import engine_manager
    import health
    import llm
    import llm_utils
    import pipeline
    import scrape
    import search
    import ui_pipeline

    def fake_llm(_model):
        return FakeListChatModel(responses=["lockbit leak site", "1, 2", SUMMARY])

    def fake_search(q, max_workers=5):
        search.last_search_stats = {"E1": {"status": "ok_results"}}
        return ([{"title": "LockBit leak mirror", "link": ONION_A}, {"title": "LockBit blog", "link": ONION_B}],
                {"E1": "ok", "E2": "failed"})

    def fake_scrape(items, max_workers=5):
        scrape.last_details = {it["link"]: {"status": "ok"} for it in items}
        scrape.last_blocked_count = 0
        return {ONION_A: BODY, ONION_B: "texto sem o alvo " * 20}

    engines = lambda: [{"name": "E1", "url": "http://e1.onion/?q={query}"},  # noqa: E731
                       {"name": "E2", "url": "http://e2.onion/?q={query}"}]
    monkeypatch.setattr(llm, "get_llm", fake_llm)
    monkeypatch.setattr(ui_pipeline, "get_llm", fake_llm)
    monkeypatch.setattr(search, "get_search_results", fake_search)
    monkeypatch.setattr(scrape, "scrape_multiple", fake_scrape)
    monkeypatch.setattr(pipeline, "get_active_engines", engines)
    monkeypatch.setattr(engine_manager, "get_active_engines", engines)
    monkeypatch.setattr(pipeline, "tor_available", lambda *a, **k: False)
    # A Home verifica os motores na 1.ª carga se o Tor estiver ativo; o teste
    # nunca pode chegar à rede, mesmo numa máquina com o Tor a correr.
    monkeypatch.setattr(health, "check_tor_proxy",
                        lambda: {"status": "down", "latency_ms": None, "error": "teste offline"})
    monkeypatch.setattr(health, "check_search_engines", lambda *a, **k: [])
    monkeypatch.setattr(llm_utils, "get_model_choices", lambda: ["fake-model"])
    monkeypatch.chdir(tmp_path)  # investigations/ e logs/ ficam na pasta temporária
    return tmp_path


@pytest.mark.parametrize("page", ["Home.py", "pages/2_🔍_Investigation.py"])
def test_page_runs_the_shared_pipeline(fakes, page):
    at = AppTest.from_file(str(ROOT / page), default_timeout=60)
    at.run()
    assert not at.exception
    at.text_input[0].input("lockbit leak site")
    next(b for b in at.button if b.label == "Run").click()
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert not at.error

    md = "\n".join(m.value for m in at.markdown)
    assert md.count("O LockBit [FONTE 1]") == 1           # relatório mostrado uma só vez
    assert "`203.0.113.9`" in md                          # IOC fora da evidência assinalado
    assert any("Tor inacessível" in w.value for w in at.warning)
    assert len(at.get("download_button")) == 2

    files = sorted((fakes / "investigations").glob("investigation_*.json"))
    assert len(files) == 1
    rec = json.loads(files[0].read_text(encoding="utf-8"))
    assert rec["pipeline_version"] == PIPELINE_VERSION and rec["model"] == "fake-model"
    assert rec["summary_quality"]["ok"] is True
    assert list(rec["scraped_content"]) == [ONION_A]
    assert rec["engine_status"] == {"E1": "ok", "E2": "failed"}

    at.run()  # rerun: volta a desenhar o resultado sem correr de novo o pipeline
    assert not at.exception
    assert "\n".join(m.value for m in at.markdown).count("O LockBit [FONTE 1]") == 1
    assert len(list((fakes / "investigations").glob("*.json"))) == 1


def test_small_model_warning_is_visible(fakes, monkeypatch):
    import llm_utils
    import local_models
    monkeypatch.setattr(llm_utils, "get_model_choices", lambda: [local_models.LIGHTEST_MODEL])
    at = AppTest.from_file(str(ROOT / "Home.py"), default_timeout=60)
    at.run()
    at.text_input[0].input("lockbit leak site")
    next(b for b in at.button if b.label == "Run").click()
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("pequeno demais" in w.value for w in at.warning)
    rec = json.loads(next((fakes / "investigations").glob("investigation_*.json")).read_text(encoding="utf-8"))
    assert rec["model"] == local_models.LIGHTEST_MODEL
    assert any("pequeno demais" in w for w in rec["warnings"])
