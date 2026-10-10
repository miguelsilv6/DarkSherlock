"""Relatório sem sentido com o modelo 0,5B: definições persistentes, modelo por omissão,
Etapa 5 com 2 termos-chave e controlo de qualidade do relatório."""

import pytest

import llm
import local_models
import pipeline
import settings_state
import text_match as tm

VALID = ("## 1. Query: akira portugal\n\n## 2. Análise por Fonte\n\n### [FONTE 1]\nO grupo Akira listou uma "
         "empresa portuguesa [FONTE 1].\n\n## 3. Artefactos / IOCs\n\nNenhum identificado.\n\n"
         "## 4. Insights Chave\n\n- Vítima em Portugal.\n\n## 5. Próximos Passos\n\n- Confirmar a vítima.")


def _degenerate(n=20):
    block = ("### 1.{i} Livros de Portugal em Inglês\n\nOs seguintes livros são considerados obras:\n\n"
             "- \"Um livro\" (2016)\n- \"Um livro\" (2017)\n")
    return "## 1. Análise de Livros\n\n" + "\n".join(block.format(i=i) for i in range(1, n + 1)) + "### 1.99 Livros"


# --- definições persistentes ---------------------------------------------------
def test_settings_survive_a_restart():
    first = {"model_select": "Phi-3.5-mini (embutido, médio)", "thread_slider": 6}
    settings_state.persist(state=first)
    restarted = {}  # nova sessão: session_state vazio
    assert settings_state.get("model_select", state=restarted) == "Phi-3.5-mini (embutido, médio)"
    assert settings_state.get("thread_slider", state=restarted) == 6
    settings_state.restore("thread_slider", state=restarted)
    assert restarted["thread_slider"] == 6


def test_saved_model_no_longer_available_falls_back(monkeypatch):
    settings_state.save_value("model_select", "modelo-que-ja-nao-existe")
    monkeypatch.setattr(settings_state, "default_model", lambda opts: opts[0])
    assert settings_state.current(["A", "B"], state={})["model"] == "A"


def test_corrupt_settings_file_is_ignored():
    settings_state.SETTINGS_FILE.write_text("{nao é json", encoding="utf-8")
    assert settings_state.load_file() == {}
    assert settings_state.get("thread_slider", state={}) == settings_state.DEFAULTS["thread_slider"]


# --- modelo por omissão ----------------------------------------------------------
def test_default_is_largest_downloaded(monkeypatch):
    have = {"Qwen2.5-0.5B (embutido, ultraleve)", "Llama-3.2-3B (embutido, médio)", "Phi-3.5-mini (embutido, médio)"}
    monkeypatch.setattr(local_models, "_ENV_DEFAULT_MODEL", "")
    monkeypatch.setattr(local_models, "is_downloaded", lambda k: k in have)
    assert local_models.preferred_default_model() == "Phi-3.5-mini (embutido, médio)"
    monkeypatch.setattr(local_models, "is_downloaded", lambda k: False)
    assert local_models.preferred_default_model() == local_models.LIGHTEST_MODEL


def test_env_default_wins(monkeypatch):
    monkeypatch.setattr(local_models, "_ENV_DEFAULT_MODEL", "Qwen2.5-1.5B (embutido, leve)")
    monkeypatch.setattr(local_models, "is_downloaded", lambda k: True)
    assert local_models.preferred_default_model() == "Qwen2.5-1.5B (embutido, leve)"


def test_small_model_warning():
    r = pipeline.PipelineResult(query="x", model=local_models.LIGHTEST_MODEL)
    pipeline.check_model(r)
    assert any("pequeno demais" in w for w in r.warnings)
    r = pipeline.PipelineResult(query="x", model="Phi-3.5-mini (embutido, médio)")
    pipeline.check_model(r)
    assert not r.warnings
    assert not local_models.is_too_small_for_report("gpt-oss-16k")  # Ollama: tamanho desconhecido


# --- Etapa 5 ---------------------------------------------------------------------
def test_required_hits_all_terms_up_to_two():
    def need(q):
        return tm.required_hits(tm.query_terms(q))
    assert need("lockbit leak site") == (1, True)
    assert need("Akira ransomware Portugal") == (2, True)
    assert need("cobalt strike beacon") == (2, True)
    assert need("alpha bravo charlie delta") == (2, True)
    assert need("alpha bravo charlie delta echo") == (3, True)


def test_page_only_about_portugal_is_not_evidence():
    q = "Akira ransomware Portugal"
    livraria = "Livraria online: os melhores livros de Portugal, autores portugueses e obras clássicas. " * 5
    akira_pt = "O grupo Akira publicou no seu leak site uma empresa de Portugal como nova vítima. " * 5
    kept = llm.filter_scraped_by_relevance(q, {"http://livros.onion": livraria, "http://akira.onion": akira_pt})
    assert list(kept) == ["http://akira.onion"]


def test_empty_stage5_explains_missing_term():
    r = pipeline.PipelineResult(query="Akira ransomware Portugal")
    r.filtered = [{"title": "t", "link": "http://livros.onion"}]
    text = "Livraria online: os melhores livros de Portugal e obras clássicas portuguesas. " * 5
    pipeline.stage_scrape(r, 1, scrape_fn=lambda f, t: ({"http://livros.onion": text},
                                                         {"http://livros.onion": {"status": "ok"}}, 0))
    assert r.stage5_outcome == "empty"
    assert any("akira: 0 de 1" in w and "portugal: 1 de 1" in w for w in r.warnings)


# --- controlo de qualidade do relatório -----------------------------------------
def test_degenerate_report_is_flagged_and_collapsed():
    text = _degenerate()
    q = llm.summary_quality(text, n_sources=3)
    assert not q["ok"] and set(q["problems"]) == {"repetition", "missing_sections", "no_citations"}
    out, banner = llm._apply_quality_gate(text, 3)
    assert "Relatório inválido" in banner and "[FONTE N]" in banner
    assert out.count("Livros de Portugal em Inglês") == 1   # 20 repetições -> 1 (e a última, cortada, sai)
    assert llm.last_summary_quality == q


def test_valid_report_passes_untouched():
    q = llm.summary_quality(VALID, n_sources=1)
    assert q["ok"] and q["citations"] == 2 and q["missing_sections"] == []
    out, banner = llm._apply_quality_gate(VALID, 1)
    assert out == VALID and banner == ""


def test_report_without_citations_gets_milder_warning():
    text = VALID.replace("[FONTE 1]", "")
    out, banner = llm._apply_quality_gate(text, 2)
    assert "sem citações" in banner and "inválido" not in banner and out == text


def test_generate_summary_marks_bad_report(fake_llm):
    content = {f"http://s{i}.onion": "O grupo Akira e uma vítima em Portugal. " * 10 for i in range(2)}
    out = llm.generate_summary(fake_llm(_degenerate()), "Akira Portugal", content)
    assert out.startswith("> ⛔ **Relatório inválido")
    assert out.count("Livros de Portugal em Inglês") == 1


# --- modelo embutido sem pedidos de rede quando já está em cache ---------------
def test_cached_model_loads_without_network(monkeypatch, tmp_path):
    huggingface_hub = pytest.importorskip("huggingface_hub")
    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(b"GGUF")
    monkeypatch.setattr(local_models, "is_available", lambda: True)
    monkeypatch.setattr(huggingface_hub, "try_to_load_from_cache", lambda **k: str(gguf))

    def no_network(**k):
        raise AssertionError("hf_hub_download não pode ser chamado com o modelo em cache")
    monkeypatch.setattr(huggingface_hub, "hf_hub_download", no_network)
    assert local_models.ensure_downloaded(local_models.LIGHTEST_MODEL) == str(gguf)


def test_missing_model_is_downloaded_once(monkeypatch, tmp_path):
    huggingface_hub = pytest.importorskip("huggingface_hub")
    calls = []
    monkeypatch.setattr(local_models, "is_available", lambda: True)
    monkeypatch.setattr(local_models, "MODELS_DIR", tmp_path)
    monkeypatch.setattr(huggingface_hub, "try_to_load_from_cache", lambda **k: None)
    monkeypatch.setattr(huggingface_hub, "hf_hub_download", lambda **k: calls.append(k) or "/x.gguf")
    spec = local_models.BUILTIN_MODELS[local_models.LIGHTEST_MODEL]
    assert local_models.ensure_downloaded(local_models.LIGHTEST_MODEL) == "/x.gguf"
    assert calls == [{"repo_id": spec["repo_id"], "filename": spec["filename"], "cache_dir": str(tmp_path)}]
