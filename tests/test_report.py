"""PR 4 — PDF forense: fontes analisadas numeradas como no prompt, todos os hashes, hora da investigação."""

import io

import pytest

pytest.importorskip("fpdf")
pypdf = pytest.importorskip("pypdf")

import report  # noqa: E402


def _pdf_text(data: dict) -> str:
    reader = pypdf.PdfReader(io.BytesIO(bytes(report.generate_forensic_pdf(data))))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def _data(n_sources=20, analysed=(3, 1, 7)):
    sources = [{"title": f"Titulo {i}", "link": f"http://s{i}.onion/p"} for i in range(1, n_sources + 1)]
    scraped = {f"http://s{i}.onion/p": f"conteudo da fonte {i} " * 20 for i in analysed}
    return {
        "audit_id": "11111111-2222-3333-4444-555555555555",
        "query": "grupo alvo",
        "refined_query": "grupo alvo",
        "model": "modelo-teste",
        "preset": "Dark Web Threat Intel",
        "timestamp_utc": "2026-09-01T10:20:30+00:00",
        "active_engines": ["E1", "E2"],
        "sources": sources,
        "integrity": report.compute_integrity_hashes(scraped),
        "scraped_content": scraped,
        "summary": "## 1. Query: grupo alvo\n\nTexto [FONTE 1].",
        "results_found": 50,
        "results_scraped": len(scraped),
    }


def test_sources_section_lists_only_analysed_in_prompt_order():
    text = _pdf_text(_data())
    sec = text[text.index("3. Fontes Analisadas"):]
    assert "Total de fontes analisadas: 3" in sec
    assert "nao analisadas" in sec and ": 17" in sec
    # mesma ordem que scraped_content (= ordem do prompt da Etapa 6)
    p1, p2, p3 = (sec.index(f"[FONTE {k}]") for k in (1, 2, 3))
    assert p1 < sec.index("Titulo 3") < p2 < sec.index("Titulo 1") < p3 < sec.index("Titulo 7")
    assert "[FONTE 4]" not in sec
    assert "Titulo 12" not in sec


def test_all_hashes_are_printed():
    analysed = tuple(range(1, 21))
    data = _data(n_sources=20, analysed=analysed)
    text = _pdf_text(data).replace("\n", "")
    for sha in data["integrity"]["sources"].values():
        assert sha[:16] in text  # o hash pode ser partido em linhas, o prefixo não


def test_pdf_uses_investigation_timestamp():
    text = _pdf_text(_data())
    assert "2026-09-01 10:20:30" in text


def test_investigation_pdf_data_from_saved_json():
    saved = _data()
    saved["search_results"] = [{"link": f"http://r{i}.onion"} for i in range(42)]
    del saved["results_found"], saved["results_scraped"]
    out = report.investigation_pdf_data(saved)
    assert out["timestamp_utc"] == "2026-09-01T10:20:30+00:00"
    assert out["results_found"] == 42
    assert out["results_scraped"] == 3
    assert list(out["scraped_content"]) == list(saved["scraped_content"])


def test_investigation_pdf_data_old_json_without_new_fields():
    old = {"query": "q", "refined_query": "q", "model": "m", "preset": "p", "timestamp": "2026-01-01T00:00:00",
           "sources": [{"link": "http://x.onion", "title": "x"}], "summary": "s",
           "integrity": {"sources": {"http://x.onion": "0" * 64}}}
    out = report.investigation_pdf_data(old)
    assert out["timestamp_utc"] == "2026-01-01T00:00:00"
    assert out["results_found"] == 1 and out["results_scraped"] == 1
    report.generate_forensic_pdf(out)  # não rebenta com JSON antigo
