import pytest

docx = pytest.importorskip("docx")

import rascunho_cap6 as RC  # noqa: E402

MD13 = """> ⚠️ ENSAIO TÉCNICO — DADOS FICTÍCIOS. NÃO USAR NA TESE.

# EQ-01 — eficiência operacional

Modelo: `Phi` · execuções desde 20261110.

## Tabela 13 — tempo end-to-end e speedup

| Cenário | Speedup (×) |
|---|---|
| A1 | **42.0** |

## Speedup por domínio

| Domínio | n |
|---|---|
| Threat Intel | 3 |

- Pares: 3 · *nota*

---

*Dados simulados (ensaio técnico, perfil realista) — não usar na tese.*
"""


def _ensaio(tmp_path, name):
    d = tmp_path / name
    d.mkdir()
    (d / "eq01_tabela13.md").write_text(MD13, encoding="utf-8")
    return d


def test_simulated_docx_footer_name_and_captions(tmp_path):
    d = _ensaio(tmp_path, "SIMULADO_REALISTA_1")
    assert RC.main(["--ensaio", str(d), "--first-table", "20"]) == 0
    files = list(d.glob("SIMULADO_Cap6_*.docx"))
    assert len(files) == 1
    doc = docx.Document(files[0])
    assert all(s.footer.paragraphs[0].text == RC.SIM_FOOTER for s in doc.sections)
    texts = [p.text for p in doc.paragraphs]
    assert "Tabela 20 — tempo end-to-end e speedup" in texts and "Tabela 21 — Speedup por domínio" in texts
    assert "6.1.1 tempo end-to-end e speedup" in texts  # o número da tabela não se repete no título
    assert not any("FICTÍCIOS" in t or "Dados simulados" in t for t in texts)
    assert any("por gerar" in t for t in texts)  # EQ-02/03, VN e EQ-04 em falta
    assert len(doc.tables) == 2
    cell = doc.tables[0].rows[1].cells[1].paragraphs[0]
    assert cell.text == "42.0" and cell.runs[0].bold
    code = [r for p in doc.paragraphs for r in p.runs if r.text == "Phi"]
    assert code and code[0].font.name == "Consolas"


def test_real_folder_has_no_footer(tmp_path):
    d = _ensaio(tmp_path, "resultados")
    out = tmp_path / "x.docx"
    assert RC.main(["--ensaio", str(d), "--out", str(out)]) == 0
    doc = docx.Document(out)
    assert all(not p.text for s in doc.sections for p in s.footer.paragraphs)


def test_simulated_name_is_forced(tmp_path):
    d = _ensaio(tmp_path, "ENSAIO_FICTICIO_1")
    assert RC.main(["--ensaio", str(d), "--out", str(tmp_path / "cap6.docx")]) == 0
    assert (tmp_path / "SIMULADO_cap6.docx").is_file() and not (tmp_path / "cap6.docx").exists()


def test_no_summaries_fails(tmp_path):
    d = tmp_path / "SIMULADO_vazio"
    d.mkdir()
    assert RC.main(["--ensaio", str(d)]) == 1
