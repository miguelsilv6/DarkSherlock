"""evaluation/stage5_report.py — leitura da Etapa 5 por cenário, sem mostrar queries nem termos."""

import json

import stage5_report as S5

Q = "Akira ransomware Portugal"   # termos-chave: T1 = akira, T2 = portugal; contexto: ransomware


def _inv(tmp, sc, i, *, query=Q, ok=5, scores=None, scraped=None):
    d = {"model": "M", "scenario_id": sc, "pipeline_version": "2.3", "query": query,
         "scrape_outcomes": {"ok": ok}, "relevance_scores": scores or {}, "scraped_content": scraped or {},
         "sources": [{"link": u, "title": "t"} for u in (scores or {})]}
    (tmp / f"eval_{sc}_20261012_00000{i}.json").write_text(json.dumps(d), encoding="utf-8")


def _page(*found):
    return {"found": list(found), "key_found": sum(1 for f in found if f != "ransomware"), "score": .5}


def test_readings(tmp_path, capsys):
    _inv(tmp_path, "A1", 0, scores={"u1": _page("akira", "portugal")}, scraped={"u1": "texto"})
    _inv(tmp_path, "B1", 0, ok=1, scores={"u1": _page()})
    _inv(tmp_path, "C1", 0, query="pessoa@exemplo.pt", scores={f"u{i}": _page() for i in range(4)})
    _inv(tmp_path, "D1", 0, scores={"u1": _page("akira"), "u2": _page("akira"), "u3": _page()})
    _inv(tmp_path, "D2", 0, scores={"u1": _page("akira", "ransomware"), "u2": _page("portugal")})
    assert S5.main(["--model", "M", "--investigations", str(tmp_path / "eval_*.json"),
                    "--out", str(tmp_path / "r.md")]) == 0
    text = (tmp_path / "r.md").read_text(encoding="utf-8")
    row = {ln.split("|")[1].strip(): ln for ln in text.splitlines() if ln.startswith("| ") and ln[2] in "ABCD"}
    assert "com evidência em 1 de 1" in row["A1"]
    assert "poucas páginas recolhidas" in row["B1"]
    assert "nenhum termo-chave" in row["C1"] and "verdadeiro negativo provável" in row["C1"]
    assert "T1 67%, T2 0%" in row["D1"] and "T1 presente(s), T2 nunca" in row["D1"]
    assert "1 só com possíveis homónimos" in row["D1"]
    assert "nunca na mesma página" in row["D2"]
    low = text.lower() + capsys.readouterr().out.lower()
    assert "akira" not in low and "portugal" not in low and "pessoa@" not in low


def test_query_change_within_scenario_is_split(tmp_path):
    _inv(tmp_path, "A1", 0, scores={"u1": _page()})
    _inv(tmp_path, "A1", 1, query="lockbit leak site", scores={"u1": _page()})
    text = S5.render(S5.load(str(tmp_path / "eval_*.json"), "M", "00000000", None, "scenarios"), "#")
    assert "A1 (query 1)" in text and "A1 (query 2)" in text
