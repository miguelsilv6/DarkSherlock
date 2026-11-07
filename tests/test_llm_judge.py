import csv
import json

import pytest
from langchain_core.runnables import RunnableLambda

import eq04_review
import llm_judge as J

SENTINEL = "SEGREDO_HUMANO_42"


def recorder(*responses):
    """Modelo falso que regista as mensagens recebidas e devolve as respostas por ordem (em ciclo)."""
    seen, state = [], {"i": 0}

    def fn(prompt_value):
        seen.append(prompt_value.to_string())
        out = responses[state["i"] % len(responses)]
        state["i"] += 1
        return out

    return RunnableLambda(fn), seen


def _write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def _read(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


@pytest.mark.parametrize("text,label", [
    ("relevant", "relevant"), ("not_relevant", "not_relevant"), ("Resposta: Não relevante.", "not_relevant"),
    ("inacessível", "inaccessible"), ("INACCESSIBLE\n", "inaccessible"), ("not relevant", "not_relevant"),
    ("Relevante", "relevant"), ("talvez", None), ("", None),
])
def test_parse_label(text, label):
    assert J.parse_label(text) == label


def test_parse_scores():
    ok = {"correcao_tecnica": 4, "auditabilidade": 3, "utilidade_operacional": 2, "ausencia_alucinacoes": 5,
          "afirmacoes_verificaveis": 7, "afirmacoes_citacao_valida": 5}
    assert J.parse_scores("Aqui está: " + json.dumps(ok)) == ok
    assert J.parse_scores("\n".join(f"{k}: {v}" for k, v in ok.items())) == ok
    assert J.parse_scores(json.dumps({**ok, "correcao_tecnica": 6})) is None
    assert J.parse_scores(json.dumps({**ok, "afirmacoes_citacao_valida": 8})) is None
    assert J.parse_scores(json.dumps({k: v for k, v in ok.items() if k != "auditabilidade"})) is None
    assert J.parse_scores("sem json") is None


def _pool_fixture(tmp_path, model="Phi X"):
    gt, inv = tmp_path / "gt", tmp_path / "inv"
    gt.mkdir()
    inv.mkdir()
    urls = [f"http://s{i}.onion/p" for i in range(4)]
    _write_csv(gt / "review_A1_A.csv", ["n", "url", "title", "label", "notes"],
               [{"n": i + 1, "url": u, "title": f"t{i}", "label": "r", "notes": SENTINEL} for i, u in enumerate(urls)])
    json.dump({"scenario_id": "A1", "model": model, "query": "alvo da query",
               "scraped_content": {urls[0]: "texto longo " * 2000, urls[1]: "texto curto"}},
              open(inv / "eval_A1_20261010_100000.json", "w", encoding="utf-8"))
    return gt, inv, urls


def test_judge_pool_labels_retry_and_blindness(tmp_path):
    gt, inv, urls = _pool_fixture(tmp_path)
    fake, seen = recorder("hmm", "relevant", "not_relevant", "inaccessible", "nada", "nada")
    meta = J.judge_pool(gt, str(inv / "eval_*.json"), ["A1"], fake, "Juiz Y", max_chars=500)
    rows = _read(gt / "llm_judge" / "review_A1_LLM.csv")
    assert [r["label"] for r in rows] == ["relevant", "not_relevant", "inaccessible", ""]
    assert [r["evidence"] for r in rows] == ["text", "text", "title_only", "title_only"]
    assert rows[0]["truncated"] == "1" and rows[1]["truncated"] == "0"
    stats = meta["scenarios"]["A1"]
    assert stats == {"n": 4, "text": 2, "title_only": 2, "truncated": 1, "invalid": 1, "same_model": False}
    assert len(seen) == 6  # 1.ª e 4.ª fontes com nova tentativa
    assert all("alvo da query" in s for s in seen)
    assert not any(SENTINEL in s for s in seen)
    assert json.loads((gt / "llm_judge" / "meta_eq0203.json").read_text())["prompt_sha256"]


def test_judge_pool_warns_same_model(tmp_path, capsys):
    gt, inv, _ = _pool_fixture(tmp_path, model="Igual")
    fake, _ = recorder("relevant")
    meta = J.judge_pool(gt, str(inv / "eval_*.json"), ["A1"], fake, "Igual", limit=2)
    assert meta["scenarios"]["A1"]["same_model"] is True
    assert meta["scenarios"]["A1"]["n"] == 2
    out = capsys.readouterr().out
    assert "auto-preferência" in out and "alvo da query" not in out and ".onion" not in out


def _eq04_fixture(tmp_path, n=4):
    eq = tmp_path / "eq04"
    (eq / "reviewer_A" / "reports").mkdir(parents=True)
    (eq / "reviewer_A" / "evidence").mkdir(parents=True)
    (eq / "private").mkdir()
    key = {}
    for i in range(1, n + 1):
        rid = f"R{i:02d}"
        (eq / "reviewer_A" / "reports" / f"{rid}.md").write_text(f"# Relatório {rid}\n[FONTE 1] afirmação", encoding="utf-8")
        (eq / "reviewer_A" / "evidence" / f"{rid}.md").write_text("evidência", encoding="utf-8")
        key[rid] = {"scenario": f"A{i}", "condition": "DarkSherlock" if i % 2 else "manual",
                    "source_file": SENTINEL, "n_sources": 1}
    (eq / "private" / "key.json").write_text(json.dumps({"model": "Gerador", "reports": key, "note": SENTINEL}),
                                             encoding="utf-8")
    return eq, key


def _score(**kw):
    base = {"correcao_tecnica": 4, "auditabilidade": 3, "utilidade_operacional": 3, "ausencia_alucinacoes": 4,
            "afirmacoes_verificaveis": 6, "afirmacoes_citacao_valida": 3}
    return json.dumps({**base, **kw})


def test_judge_reports_blind_and_valid(tmp_path):
    eq, _ = _eq04_fixture(tmp_path)
    fake, seen = recorder("lixo", _score(), _score(correcao_tecnica=2), "x", "x", _score(auditabilidade=5))
    meta = J.judge_reports(eq, fake, "Juiz Y")
    rows = _read(eq / "llm_judge" / "scores_LLM.csv")
    assert [r["id"] for r in rows] == ["R01", "R02", "R03", "R04"]
    assert rows[0]["correcao_tecnica"] == "4" and rows[1]["correcao_tecnica"] == "2"
    assert rows[2]["correcao_tecnica"] == ""  # duas respostas inválidas
    assert rows[3]["auditabilidade"] == "5"
    assert meta["invalid"] == 1 and meta["n"] == 4
    assert not any(SENTINEL in s for s in seen)
    assert set(eq04_review.SCORE_FIELDS) <= set(rows[0])


def test_compare_known_kappas(tmp_path):
    gt = tmp_path / "gt"
    (gt / "llm_judge").mkdir(parents=True)
    urls = [f"http://s{i}.onion/" for i in range(6)]
    human = ["relevant", "not_relevant", "relevant", "inaccessible", "not_relevant", "relevant"]
    for who in ("A", "B"):
        _write_csv(gt / f"review_A1_{who}.csv", ["n", "url", "title", "label", "notes"],
                   [{"n": i, "url": u, "title": "", "label": h, "notes": ""} for i, (u, h) in enumerate(zip(urls, human))])
    _write_csv(gt / "llm_judge" / "review_A1_LLM.csv", ["n", "url", "title", "label", "evidence", "truncated", "raw"],
               [{"n": i, "url": u, "title": "", "label": h, "evidence": "text", "truncated": 0, "raw": ""}
                for i, (u, h) in enumerate(zip(urls, human))])
    (gt / "llm_judge" / "meta_eq0203.json").write_text(json.dumps({"model": "Juiz Y", "prompt_sha256": "ab" * 32,
                                                                   "scenarios": {}}))
    eq, key = _eq04_fixture(tmp_path)
    rows_a = [{"id": r, "correcao_tecnica": 1 + i, "auditabilidade": 2, "utilidade_operacional": 3 + (i % 2),
               "ausencia_alucinacoes": 5 - i, "afirmacoes_verificaveis": 4, "afirmacoes_citacao_valida": 2, "notas": ""}
              for i, r in enumerate(sorted(key))]
    for who in ("A", "B"):
        (eq / f"reviewer_{who}").mkdir(exist_ok=True)
        _write_csv(eq / f"reviewer_{who}" / f"scores_{who}.csv", eq04_review.SCORE_FIELDS, rows_a)
    (eq / "llm_judge").mkdir()
    _write_csv(eq / "llm_judge" / "scores_LLM.csv", eq04_review.SCORE_FIELDS, rows_a)
    (eq / "llm_judge" / "meta_eq04.json").write_text(json.dumps({"model": "Gerador", "n": 4}))
    md = J.compare(gt, eq)
    assert "| A1 | 6 | 0 | 0 | 100 % | 1.00 | 1.00 |" in md
    assert "| Correção técnica | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 |" in md
    assert "mesmo modelo que gerou" in md
    assert "complementar" in md


def test_compare_without_human_sheets(tmp_path):
    gt = tmp_path / "gt"
    (gt / "llm_judge").mkdir(parents=True)
    _write_csv(gt / "llm_judge" / "review_B1_LLM.csv", ["n", "url", "title", "label", "evidence", "truncated", "raw"],
               [{"n": 1, "url": "http://x.onion", "title": "", "label": "relevant", "evidence": "text",
                 "truncated": 0, "raw": ""}])
    md = J.compare(gt, None)
    assert "B1: folhas humanas indisponíveis" in md
