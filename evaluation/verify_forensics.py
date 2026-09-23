"""
evaluation/verify_forensics.py — Verifica as três métricas forenses do EQ-05
(Capítulo 6, secção 6.4.5 / 6.6.5): determinismo do hash global, integridade
SHA-256 por fonte, e completude do audit trail.

Nota de desenho importante sobre o subcomando `integrity`: ele NÃO importa
report.compute_integrity_hashes() para recalcular os hashes. Reutilizar a
mesma função que gerou o hash para o "verificar" provaria muito pouco — um
bug nessa função produziria sempre o mesmo resultado (errado) em ambos os
lados da comparação. Este script reimplementa o algoritmo de forma
independente (mesma definição documentada: SHA-256 por fonte + SHA-256 da
concatenação ordenada por URL), para que a comparação seja uma verificação
real, não um espelho.

O subcomando `determinism` é a exceção deliberada: aí queremos mesmo testar
se a FUNÇÃO REAL é determinística, por isso chama-a repetidamente.

Uso:
    # EQ-05.1 — determinismo do hash (dados fixos, não depende de investigações reais)
    python evaluation/verify_forensics.py determinism --repeats 5

    # EQ-05.2 — integridade SHA-256 (recalcula a partir de scraped_content persistido)
    python evaluation/verify_forensics.py integrity investigations/*.json

    # EQ-05.3 — completude do audit trail
    python evaluation/verify_forensics.py audit-trail logs/audit.jsonl

Pré-requisito para `integrity`: as investigações têm de ter sido geradas
DEPOIS do fix que passou a persistir "scraped_content" (Home.py e
run_scenarios.py) — investigações anteriores não têm esse campo e são
reportadas como não verificáveis, não como falhas.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

# Campos que log_investigation() (audit.py) sempre inclui — ver Home.py e
# evaluation/run_scenarios.py, que chamam a mesma função com o mesmo formato.
REQUIRED_AUDIT_FIELDS = {
    "audit_id", "query", "refined_query", "model", "preset", "engines_active",
    "results_found", "results_filtered", "results_scraped",
    "summary_length_chars", "pipeline_duration_ms", "errors", "logged_at_utc",
}


def _independent_source_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _independent_overall_hash(scraped_content: dict) -> str:
    combined = "".join(content for _, content in sorted(scraped_content.items()))
    return hashlib.sha256(combined.encode("utf-8", errors="replace")).hexdigest()


def cmd_determinism(repeats: int) -> bool:
    """EQ-05.1: a mesma função, no mesmo conteúdo, dá sempre o mesmo hash?"""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from report import compute_integrity_hashes  # import tardio (precisa de fpdf2)

    fixture = {
        "http://exemplo1.onion/a": "conteúdo de teste da fonte A — " * 20,
        "http://exemplo2.onion/b": "conteúdo de teste da fonte B, diferente — " * 15,
        "http://exemplo3.onion/c": "terceira fonte com texto distinto ainda — " * 10,
    }

    results = [compute_integrity_hashes(fixture) for _ in range(repeats)]
    overall_hashes = {r["overall_sha256"] for r in results}
    per_source_snapshots = {tuple(sorted(r["sources"].items())) for r in results}
    deterministic = len(overall_hashes) == 1 and len(per_source_snapshots) == 1

    print(f"[EQ-05.1] Execuções: {repeats}")
    if deterministic:
        print(f"[EQ-05.1] Hash global (idêntico nas {repeats} execuções): {overall_hashes.pop()}")
        print("[EQ-05.1] Determinístico: SIM (100%)")
    else:
        print(f"[EQ-05.1] Determinístico: NÃO — REGRESSÃO CRÍTICA (ver secção 6.6.5 do relatório)")
        for i, r in enumerate(results, 1):
            print(f"  Execução {i}: overall_sha256={r['overall_sha256']}")
    return deterministic


def cmd_integrity(patterns: list[str]) -> None:
    """EQ-05.2: o hash guardado bate certo com um recálculo independente do conteúdo persistido?"""
    paths: list[Path] = []
    for pattern in patterns:
        matched = glob.glob(pattern)
        if not matched and Path(pattern).is_file():
            matched = [pattern]
        paths.extend(Path(p) for p in matched)

    if not paths:
        print(f"ERRO: nenhum ficheiro encontrado para os padrões: {patterns}")
        sys.exit(1)

    verifiable = 0
    intact = 0
    not_verifiable = []
    problems = []

    for p in sorted(paths):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            problems.append((p, f"ficheiro ilegível/JSON inválido: {e}"))
            continue

        integrity = data.get("integrity") or {}
        scraped_content = data.get("scraped_content") or {}
        if not integrity or not scraped_content:
            not_verifiable.append(p)
            continue

        verifiable += 1
        stored_overall = integrity.get("overall_sha256")
        recomputed_overall = _independent_overall_hash(scraped_content)

        stored_sources = integrity.get("sources", {})
        mismatched_sources = [
            url for url, content in scraped_content.items()
            if stored_sources.get(url) != _independent_source_hash(content)
        ]

        if stored_overall == recomputed_overall and not mismatched_sources:
            intact += 1
        else:
            problems.append((
                p,
                f"hash global {'OK' if stored_overall == recomputed_overall else 'DIFERENTE'}; "
                f"{len(mismatched_sources)}/{len(scraped_content)} fontes com hash incorreto",
            ))

    print(f"[EQ-05.2] Ficheiros encontrados: {len(paths)}")
    print(f"[EQ-05.2] Não verificáveis (sem scraped_content — investigação anterior ao fix): {len(not_verifiable)}")
    if verifiable:
        print(f"[EQ-05.2] Verificáveis: {verifiable} | Íntegras: {intact} ({100 * intact / verifiable:.1f}%)")
    else:
        print("[EQ-05.2] Nenhuma investigação verificável ainda — corre o pipeline pelo menos uma vez "
              "depois do fix de persistência de scraped_content antes de repetir esta verificação.")
    for p, msg in problems:
        print(f"  PROBLEMA: {p} — {msg}")


def cmd_audit_trail(path_str: str) -> None:
    """EQ-05.3: cada execução produz exatamente uma linha válida, com todos os campos?"""
    path = Path(path_str)
    if not path.is_file():
        print(f"ERRO: ficheiro não encontrado: {path_str}")
        sys.exit(1)

    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    valid = 0
    problems = []
    audit_ids = []

    for i, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            problems.append((i, f"JSON inválido: {e}"))
            continue
        missing = REQUIRED_AUDIT_FIELDS - entry.keys()
        if missing:
            problems.append((i, f"campos em falta: {sorted(missing)}"))
            continue
        valid += 1
        audit_ids.append(entry["audit_id"])

    duplicates = {aid: n for aid, n in Counter(audit_ids).items() if n > 1}

    print(f"[EQ-05.3] Linhas no audit trail: {len(lines)}")
    print(f"[EQ-05.3] Válidas (todos os campos obrigatórios): {valid}/{len(lines)} "
          f"({100 * valid / len(lines):.1f}%)" if lines else "[EQ-05.3] Ficheiro vazio.")
    print(f"[EQ-05.3] audit_id duplicados (mais de uma linha para a mesma execução): {len(duplicates)}")
    for i, msg in problems[:20]:
        print(f"  Linha {i}: {msg}")
    if len(problems) > 20:
        print(f"  ... e mais {len(problems) - 20} problemas")
    for aid, n in list(duplicates.items())[:10]:
        print(f"  DUPLICADO: audit_id={aid} aparece {n} vezes")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_det = sub.add_parser("determinism", help="EQ-05.1 — determinismo do hash global.")
    p_det.add_argument("--repeats", type=int, default=5)

    p_int = sub.add_parser("integrity", help="EQ-05.2 — integridade SHA-256 por fonte.")
    p_int.add_argument("paths", nargs="+", help="Ficheiros ou padrões glob de investigation_*.json / eval_*.json")

    p_audit = sub.add_parser("audit-trail", help="EQ-05.3 — completude do audit trail.")
    p_audit.add_argument("path", help="Caminho para logs/audit.jsonl")

    args = parser.parse_args()

    if args.command == "determinism":
        ok = cmd_determinism(args.repeats)
        sys.exit(0 if ok else 1)
    elif args.command == "integrity":
        cmd_integrity(args.paths)
    elif args.command == "audit-trail":
        cmd_audit_trail(args.path)


if __name__ == "__main__":
    main()
