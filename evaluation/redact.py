"""
evaluation/redact.py — Rasura dos dados reais da avaliação antes de entrarem no relatório.

Os cenários reais (evaluation/scenarios.local.json, fora do Git) dizem o que
rasurar: os termos de "redact" de cada cenário (ou, se faltar, os termos-chave
da query), substituídos pelo pseudónimo do cenário ("[Vítima-V2]"). Além
disso, em qualquer texto:

  - endereços .onion  -> [onion:<8 hex>]   (SHA-256 do host: o mesmo endereço
    dá sempre o mesmo código, para se poder comparar entre tabelas, sem o revelar);
  - emails            -> [email:<8 hex>]   (dados de terceiros que aparecem nas fugas).

Cada termo é reconhecido com as variantes de escrita habituais: maiúsculas e
acentos, espaços/pontos/traços entre palavras, emails ofuscados
("nome [at] dominio [dot] pt"), NIF/telefones com separadores ("123 456 789"),
domínios com "[.]".

Uso:
    python evaluation/redact.py investigations/eval_A1_*.json evaluation/results/ --out evaluation/redacted
    python evaluation/redact.py --check evaluation/redacted          # falha se restar algo
    python evaluation/redact.py --check-staged                       # hook pre-commit (ver .githooks/)

--check e --check-staged nunca imprimem o termo real encontrado — só o
ficheiro, a linha e o pseudónimo. Não é uma garantia: lê sempre o texto final
antes de o pôr no relatório.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import scenarios as scenarios_mod  # noqa: E402

TEXT_SUFFIXES = {".md", ".txt", ".csv", ".tsv", ".json", ".html", ".htm", ".log", ".jsonl"}

# Caminhos que nunca podem ser versionados (dados reais ou sensíveis).
FORBIDDEN_PATHS = [
    re.compile(r"(^|/)scenarios\.local\.json$"),
    re.compile(r"^referrals/"),
    re.compile(r"^investigations/"),
    re.compile(r"^evaluation/ground_truth/"),
    re.compile(r"^evaluation/baseline_manual/(sources|reports)/"),
]

RE_ONION = re.compile(r"\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b", re.IGNORECASE)
# "@" e as ofuscações entre parênteses; _AT_LOOSE aceita também " at " solto
# (só nos termos dos cenários: no texto em geral apanharia "hosted at site.com").
_AT = r"\s*(?:@|\[\s*(?:at|arroba)\s*\]|\(\s*(?:at|arroba)\s*\)|\{\s*(?:at|arroba)\s*\})\s*"
_AT_LOOSE = r"\s*(?:@|\[\s*(?:at|arroba)\s*\]|\(\s*(?:at|arroba)\s*\)|\{\s*(?:at|arroba)\s*\}|\s(?:at|arroba)\s)\s*"
_DOT = r"\s*(?:\.|\[\s*(?:\.|dot|ponto)\s*\]|\(\s*(?:\.|dot|ponto)\s*\)|\{\s*(?:\.|dot|ponto)\s*\}|\s(?:dot|ponto)\s)\s*"
RE_EMAIL = re.compile(r"[\w.+-]+" + _AT + r"[\w-]+(?:\.[\w-]+)*\.[a-z]{2,24}\b"
                      r"|[\w.+-]+" + _AT + r"[\w-]+(?:" + _DOT + r"[\w-]+)*" + _DOT + r"[a-z]{2,24}\b",
                      re.IGNORECASE)
RE_PLACEHOLDER = re.compile(r"\[(?:onion|email):[0-9a-f]{8}\]")


def _sha8(text: str) -> str:
    return hashlib.sha256(text.lower().encode("utf-8")).hexdigest()[:8]


def _fold_with_map(text: str):
    """Texto em minúsculas e sem acentos + posição original de cada carácter."""
    out, idx = [], []
    for i, ch in enumerate(text):
        for c in unicodedata.normalize("NFKD", ch):
            if not unicodedata.combining(c):
                out.append(c.lower())
                idx.append(i)
    return "".join(out), idx


def _fold(text: str) -> str:
    return _fold_with_map(text)[0]


@dataclass
class Rule:
    label: str
    pattern: re.Pattern
    scenario: str


def _term_pattern(term: str) -> re.Pattern | None:
    """Regex (sobre texto dobrado) que apanha o termo e as suas variantes de escrita."""
    t = _fold(term).strip()
    if len(re.sub(r"\W", "", t)) < 3:
        return None  # demasiado curto para rasurar sem destruir o texto
    if "@" in t:
        local, _, domain = t.partition("@")
        dom = _DOT.join(re.escape(p) for p in domain.split("."))
        return re.compile(r"(?<![\w.+-])" + re.escape(local) + _AT_LOOSE + dom + r"(?![\w-])")
    digits = re.sub(r"\D", "", t)
    if digits and len(digits) >= 6 and re.fullmatch(r"[\d\s.\-/]+", t):
        return re.compile(r"(?<!\d)" + r"[\s.\-/]?".join(digits) + r"(?!\d)")
    if "." in t and " " not in t:  # domínio: os pontos podem vir ofuscados ("[.]", "[dot]")
        return re.compile(r"(?<![\w-])" + _DOT.join(re.escape(lbl) for lbl in t.split(".")) + r"(?![\w-])")
    words = re.findall(r"[\w]+", t, re.UNICODE)
    # palavras: aceita espaços, pontos, traços ou nada entre elas ("empresa-exemplo", "empresa exemplo")
    return re.compile(r"(?<![\w])" + r"[\s._\-]*".join(re.escape(w) for w in words) + r"(?![\w])")


def build_rules(scenarios: list) -> list[Rule]:
    """Regras de rasura a partir dos cenários (termos explícitos, ou termos-chave da query)."""
    import text_match as tm  # só aqui: o resto do módulo não precisa do código da app
    rules, seen = [], set()
    for sc in scenarios:
        default_label = sc.get("label") or f"Cenário-{sc['id']}"
        items = sc.get("redact")
        if items is None:
            items = [t.text for t in tm.query_terms(sc["query"]) if t.key]
        for it in items:
            term, label = (it.get("term", ""), it.get("label") or default_label) if isinstance(it, dict) \
                else (str(it), default_label)
            key = _fold(term).strip()
            if not key or key in seen:
                continue
            pat = _term_pattern(term)
            if pat is not None:
                seen.add(key)
                rules.append(Rule(label, pat, sc["id"]))
    # termos mais longos primeiro ("empresa exemplo sa" antes de "empresa exemplo")
    rules.sort(key=lambda r: -len(r.pattern.pattern))
    return rules


def _apply_rules(text: str, rules: list[Rule]) -> str:
    """Uma só passagem: as ocorrências de todas as regras, sem sobreposições (a mais longa ganha).

    Assim nenhuma regra volta a rasurar dentro de um pseudónimo já inserido.
    """
    folded, idx = _fold_with_map(text)
    spans = []
    for rule in rules:
        for m in rule.pattern.finditer(folded):
            if m.end() > m.start():
                spans.append((idx[m.start()], idx[m.end() - 1] + 1, rule.label))
    spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    chosen, last_end = [], -1
    for a, b, label in spans:
        if a >= last_end:
            chosen.append((a, b, label))
            last_end = b
    for a, b, label in reversed(chosen):
        text = text[:a] + f"[{label}]" + text[b:]
    return text


def redact_text(text: str, rules: list[Rule], emails: bool = True) -> str:
    text = _apply_rules(text, rules)
    text = RE_ONION.sub(lambda m: f"[onion:{_sha8(m.group(0))}]", text)
    if emails:
        text = RE_EMAIL.sub(lambda m: f"[email:{_sha8(m.group(0))}]", text)
    return text


def redact_obj(obj, rules, emails=True):
    """Rasura recursiva de JSON: valores e chaves (p. ex. os URLs de scraped_content)."""
    if isinstance(obj, str):
        return redact_text(obj, rules, emails)
    if isinstance(obj, list):
        return [redact_obj(x, rules, emails) for x in obj]
    if isinstance(obj, dict):
        return {redact_text(k, rules, emails) if isinstance(k, str) else k: redact_obj(v, rules, emails)
                for k, v in obj.items()}
    return obj


def find_leftovers(text: str, rules: list[Rule], emails: bool = True) -> list[tuple[int, str]]:
    """(linha, descrição) de cada identificador por rasurar. A descrição nunca inclui o termo real."""
    hits = []
    clean = RE_PLACEHOLDER.sub(" ", text)
    for label in {r.label for r in rules}:
        clean = clean.replace(f"[{label}]", " ")
    for n, line in enumerate(clean.splitlines(), 1):
        folded = _fold(line)
        for rule in rules:
            if rule.pattern.search(folded):
                hits.append((n, f"termo real do cenário {rule.scenario} (rasurar como [{rule.label}])"))
        if RE_ONION.search(line):
            hits.append((n, "endereço .onion"))
        if emails and RE_EMAIL.search(line):
            hits.append((n, "email"))
    return hits


def _iter_files(paths):
    for p in map(Path, paths):
        if p.is_dir():
            yield from (f for f in sorted(p.rglob("*")) if f.is_file() and f.suffix.lower() in TEXT_SUFFIXES)
        elif p.is_file():
            yield p


def redact_file(src: Path, dst: Path, rules, emails=True) -> None:
    raw = src.read_text(encoding="utf-8", errors="replace")
    if src.suffix.lower() == ".json":
        try:
            out = json.dumps(redact_obj(json.loads(raw), rules, emails), ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            out = redact_text(raw, rules, emails)
    else:
        out = redact_text(raw, rules, emails)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(out, encoding="utf-8")


def _load_rules(path: str | None):
    sc, source = scenarios_mod.load(Path(path) if path else None)
    if source != "local":
        return [], source
    return build_rules(sc), source


def cmd_redact(args) -> int:
    rules, source = _load_rules(args.scenarios)
    if source != "local":
        print("AVISO: sem scenarios.local.json — só se rasuram endereços .onion e emails.", file=sys.stderr)
    out = Path(args.out)
    n = 0
    for p in map(Path, args.paths):
        base = p if p.is_dir() else p.parent
        for f in _iter_files([p]):
            dst = out / (p.name if p.is_dir() else "") / f.relative_to(base)
            redact_file(f, dst, rules, not args.keep_emails)
            n += 1
    print(f"{n} ficheiro(s) rasurado(s) em {out}. Confirma com: python evaluation/redact.py --check {out}")
    return 0 if n else 1


def cmd_check(args) -> int:
    rules, _ = _load_rules(args.scenarios)
    bad = 0
    for f in _iter_files(args.paths):
        for line, what in find_leftovers(f.read_text(encoding="utf-8", errors="replace"), rules, not args.keep_emails):
            print(f"{f}:{line}: {what}")
            bad += 1
    print(f"{'FALHOU' if bad else 'OK'}: {bad} identificador(es) por rasurar.")
    return 1 if bad else 0


def cmd_check_staged(args) -> int:
    """Hook pre-commit: recusa caminhos proibidos e ficheiros com termos reais dos cenários."""
    names = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                           capture_output=True, text=True, check=True).stdout.split()
    rules, _ = _load_rules(args.scenarios)
    problems = []
    for name in names:
        if any(rx.search(name) for rx in FORBIDDEN_PATHS):
            problems.append(f"{name}: caminho com dados reais/sensíveis — não pode ser versionado")
            continue
        if not rules or Path(name).suffix.lower() not in TEXT_SUFFIXES | {".py"}:
            continue
        blob = subprocess.run(["git", "show", f":{name}"], capture_output=True, text=True,
                              errors="replace").stdout
        folded = _fold(blob)
        for rule in rules:
            if rule.pattern.search(folded):
                problems.append(f"{name}: contém um termo real do cenário {rule.scenario} ([{rule.label}])")
    for p in problems:
        print(f"pre-commit: {p}", file=sys.stderr)
    if problems:
        print("pre-commit: commit recusado. Rasura com evaluation/redact.py ou retira o ficheiro do commit.",
              file=sys.stderr)
    return 1 if problems else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="Ficheiros ou pastas (.md, .csv, .json, .txt, ...).")
    ap.add_argument("--out", default=str(HERE / "redacted"), help="Pasta de saída (default: evaluation/redacted).")
    ap.add_argument("--check", action="store_true", help="Só verifica: falha se restar algum identificador.")
    ap.add_argument("--check-staged", action="store_true", help="Verifica os ficheiros preparados para commit.")
    ap.add_argument("--scenarios", default=None, help="Ficheiro de cenários (default: evaluation/scenarios.local.json).")
    ap.add_argument("--keep-emails", action="store_true", help="Não rasura emails que não sejam termos dos cenários.")
    args = ap.parse_args(argv)
    if args.check_staged:
        return cmd_check_staged(args)
    if not args.paths:
        ap.error("indica ficheiros ou pastas")
    return cmd_check(args) if args.check else cmd_redact(args)


if __name__ == "__main__":
    sys.exit(main())
