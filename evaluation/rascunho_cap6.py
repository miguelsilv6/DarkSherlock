"""
evaluation/rascunho_cap6.py — Rascunho Word (.docx) das secções de resultados
do Capítulo 6, a partir dos resumos Markdown das ferramentas de avaliação.

Junta, por esta ordem, os resumos da EQ-01 (Tabela 13), da EQ-02/EQ-03, da
tabela de verdadeiros negativos e da EQ-04. Cada "#" passa a uma secção 6.x;
cada "##" a uma subsecção; cada tabela Markdown a uma tabela Word com a legenda
"Tabela N — <subsecção>" por cima, numeradas a partir de --first-table.

Origem dos resumos:
  - --ensaio DIR: uma pasta do ensaio_tecnico.py (ENSAIO_FICTICIO_* ou
    SIMULADO_*). O ficheiro chama-se SIMULADO_Cap6_<data>.docx, fica nessa
    pasta e TODAS as páginas levam o rodapé "Rascunho com dados simulados —
    não submeter". As marcas d'água e rodapés dos .md não entram no corpo.
  - sem --ensaio: os resumos reais (evaluation/results/eq01_tabela13.md,
    evaluation/ground_truth/eq02_eq03_summary.md,
    evaluation/results/true_negatives.md,
    evaluation/ground_truth/eq04/eq04_summary.md). O ficheiro é
    evaluation/results/Cap6_resultados_<data>.docx, sem rodapé.
Os dois destinos estão fora do Git. Um resumo em falta fica assinalado no
documento ("por gerar") e no terminal.

Uso:
    python evaluation/rascunho_cap6.py --ensaio evaluation/ensaio/SIMULADO_REALISTA_20261108_101500
    python evaluation/rascunho_cap6.py --first-table 13
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIM_FOOTER = "Rascunho com dados simulados — não submeter"
SIM_PREFIXES = ("ENSAIO_FICTICIO", "SIMULADO")
# (título da secção, caminho numa pasta de ensaio, caminho real)
SOURCES = [
    ("Eficiência operacional (EQ-01)", "eq01_tabela13.md", HERE / "results" / "eq01_tabela13.md"),
    ("Cobertura e qualidade da filtragem (EQ-02 e EQ-03)", "eq02_eq03/eq02_eq03_summary.md",
     HERE / "ground_truth" / "eq02_eq03_summary.md"),
    ("Cenários sem evidência", "true_negatives.md", HERE / "results" / "true_negatives.md"),
    ("Qualidade analítica dos relatórios (EQ-04)", "eq04/eq04_summary.md",
     HERE / "ground_truth" / "eq04" / "eq04_summary.md"),
]
_SKIP = ("ENSAIO TÉCNICO — DADOS FICTÍCIOS", "Dados simulados (ensaio técnico")
_INLINE = re.compile(r"(\*\*[^*]+\*\*|\*[^*\s][^*]*\*|`[^`]+`)")
_TABLE_PREFIX = re.compile(r"^Tabela\s+\d+\s*[—-]\s*", re.IGNORECASE)


def is_simulated(folder: Path) -> bool:
    return folder.name.startswith(SIM_PREFIXES)


# ---------------------------------------------------------------------------
# Markdown -> blocos
# ---------------------------------------------------------------------------
def parse_blocks(md: str) -> list[tuple]:
    """Blocos ("h1"|"h2"|"h3", texto), ("p", texto), ("li", texto), ("quote", texto), ("table", linhas)."""
    blocks, para, table = [], [], []

    def flush_para():
        if para:
            blocks.append(("p", " ".join(para)))
            para.clear()

    def flush_table():
        if table:
            rows = [[c.strip() for c in ln.strip().strip("|").split("|")] for ln in table]
            rows = [r for r in rows if not all(re.fullmatch(r":?-{3,}:?", c) for c in r if c)]
            blocks.append(("table", rows))
            table.clear()

    for raw in md.splitlines():
        line = raw.rstrip()
        if any(s in line for s in _SKIP) or line.strip() == "---":
            flush_para()
            flush_table()
            continue
        if line.lstrip().startswith("|"):
            flush_para()
            table.append(line)
            continue
        flush_table()
        if not line.strip():
            flush_para()
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            flush_para()
            blocks.append((f"h{len(m.group(1))}", m.group(2).strip()))
        elif line.lstrip().startswith(("- ", "* ")):
            flush_para()
            blocks.append(("li", line.lstrip()[2:].strip()))
        elif line.startswith(">"):
            flush_para()
            blocks.append(("quote", line.lstrip("> ").strip()))
        else:
            para.append(line.strip())
    flush_para()
    flush_table()
    return blocks


# ---------------------------------------------------------------------------
# Word
# ---------------------------------------------------------------------------
def _runs(paragraph, text: str, size=None) -> None:
    from docx.shared import Pt

    for part in _INLINE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            run = paragraph.add_run(part[2:-2])
            run.bold = True
        elif part.startswith("`") and part.endswith("`"):
            run = paragraph.add_run(part[1:-1])
            run.font.name = "Consolas"
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            run = paragraph.add_run(part[1:-1])
            run.italic = True
        else:
            run = paragraph.add_run(part)
        if size:
            run.font.size = Pt(size)


def build_docx(sections: list[tuple[str, str | None, str]], out: Path, first_table: int, simulated: bool) -> dict:
    """sections: (título, markdown ou None se em falta, origem). Devolve contagens."""
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Pt

    doc = Document()
    normal = doc.styles["Normal"]
    normal.font.name = "Times New Roman"
    normal.font.size = Pt(12)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.5
    if simulated:
        for section in doc.sections:
            fp = section.footer.paragraphs[0]
            fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = fp.add_run(SIM_FOOTER)
            run.italic = True
            run.font.size = Pt(9)

    doc.add_heading("Capítulo 6 — Resultados", level=1)
    n_table, n_sec, missing = first_table, 0, []
    for title, md, origin in sections:
        n_sec += 1
        doc.add_heading(f"6.{n_sec} {title}", level=2)
        if md is None:
            p = doc.add_paragraph()
            _runs(p, f"*(por gerar: `{origin}`)*")
            missing.append(origin)
            continue
        n_sub, last_heading = 0, title
        for kind, value in parse_blocks(md):
            if kind == "h1":
                continue  # o título do resumo é substituído pelo da secção
            if kind in ("h2", "h3"):
                n_sub += 1 if kind == "h2" else 0
                text = _TABLE_PREFIX.sub("", value)  # o número da tabela fica só na legenda
                last_heading = re.sub(r"\s*\(.*?\)\s*$", "", text)
                doc.add_heading(f"6.{n_sec}.{n_sub} {text}" if kind == "h2" else text, level=3 if kind == "h2" else 4)
            elif kind == "p":
                _runs(doc.add_paragraph(), value)
            elif kind == "li":
                _runs(doc.add_paragraph(style="List Bullet"), value)
            elif kind == "quote":
                p = doc.add_paragraph()
                _runs(p, f"*{value}*" if not value.startswith("*") else value)
            elif kind == "table" and value:
                cap = doc.add_paragraph()
                cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                cap.paragraph_format.keep_with_next = True
                r = cap.add_run(f"Tabela {n_table} — ")
                r.bold = True
                r.font.size = Pt(11)
                r = cap.add_run(last_heading)
                r.font.size = Pt(11)
                n_table += 1
                width = max(len(row) for row in value)
                t = doc.add_table(rows=0, cols=width)
                t.style = "Table Grid"
                t.alignment = WD_TABLE_ALIGNMENT.CENTER
                for i, row in enumerate(value):
                    cells = t.add_row().cells
                    for j in range(width):
                        para = cells[j].paragraphs[0]
                        para.paragraph_format.line_spacing = 1.0
                        para.paragraph_format.space_after = Pt(2)
                        _runs(para, row[j] if j < len(row) else "", size=9)
                        if i == 0:
                            for run in para.runs:
                                run.bold = True
    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(out)
    return {"tables": n_table - first_table, "sections": n_sec, "missing": missing}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ensaio", default=None, help="Pasta de um ensaio técnico (ENSAIO_FICTICIO_* ou SIMULADO_*).")
    ap.add_argument("--first-table", type=int, default=13, help="Número da primeira tabela (default: 13).")
    ap.add_argument("--out", default=None, help="Ficheiro .docx de saída.")
    args = ap.parse_args(argv)
    try:
        import docx  # noqa: F401
    except ImportError:
        print("ERRO: falta o pacote python-docx. Instala com: .venv/bin/pip install -r requirements.txt")
        return 1

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.ensaio:
        folder = Path(args.ensaio)
        if not folder.is_dir():
            print(f"ERRO: {folder} não existe.")
            return 1
        simulated = is_simulated(folder)
        paths = [(title, folder / rel) for title, rel, _ in SOURCES]
        default_out = folder / (f"SIMULADO_Cap6_{stamp}.docx" if simulated else f"Cap6_resultados_{stamp}.docx")
    else:
        simulated = False
        paths = [(title, real) for title, _, real in SOURCES]
        default_out = HERE / "results" / f"Cap6_resultados_{stamp}.docx"
    out = Path(args.out) if args.out else default_out
    if simulated and not out.name.startswith("SIMULADO"):
        out = out.with_name("SIMULADO_" + out.name)

    sections = [(title, p.read_text(encoding="utf-8-sig") if p.is_file() else None, str(p)) for title, p in paths]
    if all(md is None for _, md, _ in sections):
        print("ERRO: nenhum resumo encontrado: " + ", ".join(str(p) for _, p in paths))
        return 1
    res = build_docx(sections, out, args.first_table, simulated)
    for m in res["missing"]:
        print(f"AVISO: resumo em falta (assinalado no documento): {m}")
    print(f"Escrito: {out} ({res['sections']} secções, {res['tables']} tabelas"
          + (", rodapé de dados simulados)" if simulated else ")"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
