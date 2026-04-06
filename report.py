"""
report.py — Geração de Relatórios Forenses e Cálculo de Hashes de Integridade

Este módulo é responsável por duas funções principais no contexto de uma
investigação forense digital com o DarkSherlock:

1. Cálculo de hashes SHA-256 para garantia de integridade dos dados recolhidos
   (cadeia de custódia digital — Chain of Custody).

2. Geração de relatórios forenses estruturados em formato PDF, adequados
   para anexar a relatórios de perícia ou dissertações de mestrado.

Dependências:
    - fpdf2 >= 2.8.0  (geração de PDF)
    - hashlib          (cálculo de SHA-256, incluído na biblioteca padrão)

Autores: tese de mestrado em Cibersegurança
"""

import hashlib
import textwrap
from datetime import datetime, timezone
from fpdf import FPDF


# ---------------------------------------------------------------------------
# Funções de Integridade (Hash SHA-256)
# ---------------------------------------------------------------------------

def compute_integrity_hashes(scraped: dict) -> dict:
    """
    Calcula hashes SHA-256 para garantia de integridade forense.

    Para cada URL scrapeada, calcula um hash individual do conteúdo.
    Adicionalmente, calcula um hash global determinístico que representa
    toda a investigação — calculado sobre a concatenação dos conteúdos
    ordenados por URL para garantir reprodutibilidade.

    Estes hashes permitem verificar posteriormente que os dados não foram
    alterados após a recolha (princípio de imutabilidade forense).

    Args:
        scraped: Dicionário {url: conteúdo_scrapeado} com o texto extraído
                 de cada fonte analisada.

    Returns:
        Dicionário com:
            - "overall_sha256": hash global de toda a investigação (str hex)
            - "sources": dicionário {url: sha256} com hash por fonte
            - "algorithm": nome do algoritmo utilizado ("SHA-256")
            - "computed_at_utc": timestamp UTC do momento do cálculo
    """
    source_hashes = {}

    # Calcular hash individual por fonte, codificando em UTF-8
    for url, content in scraped.items():
        source_hashes[url] = hashlib.sha256(
            content.encode("utf-8", errors="replace")
        ).hexdigest()

    # Hash global: concatenação dos conteúdos ordenados por URL
    # A ordenação garante que o hash é determinístico independentemente
    # da ordem de inserção no dicionário
    combined = "".join(
        content for _, content in sorted(scraped.items())
    )
    overall_hash = hashlib.sha256(
        combined.encode("utf-8", errors="replace")
    ).hexdigest()

    return {
        "overall_sha256": overall_hash,
        "sources": source_hashes,
        "algorithm": "SHA-256",
        "computed_at_utc": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Helpers internos do PDF
# ---------------------------------------------------------------------------

def _safe(text: str) -> str:
    """
    Sanitiza texto para compatibilidade com a codificação Latin-1 do fpdf2.

    Substitui caracteres Unicode fora do conjunto Latin-1 por equivalentes
    ASCII seguros. Necessário porque a fonte Helvetica integrada no fpdf2
    suporta apenas o conjunto de caracteres ISO-8859-1 (Latin-1), que cobre
    todos os caracteres do Português (Portugal) mas não alguns símbolos
    tipográficos modernos gerados por LLMs (travessão, aspas tipográficas, etc.).
    """
    replacements = {
        "\u2014": "--",   # travessão em
        "\u2013": "-",    # travessão en
        "\u2018": "'",    # aspa esquerda simples
        "\u2019": "'",    # aspa direita simples
        "\u201c": '"',    # aspa esquerda dupla
        "\u201d": '"',    # aspa direita dupla
        "\u2022": "*",    # bullet
        "\u2026": "...",  # reticências
        "\u00b7": "*",    # ponto médio
        "\u2192": "->",   # seta direita
        "\u2713": "[OK]", # visto
        "\u2717": "[X]",  # cruz
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    # Codificar para Latin-1, substituindo o que falhar por '?'
    return text.encode("latin-1", errors="replace").decode("latin-1")


class _ForensicPDF(FPDF):
    """
    Subclasse do FPDF com cabeçalho e rodapé personalizados para o DarkSherlock.

    O cabeçalho identifica o documento como um relatório de investigação OSINT.
    O rodapé inclui numeração de páginas e o timestamp de geração em UTC,
    elementos essenciais para documentação forense.
    """

    # Timestamp de geração gravado na instanciação para consistência
    _generated_at: str = ""

    def header(self):
        """Cabeçalho em todas as páginas excepto a capa (página 1)."""
        if self.page_no() == 1:
            return  # A capa tem o seu próprio layout
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(80, 80, 80)
        self.cell(0, 6, "DarkSherlock -- Relatorio de Investigacao OSINT", align="C")
        self.ln(2)
        self.set_draw_color(180, 180, 180)
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(4)
        self.set_text_color(0, 0, 0)

    def footer(self):
        """Rodapé com número de página e timestamp de geração."""
        self.set_y(-13)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(
            0, 8,
            f"Pagina {self.page_no()}/{{nb}}  |  Gerado em: {self._generated_at} UTC",
            align="C",
        )
        self.set_text_color(0, 0, 0)


# ---------------------------------------------------------------------------
# Geração do PDF Forense
# ---------------------------------------------------------------------------

def generate_forensic_pdf(data: dict) -> bytes:
    """
    Gera um relatório forense estruturado em formato PDF.

    O relatório segue uma estrutura adequada para documentação forense digital,
    incluindo metadados da investigação, cadeia de custódia com hashes SHA-256,
    lista de fontes analisadas, análise produzida pelo LLM e descrição da
    metodologia utilizada (pipeline de 6 etapas).

    Args:
        data: Dicionário com os seguintes campos:
            - audit_id (str): Identificador único da investigação (UUID4)
            - query (str): Query original do utilizador
            - refined_query (str): Query refinada pelo LLM
            - model (str): Modelo LLM utilizado
            - preset (str): Domínio de investigação (ex: "Dark Web Threat Intel")
            - timestamp_utc (str): Timestamp ISO 8601 UTC da investigação
            - active_engines (list[str]): Engines de pesquisa utilizadas
            - sources (list[dict]): Fontes filtradas (com title, link, opcionalmente
                                    retrieved_at_utc e scraped_at_utc)
            - integrity (dict): Resultado de compute_integrity_hashes()
            - summary (str): Análise gerada pelo LLM (Markdown)

    Returns:
        bytes: Conteúdo do ficheiro PDF pronto para download ou escrita em disco.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    pdf = _ForensicPDF()
    pdf._generated_at = now_utc
    pdf.alias_nb_pages()  # Permite usar {nb} no rodapé para total de páginas
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(left=15, top=15, right=15)

    # -----------------------------------------------------------------------
    # PÁGINA 1 — Capa
    # -----------------------------------------------------------------------
    pdf.add_page()

    # Bloco de título principal
    pdf.set_fill_color(20, 20, 40)
    pdf.rect(0, 0, pdf.w, 60, style="F")

    pdf.set_y(15)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 12, "DarkSherlock", align="C")
    pdf.ln(12)
    pdf.set_font("Helvetica", "", 13)
    pdf.cell(0, 8, "Relatorio de Investigacao OSINT", align="C")
    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 6, "Ferramenta OSINT para Investigacao Forense Digital", align="C")

    # Reset cor de texto
    pdf.set_text_color(0, 0, 0)
    pdf.set_y(75)

    # Caixa de identificação da investigação
    pdf.set_fill_color(245, 245, 250)
    pdf.set_draw_color(200, 200, 220)
    x, y = 20, pdf.get_y()
    pdf.rect(x, y, pdf.w - 40, 52, style="FD")

    pdf.set_xy(x + 4, y + 5)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 7, "Identificacao da Investigacao")
    pdf.ln(9)

    def _kv(label: str, value: str, indent: float = x + 4):
        """Imprime um par chave:valor na capa."""
        pdf.set_x(indent)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(45, 6, f"{label}:", border=0)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, _safe(str(value)[:80]), border=0)
        pdf.ln(7)

    _kv("ID da Investigacao", data.get("audit_id", "N/A"))
    _kv("Data / Hora (UTC)", data.get("timestamp_utc", now_utc)[:19].replace("T", " "))
    _kv("Query Original", data.get("query", ""))
    _kv("Dominio de Investigacao", data.get("preset", ""))
    _kv("Modelo LLM", data.get("model", ""))

    pdf.set_y(145)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(
        0, 5,
        "Este relatorio foi gerado automaticamente pelo DarkSherlock no ambito de uma investigacao "
        "forense digital autorizada. O conteudo destina-se exclusivamente a fins academicos e de "
        "investigacao em ciberseguranca.",
        align="C",
    )
    pdf.set_text_color(0, 0, 0)

    # -----------------------------------------------------------------------
    # PÁGINA 2 — Metadados e Cadeia de Custódia
    # -----------------------------------------------------------------------
    pdf.add_page()

    def _section_title(title: str):
        """Título de secção com fundo escuro."""
        pdf.set_fill_color(30, 30, 60)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, f"  {_safe(title)}", fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

    def _field(label: str, value: str):
        """Campo de metadados com label em negrito."""
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 9)
        label_w = 52
        pdf.cell(label_w, 6, f"{label}:", border=0)
        pdf.set_font("Helvetica", "", 9)
        # Calcular explicitamente a largura restante até à margem direita
        remaining_w = pdf.w - pdf.r_margin - pdf.get_x()
        pdf.multi_cell(remaining_w, 6, _safe(str(value)), border=0)

    # Secção 1 — Metadados
    _section_title("1. Metadados da Investigacao")
    _field("ID da Investigacao", data.get("audit_id", "N/A"))
    _field("Timestamp UTC", data.get("timestamp_utc", "")[:19].replace("T", " "))
    _field("Query Original", data.get("query", ""))
    _field("Query Refinada", data.get("refined_query", ""))
    _field("Modelo LLM", data.get("model", ""))
    _field("Dominio", data.get("preset", ""))

    engines = data.get("active_engines", [])
    _field("Engines Utilizadas", f"{len(engines)} engines: {', '.join(engines[:6])}" +
           ("..." if len(engines) > 6 else ""))

    sources = data.get("sources", [])
    _field("Fontes Encontradas", str(data.get("results_found", len(sources))))
    _field("Fontes Filtradas", str(len(sources)))
    _field("Fontes Scrapeadas", str(data.get("results_scraped", "")))

    pdf.ln(5)

    # Secção 2 — Cadeia de Custódia
    _section_title("2. Cadeia de Custodia Digital")

    integrity = data.get("integrity", {})
    overall = integrity.get("overall_sha256", "N/A")
    algo = integrity.get("algorithm", "SHA-256")
    computed = integrity.get("computed_at_utc", "")[:19].replace("T", " ")

    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(
        0, 5,
        "Os hashes SHA-256 abaixo garantem a integridade dos dados recolhidos. "
        "Qualquer alteracao ao conteudo apos a recolha resultara num hash diferente, "
        "invalidando a cadeia de custodia.",
    )
    pdf.ln(3)

    _field("Algoritmo", algo)
    _field("Calculado em (UTC)", computed)

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 6, "Hash Global da Investigacao (SHA-256):")
    pdf.ln(6)
    pdf.set_fill_color(240, 240, 245)
    pdf.set_font("Courier", "", 8)
    pdf.cell(0, 7, f"  {overall}", fill=True)
    pdf.ln(8)

    # Tabela de hashes por fonte
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 6, "Hashes por Fonte:")
    pdf.ln(5)

    source_hashes = integrity.get("sources", {})
    pdf.set_font("Courier", "", 7)
    pdf.set_fill_color(248, 248, 252)

    for url, sha in list(source_hashes.items())[:15]:  # Limitar a 15 para não exceder página
        # URL truncada para caber na linha
        short_url = (url[:55] + "...") if len(url) > 58 else url
        pdf.set_fill_color(248, 248, 252)
        pdf.cell(0, 5, f"  {_safe(short_url)}", fill=True, border=0)
        pdf.ln(5)
        pdf.set_x(15)
        pdf.set_fill_color(240, 245, 240)
        pdf.cell(0, 5, f"    SHA-256: {sha}", fill=True, border=0)
        pdf.ln(6)

    # -----------------------------------------------------------------------
    # PÁGINA — Fontes Analisadas
    # -----------------------------------------------------------------------
    pdf.add_page()
    _section_title("3. Fontes Analisadas")

    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, f"Total de fontes analisadas: {len(sources)}")
    pdf.ln(7)

    for i, item in enumerate(sources, 1):
        title = _safe(item.get("title", "Sem titulo")[:70])
        link = item.get("link", "")
        retrieved = item.get("retrieved_at_utc", "")[:19].replace("T", " ")
        scraped = item.get("scraped_at_utc", "")[:19].replace("T", " ")
        src_hash = source_hashes.get(link, "N/A")

        # Número e título
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(8, 6, f"{i}.", border=0)
        pdf.set_font("Helvetica", "B", 9)
        pdf.multi_cell(0, 6, title, border=0)

        # URL como código
        pdf.set_font("Courier", "", 7)
        pdf.set_fill_color(245, 245, 250)
        short_link = (_safe(link[:75]) + "...") if len(link) > 78 else _safe(link)
        pdf.cell(0, 5, f"  URL: {short_link}", fill=True)
        pdf.ln(5)

        # Timestamps
        if retrieved or scraped:
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(100, 100, 100)
            ts_line = []
            if retrieved:
                ts_line.append(f"Recolhido: {retrieved} UTC")
            if scraped:
                ts_line.append(f"Scrapeado: {scraped} UTC")
            pdf.cell(0, 5, "  " + "  |  ".join(ts_line))
            pdf.ln(5)
            pdf.set_text_color(0, 0, 0)

        # Hash da fonte
        if src_hash != "N/A":
            pdf.set_font("Courier", "", 7)
            pdf.set_fill_color(240, 248, 240)
            pdf.cell(0, 5, f"  SHA-256: {src_hash}", fill=True)
            pdf.ln(5)

        pdf.ln(3)

    # -----------------------------------------------------------------------
    # PÁGINA — Análise (Findings)
    # -----------------------------------------------------------------------
    pdf.add_page()
    _section_title("4. Analise e Conclusoes")

    summary_raw = data.get("summary", "Sem analise disponivel.")

    # Remover markdown pesado (asteriscos, #, etc.) para o PDF
    summary_clean = summary_raw
    for md_char in ["**", "__", "##", "###", "# "]:
        summary_clean = summary_clean.replace(md_char, "")

    pdf.set_font("Helvetica", "", 9)
    # Dividir em parágrafos para evitar overflow
    paragraphs = summary_clean.split("\n")
    for para in paragraphs:
        para = para.strip()
        if not para:
            pdf.ln(3)
            continue
        # Linhas que parecem títulos (curtas e sem ponto final)
        if len(para) < 60 and not para.endswith(".") and para.endswith(":"):
            pdf.set_font("Helvetica", "B", 9)
            pdf.multi_cell(0, 6, _safe(para))
            pdf.set_font("Helvetica", "", 9)
        else:
            pdf.multi_cell(0, 6, _safe(para))
        pdf.ln(1)

    # -----------------------------------------------------------------------
    # PÁGINA — Metodologia
    # -----------------------------------------------------------------------
    pdf.add_page()
    _section_title("5. Metodologia — Pipeline de Investigacao")

    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(
        0, 6,
        "O DarkSherlock executa um pipeline automatizado de 6 etapas para cada investigacao. "
        "Cada etapa e executada sequencialmente, com os resultados de cada fase a alimentar a seguinte. "
        "O pipeline e desenhado para maximizar a qualidade e relevancia dos resultados obtidos.",
    )
    pdf.ln(5)

    etapas = [
        (
            "Etapa 1 — Carregamento do Modelo LLM",
            "Inicializacao do modelo de linguagem selecionado (local via Ollama ou remoto via API). "
            "O modelo e usado nas etapas 2, 4 e 6 para processamento de linguagem natural.",
        ),
        (
            "Etapa 2 — Refinamento da Query",
            "A query original do utilizador e refinada pelo LLM para otimizar os resultados "
            "nas dark web search engines. O refinamento e sensivel ao dominio de investigacao "
            "selecionado (threat intel, ransomware, identidade, espionagem).",
        ),
        (
            "Etapa 3 — Pesquisa nas Dark Web Engines",
            "A query refinada e enviada em paralelo a todas as engines de pesquisa ativas, "
            "atraves do proxy SOCKS5h do Tor (porta 9050). Os resultados sao deduplicados "
            "por URL e estampados com timestamp UTC.",
        ),
        (
            "Etapa 4 — Filtragem por Relevancia (LLM)",
            "O LLM analisa os titulos e URLs dos resultados e seleciona os mais relevantes "
            "para a query de investigacao, descartando resultados genericos ou irrelevantes.",
        ),
        (
            "Etapa 5 — Recolha de Conteudo (Scraping)",
            "As paginas filtradas sao acedidas individualmente atraves do Tor. O conteudo HTML "
            "e extraido, limpo (remocao de scripts e estilos) e truncado a 2000 caracteres por fonte. "
            "Paginas inacessiveis (login walls, timeouts) sao removidas automaticamente. "
            "Cada fonte recebe um hash SHA-256 para garantia de integridade.",
        ),
        (
            "Etapa 6 — Geracao de Sumario de Inteligencia (LLM)",
            "O LLM analisa o conteudo recolhido e gera um relatorio de inteligencia estruturado "
            "em Portugues (Portugal), identificando IOCs, TTPs, threat actors e recomendacoes. "
            "A resposta e limitada a 12.000 caracteres de contexto e 600 palavras de output.",
        ),
    ]

    for titulo, descricao in etapas:
        pdf.set_fill_color(230, 230, 245)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 7, f"  {_safe(titulo)}", fill=True)
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 6, _safe(descricao))
        pdf.ln(5)

    pdf.ln(3)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(
        0, 5,
        "Nota: Toda a comunicacao de rede e efetuada atraves da rede Tor para preservar "
        "o anonimato do investigador e aceder a servicos .onion. O modelo LLM pode ser "
        "executado localmente (sem envio de dados para terceiros) ou via API remota.",
    )
    pdf.set_text_color(0, 0, 0)

    # Retornar bytes do PDF
    return bytes(pdf.output())
