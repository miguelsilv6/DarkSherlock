"""
theme.py — DarkSherlock Design System (runtime CSS + components).

Este módulo centraliza o *DarkSherlock Design System* (DSDS): tokens de cor,
tipografia mono, espaçamentos, raios, glows e motion. Antes desta consolidação,
cada página Streamlit repetia em-linha o seu próprio bloco <style>, o que
levava à inevitável deriva visual entre páginas e duplicação de regras.

Uso em qualquer página:

    from theme import apply_theme, render_metrics, render_chip
    apply_theme()
    ...
    render_metrics(refined="ransomware leak", results=224, filtered=20)
    render_chip("ahmia", status="up")        # verde
    render_chip("darksearch", status="down") # vermelho
    render_chip("onionland", status="idle")  # cinzento

Fonte do design system:
    darksherlock-design-system/project/colors_and_type.css
    darksherlock-design-system/project/README.md (secção 4 — Visual foundations)

Princípios preservados:
    - JetBrains Mono em TODO o produto (sem fallback sans-serif).
    - Flat + glow: zero gradientes, zero sombras materiais, só glows neon.
    - Paleta estrita dark + verde-neon + semântica; o roxo/cyan da mascote
      é reservado a contexto ilustrativo.
    - Radii: 4px (inputs/botões/pills) · 6px (status/expanders) · 8px (cards).
    - Motion: 0.2–0.25s ease; animar apenas border-color / box-shadow / color.
"""

import streamlit as st


# ---------------------------------------------------------------------------
# Design tokens — copiados de colors_and_type.css do bundle de handoff.
# Qualquer alteração a estes valores deve ser espelhada em .streamlit/config.toml
# (backgroundColor, secondaryBackgroundColor, primaryColor, textColor).
# ---------------------------------------------------------------------------
_DESIGN_TOKENS_CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
    /* Core palette */
    --ds-bg:              #0a0a0f;
    --ds-bg-elev:         #111118;
    --ds-bg-input:        #0d0d14;
    --ds-bg-container:    #0d0d18;

    /* Primary — neon green */
    --ds-primary:         #00ff9f;
    --ds-primary-dim:     #a0f0c8;
    --ds-primary-muted:   #7a9e8e;
    --ds-primary-hover:   #c0ffe0;

    /* Alpha variants on neon green */
    --ds-primary-a08:     rgba(0, 255, 159, 0.05);
    --ds-primary-a13:     rgba(0, 255, 159, 0.08);
    --ds-primary-a14:     rgba(0, 255, 159, 0.08);
    --ds-primary-a18:     rgba(0, 255, 159, 0.09);
    --ds-primary-a1a:     rgba(0, 255, 159, 0.10);
    --ds-primary-a22:     rgba(0, 255, 159, 0.13);
    --ds-primary-a2a:     rgba(0, 255, 159, 0.16);
    --ds-primary-a33:     rgba(0, 255, 159, 0.20);
    --ds-primary-a44:     rgba(0, 255, 159, 0.27);
    --ds-primary-a55:     rgba(0, 255, 159, 0.33);
    --ds-primary-a88:     rgba(0, 255, 159, 0.53);

    /* Soft green alpha (secondary button border) */
    --ds-soft-a33:        rgba(160, 240, 200, 0.20);

    /* Semantic tinted fills (alert backgrounds — see colors_and_type.css) */
    --ds-warning-a0c:     rgba(255, 204, 0, 0.06);
    --ds-error-a0c:       rgba(255, 68, 68, 0.06);
    --ds-info-border-a40: rgba(160, 240, 200, 0.40);

    /* Text */
    --ds-text:            #e2e8f0;
    --ds-text-muted:      #a0f0c8;
    --ds-text-dim:        #7a9e8e;

    /* Semantic */
    --ds-warning:         #ffcc00;
    --ds-error:           #ff4444;
    --ds-success:         #00ff9f;

    /* Brand accents (logo only, NEVER use in chrome) */
    --ds-brand-purple:    #6b2a8a;
    --ds-brand-purple-lt: #a06bc2;
    --ds-brand-cyan:      #2ec3ff;
    --ds-brand-bone:      #f5f5f0;

    /* Placeholder colour for text inputs (mono-green desaturated) */
    --ds-placeholder: #4a6b5a;

    /* Type */
    --ds-font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace,
                    'SFMono-Regular', Menlo, Consolas, monospace;
    --ds-font-body: var(--ds-font-mono);

    --ds-fs-h1:      1.55rem;
    --ds-fs-h2:      1.25rem;
    --ds-fs-h3:      1.05rem;
    --ds-fs-body:    1rem;
    --ds-fs-sm:      0.875rem;
    --ds-fs-xs:      0.75rem;

    --ds-lh-tight:   1.2;
    --ds-lh-body:    1.55;
    --ds-lh-loose:   1.7;

    --ds-fw-regular: 400;
    --ds-fw-medium:  500;
    --ds-fw-semi:    600;
    --ds-fw-bold:    700;

    --ds-tracking-h1:    0.12em;
    --ds-tracking-h2:    0.06em;
    --ds-tracking-pill:  0.04em;

    /* Spacing (4/8/16/24 step — full scale from colors_and_type.css) */
    --ds-space-0: 0;
    --ds-space-1: 4px;
    --ds-space-2: 8px;
    --ds-space-3: 12px;
    --ds-space-4: 16px;
    --ds-space-5: 24px;
    --ds-space-6: 32px;
    --ds-space-7: 48px;
    --ds-space-8: 64px;

    /* Radii */
    --ds-radius-sm:   4px;
    --ds-radius-md:   6px;
    --ds-radius-lg:   8px;
    --ds-radius-pill: 999px;

    /* Border tokens (mirror colors_and_type.css so that future custom
       components can reach for a single named border rather than rebuild
       the rgba string each time) */
    --ds-border-hairline: 1px solid var(--ds-primary-a22);
    --ds-border-subtle:   1px solid var(--ds-primary-a33);
    --ds-border-active:   1px solid var(--ds-primary);
    --ds-border-warning:  3px solid var(--ds-warning);
    --ds-border-error:    3px solid var(--ds-error);

    /* Glows */
    --ds-glow-sm:     0 0 8px var(--ds-primary-a44);
    --ds-glow-md:     0 0 10px var(--ds-primary-a55);
    --ds-glow-lg:     0 0 14px var(--ds-primary-a55);
    --ds-glow-focus:  0 0 0 1px var(--ds-primary), 0 0 14px var(--ds-primary-a55);

    /* Motion */
    --ds-ease:      cubic-bezier(0.2, 0.8, 0.2, 1);
    --ds-dur-fast:  0.15s;
    --ds-dur-base:  0.2s;
    --ds-dur-slow:  0.25s;
}
"""


# ---------------------------------------------------------------------------
# Component CSS — traduz as regras do DS para os selectores internos Streamlit.
# Aplica-se globalmente a TODAS as páginas da app quando `apply_theme()` é chamada.
# ---------------------------------------------------------------------------
_COMPONENT_CSS = """
/* Tipografia — mono em tudo. O Streamlit injecta sans-serif por omissão. */
html, body, [class*="css"] {
    font-family: var(--ds-font-mono) !important;
}

/* H1 — uppercase, tracked-out, neon green, com hairline verde a separar */
h1 {
    font-size: var(--ds-fs-h1) !important;
    font-weight: var(--ds-fw-bold) !important;
    letter-spacing: var(--ds-tracking-h1) !important;
    text-transform: uppercase !important;
    color: var(--ds-primary) !important;
    border-bottom: 1px solid var(--ds-primary-a33) !important;
    padding-bottom: 0.4rem !important;
    margin-bottom: 1.4rem !important;
}
h2, h3 {
    letter-spacing: var(--ds-tracking-h2);
    color: var(--ds-text-muted);
}

/* Text input — glow verde no focus */
input[type="text"] {
    background-color: var(--ds-bg-input) !important;
    border: 1px solid var(--ds-primary-a55) !important;
    border-radius: var(--ds-radius-sm) !important;
    color: var(--ds-text) !important;
    caret-color: var(--ds-primary) !important;
    font-family: inherit !important;
    transition: border-color var(--ds-dur-slow) var(--ds-ease),
                box-shadow var(--ds-dur-slow) var(--ds-ease) !important;
}
input[type="text"]:focus {
    border-color: var(--ds-primary) !important;
    box-shadow: var(--ds-glow-focus) !important;
    outline: none !important;
}
input[type="text"]::placeholder,
textarea::placeholder {
    color: var(--ds-placeholder) !important;
    opacity: 1 !important;
}

/* Textareas — herdam o estilo dos inputs mas precisam de altura livre */
textarea {
    background-color: var(--ds-bg-input) !important;
    border: 1px solid var(--ds-primary-a55) !important;
    border-radius: var(--ds-radius-sm) !important;
    color: var(--ds-text) !important;
    caret-color: var(--ds-primary) !important;
    font-family: inherit !important;
    transition: border-color var(--ds-dur-slow) var(--ds-ease),
                box-shadow var(--ds-dur-slow) var(--ds-ease) !important;
}
textarea:focus {
    border-color: var(--ds-primary) !important;
    box-shadow: var(--ds-glow-focus) !important;
    outline: none !important;
}

/* Primary buttons — α14 fill, solid neon border, glow on hover */
button[kind="primaryFormSubmit"],
button[data-testid="baseButton-primary"],
.stButton > button[kind="primary"] {
    background-color: var(--ds-primary-a14) !important;
    color: var(--ds-primary) !important;
    border: 1px solid var(--ds-primary) !important;
    border-radius: var(--ds-radius-sm) !important;
    font-weight: var(--ds-fw-semi) !important;
    transition: background-color var(--ds-dur-base) var(--ds-ease),
                box-shadow var(--ds-dur-base) var(--ds-ease) !important;
}
button[kind="primaryFormSubmit"]:hover,
button[data-testid="baseButton-primary"]:hover,
.stButton > button[kind="primary"]:hover {
    background-color: var(--ds-primary-a2a) !important;
    box-shadow: var(--ds-glow-md) !important;
}

/* Secondary buttons — transparente, dim-green → neon no hover */
.stButton > button, .stDownloadButton > button {
    background-color: transparent !important;
    color: var(--ds-primary-dim) !important;
    border: 1px solid var(--ds-soft-a33) !important;
    border-radius: var(--ds-radius-sm) !important;
    transition: border-color var(--ds-dur-base) var(--ds-ease),
                color var(--ds-dur-base) var(--ds-ease) !important;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    border-color: var(--ds-primary) !important;
    color: var(--ds-primary) !important;
}

/* Status widgets + expanders — hairline verde, bg ligeiramente elevado */
[data-testid="stStatusWidget"],
div[data-testid="stExpander"] {
    border: 1px solid var(--ds-primary-a22) !important;
    border-radius: var(--ds-radius-md) !important;
    background-color: var(--ds-bg-container) !important;
}

/* Pills do selector de preset */
div[data-testid="stPillsButton"] button {
    background-color: var(--ds-bg-container) !important;
    border: 1px solid var(--ds-primary-a33) !important;
    color: var(--ds-primary-muted) !important;
    border-radius: var(--ds-radius-sm) !important;
    font-weight: var(--ds-fw-medium) !important;
    letter-spacing: var(--ds-tracking-pill) !important;
    transition: all var(--ds-dur-base) var(--ds-ease) !important;
}
div[data-testid="stPillsButton"] button[aria-checked="true"] {
    background-color: var(--ds-primary-a18) !important;
    border-color: var(--ds-primary) !important;
    color: var(--ds-primary) !important;
    box-shadow: var(--ds-glow-sm) !important;
}
div[data-testid="stPillsButton"] button:hover {
    border-color: var(--ds-primary-a88) !important;
    color: var(--ds-primary-hover) !important;
}

/* Sidebar — borda direita subtil em verde */
[data-testid="stSidebar"] {
    border-right: 1px solid var(--ds-primary-a1a) !important;
}

/* Alertas — barra lateral esquerda por estado semântico + fundo tingido
   muito subtil (5–6% alpha), como prescrito em preview/components-alerts.html */
[data-testid="stAlertContainer"][kind="success"] {
    border-left: 3px solid var(--ds-success) !important;
    background-color: var(--ds-primary-a08) !important;
}
[data-testid="stAlertContainer"][kind="warning"] {
    border-left: 3px solid var(--ds-warning) !important;
    background-color: var(--ds-warning-a0c) !important;
}
[data-testid="stAlertContainer"][kind="error"] {
    border-left: 3px solid var(--ds-error) !important;
    background-color: var(--ds-error-a0c) !important;
}
[data-testid="stAlertContainer"][kind="info"] {
    border-left: 3px solid var(--ds-info-border-a40) !important;
    background-color: rgba(0, 255, 159, 0.03) !important;
}

/* Links de download em estilo legacy usados em algumas páginas */
.aStyle {
    font-size: 18px; font-weight: bold;
    padding: 5px; padding-left: 0px;
    text-align: left; color: var(--ds-primary);
}

/* -------------------------------------------------
 * Metric cards (3-up grid) — o único componente custom
 * do DS que precisa de CSS próprio além do chrome Streamlit.
 * ------------------------------------------------- */
.ds-metrics-row {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
    margin: var(--ds-space-5) 0 var(--ds-space-4);
}
.ds-metric-card {
    background: var(--ds-bg-container);
    border: 1px solid var(--ds-primary-a33);
    border-radius: var(--ds-radius-md);
    padding: 14px;
    text-align: center;
    transition: border-color var(--ds-dur-base) var(--ds-ease),
                box-shadow var(--ds-dur-base) var(--ds-ease);
}
.ds-metric-card:hover {
    border-color: var(--ds-primary-a88);
    box-shadow: var(--ds-glow-sm);
}
.ds-metric-card .lbl {
    font-size: 11px;
    color: var(--ds-error);
    font-weight: var(--ds-fw-bold);
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-bottom: 6px;
}
.ds-metric-card .val {
    font-size: 20px;
    font-weight: var(--ds-fw-bold);
    color: var(--ds-text);
    font-family: var(--ds-font-mono);
}
.ds-metric-card .small {
    font-size: 11px;
    color: var(--ds-primary);
    margin-top: 4px;
    font-family: var(--ds-font-mono);
    word-break: break-word;
    line-height: var(--ds-lh-tight);
}

/* -------------------------------------------------
 * Status chips (engine up/down/idle indicators)
 * Derivado de preview/components-chips.html. Usa-se como:
 *   <span class="ds-chip ds-chip--up">● ahmia</span>
 * ------------------------------------------------- */
.ds-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    font-size: 11px;
    border-radius: var(--ds-radius-pill);
    margin-right: 6px;
    letter-spacing: var(--ds-tracking-pill);
    font-family: var(--ds-font-mono);
}
.ds-chip--up {
    background: var(--ds-primary-a13);
    color: var(--ds-primary);
    border: 1px solid var(--ds-primary-a55);
}
.ds-chip--down {
    background: rgba(255, 68, 68, 0.08);
    color: var(--ds-error);
    border: 1px solid rgba(255, 68, 68, 0.33);
}
.ds-chip--idle {
    background: transparent;
    color: var(--ds-text-dim);
    border: 1px solid rgba(122, 158, 142, 0.30);
}

/* -------------------------------------------------
 * Stage strip (pipeline step indicators — HITL reruns)
 * Derivado de preview/components-stages.html. Espelha o
 * _show_completed() inline e permite um visual mais
 * próximo do preview para o indicador "✓ Stage N — done"
 * quando se quiser HTML em vez de st.success.
 * ------------------------------------------------- */
.ds-stage {
    background: var(--ds-bg-container);
    border: var(--ds-border-hairline);
    border-radius: var(--ds-radius-md);
    padding: 10px 14px;
    margin-bottom: 8px;
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-family: var(--ds-font-mono);
}
.ds-stage b { color: var(--ds-text); font-weight: var(--ds-fw-semi); }
.ds-stage .ds-stage-tick { color: var(--ds-primary); font-weight: var(--ds-fw-semi); }
.ds-stage .ds-stage-time {
    margin-left: auto;
    font-size: 11px;
    color: var(--ds-text-dim);
    letter-spacing: 0.04em;
}
.ds-stage--pending b,
.ds-stage--pending .ds-stage-tick { color: var(--ds-text-dim); }

/* -------------------------------------------------
 * Inline code token (`llama3.2:latest`, `audit_id`, etc.)
 * Streamlit's native `st.code` is for blocks — for inline
 * we use markdown backticks, which render as <code> and
 * are targeted by the global `code` rule below.
 * ------------------------------------------------- */
code, .ds-code {
    font-family: var(--ds-font-mono) !important;
    color: var(--ds-primary) !important;
    background: var(--ds-bg-input) !important;
    padding: 2px 6px !important;
    border-radius: 3px !important;
    font-size: 0.95em !important;
}

/* -------------------------------------------------
 * Brand lockup — glifo SVG (terminal brackets + lupa)
 * + wordmark "Dark**Sherlock**" + caret a piscar + tagline
 * "AI · DARK WEB · OSINT". Tradução directa de
 * preview/brand-logo.html para consumo dentro do Streamlit.
 * ------------------------------------------------- */
.ds-lockup {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 18px;
    padding: 18px 24px;
    box-sizing: border-box;
}
.ds-lockup-mark {
    width: 74px;
    height: 74px;
    position: relative;
    flex-shrink: 0;
}
.ds-lockup-mark svg { width: 100%; height: 100%; display: block; }
.ds-lockup-wordmark {
    display: flex;
    flex-direction: column;
    gap: 4px;
}
.ds-lockup-brand {
    font-family: var(--ds-font-mono);
    font-weight: var(--ds-fw-bold);
    font-size: 30px;
    letter-spacing: 0.02em;
    line-height: 1;
    color: var(--ds-text);
    display: flex;
    align-items: baseline;
}
.ds-lockup-brand .ds-lockup-dark     { color: var(--ds-text); }
.ds-lockup-brand .ds-lockup-sherlock {
    color: var(--ds-primary);
    text-shadow: 0 0 10px rgba(0, 255, 159, 0.35);
}
.ds-lockup-brand .ds-lockup-caret {
    display: inline-block;
    width: 11px;
    height: 22px;
    background: var(--ds-primary);
    margin-left: 6px;
    box-shadow: 0 0 10px rgba(0, 255, 159, 0.55);
    animation: ds-lockup-blink 1.1s steps(2, end) infinite;
    transform: translateY(2px);
}
@keyframes ds-lockup-blink { 50% { opacity: 0; } }
.ds-lockup-tag {
    font-size: 10px;
    letter-spacing: 0.28em;
    color: var(--ds-text-dim);
    text-transform: uppercase;
    padding-top: 2px;
}
"""


def apply_theme() -> None:
    """Injecta o DarkSherlock Design System no documento Streamlit.

    Chame-o **uma vez** perto do topo de cada página, depois de
    `st.set_page_config(...)`. Substitui os blocos inline <style> que
    estavam anteriormente duplicados por Home.py e pelas sub-páginas.

    Idempotente dentro de um render — chamar duas vezes duplica o <style>
    mas não tem efeito visível. Evite-o assim mesmo para não poluir o DOM.
    """
    st.markdown(
        f"<style>{_DESIGN_TOKENS_CSS}{_COMPONENT_CSS}</style>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Componentes de UI reutilizáveis
# ---------------------------------------------------------------------------

def render_metrics(refined: str, results: int, filtered: int) -> None:
    """Renderiza o componente "3-up metric cards" do design system.

    É a grelha 1×3 que o README do design system descreve como "notable
    exception" à regra de coluna única: aparece abaixo do pipeline e
    sintetiza o estado da investigação com:

      [ Refined Query | Search Results | Filtered Results ]

    Cada cartão tem um *label* vermelho a caixa alta (indicador forense) e
    um valor central em branco. O primeiro cartão usa a variante *small*
    (texto verde, word-wrap) porque o refined é uma string, não um número.

    Args:
        refined:  Consulta refinada pelo LLM (string curta).
        results:  Número de resultados encontrados pelos motores (Stage 3).
        filtered: Número de resultados após filtragem LLM (Stage 4).
    """
    # Trunca o refined para evitar que esticasse o layout numa query muito longa.
    display_refined = refined if len(refined) <= 80 else refined[:77] + "…"
    # Escape básico para o HTML do cartão.
    display_refined = (
        display_refined.replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;")
    )
    st.markdown(
        f"""
        <div class="ds-metrics-row">
          <div class="ds-metric-card">
            <div class="lbl">Refined Query</div>
            <div class="small">{display_refined}</div>
          </div>
          <div class="ds-metric-card">
            <div class="lbl">Search Results</div>
            <div class="val">{results}</div>
          </div>
          <div class="ds-metric-card">
            <div class="lbl">Filtered Results</div>
            <div class="val">{filtered}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_chip(label: str, status: str = "up") -> None:
    """Renderiza um chip de estado (engine status, role tag, etc.).

    Chips são pequenas etiquetas arredondadas com 3 estados semânticos,
    directamente traduzidos de `preview/components-chips.html`:

      - ``up``   — verde neon, usado para motores online
      - ``down`` — vermelho, usado para falhas / offline
      - ``idle`` — cinzento neutro, usado para inactivos

    Args:
        label:  Texto a apresentar no chip (ex.: nome do motor).
        status: Um de ``"up" | "down" | "idle"``. Valor inválido
            faz fallback para ``"idle"``.
    """
    _variant = {
        "up": "ds-chip--up",
        "down": "ds-chip--down",
        "idle": "ds-chip--idle",
    }.get(status, "ds-chip--idle")
    # O bullet indica estado: ● para up/down, ○ para idle — combina com os
    # emojis tradicionais do Streamlit (🟢/🔴) mas com o visual DS.
    _bullet = "○" if status == "idle" else "●"
    # Escape básico do label para evitar que nomes com < > partam o HTML.
    safe = (
        label.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
    )
    st.markdown(
        f'<span class="ds-chip {_variant}">{_bullet} {safe}</span>',
        unsafe_allow_html=True,
    )


def render_brand_lockup() -> None:
    """Renderiza o brand lockup canónico do DarkSherlock.

    Tradução directa de ``preview/brand-logo.html`` do design system para
    consumo dentro do Streamlit. O lockup é composto por:

      1. **Glifo SVG** — "forensic-magnifier-meets-terminal": dois ângulos
         `<` e `>` a envolver uma lupa com crosshair, desenhados a traço
         verde neon com filtro de *glow* gaussiano.
      2. **Wordmark** — "Dark" em branco-azulado + "Sherlock" em verde
         neon com text-shadow + um bloco verde a piscar (caret) a simular
         prompt de terminal.
      3. **Tag** — "AI · DARK WEB · OSINT" em caixa alta e tracking 0.28em.

    Todo o CSS necessário vive em ``_COMPONENT_CSS`` — esta função apenas
    emite o HTML. Chamar após ``apply_theme()``.

    Não recebe argumentos: o lockup é uma peça de identidade, não
    parametrizada. Se no futuro for preciso um glifo isolado ou um
    wordmark isolado, adicione-se uma segunda função — **não** se
    introduza um flag opcional que deturpe o lockup canónico.
    """
    st.markdown(
        """
        <div class="ds-lockup">
          <div class="ds-lockup-mark" aria-label="DarkSherlock glyph">
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <filter id="ds-lockup-glow" x="-30%" y="-30%" width="160%" height="160%">
                  <feGaussianBlur stdDeviation="1.4" result="b"/>
                  <feMerge>
                    <feMergeNode in="b"/>
                    <feMergeNode in="SourceGraphic"/>
                  </feMerge>
                </filter>
              </defs>
              <g fill="none" stroke="#00ff9f" stroke-width="3"
                 stroke-linecap="square" stroke-linejoin="miter"
                 filter="url(#ds-lockup-glow)">
                <polyline points="20,14 8,50 20,86"/>
                <polyline points="80,14 92,50 80,86"/>
                <circle cx="42" cy="46" r="20" stroke-width="3.5"/>
                <line x1="42" y1="32" x2="42" y2="60" stroke-width="1.5"/>
                <line x1="28" y1="46" x2="56" y2="46" stroke-width="1.5"/>
                <line x1="57" y1="61" x2="74" y2="78" stroke-width="5"/>
              </g>
              <circle cx="42" cy="46" r="18" fill="#0a0a0f" opacity="0.4"/>
            </svg>
          </div>
          <div class="ds-lockup-wordmark">
            <div class="ds-lockup-brand">
              <span class="ds-lockup-dark">Dark</span><span class="ds-lockup-sherlock">Sherlock</span><span class="ds-lockup-caret"></span>
            </div>
            <div class="ds-lockup-tag">AI · DARK WEB · OSINT</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
