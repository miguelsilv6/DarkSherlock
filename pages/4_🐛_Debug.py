"""
4_🐛_Debug.py — Página de Diagnóstico e Logs do DarkSherlock.

Esta página centraliza toda a informação de diagnóstico gerada durante a
execução da ferramenta, permitindo ao investigador ou programador:

  - Consultar o histórico de investigações no log de auditoria estruturado
    (logs/audit.jsonl): cada entrada regista os parâmetros, métricas e
    duração de uma execução completa do pipeline.

  - Consultar o log aplicacional em texto livre (logs/app.log): captura todas
    as mensagens de logging emitidas pelos módulos da aplicação (scraping,
    pesquisa, erros de rede, etc.) através do sistema standard `logging`.

  - Limpar os ficheiros de log quando necessário (ex.: entre investigações
    para reduzir ruído, ou para iniciar um novo registo limpo).

Contexto académico: Dissertação de Mestrado em Cibersegurança — ferramenta
OSINT para monitorização da dark web.
"""

import json
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

from audit import load_audit_log, setup_file_logging
from sidebar import render_sidebar

# Configura logging para ficheiro nesta página também
setup_file_logging()

st.set_page_config(
    page_title="DarkSherlock — Debug",
    page_icon="🐛",
    initial_sidebar_state="expanded",
)

render_sidebar()

# Caminhos dos ficheiros de log
_LOG_DIR = Path("logs")
_AUDIT_LOG = _LOG_DIR / "audit.jsonl"
_APP_LOG = _LOG_DIR / "app.log"

# ---------------------------------------------------------------------------
# Cabeçalho da página
# ---------------------------------------------------------------------------

st.title("Debug & Logs")
st.caption("Diagnóstico em tempo real — logs de auditoria e aplicação")

# ---------------------------------------------------------------------------
# Barra de acções — botões de limpeza e atualização
# ---------------------------------------------------------------------------

col_refresh, col_clear_app, col_clear_audit, col_clear_all = st.columns(4)

with col_refresh:
    refresh = st.button("🔄 Atualizar", use_container_width=True,
                        help="Recarrega os ficheiros de log do disco")

with col_clear_app:
    if st.button("🗑 Limpar App Log", use_container_width=True,
                 help="Apaga o conteúdo de logs/app.log"):
        if _APP_LOG.exists():
            _APP_LOG.write_text("", encoding="utf-8")
        st.success("logs/app.log limpo.")
        time.sleep(0.5)
        st.rerun()

with col_clear_audit:
    if st.button("🗑 Limpar Audit Log", use_container_width=True,
                 help="Apaga o conteúdo de logs/audit.jsonl"):
        if _AUDIT_LOG.exists():
            _AUDIT_LOG.write_text("", encoding="utf-8")
        st.success("logs/audit.jsonl limpo.")
        time.sleep(0.5)
        st.rerun()

with col_clear_all:
    if st.button("💣 Limpar Tudo", use_container_width=True,
                 help="Apaga todos os ficheiros de log"):
        for log_file in [_APP_LOG, _AUDIT_LOG]:
            if log_file.exists():
                log_file.write_text("", encoding="utf-8")
        st.success("Todos os logs limpos.")
        time.sleep(0.5)
        st.rerun()

st.divider()

# ---------------------------------------------------------------------------
# Secção 1 — Log de Auditoria (investigações executadas)
# ---------------------------------------------------------------------------

st.subheader("Audit Log — Investigações Executadas")

audit_entries = load_audit_log()

if not audit_entries:
    st.info("Sem investigações registadas ainda. Execute um pipeline para gerar entradas.")
else:
    st.caption(f"{len(audit_entries)} investigações registadas")

    # Tabela resumo com métricas principais de cada investigação
    # Os campos mais relevantes para diagnóstico são apresentados em colunas
    summary_rows = []
    for e in reversed(audit_entries):  # mais recentes primeiro
        ts = e.get("logged_at_utc", e.get("timestamp_utc", ""))[:16].replace("T", " ")
        duration_ms = e.get("pipeline_duration_ms", 0)
        m, s = divmod(duration_ms // 1000, 60)
        duration_fmt = f"{m}m{s:02d}s" if m else f"{s}s"
        summary_rows.append({
            "Timestamp (UTC)": ts,
            "Query": e.get("query", "")[:50],
            "Modelo": e.get("model", ""),
            "Preset": e.get("preset", ""),
            "Resultados": e.get("results_found", 0),
            "Filtrados": e.get("results_filtered", 0),
            "Scrapeados": e.get("results_scraped", 0),
            "Duração": duration_fmt,
            "Erros": len(e.get("errors", [])),
        })

    st.dataframe(summary_rows, use_container_width=True)

    # Expansores com o JSON completo de cada entrada, para diagnóstico
    # detalhado (engines activas, audit_id, hashes, etc.)
    with st.expander("Ver entradas completas (JSON)", expanded=False):
        for i, entry in enumerate(reversed(audit_entries)):
            ts = entry.get("logged_at_utc", "")[:16].replace("T", " ")
            query_preview = entry.get("query", "")[:40]
            with st.expander(f"{ts} — {query_preview}", expanded=False):
                st.json(entry)

st.divider()

# ---------------------------------------------------------------------------
# Secção 2 — Log Aplicacional (mensagens de logging dos módulos)
# ---------------------------------------------------------------------------

st.subheader("App Log — Mensagens dos Módulos")

if not _APP_LOG.exists() or _APP_LOG.stat().st_size == 0:
    st.info(
        "Nenhum log aplicacional disponível ainda.\n\n"
        "Os logs de debug (timeouts de scraping, erros de rede, etc.) "
        "aparecerão aqui depois de executar o pipeline."
    )
else:
    # Lê o ficheiro e mostra as últimas N linhas (mais recentes no fundo)
    raw_log = _APP_LOG.read_text(encoding="utf-8", errors="replace")
    lines = [l for l in raw_log.splitlines() if l.strip()]

    # Controlos de filtragem e quantidade de linhas a mostrar
    col_lines, col_level = st.columns([2, 2])
    with col_lines:
        max_lines = st.slider(
            "Linhas a mostrar",
            min_value=50,
            max_value=min(2000, len(lines)),
            value=min(200, len(lines)),
            step=50,
            key="debug_max_lines",
        )
    with col_level:
        level_filter = st.selectbox(
            "Filtrar por nível",
            ["TODOS", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            key="debug_level_filter",
        )

    # Aplica filtro de nível se selecionado
    if level_filter != "TODOS":
        lines = [l for l in lines if f"[{level_filter}" in l]

    # Mostra apenas as últimas `max_lines` linhas
    display_lines = lines[-max_lines:]

    # Estatísticas rápidas sobre o conteúdo do log
    total_lines = len(lines)
    error_lines = sum(1 for l in lines if "[ERROR" in l or "[CRITICAL" in l)
    warn_lines = sum(1 for l in lines if "[WARNING" in l)

    m_col1, m_col2, m_col3 = st.columns(3)
    m_col1.metric("Total de linhas", total_lines)
    m_col2.metric("Avisos", warn_lines)
    m_col3.metric("Erros", error_lines)

    st.caption(
        f"A mostrar as últimas {len(display_lines)} de {total_lines} linhas"
        + (f" (filtro: {level_filter})" if level_filter != "TODOS" else "")
    )

    # Apresenta as linhas como bloco de código com scroll
    # O texto de log é apresentado numa área de texto de altura fixa
    log_text = "\n".join(display_lines)
    st.code(log_text, language=None)

    # Botão de download do log completo
    st.download_button(
        label="⬇ Download app.log completo",
        data=raw_log.encode("utf-8"),
        file_name=f"app_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        mime="text/plain",
        use_container_width=False,
    )

st.divider()

# ---------------------------------------------------------------------------
# Secção 3 — Estado dos ficheiros de log
# ---------------------------------------------------------------------------

st.subheader("Estado dos Ficheiros de Log")

for log_path, label in [(_AUDIT_LOG, "audit.jsonl"), (_APP_LOG, "app.log")]:
    if log_path.exists():
        size_kb = log_path.stat().st_size / 1024
        mtime = datetime.fromtimestamp(log_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        st.markdown(f"- **logs/{label}** — {size_kb:.1f} KB — última modificação: {mtime}")
    else:
        st.markdown(f"- **logs/{label}** — _não existe ainda_")
