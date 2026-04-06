"""
audit.py — Log de Auditoria de Investigações

Regista todas as investigações executadas num ficheiro de log estruturado
no formato JSON Lines (JSONL): um objeto JSON por linha, o que facilita
a análise posterior com ferramentas como jq, pandas, ou qualquer leitor
de logs estruturados.

Localização do log: logs/audit.jsonl (relativo ao diretório de trabalho)

O log de auditoria é essencial em contexto forense para:
    - Rastreabilidade: saber quando, com que modelo e que query foi executada
    - Reprodutibilidade: re-executar investigações com os mesmos parâmetros
    - Análise metodológica: avaliar a eficácia de diferentes modelos e presets
    - Conformidade: demonstrar que as investigações foram conduzidas de forma
      controlada e documentada (importante para teses académicas)

Formato de cada entrada:
    {
        "audit_id": "uuid4",
        "timestamp_utc": "ISO 8601",
        "query": "query original",
        "refined_query": "query refinada pelo LLM",
        "model": "llama3.2:latest",
        "preset": "threat_intel",
        "engines_active": ["Ahmia", "OnionLand", ...],
        "results_found": 42,
        "results_filtered": 10,
        "results_scraped": 8,
        "summary_length_chars": 1200,
        "pipeline_duration_ms": 48000,
        "errors": []
    }
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# Diretório e ficheiros de log
_LOG_DIR = Path("logs")
_LOG_FILE = _LOG_DIR / "audit.jsonl"
_APP_LOG_FILE = _LOG_DIR / "app.log"


def setup_file_logging(level: int = logging.DEBUG) -> None:
    """
    Configura um FileHandler no logger raiz para escrever em logs/app.log.

    Captura todas as mensagens de logging emitidas pelos módulos da aplicação
    (incluindo os `logger.debug()` em scrape.py, search.py, etc.) num ficheiro
    persistente que pode ser consultado na página de Debug.

    A função verifica se o handler já foi adicionado antes de o criar, para
    evitar duplicação de entradas quando o Streamlit re-executa o script.

    Args:
        level: Nível mínimo de logging a capturar (padrão: DEBUG — captura tudo).
    """
    _LOG_DIR.mkdir(exist_ok=True)

    root_logger = logging.getLogger()

    # Evitar duplicar handlers em re-execuções do Streamlit:
    # verificar se já existe um FileHandler apontando para app.log
    app_log_path = str(_APP_LOG_FILE.resolve())
    for handler in root_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            if getattr(handler, "baseFilename", "") == app_log_path:
                return  # Handler já configurado — não duplicar

    # Criar e configurar o FileHandler
    handler = logging.FileHandler(_APP_LOG_FILE, encoding="utf-8")
    handler.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(fmt)

    # Adicionar ao logger raiz para capturar logs de todos os módulos
    root_logger.addHandler(handler)
    root_logger.setLevel(level)


def log_investigation(data: dict) -> None:
    """
    Regista uma investigação completa no ficheiro de auditoria.

    Cada chamada adiciona uma nova linha ao ficheiro JSONL.
    O ficheiro e o diretório são criados automaticamente se não existirem.
    Falhas de escrita são silenciadas para não interromper o pipeline
    de investigação — o log é complementar, não crítico.

    Args:
        data: Dicionário com os campos da investigação. Campos esperados:
            - audit_id (str): UUID4 único para esta investigação
            - query (str): Query original do utilizador
            - refined_query (str): Query após refinamento pelo LLM
            - model (str): Identificador do modelo LLM utilizado
            - preset (str): Domínio de investigação selecionado
            - engines_active (list[str]): Nomes das engines utilizadas
            - results_found (int): Total de resultados de pesquisa
            - results_filtered (int): Resultados após filtragem por LLM
            - results_scraped (int): Páginas com conteúdo scrapeado
            - summary_length_chars (int): Comprimento do sumário gerado
            - pipeline_duration_ms (int): Duração total do pipeline em ms
            - errors (list[str]): Lista de erros ocorridos (pode ser vazia)
    """
    try:
        # Garantir que o diretório de logs existe
        _LOG_DIR.mkdir(exist_ok=True)

        # Adicionar timestamp de escrita do log (distinto do timestamp
        # da investigação, que pode ser ligeiramente anterior)
        entry = {
            "logged_at_utc": datetime.now(timezone.utc).isoformat(),
            **data,
        }

        # Escrever em modo append — uma linha JSON por investigação
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    except Exception:
        # O log de auditoria não deve nunca interromper a investigação.
        # Em produção, aqui seria registado num logger secundário.
        pass


def load_audit_log() -> list[dict]:
    """
    Carrega todas as entradas do log de auditoria.

    Útil para análise retrospetiva de investigações, geração de estatísticas
    sobre engines mais produtivas, modelos mais eficazes, etc.

    Returns:
        Lista de dicionários, um por investigação, ordenada do mais antigo
        para o mais recente. Retorna lista vazia se o ficheiro não existir.
    """
    if not _LOG_FILE.exists():
        return []

    entries = []
    for line in _LOG_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            # Linha corrompida — ignorar silenciosamente
            continue

    return entries
