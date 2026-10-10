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
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path

# Diretório e ficheiros de log
_LOG_DIR = Path("logs")
_LOG_FILE = _LOG_DIR / "audit.jsonl"
_APP_LOG_FILE = _LOG_DIR / "app.log"


# Módulos da app cujos registos DEBUG vão para logs/app.log. As bibliotecas
# externas só a partir de WARNING: em DEBUG, o urllib3 regista cada pedido via
# Tor, o httpcore cada fragmento da resposta do Ollama, e o watchdog cada
# evento do sistema de ficheiros.
APP_LOGGERS = {
    "llm", "llm_utils", "local_models", "search", "search_filters", "scrape", "safety",
    "pipeline", "ui_pipeline", "engine_manager", "health", "report", "audit", "text_match",
    "settings_state", "forum_adapters", "evaluation", "__main__", "run_scenarios",
    "run_multi_model_eval", "run_refusal_ablation", "run_induced_resilience",
}

# Limite do app.log: 5 MB por ficheiro, 3 cópias rodadas (app.log.1 … .3) → ~20 MB.
APP_LOG_MAX_BYTES = 5 * 1024 * 1024
APP_LOG_BACKUPS = 3


class _AppOrWarningFilter(logging.Filter):
    """Deixa passar tudo dos módulos da app e só WARNING+ das bibliotecas externas."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING or record.name.split(".")[0] in APP_LOGGERS


def setup_file_logging(level: int = logging.DEBUG) -> None:
    """
    Escreve os registos da app em logs/app.log (consultável na página Debug).

    - DEBUG só para os módulos da app (APP_LOGGERS); bibliotecas externas a partir
      de WARNING.
    - Ficheiro rotativo com limite (APP_LOG_MAX_BYTES × APP_LOG_BACKUPS).
    - O watchdog fica em WARNING. O Streamlit vigia a pasta do projeto
      recursivamente e o watchdog regista em DEBUG cada evento do sistema de
      ficheiros — incluindo a escrita de cada linha neste log, o que gerava um
      ciclo: cada linha escrita produzia outra (~2 MB/s, ~7 GB/hora com a app parada).

    Não duplica o handler quando o Streamlit volta a correr o script.
    """
    _LOG_DIR.mkdir(exist_ok=True)

    root_logger = logging.getLogger()
    app_log_path = str(_APP_LOG_FILE.resolve())
    for handler in root_logger.handlers:
        if isinstance(handler, logging.FileHandler) and getattr(handler, "baseFilename", "") == app_log_path:
            return  # já configurado

    handler = RotatingFileHandler(_APP_LOG_FILE, maxBytes=APP_LOG_MAX_BYTES,
                                  backupCount=APP_LOG_BACKUPS, encoding="utf-8")
    handler.setLevel(level)
    handler.addFilter(_AppOrWarningFilter())
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root_logger.addHandler(handler)

    # O raiz só desce ao nível pedido para os registos da app chegarem ao handler;
    # o filtro trava as bibliotecas. O watchdog é travado também na origem.
    if root_logger.level == logging.NOTSET or root_logger.level > level:
        root_logger.setLevel(level)
    logging.getLogger("watchdog").setLevel(logging.WARNING)


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
