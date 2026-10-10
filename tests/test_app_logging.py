"""logs/app.log: sem o ciclo do watchdog, só DEBUG da app, com limite de tamanho."""

import logging
import time
from logging.handlers import RotatingFileHandler

import pytest

import audit


@pytest.fixture
def app_log(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "_LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(audit, "_APP_LOG_FILE", tmp_path / "logs" / "app.log")
    root, wd = logging.getLogger(), logging.getLogger("watchdog")
    saved = (list(root.handlers), root.level, wd.level)
    yield tmp_path / "logs" / "app.log"
    for h in list(root.handlers):
        if h not in saved[0]:
            root.removeHandler(h)
            h.close()
    root.setLevel(saved[1])
    wd.setLevel(saved[2])


def _flush():
    for h in logging.getLogger().handlers:
        h.flush()


def test_only_app_debug_and_external_warnings(app_log):
    audit.setup_file_logging()
    logging.getLogger("llm").debug("app debug")
    logging.getLogger("forum_adapters.darkforums").debug("adapter debug")
    logging.getLogger("urllib3.connectionpool").debug("pedido via tor")
    logging.getLogger("httpcore.http11").debug("fragmento da resposta")
    logging.getLogger("watchdog.observers.inotify_buffer").debug("in-event")
    logging.getLogger("urllib3.connectionpool").warning("aviso externo")
    _flush()
    text = app_log.read_text(encoding="utf-8")
    assert "app debug" in text and "adapter debug" in text and "aviso externo" in text
    assert "pedido via tor" not in text and "fragmento" not in text and "in-event" not in text


def test_rotating_with_limit_and_no_duplicates(app_log):
    audit.setup_file_logging()
    audit.setup_file_logging()  # o Streamlit volta a correr o script
    handlers = [h for h in logging.getLogger().handlers if isinstance(h, RotatingFileHandler)
                and h.baseFilename == str(app_log.resolve())]
    assert len(handlers) == 1
    assert handlers[0].maxBytes == audit.APP_LOG_MAX_BYTES and handlers[0].backupCount == audit.APP_LOG_BACKUPS
    assert logging.getLogger("watchdog").level == logging.WARNING


def test_no_feedback_loop_with_recursive_watcher(app_log):
    """O Streamlit vigia a pasta recursivamente: antes, cada linha do log gerava outra (~2 MB/s)."""
    pytest.importorskip("watchdog")
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    audit.setup_file_logging()
    obs = Observer()
    obs.schedule(FileSystemEventHandler(), str(app_log.parent.parent), recursive=True)
    obs.start()
    try:
        logging.getLogger("llm").info("arranque")
        time.sleep(1.5)
    finally:
        obs.stop()
        obs.join()
    _flush()
    assert app_log.read_text(encoding="utf-8").count("\n") == 1
