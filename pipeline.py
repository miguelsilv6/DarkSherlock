"""
pipeline.py — O pipeline de investigação (Etapas 2 a 6), sem Streamlit.

Antes desta revisão havia três cópias do pipeline (Home.py,
pages/2_🔍_Investigation.py e evaluation/run_scenarios.py) que divergiam em
pormenores (limites, timestamps, campos gravados). Agora as três chamam estas
funções, e a avaliação mede exatamente o que a app faz.

  - PipelineResult: estado e resultado de uma investigação, etapa a etapa.
  - stage_refine / stage_search / stage_filter / stage_scrape / stage_summary:
    uma função por etapa, que preenche o PipelineResult. A UI chama-as dentro
    dos seus painéis de estado; a avaliação chama run_pipeline().
  - search_with_stats / scrape_with_details: pesquisa e recolha que devolvem
    também o detalhe da execução (em vez de o deixar só em variáveis de
    módulo), para poderem ser postas em cache sem perder esse detalhe.
  - investigation_record / audit_record / save_investigation: um único
    formato para o JSON da investigação e para a linha do audit trail.
  - tor_available: verificação rápida do proxy SOCKS do Tor.
"""

from __future__ import annotations

import json
import os
import socket
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import llm as llm_module
import scrape as scrape_module
import search as search_module
from config import PIPELINE_VERSION
from engine_manager import get_active_engines
from report import compute_integrity_hashes

TOR_HOST, TOR_PORT = "127.0.0.1", 9050

# Páginas com menos texto do que isto não contam como fonte (o raspador já só
# devolve páginas válidas; mantém-se o mínimo histórico).
MIN_SOURCE_CHARS = 150

# Desfechos de recolha que dependem do estado do Tor/rede no momento e não
# devem ficar em cache (uma nova tentativa pode ter sucesso).
TRANSIENT_SCRAPE = {"timeout", "connection_error", "error"}


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def tor_available(host: str = TOR_HOST, port: int = TOR_PORT, timeout: float = 3) -> bool:
    """True se o proxy SOCKS do Tor aceita ligações."""
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@dataclass
class PipelineResult:
    query: str
    preset: str = "threat_intel"
    model: str = ""
    pipeline_version: str = PIPELINE_VERSION
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_utc: str = field(default_factory=_now_utc)
    timestamp_utc: str = ""            # fim da investigação (o que o JSON e o PDF mostram)
    refined_query: str = ""
    active_engines: list = field(default_factory=list)
    search_results: list = field(default_factory=list)
    engine_status: dict = field(default_factory=dict)
    search_stats: dict = field(default_factory=dict)
    stage4_outcome: str | None = None
    filtered: list = field(default_factory=list)
    scrape_outcomes: dict = field(default_factory=dict)
    safety_blocked: int = 0
    pages_valid: int = 0               # páginas recolhidas com sucesso (antes da relevância)
    stage5_outcome: str | None = None
    relevance_scores: dict = field(default_factory=dict)
    scraped_content: dict = field(default_factory=dict)
    integrity: dict = field(default_factory=dict)
    summary: str = ""
    ioc_check: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    timings_ms: dict = field(default_factory=dict)
    total_ms: int = 0

    @property
    def pages_failed(self) -> int:
        """Páginas do Top-K pedidas sem sucesso (inacessíveis, erro, captcha, ...)."""
        return max(0, len(self.filtered) - self.pages_valid - self.safety_blocked)


class _Timer:
    def __init__(self, r: PipelineResult, name: str):
        self.r, self.name = r, name

    def __enter__(self):
        self.t0 = time.time()
        return self

    def __exit__(self, *exc):
        self.r.timings_ms[self.name] = round((time.time() - self.t0) * 1000)
        return False


# ---------------------------------------------------------------------------
# Pesquisa e recolha com detalhe (podem ser postas em cache pela UI)
# ---------------------------------------------------------------------------
def search_with_stats(query: str, threads: int = 4):
    """(resultados, estado por motor, estatísticas por motor, hora da recolha).

    Cada resultado leva "retrieved_at_utc" da hora em que foi de facto obtido —
    se o resultado vier de cache, mantém a hora original.
    """
    results, engine_status = search_module.get_search_results(query, max_workers=threads)
    stats = dict(search_module.last_search_stats)
    retrieved_at = _now_utc()
    for item in results:
        item["retrieved_at_utc"] = retrieved_at
    return results, engine_status, stats, retrieved_at


def search_is_cacheable(out) -> bool:
    """Não guardar em cache pesquisas sem resultados ou com motores em falha."""
    results, engine_status = out[0], out[1]
    return bool(results) and not any(v == "failed" for v in engine_status.values())


def scrape_with_details(filtered: list, threads: int = 4):
    """(texto por URL das páginas válidas, desfecho por URL, n.º bloqueado pela salvaguarda)."""
    scraped = scrape_module.scrape_multiple(filtered, max_workers=threads)
    return scraped, dict(scrape_module.last_details), scrape_module.last_blocked_count


def scrape_is_cacheable(out) -> bool:
    """Não guardar em cache recolhas com falhas de rede (podem resultar ao repetir)."""
    return not any(d.get("status") in TRANSIENT_SCRAPE for d in out[1].values())


# ---------------------------------------------------------------------------
# Etapas
# ---------------------------------------------------------------------------
def stage_refine(r: PipelineResult, llm) -> None:
    with _Timer(r, "refine_query"):
        r.refined_query = llm_module.refine_query(llm, r.query, preset=r.preset)


def stage_search(r: PipelineResult, max_results: int, threads: int, search_fn=search_with_stats) -> None:
    with _Timer(r, "search"):
        r.active_engines = [e["name"] for e in get_active_engines()]
        if not tor_available():
            r.warnings.append(f"Tor inacessível em {TOR_HOST}:{TOR_PORT}: a pesquisa e a recolha vão falhar.")
        results, r.engine_status, r.search_stats, _ = search_fn(r.refined_query or r.query, threads)
        r.search_results = list(results)[:max_results]
        if r.engine_status and all(v == "failed" for v in r.engine_status.values()):
            r.warnings.append("Todos os motores de pesquisa falharam.")
        elif not r.search_results:
            r.warnings.append("A pesquisa não devolveu resultados.")


def stage_filter(r: PipelineResult, llm, max_scrape: int) -> None:
    with _Timer(r, "filter_results"):
        # A query original: a refinada só serve para a pesquisa.
        filtered = llm_module.filter_results(llm, r.query, r.search_results)
        r.stage4_outcome = llm_module.last_filter_outcome
        r.filtered = list(filtered)[:max_scrape]


def stage_scrape(r: PipelineResult, threads: int, scrape_fn=scrape_with_details) -> None:
    with _Timer(r, "scrape"):
        scraped, details, r.safety_blocked = scrape_fn(r.filtered, threads)
        r.scrape_outcomes = dict(Counter(d.get("status", "?") for d in details.values()))
        meaningful = {u: c for u, c in scraped.items() if len(c) > MIN_SOURCE_CHARS}
        r.pages_valid = len(meaningful)
        kept = llm_module.filter_scraped_by_relevance(r.query, meaningful)
        r.stage5_outcome = llm_module.last_relevance_outcome
        r.relevance_scores = dict(llm_module.last_relevance_scores)
        scraped_at = _now_utc()
        for item in r.filtered:
            if item.get("link", "") in kept:
                item["scraped_at_utc"] = scraped_at
        r.scraped_content = kept
        r.integrity = compute_integrity_hashes(kept)
        if r.filtered and not r.pages_valid:
            r.warnings.append("Nenhuma das páginas selecionadas foi recolhida com sucesso.")
        elif r.pages_valid and not kept:
            r.warnings.append("Nenhuma das páginas recolhidas menciona os termos da query.")


def stage_summary(r: PipelineResult, llm, custom_instructions: str = "") -> None:
    with _Timer(r, "generate_summary"):
        llm_module.last_ioc_check = {}
        r.summary = llm_module.generate_summary(
            llm, r.query, r.scraped_content, preset=r.preset, custom_instructions=custom_instructions,
        )
        r.ioc_check = dict(llm_module.last_ioc_check)


def finish(r: PipelineResult, t_start: float | None = None) -> None:
    r.timestamp_utc = _now_utc()
    if t_start is not None:
        r.total_ms = round((time.time() - t_start) * 1000)
    else:
        r.total_ms = sum(r.timings_ms.values())


class PipelineError(RuntimeError):
    """Falha numa etapa; `result` tem o que foi feito até aí."""

    def __init__(self, stage: str, err: Exception, result: PipelineResult):
        super().__init__(f"{stage}: {err}")
        self.stage, self.err, self.result = stage, err, result


def run_pipeline(query: str, preset: str, llm, *, model: str = "", max_results: int = 50,
                 max_scrape: int = 10, threads: int = 4, custom_instructions: str = "",
                 search_fn=search_with_stats, scrape_fn=scrape_with_details) -> PipelineResult:
    """Etapas 2–6 completas (o LLM já carregado é a Etapa 1)."""
    r = PipelineResult(query=query, preset=preset, model=model)
    t_start = time.time()
    steps = [
        ("refine", lambda: stage_refine(r, llm)),
        ("search", lambda: stage_search(r, max_results, threads, search_fn)),
        ("filter", lambda: stage_filter(r, llm, max_scrape)),
        ("scrape", lambda: stage_scrape(r, threads, scrape_fn)),
        ("summary", lambda: stage_summary(r, llm, custom_instructions)),
    ]
    for name, step in steps:
        try:
            step()
        except Exception as e:  # noqa: BLE001 — devolve o estado parcial a quem chamou
            r.errors.append(f"{name}: {e}")
            finish(r, t_start)
            raise PipelineError(name, e, r) from e
    finish(r, t_start)
    return r


# ---------------------------------------------------------------------------
# Persistência
# ---------------------------------------------------------------------------
def investigation_record(r: PipelineResult, preset_label: str | None = None, **extra) -> dict:
    """O JSON de uma investigação (app e avaliação usam o mesmo formato)."""
    rec = {
        "audit_id": r.audit_id,
        "timestamp": datetime.now().isoformat(),
        "timestamp_utc": r.timestamp_utc or _now_utc(),
        "started_utc": r.started_utc,
        "pipeline_version": r.pipeline_version,
        "query": r.query,
        "refined_query": r.refined_query,
        "model": r.model,
        # "preset" guarda o rótulo mostrado na UI (como antes); a avaliação grava a chave.
        "preset": preset_label if preset_label is not None else r.preset,
        "preset_key": r.preset,
        "active_engines": r.active_engines,
        # Top-K selecionado pela Etapa 4
        "sources": r.filtered,
        # Lista completa de fontes recuperadas (antes do filtro por LLM), com
        # "found_by": base do recall e dos motores produtivos do EQ-02.
        "search_results": r.search_results,
        # Estado por motor ("ok"/"failed"): EQ-06. Detalhe por motor em search_stats.
        "engine_status": r.engine_status,
        "search_stats": r.search_stats,
        # Como terminou a Etapa 4: só "ranked" é um ranking do LLM (EQ-03).
        "stage4_outcome": r.stage4_outcome,
        # Desfecho do pedido de cada página do Top-K e bloqueios da salvaguarda ética.
        "scrape_outcomes": r.scrape_outcomes,
        "safety_blocked": r.safety_blocked,
        # Etapa 5: "kept" / "empty" / "no_terms" e pontuação de cada fonte.
        "stage5_outcome": r.stage5_outcome,
        "relevance_scores": r.relevance_scores,
        "summary": r.summary,
        "ioc_check": r.ioc_check,
        # Cadeia de custódia: hashes e o conteúdo exato que foi hashado (verificável depois).
        "integrity": r.integrity,
        "scraped_content": r.scraped_content,
        "warnings": r.warnings,
        "errors": r.errors,
        "timings_ms": r.timings_ms,
        "total_ms": r.total_ms,
    }
    rec.update(extra)
    return rec


def audit_record(r: PipelineResult, preset_label: str | None = None, **extra) -> dict:
    """Linha do audit trail (audit.log_investigation)."""
    rec = {
        "audit_id": r.audit_id,
        "pipeline_version": r.pipeline_version,
        "query": r.query,
        "refined_query": r.refined_query,
        "model": r.model,
        "preset": preset_label if preset_label is not None else r.preset,
        "engines_active": r.active_engines,
        "results_found": len(r.search_results),
        "results_filtered": len(r.filtered),
        "results_scraped": len(r.scraped_content),
        "summary_length_chars": len(r.summary),
        "pipeline_duration_ms": r.total_ms,
        "errors": r.errors,
        # EQ-06: motores efetivamente tentados vs. quantos falharam.
        "engines_attempted": len(r.engine_status),
        "engines_failed": sum(1 for v in r.engine_status.values() if v == "failed"),
    }
    rec.update(extra)
    return rec


def save_investigation(record: dict, directory: Path | str = "investigations", prefix: str = "investigation") -> str:
    """Grava o JSON em `directory/<prefix>_<AAAAMMDD_HHMMSS>.json` (pasta com permissões 700). Devolve o nome."""
    d = Path(directory)
    d.mkdir(exist_ok=True)
    try:
        os.chmod(d, 0o700)  # conteúdo sensível (IOCs, PII, .onion); no-op em Windows
    except OSError:
        pass
    # Nome <prefix>_AAAAMMDD_HHMMSS.json (as ferramentas de avaliação leem a data
    # do nome); se já existir um do mesmo segundo, espera pelo seguinte.
    while True:
        fname = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        if not (d / fname).exists():
            break
        time.sleep(0.2)
    (d / fname).write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return fname
