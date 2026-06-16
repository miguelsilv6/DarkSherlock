"""
forum_adapters/darkforums.py — Adapter autenticado para o fórum DarkForums (MyBB).

Contexto
--------
DarkForums (`darkforums.st`) é um fórum MyBB clearnet com Cloudflare em frente.
Para indexá-lo como fonte OSINT no pipeline DarkSherlock é necessário:

  1. Login HTTP POST → cookie de sessão `mybbuser`.
  2. Pesquisa autenticada via `POST /search.php` (resposta 302 → `search.php?sid=…`).
  3. Bypass do challenge Cloudflare (IUAM/Turnstile) — feito com `curl_cffi`,
     que imita TLS/JA3 + HTTP/2 fingerprint de um Chrome real.
  4. Encaminhamento por Tor SOCKS5h, alinhado com o restante pipeline.
  5. Persistência da cookie jar em `config/sessions/darkforums.json` para
     evitar logins repetidos entre execuções.

Disclaimer académico: este adapter foi acrescentado exclusivamente para
investigação em threat intelligence, no âmbito de uma dissertação de Mestrado
em Cibersegurança. A conta de acesso deve ser criada pelo investigador,
sem qualquer interacção activa no fórum (sem posts, sem mensagens), e
respeitando o Tos na medida em que este é compatível com investigação
académica passiva.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .base import ForumAdapter

logger = logging.getLogger(__name__)

# Importação tardia/defensiva: o pipeline geral deve continuar a funcionar
# mesmo que `curl_cffi` não esteja instalado (engine simplesmente fica
# desactivado em vez de partir o import de search.py).
try:
    from curl_cffi import requests as cffi_requests  # type: ignore[import-not-found]
    _CURL_CFFI_AVAILABLE = True
except Exception as _exc:  # noqa: BLE001 — qualquer falha de import deve degradar graciosamente
    cffi_requests = None  # type: ignore[assignment]
    _CURL_CFFI_AVAILABLE = False
    logger.info("curl_cffi indisponível (%s) — DarkForumsAdapter ficará desactivado.", _exc)


# Caminho onde a cookie jar serializada é guardada entre execuções.
# Listado em .gitignore para não vazar sessões.
_SESSION_DIR = Path("config") / "sessions"
_SESSION_FILE = _SESSION_DIR / "darkforums.json"

# Lock global para serializar operações de login concorrentes — múltiplas
# threads do ThreadPoolExecutor poderiam disparar logins em paralelo se
# encontrassem o cookie expirado ao mesmo tempo.
_LOGIN_LOCK = threading.Lock()


def _truncate_at_paragraph(text: str, max_chars: int) -> str:
    """
    Versão local do helper homónimo em scrape.py — evita import circular
    entre scrape.py (que vai despachar para este adapter) e forum_adapters.
    Mantém o mesmo comportamento: corta no último parágrafo/frase antes
    de `max_chars`, ou aplica truncagem simples com '…' se a fronteira
    estiver demasiado perto do início.
    """
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars]
    last_para = truncated.rfind("\n\n")
    last_period = truncated.rfind(". ")
    boundary = max(last_para, last_period)
    if boundary > max_chars * 0.6:
        return truncated[: boundary + 1].strip()
    return truncated.rstrip() + "…"


class DarkForumsAdapter(ForumAdapter):
    """Adapter autenticado para darkforums.st (MyBB sobre Cloudflare)."""

    name = "darkforums"
    domains = ("darkforums.st",)

    # Configurações conservadoras para OSINT passivo:
    #   - intervalo mínimo de 2s entre pedidos (rate-limit "amigável")
    #   - 2 tentativas extra perante challenge Cloudflare
    #   - timeout generoso (Tor + CF challenge resolution pode ser lento)
    _MIN_REQUEST_INTERVAL_S = 2.0
    _MAX_CF_RETRIES = 2
    _REQUEST_TIMEOUT_S = 60
    _SEARCH_RESULTS_LIMIT = 20
    _THREAD_MAX_CHARS = 4000  # texto entregue ao LLM por thread

    def __init__(self) -> None:
        self._base_url = os.getenv("DARKFORUMS_BASE_URL", "https://darkforums.st").rstrip("/")
        self._username = os.getenv("DARKFORUMS_USERNAME", "").strip()
        self._password = os.getenv("DARKFORUMS_PASSWORD", "")
        self._session: Any | None = None
        self._last_request_ts: float = 0.0
        self._authenticated: bool = False
        # Lock dedicado a rate-limiting (separado do lock de login global)
        self._rate_lock = threading.Lock()

    # ----------------------------------------------------------------- contracto
    def is_configured(self) -> bool:
        return bool(self._username and self._password and _CURL_CFFI_AVAILABLE)

    def ensure_session(self) -> bool:
        if not self.is_configured():
            return False
        # Fast path: já autenticado nesta instância — assumimos válido até
        # que um pedido subsequente descubra que a cookie expirou (nessa
        # altura `_check_session_valid` invalida e re-tenta).
        if self._authenticated and self._session is not None:
            return True

        with _LOGIN_LOCK:
            if self._authenticated and self._session is not None:
                return True
            self._init_session()
            # Tenta primeiro reaproveitar cookies persistidas em disco.
            if self._load_cookies() and self._verify_session():
                self._authenticated = True
                _log_audit("darkforums_session_restored")
                return True
            # Senão, executa login completo.
            ok = self._login()
            self._authenticated = ok
            return ok

    def search(self, query: str) -> list[dict]:
        if not self.ensure_session():
            return []
        try:
            html = self._post_search(query)
            if html is None:
                return []
            return self._parse_search_results(html)[: self._SEARCH_RESULTS_LIMIT]
        except Exception as e:  # noqa: BLE001
            logger.debug("DarkForums search falhou para '%s': %s", query, e)
            _log_audit("darkforums_search_error", error=str(e))
            return []

    def fetch_thread(self, url: str) -> str:
        if not self.ensure_session():
            return ""
        try:
            response = self._get(url)
            if response is None or response.status_code != 200:
                return ""
            if self._looks_like_login_page(response.text):
                # Sessão expirou entre search e fetch — re-login uma vez.
                self._authenticated = False
                if not self.ensure_session():
                    return ""
                response = self._get(url)
                if response is None or response.status_code != 200:
                    return ""
            return self._parse_thread(response.text)
        except Exception as e:  # noqa: BLE001
            logger.debug("DarkForums fetch_thread falhou para %s: %s", url, e)
            _log_audit("darkforums_fetch_error", error=str(e))
            return ""

    # ------------------------------------------------------------- sessão / login
    def _init_session(self) -> None:
        """Cria sessão curl_cffi com impersonation + proxies Tor SOCKS5h."""
        if not _CURL_CFFI_AVAILABLE:
            return
        # impersonate="chrome124" alinha TLS/JA3, HTTP/2 SETTINGS e User-Agent
        # com um Chrome real recente. É a defesa principal contra o Cloudflare
        # IUAM, que faz fingerprinting do cliente para distinguir bots.
        self._session = cffi_requests.Session(impersonate="chrome124")
        self._session.proxies = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050",
        }

    def _login(self) -> bool:
        """POST /member.php?action=do_login. Devolve True em sucesso."""
        assert self._session is not None
        url = f"{self._base_url}/member.php"
        data = {
            "action": "do_login",
            "url": self._base_url + "/",
            "quick_login": "1",
            "username": self._username,
            "password": self._password,
            "remember": "yes",
            "submit": "Login",
        }
        response = self._post(url, data=data)
        if response is None:
            _log_audit("darkforums_login_failed", reason="no_response")
            return False
        # MyBB define a cookie `mybbuser` quando o login tem sucesso.
        # Verificamos tanto a cookie como a ausência do formulário de password
        # na resposta (defesa em profundidade contra páginas de erro estranhas).
        mybbuser = self._cookie_value("mybbuser")
        if mybbuser and not self._looks_like_login_page(response.text):
            self._save_cookies()
            _log_audit("darkforums_login_success")
            return True
        _log_audit(
            "darkforums_login_failed",
            reason="bad_credentials_or_cf",
            status=response.status_code,
        )
        return False

    def _verify_session(self) -> bool:
        """Pede a página inicial e confirma que não estamos a ver o login form."""
        response = self._get(f"{self._base_url}/index.php")
        if response is None or response.status_code != 200:
            return False
        return not self._looks_like_login_page(response.text)

    # ----------------------------------------------------------- HTTP com retries
    def _get(self, url: str) -> Any | None:
        return self._request("GET", url)

    def _post(self, url: str, data: dict[str, str]) -> Any | None:
        return self._request("POST", url, data=data)

    def _request(self, method: str, url: str, **kwargs: Any) -> Any | None:
        assert self._session is not None
        self._respect_rate_limit()
        last_exc: Exception | None = None
        for attempt in range(self._MAX_CF_RETRIES + 1):
            try:
                response = self._session.request(
                    method,
                    url,
                    timeout=self._REQUEST_TIMEOUT_S,
                    allow_redirects=True,
                    **kwargs,
                )
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                logger.debug(
                    "DarkForums %s %s tentativa %d falhou: %s",
                    method, url, attempt + 1, exc,
                )
                time.sleep(0.5 * (attempt + 1))
                continue

            if self._is_cf_challenge(response):
                _log_audit("darkforums_cf_challenge", url=url, attempt=attempt + 1)
                # curl_cffi pode resolver desafios estáticos automaticamente,
                # mas Turnstile/IUAM v2 requer JS — backoff e retry permite
                # apanhar casos em que o CF clearance cookie chega no segundo
                # pedido após desafio interactivo.
                time.sleep(2.0 * (attempt + 1))
                continue

            if 500 <= response.status_code < 600 and attempt < self._MAX_CF_RETRIES:
                time.sleep(1.0 * (attempt + 1))
                continue

            return response

        if last_exc is not None:
            logger.debug("DarkForums esgotou retries para %s %s: %s", method, url, last_exc)
        return None

    def _respect_rate_limit(self) -> None:
        with self._rate_lock:
            elapsed = time.monotonic() - self._last_request_ts
            wait = self._MIN_REQUEST_INTERVAL_S - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_request_ts = time.monotonic()

    # ----------------------------------------------------------- pesquisa/parsing
    def _post_search(self, query: str) -> str | None:
        url = f"{self._base_url}/search.php"
        data = {
            "action": "do_search",
            "keywords": query,
            "author": "",
            "matchusername": "0",
            "postthread": "1",
            "showresults": "threads",
            "findthreadst": "0",
            "numreplies": "",
            "postdate": "0",
            "pddir": "1",
            "sortby": "lastpost",
            "sortordr": "desc",
            "submit": "Search",
        }
        response = self._post(url, data=data)
        if response is None or response.status_code != 200:
            return None
        if self._looks_like_login_page(response.text):
            self._authenticated = False
            return None
        return response.text

    def _parse_search_results(self, html: str) -> list[dict]:
        """
        Extrai threads do HTML de resultados MyBB.

        O layout-padrão lista cada thread como `<a class="thread_link" …>` ou,
        em temas alternativos, como link dentro de `<span class="subject_…">`.
        Tentamos selectors específicos primeiro e caímos numa heurística
        baseada em URLs `/Thread-…` em último recurso.
        """
        soup = BeautifulSoup(html, "html.parser")
        results: list[dict] = []
        seen: set[str] = set()

        anchors = soup.select("a.thread_link")
        if not anchors:
            # Layouts MyBB alternativos / temas custom: caçar âncoras com
            # padrão Thread-… no href.
            anchors = [
                a for a in soup.find_all("a", href=True)
                if "Thread-" in a["href"]
            ]

        for a in anchors:
            href = a.get("href", "").strip()
            title = a.get_text(strip=True)
            if not href or not title or len(title) < 4:
                continue
            link = urljoin(self._base_url + "/", href)
            # Deduplicar e excluir variações com query strings que apontem
            # ao mesmo thread base (#pid, ?pid=).
            base = link.split("?")[0].split("#")[0]
            if base in seen:
                continue
            seen.add(base)
            results.append({"title": title, "link": link})

        return results

    def _parse_thread(self, html: str) -> str:
        """
        Extrai texto consolidado dos posts de uma thread MyBB.

        MyBB envolve cada post em `<div class="post_body">`. Concatenamos por
        ordem com separadores e devolvemos texto normalizado e truncado para
        a janela de contexto do LLM.
        """
        soup = BeautifulSoup(html, "html.parser")

        # Tira ruído antes da extracção textual.
        for tag in soup(["script", "style", "noscript"]):
            tag.extract()

        # Título da thread — útil para o LLM identificar o tópico.
        title_el = soup.find(["h1", "title"])
        title = title_el.get_text(strip=True) if title_el else ""

        posts = soup.select("div.post_body, div.post_content, div.message")
        if not posts:
            # Fallback: body inteiro se o tema não corresponder a MyBB base.
            body = soup.body
            posts = [body] if body is not None else []

        chunks: list[str] = []
        for post in posts:
            text = " ".join(post.get_text(separator=" ").split())
            if len(text) >= 20:
                chunks.append(text)

        combined = "\n\n".join(chunks)
        if title:
            combined = f"{title}\n\n{combined}"
        return _truncate_at_paragraph(combined, self._THREAD_MAX_CHARS)

    # -------------------------------------------------------------- helpers misc
    def _cookie_value(self, name: str) -> str | None:
        if self._session is None:
            return None
        try:
            for cookie in self._session.cookies.jar:
                if cookie.name == name:
                    return cookie.value
        except Exception:  # noqa: BLE001
            return None
        return None

    def _looks_like_login_page(self, html: str) -> bool:
        if not html:
            return False
        lowered = html.lower()
        return (
            'name="password"' in lowered
            and 'name="username"' in lowered
            and "do_login" in lowered
        )

    def _is_cf_challenge(self, response: Any) -> bool:
        """Heurística: status 403/503 + assinatura CF, ou body com 'just a moment'."""
        try:
            headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception:  # noqa: BLE001
            headers = {}
        if "cf-ray" not in headers:
            # Sem CF-Ray normalmente significa que não passou sequer por CF.
            return False
        if response.status_code in (403, 429, 503):
            return True
        body = (response.text or "").lower()
        return "just a moment" in body or "cf-chl-bypass" in body or "challenge-platform" in body

    # -------------------------------------------------------------- cookie I/O
    def _save_cookies(self) -> None:
        if self._session is None:
            return
        try:
            _SESSION_DIR.mkdir(parents=True, exist_ok=True)
            # chmod 700 no dir: cookies de sessão permitem impersonation
            # do investigador no fórum. Acesso restrito ao próprio user.
            try:
                os.chmod(_SESSION_DIR, 0o700)
            except OSError:
                pass
            data = [
                {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
                for c in self._session.cookies.jar
            ]
            _SESSION_FILE.write_text(json.dumps(data), encoding="utf-8")
            try:
                os.chmod(_SESSION_FILE, 0o600)
            except OSError:
                pass
        except Exception as e:  # noqa: BLE001
            logger.debug("Falha ao guardar cookies DarkForums: %s", e)

    def _load_cookies(self) -> bool:
        if self._session is None or not _SESSION_FILE.exists():
            return False
        try:
            data = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
            for c in data:
                self._session.cookies.set(
                    c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/")
                )
            return bool(self._cookie_value("mybbuser"))
        except Exception as e:  # noqa: BLE001
            logger.debug("Falha ao carregar cookies DarkForums: %s", e)
            return False


def _log_audit(event: str, **fields: Any) -> None:
    """
    Regista evento operacional do adapter via logger normal.

    NOTA: deliberadamente NÃO usa `audit.log_investigation` — esse log é
    JSONL com schema fixo para investigações completas (audit_id, query,
    refined_query, model, …). Misturar eventos do adapter (logins, CF
    challenges, sessão expirada) poluiria o schema e quebraria leitores
    como a página Debug.

    Os eventos são canalizados para `logs/app.log` via o FileHandler
    configurado em `audit.setup_file_logging()`, ficando consultáveis
    na página Debug sem confundir o ficheiro de auditoria.
    """
    logger.info("[adapter=darkforums] event=%s %s", event, fields)
