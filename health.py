import time
import socket
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from search import get_tor_session, USER_AGENTS
from engine_manager import get_active_engines
from llm import get_llm
from llm_utils import resolve_model_config


def rotate_tor_circuit(control_port: int = 9051, password: str = None) -> dict:
    """
    Solicita um novo circuito Tor através do control port (porta 9051).

    Um novo circuito significa que o próximo pedido de rede sairá por um
    nó de saída Tor diferente, alterando o IP aparente da ferramenta.
    Isto é útil entre investigações para dificultar correlação de pedidos
    pelas dark web search engines.

    Utiliza a biblioteca `stem` para comunicar com o Tor via protocolo de
    controlo. Tenta autenticação por cookie (CookieAuthentication) primeiro,
    e por password como fallback.

    Requisitos no torrc:
        ControlPort 9051
        CookieAuthentication 1   # (recomendado)
        # ou: HashedControlPassword <hash>  (se usar password)

    Args:
        control_port: Porta do Tor control port (padrão: 9051).
        password: Password do control port, se configurada. Se None,
                  tenta autenticação por cookie.

    Returns:
        Dicionário com:
            - "status": "rotated" se bem-sucedido, "error" em caso de falha
            - "message": descrição do resultado ou mensagem de erro
    """
    try:
        from stem import Signal
        from stem.control import Controller

        # Abrir ligação ao control port do Tor
        with Controller.from_port(port=control_port) as controller:
            # Tentar autenticação por cookie primeiro (mais seguro),
            # depois por password se fornecida, depois sem autenticação
            if password:
                controller.authenticate(password=password)
            else:
                controller.authenticate()

            # Enviar sinal NEWNYM: pede ao Tor um novo circuito
            # O Tor aguarda o intervalo mínimo (normalmente 10s) entre
            # rotações para evitar abusos
            controller.signal(Signal.NEWNYM)

        return {
            "status": "rotated",
            "message": "Novo circuito Tor estabelecido com sucesso.",
        }

    except ImportError:
        return {
            "status": "error",
            "message": "Biblioteca 'stem' não instalada. Execute: pip install stem",
        }
    except Exception as e:
        err = str(e)
        # Fornecer mensagem de ajuda contextual baseada no tipo de erro
        if "111" in err or "refused" in err.lower():
            msg = (
                f"Control port {control_port} recusou ligação. "
                "Verifique que o torrc tem 'ControlPort 9051' e reinicie o Tor."
            )
        elif "authentication" in err.lower() or "password" in err.lower():
            msg = (
                "Falha de autenticação. Verifique 'CookieAuthentication 1' "
                "no torrc ou forneça a password correta."
            )
        else:
            msg = f"Erro ao rodar circuito: {err}"
        return {"status": "error", "message": msg}


def check_tor_proxy():
    """Test that the Tor SOCKS5 proxy on 127.0.0.1:9050 is accepting connections."""
    try:
        start = time.time()
        sock = socket.create_connection(("127.0.0.1", 9050), timeout=5)
        sock.close()
        latency_ms = round((time.time() - start) * 1000)
        return {"status": "up", "latency_ms": latency_ms, "error": None}
    except Exception as e:
        return {"status": "down", "latency_ms": None, "error": str(e)}


def check_llm_health(model_choice):
    """
    Test actual connectivity to the selected LLM by sending a minimal prompt.
    Returns {status, latency_ms, error, provider}.
    """
    config = resolve_model_config(model_choice)
    if config is None:
        return {
            "status": "error",
            "latency_ms": None,
            "error": f"Unknown model: {model_choice}",
            "provider": "unknown",
        }

    # Determine provider name for display
    class_name = getattr(config["class"], "__name__", str(config["class"]))
    ctor = config.get("constructor_params", {}) or {}
    if "ChatAnthropic" in class_name:
        provider = "Anthropic"
    elif "ChatGoogleGenerativeAI" in class_name:
        provider = "Google Gemini"
    elif "ChatOllama" in class_name:
        provider = "Ollama (local)"
    elif "ChatOpenAI" in class_name:
        base_url = (ctor.get("base_url") or "").lower()
        if "openrouter" in base_url:
            provider = "OpenRouter"
        elif "llama" in base_url or "localhost" in base_url or "127.0.0.1" in base_url:
            provider = "llama.cpp (local)"
        else:
            provider = "OpenAI"
    else:
        provider = class_name

    try:
        start = time.time()
        llm = get_llm(model_choice)
        # Send a tiny prompt — cheapest possible API call
        response = llm.invoke("Say OK")
        latency_ms = round((time.time() - start) * 1000)
        # Extract text from response
        text = getattr(response, "content", str(response))
        if text and len(text.strip()) > 0:
            return {
                "status": "up",
                "latency_ms": latency_ms,
                "error": None,
                "provider": provider,
            }
        else:
            return {
                "status": "down",
                "latency_ms": latency_ms,
                "error": "Empty response from API",
                "provider": provider,
            }
    except Exception as e:
        latency_ms = round((time.time() - start) * 1000)
        return {
            "status": "down",
            "latency_ms": latency_ms,
            "error": str(e),
            "provider": provider,
        }


def _ping_single_engine(engine):
    """Ping a single search engine via Tor and return its status."""
    name = engine["name"]
    # Extract base URL (host only) from the template URL
    url_template = engine["url"]
    # Use a dummy query to form a valid URL for the ping
    url = url_template.format(query="test")

    try:
        session = get_tor_session()
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        start = time.time()
        resp = session.get(url, headers=headers, timeout=20)
        latency_ms = round((time.time() - start) * 1000)
        return {
            "name": name,
            "status": "up" if resp.status_code == 200 else "down",
            "latency_ms": latency_ms,
            "error": None if resp.status_code == 200 else f"HTTP {resp.status_code}",
        }
    except Exception as e:
        return {
            "name": name,
            "status": "down",
            "latency_ms": None,
            "error": str(e)[:80],
        }


def check_search_engines(max_workers=8):
    """
    Concurrently ping all active search engines via Tor.
    Returns a list of per-engine status dicts.
    """
    engines = get_active_engines()
    return check_engines_list(engines, max_workers=max_workers)


def check_engines_list(engines, max_workers=8):
    """
    Concurrently ping a given list of engines via Tor.
    Each engine must have 'name' and 'url' keys.
    Returns a list of per-engine status dicts in original order.
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_engine = {
            executor.submit(_ping_single_engine, eng): eng
            for eng in engines
        }
        for future in as_completed(future_to_engine):
            results.append(future.result())

    # Sort by original engine order
    name_order = {e["name"]: i for i, e in enumerate(engines)}
    results.sort(key=lambda r: name_order.get(r["name"], 999))
    return results
