import json
import os
import tempfile
from pathlib import Path
from typing import List, Dict, Optional

from search import SEARCH_ENGINES as _BUILTIN_ENGINES

CONFIG_DIR = Path("config")
CONFIG_FILE = CONFIG_DIR / "search_engines.json"


def _seed_engines() -> List[Dict]:
    """Cria a lista inicial de engines a partir dos builtins.

    Respeita o campo `default_enabled` de cada engine: se estiver definido
    como False, a engine é adicionada desactivada por omissão. Engines sem
    este campo ficam activas por omissão (comportamento original).

    Engines do tipo "forum" trazem campos extra `type` e `adapter` que
    indicam ao pipeline para invocar um forum_adapters.* em vez do
    contrato simples GET-com-{query}.
    """
    seeded: List[Dict] = []
    for e in _BUILTIN_ENGINES:
        entry = {
            "name": e["name"],
            "url": e["url"],
            "enabled": e.get("default_enabled", True),
            "is_default": True,
        }
        if "type" in e:
            entry["type"] = e["type"]
        if "adapter" in e:
            entry["adapter"] = e["adapter"]
        seeded.append(entry)
    return seeded


def load_engines() -> List[Dict]:
    """Carrega engines do ficheiro JSON de configuração.

    Se o ficheiro não existir, semeia a partir dos builtins e guarda.
    Caso existam novas engines builtin que ainda não constam do ficheiro
    de configuração (e.g., após actualização do software), essas engines
    são adicionadas automaticamente com o seu estado `default_enabled`
    — activas ou inactivas conforme definido em search.py — sem afectar
    a configuração existente das engines já presentes.
    """
    if not CONFIG_FILE.exists():
        engines = _seed_engines()
        save_engines(engines)
        return engines

    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        engines = data.get("engines", [])
    except (json.JSONDecodeError, OSError):
        engines = _seed_engines()
        save_engines(engines)
        return engines

    # Sincronizar: adicionar novas engines builtin que não existem ainda na config.
    # Isto garante que actualizações ao SEARCH_ENGINES em search.py chegam
    # automaticamente a instalações existentes sem forçar um reset completo.
    existing_urls = {e["url"] for e in engines}
    new_engines_added = False
    for builtin in _BUILTIN_ENGINES:
        if builtin["url"] not in existing_urls:
            entry = {
                "name": builtin["name"],
                "url": builtin["url"],
                "enabled": builtin.get("default_enabled", True),
                "is_default": True,
            }
            if "type" in builtin:
                entry["type"] = builtin["type"]
            if "adapter" in builtin:
                entry["adapter"] = builtin["adapter"]
            engines.append(entry)
            new_engines_added = True

    if new_engines_added:
        save_engines(engines)

    return engines


def save_engines(engines: List[Dict]) -> None:
    """Atomically write engines to JSON config."""
    CONFIG_DIR.mkdir(exist_ok=True)
    data = json.dumps({"engines": engines}, indent=2, ensure_ascii=False)
    # Write to temp file then rename for atomicity
    fd, tmp_path = tempfile.mkstemp(dir=CONFIG_DIR, suffix=".json")
    try:
        os.write(fd, data.encode())
        os.close(fd)
        os.replace(tmp_path, CONFIG_FILE)
    except Exception:
        os.close(fd) if not os.get_inheritable(fd) else None
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    # Invalida o cache de health-check no Streamlit (se em runtime).
    # Sem esta invalidação, banners mostram estado obsoleto após o user
    # toggle/edit/remove de engines. Import tardio porque engine_manager é
    # também usado fora do contexto Streamlit (CLI, testes).
    try:
        import streamlit as st  # type: ignore[import-not-found]
        if hasattr(st, "session_state"):
            st.session_state.pop("engine_health", None)
            st.session_state.pop("last_engine_check", None)
    except Exception:  # noqa: BLE001 — falhas de import não devem partir CRUD
        pass


def get_all_engines() -> List[Dict]:
    """Return full engine list including disabled ones."""
    return load_engines()


def get_active_engines() -> List[Dict]:
    """Return only enabled engines.

    Inclui campos opcionais `type` e `adapter` quando presentes — necessários
    para o pipeline distinguir engines simples (GET com {query}) de engines
    de fórum autenticado (despacho via forum_adapters).
    """
    active: List[Dict] = []
    for e in load_engines():
        if not e.get("enabled", True):
            continue
        entry = {"name": e["name"], "url": e["url"]}
        if "type" in e:
            entry["type"] = e["type"]
        if "adapter" in e:
            entry["adapter"] = e["adapter"]
        active.append(entry)
    return active


def get_active_engine_urls() -> List[str]:
    """Return flat list of URLs for active SIMPLE engines.

    Mantida para compatibilidade retroactiva (audit.py / chamadores antigos).
    Exclui engines de fórum, cujos URLs são apenas informativos — o pipeline
    deve usar get_active_engines() para fazer dispatch por tipo.
    """
    return [e["url"] for e in get_active_engines() if e.get("type", "simple") == "simple"]


def add_engine(name: str, url: str) -> str:
    """Add a new engine via UI.

    Apenas suporta engines simples (GET com {query}). Engines de fórum
    autenticado são registadas via builtins + adapter dedicado (forum_adapters/),
    porque exigem login e parsing custom que não podem ser configurados só
    com um URL template.
    """
    name = name.strip()
    url = url.strip()

    if not name:
        return "Nome do engine nao pode estar vazio."
    if "{query}" not in url:
        return "O URL deve conter {query} como placeholder."
    if not url.startswith("http"):
        return "O URL deve comecar com http:// ou https://."

    engines = load_engines()
    if any(e["url"] == url for e in engines):
        return "Ja existe um engine com este URL."

    engines.append({
        "name": name,
        "url": url,
        "enabled": True,
        "is_default": False,
        "type": "simple",
    })
    save_engines(engines)
    return ""


def update_engine(index: int, name: str, url: str, enabled: bool) -> str:
    """Update engine at index. Returns error message or empty string on success.

    Para engines de fórum (type != simple), o URL não é editável (define-se
    apenas o estado enabled/disabled e o nome) — o adapter controla os
    endpoints reais.
    """
    engines = load_engines()
    if index < 0 or index >= len(engines):
        return "Indice invalido."

    name = name.strip()
    url = url.strip()

    if not name:
        return "Nome do engine nao pode estar vazio."

    engine_type = engines[index].get("type", "simple")
    if engine_type == "simple" and "{query}" not in url:
        return "O URL deve conter {query} como placeholder."

    engines[index]["name"] = name
    if engine_type == "simple":
        engines[index]["url"] = url
    engines[index]["enabled"] = enabled
    save_engines(engines)
    return ""


def remove_engine(index: int) -> str:
    """Remove engine at index. Returns error message or empty string on success."""
    engines = load_engines()
    if index < 0 or index >= len(engines):
        return "Indice invalido."

    engines.pop(index)
    save_engines(engines)
    return ""


def toggle_engine(index: int) -> None:
    """Toggle enabled state of engine at index."""
    engines = load_engines()
    if 0 <= index < len(engines):
        engines[index]["enabled"] = not engines[index].get("enabled", True)
        save_engines(engines)


def reset_to_defaults() -> None:
    """Reset engine list to builtin defaults."""
    engines = _seed_engines()
    save_engines(engines)
