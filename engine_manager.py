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
    """
    return [
        {
            "name": e["name"],
            "url": e["url"],
            "enabled": e.get("default_enabled", True),
            "is_default": True,
        }
        for e in _BUILTIN_ENGINES
    ]


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
        data = json.loads(CONFIG_FILE.read_text())
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
            engines.append({
                "name": builtin["name"],
                "url": builtin["url"],
                "enabled": builtin.get("default_enabled", True),
                "is_default": True,
            })
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


def get_all_engines() -> List[Dict]:
    """Return full engine list including disabled ones."""
    return load_engines()


def get_active_engines() -> List[Dict]:
    """Return only enabled engines as {name, url} dicts."""
    return [
        {"name": e["name"], "url": e["url"]}
        for e in load_engines()
        if e.get("enabled", True)
    ]


def get_active_engine_urls() -> List[str]:
    """Return flat list of URLs for active engines (replaces DEFAULT_SEARCH_ENGINES)."""
    return [e["url"] for e in get_active_engines()]


def add_engine(name: str, url: str) -> str:
    """Add a new engine. Returns error message or empty string on success."""
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
    })
    save_engines(engines)
    return ""


def update_engine(index: int, name: str, url: str, enabled: bool) -> str:
    """Update engine at index. Returns error message or empty string on success."""
    engines = load_engines()
    if index < 0 or index >= len(engines):
        return "Indice invalido."

    name = name.strip()
    url = url.strip()

    if not name:
        return "Nome do engine nao pode estar vazio."
    if "{query}" not in url:
        return "O URL deve conter {query} como placeholder."

    engines[index]["name"] = name
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
