"""PR 7 — configuração dos motores (já não versionada), nomes únicos, pasta dos modelos e .dockerignore."""

import importlib
import json
from pathlib import Path

import pytest

import engine_manager as em
import search

ROOT = Path(__file__).resolve().parent.parent
EVO_OLD = "http://wbr4bzzxbeidc6dwcqgwr3b6jl7ewtykooddsc5ztev3t3otnl45khyd.onion/evo/search.php?q={query}"
EVO_NEW = "http://wbr4bzzxbeidc6dwcqgwr3b6jl7ewtykooddsc5ztev3t3otnl45khyd.onion/?q={query}"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    d = tmp_path / "config"
    monkeypatch.setattr(em, "CONFIG_DIR", d)
    monkeypatch.setattr(em, "CONFIG_FILE", d / "search_engines.json")
    monkeypatch.setattr(em, "_DEAD_ENGINES_MARKER", d / ".dead_engines_migrated")
    return d


def _write(cfg, engines):
    cfg.mkdir(exist_ok=True)
    (cfg / "search_engines.json").write_text(json.dumps({"engines": engines}), encoding="utf-8")


def test_seed_has_unique_names_and_no_retired_urls(cfg):
    engines = em.load_engines()
    names = [e["name"].lower() for e in engines]
    assert len(names) == len(set(names))
    assert not any(e["url"] in em._RETIRED_URLS for e in engines)
    assert len(engines) == len(search.SEARCH_ENGINES)


def test_old_config_with_duplicate_evo_entries_is_repaired(cfg):
    _write(cfg, [
        {"name": "Evo Search", "url": EVO_NEW, "enabled": True, "is_default": True},
        {"name": "Evo Search", "url": EVO_OLD, "enabled": False, "is_default": True},
    ])
    engines = em.load_engines()
    evo = [e for e in engines if e["name"].startswith("Evo Search")]
    assert evo == [{"name": "Evo Search", "url": EVO_NEW, "enabled": True, "is_default": True}]
    saved = json.loads((cfg / "search_engines.json").read_text(encoding="utf-8"))["engines"]
    assert sum(e["url"] == EVO_OLD for e in saved) == 0


def test_old_url_alone_moves_to_new_url_keeping_user_choice(cfg):
    _write(cfg, [{"name": "Evo Search", "url": EVO_OLD, "enabled": True, "is_default": True}])
    evo = [e for e in em.load_engines() if e["name"] == "Evo Search"]
    assert evo[0]["url"] == EVO_NEW and evo[0]["enabled"] is True


def test_duplicate_user_names_get_suffix(cfg):
    _write(cfg, [
        {"name": "Meu Motor", "url": "http://a.onion/?q={query}", "enabled": True},
        {"name": "meu motor", "url": "http://b.onion/?q={query}", "enabled": True},
    ])
    names = [e["name"] for e in em.load_engines()][:2]
    assert names == ["Meu Motor", "meu motor (2)"]


def test_add_and_update_reject_duplicate_names(cfg):
    em.load_engines()
    assert "nome" in em.add_engine("ahmia", "http://zzzz.onion/?q={query}")
    assert em.add_engine("Novo", "http://zzzz.onion/?q={query}") == ""
    engines = em.load_engines()
    idx = next(i for i, e in enumerate(engines) if e["name"] == "Novo")
    assert "nome" in em.update_engine(idx, "Ahmia", engines[idx]["url"], True)
    assert em.update_engine(idx, "Novo 2", engines[idx]["url"], True) == ""


def test_engine_config_is_not_tracked_and_is_ignored():
    import subprocess
    tracked = subprocess.run(["git", "ls-files", "config/search_engines.json"], cwd=ROOT,
                             capture_output=True, text=True).stdout.strip()
    assert tracked == ""
    assert subprocess.run(["git", "check-ignore", "-q", "config/search_engines.json"], cwd=ROOT).returncode == 0


def test_empty_models_dir_env_falls_back_to_models(monkeypatch):
    import config
    monkeypatch.setenv("DARKSHERLOCK_MODELS_DIR", "")
    try:
        assert importlib.reload(config).MODELS_DIR == Path("models")
    finally:
        monkeypatch.delenv("DARKSHERLOCK_MODELS_DIR", raising=False)
        importlib.reload(config)


def test_dockerignore_keeps_secrets_and_evidence_out_of_the_image():
    lines = {ln.strip() for ln in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()}
    for must in (".env", "investigations/", "referrals/", "models/", "logs/", "evaluation/scenarios.local.json",
                 "config/search_engines.json"):
        assert must in lines, must
