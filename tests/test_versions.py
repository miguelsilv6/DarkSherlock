"""PR 5 — as ferramentas de avaliação não misturam versões do pipeline sem o dizer."""

import json
import subprocess
import sys
from pathlib import Path

import versions

ROOT = Path(__file__).resolve().parent.parent


def test_version_of_and_keep():
    assert versions.version_of({}) == "1.0-legacy"
    assert versions.version_of({"pipeline_version": "2.0"}) == "2.0"
    assert versions.keep({}, None) and versions.keep({}, "any")
    assert versions.keep({"pipeline_version": "2.0"}, "2.0")
    assert not versions.keep({}, "2.0")


def test_mixed_error():
    invs = [{}, {"pipeline_version": "2.0"}, {"pipeline_version": "2.0"}]
    msg = versions.mixed_error(invs, None)
    assert "1.0-legacy: 1" in msg and "2.0: 2" in msg
    assert versions.mixed_error(invs, "any") is None
    assert versions.mixed_error(invs[1:], None) is None


def _write(d: Path, name: str, version=None):
    data = {"model": "M", "scenario_id": "A1", "search_results": [{"link": "http://a.onion", "found_by": ["E"]}],
            "sources": [], "stage4_outcome": "ranked", "scraped_content": {}}
    if version:
        data["pipeline_version"] = version
    (d / name).write_text(json.dumps(data), encoding="utf-8")


def _check_runs(d: Path, *extra):
    return subprocess.run([sys.executable, str(ROOT / "evaluation" / "check_runs.py"), "--model", "M",
                           "--dir", str(d), *extra], capture_output=True, text=True)


def test_check_runs_refuses_mixed_versions(tmp_path):
    _write(tmp_path, "eval_A1_20261001_100000.json")
    _write(tmp_path, "eval_A1_20261011_100000.json", "2.0")
    out = _check_runs(tmp_path)
    assert out.returncode == 2 and "misturam versões" in out.stderr

    out = _check_runs(tmp_path, "--pipeline-version", "2.0")
    assert out.returncode != 2 and "misturam" not in out.stderr
    assert "A1" in out.stdout
