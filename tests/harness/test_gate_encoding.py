"""Real child pipes keep JSON and diagnostics UTF-8 under Windows ACP defaults."""

import json
import os
import runpy
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATE = runpy.run_path(str(ROOT / "harness" / "build"))


@pytest.fixture
def directory():
    parent = (ROOT / "artifacts" / "gate-encoding-tests").resolve()
    assert parent.is_relative_to(ROOT)
    result = parent / uuid4().hex
    result.mkdir(parents=True)
    return result


def test_gate_overrides_inherited_acp_without_mutating_parent_environment(monkeypatch):
    monkeypatch.setenv("PYTHONIOENCODING", "cp1251")
    monkeypatch.setenv("PYTHONUTF8", "0")
    monkeypatch.setenv("ARXION_SYNTHETIC_PASSTHROUGH", "retained")

    environment = GATE["gate_environment"]()

    assert environment["PYTHONIOENCODING"] == "utf-8"
    assert environment["PYTHONUTF8"] == "1"
    assert environment["ARXION_SYNTHETIC_PASSTHROUGH"] == "retained"
    assert os.environ["PYTHONIOENCODING"] == "cp1251"
    assert os.environ["PYTHONUTF8"] == "0"


def test_child_json_and_diagnostics_write_actual_utf8_bytes(directory, monkeypatch):
    monkeypatch.setenv("PYTHONIOENCODING", "cp1251")
    monkeypatch.setenv("PYTHONUTF8", "0")
    output, log = directory / "result.json", directory / "diagnostic.log"
    # Match execute(): TextIO wrappers do not transcode bytes written by a child.
    with output.open("w", encoding="utf-8") as stdout, log.open("w", encoding="utf-8") as stderr:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import json,sys; print(json.dumps({'rule':'Правило ∆'},ensure_ascii=False)); "
                "print('Диагностика ✓',file=sys.stderr)",
            ],
            env=GATE["gate_environment"](),
            stdout=stdout,
            stderr=stderr,
            check=False,
            timeout=15,
        )

    assert result.returncode == 0
    assert json.loads(output.read_text(encoding="utf-8")) == {"rule": "Правило ∆"}
    assert "Правило ∆".encode() in output.read_bytes()
    assert log.read_text(encoding="utf-8").strip() == "Диагностика ✓"


def test_actual_cli_json_with_cyrillic_evidence_is_utf8(directory, monkeypatch):
    monkeypatch.setenv("PYTHONIOENCODING", "cp1251")
    monkeypatch.setenv("PYTHONUTF8", "0")
    source = directory / "синтетический.cfg"
    source.write_text(
        "hostname SYNTHETIC-ENCODING\naccess-list AUDIT extended permit ip any any\n"
        "access-group AUDIT in interface outside\n",
        encoding="utf-8",
    )
    output, log = directory / "cli.json", directory / "cli.log"
    with output.open("w", encoding="utf-8") as stdout, log.open("w", encoding="utf-8") as stderr:
        result = subprocess.run(
            [sys.executable, "-m", "firewall_compliance", "analyze", str(source)],
            cwd=ROOT,
            env=GATE["gate_environment"](),
            stdout=stdout,
            stderr=stderr,
            check=False,
            timeout=30,
        )

    assert result.returncode == 0, log.read_text(encoding="utf-8")
    report = json.loads(output.read_text(encoding="utf-8"))
    assert len(report["checks"]) == 7
    assert not report["parse_errors"]
    assert source.name.encode("utf-8") in output.read_bytes()
