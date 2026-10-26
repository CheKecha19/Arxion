"""Exercise relative imports, reverse impact and forbidden layer detection."""

import json
import runpy
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "project_graph.py"


def test_relative_imports_and_reverse_test_impact(tmp_path, monkeypatch):
    files = {
        "src/firewall_compliance/domain/model.py": "class Model: pass\n",
        "src/firewall_compliance/domain/consumer.py": "from .model import Model\n",
        "tests/test_consumer.py": "from firewall_compliance.domain.consumer import Model\n",
    }
    for name, contents in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents)
    ns = runpy.run_path(str(SCRIPT))
    monkeypatch.setitem(ns["main"].__globals__, "ROOT", tmp_path)
    monkeypatch.setattr(
        ns["main"].__globals__["subprocess"],
        "check_output",
        lambda cmd, **kwargs: "fake-sha" if kwargs.get("text") else b"",
    )
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "impact", "src/firewall_compliance/domain/model.py", "--output", str(output)],
    )
    assert ns["main"]() == 0
    report = json.loads(output.read_text())
    assert report["candidate_tests"] == ["tests/test_consumer.py"]
    assert report["layer_violations"] == []


def test_domain_cannot_import_interface(tmp_path, monkeypatch):
    target = tmp_path / "src/firewall_compliance/domain/bad.py"
    target.parent.mkdir(parents=True)
    target.write_text("from firewall_compliance.interfaces.desktop import qt_app\n")
    ns = runpy.run_path(str(SCRIPT))
    monkeypatch.setitem(ns["main"].__globals__, "ROOT", tmp_path)
    monkeypatch.setattr(
        ns["main"].__globals__["subprocess"], "check_output", lambda *args, **kwargs: "fake-sha"
    )
    output = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "architecture", "--output", str(output)])
    assert ns["main"]() == 1
    report = json.loads(output.read_text())
    assert report["layer_violations"][0]["path"] == "src/firewall_compliance/domain/bad.py"
