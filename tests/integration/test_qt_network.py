"""Qt-панель сохраняет контекст и ограничения сетевых решений."""

import os
import time
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.jobs import JobRunner
from firewall_compliance.interfaces.desktop.qt_network import NetworkWidget


@pytest.fixture(scope="module")
def app() -> QApplication:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    return QApplication.instance() or QApplication([])  # type: ignore[return-value]


def test_network_guard_excludes_aruba(app: QApplication) -> None:
    result = analyze_file(Path("tests/fixtures/hp_aruba/aos_switch.cfg"))
    assert isinstance(result, AnalysisSession)
    runner = JobRunner()
    widget = NetworkWidget(lambda: (result,), runner)
    try:
        assert widget.base_combo.count() == 0
        assert "ASA" in widget.status.text()
        widget.query("route")
        assert runner.pending_count == 0
        assert widget.current_result is None
    finally:
        runner.shutdown()
        widget.close()


def test_query_keeps_original_model_and_switch_clears_display(app: QApplication) -> None:
    result = analyze_file(Path("tests/fixtures/assurance/policy_quality.cfg"))
    assert isinstance(result, AnalysisSession)
    sessions = [result]
    runner = JobRunner()
    widget = NetworkWidget(lambda: tuple(sessions), runner)
    try:
        assert widget.base_combo.count() == 1
        widget.query_fields["ingress_interface_id"].setText("interface:GigabitEthernet0/0")
        widget.query("interface")
        deadline = time.monotonic() + 5
        while widget.current_result is None and time.monotonic() < deadline:
            runner.poll()
            app.processEvents()
            time.sleep(0.01)
        assert widget.current_result is not None
        assert widget.current_result.model_dump()["status"] == "unknown"
        assert widget.output.toPlainText() == widget.current_result.model_dump_json(indent=2)
        sessions.clear()
        widget.refresh_sessions()
        assert widget.current_result is None
        assert widget.output.toPlainText() == ""
    finally:
        runner.shutdown()
        widget.close()


def test_selected_checks_are_explicit_and_defaults_unchanged() -> None:
    from firewall_compliance.interfaces.desktop.backend import selected_checks

    assert selected_checks(None) is None
    assert [check.check_id for check in selected_checks(("FW-ANY-ANY",)) or ()] == ["FW-ANY-ANY"]
    for values in ((), ("unknown",)):
        with pytest.raises(ValueError):
            selected_checks(values)
    result = analyze_file(
        Path("tests/fixtures/assurance/policy_quality.cfg"),
        enabled_check_ids=("FW-ANY-ANY", "FW-LOGGING"),
    )
    assert isinstance(result, AnalysisSession)
    assert {check.check_id for check in result.report.checks} == {"FW-ANY-ANY", "FW-LOGGING"}
