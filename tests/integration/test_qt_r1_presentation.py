"""R1 uses real Qt selection, disclosure and source-preserving presentation."""

from __future__ import annotations

import copy
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.parsers import ParseFailure


@pytest.fixture(scope="module")
def qt_app() -> Iterator[Any]:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app
    app.processEvents()


@pytest.fixture
def window(qt_app: Any, tmp_path: Path) -> Iterator[Any]:
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QWidget

    from firewall_compliance.interfaces.desktop.qt_app import MainWindow

    view = MainWindow(
        ProjectStore(tmp_path / "synthetic.sqlite3"),
        advanced_widget_factory=lambda _sessions, _runner: QWidget(),
    )
    view.show()
    qt_app.processEvents()
    yield view
    view.close()
    view.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qt_app.processEvents()


def _seed(window: Any, tmp_path: Path) -> tuple[str, dict[str, Any]]:
    source = tmp_path / "distinct-source-name.cfg"
    source.write_text(
        "hostname R1-SYNTHETIC\n"
        "access-list OUTSIDE extended permit ip any any\n"
        "access-group OUTSIDE in interface outside\n",
        encoding="utf-8",
    )
    session = analyze_file(source, device_id="R1-DEVICE")
    assert isinstance(session, AnalysisSession)
    project = window.create_project("Synthetic R1")
    run = window.store.create_run(project)
    window.store.record_session(run, session)
    window.store.finish_run(run)
    window.load_run(run)
    return run, window.store.get_run(run)["items"][0]


def test_inventory_search_preserves_hidden_source_and_failure_records(
    window: Any,
    tmp_path: Path,
    qt_app: Any,
) -> None:
    run, _item = _seed(window, tmp_path)
    bad = tmp_path / "unsupported-export.txt"
    bad.write_text("synthetic unsupported", encoding="utf-8")
    failure = analyze_file(bad)
    assert isinstance(failure, ParseFailure)
    failed_run = window.store.create_run(window.project_id)
    window.store.record_failure(failed_run, bad, failure)
    window.store.finish_run(failed_run)
    window.load_run(failed_run)
    assert window.device_model.headers == ("Устройство", "Платформа / версия", "Тип", "Правил")
    assert window.device_model.rowCount() == 1  # last valid device is preserved
    assert len(window._import_error_items) == 1
    assert window._import_error_items[0]["run_id"] == failed_run
    assert "1 записей в истории проекта" in window.import_errors_button.text()
    window.resource_search.setText("distinct-source-name")
    qt_app.processEvents()
    assert window.device_proxy.rowCount() == 1
    window.device_table.selectRow(0)
    assert "R1-DEVICE" in window.device_detail.toPlainText()
    assert "distinct-source-name.cfg" in window.resource_source_detail.toPlainText()
    window.resource_search.clear()
    window.device_scope.setCurrentIndex(window.device_scope.findData("run"))
    assert "Импорт не выполнен" in window.device_model.rows[0][0]
    assert window.device_model.rows[0][3] == "—"
    window.load_run(run)
    assert window.device_model.rows[0][3] == 1
    rule_row = next(
        row
        for row, payload in zip(window.rules_model.rows, window.rules_model.payloads, strict=True)
        if "rule_id" in payload["value"]
    )
    assert "Любой адрес" in rule_row[4] and "Любой адрес" in rule_row[5]
    assert "Любой IP-протокол" in rule_row[6]


def test_rule_object_full_inspector_is_human_and_retains_source_and_json(
    window: Any,
    tmp_path: Path,
    qt_app: Any,
    monkeypatch: Any,
) -> None:
    from PySide6.QtWidgets import QDialog, QPlainTextEdit, QTabWidget

    _run, item = _seed(window, tmp_path)
    value = copy.deepcopy(item["parse_result"]["endpoints"][0])
    value.update(
        name="Synthetic large group",
        kind="group",
        resolution_status="unknown",
        cidrs=[f"192.0.2.{index}/32" for index in range(1, 8)],
    )
    item["parse_result"]["endpoints"] = [value]
    window._project_devices = lambda: [item]
    window._refresh_rules()
    object_row = next(
        index
        for index, payload in enumerate(window.rules_model.payloads)
        if payload["value"].get("name") == value["name"]
    )
    assert "{" not in window.rules_model.rows[object_row][-1]
    assert "ещё 4" in window.rules_model.rows[object_row][-1]
    window.rule_search.setText("192.0.2.7")
    qt_app.processEvents()
    assert window.rules_proxy.rowCount() == 1
    window.rules_table.selectRow(0)
    human = window.rule_detail.toPlainText()
    assert "192.0.2.7/32" in human and "Не определено" in human
    assert "{" not in human
    captured: list[list[str]] = []

    def inspect_dialog(dialog: Any) -> int:
        tabs = dialog.findChild(QTabWidget)
        assert [tabs.tabText(index) for index in range(3)] == [
            "Понятное описание",
            "Доказательство",
            "Технический JSON",
        ]
        captured.append([tabs.widget(index).toPlainText() for index in range(3)])
        assert isinstance(tabs.widget(0), QPlainTextEdit)
        return 0

    monkeypatch.setattr(QDialog, "exec", inspect_dialog)
    window.resource_details.show_rule_details()
    assert "192.0.2.7/32" in captured[0][0]
    assert item["content_sha256"] in captured[0][0]
    assert "Расположение в исходнике не сохранено" in captured[0][1]
    assert '"cidrs"' in captured[0][2]


def test_device_checks_and_finding_evidence_keep_unknowns_without_unrelated_repetition(
    window: Any,
    tmp_path: Path,
    qt_app: Any,
    monkeypatch: Any,
) -> None:
    _run, item = _seed(window, tmp_path)
    rule_id = item["parse_result"]["rules"][0]["rule_id"]
    check = next(check for check in item["report"]["checks"] if check["findings"])
    finding = check["findings"][0]
    check.update(
        status="partial",
        limitations=[
            {"code": "LOCAL", "message": "Relevant unknown condition", "rule_ids": [rule_id]},
            {"code": "OTHER", "message": "Unrelated second rule", "rule_ids": ["other-rule"]},
            {"code": "GLOBAL", "message": "Source-wide scope unknown", "rule_ids": []},
        ],
    )
    finding["affected_rule_ids"] = [rule_id]
    finding["evidence"]["limitations"] = ["Finding-specific qualification"]
    original = copy.deepcopy(item)
    window.finding_model.replace(
        [("Высокая", "R1", check["check_id"], "Example", "Новая")],
        [{"item": item, "check": check, "finding": finding, "mark": {}}],
    )
    window.finding_table.selectRow(0)
    qt_app.processEvents()
    text = window.finding_detail.toPlainText()
    assert "Relevant unknown condition" in text
    assert "Finding-specific qualification" in text
    assert "Unrelated second rule" not in text
    assert "Общие ограничения источника / проверки" in text
    assert item["content_sha256"] in text
    captured: list[str] = []
    monkeypatch.setattr(
        window.resource_details, "_text_dialog", lambda _title, body: captured.append(body)
    )
    window.resource_details.show_finding_limitations()
    assert "Source-wide scope unknown" in captured[0]
    assert "Unrelated second rule" not in captured[0]
    window.device_model.replace([("R1", "ASA", "Device", 1)], [item])
    window.device_table.selectRow(0)
    assert "Проверка" in window.device_detail.toPlainText()
    assert "в проверенной части" in window.device_detail.toPlainText()
    assert item == original  # presentation never changes saved/raw result


def test_import_error_dialog_opens_its_original_run_without_losing_valid_device(
    window: Any,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    from PySide6.QtWidgets import QDialog, QPushButton, QTableView

    first, _item = _seed(window, tmp_path)
    failed = window.store.create_run(window.project_id)
    window.store.record_error(failed, tmp_path / "missing.cfg", "Synthetic unavailable source")
    window.store.finish_run(failed)
    window._refresh_devices()

    def inspect(dialog: Any) -> int:
        assert dialog.findChild(QTableView).model().rowCount() == 1
        button = next(
            button
            for button in dialog.findChildren(QPushButton)
            if button.text() == "Открыть исходную операцию"
        )
        button.click()
        return 0

    monkeypatch.setattr(QDialog, "exec", inspect)
    window.resource_details.show_import_errors()
    assert window.run_id == failed and window.current_section_id == "reports"
    assert window.device_model.rowCount() == 1
    window.workspace_history.back()
    assert window.run_id == first


def test_no_selection_inspectors_and_empty_error_action_are_safe(window: Any) -> None:
    window.resource_details.show_rule_details()
    window.resource_details.show_device_rule_details()
    window.resource_details.show_device_object_details()
    window.resource_details.show_finding_limitations()
    window.resource_details.show_import_errors()
    assert window.rules_model.rowCount() == 0


def test_multi_selection_does_not_describe_an_arbitrary_first_device(
    window: Any,
    tmp_path: Path,
    qt_app: Any,
) -> None:
    from PySide6.QtCore import QItemSelectionModel

    _run, item = _seed(window, tmp_path)
    other = copy.deepcopy(item)
    other["id"] = "different-source-record"
    other["report"]["device_id"] = "SECOND"
    window.device_model.replace(
        [("FIRST", "ASA", "Device", 1), ("SECOND", "ASA", "Device", 1)], [item, other]
    )
    window.device_table.selectAll()
    qt_app.processEvents()
    assert "Выбрано ресурсов: 2" in window.device_detail.toPlainText()
    assert window.device_rules_model.rowCount() == 0
    assert not window.attach_button.isEnabled()
    assert not window.repeat_button.isEnabled()
    window.device_table.clearSelection()
    window.device_table.selectionModel().select(
        window.device_proxy.mapFromSource(window.device_model.index(0, 0)),
        QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
    )
    assert "R1-DEVICE" in window.device_detail.toPlainText()
    assert window.device_rules_model.rowCount() == 1


def test_unsupported_comware_condition_never_becomes_any_or_all_ports_in_rule_ui(
    window: Any,
    tmp_path: Path,
    qt_app: Any,
) -> None:
    path = tmp_path / "unsupported-comware-qualifier.cfg"
    path.write_text(
        "version 7.1.045\nsysname R1-COMWARE\nacl number 3000\n"
        " rule 0 permit tcp source-port eq 12345\n#\n",
        encoding="utf-8",
    )
    session = analyze_file(path)
    assert isinstance(session, AnalysisSession)
    rule = session.parse_result.rules[0]
    assert rule.match_status.value == "unsupported"
    assert rule.service_status.value == "unsupported"
    assert rule.services[0].resolution_status.value == "known"
    project = window.create_project("Unsupported aggregate condition")
    run = window.store.create_run(project)
    window.store.record_session(run, session)
    window.store.finish_run(run)
    window.load_run(run)
    window.device_table.selectRow(0)
    qt_app.processEvents()
    row = window.device_rules_model.rows[0]
    assert "Любой адрес" not in " ".join(map(str, row))
    assert "все порты" not in " ".join(map(str, row))
    assert "не подтвержден" in " ".join(map(str, row)).lower()
    source_row = next(
        index
        for index, payload in enumerate(window.rules_model.payloads)
        if payload["value"].get("rule_id") == rule.rule_id
    )
    global_row = window.rules_model.rows[source_row]
    assert "Любой адрес" not in " ".join(map(str, global_row))
    assert "все порты" not in " ".join(map(str, global_row))
    window.rules_table.selectRow(
        window.rules_proxy.mapFromSource(window.rules_model.index(source_row, 0)).row()
    )
    detail = window.rule_detail.toPlainText()
    assert "Любой адрес" not in detail and "все порты" not in detail
    assert "Не поддержано" in detail
    assert "TCP" in detail  # retained extracted protocol is still visible
