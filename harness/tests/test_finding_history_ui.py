"""Real SQLite/Qt decision-history rendering and historical finding selection."""

import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QDialog, QTextBrowser, QWidget

from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow

APP = None


@pytest.fixture
def window():
    global APP
    APP = QApplication.instance() or QApplication([])
    directory = Path("artifacts/finding-history-ui") / str(uuid4())
    directory.mkdir(parents=True)
    view = MainWindow(
        store=ProjectStore(directory / "projects.sqlite3"),
        advanced_widget_factory=lambda _sessions, _runner: QWidget(),
    )
    try:
        yield view
    finally:
        view.close()
        view.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        APP.processEvents()


def save_findings(window, name):
    source = window.store.path.parent / f"{name}.cfg"
    source.write_text(
        f"hostname {name}\naccess-list OUTSIDE extended permit ip any any\n"
        "access-group OUTSIDE in interface outside\n",
        encoding="utf-8",
    )
    session = analyze_file(source)
    assert isinstance(session, AnalysisSession)
    run_id = window.store.create_run(window.project_id)
    window.store.record_session(run_id, session)
    window.store.finish_run(run_id)
    finding_id = str(next(f for check in session.report.checks for f in check.findings).finding_id)
    return run_id, finding_id


def select_finding(window, run_id, finding_id):
    window.refresh_findings()
    row = next(
        index
        for index, payload in enumerate(window.finding_model.payloads)
        if payload["item"]["run_id"] == run_id
        and str(payload["finding"]["finding_id"]) == finding_id
    )
    index = window.finding_proxy.mapFromSource(window.finding_model.index(row, 0))
    window.finding_table.selectRow(index.row())
    APP.processEvents()


def capture_dialogs(monkeypatch):
    captured = []

    def execute(dialog):
        browser = dialog.findChild(QTextBrowser, "findingTransitionHistory")
        assert browser is not None
        captured.append((browser.toHtml(), browser.toPlainText()))
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(QDialog, "exec", execute)
    return captured


def test_history_button_reads_persisted_status_and_comment_transitions(window, monkeypatch):
    project = window.create_project("Synthetic decision history")
    run_id, finding_id = save_findings(window, "SYNTHETIC-HISTORY")
    comment = '<script>alert("synthetic")</script><b>literal comment</b>'
    window.store.set_finding_mark(run_id, finding_id, "confirmed", comment)
    window.store.set_finding_mark(run_id, finding_id, "resolved", "Second decision")
    before = window.store.get_run(run_id)
    window.store = ProjectStore(window.store.path)
    window.load_run(run_id)
    select_finding(window, run_id, finding_id)
    dialogs = capture_dialogs(monkeypatch)
    window.finding_history_button.click()
    assert len(dialogs) == 1
    rendered, text = dialogs[0]
    assert comment in text and "Second decision" in text
    assert "Новая → Подтверждена" in text and "Подтверждена → Устранена" in text
    assert "Более ранние переходы неизвестны" not in text
    assert "&lt;script&gt;" in rendered and "&lt;b&gt;literal comment&lt;/b&gt;" in rendered
    assert "<script>" not in rendered and "<b>literal comment</b>" not in rendered
    assert window.store.get_run(run_id) == before
    assert len(window.store.list_finding_transitions(project, run_id, finding_id)) == 2


def test_legacy_baseline_is_displayed_without_manufacturing_prior_events(window, monkeypatch):
    project = window.create_project("Synthetic legacy decision")
    run_id, finding_id = save_findings(window, "SYNTHETIC-LEGACY")
    with sqlite3.connect(window.store.path) as db:
        db.execute(
            "INSERT INTO marks VALUES (?,?,?,?,?)",
            (run_id, finding_id, "accepted_risk", "<b>legacy comment</b>", "2026-01-01T00:00:00Z"),
        )
    window.store = ProjectStore(window.store.path)
    window.load_run(run_id)
    select_finding(window, run_id, finding_id)
    dialogs = capture_dialogs(monkeypatch)
    window.show_finding_history()
    assert len(dialogs) == 1
    html, text = dialogs[0]
    assert "Более ранние переходы неизвестны" in text
    assert "Изменений с момента включения журнала нет" in text
    assert "<b>legacy comment</b>" in text and "&lt;b&gt;legacy comment&lt;/b&gt;" in html
    assert window.store.list_finding_transitions(project) == []


def test_project_findings_open_original_run_history_while_another_run_is_current(
    window, monkeypatch
):
    window.create_project("Synthetic historical selection")
    old_run, old_finding = save_findings(window, "SYNTHETIC-OLD-DEVICE")
    window.store.set_finding_mark(old_run, old_finding, "confirmed", "Old run decision")
    new_run, new_finding = save_findings(window, "SYNTHETIC-NEW-DEVICE")
    window.store.set_finding_mark(new_run, new_finding, "resolved", "New run decision")
    window.load_run(new_run)
    window.finding_scope.setCurrentIndex(window.finding_scope.findData("project"))
    select_finding(window, old_run, old_finding)
    dialogs = capture_dialogs(monkeypatch)
    window.show_finding_history()
    assert window.run_id == new_run
    assert "Old run decision" in dialogs[0][1]
    assert "New run decision" not in dialogs[0][1]
    window.load_run(old_run)
    window.finding_scope.setCurrentIndex(window.finding_scope.findData("run"))
    select_finding(window, old_run, old_finding)
    window.show_finding_history()
    assert dialogs[1][1] == dialogs[0][1]


def test_no_selection_does_not_open_dialog_or_add_events(window, monkeypatch):
    project = window.create_project("Synthetic no selection")
    run_id, _ = save_findings(window, "SYNTHETIC-UNSELECTED")
    window.load_run(run_id)
    window.finding_table.clearSelection()
    dialogs = capture_dialogs(monkeypatch)
    window.show_finding_history()
    assert not dialogs and window.store.list_finding_transitions(project) == []


def test_stale_foreign_finding_selection_is_rejected_without_cross_project_dialog(
    window, monkeypatch
):
    first_project = window.create_project("Synthetic first project")
    first_run, finding_id = save_findings(window, "SYNTHETIC-PRIVATE-FIRST")
    window.store.set_finding_mark(first_run, finding_id, "confirmed", "First project comment")
    window.load_run(first_run)
    foreign = next(
        payload
        for payload in window.finding_model.payloads
        if str(payload["finding"]["finding_id"]) == finding_id
    )
    second_project = window.create_project("Synthetic second project")
    monkeypatch.setattr(window, "_selected_payloads", lambda *_args: [foreign])
    dialogs = capture_dialogs(monkeypatch)
    window.show_finding_history()
    assert window.project_id == second_project and first_project != second_project
    assert not dialogs and "Не удалось прочитать историю" in window.progress_label.text()
    assert window.store.list_finding_transitions(second_project) == []
