"""Real Qt/SQLite general-result save, isolation and export without source rereads."""

import json
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Signal
from PySide6.QtWidgets import QApplication, QFileDialog, QPushButton, QWidget

from firewall_compliance.analysis.route_selection import select_route
from firewall_compliance.domain.enums import Protocol
from firewall_compliance.domain.reachability import ReachabilityQuery
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.interfaces.desktop import analysis_result_adapter
from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.jobs import JobError, JobStatus
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow
from firewall_compliance.interfaces.desktop.qt_network import (
    NetworkFactsSnapshot,
    NetworkQuerySnapshot,
)

APP = None


class NetworkPanel(QWidget):
    query_result_changed = Signal(object)

    def set_project_context(self, project_id):
        self.project_id = project_id
        self.query_result_changed.emit(None)


@pytest.fixture
def scene():
    global APP
    APP = QApplication.instance() or QApplication([])
    directory = Path("artifacts/analysis-result-ui") / str(uuid4())
    directory.mkdir(parents=True)
    source = directory / "synthetic.txt"
    source.write_text(
        "hostname SYNTHETIC-REPORT\n"
        "access-list OUTSIDE extended permit ip any any\n"
        "access-group OUTSIDE in interface outside\n",
        encoding="utf-8",
    )
    session = analyze_file(source)
    assert isinstance(session, AnalysisSession)
    store = ProjectStore(directory / "projects.sqlite3")
    window = MainWindow(store=store, advanced_widget_factory=lambda *_: NetworkPanel())
    project = window.create_project("Synthetic result project")
    run = store.create_run(project)
    store.record_session(run, session)
    store.finish_run(run)
    window.load_run(run)
    wait(window, lambda: window.save_run_analysis_button.isEnabled())
    yield window, directory, session, project, run
    window.close()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    APP.processEvents()


def wait(window, predicate):
    deadline = time.monotonic() + 10
    while not predicate():
        APP.processEvents()
        window.poll_jobs()
        if time.monotonic() >= deadline:
            raise AssertionError(window.progress_label.text())
        time.sleep(0.005)
    APP.processEvents()


def save_run(window):
    window.save_run_analysis_button.click()
    wait(window, lambda: window.analysis_result_export_buttons["json"].isEnabled())
    return window._analysis_result_active


def network_snapshot(session, project):
    revision = session.revision
    request = ReachabilityQuery(
        revision_id=revision.revision_id,
        device_id=revision.device.device_id,
        ingress_interface_id="outside",
        source_ip="198.51.100.1",
        destination_ip="192.0.2.1",
        protocol=Protocol.TCP,
        destination_port=443,
    )
    now = datetime.now(UTC)
    return NetworkQuerySnapshot(
        NetworkFactsSnapshot(revision, None, None),
        "legacy",
        request,
        select_route(revision, request),
        1,
        project_reference=project,
        started_at=now,
        finished_at=now,
    )


def test_policy_result_saved_selected_and_reopened_with_old_reports_intact(scene):
    window, _, _, project, run = scene
    assert window.report_tabs.tabText(0) == "Отчёт запуска"
    assert window.report_tabs.tabText(1) == "Общие результаты"
    assert window.report_run.currentData() == run
    assert not window.save_network_analysis_button.isEnabled()
    result = save_run(window)
    assert result.project_reference == project and result.run_reference == run
    assert window.report_tabs.currentIndex() == 1
    assert window.analysis_result_selector.currentData() == str(result.analysis_id)
    assert result.sources[0].source_name in window.analysis_result_summary.toPlainText()
    assert result.sources[0].content_sha256 in window.analysis_result_summary.toPlainText()
    assert "SHA-256" in window.analysis_result_summary.toPlainText()
    assert "не является" in window.analysis_result_summary.toPlainText()
    assert len(window.store.list_runs(project)) == 1
    reopened = MainWindow(
        store=ProjectStore(window.store.path), advanced_widget_factory=lambda *_: NetworkPanel()
    )
    try:
        wait(reopened, lambda: reopened._analysis_result_active is not None)
        assert reopened._analysis_result_active == result
        assert reopened.report_run.currentData() == run
        assert reopened.analysis_result_export_buttons["csv"].isEnabled()
    finally:
        reopened.close()
        reopened.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_cached_json_csv_html_export_does_not_read_source_or_rerun_checks(scene, monkeypatch):
    window, directory, _, _, _ = scene
    result = save_run(window)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("export reread source or replayed checks")

    monkeypatch.setattr(FileSourceReader, "read", forbidden)
    monkeypatch.setattr(analysis_result_adapter, "analysis_from_run", forbidden)
    from firewall_compliance.application import analysis_result

    monkeypatch.setattr(analysis_result, "replay_policy", forbidden)
    for format_name in ("json", "csv", "html"):
        path = directory / ("saved." + format_name)
        window.export_analysis_result(format_name, path)
        assert path.is_file() and path.stat().st_size > 100
    saved = json.loads((directory / "saved.json").read_text(encoding="utf-8"))
    assert saved["analysis_id"] == str(result.analysis_id)
    assert saved["components"][0]["kind"] == "policy"
    assert "policy" in (directory / "saved.csv").read_text(encoding="utf-8")
    assert "SHA" in (directory / "saved.html").read_text(encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_: ("", ""))
    window.export_analysis_result("json")


@pytest.mark.parametrize("failed", [False, True])
def test_network_capture_requires_current_project_and_preserves_partial_or_failed(scene, failed):
    window, _, session, project, _ = scene
    snapshot = network_snapshot(session, project)
    if failed:
        snapshot = replace(snapshot, result=JobError("synthetic", "Synthetic calculation failed"))
    window.advanced_panel.query_result_changed.emit(replace(snapshot, project_reference="foreign"))
    assert not window.save_network_analysis_button.isEnabled()
    window.advanced_panel.query_result_changed.emit(snapshot)
    assert window.save_network_analysis_button.isEnabled()
    assert not window.store.list_analysis_results(project)
    window.save_network_analysis_button.click()
    wait(window, lambda: window._analysis_result_active is not None)
    result = window._analysis_result_active
    assert result.project_reference == project and result.run_reference is None
    assert result.state == ("failed" if failed else "partial")
    assert result.components[0].kind == ("attempt" if failed else "route")
    assert len(window.store.list_runs(project)) == 1
    other = window.create_project("Other synthetic project")
    wait(window, lambda: not window.analysis_result_selector.count())
    assert window.advanced_panel.project_id == other
    assert window._analysis_network_snapshot is None
    assert not window.save_network_analysis_button.isEnabled()
    assert not any(button.isEnabled() for button in window.analysis_result_export_buttons.values())
    window.advanced_panel.query_result_changed.emit(snapshot)
    assert window._analysis_network_snapshot is None
    assert not window.store.list_analysis_results(other)


def test_late_save_stays_in_original_project_and_does_not_replace_new_project_selection(
    scene, monkeypatch
):
    window, _, _, first, _ = scene
    entered, release = Event(), Event()
    original = analysis_result_adapter.analysis_from_run

    def delayed(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(analysis_result_adapter, "analysis_from_run", delayed)
    window.save_run_analysis_button.click()
    wait(window, entered.is_set)
    other = window.create_project("Different project during save")
    release.set()
    wait(window, lambda: not window._analysis_result_busy)
    wait(window, lambda: window.runner.pending_count == 0 and window.runner.running_count == 0)
    window.poll_jobs()
    assert len(window.store.list_analysis_results(first)) == 1
    assert not window.store.list_analysis_results(other)
    assert window._analysis_result_active is None
    assert not window.analysis_result_selector.count()
    window.refresh_projects(first)
    wait(window, lambda: window._analysis_result_active is not None)
    assert window._analysis_result_active.project_reference == first


def test_corrupt_saved_result_disables_export_and_save_errors_are_safe(scene, monkeypatch):
    window, _, _, _, _ = scene
    save_run(window)

    def invalid(*_):
        raise ValueError("SENSITIVE INTERNAL DETAIL")

    monkeypatch.setattr(window.store, "list_analysis_results", invalid)
    window._refresh_analysis_results()
    wait(window, lambda: "Не удалось прочитать список" in window.progress_label.text())
    assert not window.analysis_result_selector.count()
    assert not any(button.isEnabled() for button in window.analysis_result_export_buttons.values())
    assert "SENSITIVE" not in window.progress_label.text()
    monkeypatch.setattr(analysis_result_adapter, "analysis_from_run", invalid)
    window.save_run_analysis_button.click()
    wait(window, lambda: not window._analysis_result_busy)
    assert "Не удалось сохранить" in window.progress_label.text()
    assert "SENSITIVE" not in window.progress_label.text()
    assert window.report_run.currentData() == window.run_id


def test_original_batch_buttons_remain_available(scene, monkeypatch):
    window, _, _, _, _ = scene
    called = []
    monkeypatch.setattr(window, "export_batch", called.append)
    window.report_tabs.setCurrentIndex(0)
    for text, format_name in (("Сохранить HTML", "html"), ("Сохранить JSON", "json")):
        button = next(
            button for button in window.findChildren(QPushButton) if button.text() == text
        )
        button.click()
        assert called[-1] == format_name


@pytest.mark.parametrize("network", [False, True])
def test_canceling_queued_common_save_clears_busy_and_allows_retry(scene, network):
    window, _, session, project, _ = scene
    wait(window, lambda: window.runner.pending_count == 0 and window.runner.running_count == 0)
    if network:
        window.advanced_panel.query_result_changed.emit(network_snapshot(session, project))
    button = window.save_network_analysis_button if network else window.save_run_analysis_button
    assert button.isEnabled()
    entered, release = Event(), Event()

    def block_worker():
        entered.set()
        assert release.wait(10)

    blocker = window.runner.submit(block_worker, lambda _: None)
    try:
        wait(window, entered.is_set)
        assert window.runner.status(blocker) == JobStatus.RUNNING
        button.click()
        identifier = window._analysis_result_save_id
        assert identifier is not None
        assert window.runner.status(identifier) == JobStatus.PENDING
        assert window._analysis_result_busy and not button.isEnabled()

        window.cancel_pending()
        window.poll_jobs()

        assert window.runner.status(identifier) == JobStatus.CANCELED
        assert window._analysis_result_save_id is None
        assert not window._analysis_result_busy
        assert button.isEnabled()
        assert not window.store.list_analysis_results(project)
        assert window._analysis_result_active is None
        assert "отменено до запуска" in window.progress_label.text()
    finally:
        release.set()
    wait(window, lambda: window.runner.pending_count == 0 and window.runner.running_count == 0)

    button.click()
    wait(window, lambda: window._analysis_result_active is not None)

    assert len(window.store.list_analysis_results(project)) == 1
    assert not window._analysis_result_busy and window._analysis_result_save_id is None
    assert button.isEnabled()
    assert window._analysis_result_active.components[0].kind == ("route" if network else "policy")


def test_cancel_pending_does_not_cancel_running_common_save(scene, monkeypatch):
    window, _, _, project, _ = scene
    wait(window, lambda: window.runner.pending_count == 0 and window.runner.running_count == 0)
    original = analysis_result_adapter.analysis_from_run
    entered, release = Event(), Event()
    calls = []

    def delayed(*arguments):
        calls.append(arguments)
        entered.set()
        assert release.wait(10)
        return original(*arguments)

    monkeypatch.setattr(analysis_result_adapter, "analysis_from_run", delayed)
    try:
        window.save_run_analysis_button.click()
        wait(window, entered.is_set)
        identifier = window._analysis_result_save_id
        assert identifier is not None
        assert window.runner.status(identifier) == JobStatus.RUNNING

        window.cancel_pending()
        window.poll_jobs()

        assert window.runner.status(identifier) == JobStatus.RUNNING
        assert window._analysis_result_save_id == identifier
        assert window._analysis_result_busy
        assert not window.save_run_analysis_button.isEnabled()
        assert not window.store.list_analysis_results(project)
    finally:
        release.set()
    wait(window, lambda: window._analysis_result_active is not None)

    assert window.runner.status(identifier) == JobStatus.COMPLETED
    assert len(calls) == 1
    assert len(window.store.list_analysis_results(project)) == 1
    assert not window._analysis_result_busy and window._analysis_result_save_id is None
    assert window.save_run_analysis_button.isEnabled()
