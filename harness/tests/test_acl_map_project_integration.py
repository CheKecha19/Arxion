"""Project ACL-map persistence/batch and Qt worker isolation on synthetic captures."""

import time
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QApplication, QWidget

from firewall_compliance.application.acl_map_store import AclMapStore
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow

APP = None
COMWARE = """version 7.1.045
sysname SYNTHETIC-MAP-{index}
acl number 3000
 rule 10 permit tcp source any destination 198.51.100.10 0 destination-port eq 443 logging
 rule 20 deny ip source any destination any
#
"""


@pytest.fixture
def captured():
    directory = (
        Path(__file__).resolve().parents[2] / "artifacts" / "acl-map-project-tests" / uuid4().hex
    )
    directory.mkdir(parents=True)
    store = ProjectStore(directory / "project.sqlite3")
    project = store.create_project("Synthetic map project")
    run = store.create_run(project)
    items, sessions = [], []
    for index in range(2):
        path = directory / f"synthetic-{index}.cfg"
        path.write_text(COMWARE.format(index=index), encoding="utf-8")
        session = analyze_file(path)
        assert isinstance(session, AnalysisSession)
        items.append(store.record_session(run, session))
        sessions.append(session)
    missing = store.record_error(run, directory / "unreadable.cfg", "Synthetic input failure")
    cancelled = store.record_cancelled(run, directory / "cancelled.cfg")
    store.finish_run(run)
    return store, directory, project, run, items, sessions, missing, cancelled


def wait(window, predicate):
    deadline = time.monotonic() + 12
    while not predicate():
        APP.processEvents()
        window.poll_jobs()
        if time.monotonic() >= deadline:
            raise AssertionError(
                window.acl_map_saved_status.text() + window.acl_map_batch_status.toPlainText()
            )
        time.sleep(0.005)
    APP.processEvents()


def close(window):
    window.close()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    APP.processEvents()


@pytest.fixture
def window(captured):
    global APP
    APP = QApplication.instance() or QApplication([])
    result = MainWindow(store=captured[0], advanced_widget_factory=lambda *_: QWidget())
    result.load_run(captured[3])
    wait(
        result,
        lambda: result.acl_map_batch_items.count() == 4 and result.acl_map_save_button.isEnabled(),
    )
    yield result
    close(result)


def test_store_batch_preserves_exact_captures_failures_and_old_run(captured, monkeypatch):
    store, _, project, run, items, sessions, missing, cancelled = captured
    before = store.get_run(run)
    monkeypatch.setattr(FileSourceReader, "read", lambda *_: pytest.fail("Batch reread source"))
    batch, identifiers = store.save_acl_map_batch(project, run)
    assert len(batch.items) == len(identifiers) == 2
    assert {failure.input_reference for failure in batch.failures} == {missing, cancelled}
    assert {issue.code for failure in batch.failures for issue in failure.diagnostics} == {
        "IMPORT_ERROR",
        "IMPORT_CANCELLED",
    }
    assert store.get_run(run) == before
    for item, session, identifier in zip(items, sessions, identifiers, strict=True):
        assert store.get_acl_map(project, identifier).revision == session.revision
        record = next(row for row in store.list_acl_maps(project) if row["map_id"] == identifier)
        assert record["run_id"] == run and record["item_id"] == item
    reopened = ProjectStore(store.path)
    assert len(reopened.list_acl_maps(project)) == 2
    other = store.create_project("Unrelated project")
    assert reopened.list_acl_maps(other) == []
    with pytest.raises(KeyError):
        reopened.get_acl_map(other, identifiers[0])


def test_store_selected_batch_and_invalid_scope_are_explicit(captured):
    store, _, project, run, items, _, missing, _ = captured
    batch, identifiers = store.save_acl_map_batch(project, run, item_ids=(items[1], missing))
    assert [item.input_reference for item in batch.items] == [items[1]]
    assert [failure.input_reference for failure in batch.failures] == [missing]
    assert len(identifiers) == 1
    for selection in ((), ("missing",), (items[0], items[0])):
        with pytest.raises(ValueError):
            store.save_acl_map_batch(project, run, item_ids=selection)
    with pytest.raises(ValueError):
        store.save_acl_map_batch(store.create_project("Other"), run)
    running = store.create_run(project)
    with pytest.raises(ValueError):
        store.save_acl_map_batch(project, running)
    store.finish_run(running)
    empty, identifiers = store.save_acl_map_batch(project, running)
    assert not empty.items and not identifiers
    assert empty.failures[0].code == "RUN_EMPTY"


def test_batch_storage_rolls_back_all_maps_when_write_fails(captured, monkeypatch):
    store, _, project, run, *_ = captured
    original = AclMapStore.save
    calls = []

    def failing(repository, *args, **kwargs):
        calls.append(True)
        if len(calls) == 2:
            raise ValueError("Synthetic second write failure")
        return original(repository, *args, **kwargs)

    monkeypatch.setattr(AclMapStore, "save", failing)
    with pytest.raises(ValueError):
        store.save_acl_map_batch(project, run)
    assert store.list_acl_maps(project) == []


def test_qt_save_load_and_restart_keep_original_graph_and_run_item(window, captured, monkeypatch):
    store, _, project, run, items, _, _, _ = captured
    original = window._map_analysis_state.graph
    assert original is not None
    selected = window.map_result_selector.currentData()
    window.acl_map_save_button.click()
    wait(window, lambda: not window._acl_map_busy and window.acl_map_saved_selector.count() == 1)
    identifier = window.acl_map_saved_selector.currentData()
    record = store.list_acl_maps(project)[0]
    assert record["run_id"] == run and record["item_id"] == selected
    monkeypatch.setattr(FileSourceReader, "read", lambda *_: pytest.fail("Saved map reread source"))
    window.map_result_selector.setCurrentIndex(window.map_result_selector.findData(items[1]))
    window.acl_map_load_button.click()
    wait(window, lambda: window._acl_map_loaded_record is not None)
    assert window.map_widget.state.graph == original
    assert window.map_mode_selector.currentData() == "policy"
    assert window.map_result_selector.currentData() is None
    assert window._selected_acl_map_scope() == (run, selected)
    window.acl_map_save_button.click()
    wait(window, lambda: not window._acl_map_busy)
    assert len(store.list_acl_maps(project)) == 1
    reopened = MainWindow(
        store=ProjectStore(store.path), advanced_widget_factory=lambda *_: QWidget()
    )
    try:
        wait(reopened, lambda: reopened.acl_map_saved_selector.count() == 1)
        assert reopened.acl_map_saved_selector.currentData() == identifier
        reopened.acl_map_load_button.click()
        wait(reopened, lambda: reopened._acl_map_loaded_record is not None)
        assert reopened.map_widget.state.graph == original
    finally:
        close(reopened)


def test_qt_batch_selected_then_all_displays_failures_and_saved_maps(window, captured):
    store, _, project, run, items, _, missing, cancelled = captured
    window.acl_map_batch_items.clearSelection()
    for index in range(window.acl_map_batch_items.count()):
        row = window.acl_map_batch_items.item(index)
        if row.data(Qt.ItemDataRole.UserRole) == items[0]:
            row.setSelected(True)
    window.acl_map_batch_selected_button.click()
    wait(window, lambda: not window._acl_map_busy and len(store.list_acl_maps(project)) == 1)
    assert len(window._acl_map_batch_result.items) == 1
    window.acl_map_batch_all_button.click()
    wait(window, lambda: not window._acl_map_busy and len(store.list_acl_maps(project)) == 3)
    batch = window._acl_map_batch_result
    assert {failure.input_reference for failure in batch.failures} == {missing, cancelled}
    text = window.acl_map_batch_status.toPlainText()
    assert run in text and "Отказов: 2" in text
    assert "IMPORT_ERROR" in text and "IMPORT_CANCELLED" in text
    assert window.analysis_result_selector.count() == 0


@pytest.mark.parametrize("operation", ["save", "load", "batch"])
def test_project_switch_ignores_stale_map_callbacks(window, captured, monkeypatch, operation):
    store, _, project, _, *_ = captured
    if operation == "load":
        window.acl_map_save_button.click()
        wait(
            window, lambda: not window._acl_map_busy and window.acl_map_saved_selector.count() == 1
        )
    started, release = Event(), Event()
    method = {"save": "save_acl_map", "load": "get_acl_map", "batch": "save_acl_map_batch"}[
        operation
    ]
    original = getattr(store, method)

    def paused(*args, **kwargs):
        started.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, method, paused)
    {
        "save": window.acl_map_save_button,
        "load": window.acl_map_load_button,
        "batch": window.acl_map_batch_all_button,
    }[operation].click()
    wait(window, started.is_set)
    other = window.create_project("Fresh empty project")
    assert other != project
    release.set()
    wait(window, lambda: window.runner.pending_count == 0 and window.runner.running_count == 0)
    window.poll_jobs()
    assert window.project_id == other
    assert window._map_analysis_state.graph is None
    assert window.acl_map_saved_selector.count() == 0
    assert window._acl_map_loaded_record is None
    assert window._acl_map_batch_result is None
    assert store.list_acl_maps(other) == []


def test_only_failed_items_produce_explicit_zero_map_result(window, captured):
    store, _, project, _, _, _, missing, _ = captured
    window.acl_map_batch_items.clearSelection()
    for index in range(window.acl_map_batch_items.count()):
        row = window.acl_map_batch_items.item(index)
        if row.data(Qt.ItemDataRole.UserRole) == missing:
            row.setSelected(True)
    window.acl_map_batch_selected_button.click()
    wait(window, lambda: not window._acl_map_busy and window._acl_map_batch_result is not None)
    assert not window._acl_map_batch_result.items
    assert not store.list_acl_maps(project)
    assert "Карты не построены" in window.acl_map_batch_status.toPlainText()


@pytest.mark.parametrize("operation", ["save", "batch", "load"])
def test_queued_map_job_cancellation_recovers_controls(window, captured, operation):
    store, _, project, *_ = captured
    if operation == "load":
        window.acl_map_save_button.click()
        wait(
            window, lambda: not window._acl_map_busy and window.acl_map_saved_selector.count() == 1
        )
    wait(window, lambda: window.runner.running_count == 0 and window.runner.pending_count == 0)
    started, release = Event(), Event()

    def blocking():
        started.set()
        assert release.wait(10)

    window.runner.submit(blocking, lambda *_: None)
    wait(window, started.is_set)
    button = {
        "save": window.acl_map_save_button,
        "batch": window.acl_map_batch_all_button,
        "load": window.acl_map_load_button,
    }[operation]
    button.click()
    window.cancel_pending()
    window.poll_jobs()
    assert not window._acl_map_busy
    assert (
        "отменен" in window.acl_map_saved_status.text().replace("ё", "е").lower()
        or "отменено" in window.acl_map_batch_status.toPlainText()
    )
    release.set()
    wait(window, lambda: window.runner.running_count == 0 and window.runner.pending_count == 0)
    assert len(store.list_acl_maps(project)) == (1 if operation == "load" else 0)
    button.click()
    if operation == "load":
        wait(window, lambda: window._acl_map_loaded_record is not None)
    else:
        wait(window, lambda: not window._acl_map_busy and len(store.list_acl_maps(project)) > 0)


def test_failed_map_load_preserves_current_map(window, captured, monkeypatch):
    window.acl_map_save_button.click()
    wait(window, lambda: not window._acl_map_busy and window.acl_map_saved_selector.count() == 1)
    original = window.map_widget.state.graph

    def failed(*_):
        raise ValueError("Synthetic damaged stored map")

    monkeypatch.setattr(captured[0], "get_acl_map", failed)
    window.acl_map_load_button.click()
    wait(window, lambda: "повреждена" in window.acl_map_saved_status.text())
    assert window.map_widget.state.graph == original
    assert window._acl_map_loaded_record is None
