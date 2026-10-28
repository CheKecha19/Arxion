"""Synthetic SQLite/Qt control assessment history, isolation and worker boundaries."""

import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
from test_control_assessment import AT, assess, profile, source_result

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QApplication, QFileDialog, QWidget

from firewall_compliance.application.control_assessment import ControlAssessment
from firewall_compliance.domain.controls import ControlRequirement
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.interfaces.desktop import qt_controls
from firewall_compliance.interfaces.desktop.control_assessment_store import ControlAssessmentStore
from firewall_compliance.interfaces.desktop.organization_backup import create_workspace_backup
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow
from firewall_compliance.interfaces.desktop.qt_controls import ControlsPanel


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    if os.name == "nt" and not QFontDatabase.families():
        font = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "arial.ttf"
        assert QFontDatabase.addApplicationFont(str(font)) >= 0
    yield instance


@pytest.fixture
def scene():
    directory = (
        Path(__file__).resolve().parents[2] / "artifacts" / "controls-project-ui" / uuid4().hex
    )
    directory.mkdir(parents=True)
    store = ProjectStore(directory / "projects.sqlite3")
    project = store.create_project("Synthetic technical controls")
    source = source_result().model_copy(update={"project_reference": project})
    store.save_analysis_result(project, source)
    result = assess(source)
    repository = ControlAssessmentStore(store.path)
    return directory, store, project, source, result, repository


@pytest.fixture
def panel(app, scene):
    _, store, project, *_ = scene
    widget = ControlsPanel(store)
    widget.set_project_context(project)
    wait(widget, lambda: not widget._busy and widget.source_selector.count() == 1)
    yield widget
    widget.shutdown()
    widget.close()
    widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


def wait(widget, predicate):
    deadline = time.monotonic() + 15
    while not predicate():
        QApplication.processEvents()
        widget.poll_jobs()
        if time.monotonic() >= deadline:
            raise AssertionError(widget.status_label.text())
        time.sleep(0.005)
    QApplication.processEvents()


def choose_profile(widget, directory, *, selected=None):
    path = directory / f"profile-{uuid4().hex}.json"
    path.write_text((selected or profile()).model_dump_json(), encoding="utf-8-sig")
    widget.load_profile_path(path)
    wait(widget, lambda: not widget._busy and widget.profile is not None)
    return path


def evaluate(widget, directory):
    choose_profile(widget, directory)
    widget.evaluate_current(assessed_at=AT + timedelta(hours=2))
    wait(widget, lambda: not widget._busy and widget.active_assessment is not None)
    return widget.active_assessment


def test_store_exact_project_snapshot_reopens_without_creating_runs(scene):
    _, store, project, source, result, repository = scene
    identifier = repository.save(project, result)
    reopened = ControlAssessmentStore(store.path)
    assert reopened.get(project, identifier) == result
    metadata = reopened.list(project)
    assert metadata[0]["analysis_id"] == str(source.analysis_id)
    assert metadata[0]["profile_id"] == result.profile.profile_id
    assert metadata[0]["profile_version"] == result.profile.version
    assert metadata[0]["coverage"]["violations"] == 1
    assert not store.list_runs(project)
    with store._connect() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1


def test_save_identical_is_idempotent_and_different_payload_same_id_is_rejected(scene):
    _, store, project, _, result, repository = scene
    identifier = repository.save(project, result)
    with store._connect() as db:
        before = tuple(db.execute("SELECT * FROM control_assessments").fetchone())
    assert repository.save(project, result) == identifier
    changed = result.model_copy(update={"assessed_at": result.assessed_at + timedelta(seconds=1)})
    with pytest.raises(ValueError, match="different"):
        repository.save(project, changed)
    with store._connect() as db:
        assert tuple(db.execute("SELECT * FROM control_assessments").fetchone()) == before


def test_source_must_already_be_persisted_exactly_in_same_project(scene):
    _, store, project, source, result, repository = scene
    missing = source.model_copy(update={"analysis_id": uuid4()})
    with pytest.raises(ValueError, match="already"):
        repository.save(project, result.model_copy(update={"source": missing}))
    changed = source.model_copy(update={"application_version": "synthetic-different-version"})
    with pytest.raises(ValueError, match="does not equal"):
        repository.save(project, result.model_copy(update={"source": changed}))
    other = store.create_project("Other synthetic project")
    with pytest.raises(ValueError):
        repository.save(other, result)
    assert repository.list(other) == []


def test_get_is_project_scoped_even_with_valid_assessment_uuid(scene):
    _, store, project, _, result, repository = scene
    identifier = repository.save(project, result)
    other = store.create_project("Other synthetic project")
    with pytest.raises(KeyError):
        repository.get(other, identifier)
    with pytest.raises(KeyError):
        repository.list(str(uuid4()))


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_stored_assessment_has_append_only_triggers(scene, operation):
    _, store, project, _, result, repository = scene
    repository.save(project, result)
    query = (
        "UPDATE control_assessments SET assessed_at=assessed_at"
        if operation == "UPDATE"
        else "DELETE FROM control_assessments"
    )
    with store._connect() as db, pytest.raises(sqlite3.IntegrityError):
        db.execute(query)
    assert repository.get(project, str(result.assessment_id)) == result


@pytest.mark.parametrize(
    "field", ["payload", "project_id", "analysis_id", "created_at", "assessed_at"]
)
def test_tampered_payload_or_identity_is_not_trusted_by_get_or_list(scene, field):
    _, store, project, _, result, repository = scene
    repository.save(project, result)
    with store._connect() as db:
        db.execute("DROP TRIGGER control_assessments_no_update")
        value = "{}" if field == "payload" else "tampered"
        if field == "project_id":
            value = store.create_project("Synthetic tampered project")
        if field == "analysis_id":
            another = source_result().model_copy(update={"project_reference": project})
            store.save_analysis_result(project, another)
            value = str(another.analysis_id)
        db.execute(f"UPDATE control_assessments SET {field}=?", (value,))
    target = value if field == "project_id" else project
    with pytest.raises(ValueError, match="checksum"):
        repository.get(target, str(result.assessment_id))
    with pytest.raises(ValueError, match="checksum"):
        repository.list(target)


def test_saved_source_checksum_is_rechecked_on_assessment_read(scene):
    _, store, project, _, result, repository = scene
    repository.save(project, result)
    with store._connect() as db:
        db.execute("DROP TRIGGER analysis_results_no_update")
        db.execute("UPDATE analysis_results SET payload=payload || ' '")
    with pytest.raises(ValueError, match="source analysis checksum"):
        repository.get(project, str(result.assessment_id))


def test_concurrent_identical_saves_return_same_immutable_assessment(scene):
    _, _, project, _, result, repository = scene
    with ThreadPoolExecutor(max_workers=2) as executor:
        identifiers = list(executor.map(lambda _: repository.save(project, result), range(2)))
    assert identifiers == [str(result.assessment_id)] * 2
    assert len(repository.list(project)) == 1


def test_workspace_backup_preserves_assessment_and_exact_source(scene):
    directory, store, project, source, result, repository = scene
    repository.save(project, result)
    backup = directory / "controls-backup.sqlite3"
    create_workspace_backup(store.path, backup)
    restored = ControlAssessmentStore(backup)
    assert restored.get(project, str(result.assessment_id)) == result
    assert ProjectStore(backup).get_analysis_result(project, str(source.analysis_id)) == source


def test_store_rejects_newer_database_version_and_never_creates_missing_file(scene):
    directory, store, *_ = scene
    with store._connect() as db:
        db.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="Unsupported"):
        ControlAssessmentStore(store.path)
    missing = directory / "must-not-be-created.sqlite3"
    with pytest.raises(sqlite3.OperationalError):
        ControlAssessmentStore(missing)
    assert not missing.exists()


def test_panel_requires_explicit_profile_and_does_not_autoapprove(panel, scene):
    directory, _, _, _, _, repository = scene
    assert panel.profile is None
    assert not panel.evaluate_button.isEnabled()
    assert not any(button.isEnabled() for button in panel.export_buttons.values())
    selected = profile(
        "TECH-BROAD-ALLOW", "TECH-POLICY-LOGGING", "TECH-ADMIN-SOURCES", "TECH-POLICY-COMMENTS"
    )
    selected = selected.model_copy(
        update={
            "requirements": (
                *selected.requirements[:3],
                ControlRequirement(
                    control_id="TECH-POLICY-COMMENTS",
                    applicable=False,
                    justification="Explicit approved synthetic scope",
                ),
            )
        }
    )
    choose_profile(panel, directory, selected=selected)
    assert panel.evaluate_button.isEnabled()
    assert "не означает" in panel.profile_label.text()
    assert repository.list(panel.project_id) == []
    panel.evaluate_current(assessed_at=AT + timedelta(hours=2))
    wait(panel, lambda: not panel._busy and panel.active_assessment is not None)
    value = panel.active_assessment
    assert {row.state for row in value.evaluations} == {
        "technical_violation",
        "no_violation_in_examined_scope",
        "insufficient_evidence",
        "not_applicable",
    }
    assert (
        "Недостаточно" in panel.summary_label.text() or "недостаточно" in panel.summary_label.text()
    )
    assert str(value.source.analysis_id) in panel.summary_label.text()
    assert value.profile.version in panel.summary_label.text()


def test_panel_history_reopens_from_sqlite_without_current_profile(panel, scene, app):
    directory, store, project, *_ = scene
    value = evaluate(panel, directory)
    reopened = ControlsPanel(ProjectStore(store.path))
    try:
        reopened.set_project_context(project)
        wait(reopened, lambda: not reopened._busy and reopened.active_assessment is not None)
        assert reopened.active_assessment == value
        assert reopened.profile is None
        assert not reopened.evaluate_button.isEnabled()
        assert all(button.isEnabled() for button in reopened.export_buttons.values())
    finally:
        reopened.shutdown()
        reopened.close()
        reopened.deleteLater()
        app.processEvents()


@pytest.mark.parametrize("format_name", ["json", "csv", "html"])
def test_panel_export_uses_immutable_current_assessment_without_source_reread(
    panel, scene, monkeypatch, format_name
):
    directory, *_ = scene
    original = evaluate(panel, directory)

    def forbidden(*_):
        raise AssertionError("Unexpected source read or reanalysis")

    monkeypatch.setattr(FileSourceReader, "read", forbidden)
    monkeypatch.setattr(qt_controls, "assess_controls", forbidden)
    selected = profile().model_copy(update={"version": "new-current-profile"})
    choose_profile(panel, directory, selected=selected)
    assert panel.active_assessment == original
    monkeypatch.setattr(qt_controls, "_read", forbidden)
    output = directory / f"historical.{format_name}"
    panel.export_current(output, format_name)
    wait(panel, lambda: not panel._busy)
    text = output.read_text(encoding="utf-8")
    assert "technical_violation" in text
    if format_name == "json":
        restored = ControlAssessment.model_validate_json(text)
        assert restored == original and restored.profile.version == "1"
    else:
        assert "new-current-profile" not in text


@pytest.mark.parametrize("protected", ["database", "profile"])
def test_panel_export_rejects_hardlink_to_database_or_loaded_profile(panel, scene, protected):
    directory, store, *_ = scene
    evaluate(panel, directory)
    source = store.path if protected == "database" else panel._profile_path
    original = source.read_bytes()
    output = directory / "dangerous-output.json"
    os.link(source, output)
    panel.export_current(output, "json")
    wait(panel, lambda: not panel._busy)
    assert source.read_bytes() == original
    assert "не выполнена" in panel.status_label.text()


def test_project_switch_during_worker_cannot_save_or_show_foreign_result(panel, scene, monkeypatch):
    directory, store, project, _, _, repository = scene
    choose_profile(panel, directory)
    entered, release = Event(), Event()
    original = qt_controls.assess_controls

    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(qt_controls, "assess_controls", delayed)
    panel.evaluate_current(assessed_at=AT + timedelta(hours=2))
    wait(panel, entered.is_set)
    other = store.create_project("Different synthetic project")
    try:
        panel.set_project_context(other)
    finally:
        release.set()
    wait(
        panel,
        lambda: (
            not panel._busy and panel.runner.running_count == 0 and panel.runner.pending_count == 0
        ),
    )
    panel.poll_jobs()
    assert panel.active_assessment is None
    assert panel.profile is None
    assert panel.source_selector.count() == 0
    assert panel.assessment_selector.count() == 0
    assert repository.list(other) == []
    assert repository.list(project) == []


def test_cancel_queued_evaluation_does_not_persist_and_allows_retry(panel, scene):
    directory, _, project, _, _, repository = scene
    choose_profile(panel, directory)
    entered, release = Event(), Event()

    def block():
        entered.set()
        assert release.wait(10)

    panel.runner.submit(block, lambda _: None)
    wait(panel, entered.is_set)
    try:
        panel.evaluate_current(assessed_at=AT + timedelta(hours=2))
        assert panel._busy
        panel.cancel_current()
        assert not panel._busy and panel.evaluate_button.isEnabled()
    finally:
        release.set()
    wait(panel, lambda: panel.runner.running_count == 0 and panel.runner.pending_count == 0)
    panel.poll_jobs()
    assert repository.list(project) == []
    panel.evaluate_current(assessed_at=AT + timedelta(hours=2))
    wait(panel, lambda: not panel._busy and panel.active_assessment is not None)
    assert len(repository.list(project)) == 1


def test_invalid_profile_error_is_safe_and_preserves_loaded_profile(panel, scene):
    directory, *_ = scene
    choose_profile(panel, directory)
    original = panel.profile
    invalid = directory / "invalid.json"
    invalid.write_text('{"SENSITIVE-SYNTHETIC-MARKER": "invalid"}', encoding="utf-8")
    panel.load_profile_path(invalid)
    wait(panel, lambda: not panel._busy)
    assert panel.profile == original
    assert "SENSITIVE" not in panel.status_label.text()
    assert "не выполнена" in panel.status_label.text()


def test_explicit_catalogue_selection_and_file_dialog_exports(panel, scene, monkeypatch):
    directory, *_ = scene
    original = evaluate(panel, directory)
    path = directory / "catalogue.json"
    changed = panel.catalogue.model_copy(update={"version": "synthetic-new-catalogue"})
    path.write_text(changed.model_dump_json(), encoding="utf-8")
    panel.load_catalogue_path(path)
    wait(panel, lambda: not panel._busy)
    assert panel.catalogue == changed
    assert panel.active_assessment == original
    output = directory / "dialog-export.html"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_: (str(output), "HTML"))
    panel.export_buttons["html"].click()
    wait(panel, lambda: not panel._busy)
    assert "synthetic-new-catalogue" not in output.read_text(encoding="utf-8")
    panel.internal_catalogue_button.click()
    assert panel.catalogue.version == "1.0.0"


def test_profile_button_uses_explicit_json_selection_and_catalogue_error_is_safe(
    panel, scene, monkeypatch
):
    directory, *_ = scene
    path = directory / "selected-profile.json"
    path.write_text(profile().model_dump_json(), encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *_: (str(path), "JSON"))
    panel.profile_button.click()
    wait(panel, lambda: not panel._busy and panel.profile is not None)
    assert panel._profile_path == path
    original = panel.catalogue
    bad = directory / "invalid-catalogue.json"
    bad.write_text('{"SENSITIVE-SYNTHETIC-CATALOGUE": "invalid"}', encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *_: (str(bad), "JSON"))
    panel.catalogue_button.click()
    wait(panel, lambda: not panel._busy)
    assert panel.catalogue == original
    assert "SENSITIVE" not in panel.status_label.text()
    assert "не выполнена" in panel.status_label.text()


def test_oversized_selected_profile_is_not_loaded_or_persisted(panel, scene):
    directory, _, project, _, _, repository = scene
    path = directory / "oversized-profile.json"
    with path.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    panel.load_profile_path(path)
    wait(panel, lambda: not panel._busy)
    assert panel.profile is None
    assert not panel.evaluate_button.isEnabled()
    assert repository.list(project) == []
    assert "не выполнена" in panel.status_label.text()


def test_panel_shutdown_prevents_pending_delivery(panel, scene):
    directory, *_ = scene
    choose_profile(panel, directory)
    panel.shutdown()
    assert not panel.evaluate_button.isEnabled()
    panel.evaluate_current(assessed_at=AT + timedelta(hours=2))
    assert panel.active_assessment is None


class _NetworkPanel(QWidget):
    query_result_changed = Signal(object)

    def set_project_context(self, project_id):
        self.project_id = project_id
        self.query_result_changed.emit(None)


def test_main_window_controls_report_tab_discovers_saved_results_isolates_and_restarts(scene, app):
    directory, store, project, source, _, _ = scene
    window = MainWindow(store=store, advanced_widget_factory=lambda *_: _NetworkPanel())
    reopened = None
    try:
        panel = window.controls_panel
        assert panel is not None
        assert window.report_tabs.tabText(2) == "Технические контроли"
        assert window.report_tabs.widget(2) is panel
        window.refresh_projects(project)
        window.report_tabs.setCurrentIndex(2)
        wait(
            panel,
            lambda: (
                panel.project_id == project
                and not panel._busy
                and panel.source_selector.count() == 1
            ),
        )
        assert panel.source_selector.currentData() == str(source.analysis_id)
        extra = source_result().model_copy(update={"project_reference": project})
        store.save_analysis_result(project, extra)
        window.report_tabs.setCurrentIndex(0)
        window.report_tabs.setCurrentIndex(2)
        wait(panel, lambda: not panel._busy and panel.source_selector.count() == 2)
        value = evaluate(panel, directory)
        other = window.create_project("Different main-window controls project")
        wait(panel, lambda: panel.project_id == other and not panel._busy)
        assert panel.active_assessment is None and panel.profile is None
        assert not panel.source_selector.count() and not panel.assessment_selector.count()
        window.refresh_projects(project)
        wait(panel, lambda: not panel._busy and panel.active_assessment is not None)
        assert panel.active_assessment == value
        window.close()
        assert panel._closed
        reopened = MainWindow(
            store=ProjectStore(store.path), advanced_widget_factory=lambda *_: _NetworkPanel()
        )
        reopened.refresh_projects(project)
        saved_panel = reopened.controls_panel
        assert saved_panel is not None
        wait(
            saved_panel, lambda: not saved_panel._busy and saved_panel.active_assessment is not None
        )
        assert saved_panel.active_assessment == value
        assert saved_panel.profile is None
    finally:
        if reopened is not None:
            reopened.close()
            reopened.deleteLater()
        window.close()
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()
