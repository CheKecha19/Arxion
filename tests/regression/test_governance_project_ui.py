"""Synthetic project-scoped governance input, history, exports and worker safety."""

import os
import time
from datetime import timedelta
from pathlib import Path
from threading import Event, get_ident
from uuid import uuid4

import pytest

from tests.regression.test_analysis_result import bundle, policy
from tests.regression.test_governance_workflow import ASSESSED, evidence
from tests.regression.test_policy_governance import profile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QApplication, QWidget

from firewall_compliance.application.analysis_result import AnalysisResult, PolicyComponent
from firewall_compliance.application.governance_workflow import GOVERNANCE_CHECK_IDS
from firewall_compliance.interfaces.desktop import qt_governance
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow
from firewall_compliance.interfaces.desktop.qt_governance import GovernancePanel
from firewall_compliance.interfaces.desktop.qt_theme import apply_theme

DEFAULT_EVIDENCE = evidence()
APP = None


@pytest.fixture(scope="module")
def app():
    # Qt's application/font caches belong to one application for the process.
    # Keep a reference beyond module teardown when other UI modules run next.
    global APP
    APP = QApplication.instance() or QApplication([])
    if os.name == "nt" and not QFontDatabase.families():
        font = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "arial.ttf"
        assert QFontDatabase.addApplicationFont(str(font)) >= 0
    yield APP


@pytest.fixture
def scene():
    root = Path(__file__).resolve().parents[2] / "artifacts" / "governance-ui" / uuid4().hex
    root.mkdir(parents=True)
    store = ProjectStore(root / "projects.sqlite3")
    project = store.create_project("Synthetic governance")
    source = bundle(policy()).model_copy(update={"project_reference": project})
    store.save_analysis_result(project, source)
    return root, store, project, source


@pytest.fixture
def panel(app, scene):
    _, store, project, _ = scene
    widget = GovernancePanel(store)
    widget.set_project_context(project)
    wait(widget, lambda: not widget._busy and widget.active_result is not None)
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


def load_documents(widget, directory, *, inputs=DEFAULT_EVIDENCE):
    path = directory / "profile.json"
    path.write_text(profile().model_dump_json(), encoding="utf-8-sig")
    widget.load_profile(path)
    wait(widget, lambda: not widget._busy and widget.profile is not None)
    if inputs is not None:
        path = directory / "inputs.json"
        path.write_text(inputs.model_dump_json(), encoding="utf-8-sig")
        widget.load_inputs(path)
        wait(widget, lambda: not widget._busy and widget.inputs is not None)


def evaluate(widget):
    previous = widget.active_result.analysis_id
    widget.evaluate_current(assessed_at=ASSESSED)
    wait(widget, lambda: not widget._busy and widget.active_result.analysis_id != previous)
    return widget.active_result


def test_selected_exact_revision_and_new_stage_preserve_original_and_reopen(panel, scene, app):
    directory, store, project, original = scene
    load_documents(panel, directory)
    assert (
        str(original.components[0].revision.revision_id) in panel.component_selector.currentText()
    )
    assert (
        original.components[0].revision.device.device_id in panel.component_selector.currentText()
    )
    saved = []
    panel.result_saved.connect(saved.append)
    result = evaluate(panel)
    assert saved == [str(result.analysis_id)]
    assert store.get_analysis_result(project, str(original.analysis_id)) == original
    assert result.components[:-1] == original.components
    stage = result.components[-1]
    assert isinstance(stage, PolicyComponent)
    assert stage.options.check_ids == GOVERNANCE_CHECK_IDS
    assert all(check.findings for check in stage.result.checks)
    assert panel.source_selector.count() == 2
    assert profile().profile_id in panel.summary_label.text()
    assert "v3" in panel.summary_label.text()
    assert stage.revision.parse_result.configuration.source_name in panel.browser.toPlainText()
    reopened = GovernancePanel(ProjectStore(store.path))
    try:
        reopened.set_project_context(project)
        wait(reopened, lambda: not reopened._busy and reopened.active_result is not None)
        assert reopened.source_selector.count() == 2
        index = reopened.source_selector.findData(str(result.analysis_id))
        reopened.source_selector.setCurrentIndex(index)
        wait(reopened, lambda: not reopened._busy)
        assert reopened.active_result == result
        assert "FW-RULE-GOVERNANCE" in reopened.browser.toPlainText()
        assert reopened.profile is None and reopened.inputs is None
    finally:
        reopened.shutdown()
        reopened.close()
        app.processEvents()


def test_omitted_evidence_is_unknown_not_zero_or_missing_owner_violation(panel, scene):
    load_documents(panel, scene[0], inputs=None)
    result = evaluate(panel)
    stage = result.components[-1]
    assert all(check.status.value == "partial" for check in stage.result.checks)
    assert all(not check.findings for check in stage.result.checks)
    assert "UNKNOWN" in panel.browser.toPlainText()
    assert stage.options.governance_inputs is None


@pytest.mark.parametrize("format_name", ["json", "csv", "html"])
def test_cached_exports_preserve_all_stages_without_reread_or_reanalysis(
    panel, scene, monkeypatch, format_name
):
    directory, _, _, _ = scene
    load_documents(panel, directory)
    result = evaluate(panel)

    def forbidden(*args, **kwargs):
        raise AssertionError("Cached export must not read or rerun analysis")

    monkeypatch.setattr(qt_governance, "assess_governance", forbidden)
    monkeypatch.setattr(qt_governance, "_read", forbidden)
    path = directory / f"report.{format_name}"
    panel.export_current(format_name, path)
    wait(panel, lambda: not panel._busy)
    assert "Экспорт сохранён" in panel.status_label.text()
    text = path.read_text(encoding="utf-8")
    assert "FW-RULE-GOVERNANCE" in text and "FW-UNUSED-CANDIDATE" in text
    if format_name == "json":
        assert AnalysisResult.model_validate_json(text) == result


def test_wrong_revision_inputs_do_not_create_a_result_or_replace_previous(panel, scene):
    directory, store, project, original = scene
    unrelated = evidence().model_copy(
        update={"revision_id": uuid4(), "metadata": (), "statistics": ()}
    )
    load_documents(panel, directory, inputs=unrelated)
    panel.evaluate_current(assessed_at=ASSESSED)
    wait(panel, lambda: not panel._busy)
    assert "Операция не выполнена" in panel.status_label.text()
    assert panel.active_result == original
    assert len(store.list_analysis_results(project)) == 1


def test_bad_profile_keeps_previous_explicit_profile_and_does_not_leak_payload(panel, scene):
    load_documents(panel, scene[0], inputs=None)
    previous = panel.profile
    path = scene[0] / "invalid.json"
    path.write_text('{"schema_version":"SECRET-SYNTHETIC-MARKER"}', encoding="utf-8")
    panel.load_profile(path)
    wait(panel, lambda: not panel._busy)
    assert panel.profile is previous
    assert "SECRET-SYNTHETIC-MARKER" not in panel.status_label.text()
    assert "Операция не выполнена" in panel.status_label.text()


def test_project_switch_clears_inputs_profile_and_old_result(panel, scene):
    load_documents(panel, scene[0])
    other = scene[1].create_project("Other synthetic")
    panel.set_project_context(other)
    wait(panel, lambda: not panel._busy)
    assert panel.active_result is None and panel.profile is None and panel.inputs is None
    assert panel.source_selector.count() == panel.component_selector.count() == 0
    assert not panel.evaluate_button.isEnabled()
    assert all(not button.isEnabled() for button in panel.export_buttons.values())


@pytest.mark.parametrize("action", ["cancel", "switch", "shutdown"])
def test_late_evaluation_does_not_save_or_deliver_after_invalidation(
    panel, scene, monkeypatch, action
):
    load_documents(panel, scene[0])
    entered, release = Event(), Event()
    actual = qt_governance.assess_governance
    gui_thread = get_ident()
    workers = []

    def blocked(*args, **kwargs):
        workers.append(get_ident())
        entered.set()
        assert release.wait(5)
        return actual(*args, **kwargs)

    monkeypatch.setattr(qt_governance, "assess_governance", blocked)
    panel.evaluate_current(assessed_at=ASSESSED)
    assert entered.wait(5)
    if action == "cancel":
        panel.cancel_current()
    elif action == "switch":
        panel.set_project_context(scene[1].create_project("Other project"))
    else:
        panel.shutdown()
    release.set()
    deadline = time.monotonic() + 5
    while panel.runner.running_count and time.monotonic() < deadline:
        QApplication.processEvents()
        panel.poll_jobs()
        time.sleep(0.005)
    assert len(scene[1].list_analysis_results(scene[2])) == 1
    assert workers and workers[0] != gui_thread
    if action == "switch":
        wait(panel, lambda: not panel._busy)
        assert panel.active_result is None
    else:
        assert panel.active_result == scene[3]


def test_export_refuses_profile_hardlink_and_preserves_file(panel, scene):
    load_documents(panel, scene[0], inputs=None)
    source = scene[0] / "profile.json"
    target = scene[0] / "alias.json"
    os.link(source, target)
    before = source.read_bytes()
    panel.export_current("json", target)
    wait(panel, lambda: not panel._busy)
    assert "Операция не выполнена" in panel.status_label.text()
    assert source.read_bytes() == before


def test_oversized_json_is_rejected_without_reading_unbounded_input(panel, scene):
    path = scene[0] / "large.json"
    with path.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    panel.load_inputs(path)
    wait(panel, lambda: not panel._busy)
    assert panel.inputs is None
    assert "Операция не выполнена" in panel.status_label.text()


def test_profile_can_be_changed_without_rewriting_prior_stage(panel, scene):
    load_documents(panel, scene[0])
    first = evaluate(panel)
    path = scene[0] / "next-profile.json"
    next_profile = profile(version="4", lifecycle_enabled=False, unused_enabled=False)
    path.write_text(next_profile.model_dump_json(), encoding="utf-8")
    panel.load_profile(path)
    wait(panel, lambda: not panel._busy and panel.profile.version == "4")
    panel.evaluate_current(assessed_at=ASSESSED + timedelta(seconds=1))
    wait(panel, lambda: not panel._busy and panel.active_result.analysis_id != first.analysis_id)
    second = panel.active_result
    assert second.components[:-1] == first.components
    assert all(
        check.status.value == "not_applicable" for check in second.components[-1].result.checks
    )
    assert scene[1].get_analysis_result(scene[2], str(first.analysis_id)) == first


class _NetworkPanel(QWidget):
    query_result_changed = Signal(object)

    def set_project_context(self, project_id):
        self.project_id = project_id
        self.query_result_changed.emit(None)


def wait_main(window, predicate):
    deadline = time.monotonic() + 15
    while not predicate():
        QApplication.processEvents()
        window.poll_jobs()
        if window.governance_panel is not None:
            window.governance_panel.poll_jobs()
        if time.monotonic() >= deadline:
            raise AssertionError(window.progress_label.text())
        time.sleep(0.005)
    QApplication.processEvents()


@pytest.fixture
def window(app, scene):
    result = MainWindow(store=scene[1], advanced_widget_factory=lambda *_: _NetworkPanel())
    result.refresh_projects(scene[2])
    result.report_tabs.setCurrentIndex(3)
    wait_main(
        result,
        lambda: (
            result.governance_panel.project_id == scene[2]
            and not result.governance_panel._busy
            and result.governance_panel.active_result is not None
        ),
    )
    yield result
    result.close()
    result.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


def test_main_window_saved_governance_stage_refreshes_common_reports_and_survives_restart(
    window, scene, app
):
    directory, store, project, original = scene
    panel = window.governance_panel
    assert window.report_tabs.tabText(3) == "Метаданные правил"
    assert window.report_tabs.widget(3) is panel
    assert panel.source_selector.currentData() == str(original.analysis_id)
    load_documents(panel, directory)
    saved = []
    panel.result_saved.connect(saved.append)
    result = evaluate(panel)
    wait_main(
        window,
        lambda: (
            window.analysis_result_selector.currentData() == str(result.analysis_id)
            and window._analysis_result_active == result
        ),
    )
    assert saved == [str(result.analysis_id)]
    assert panel.profile == profile() and panel.inputs == DEFAULT_EVIDENCE
    assert panel.active_result == result
    assert panel.source_selector.currentData() == str(result.analysis_id)
    assert store.get_analysis_result(project, str(original.analysis_id)) == original
    assert len(store.list_analysis_results(project)) == 2
    assert result.components[:-1] == original.components
    assert window._analysis_result_active == result
    window.close()
    assert panel._closed
    reopened = MainWindow(
        store=ProjectStore(store.path), advanced_widget_factory=lambda *_: _NetworkPanel()
    )
    try:
        reopened.refresh_projects(project)
        reopened.report_tabs.setCurrentIndex(3)
        restored = reopened.governance_panel
        wait_main(
            reopened,
            lambda: not restored._busy and restored.source_selector.count() == 2,
        )
        restored.source_selector.setCurrentIndex(
            restored.source_selector.findData(str(result.analysis_id))
        )
        wait_main(reopened, lambda: not restored._busy and restored.active_result == result)
        assert restored.profile is None and restored.inputs is None
        assert "FW-RULE-GOVERNANCE" in restored.browser.toPlainText()
        assert "FW-UNUSED-CANDIDATE" in restored.browser.toPlainText()
    finally:
        reopened.close()
        reopened.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()


def test_main_window_governance_tab_refresh_discovers_a_new_saved_source(window, scene):
    panel = window.governance_panel
    extra = scene[3].model_copy(update={"analysis_id": uuid4()})
    scene[1].save_analysis_result(scene[2], extra)
    assert panel.source_selector.count() == 1
    window.report_tabs.setCurrentIndex(0)
    window.report_tabs.setCurrentIndex(3)
    wait_main(window, lambda: not panel._busy and panel.source_selector.count() == 2)
    assert panel.source_selector.findData(str(extra.analysis_id)) >= 0


def test_main_window_project_switch_invalidates_a_pending_governance_save(
    window, scene, monkeypatch
):
    panel = window.governance_panel
    load_documents(panel, scene[0])
    entered, release = Event(), Event()
    actual = qt_governance.assess_governance

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return actual(*args, **kwargs)

    monkeypatch.setattr(qt_governance, "assess_governance", blocked)
    panel.evaluate_current(assessed_at=ASSESSED)
    assert entered.wait(5)
    try:
        other = window.create_project("Other main-window governance project")
    finally:
        release.set()
    wait_main(
        window,
        lambda: panel.project_id == other and not panel._busy and not panel.runner.running_count,
    )
    assert panel.active_result is None and panel.profile is None and panel.inputs is None
    assert panel.source_selector.count() == panel.component_selector.count() == 0
    assert not panel.evaluate_button.isEnabled()
    assert not scene[1].list_analysis_results(other)
    assert len(scene[1].list_analysis_results(scene[2])) == 1
    assert window._analysis_result_active is None
    window.refresh_projects(scene[2])
    window.report_tabs.setCurrentIndex(3)
    wait_main(window, lambda: not panel._busy and panel.active_result is not None)
    assert panel.active_result == scene[3]
    assert panel.profile is None and panel.inputs is None


def test_main_window_governance_report_fits_minimum_window_with_real_font(window, app, scene):
    apply_theme(app)
    window.navigate("reports")
    window.report_tabs.setCurrentIndex(3)
    window.resize(1000, 650)
    window.show()
    app.processEvents()
    panel = window.governance_panel
    assert window.size().width() == 1000 and window.size().height() == 650
    assert not panel.isHidden() and panel.scroll_area.viewport().width() > 0
    assert panel.scroll_area.viewport().height() >= 100
    assert panel.browser.minimumHeight() >= 120
    bounds = panel.scroll_area.widget().rect()
    for control in (
        panel.source_selector,
        panel.component_selector,
        panel.profile_button,
        panel.inputs_button,
        panel.clear_inputs_button,
        panel.evaluate_button,
        *panel.export_buttons.values(),
    ):
        assert not control.isHidden()
        assert bounds.contains(control.geometry())
    panel.scroll_area.ensureWidgetVisible(panel.export_buttons["json"])
    app.processEvents()
    assert window.grab().save(str(scene[0] / "main-window-governance-1000x650.png"))
