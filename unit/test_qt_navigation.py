"""Regression checks for navigation, project scope and asynchronous page retention."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from time import monotonic, sleep
from typing import Any

import pytest

from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.project_store import ProjectStore

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="module")
def qt_app() -> Iterator[Any]:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    application = QApplication.instance() or QApplication([])
    yield application
    application.processEvents()


@pytest.fixture
def window(qt_app: Any, tmp_path: Path) -> Iterator[Any]:
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QWidget

    from firewall_compliance.interfaces.desktop.qt_app import MainWindow

    view = MainWindow(
        ProjectStore(tmp_path / "projects.sqlite3"),
        advanced_widget_factory=lambda _sessions, _runner: QWidget(),
    )
    view.show()
    qt_app.processEvents()
    yield view
    view.close()
    view.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qt_app.processEvents()


def _wait(application: Any, predicate: Any, timeout: float = 15) -> None:
    deadline = monotonic() + timeout
    while not predicate():
        application.processEvents()
        if monotonic() >= deadline:
            raise AssertionError("Qt worker did not complete")
        sleep(0.005)
    application.processEvents()


def _save_run(store: ProjectStore, project_id: str, devices: list[tuple[str, Path]]) -> str:
    run_id = store.create_run(project_id)
    for device_id, path in devices:
        session = analyze_file(path, device_id=device_id)
        assert isinstance(session, AnalysisSession)
        store.record_session(run_id, session)
    store.finish_run(run_id)
    return run_id


def test_navigation_contains_network_map_and_separate_settings(window: Any) -> None:
    tree = window.navigation
    assert tree.topLevelItemCount() == 6
    assert [tree.topLevelItem(i).text(0) for i in range(6)] == [
        "Обзор",
        "Инфраструктура",
        "Сетевая карта",
        "Анализ",
        "Операции",
        "Отчёты",
    ]
    assert window.settings_button.text() == "Настройки"
    assert window.settings_button.parent() == tree.parent()
    for section in (
        "home",
        "devices",
        "history",
        "reports",
        "map",
        "findings",
        "rules",
        "advanced",
        "settings",
        "scans",
        "staging",
    ):
        window.navigate(section)
        assert window.current_section_id == section


def test_settings_and_import_controls_belong_to_their_pages(window: Any) -> None:
    home = window.pages.widget(0)
    devices = window.pages.widget(2)
    settings = window.pages.widget(8)
    preparation = window.pages.widget(10)
    assert not home.isAncestorOf(window.logging_check)
    assert not home.isAncestorOf(window.stage_table)
    assert settings.isAncestorOf(window.logging_check)
    assert settings.isAncestorOf(window.comments_check)
    assert all(settings.isAncestorOf(box) for box in window.check_boxes.values())
    assert not devices.isAncestorOf(window.stage_table)
    assert preparation.isAncestorOf(window.folder_button)
    assert preparation.isAncestorOf(window.files_button)
    assert preparation.isAncestorOf(window.stage_table)
    assert preparation.isAncestorOf(window.run_button)


def test_map_opens_project_map_with_device_modes_available(window: Any, qt_app: Any) -> None:
    window.navigate("map")
    qt_app.processEvents()
    assert window.navigation.currentItem().text(0) == "Сетевая карта"
    assert not window.section_tabs.isVisible()
    assert window.map_mode_selector.currentData() == "project"
    assert window.map_mode_stack.currentWidget() is window.project_map_widget
    assert not window.map_result_selector.isVisible()
    window.map_mode_selector.setCurrentIndex(1)
    assert window.map_mode_stack.currentWidget() is window.topology_map_widget
    assert not window.map_sources_panel.isVisible()
    window.map_sources_button.click()
    assert window.map_sources_panel.isVisible()
    window.map_mode_selector.setCurrentIndex(0)
    window.navigate("findings")
    assert "Сетевая карта" not in [
        window.section_tabs.tabText(i) for i in range(window.section_tabs.count())
    ]
    window.navigate("map")
    assert window.map_mode_selector.currentData() == "policy"


def test_sections_and_tabs_work_with_keyboard(window: Any, qt_app: Any) -> None:
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    window.navigate("home")
    window.navigation.setFocus()
    QTest.keyClick(window.navigation, Qt.Key.Key_Down)
    qt_app.processEvents()
    assert window.current_section_id == "devices"
    QTest.keyClick(window.navigation, Qt.Key.Key_Down)
    qt_app.processEvents()
    assert window.current_section_id == "map"
    QTest.keyClick(window.navigation, Qt.Key.Key_Down)
    qt_app.processEvents()
    assert window.current_section_id == "findings"
    window.section_tabs.setFocus()
    QTest.keyClick(window.section_tabs, Qt.Key.Key_Right)
    qt_app.processEvents()
    assert window.current_section_id == "rules"
    assert window.navigation.currentItem().text(0) == "Анализ"


def test_project_map_uses_all_runs_and_persists_zone_names(window: Any, qt_app: Any) -> None:
    project_id = window.create_project("Карта всей инфраструктуры")
    fixture = FIXTURES / "assurance" / "policy_quality.cfg"
    _save_run(window.store, project_id, [("first-device", fixture)])
    latest = _save_run(window.store, project_id, [("second-device", fixture)])
    window.load_run(latest)
    window.navigate("map")
    qt_app.processEvents()
    graph = window.project_map_widget.graph
    assert {node.key for node in graph.nodes if node.key.startswith("device:")} == {
        "device:first-device",
        "device:second-device",
    }
    key = next(iter(window.project_map_widget.zone_items))
    window.project_map_widget.rename_zone(key, "Основное оборудование")
    assert window.store.get_project(project_id)["settings"]["map_zone_labels"][key] == (
        "Основное оборудование"
    )
    another = window.create_project("Другой проект")
    assert another != project_id
    window.navigate("map")
    assert not window.project_map_widget.graph.nodes
    assert not window.project_map_widget.zone_labels
    window.project_combo.setCurrentIndex(window.project_combo.findData(project_id))
    window.navigate("map")
    assert window.project_map_widget.zone_labels[key] == "Основное оборудование"


def test_settings_submenu_switches_between_integrations_and_rules(window: Any) -> None:
    window.navigate("settings")
    assert window.settings_nav_buttons["integrations"].isChecked()
    assert window.settings_pages.currentIndex() == 0
    assert not window.logging_check.isVisible()
    window.settings_nav_buttons["rules"].click()
    assert window.settings_pages.currentIndex() == 1
    assert window.logging_check.isVisible()
    assert window.settings_nav_buttons["rules"].isChecked()
    assert not window.settings_nav_buttons["integrations"].isChecked()
    window.settings_nav_buttons["integrations"].click()
    assert window.settings_pages.currentIndex() == 0
    assert not window.logging_check.isVisible()


def test_integration_cards_open_platform_pages_and_mark_planned_platforms(
    window: Any, qt_app: Any
) -> None:
    from PySide6.QtWidgets import QPushButton

    window.navigate("settings")
    qt_app.processEvents()
    assert window.settings_pages.currentWidget().horizontalScrollBar().maximum() == 0
    for key in ("aruba", "usergate", "pt", "ideco", "cloud_ru"):
        assert window.integration_buttons[key].isVisible()
        assert window.integration_buttons[key].isEnabled()
        window.integration_buttons[key].click()
        assert window.integration_pages.currentIndex() == window.integration_detail_indices[key]
        back = next(
            button
            for button in window.integration_pages.currentWidget().findChildren(QPushButton)
            if button.text() == "← Все интеграции"
        )
        back.click()
        assert window.integration_pages.currentIndex() == 0
    for key in ("usergate", "pt", "ideco"):
        assert "Запланировано" in window.integration_buttons[key].text()
    assert [grid.columnCount() for grid in window.integration_grids] == [5, 5, 5]


def test_aruba_import_opens_existing_file_import(window: Any, monkeypatch: Any) -> None:
    called = []
    monkeypatch.setattr(window, "choose_files", lambda: called.append(True))
    window.navigate("settings")
    window.integration_buttons["aruba"].click()
    window._import_integration_files()
    assert window.current_section_id == "staging"
    assert called == [True]


def test_cloud_platform_tabs_and_scan_navigation(window: Any) -> None:
    window.navigate("scans")
    panel = window.cloud_panel
    assert window.pages.currentWidget() is panel.scans_widget
    panel.configure_button.click()
    assert window.current_section_id == "settings"
    assert window.integration_pages.currentIndex() == window.integration_detail_indices["cloud_ru"]
    assert [panel.settings_widget.tabText(i) for i in range(3)] == [
        "VMware",
        "Advanced",
        "Evolution",
    ]
    window.create_project("Cloud source")
    panel.source.setCurrentIndex(1)
    assert panel.scan_button.isEnabled()
    assert not panel.resource_checks["edges"].isEnabled()
    assert panel.resource_checks["security_groups"].isEnabled()
    panel.source.setCurrentIndex(0)
    assert panel.scan_button.isEnabled()
    panel.resource_checks["edges"].setChecked(False)
    assert not panel.data_checks["firewall"].isEnabled()
    assert panel.data_checks["vm_networks"].isEnabled()


def test_cloud_credentials_follow_project_and_blank_token_retains_secret(window: Any) -> None:
    first = window.create_project("First cloud")
    panel = window.cloud_panel
    panel.site.setText("https://vcd01-01.cloud.ru")
    panel.tenant.setText("tenant")
    panel.save()
    assert "Введите API Token" in panel.connection_status.text()
    panel.token.setText("synthetic-qt-token")
    panel.save()
    assert panel.token.text() == ""
    assert window.store.get_vmware_token(first) == "synthetic-qt-token"
    panel.timeout.setValue(60)
    panel.save()
    assert window.store.get_vmware_token(first) == "synthetic-qt-token"
    assert window.store.get_vmware_integration(first)["timeout"] == 60
    window.create_project("Second cloud")
    assert panel.site.text() == ""
    assert panel.tenant.text() == ""
    window.refresh_projects(first)
    assert panel.tenant.text() == "tenant"
    panel.site.setText("https://vcd11-01.cloud.ru")
    panel.save()
    assert "заново" in panel.connection_status.text()
    assert window.store.get_vmware_integration(first)["site"] == "https://vcd01-01.cloud.ru"


def test_cloud_scan_uses_selection_and_saves_to_original_project(window: Any, qt_app: Any) -> None:
    from dataclasses import asdict
    from threading import Event

    from firewall_compliance.infrastructure.cloud_vmware import (
        ScanResult,
        VMwareClient,
        VMwareConfig,
    )

    first = window.create_project("Scan project")
    panel = window.cloud_panel
    window.store.save_vmware_integration(
        first, asdict(VMwareConfig("https://vcd01-01.cloud.ru", "tenant")), "synthetic-token"
    )
    started = Event()
    release = Event()
    selections = []

    class Client(VMwareClient):
        def scan(self, selection: Any) -> ScanResult:
            selections.append(selection)
            started.set()
            assert release.wait(10)
            return ScanResult(
                "completed",
                records=[
                    {
                        "type": "vms",
                        "name": "Synthetic VM",
                        "id": "1",
                        "inventory": {},
                        "data": {},
                    }
                ],
            )

    panel.client_factory = Client
    panel.resource_checks["edges"].setChecked(False)
    panel.resource_checks["networks"].setChecked(False)
    panel.data_checks["vm_networks"].setChecked(False)
    panel.start_scan()
    _wait(qt_app, started.is_set)
    assert panel.busy
    assert not panel.scan_button.isEnabled()
    assert selections[0].resources == ("vms",)
    assert selections[0].data == ()
    second = window.create_project("Other project")
    assert panel.history.count() == 0
    release.set()
    _wait(qt_app, lambda: not panel.busy)
    assert not window.store.list_cloud_scans(second)
    assert window.store.list_cloud_scans(first)[0]["state"] == "completed"
    assert panel.history.count() == 0
    window.refresh_projects(first)
    assert panel.history.count() == 1
    assert panel.records_view.topLevelItemCount() == 1
    assert "Synthetic VM" in panel.record_detail.toPlainText()
    assert "synthetic-token" not in panel.result.toPlainText()


def test_closing_window_marks_active_cloud_scan_interrupted(window: Any, qt_app: Any) -> None:
    from dataclasses import asdict
    from threading import Event

    from firewall_compliance.infrastructure.cloud_vmware import (
        ScanResult,
        VMwareClient,
        VMwareConfig,
    )

    project = window.create_project("Close cloud")
    panel = window.cloud_panel
    window.store.save_vmware_integration(
        project, asdict(VMwareConfig("https://vcd01-01.cloud.ru", "tenant")), "synthetic-token"
    )
    started = Event()

    class Client(VMwareClient):
        def scan(self, _selection: Any) -> ScanResult:
            started.set()
            self.cancel.wait(10)
            return ScanResult("cancelled")

    panel.client_factory = Client
    panel.start_scan()
    _wait(qt_app, started.is_set)
    window.close()
    assert window.store.list_cloud_scans(project)[0]["state"] == "interrupted"


@pytest.mark.parametrize("platform,index", [("advanced", 1), ("evolution", 2)])
def test_public_cloud_forms_save_keys_and_keep_platforms_isolated(
    window: Any, platform: str, index: int
) -> None:
    project = window.create_project("Public cloud")
    panel = window.cloud_panel
    form = panel.public_forms[platform]
    form.project.setText(
        "0123456789abcdef0123456789abcdef"
        if platform == "advanced"
        else "01234567-89ab-cdef-0123-456789abcdef"
    )
    form.access_key.setText("SYNTHETIC-KEY-ID")
    form.secret_key.setText("SYNTHETIC-KEY-SECRET")
    form.save()
    assert form.access_key.text() == form.secret_key.text() == ""
    keys = window.store.get_public_cloud_credentials(project, platform)
    assert keys["secret_key"] == "SYNTHETIC-KEY-SECRET"
    other = "advanced" if platform == "evolution" else "evolution"
    assert window.store.get_public_cloud_integration(project, other) is None
    assert window.store.get_vmware_integration(project) is None
    assert "SYNTHETIC" not in str(window.store.get_project(project)["settings"])
    form.timeout.setValue(60)
    form.save()
    assert window.store.get_public_cloud_credentials(project, platform) == keys
    panel.source.setCurrentIndex(index)
    assert panel.scan_button.isEnabled()
    assert panel.resource_checks["security_groups"].isEnabled()
    assert not panel.resource_checks["edges"].isEnabled()
    assert not panel.data_checks["nat"].isEnabled()
    assert panel.data_checks["security_rules"].isEnabled()
    panel.configure_button.click()
    assert panel.settings_widget.currentIndex() == index
    window.create_project("Other public cloud")
    assert form.project.text() == ""
    assert platform.capitalize() in panel.scan_status.text()
    window.refresh_projects(project)
    assert form.project.text()
    assert form.secret_key.text() == ""
    assert panel.scan_status.text() == "Готово к сканированию."


@pytest.mark.parametrize("platform,index", [("advanced", 1), ("evolution", 2)])
def test_public_cloud_scan_and_connection_are_independent_of_vmware(
    window: Any, qt_app: Any, platform: str, index: int
) -> None:
    from firewall_compliance.infrastructure.cloud_public import PublicCloudClient
    from firewall_compliance.infrastructure.cloud_vmware import ScanResult

    project = window.create_project("Public scan")
    panel = window.cloud_panel
    form = panel.public_forms[platform]
    form.project.setText(
        "0123456789abcdef0123456789abcdef"
        if platform == "advanced"
        else "01234567-89ab-cdef-0123-456789abcdef"
    )
    form.access_key.setText("synthetic-key")
    form.secret_key.setText("synthetic-secret")
    form.save()
    selections = []

    class Client(PublicCloudClient):
        def check_connection(self) -> ScanResult:
            return ScanResult("completed")

        def scan(self, selection: Any) -> ScanResult:
            selections.append(selection)
            return ScanResult(
                "completed",
                records=[
                    {
                        "type": "security_groups",
                        "name": "Synthetic security group",
                        "id": "1",
                        "inventory": {},
                        "data": {"security_rules": [{"direction": "ingress"}]},
                    }
                ],
            )

    panel.public_factories[platform] = Client
    panel._test_public(platform)
    _wait(qt_app, lambda: not panel.busy)
    assert "успешно" in form.status.text()
    panel.source.setCurrentIndex(index)
    for key, checkbox in panel.resource_checks.items():
        checkbox.setChecked(key == "security_groups")
    panel.start_scan()
    _wait(qt_app, lambda: not panel.busy)
    assert selections[0].resources == ("security_groups",)
    assert selections[0].data == ("security_rules",)
    scans = window.store.list_cloud_scans(project)
    assert len(scans) == 1
    assert scans[0]["config"]["platform"] == platform
    assert scans[0]["state"] == "completed"
    assert "synthetic-secret" not in str(scans)
    assert panel.records_view.topLevelItemCount() == 1
    assert "ingress" in panel.record_detail.toPlainText()
    window.navigate("devices")
    assert window.device_model.rowCount() == 1
    window.device_table.selectRow(0)
    qt_app.processEvents()
    assert "Проверки недоступны" in window.device_detail.toPlainText()
    assert not window.attach_button.isEnabled()
    assert window.device_rules_model.rowCount() == 1
    assert window.history_model.payloads[0]["operation_kind"] == "collection"
    window.resource_operation_button.click()
    assert window.current_section_id == "scans"
    assert panel.history.currentData()["id"] == scans[0]["id"]
    assert panel.collection_tabs.currentIndex() == 1


def test_settings_persist_per_project_when_switching_projects(window: Any) -> None:
    first = window.create_project("First settings")
    window.navigate("settings")
    window.logging_check.setChecked(False)
    window.comments_check.setChecked(False)
    window.check_boxes["FW-LOGGING"].setChecked(False)
    stored = window.store.get_project(first)["settings"]
    assert stored["require_logging"] is False
    assert stored["require_comments"] is False
    assert "FW-LOGGING" not in stored["enabled_check_ids"]
    window.create_project("Second settings")
    assert window.logging_check.isChecked()
    assert window.comments_check.isChecked()
    assert window.check_boxes["FW-LOGGING"].isChecked()
    window.refresh_projects(first)
    assert not window.logging_check.isChecked()
    assert not window.comments_check.isChecked()
    assert not window.check_boxes["FW-LOGGING"].isChecked()


def test_home_inventory_includes_earlier_devices_once(window: Any, qt_app: Any) -> None:
    project_id = window.create_project("Project inventory")
    asa = FIXTURES / "assurance/policy_quality.cfg"
    aruba = FIXTURES / "hp_aruba/aos_switch.cfg"
    earlier_run = _save_run(window.store, project_id, [("ASA", asa), ("ARUBA", aruba)])
    last_run = _save_run(window.store, project_id, [("ASA", asa)])
    window.load_run(last_run)
    window.navigate("home")
    qt_app.processEvents()
    assert window.device_count_label.text() == "Устройств проекта: 2"
    assert window.vendor_model.rowCount() == 2
    assert sum(int(row[1]) for row in window.vendor_model.rows) == 2
    assert window.last_check_label.text() not in {"", "—"}
    assert len(window.run["items"]) == 1
    latest_check_text = window.last_check_label.text()
    window.load_run(earlier_run)
    assert window.last_check_label.text() == latest_check_text


def test_rules_project_scope_and_device_tabs_are_independent(window: Any, qt_app: Any) -> None:
    project_id = window.create_project("Device details")
    asa = FIXTURES / "assurance/policy_quality.cfg"
    aruba = FIXTURES / "hp_aruba/aos_switch.cfg"
    _save_run(window.store, project_id, [("ASA", asa), ("ARUBA", aruba)])
    last_run = _save_run(window.store, project_id, [("ASA", asa)])
    window.load_run(last_run)
    assert window.rule_scope.currentData() == "project"
    assert {payload["item"]["report"]["device_id"] for payload in window.rules_model.payloads} == {
        "ASA",
        "ARUBA",
    }
    window.navigate("devices")
    window.device_scope.setCurrentIndex(window.device_scope.findData("project"))
    assert window.device_model.rowCount() == 2
    source_row = next(
        i
        for i, item in enumerate(window.device_model.payloads)
        if item["report"]["device_id"] == "ARUBA"
    )
    proxy_row = window.device_proxy.mapFromSource(window.device_model.index(source_row, 0)).row()
    window.device_table.selectRow(proxy_row)
    qt_app.processEvents()
    selected = window.device_model.payloads[source_row]["parse_result"]
    assert [window.device_tabs.tabText(i) for i in range(window.device_tabs.count())] == [
        "Сведения",
        "Правила",
        "Объекты",
        "Проблемы",
        "История",
        "Источники",
    ]
    assert window.device_rules_model.rowCount() == len(selected["rules"])
    assert window.device_objects_model.rowCount() == (
        len(selected["endpoints"]) + len(selected["services"])
    )
    assert "ARUBA" in window.device_detail.toPlainText()
    window.rule_scope.setCurrentIndex(window.rule_scope.findData("run"))
    assert {payload["item"]["report"]["device_id"] for payload in window.rules_model.payloads} == {
        "ASA"
    }


def test_completed_partial_batch_retains_page_and_offers_summary(
    window: Any, qt_app: Any, tmp_path: Path
) -> None:
    window.create_project("Completion navigation")
    unsupported = tmp_path / "unknown.txt"
    unsupported.write_text("not a supported configuration", encoding="utf-8")
    window.stage_paths([FIXTURES / "hp_aruba/aos_switch.cfg", unsupported])
    _wait(qt_app, lambda: not window._preflight_jobs)
    window.navigate("reports")
    window.start_analysis()
    _wait(qt_app, lambda: not window._batch_active)
    assert window.current_section_id == "reports"
    assert window.notification_label.isVisible()
    assert window.notification_button.isVisible()
    assert any(item["status"] == "unsupported" for item in window.run["items"])
    assert all(item["warning"] not in {"Выполняется", "В очереди"} for item in window.staged)
    assert "1" in window.notification_label.text()
    window.notification_button.click()
    qt_app.processEvents()
    assert window.current_section_id == "findings"
    assert window.finding_scope.currentData() == "run"


def test_resource_problem_rule_and_back_preserve_snapshot_and_filter(window: Any) -> None:
    project = window.create_project("Linked resource")
    first = _save_run(window.store, project, [("FIRST", FIXTURES / "assurance/policy_quality.cfg")])
    second = _save_run(
        window.store, project, [("SECOND", FIXTURES / "assurance/policy_quality.cfg")]
    )
    window.load_run(second)
    window.navigate("devices")
    window.resource_search.setText("FIRST")
    window.device_table.selectRow(0)
    assert window.resource_findings_model.rowCount() > 0
    window.device_tabs.setCurrentIndex(3)
    window.resource_findings_table.selectRow(0)
    window.resource_details.open_findings()
    assert window.run_id == first
    assert window.finding_device.currentData() == "FIRST"
    assert window.finding_table.selectionModel().hasSelection()
    finding = window._selected_payloads(
        window.finding_table, window.finding_proxy, window.finding_model
    )[0]["finding"]
    window.finding_detail_tabs.setCurrentIndex(1)
    window.open_finding_rules()
    assert window.current_section_id == "rules"
    rules = window._selected_payloads(window.rules_table, window.rules_proxy, window.rules_model)
    assert {p["value"]["rule_id"] for p in rules} == set(finding["affected_rule_ids"])
    window.workspace_history.back()
    assert window.current_section_id == "findings"
    assert window.finding_table.selectionModel().hasSelection()
    assert window.finding_detail_tabs.currentIndex() == 1
    window.workspace_history.back()
    assert window.current_section_id == "devices"
    assert window.run_id == second
    assert window.resource_search.text() == "FIRST"
    assert window.device_tabs.currentIndex() == 3
    assert "FIRST" in window.device_detail.toPlainText()


def test_project_findings_marks_belong_to_original_run(window: Any) -> None:
    project = window.create_project("Project marks")
    first = _save_run(window.store, project, [("FIRST", FIXTURES / "assurance/policy_quality.cfg")])
    second = _save_run(
        window.store, project, [("SECOND", FIXTURES / "assurance/policy_quality.cfg")]
    )
    window.load_run(second)
    assert window.finding_scope.currentData() == "project"
    window.finding_device.setCurrentIndex(window.finding_device.findData("FIRST"))
    window.finding_table.selectRow(0)
    window.mark_combo.setCurrentIndex(window.mark_combo.findData("accepted_risk"))
    window.comment_edit.setPlainText("Synthetic decision on earlier snapshot")
    window.save_marks()
    assert window.store.get_run(first)["marks"]
    assert not window.store.get_run(second)["marks"]


def test_report_selector_and_overview_do_not_confuse_historical_runs(window: Any) -> None:
    project = window.create_project("Report context")
    first = _save_run(window.store, project, [("FIRST", FIXTURES / "assurance/policy_quality.cfg")])
    second = _save_run(
        window.store, project, [("SECOND", FIXTURES / "assurance/policy_quality.cfg")]
    )
    window.load_run(second)
    latest_label = window.last_check_label.text()
    window.navigate("reports")
    window.report_run.setCurrentIndex(window.report_run.findData(first))
    assert window.run_id == first and first in window.context_label.text()
    assert "FIRST" in window.report_summary.toPlainText()
    assert window.last_check_label.text() == latest_label
    window.open_overview_findings("high")
    assert window.run_id == second
    assert window.finding_scope.currentData() == "run"
    assert window.severity_filter.currentData() == "high"


def test_project_switch_clears_filters_and_navigation_history(window: Any) -> None:
    project = window.create_project("Filtered project")
    run = _save_run(window.store, project, [("FIRST", FIXTURES / "assurance/policy_quality.cfg")])
    window.load_run(run)
    window.navigate("devices")
    window.resource_search.setText("FIRST")
    window.navigate("findings")
    window.finding_search.setText("FIRST")
    window.create_project("Empty new project")
    assert not window.back_button.isEnabled()
    assert not window.finding_search.text() and not window.resource_search.text()
    assert window.finding_model.rowCount() == 0
    assert window.device_model.rowCount() == 0
    assert "Результатов проверок нет" in window.finding_coverage.text()


def test_rule_evidence_dialog_and_finding_attachment_use_selected_import(
    window: Any, monkeypatch: Any
) -> None:
    from PySide6.QtWidgets import QDialog, QFileDialog, QPlainTextEdit

    project = window.create_project("Evidence navigation")
    run = _save_run(window.store, project, [("DEVICE", FIXTURES / "assurance/policy_quality.cfg")])
    window.load_run(run)
    window.finding_table.selectRow(0)
    selected = window._selected_payloads(
        window.finding_table, window.finding_proxy, window.finding_model
    )[0]
    attached = []
    path = FIXTURES / "assurance/policy_quality.cfg"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (str(path), ""))
    monkeypatch.setattr(
        window, "attach_source", lambda identity, file: attached.append((identity, file))
    )
    window.attach_finding_source()
    assert attached == [(selected["item"]["id"], path)]
    window.open_finding_rules()
    dialogs = []

    def inspect_dialog(dialog: Any) -> int:
        dialogs.append(dialog.findChild(QPlainTextEdit).toPlainText())
        return 0

    monkeypatch.setattr(QDialog, "exec", inspect_dialog)
    window.resource_details.show_rule_source()
    assert len(dialogs) == 1
    assert selected["item"]["content_sha256"] in dialogs[0]
    assert "Строки:" in dialogs[0]
    window.resource_details.show_rule_json()
    assert len(dialogs) == 2
    import json

    assert (
        json.loads(dialogs[1])
        == window._selected_payloads(window.rules_table, window.rules_proxy, window.rules_model)[0][
            "value"
        ]
    )


def test_overview_can_scroll_without_squeezing_hero(window: Any, qt_app: Any) -> None:
    from PySide6.QtWidgets import QFrame

    window.resize(1280, 720)
    window.navigate("home")
    qt_app.processEvents()
    hero = window.findChild(QFrame, "hero")
    assert hero.height() >= hero.layout().minimumSize().height()
    assert window.overview_scroll.widget().height() >= window.overview_scroll.viewport().height()


def test_back_restores_settings_submenu_selection(window: Any) -> None:
    window.navigate("settings")
    window._select_settings_tab("rules", 1)
    window.navigate("devices")
    window._select_settings_tab("integrations", 0)
    window.workspace_history.back()
    assert window.settings_pages.currentIndex() == 1
    assert window.settings_nav_buttons["rules"].isChecked()
