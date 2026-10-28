"""Synthetic Qt/SQLite contracts for cumulative registry, dashboard and project map."""

import os
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QApplication

from firewall_compliance.interfaces.desktop.cloud_analysis import analyze_saved_vmware
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow
from firewall_compliance.interfaces.desktop.qt_theme import apply_theme

APP = None
CONFIG = {"platform": "vmware", "site": "https://synthetic.invalid", "tenant": "synthetic"}


@pytest.fixture
def window():
    global APP
    APP = QApplication.instance() or QApplication([])
    if os.name == "nt" and not QFontDatabase.families():
        system_font = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "arial.ttf"
        assert QFontDatabase.addApplicationFont(str(system_font)) >= 0
    root = Path("artifacts/registry-dashboard-integration")
    root.mkdir(parents=True, exist_ok=True)
    widget = MainWindow(store=ProjectStore(root / f"{uuid4()}.sqlite3"))
    try:
        yield widget
    finally:
        widget.close()
        APP.processEvents()


def save_scan(store, project, suffix, *, analyze=True):
    edge = {
        "type": "edges",
        "id": f"urn:vcloud:gateway:aaaaaaaa-bbbb-cccc-dddd-{suffix:012d}",
        "name": f"Synthetic Edge {suffix}",
        "collected_at": "2026-10-26T00:00:00+00:00",
        "inventory": {"ownerRef": {"id": "urn:vcloud:vdc:synthetic-vdc", "name": "VDC test"}},
        "data": {
            "firewall": {
                "systemRules": [],
                "defaultRules": [],
                "userDefinedRules": [
                    {
                        "id": "synthetic-rule",
                        "name": "Synthetic rule",
                        "actionValue": "ALLOW",
                        "active": True,
                        "direction": "IN_OUT",
                        "ipProtocol": "IPV4",
                        "sourceFirewallGroups": None,
                        "sourceFirewallIpAddresses": None,
                        "destinationFirewallGroups": None,
                        "destinationFirewallIpAddresses": None,
                        "applicationPortProfiles": None,
                        "rawPortProtocols": None,
                        "logging": False,
                        "description": "",
                    }
                ],
            }
        },
    }
    vm = {
        "type": "vms",
        "id": f"vm-{suffix}",
        "name": f"Synthetic VM {suffix}",
        "inventory": {"ipAddress": f"10.0.{suffix}.5", "vdcName": "VDC test"},
        "data": {},
    }
    scan_id = store.create_cloud_scan(project, {}, CONFIG)
    store.finish_cloud_scan(scan_id, {"state": "completed", "records": [edge, vm], "errors": []})
    saved = next(scan for scan in store.list_cloud_scans(project) if scan["id"] == scan_id)
    run_id = None
    if analyze:
        payloads = analyze_saved_vmware(saved, {}, Event())
        run_id = store.save_cloud_analysis(scan_id, payloads, {})
    return scan_id, run_id


def refresh(window):
    window._refresh_all()
    window._refresh_project_map()
    return window.registry_panel.model.rows, window.compact_dashboard.snapshot


def saved_scan(store, project, scan_id):
    return next(scan for scan in store.list_cloud_scans(project) if scan["id"] == scan_id)


def select(window, resource_id):
    panel = window.registry_panel
    row = next(index for index, item in enumerate(panel.model.rows) if item["id"] == resource_id)
    panel.table.selectRow(panel.proxy.mapFromSource(panel.model.index(row, 0)).row())


def test_empty_window_then_manual_resources_are_not_claimed_as_checked(window):
    assert window.project_id is None
    assert not window.registry_panel.model.rows
    assert window.compact_dashboard.snapshot.active_resources == 0
    project = window.create_project("Synthetic manual project")
    resource_id = window.registry_panel.create_resource(
        {"name": "Manual NGFW", "category": "ngfw", "label": "Border"}
    )
    assert resource_id
    snapshot = window.compact_dashboard.snapshot
    assert snapshot.active_resources == 1 and snapshot.analysis_runs == 0
    assert next(row for row in snapshot.categories if row.category == "ngfw").unchecked == 1
    assert not window.project_map_widget.graph.nodes
    select(window, resource_id)
    window.registry_panel.archive_selected()
    assert window.compact_dashboard.snapshot.active_resources == 0
    assert window.compact_dashboard.snapshot.archived_resources == 1
    window.registry_panel.show_archived.setChecked(True)
    select(window, resource_id)
    window.registry_panel.restore_selected()
    assert window.compact_dashboard.snapshot.active_resources == 1
    assert window.store.resource_registry.list_resources(project)[0]["last_check"] is None


def test_all_saved_runs_and_scans_accumulate_and_metadata_survives_reopen(window):
    project = window.create_project("Cumulative synthetic")
    scan_one, run_one = save_scan(window.store, project, 1)
    rows, snapshot = refresh(window)
    assert len(rows) == 2 and snapshot.analysis_runs == 1
    original = next(row for row in rows if row["name"] == "Synthetic Edge 1")
    window.registry_panel.edit_resource(
        original["id"], {"label": "Human border", "comments": "Keep note", "vdc": "User VDC"}
    )
    _, run_two = save_scan(window.store, project, 2)
    window.load_run(run_two)
    rows, snapshot = refresh(window)
    assert len(rows) == 4 and snapshot.analysis_runs == 2
    assert snapshot.virtual_machines == 2 and snapshot.executed_checks > 0
    assert {operation.operation_id for operation in snapshot.recent_checks} == {run_one, run_two}
    assert {row["name"] for row in rows} == {
        "Synthetic Edge 1",
        "Synthetic Edge 2",
        "Synthetic VM 1",
        "Synthetic VM 2",
    }
    node_names = {node.label for node in window.project_map_widget.graph.nodes}
    assert {
        "Synthetic Edge 1",
        "Synthetic Edge 2",
        "Synthetic VM 1",
        "Synthetic VM 2",
    } <= node_names
    assert (
        saved_scan(window.store, project, scan_one)["result"]["records"][0]["name"]
        == "Synthetic Edge 1"
    )
    reopened = MainWindow(store=ProjectStore(window.store.path))
    try:
        reopened.refresh_projects(project)
        rows, snapshot = refresh(reopened)
        restored = next(row for row in rows if row["id"] == original["id"])
        assert restored["name"] == "Synthetic Edge 1" and restored["label"] == "Human border"
        assert restored["comments"] == "Keep note" and restored["vdc"] == "User VDC"
        assert snapshot.active_resources == 4 and snapshot.analysis_runs == 2
    finally:
        reopened.close()


@pytest.mark.parametrize("resource_type", ["vms", "edges"])
def test_archive_hides_cloud_map_resource_and_restore_keeps_saved_evidence(window, resource_type):
    project = window.create_project("Synthetic lifecycle")
    scan_id, _ = save_scan(window.store, project, 3)
    rows, _ = refresh(window)
    resource = next(row for row in rows if row["resource_type"] == resource_type)
    before = saved_scan(window.store, project, scan_id)
    select(window, resource["id"])
    window.registry_panel.archive_selected()
    assert window.compact_dashboard.snapshot.active_resources == 1
    assert window.compact_dashboard.snapshot.virtual_machines == (
        0 if resource_type == "vms" else 1
    )
    assert resource["name"] not in {node.label for node in window.project_map_widget.graph.nodes}
    window.registry_panel.show_archived.setChecked(True)
    select(window, resource["id"])
    window.registry_panel.restore_selected()
    assert window.compact_dashboard.snapshot.virtual_machines == 1
    assert resource["name"] in {node.label for node in window.project_map_widget.graph.nodes}
    assert saved_scan(window.store, project, scan_id) == before


def test_project_switch_isolation_and_old_report_operation_navigation(window):
    first = window.create_project("Synthetic first")
    _, run_old = save_scan(window.store, first, 4)
    _, run_new = save_scan(window.store, first, 5)
    rows, _ = refresh(window)
    old = next(row for row in rows if row["name"] == "Synthetic Edge 4")
    collected = next(row for row in rows if row["name"] == "Synthetic VM 4")
    assert old["source"]["run_id"] == run_old
    second = window.create_project("Synthetic isolated")
    rows, snapshot = refresh(window)
    assert not rows and not snapshot.active_resources and not snapshot.analysis_runs
    assert not window.project_map_widget.graph.nodes
    window._open_registry_operation(old)
    assert window.project_id == second and window.run_id is None
    window.refresh_projects(first)
    window.load_run(run_new)
    window._open_registry_operation(old)
    assert window.run_id == run_old and window.current_section_id == "reports"
    assert window.compact_dashboard.snapshot.analysis_runs == 2
    assert len(window.registry_panel.model.rows) == 4
    window._open_registry_operation(collected)
    assert window.current_section_id == "scans"
    assert window.cloud_panel.history.currentData()["id"] == collected["source"]["scan_id"]


def test_themed_minimum_window_retains_five_visible_registry_rows(window):
    apply_theme(APP)
    project = window.create_project("Synthetic geometry")
    for index in range(12):
        window.store.resource_registry.add_manual(project, {"name": f"Device {index}"})
    refresh(window)
    window.navigate("devices")
    window.resize(1000, 650)
    window.show()
    APP.processEvents()
    assert window.width() == 1000 and window.height() == 650
    panel = window.registry_panel
    row_height = panel.table.verticalHeader().defaultSectionSize()
    assert row_height >= 30
    assert panel.active_filters.isHidden()
    assert panel.table.viewport().height() >= 5 * row_height
    panel.filter_value.setText("Device")
    panel.add_filter()
    APP.processEvents()
    assert not panel.active_filters.isHidden()
    assert panel.proxy.rowCount() == 12
    assert panel.table.viewport().height() >= 4 * row_height
    for control in (
        panel.search,
        panel.show_archived,
        panel.audit_button,
        panel.filter_field,
        panel.filter_operation,
        panel.filter_value,
        panel.add_filter_button,
        panel.active_filters,
        panel.add_button,
        panel.edit_button,
        panel.archive_button,
        panel.restore_button,
        panel.link_button,
        panel.operation_button,
    ):
        assert control.isVisible()
        position = control.mapTo(panel, control.rect().topLeft())
        assert position.x() >= 0 and position.y() >= 0
        assert position.x() + control.width() <= panel.width()
        assert position.y() + control.height() <= panel.height()
    panel.clear_filters()
    APP.processEvents()
    assert panel.active_filters.isHidden()
    assert panel.proxy.rowCount() == 12
