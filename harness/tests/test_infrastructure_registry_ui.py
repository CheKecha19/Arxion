"""Synthetic infrastructure matrix behavior, independent of the database adapter."""

from copy import deepcopy
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import QDate, Qt
from PySide6.QtTest import QSignalSpy
from PySide6.QtWidgets import QApplication, QComboBox, QLineEdit

from firewall_compliance.interfaces.desktop.qt_infrastructure_registry import (
    COLUMNS,
    InfrastructureRegistryPanel,
    RegistryFilter,
    ResourceEditor,
)
from firewall_compliance.interfaces.desktop.resource_registry import ResourceRegistry

APP = None


class Registry:
    def __init__(self):
        self.rows = {"project": [], "other": []}
        self.calls = []

    def list_resources(self, project_id, *, include_archived=False):
        if project_id == "unavailable":
            raise ValueError("Хранилище недоступно")
        return deepcopy(
            [
                row
                for row in self.rows[project_id]
                if include_archived or row.get("lifecycle") != "archived"
            ]
        )

    def add_manual(self, project_id, fields):
        if not fields.get("name"):
            raise ValueError("Укажите имя ресурса")
        identity = f"manual-{len(self.rows[project_id])}"
        self.rows[project_id].append(
            {
                "id": identity,
                "origin": "manual",
                "lifecycle": "active",
                "added_at": "2026-10-26T00:00:00Z",
                "last_scan": None,
                "last_check": None,
                "metadata": {},
                **fields,
            }
        )
        self.calls.append(("add", project_id, deepcopy(fields)))
        return identity

    def update(self, project_id, resource_id, fields):
        row = next(row for row in self.rows[project_id] if row["id"] == resource_id)
        for key, value in fields.items():
            if value is None:
                row[key] = row.get("observed", {}).get(key)
                row.setdefault("metadata", {}).pop(key, None)
            else:
                row[key] = value
                row.setdefault("metadata", {})[key] = value
        self.calls.append(("update", project_id, deepcopy(fields)))

    def archive(self, project_id, resource_id):
        next(row for row in self.rows[project_id] if row["id"] == resource_id)["lifecycle"] = (
            "archived"
        )
        self.calls.append(("archive", project_id, resource_id))

    def restore(self, project_id, resource_id):
        next(row for row in self.rows[project_id] if row["id"] == resource_id)["lifecycle"] = (
            "active"
        )

    def link_manual(self, project_id, manual_id, discovered_id):
        self.calls.append(("link", project_id, manual_id, discovered_id))

    def history(self, project_id, resource_id):
        return [{"operation": "created", "resource_id": resource_id, "project_id": project_id}]


def panel(registry):
    global APP
    APP = QApplication.instance() or QApplication([])
    widget = InfrastructureRegistryPanel(registry)
    widget.set_project("project")
    return widget


def select(widget, identity):
    for row, value in enumerate(widget.model.rows):
        if value["id"] == identity:
            index = widget.proxy.mapFromSource(widget.model.index(row, 0))
            widget.table.selectRow(index.row())
            return
    raise AssertionError(identity)


def values(widget):
    return [
        widget.proxy.data(widget.proxy.index(row, 0), Qt.ItemDataRole.UserRole)
        for row in range(widget.proxy.rowCount())
    ]


def test_manual_add_edit_archive_restore_and_project_switch():
    registry = Registry()
    widget = panel(registry)
    changes = QSignalSpy(widget.changed)
    try:
        identity = widget.create_resource(
            {"name": "Manual NGFW", "category": "ngfw", "label": "Gateway"}
        )
        assert identity
        assert widget.model.rows[0]["last_scan"] is None
        assert widget.model.rows[0]["last_check"] is None
        widget.edit_resource(
            identity, {"city": "Synthetic city", "rack": "R1", "rack_position": "12U"}
        )
        select(widget, identity)
        assert not widget.operation_button.isEnabled()
        widget.archive_button.click()
        assert widget.proxy.rowCount() == 0
        widget.show_archived.setChecked(True)
        select(widget, identity)
        assert widget.restore_button.isEnabled()
        widget.restore_button.click()
        assert widget.model.rows[0]["rack"] == "R1"
        assert widget.model.rows[0]["lifecycle"] == "active"
        assert changes.count() == 4
        widget.set_project("other")
        assert widget.proxy.rowCount() == 0
        widget.set_project("project")
        assert widget.model.rows[0]["label"] == "Gateway"
    finally:
        widget.close()


def test_multiple_filters_are_intersected_across_any_fields():
    registry = Registry()
    registry.rows["project"] = [
        {
            "id": "one",
            "name": "Cloud VM",
            "city": "Moscow",
            "comments": "Database zone",
            "category": "cloud",
            "vdc": "VDC-A",
        },
        {
            "id": "two",
            "name": "Cloud VM 2",
            "city": "Moscow",
            "comments": "Application zone",
            "category": "cloud",
            "vdc": "VDC-B",
        },
        {
            "id": "three",
            "name": "Switch",
            "city": "Other city",
            "comments": "Database zone",
            "category": "network",
        },
    ]
    widget = panel(registry)
    try:
        widget.search.setText("database")
        assert {row["id"] for row in values(widget)} == {"one", "three"}
        widget.filter_field.setCurrentIndex(widget.filter_field.findData("city"))
        widget.filter_value.setText("Moscow")
        widget.add_filter_button.click()
        assert [row["id"] for row in values(widget)] == ["one"]
        widget.filter_field.setCurrentIndex(widget.filter_field.findData("vdc"))
        widget.filter_operation.setCurrentIndex(widget.filter_operation.findData("equals"))
        widget.filter_value.setText("VDC-A")
        widget.add_filter()
        assert len(widget.proxy.conditions) == 2
        assert widget.proxy.rowCount() == 1
        widget.clear_filters()
        assert widget.proxy.rowCount() == 3
    finally:
        widget.close()


def test_chronological_sort_handles_offsets_and_unknown_dates():
    registry = Registry()
    registry.rows["project"] = [
        {"id": "later", "name": "A", "last_scan": "2025-12-31T23:00:00Z"},
        {"id": "earlier", "name": "B", "last_scan": "2026-01-01T00:30:00+03:00"},
        {"id": "unknown", "name": "C", "last_scan": None},
    ]
    widget = panel(registry)
    try:
        column = next(i for i, value in enumerate(COLUMNS) if value[0] == "last_scan")
        widget.table.sortByColumn(column, Qt.SortOrder.AscendingOrder)
        assert [row["id"] for row in values(widget)] == ["unknown", "earlier", "later"]
        widget.table.sortByColumn(column, Qt.SortOrder.DescendingOrder)
        assert [row["id"] for row in values(widget)] == ["later", "earlier", "unknown"]
        widget.filter_field.setCurrentIndex(widget.filter_field.findData("last_scan"))
        widget.from_enabled.setChecked(True)
        widget.to_enabled.setChecked(True)
        widget.date_from.setDate(QDate(2025, 12, 31))
        widget.date_to.setDate(QDate(2025, 12, 31))
        widget.add_filter()
        assert {row["id"] for row in values(widget)} == {"earlier", "later"}
        widget.clear_filters()
        widget.proxy.conditions.append(RegistryFilter("last_scan", "empty"))
        widget.proxy.apply()
        assert [row["id"] for row in values(widget)] == ["unknown"]
    finally:
        widget.close()


def test_editor_sends_only_changed_metadata_and_can_restore_observed_vdc():
    global APP
    APP = QApplication.instance() or QApplication([])
    source = {
        "id": "discovered",
        "origin": "discovered",
        "name": "Imported VM",
        "platform": "VMware",
        "resource_type": "vms",
        "category": "cloud",
        "label": "Friendly",
        "vdc": "Manual VDC",
        "observed": {"vdc": "Imported VDC"},
        "metadata": {"vdc": "Manual VDC"},
    }
    editor = ResourceEditor(source)
    try:
        assert editor.values() == {}
        assert not editor.fields["name"].isEnabled()
        assert not editor.fields["category"].isEnabled()
        label = editor.fields["label"]
        assert isinstance(label, QLineEdit)
        label.setText("Another friendly label")
        assert editor.values() == {"label": "Another friendly label"}
        editor._reset("vdc")
        assert editor.values()["vdc"] is None
        assert source["vdc"] == "Manual VDC"
        assert not any(key in editor.values() for key in ("name", "platform", "category"))
    finally:
        editor.close()


def test_manual_editor_allows_labels_without_location_and_never_invents_scan_dates():
    global APP
    APP = QApplication.instance() or QApplication([])
    editor = ResourceEditor()
    try:
        name, category = editor.fields["name"], editor.fields["category"]
        assert isinstance(name, QLineEdit) and isinstance(category, QComboBox)
        name.setText("Manual firewall")
        category.setCurrentIndex(category.findData("ngfw"))
        result = editor.values()
        assert result["category"] == "ngfw" and result["country"] == ""
        assert not set(result) & {"last_scan", "last_check", "first_seen", "added_at"}
    finally:
        editor.close()


def test_link_signal_operation_and_error_does_not_expose_other_project_rows():
    registry = Registry()
    registry.rows["project"] = [
        {
            "id": "imported",
            "origin": "discovered",
            "name": "Imported",
            "source": {"scan_id": "synthetic"},
        }
    ]
    widget = panel(registry)
    operation = QSignalSpy(widget.operation_requested)
    try:
        select(widget, "imported")
        widget.operation_button.click()
        assert operation.count() == 1
        assert operation.at(0)[0]["id"] == "imported"
        widget.link_resources("manual", "imported")
        assert registry.calls[-1] == ("link", "project", "manual", "imported")
        widget.set_project("unavailable")
        assert widget.model.rowCount() == 0
        assert "недоступно" in widget.status.text()
    finally:
        widget.close()


def test_invalid_date_bounds_do_not_add_a_filter():
    widget = panel(Registry())
    try:
        widget.filter_field.setCurrentIndex(widget.filter_field.findData("last_scan"))
        widget.add_filter()
        assert not widget.proxy.conditions
        widget.from_enabled.setChecked(True)
        widget.to_enabled.setChecked(True)
        widget.date_from.setDate(QDate(2026, 2, 1))
        widget.date_to.setDate(QDate(2026, 1, 1))
        widget.add_filter()
        assert not widget.proxy.conditions
    finally:
        widget.close()


def test_editor_keeps_invalid_form_open():
    global APP
    APP = QApplication.instance() or QApplication([])
    editor = ResourceEditor()
    try:
        editor.accept()
        assert editor.result() == 0
        assert "имя" in editor.validation.text()
        name = editor.fields["name"]
        assert isinstance(name, QLineEdit)
        name.setText("Valid manual resource")
        editor.accept()
        assert editor.result() == 1
    finally:
        editor.close()


def test_unnamed_discovered_resource_can_receive_metadata():
    global APP
    APP = QApplication.instance() or QApplication([])
    editor = ResourceEditor({"id": "unnamed", "origin": "discovered", "name": ""})
    try:
        label = editor.fields["label"]
        assert isinstance(label, QLineEdit)
        label.setText("Friendly name")
        editor.accept()
        assert editor.result() == 1
        assert editor.values() == {"label": "Friendly name"}
    finally:
        editor.close()


def test_actual_registry_reopens_manual_values_without_scan_dates():
    from firewall_compliance.interfaces.desktop.project_store import ProjectStore

    global APP
    APP = QApplication.instance() or QApplication([])
    root = Path("artifacts/infrastructure-ui-tests")
    root.mkdir(parents=True, exist_ok=True)
    store = ProjectStore(root / f"{uuid4()}.sqlite3")
    project = store.create_project("Synthetic registry UI")
    registry = ResourceRegistry(store.path)
    widget = InfrastructureRegistryPanel(registry)
    try:
        widget.set_project(project)
        identity = widget.create_resource(
            {"name": "Manual NGFW", "category": "ngfw", "label": "Border"}
        )
        assert identity
        widget.edit_resource(identity, {"rack": "R10", "vdc": "Optional VDC"})
        select(widget, identity)
        widget.archive_selected()
        widget.show_archived.setChecked(True)
        select(widget, identity)
        widget.restore_selected()
        reopened = ResourceRegistry(store.path).list_resources(project)
        assert reopened[0]["label"] == "Border"
        assert reopened[0]["rack"] == "R10"
        assert reopened[0]["last_scan"] is None and reopened[0]["last_check"] is None
        assert len(registry.history(project, identity)) >= 4
    finally:
        widget.close()
