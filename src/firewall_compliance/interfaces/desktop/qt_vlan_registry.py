"""Реестр настроенных VLAN из сохранённых конфигураций выбранной площадки."""

from __future__ import annotations

import html
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from ipaddress import ip_interface
from typing import Any, cast

from PySide6.QtCore import QModelIndex, QSortFilterProxyModel, Qt, QTimer, QUrl, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableView,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.logical_networks import (
    LogicalNetworkStore,
    subnet_comparison,
)
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner, JobStatus
from firewall_compliance.interfaces.desktop.logical_network_vlan_draft import (
    LogicalNetworkVlanDraft, prepare_logical_network_vlan_drafts,
)
from firewall_compliance.interfaces.desktop.qt_models import RowsModel
from firewall_compliance.interfaces.desktop.qt_vlan_batch_preview import VlanBatchPreviewDialog


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _allowed(expression: Any, vlan_id: int) -> bool:
    if not isinstance(expression, str):
        return False
    if expression.strip() == "all":
        return True
    expression = re.sub(r"(\d+)\s+to\s+(\d+)", r"\1-\2", expression)
    for token in re.split(r"[,\s]+", expression):
        if token.isdecimal() and int(token) == vlan_id:
            return True
        bounds = re.fullmatch(r"(\d+)-(\d+)", token)
        if bounds and int(bounds[1]) <= vlan_id <= int(bounds[2]):
            return True
    return False


def vlan_records(
    items: Sequence[Mapping[str, Any]], assignments: Mapping[str, str],
    sites: Sequence[Mapping[str, str]],
) -> list[dict[str, Any]]:
    """Одна запись на VLAN устройства; совпадения номеров не объединяют L2-домены."""
    names = {site["id"]: site["name"] for site in sites}
    records: list[dict[str, Any]] = []
    for item in items:
        parsed = item.get("parse_result") or (item.get("revision") or {}).get("parse_result") or {}
        facts = parsed.get("switch_facts") or {}
        configuration = parsed.get("configuration") or {}
        device_id = str(configuration.get("device_id") or "")
        interfaces = _objects(facts.get("interfaces"))
        for vlan in _objects(facts.get("vlans")):
            vlan_id = vlan.get("vlan_id")
            if not isinstance(vlan_id, int) or not 1 <= vlan_id <= 4094:
                continue
            tagged = set(str(value) for value in vlan.get("tagged_interfaces", []))
            untagged = set(str(value) for value in vlan.get("untagged_interfaces", []))
            connections: list[dict[str, Any]] = []
            addresses: list[str] = []
            subnet_sources: dict[str, list[dict[str, Any]]] = {}
            incomplete = False
            for interface in interfaces:
                name = str(interface.get("name") or "")
                modes = []
                if (
                    interface.get("access_vlan") == vlan_id
                    or vlan_id in interface.get("untagged_vlans", [])
                    or name in untagged
                ):
                    modes.append("Access / untagged")
                    untagged.add(name)
                if vlan_id in interface.get("tagged_vlans", []) or name in tagged:
                    modes.append("Tagged")
                    tagged.add(name)
                if _allowed(interface.get("allowed_vlans"), vlan_id):
                    modes.append("Trunk: " + str(interface["allowed_vlans"]))
                    tagged.add(name)
                if interface.get("native_vlan") == vlan_id:
                    modes.append("Native (настроен)")
                is_svi = name.casefold() in {
                    f"vlan {vlan_id}", f"vlan-interface{vlan_id}", f"vlan-interface {vlan_id}",
                }
                if is_svi:
                    modes.append("L3-интерфейс VLAN")
                    for address in _objects(interface.get("addresses")):
                        cidr = address.get("cidr")
                        if address.get("status") != "known" or not isinstance(cidr, str):
                            incomplete = True
                            continue
                        try:
                            subnet = str(ip_interface(cidr).network)
                        except ValueError:
                            incomplete = True
                            continue
                        subnet_sources.setdefault(subnet, []).extend(
                            _objects(address.get("source_locations"))
                        )
                    addresses.extend(
                        str(address.get("cidr") or address.get("raw") or "Неизвестно")
                        + (" (некорректно)" if address.get("status") == "unknown" else "")
                        for address in _objects(interface.get("addresses"))
                    )
                    if interface.get("address_method") in {"dhcp", "dhcp-bootp"}:
                        addresses.append(str(interface["address_method"]) + ": адрес неизвестен")
                        incomplete = True
                if modes:
                    connections.append({
                        **interface, "membership": "; ".join(modes),
                        "vlan_addresses": _objects(interface.get("addresses")) if is_svi else [],
                    })
            records.append({
                "vlan_id": vlan_id, "name": vlan.get("name") or "—",
                "description": vlan.get("description") or "",
                "device": facts.get("hostname") or device_id,
                "binding_key": (device_id, vlan_id) if device_id else None,
                "site_id": assignments.get(device_id, ""),
                "subnet_sources": subnet_sources,
                "incomplete_subnets": incomplete,
                "item_id": item.get("id"),
                "site": names.get(assignments.get(device_id, ""), "Не назначена"),
                "addresses": addresses, "tagged": sorted(tagged), "untagged": sorted(untagged),
                "connections": connections, "source_locations": vlan.get("source_locations", []),
                "source_name": facts.get("source_name") or configuration.get("source_name"),
                "captured_at": facts.get("captured_at") or configuration.get("captured_at"),
                "revision_id": (item.get("revision") or {}).get("revision_id"),
                "content_sha256": facts.get("content_sha256"),
                "roles": [],
            })
        records.extend(_controller_vlans(item, parsed, assignments, names))
    return sorted(records, key=lambda row: (row["vlan_id"], row["site"], row["device"]))


def _controller_vlans(
    item: Mapping[str, Any], parsed: Mapping[str, Any],
    assignments: Mapping[str, str], sites: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Назначение VLAN ролью не является untagged-принадлежностью физического порта."""
    inventory = parsed.get("controller_inventory") or {}
    objects = _objects(inventory.get("objects"))
    by_id = {obj["object_id"]: obj for obj in objects}
    configuration = parsed.get("configuration") or {}
    device_id = str(configuration.get("device_id") or "")
    result: dict[int, dict[str, Any]] = {}

    def record(vlan_id: int) -> dict[str, Any]:
        if vlan_id not in result:
            result[vlan_id] = {
                "vlan_id": vlan_id, "name": "—",
                "description": "Указан в роли; отдельное объявление VLAN в экспорте не найдено",
                "device": device_id, "site": sites.get(assignments.get(device_id, ""), "Не назначена"),
                "addresses": [], "tagged": [], "untagged": [], "connections": [],
                "roles": [], "source_locations": [],
                "source_name": inventory.get("source_name") or configuration.get("source_name"),
                "captured_at": inventory.get("captured_at") or configuration.get("captured_at"),
                "revision_id": (item.get("revision") or {}).get("revision_id"),
                "content_sha256": inventory.get("content_sha256"),
            }
        return result[vlan_id]

    for obj in objects:
        if obj.get("kind") != "vlan":
            continue
        name = str(obj.get("name") or "")
        if name.isdecimal() and 1 <= int(name) <= 4094:
            row = record(int(name))
            row["name"] = (obj.get("attributes") or {}).get("name") or name
            row["description"] = obj.get("description") or ""
            row["source_locations"].extend(_objects(obj.get("source_locations")))
    for reference in _objects(inventory.get("references")):
        source = by_id.get(reference.get("source_id"), {})
        target = str(reference.get("target_name") or "")
        if source.get("kind") != "role" or reference.get("target_kind") != "vlan":
            continue
        if not target.isdecimal() or not 1 <= int(target) <= 4094:
            continue
        row = record(int(target))
        row["roles"].append(str(source["name"]))
        row["source_locations"].extend(_objects(reference.get("source_locations")))
        row["connections"].append({
            "name": source["name"], "membership": "Назначение VLAN ролью (не физический порт)",
            "description": source.get("description") or "—", "aggregate": "Не применяется",
            "admin_state": "Активное назначение клиенту не наблюдалось",
        })
    return list(result.values())


class VlanRegistryPanel(QWidget):
    """Наблюдения и подтверждённые логические сети проекта."""

    source_requested = Signal(str, object)
    matrix_groups_requested = Signal(object)

    def __init__(
        self, store: LogicalNetworkStore, parent: QWidget | None = None, *, runner: JobRunner | None = None,
    ) -> None:
        super().__init__(parent)
        self.store = store
        self._runner = runner
        self._observation_version = 0
        self._batch_pending = False
        self._recent_network_ids: tuple[str, ...] = ()
        self.project_id: str | None = None
        self.sites: Sequence[Mapping[str, str]] = ()
        self.records: list[dict[str, Any]] = []
        self.networks: list[dict[str, Any]] = []
        self.source_locations: list[dict[str, Any]] = []
        outer = QVBoxLayout(self)
        self.tabs = QTabWidget()
        outer.addWidget(self.tabs)
        observed_page = QWidget()
        self.tabs.addTab(observed_page, "Обнаруженные VLAN")
        layout = QVBoxLayout(observed_page)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск по VLAN, устройству, площадке, адресу или порту")
        self.search.setClearButtonEnabled(True)
        layout.addWidget(self.search)
        self.status = QLabel()
        layout.addWidget(self.status)
        note = QLabel(
            "Последние сохранённые конфигурации устройств в выбранной области. "
            "Одинаковый VLAN ID не доказывает общую сеть; IP-интерфейс не подтверждает роль шлюза."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        actions = QHBoxLayout()
        self.create_from_vlan = QPushButton("Создать логическую сеть")
        self.create_from_vlan.clicked.connect(self._create_from_vlan)
        self.create_batch = QPushButton("Подготовить сети из выборки…")
        self.create_batch.clicked.connect(self._create_network_batch)
        self.bind_button = QPushButton("Изменить привязку")
        self.bind_button.clicked.connect(self._choose_binding)
        self.edit_bound_network = QPushButton("Редактировать логическую сеть")
        self.edit_bound_network.clicked.connect(self._edit_bound_network)
        actions.addWidget(self.create_from_vlan)
        actions.addWidget(self.create_batch)
        actions.addWidget(self.bind_button)
        actions.addWidget(self.edit_bound_network)
        actions.addStretch()
        layout.addLayout(actions)
        self.model = RowsModel((
            "VLAN ID", "Название / описание", "Площадка", "Устройство", "IP-интерфейсы",
            "Логическая сеть", "Сравнение подсетей",
            "Access / untagged", "Tagged / trunk", "Получено", "Источник",
            "Назначено ролям",
        ))
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setAccessibleName("Реестр VLAN")
        self.table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((85, 175, 135, 180, 175, 175, 170, 200, 200, 170, 170)):
            self.table.setColumnWidth(column, width)
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        self.detail.anchorClicked.connect(self._open_source)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setSizes([450, 200])
        layout.addWidget(splitter, 1)
        self.search.textChanged.connect(self._filter)
        self.table.selectionModel().selectionChanged.connect(self._selected)

        networks_page = QWidget()
        self.tabs.addTab(networks_page, "Логические сети")
        networks_layout = QVBoxLayout(networks_page)
        network_actions = QHBoxLayout()
        self.add_network = QPushButton("Добавить сеть")
        self.add_network.clicked.connect(lambda: self._edit_network())
        self.edit_network = QPushButton("Редактировать сеть")
        self.edit_network.clicked.connect(self._edit_selected_network)
        self.confirm_vlans = QPushButton("Подтвердить предложенные VLAN")
        self.confirm_vlans.clicked.connect(self._confirm_suggestions)
        self.history_button = QPushButton("История правок")
        self.history_button.clicked.connect(self._show_history)
        self.open_matrix_groups = QPushButton("Открыть группы матрицы…")
        self.open_matrix_groups.clicked.connect(lambda: self.matrix_groups_requested.emit(self._recent_network_ids))
        for button in (self.add_network, self.edit_network, self.confirm_vlans, self.history_button):
            network_actions.addWidget(button)
        network_actions.addWidget(self.open_matrix_groups)
        network_actions.addStretch()
        networks_layout.addLayout(network_actions)
        self.network_status = QLabel()
        self.network_status.setWordWrap(True)
        self.network_status.hide()
        networks_layout.addWidget(self.network_status)
        self.network_model = RowsModel(("Название", "Площадка", "VLAN ID", "Подсети", "VRF"))
        self.network_table = QTableView()
        self.network_table.setModel(self.network_model)
        self.network_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.network_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.network_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.network_table.horizontalHeader().setStretchLastSection(True)
        self.member_model = RowsModel(("Устройство", "VLAN", "Подсети", "Сравнение", "Источник"))
        self.member_table = QTableView()
        self.member_table.setModel(self.member_model)
        self.member_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.member_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.member_table.doubleClicked.connect(self._open_member)
        self.member_table.setAccessibleName("Привязанные VLAN в выбранной области")
        members_page = QWidget()
        members_layout = QVBoxLayout(members_page)
        members_layout.addWidget(QLabel("Привязанные VLAN в выбранной области"))
        members_layout.addWidget(self.member_table)
        networks_splitter = QSplitter(Qt.Orientation.Vertical)
        networks_splitter.addWidget(self.network_table)
        networks_splitter.addWidget(members_page)
        networks_layout.addWidget(networks_splitter)
        self.network_table.selectionModel().selectionChanged.connect(self._network_selected)
        self.set_items([], {}, ())

    def set_items(
        self, items: Sequence[Mapping[str, Any]], assignments: Mapping[str, str],
        sites: Sequence[Mapping[str, str]],
        *, project_id: str | None = None,
    ) -> None:
        if project_id != self.project_id:
            self._recent_network_ids = ()
            self.table.clearSelection()
            self.network_table.clearSelection()
            self.network_status.hide()
        self._observation_version += 1
        self.project_id = project_id
        self.sites = sites
        self.records = vlan_records(items, assignments, sites)
        self._refresh()

    def _refresh(self) -> None:
        previous = self._current_row()
        selected_key = previous.get("binding_key") if previous else None
        previous_network = self._current_network()
        project_id = self.project_id
        self.networks, bindings = self.store.read(project_id) if project_id else ([], {})
        by_id = {network["id"]: network for network in self.networks}
        site_names = {site["id"]: site["name"] for site in self.sites}
        self.network_model.replace([
            (network["name"], site_names.get(network["site_id"], "Не назначена"),
             network["vlan_id"], ", ".join(network["subnets"]) or "—", network["vrf"] or "—")
            for network in self.networks
        ], self.networks)
        self.add_network.setEnabled(bool(project_id))
        self.history_button.setEnabled(bool(project_id))
        self.open_matrix_groups.setEnabled(bool(project_id and self.networks))
        records = []
        selected_index = None
        for observation in self.records:
            row = dict(observation)
            key = row.get("binding_key")
            network_id = bindings.get(key)
            network = by_id.get(network_id) if network_id is not None else None
            row["network"] = network
            row["comparison"] = "Не привязан" if key else "—"
            row["unexpected"] = set()
            if network is not None:
                row["comparison"], row["unexpected"] = subnet_comparison(
                    set(row["subnet_sources"]), network["subnets"],
                    incomplete=row["incomplete_subnets"],
                )
            if selected_key and key == selected_key:
                selected_index = len(records)
            records.append(row)
        self.model.replace([
            (row["vlan_id"], str(row["name"]) + (" · " + row["description"] if row["description"] else ""),
             row["site"], row["device"], ", ".join(row["addresses"]) or "Не установлены",
             row["network"]["name"] if row["network"] else "—", row["comparison"],
             ", ".join(row["untagged"]) or "—", ", ".join(row["tagged"]) or "—",
             row["captured_at"] or "Неизвестно", row["source_name"] or "—",
             ", ".join(row.get("roles", [])) or "—")
            for row in records
        ], records)
        if selected_index is not None:
            index = self.proxy.mapFromSource(self.model.index(selected_index, 0))
            if index.isValid():
                self.table.selectRow(index.row())
        if previous_network is not None:
            self._select_network(previous_network["id"])
        self._network_selected()
        self._selected()
        if not records:
            self.detail.setPlainText(
                "Импортируйте конфигурации с поддержанным разделом VLAN."
            )
        self._filter(self.search.text())

    def _network_selected(self, *_: Any) -> None:
        network = self._current_network()
        self.edit_network.setEnabled(network is not None)
        self.confirm_vlans.setEnabled(network is not None and bool(self._suggestions(network)))
        members = [
            row for row in self.model.payloads
            if network is not None and row["network"] == network
        ]
        self.member_model.replace([
            (row["device"], row["vlan_id"], ", ".join(sorted(row["subnet_sources"])) or "—",
             row["comparison"], row["source_name"] or "—")
            for row in members
        ], members)

    def _current_network(self) -> dict[str, Any] | None:
        selected = self.network_table.selectionModel().selectedRows()
        if selected and selected[0].row() < len(self.network_model.payloads):
            return self.network_model.payloads[selected[0].row()]
        return None

    def _select_network(self, network_id: str) -> None:
        for index, network in enumerate(self.networks):
            if network["id"] == network_id:
                self.network_table.selectRow(index)
                break

    def _edit_selected_network(self) -> None:
        network = self._current_network()
        if network is not None:
            self._edit_network(network)

    def _open_member(self, index: QModelIndex) -> None:
        row = self.member_model.payloads[index.row()]
        self.search.clear()
        source_row = self.model.payloads.index(row)
        target = self.proxy.mapFromSource(self.model.index(source_row, 0))
        self.tabs.setCurrentIndex(0)
        self.table.selectRow(target.row())
        self.table.scrollTo(target)

    def _suggestions(self, network: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            row for row in self.model.payloads
            if row.get("binding_key") and row["network"] is None
            and network["site_id"] and row["site_id"] == network["site_id"]
            and row["vlan_id"] == network["vlan_id"]
        ]

    def _confirm_suggestions(self) -> None:
        project_id = self.project_id
        network = self._current_network()
        if not project_id or network is None:
            return
        rows = self._suggestions(network)
        if not rows:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Предложенные VLAN · {network['name']}")
        dialog.resize(860, 440)
        layout = QVBoxLayout(dialog)
        expected = ", ".join(network["subnets"]) or "—"
        note = QLabel(f"Ожидаемые подсети: {expected}. Выберите VLAN для подтверждения.")
        note.setTextFormat(Qt.TextFormat.PlainText)
        note.setWordWrap(True)
        layout.addWidget(note)
        model = RowsModel(("Устройство", "Обнаруженные подсети", "Сравнение", "Источник"))
        model.replace([
            (row["device"], ", ".join(sorted(row["subnet_sources"])) or "—",
             subnet_comparison(
                 set(row["subnet_sources"]), network["subnets"],
                 incomplete=row["incomplete_subnets"],
             )[0],
             row["source_name"] or "—")
            for row in rows
        ], rows)
        table = QTableView()
        table.setModel(model)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(table)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        confirm = buttons.button(QDialogButtonBox.StandardButton.Ok)
        confirm.setText("Подтвердить привязки")
        confirm.setEnabled(False)
        table.selectionModel().selectionChanged.connect(
            lambda *_: confirm.setEnabled(bool(table.selectionModel().selectedRows()))
        )
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        def save() -> None:
            keys = [
                rows[index.row()]["binding_key"]
                for index in table.selectionModel().selectedRows()
            ]
            if not keys:
                return
            try:
                self.store.confirm_suggestions(
                    project_id, network["id"], network["site_id"], network["vlan_id"], keys,
                )
            except (ValueError, sqlite3.Error) as error:
                QMessageBox.warning(dialog, "Привязки VLAN", str(error))
                dialog.reject()
                self._refresh()
                return
            dialog.accept()

        buttons.accepted.connect(save)
        if dialog.exec():
            self._refresh()

    def _current_row(self) -> dict[str, Any] | None:
        selected = self.table.selectionModel().selectedRows()
        if selected:
            index = self.proxy.mapToSource(selected[0])
            if index.isValid() and index.row() < len(self.model.payloads):
                return self.model.payloads[index.row()]
        return None

    def _create_from_vlan(self) -> None:
        row = self._current_row()
        if row and row.get("binding_key"):
            self._edit_network(observation=row)

    def _create_network_batch(self) -> None:
        project_id = self.project_id
        if project_id is None or self._batch_pending:
            return
        version = self._observation_version
        rows = tuple(
            self.model.payloads[index.row()]
            for proxy_row in range(self.proxy.rowCount())
            if (index := self.proxy.mapToSource(self.proxy.index(proxy_row, 0))).isValid()
        )
        if not rows:
            return
        self._batch_pending = True
        self._filter(self.search.text())
        self.status.setText("Подготавливаем логические сети из выбранных наблюдений…")

        def prepare() -> tuple[LogicalNetworkVlanDraft, ...]:
            networks, bindings = self.store.read(project_id)
            return prepare_logical_network_vlan_drafts(rows, networks, bindings)

        def prepared(value: object) -> None:
            if self.project_id != project_id or self._observation_version != version:
                self._batch_pending = False
                self._filter(self.search.text())
                return
            if isinstance(value, JobError):
                self._batch_pending = False
                self._filter(self.search.text())
                self.status.setText(value.message)
                return
            dialog = VlanBatchPreviewDialog(cast(tuple[LogicalNetworkVlanDraft, ...], value), self)
            accepted = dialog.exec() == QDialog.DialogCode.Accepted
            candidates = dialog.selected_candidates() if accepted else ()
            dialog.deleteLater()
            self._batch_pending = False
            self._filter(self.search.text())
            if not candidates:
                return
            if self.project_id != project_id or self._observation_version != version:
                self.status.setText("Наблюдения изменились. Обновите предпросмотр.")
                return
            try:
                identifiers = self.store.create_from_vlans(project_id, candidates)
            except (ValueError, sqlite3.Error) as error:
                QMessageBox.warning(self, "Логические сети", str(error))
                self._refresh()
                return
            self._refresh()
            if identifiers:
                self._recent_network_ids = identifiers
                self._select_network(identifiers[0])
                self.tabs.setCurrentIndex(1)
                self.network_status.setText(
                    f"Создано логических сетей: {len(identifiers)}. "
                    "Откройте группы матрицы, чтобы выбрать эти сети из каталога."
                )
                self.network_status.show()
                self.open_matrix_groups.setFocus()

        if self._runner is None:
            try:
                prepared(prepare())
            except (ValueError, sqlite3.Error) as error:
                prepared(JobError("logical_networks", str(error)))
        else:
            job_id = self._runner.submit(prepare, prepared)
            timer = QTimer(self)
            timer.setInterval(150)

            def check_job() -> None:
                state = self._runner.status(job_id) if self._runner is not None else None
                if state in (JobStatus.PENDING, JobStatus.RUNNING):
                    return
                timer.stop()
                timer.deleteLater()
                if state == JobStatus.CANCELED:
                    prepared(JobError("cancelled", "Подготовка логических сетей отменена."))

            timer.timeout.connect(check_job)
            timer.start()

    def _edit_bound_network(self) -> None:
        row = self._current_row()
        if row and row["network"]:
            self._edit_network(row["network"])

    def _edit_network(
        self, network: dict[str, Any] | None = None, *, observation: dict[str, Any] | None = None
    ) -> None:
        project_id = self.project_id
        if not project_id:
            return
        defaults = network or observation or {}
        dialog = QDialog(self)
        dialog.setWindowTitle("Логическая сеть")
        form = QFormLayout(dialog)
        default_name = defaults.get("name", "")
        name = QLineEdit("" if default_name == "—" else default_name)
        site = QComboBox()
        site.addItem("Не назначена", "")
        for entry in self.sites:
            site.addItem(entry["name"], entry["id"])
        site_id = defaults.get("site_id", "")
        if site.findData(site_id) < 0:
            site.addItem("Площадка недоступна", site_id)
        site.setCurrentIndex(site.findData(site_id))
        vlan = QSpinBox()
        vlan.setRange(1, 4094)
        vlan.setValue(defaults.get("vlan_id", 1))
        default_subnets = defaults.get("subnets", sorted(defaults.get("subnet_sources", {})))
        subnets = QLineEdit(", ".join(default_subnets))
        subnets.setPlaceholderText("10.20.100.0/24, 2001:db8:100::/64")
        vrf = QLineEdit(defaults.get("vrf", ""))
        for label, field in (
            ("Название", name), ("Площадка", site), ("Ожидаемый VLAN ID", vlan),
            ("Ожидаемые подсети", subnets), ("VRF", vrf),
        ):
            form.addRow(label, field)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        form.addRow(buttons)
        buttons.rejected.connect(dialog.reject)
        saved_id: str | None = None

        def save() -> None:
            nonlocal saved_id
            try:
                saved_id = self.store.save(
                    project_id, name=name.text(), site_id=site.currentData(), vlan_id=vlan.value(),
                    subnets=subnets.text().replace(",", " ").split(), vrf=vrf.text(),
                    network_id=network["id"] if network else None,
                    binding=observation["binding_key"] if observation else None,
                )
            except (ValueError, sqlite3.Error) as error:
                QMessageBox.warning(dialog, "Логическая сеть", str(error))
                return
            dialog.accept()

        buttons.accepted.connect(save)
        if dialog.exec() and saved_id is not None:
            self._refresh()
            self._select_network(saved_id)
            if observation is not None:
                self.tabs.setCurrentIndex(1)

    def _choose_binding(self) -> None:
        row = self._current_row()
        project_id = self.project_id
        if not project_id or not row or not row.get("binding_key"):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Привязка VLAN {row['vlan_id']} · {row['device']}")
        form = QFormLayout(dialog)
        target = QComboBox()
        target.addItem("Без привязки", None)
        site_names = {site["id"]: site["name"] for site in self.sites}
        for network in self.networks:
            same_site = bool(row["site_id"]) and row["site_id"] == network["site_id"]
            suggested = same_site and row["vlan_id"] == network["vlan_id"]
            label = (
                f"{network['name']} · {site_names.get(network['site_id'], 'Не назначена')}"
                f" · VLAN {network['vlan_id']}"
                + (f" · VRF {network['vrf']}" if network["vrf"] else "")
                + (" · предложено" if suggested else "")
            )
            target.addItem(label, network["id"])
        if row["network"]:
            target.setCurrentIndex(target.findData(row["network"]["id"]))
        form.addRow("Логическая сеть", target)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        def save() -> None:
            try:
                self.store.bind(project_id, row["binding_key"], target.currentData())
            except (ValueError, sqlite3.Error) as error:
                QMessageBox.warning(dialog, "Привязка VLAN", str(error))
                return
            dialog.accept()

        buttons.accepted.connect(save)
        if dialog.exec():
            self._refresh()

    def _show_history(self) -> None:
        if not self.project_id:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("История правок логических сетей")
        dialog.resize(780, 480)
        layout = QVBoxLayout(dialog)
        history = QTextBrowser()
        events = self.store.history(self.project_id)
        history.setPlainText("\n\n".join(
            f"{event['created_at']} · {event['action']}\n"
            + "\n".join(
                f"{label}\n" + json.dumps(json.loads(event[key]), ensure_ascii=False, indent=2)
                for label, key in (("До", "before_value"), ("После", "after_value"))
            )
            for event in events
        ) or "Правок пока нет.")
        layout.addWidget(history)
        dialog.exec()

    def _filter(self, value: str) -> None:
        self.proxy.setFilterFixedString(value)
        self.create_batch.setEnabled(bool(self.project_id and self.proxy.rowCount() and not self._batch_pending))
        self.status.setText(
            f"Показано записей VLAN: {self.proxy.rowCount()} из {len(self.model.rows)} · "
            "сведения конфигурации, рабочее состояние неизвестно"
        )

    def _selected(self, *_: Any) -> None:
        row = self._current_row()
        editable = bool(self.project_id and row and row.get("binding_key"))
        self.create_from_vlan.setEnabled(editable and bool(row and not row["network"]))
        self.bind_button.setEnabled(editable and bool(self.networks))
        self.edit_bound_network.setEnabled(bool(row and row["network"]))
        self.source_locations = []
        if row is None:
            self.detail.setPlainText("Выберите VLAN для просмотра подключений и источников.")
            return

        def escape(value: Any) -> str:
            return html.escape(str(value))

        parts = [
            f"<h3>VLAN {row['vlan_id']} · {escape(row['name'])}</h3>",
            f"<p>{escape(row['device'])} · {escape(row['site'])}</p>",
            "<p>Полнота: частичный конфигурационный срез. Шлюз и внешняя фильтрация не подтверждены.</p>",
        ]
        network = row["network"]
        if network:
            parts.append(
                f"<p>{escape(network['name'])} · {escape(row['comparison'])}<br>"
                f"Ожидаемые подсети: {escape(', '.join(network['subnets']) or '—')}<br>"
                f"Обнаруженные подсети: {escape(', '.join(sorted(row['subnet_sources'])) or '—')}</p>"
            )
            for subnet in sorted(row["unexpected"]):
                parts.append(f"<p>Неожиданная подсеть: {escape(subnet)}</p>")
                for location in row["subnet_sources"][subnet]:
                    parts.append(self._source_link(row, location))
        parts.append(
            "<table><tr><th>Интерфейс</th><th>Подключение</th><th>Описание</th>"
            "<th>Агрегат</th><th>Адм. состояние</th><th>IP-адреса</th></tr>"
        )
        for connection in row["connections"]:
            parts.append("<tr>" + "".join(
                f"<td>{escape(connection.get(key) or '—')}</td>"
                for key in ("name", "membership", "description", "aggregate", "admin_state")
            ) + "<td>" + "<br>".join(
                escape(address.get("cidr") or address.get("raw") or "Неизвестно")
                for address in connection.get("vlan_addresses", [])
            ) + "</td></tr>")
        parts.append("</table>")
        parts.append(f"<p>Ревизия: {escape(row['revision_id'])}<br>SHA-256: {escape(row['content_sha256'])}</p>")
        for location in _objects(row["source_locations"]):
            parts.append(self._source_link(row, location))
        self.detail.setHtml("".join(parts))

    def _source_link(self, row: dict[str, Any], location: dict[str, Any]) -> str:
        label = html.escape(f"{location.get('source_name')}:{location.get('line_start')}")
        if row.get("item_id"):
            index = len(self.source_locations)
            self.source_locations.append(location)
            return f'<p>Источник: <a href="source:{index}">{label}</a></p>'
        return f"<p>Источник: {label}</p>"

    def _open_source(self, url: QUrl) -> None:
        row = self._current_row()
        index = url.path()
        if url.scheme() == "source" and index.isdecimal() and row and row.get("item_id"):
            number = int(index)
            if number < len(self.source_locations):
                self.source_requested.emit(str(row["item_id"]), self.source_locations[number])
