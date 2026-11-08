"""Organizational service exposure policy with explicit unknown/empty requirements."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.domain.network import PortRange
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile, PolicyServiceSelector


def _ports(text: str) -> list[dict[str, int]]:
    result = []
    for part in text.split(","):
        token = part.strip()
        if not token:
            if not text.strip():
                return []
            raise ValueError("Порты: уберите пустые элементы между запятыми.")
        pair = token.split("-")
        if len(pair) > 2 or any(not value.strip().isdigit() for value in pair):
            raise ValueError("Порты: используйте числа или диапазоны, например 443, 8000-8010.")
        port = PortRange(start=int(pair[0]), end=int(pair[-1]))
        result.append({"start": port.start, "end": port.end})
    return result


class ServiceCatalogue(QWidget):
    changed = Signal()

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.title = title
        self._loading = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.declared = QCheckBox(f"{title}: требования определены")
        self.declared.setToolTip(
            "Выключено — требования неизвестны. Включено и нет строк — явный пустой каталог."
        )
        self.declared.toggled.connect(self._changed)
        layout.addWidget(self.declared)
        self.table = QTableWidget(0, 3)
        self.table.setAccessibleName(title)
        self.table.setHorizontalHeaderLabels(("Название сервиса", "Протокол", "Порты назначения"))
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setMinimumHeight(130)
        self.table.setMaximumHeight(240)
        self.table.itemChanged.connect(self._changed)
        layout.addWidget(self.table)
        buttons = QHBoxLayout()
        self.add_button = QPushButton("Добавить сервис")
        self.add_button.clicked.connect(self.add_service)
        self.remove_button = QPushButton("Убрать выбранный")
        self.remove_button.clicked.connect(self.remove_selected)
        buttons.addWidget(self.add_button)
        buttons.addWidget(self.remove_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self._sync_enabled()

    def _sync_enabled(self) -> None:
        enabled = self.declared.isChecked()
        for widget in (self.table, self.add_button, self.remove_button):
            widget.setEnabled(enabled)

    def _changed(self, *_: Any) -> None:
        self._sync_enabled()
        if not self._loading:
            self.changed.emit()

    def add_service(self, *_: Any) -> None:
        self._loading = True
        try:
            self._append(
                {"selector_id": str(uuid4()), "name": "", "protocol": None, "port_ranges": []}
            )
        finally:
            self._loading = False
        self._changed()

    def _append(self, value: dict[str, Any]) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        name = QTableWidgetItem(str(value.get("name") or ""))
        name.setData(Qt.ItemDataRole.UserRole, value["selector_id"])
        self.table.setItem(row, 0, name)
        protocol = QComboBox()
        protocol.setAccessibleName(f"{self.title}: протокол сервиса")
        protocol.addItem("Выберите", None)
        for option in ("tcp", "udp", "icmp"):
            protocol.addItem(option.upper(), option)
        protocol.setCurrentIndex(max(0, protocol.findData(value.get("protocol"))))
        protocol.currentIndexChanged.connect(self._changed)
        self.table.setCellWidget(row, 1, protocol)
        ports = ", ".join(
            str(item["start"]) if item["start"] == item["end"] else f"{item['start']}-{item['end']}"
            for item in value.get("port_ranges", [])
        )
        self.table.setItem(row, 2, QTableWidgetItem(ports))

    def remove_selected(self) -> None:
        row = self.table.currentRow()
        if row >= 0:
            self.table.removeRow(row)
            self._changed()

    def values(self) -> list[dict[str, Any]] | None:
        if not self.declared.isChecked():
            return None
        result = []
        for row in range(self.table.rowCount()):
            name, ports = self.table.item(row, 0), self.table.item(row, 2)
            protocol = self.table.cellWidget(row, 1)
            if name is None or ports is None or not isinstance(protocol, QComboBox):
                raise ValueError(f"{self.title}: строка {row + 1} заполнена не полностью.")
            try:
                selector = PolicyServiceSelector.model_validate(
                    {
                        "selector_id": name.data(Qt.ItemDataRole.UserRole),
                        "name": name.text(),
                        "protocol": protocol.currentData(),
                        "port_ranges": _ports(ports.text()),
                    }
                )
            except ValueError:
                raise ValueError(
                    f"{self.title}, строка {row + 1}: укажите название, протокол и порты "
                    "1–65535; TCP/UDP требуют порты, ICMP — пустой список портов."
                ) from None
            result.append(selector.model_dump(mode="json"))
        return result

    def load(self, values: tuple[PolicyServiceSelector, ...] | None) -> None:
        self._loading = True
        try:
            self.table.setRowCount(0)
            self.declared.setChecked(values is not None)
            for selector in values or ():
                self._append(selector.model_dump(mode="json"))
            self._sync_enabled()
        finally:
            self._loading = False


class PolicyExposureSettings(QWidget):
    changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._loading = False
        self.profile_id = "policy-exposure"
        self.profile_version = "1"
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.catalogues: dict[str, ServiceCatalogue] = {}
        for key, title in (
            ("dangerous_services", "Опасные сервисы"),
            ("administrative_services", "Административные сервисы"),
        ):
            catalogue = ServiceCatalogue(title, self)
            catalogue.changed.connect(self._changed)
            self.catalogues[key] = catalogue
            layout.addWidget(catalogue)
        self.fields: dict[str, QLineEdit] = {}
        for key, title in (
            ("administrative_targets", "Административные цели (CIDR)"),
            ("trusted_admin_networks", "Доверенные сети администраторов (CIDR)"),
        ):
            layout.addWidget(QLabel(title))
            field = QLineEdit()
            field.setAccessibleName(title)
            field.setPlaceholderText(
                "Сети через запятую; пусто — неизвестно; [] — явный пустой список"
            )
            field.editingFinished.connect(self._changed)
            self.fields[key] = field
            layout.addWidget(field)
        self.error = QLabel()
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setWordWrap(True)
        layout.addWidget(self.error)

    def _changed(self) -> None:
        if not self._loading:
            self.changed.emit()

    def profile(self) -> PolicyExposureProfile:
        values: dict[str, Any] = {"profile_id": self.profile_id, "version": self.profile_version}
        try:
            for key, catalogue in self.catalogues.items():
                values[key] = catalogue.values()
            for key, field in self.fields.items():
                text = field.text().strip()
                values[key] = (
                    None
                    if not text
                    else []
                    if text == "[]"
                    else [part.strip() for part in text.split(",")]
                )
            profile = PolicyExposureProfile.model_validate(values)
        except ValueError as error:
            message = (
                str(error)
                if not hasattr(error, "errors")
                else "Проверьте сети CIDR и ID сервисов. Некорректный профиль не сохранён."
            )
            self.error.setText(message)
            raise ValueError(message) from None
        self.error.clear()
        return profile

    def load_profile(self, payload: dict[str, Any] | None) -> None:
        profile = PolicyExposureProfile.model_validate(payload or {})
        self._loading = True
        try:
            self.profile_id, self.profile_version = profile.profile_id, profile.version
            for key, catalogue in self.catalogues.items():
                catalogue.load(getattr(profile, key))
            for key, field in self.fields.items():
                networks = getattr(profile, key)
                field.setText("" if networks is None else ", ".join(networks) if networks else "[]")
            self.error.clear()
        finally:
            self._loading = False
