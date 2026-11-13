"""Editable accumulated infrastructure registry, separate from imported evidence."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cached_property
from ipaddress import IPv4Network, IPv6Network, ip_network
from threading import Event
from typing import Any, Protocol

from PySide6.QtCore import (
    QAbstractTableModel,
    QDate,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
    QTimer,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.qt_resource_batch import ResourceBatchDialog
from firewall_compliance.interfaces.desktop.resource_registry import (
    MATRIX_BINDING_FIELD,
    MATRIX_SOURCE_BINDINGS_FIELD,
    resource_address_binding,
    resource_source_address_bindings,
)


class Registry(Protocol):
    def list_resources(
        self, project_id: str, *, include_archived: bool = False
    ) -> list[dict[str, Any]]: ...
    def add_manual(self, project_id: str, fields: dict[str, Any]) -> str: ...
    def add_manual_batch(self, project_id: str, rows: Sequence[Mapping[str, Any]]) -> tuple[str, ...]: ...
    def update(self, project_id: str, resource_id: str, fields: dict[str, Any]) -> None: ...
    def archive(self, project_id: str, resource_id: str) -> None: ...
    def restore(self, project_id: str, resource_id: str) -> None: ...
    def link_manual(self, project_id: str, manual_id: str, discovered_id: str) -> None: ...
    def history(self, project_id: str, resource_id: str) -> list[dict[str, Any]]: ...


CATEGORIES = {
    "unclassified": "Не классифицировано",
    "ngfw": "NGFW",
    "network": "Сетевое оборудование",
    "cloud": "Облачный сегмент",
}
Index = QModelIndex | QPersistentModelIndex
AddressNetwork = IPv4Network | IPv6Network
EMPTY_INDEX = QModelIndex()
LOCATION_FIELDS = (
    ("country", "Страна"),
    ("region", "Регион"),
    ("province", "Область / субъект"),
    ("city", "Город"),
    ("site", "Здание / площадка"),
    ("street", "Улица"),
    ("house", "Дом"),
    ("floor", "Этаж"),
    ("room", "Помещение"),
    ("rack", "Стойка"),
    ("rack_position", "Место в стойке"),
)
COLUMNS = (
    ("name", "Имя из источника"),
    ("label", "Подпись"),
    ("addresses", "IP-адреса и сети"),
    ("category", "Категория"),
    ("platform", "Платформа"),
    ("resource_type", "Тип ресурса"),
    ("status", "Статус пользователя"),
    ("lifecycle", "Состояние реестра"),
    ("check_state", "Проверка"),
    ("vdc", "VDC"),
    ("description", "Описание"),
    ("comments", "Комментарии"),
    ("added_at", "Добавлен (UTC)"),
    ("first_seen", "Впервые обнаружен (UTC)"),
    ("last_scan", "Последний сбор (UTC)"),
    ("last_check", "Последняя проверка (UTC)"),
    *LOCATION_FIELDS,
    ("origin", "Происхождение"),
)
DATE_FIELDS = {"added_at", "first_seen", "last_scan", "last_check"}


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(UTC) if result.tzinfo else result.replace(tzinfo=UTC)
    except ValueError:
        return None


def _text(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    if key == "category":
        return CATEGORIES.get(str(value), str(value or ""))
    if key == "lifecycle":
        return {"active": "Активен", "archived": "В архиве"}.get(str(value), str(value or ""))
    if key == "origin":
        return {"manual": "Добавлен вручную", "discovered": "Обнаружен"}.get(
            str(value), str(value or "")
        )
    if key == "check_state":
        explicit = row.get("check_state")
        return (
            str(explicit)
            if explicit
            else "Проверялось"
            if row.get("last_check")
            else "Не проверялось"
        )
    if key in DATE_FIELDS:
        stamp = _timestamp(value)
        return stamp.strftime("%Y-%m-%d %H:%M:%S UTC") if stamp else ""
    return str(value) if value is not None else ""


def _network(value: str, *, strict: bool = True) -> AddressNetwork | None:
    try:
        return ip_network(value.strip(), strict=strict) if "%" not in value else None
    except ValueError:
        return None


def _networks(values: object) -> tuple[AddressNetwork, ...]:
    if not isinstance(values, (tuple, list)):
        return ()
    return tuple(
        dict.fromkeys(
            network
            for value in values
            if isinstance(value, str) and (network := _network(value)) is not None
        )
    )


def _address_text(networks: tuple[AddressNetwork, ...]) -> str:
    return ", ".join(
        str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
        for network in networks
    )


def _overlaps(network: AddressNetwork, candidates: tuple[AddressNetwork, ...]) -> bool:
    return any(
        network.version == candidate.version and network.overlaps(candidate)
        for candidate in candidates
    )


@dataclass(frozen=True, slots=True)
class _SearchRow:
    text: dict[str, str]
    normalized: dict[str, str]
    haystack: str
    dates: dict[str, datetime | None]
    addresses: tuple[AddressNetwork, ...]
    address_tooltip: str

    @classmethod
    def read(cls, row: dict[str, Any]) -> _SearchRow:
        metadata = row.get("metadata")
        binding = row.get(MATRIX_BINDING_FIELD)
        if isinstance(metadata, Mapping):
            binding = metadata.get(MATRIX_BINDING_FIELD, binding)
        confirmed = _networks(binding.get("prefixes")) if isinstance(binding, Mapping) else ()
        observed = _networks(row.get("observed_addresses"))
        addresses = tuple(dict.fromkeys((*observed, *confirmed)))
        dates = {key: _timestamp(row.get(key)) for key in DATE_FIELDS}
        values = {}
        for key, _ in COLUMNS:
            if key == "addresses":
                values[key] = _address_text(addresses)
            elif key in dates:
                stamp = dates[key]
                values[key] = stamp.strftime("%Y-%m-%d %H:%M:%S UTC") if stamp else ""
            else:
                values[key] = _text(row, key)
        normalized = {key: value.casefold() for key, value in values.items()}
        observed_text, confirmed_text = _address_text(observed), _address_text(confirmed)
        tooltip = (
            f"Из источника: {observed_text or 'неизвестно'}\n"
            f"Подтверждено в карточке: {confirmed_text or 'не указано'}"
        )
        return cls(values, normalized, " ".join(normalized.values()), dates, addresses, tooltip)


class RegistryRows(QAbstractTableModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.rows: list[dict[str, Any]] = []
        self.search_rows: list[_SearchRow] = []

    def rowCount(self, parent: Index = EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: Index = EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or index.row() >= len(self.rows):
            return None
        key = COLUMNS[index.column()][0]
        search = self.search_rows[index.row()]
        if role == Qt.ItemDataRole.ToolTipRole and key == "addresses":
            return search.address_tooltip
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            unknown = "Неизвестно" if key in DATE_FIELDS or key == "addresses" else "—"
            return search.text[key] or unknown
        if role == Qt.ItemDataRole.UserRole:
            return self.rows[index.row()]
        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section][1]
        return super().headerData(section, orientation, role)

    def replace(self, rows: list[dict[str, Any]], search_rows: list[_SearchRow] | None = None) -> None:
        if search_rows is None:
            search_rows = [_SearchRow.read(row) for row in rows]
        self.beginResetModel()
        self.rows = rows
        self.search_rows = search_rows
        self.endResetModel()


@dataclass(frozen=True)
class RegistryFilter:
    field: str
    operation: str = "contains"
    value: str = ""
    since: str | None = None
    until: str | None = None

    @cached_property
    def normalized(self) -> str:
        return self.value.casefold()

    @cached_property
    def network(self) -> AddressNetwork | None:
        return _network(self.value, strict=False) if self.field == "addresses" else None

    @cached_property
    def bounds(self) -> tuple[datetime | None, datetime | None]:
        lower, upper = _timestamp(self.since), _timestamp(self.until)
        return lower, upper + timedelta(days=1) if upper is not None else None


class RegistryProxy(QSortFilterProxyModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._query = ""
        self._network: AddressNetwork | None = None
        self.site_id: str | None = None
        self.device_sites: Mapping[str, str] = {}
        self.conditions: list[RegistryFilter] = []

    def filterAcceptsRow(self, source_row: int, source_parent: Index) -> bool:
        model = self.sourceModel()
        if not isinstance(model, RegistryRows):
            return False
        if self.site_id is not None and not self._matches_site(model.rows[source_row]):
            return False
        row = model.search_rows[source_row]
        if self._network is not None:
            if not _overlaps(self._network, row.addresses):
                return False
        elif self._query not in row.haystack:
            return False
        for condition in self.conditions:
            text = row.normalized.get(condition.field, "")
            if condition.operation == "empty" and text:
                return False
            if condition.operation == "filled" and not text:
                return False
            if condition.operation == "contains":
                if condition.network is not None:
                    if not _overlaps(condition.network, row.addresses):
                        return False
                elif condition.normalized not in text:
                    return False
            if condition.operation == "equals":
                if condition.network is not None:
                    if condition.network not in row.addresses:
                        return False
                elif condition.normalized != text:
                    return False
            if condition.operation == "range":
                stamp = row.dates.get(condition.field)
                if stamp is None:
                    return False
                lower, upper = condition.bounds
                if lower and stamp < lower or upper and stamp >= upper:
                    return False
        return True

    def _matches_site(self, row: dict[str, Any]) -> bool:
        source = row.get("source") or {}
        if source.get("kind") == "cloud" or source.get("scan_id"):
            return True
        device = source.get("device_id")
        if isinstance(device, str) and device:
            return self.device_sites.get(device, "") == self.site_id
        binding = (row.get("metadata") or {}).get(MATRIX_BINDING_FIELD)
        return not isinstance(binding, Mapping) or binding.get("site_id") == self.site_id

    def lessThan(self, left: Index, right: Index) -> bool:
        model = self.sourceModel()
        if not isinstance(model, RegistryRows):
            return False
        key = COLUMNS[left.column()][0]
        a, b = model.search_rows[left.row()], model.search_rows[right.row()]
        if key in DATE_FIELDS:
            first, second = a.dates[key], b.dates[key]
            if first is None or second is None:
                return first is None and second is not None
            return first < second
        return a.normalized[key] < b.normalized[key]

    def apply(self, query: str | None = None) -> None:
        modern = hasattr(self, "beginFilterChange") and hasattr(self, "endFilterChange")
        if modern:
            self.beginFilterChange()
        if query is not None:
            self._query = query.casefold()
            self._network = _network(query, strict=False) if query.strip() else None
        if modern:
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            self.invalidateFilter()


class ResourceEditor(QDialog):
    def __init__(
        self, row: dict[str, Any] | None = None, parent: QWidget | None = None, *,
        access_sites: Sequence[Mapping[str, str]] = (),
    ) -> None:
        super().__init__(parent)
        self.row = row or {}
        self.manual = not row or row.get("origin") == "manual"
        self.fields: dict[str, QLineEdit | QPlainTextEdit | QComboBox] = {}
        self._initial: dict[str, str] = {}
        self._resets: set[str] = set()
        self.setWindowTitle("Изменить ресурс" if row else "Добавить ресурс вручную")
        self.resize(650, 640)
        layout = QVBoxLayout(self)
        hint = QLabel("↶ — сбросить ручное значение поля.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        tabs = QTabWidget()
        layout.addWidget(tabs, 1)
        general = self._page(tabs, "Ресурс")
        for key, label in (
            ("name", "Имя *"),
            ("platform", "Платформа"),
            ("resource_type", "Тип"),
            ("category", "Категория *"),
            ("label", "Подпись"),
            ("status", "Статус пользователя"),
            ("vdc", "VDC"),
            ("description", "Описание"),
            ("comments", "Комментарии"),
        ):
            self._field(
                general,
                key,
                label,
                readonly=not self.manual
                and key in {"name", "platform", "resource_type", "category"},
            )
        placement = self._page(tabs, "Размещение")
        for key, label in LOCATION_FIELDS:
            self._field(placement, key, label)
        access = self._page(tabs, "Адреса для матрицы")
        access_hint = QLabel(
            "Подтвердите IP-адреса или сети CIDR ресурса в стандартном сетевом контексте "
            "одной площадки. Используйте отдельную строку для каждого значения."
        )
        access_hint.setWordWrap(True)
        access.addRow(access_hint)
        raw_binding = self.row.get(MATRIX_BINDING_FIELD)
        try:
            self._initial_binding = (
                resource_address_binding(raw_binding) if raw_binding is not None else None
            )
        except ValueError:
            self._initial_binding = None
            access_hint.setText(access_hint.text() + " Сохранённые адреса не удалось прочитать.")
        self.access_site = QComboBox()
        self.access_site.addItem("Выберите площадку", None)
        self.access_site.addItem("Без площадки", "")
        self.access_site.setAccessibleName("Площадка для сверки")
        for site in access_sites:
            self.access_site.addItem(site["name"], site["id"])
        if self._initial_binding is not None:
            saved_site = self._initial_binding["site_id"]
            site_index = self.access_site.findData(saved_site)
            if site_index < 0:
                self.access_site.addItem(f"Сохранённая площадка: {saved_site}", saved_site)
                site_index = self.access_site.count() - 1
            self.access_site.setCurrentIndex(site_index)
        self.access_prefixes = QPlainTextEdit(
            "\n".join(self._initial_binding["prefixes"]) if self._initial_binding is not None else ""
        )
        self.access_prefixes.setPlaceholderText("10.10.20.10\n10.10.30.0/24")
        self.access_prefixes.setAccessibleName("Подтверждённые адреса ресурса")
        access.addRow("Площадка для сверки", self.access_site)
        access.addRow("IP-адреса и CIDR", self.access_prefixes)
        source_bindings = self.row.get(MATRIX_SOURCE_BINDINGS_FIELD)
        if source_bindings:
            try:
                bindings = resource_source_address_bindings(source_bindings)
            except ValueError:
                bindings = ()
            if bindings:
                site_names = {site["id"]: site["name"] for site in access_sites}
                summary = QLabel("\n".join(
                    f"{binding['device_id']} · {binding['platform']}"
                    + (f" · {binding['device_context']}" if binding["device_context"] else "")
                    + (f" · VRF {binding['vrf']}" if binding.get("vrf") else "")
                    + f" · {site_names.get(binding['site_id'], binding['site_id'] or 'Без площадки')}"
                    + "\n" + ", ".join(binding["prefixes"])
                    for binding in bindings
                ))
                summary.setTextFormat(Qt.TextFormat.PlainText)
                summary.setWordWrap(True)
                summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                access.addRow("Для отдельных источников", summary)
        dates = self._page(tabs, "Наблюдения")
        for key in ("added_at", "first_seen", "last_scan", "last_check"):
            dates.addRow(dict(COLUMNS)[key], QLabel(_text(self.row, key) or "Неизвестно"))
        self.validation = QLabel()
        self.validation.setWordWrap(True)
        self.validation.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.validation)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accept(self) -> None:
        name = self.fields["name"]
        if self.manual and isinstance(name, QLineEdit) and not name.text().strip():
            self.validation.setText("Укажите имя ресурса.")
            return
        try:
            values = self.values()
        except ValueError as error:
            self.validation.setText(str(error))
            return
        if any(
            isinstance(value, str) and (len(value) > 16000 or "\x00" in value)
            for value in values.values()
        ):
            self.validation.setText(
                "Поля должны содержать не более 16000 символов без нулевых байтов."
            )
            return
        super().accept()

    @staticmethod
    def _page(tabs: QTabWidget, name: str) -> QFormLayout:
        page = QWidget()
        form = QFormLayout(page)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(page)
        tabs.addTab(scroll, name)
        return form

    def _field(self, form: QFormLayout, key: str, label: str, readonly: bool = False) -> None:
        initial = str(self.row.get(key) or "")
        widget: QLineEdit | QPlainTextEdit | QComboBox
        if key == "category":
            widget = QComboBox()
            for value, title in CATEGORIES.items():
                widget.addItem(title, value)
            widget.setCurrentIndex(max(0, widget.findData(initial)))
        elif key in {"description", "comments"}:
            widget = QPlainTextEdit(initial)
            widget.setMaximumHeight(100)
        else:
            widget = QLineEdit(initial)
        widget.setAccessibleName(label)
        widget.setEnabled(not readonly)
        self.fields[key] = widget
        self._initial[key] = initial
        container = QWidget()
        line = QHBoxLayout(container)
        line.setContentsMargins(0, 0, 0, 0)
        line.addWidget(widget, 1)
        if (
            not readonly
            and key not in {"name", "platform", "resource_type", "category"}
            and self.row
        ):
            reset = QPushButton("↶")
            reset.setFixedWidth(26)
            reset.setAccessibleName("Сбросить ручное значение")
            reset.setToolTip("Удалить ручное значение и использовать данные источника")
            reset.clicked.connect(lambda _checked=False, field=key: self._reset(field))
            line.addWidget(reset)
        form.addRow(label, container)
        if isinstance(widget, QLineEdit):
            widget.textChanged.connect(lambda _text, field=key: self._resets.discard(field))
        elif isinstance(widget, QPlainTextEdit):
            widget.textChanged.connect(lambda field=key: self._resets.discard(field))
        else:
            widget.currentIndexChanged.connect(
                lambda _index, field=key: self._resets.discard(field)
            )

    def _reset(self, key: str) -> None:
        observed = self.row.get("observed") or {}
        value = str(observed.get(key) or "")
        widget = self.fields[key]
        if isinstance(widget, QLineEdit):
            widget.setText(value)
        elif isinstance(widget, QPlainTextEdit):
            widget.setPlainText(value)
        self._resets.add(key)

    def values(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, widget in self.fields.items():
            if not widget.isEnabled():
                continue
            value = (
                widget.text()
                if isinstance(widget, QLineEdit)
                else widget.toPlainText()
                if isinstance(widget, QPlainTextEdit)
                else str(widget.currentData() or "")
            )
            if key in self._resets:
                result[key] = None
            elif not self.row or value != self._initial[key]:
                result[key] = value
        prefixes = [line for line in self.access_prefixes.toPlainText().splitlines() if line.strip()]
        site_id = self.access_site.currentData()
        if prefixes and site_id is None:
            raise ValueError("Выберите площадку для подтверждённых адресов ресурса.")
        binding = (
            resource_address_binding({"site_id": site_id, "prefixes": prefixes})
            if prefixes else None
        )
        if binding != self._initial_binding:
            result[MATRIX_BINDING_FIELD] = binding
        return result


type _RegistryKey = tuple[str, str | None, bool]


@dataclass(slots=True)
class _RegistryRead:
    key: _RegistryKey
    prepare: Callable[[], None] | None
    on_loaded: Callable[[], None] | None
    cancelled: Event = field(default_factory=Event)


@dataclass(slots=True)
class _RegistryContents:
    rows: list[dict[str, Any]]
    search_rows: list[_SearchRow]


class InfrastructureRegistryPanel(QWidget):
    changed = Signal()
    operation_requested = Signal(object)
    details_requested = Signal(object)
    map_requested = Signal(object)
    matrix_groups_requested = Signal(object)

    def __init__(
        self, registry: Registry, parent: QWidget | None = None, *, runner: JobRunner | None = None,
    ) -> None:
        super().__init__(parent)
        self.registry = registry
        self._runner = runner
        self._pending: _RegistryRead | None = None
        self._failed: _RegistryRead | None = None
        self._loaded_key: _RegistryKey | None = None
        self._read_error: str | None = None
        self.project_id: str | None = None
        self.access_sites: tuple[Mapping[str, str], ...] = ()
        self._recent_manual_ids: tuple[str, ...] = ()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)
        explanation = (
            "Накопленный состав проекта. Отсутствие в новом сборе не удаляет ресурс. "
            "Архивирование сохраняет историю; ручные подписи не заменяют данные источника."
        )
        top = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setClearButtonEnabled(True)
        self.search.setPlaceholderText("Имя, IP-адрес, сеть CIDR или текст карточки")
        self.search.setAccessibleName("Поиск в реестре инфраструктуры")
        self.search.setToolTip(
            "IP-адрес ищется среди известных адресов и сетей ресурса. "
            "Для CIDR показываются пересекающиеся сети. Текст ищется по всем полям."
        )
        top.addWidget(self.search, 1)
        self.show_archived = QCheckBox("Показывать архив")
        self.show_archived.toggled.connect(self.refresh)
        top.addWidget(self.show_archived)
        self.audit_button = QPushButton("История")
        self.audit_button.setToolTip("История изменений выбранной карточки")
        self.audit_button.clicked.connect(self._history)
        top.addWidget(self.audit_button)
        layout.addLayout(top)
        filter_row = QHBoxLayout()
        self.filter_field = QComboBox()
        self.filter_field.setAccessibleName("Поле дополнительного фильтра")
        for key, label in COLUMNS:
            self.filter_field.addItem(label, key)
        filter_row.addWidget(self.filter_field)
        self.filter_operation = QComboBox()
        for label, key in (
            ("содержит", "contains"),
            ("равно", "equals"),
            ("не заполнено", "empty"),
            ("заполнено", "filled"),
        ):
            self.filter_operation.addItem(label, key)
        filter_row.addWidget(self.filter_operation)
        self.filter_value = QLineEdit()
        self.filter_value.setAccessibleName("Значение дополнительного фильтра")
        filter_row.addWidget(self.filter_value, 1)
        self.date_bounds = QWidget()
        dates = QHBoxLayout(self.date_bounds)
        dates.setContentsMargins(0, 0, 0, 0)
        self.from_enabled, self.to_enabled = QCheckBox("с"), QCheckBox("по")
        self.date_from, self.date_to = (
            QDateEdit(QDate.currentDate()),
            QDateEdit(QDate.currentDate()),
        )
        for edit in (self.date_from, self.date_to):
            edit.setCalendarPopup(True)
            edit.setDisplayFormat("yyyy-MM-dd")
        self.date_from.setAccessibleName("Начальная дата фильтра UTC")
        self.date_to.setAccessibleName("Конечная дата фильтра UTC")
        for widget in (self.from_enabled, self.date_from, self.to_enabled, self.date_to):
            dates.addWidget(widget)
        filter_row.addWidget(self.date_bounds)
        self.add_filter_button = QPushButton("Добавить фильтр")
        self.add_filter_button.clicked.connect(self.add_filter)
        filter_row.addWidget(self.add_filter_button)
        layout.addLayout(filter_row)
        self.active_filters = QWidget()
        filter_actions = QHBoxLayout(self.active_filters)
        filter_actions.setContentsMargins(0, 0, 0, 0)
        self.filters = QListWidget()
        self.filters.setAccessibleName("Совместно применяемые фильтры")
        self.filters.setFixedHeight(40)
        filter_actions.addWidget(self.filters, 1)
        remove_filter = QPushButton("Убрать")
        remove_filter.setToolTip("Убрать выбранный дополнительный фильтр")
        remove_filter.clicked.connect(self.remove_filter)
        filter_actions.addWidget(remove_filter)
        clear = QPushButton("Сбросить")
        clear.setToolTip("Сбросить поиск и дополнительные фильтры")
        clear.clicked.connect(self.clear_filters)
        filter_actions.addWidget(clear)
        layout.addWidget(self.active_filters)
        self.active_filters.hide()
        self.model = RegistryRows(self)
        self.proxy = RegistryProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setAccessibleName("Накопленный реестр ресурсов проекта")
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.horizontalHeader().setStretchLastSection(False)
        layout.addWidget(self.table, 1)
        actions = QHBoxLayout()
        self.add_button = QPushButton("Добавить")
        self.add_button.setToolTip("Добавить устройство вручную до первого сканирования")
        self.add_button.clicked.connect(self._new)
        self.batch_button = QPushButton("Добавить из таблицы…")
        self.batch_button.clicked.connect(self._new_batch)
        self.matrix_groups_button = QPushButton("Группы матрицы…")
        self.matrix_groups_button.clicked.connect(lambda: self.matrix_groups_requested.emit(self._recent_manual_ids))
        self.edit_button = QPushButton("Изменить")
        self.edit_button.setToolTip("Изменить подпись, описание, комментарии и размещение")
        self.edit_button.clicked.connect(self._edit)
        self.archive_button = QPushButton("В архив")
        self.archive_button.setToolTip("Убрать из активного реестра, сохраняя историю")
        self.archive_button.clicked.connect(self.archive_selected)
        self.restore_button = QPushButton("Восстановить")
        self.restore_button.clicked.connect(self.restore_selected)
        self.link_button = QPushButton("Связать записи")
        self.link_button.setToolTip("Явно связать ручную карточку с обнаруженным ресурсом")
        self.link_button.clicked.connect(self._link_dialog)
        self.operation_button = QPushButton("Источник")
        self.operation_button.setToolTip("Открыть исходную операцию ресурса")
        self.operation_button.clicked.connect(self._open_operation)
        self.details_button = QPushButton("Структура и политики")
        self.details_button.setToolTip("Открыть объекты и связи последней сохранённой конфигурации")
        self.details_button.clicked.connect(self._open_details)
        self.map_button = QPushButton("На карте")
        self.map_button.setToolTip("Показать окружение выбранного ресурса")
        self.map_button.clicked.connect(self._open_map)
        for button in (
            self.add_button,
            self.batch_button,
            self.edit_button,
            self.archive_button,
            self.restore_button,
            self.link_button,
            self.operation_button,
            self.details_button,
            self.map_button,
        ):
            actions.addWidget(button)
        layout.addLayout(actions)
        self.status = QLabel("Выберите проект.")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setToolTip(
            explanation + " Неизвестные даты не подменяются текущими; даты отображаются в UTC."
        )
        status_row = QHBoxLayout()
        status_row.addWidget(self.status, 1)
        self._retry = QPushButton("Повторить загрузку")
        self._retry.clicked.connect(self._retry_read)
        self._retry.hide()
        status_row.addWidget(self._retry)
        status_row.addWidget(self.matrix_groups_button)
        layout.addLayout(status_row)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(150)
        self._search_timer.timeout.connect(self._apply_filters)
        self.search.textChanged.connect(lambda _text: self._search_timer.start())
        self.search.returnPressed.connect(self._apply_filters)
        self.filter_field.currentIndexChanged.connect(self._filter_field_changed)
        self.filter_operation.currentIndexChanged.connect(self._filter_field_changed)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        self.table.doubleClicked.connect(self._edit)
        self._filter_field_changed()
        self.add_button.setEnabled(False)
        self.link_button.setEnabled(False)
        self._selection_changed()

    def set_project(self, project_id: str | None, *, refresh: bool = True) -> None:
        if self.project_id != project_id:
            self._recent_manual_ids = ()
            self.clear_filters()
            self.show_archived.blockSignals(True)
            self.show_archived.setChecked(False)
            self.show_archived.blockSignals(False)
        self.project_id = project_id
        if refresh:
            self.refresh()
        else:
            self._reset_read()
            self._update_count()

    def set_access_sites(self, sites: Sequence[Mapping[str, str]]) -> None:
        self.access_sites = tuple(sites)

    def set_site_filter(self, site_id: str | None, assignments: Mapping[str, str]) -> None:
        changed_site = self.proxy.site_id != site_id
        changed_assignments = self.proxy.device_sites != assignments
        if changed_site:
            self._recent_manual_ids = ()
        self.proxy.site_id = site_id
        self.proxy.device_sites = dict(assignments)
        if changed_site and self._runner is not None:
            self._reset_read()
            self._update_count()
        elif changed_site or changed_assignments:
            self._apply_filters()

    def _reset_read(self) -> None:
        if self._pending is not None:
            self._pending.cancelled.set()
            self._pending = None
        self._loaded_key = None
        self._read_error = None
        self._failed = None
        self.model.replace([], [])
        self._selection_changed()

    def refresh(
        self, *_: Any, prepare: Callable[[], None] | None = None, force: bool = False,
        on_loaded: Callable[[], None] | None = None,
    ) -> None:
        """Read registry contents, optionally preparing the captured project snapshot first."""
        project_id = self.project_id
        if project_id is None:
            self._reset_read()
            self._update_count()
            return
        include_archived = self.show_archived.isChecked()
        key = project_id, self.proxy.site_id, include_archived
        pending = self._pending
        if (pending is not None and pending.key == key and not force
                and (prepare is None or pending.prepare is not None)):
            if on_loaded is not None:
                pending.on_loaded = on_loaded
            return
        previous = pending or self._failed
        if previous is not None and previous.key[:2] == key[:2] and prepare is None:
            prepare = previous.prepare
            on_loaded = on_loaded or previous.on_loaded
        if pending is not None:
            pending.cancelled.set()
        if self._loaded_key != key:
            self._reset_read()
        request = _RegistryRead(key, prepare, on_loaded)
        self._pending = request
        self._read_error = None
        self._failed = None
        registry = self.registry

        def read() -> _RegistryContents | None:
            if request.cancelled.is_set():
                return None
            if prepare is not None:
                prepare()
            if request.cancelled.is_set():
                return None
            rows = registry.list_resources(project_id, include_archived=include_archived)
            search_rows = []
            for row in rows:
                if request.cancelled.is_set():
                    return None
                search_rows.append(_SearchRow.read(row))
            return _RegistryContents(rows, search_rows)

        if self._runner is None:
            try:
                result = read()
            except (ValueError, OSError, sqlite3.Error) as error:
                result = JobError("registry", str(error))
            self._complete_read(request, result)
            return
        self._update_count()
        self._selection_changed()
        try:
            self._runner.submit(read, lambda result: self._complete_read(request, result))
        except RuntimeError:
            self._complete_read(request, JobError("registry", "Загрузка реестра недоступна."))

    def _complete_read(self, request: _RegistryRead, result: object) -> None:
        if self._pending is not request or request.cancelled.is_set():
            return
        if request.key != (self.project_id, self.proxy.site_id, self.show_archived.isChecked()):
            self._reset_read()
            self._update_count()
            return
        self._pending = None
        if isinstance(result, _RegistryContents):
            self._install_contents(request.key, result)
        else:
            self._reset_read()
            self._read_error = result.message if isinstance(result, JobError) else "Не удалось загрузить реестр."
            self._failed = request
        self._update_count()
        self._selection_changed()
        if isinstance(result, _RegistryContents) and request.on_loaded is not None:
            request.on_loaded()

    def _retry_read(self) -> None:
        request = self._failed
        if request is not None:
            self.refresh(prepare=request.prepare, on_loaded=request.on_loaded)

    def _install_contents(self, key: _RegistryKey, result: _RegistryContents) -> None:
        selected = self.selected()
        identity = selected.get("id") if selected else None
        top = self.proxy.mapToSource(self.proxy.index(self.table.rowAt(0), 0))
        top_identity = self.model.rows[top.row()]["id"] if top.isValid() else None
        vertical = self.table.verticalScrollBar().value()
        horizontal = self.table.horizontalScrollBar().value()
        self._loaded_key = key
        self._search_timer.stop()
        self.model.replace(result.rows, result.search_rows)
        self.proxy.apply(self.search.text())
        restored_top = EMPTY_INDEX
        if identity is not None or top_identity is not None:
            for index, row in enumerate(result.rows):
                if row["id"] not in (identity, top_identity):
                    continue
                mapped = self.proxy.mapFromSource(self.model.index(index, 0))
                if mapped.isValid() and row["id"] == identity:
                    self.table.selectRow(mapped.row())
                if row["id"] == top_identity:
                    restored_top = mapped
        self.table.doItemsLayout()
        if restored_top.isValid():
            self.table.scrollTo(restored_top, QAbstractItemView.ScrollHint.PositionAtTop)
        else:
            self.table.verticalScrollBar().setValue(vertical)
        self.table.horizontalScrollBar().setValue(horizontal)

    def selected(self) -> dict[str, Any] | None:
        indexes = self.table.selectionModel().selectedRows()
        if len(indexes) != 1:
            return None
        source = self.proxy.mapToSource(indexes[0])
        return (
            self.model.rows[source.row()]
            if source.isValid() and 0 <= source.row() < len(self.model.rows)
            else None
        )

    def _selection_changed(self, *_: Any) -> None:
        loading = self._pending is not None
        row = None if loading else self.selected()
        self.table.setEnabled(not loading)
        self.add_button.setEnabled(bool(self.project_id))
        self.batch_button.setEnabled(bool(self.project_id))
        self.matrix_groups_button.setEnabled(bool(self.project_id))
        self.link_button.setEnabled(bool(self.project_id) and not loading)
        self.edit_button.setEnabled(bool(row))
        self.archive_button.setEnabled(
            bool(row) and row.get("lifecycle") == "active" if row else False
        )
        self.restore_button.setEnabled(
            bool(row) and row.get("lifecycle") == "archived" if row else False
        )
        self.operation_button.setEnabled(bool(row and row.get("source")))
        self.details_button.setEnabled(bool(row and row.get("source")))
        self.map_button.setEnabled(bool(row))
        self.audit_button.setEnabled(bool(row))

    def _filter_field_changed(self, *_: Any) -> None:
        field = self.filter_field.currentData()
        is_date = field in DATE_FIELDS
        range_mode = is_date and self.filter_operation.currentData() in {"contains", "equals"}
        self.date_bounds.setVisible(range_mode)
        self.filter_value.setVisible(
            not is_date and self.filter_operation.currentData() in {"contains", "equals"}
        )
        self.filter_value.setPlaceholderText("IP-адрес или CIDR" if field == "addresses" else "")
        self.filter_value.setToolTip(
            "«Содержит» ищет пересечение адресов и сетей. «Равно» сравнивает адрес или CIDR целиком."
            if field == "addresses" else ""
        )

    def add_filter(self) -> None:
        field, operation = (
            str(self.filter_field.currentData()),
            str(self.filter_operation.currentData()),
        )
        value = self.filter_value.text().strip()
        since = until = None
        if field in DATE_FIELDS and operation in {"contains", "equals"}:
            operation = "range"
            since = (
                self.date_from.date().toString("yyyy-MM-dd")
                if self.from_enabled.isChecked()
                else None
            )
            until = (
                self.date_to.date().toString("yyyy-MM-dd") if self.to_enabled.isChecked() else None
            )
            if not since and not until:
                self.status.setText("Для фильтра даты включите границу «с» и/или «по» (UTC).")
                return
            if since and until and since > until:
                self.status.setText("Начальная дата должна быть не позже конечной.")
                return
        elif operation in {"contains", "equals"} and not value:
            self.status.setText("Введите значение дополнительного фильтра.")
            return
        condition = RegistryFilter(field, operation, value, since, until)
        self.proxy.conditions.append(condition)
        label = dict(COLUMNS)[field]
        description = (
            f"{since or '…'} — {until or '…'} (UTC)"
            if operation == "range"
            else f"{self.filter_operation.currentText()} {value}"
        )
        self.filters.addItem(f"{label}: {description}")
        self._apply_filters()

    def remove_filter(self) -> None:
        index = self.filters.currentRow()
        if index >= 0:
            self.filters.takeItem(index)
            self.proxy.conditions.pop(index)
            self._apply_filters()

    def clear_filters(self) -> None:
        self.search.clear()
        self.filters.clear()
        self.proxy.conditions.clear()
        self._apply_filters()

    def _apply_filters(self, *_: Any) -> None:
        self._search_timer.stop()
        self.active_filters.setVisible(bool(self.proxy.conditions))
        self.proxy.apply(self.search.text())
        self._update_count()
        self._selection_changed()

    def _update_count(self) -> None:
        self._retry.setVisible(self._failed is not None)
        if self._pending is not None:
            self.status.setText("Загружаем ресурсы проекта…")
            return
        if self._read_error is not None:
            self.status.setText(self._read_error)
            return
        if self.project_id is None:
            self.status.setText("Выберите проект.")
            return
        self.status.setText(
            f"Показано: {self.proxy.rowCount()} из {len(self.model.rows)} · даты UTC"
            + (" · выбранная площадка и записи без установленной области" if self.proxy.site_id is not None else "")
        )

    def _new(self) -> None:
        editor = ResourceEditor(parent=self, access_sites=self.access_sites)
        if editor.exec() == QDialog.DialogCode.Accepted:
            self.create_resource(editor.values())

    def _new_batch(self) -> None:
        project_id = self.project_id
        site_id = self.proxy.site_id
        if project_id is None:
            return
        registry = self.registry

        def create(rows: tuple[dict[str, Any], ...]) -> tuple[str, ...]:
            return registry.add_manual_batch(project_id, rows)

        dialog = ResourceBatchDialog(
            self.access_sites, self, initial_site_id=site_id, create=create, runner=self._runner,
        )
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        created = dialog.created_ids if accepted else ()
        dialog.deleteLater()
        if created and self.project_id == project_id and self.proxy.site_id == site_id:
            self._recent_manual_ids = created

            def loaded() -> None:
                self.status.setText(
                    f"Добавлено ручных ресурсов: {len(created)}. Их можно выбрать из каталога в группах матрицы."
                )

            self.refresh(force=True, on_loaded=loaded)
            self.changed.emit()
            self.matrix_groups_button.setFocus()

    def _edit(self, *_: Any) -> None:
        row = self.selected()
        if not row:
            return
        editor = ResourceEditor(row, self, access_sites=self.access_sites)
        if editor.exec() == QDialog.DialogCode.Accepted:
            self.edit_resource(row["id"], editor.values())

    def create_resource(self, fields: dict[str, Any]) -> str | None:
        if not self.project_id:
            return None
        try:
            identity = self.registry.add_manual(self.project_id, fields)
            self.refresh(force=True)
            self.changed.emit()
            return identity
        except (ValueError, OSError, sqlite3.Error) as error:
            self.status.setText(str(error))
            return None

    def edit_resource(self, resource_id: str, fields: dict[str, Any]) -> None:
        if not self.project_id or not fields:
            return
        try:
            self.registry.update(self.project_id, resource_id, fields)
            self.refresh(force=True)
            self.changed.emit()
        except (ValueError, OSError, sqlite3.Error) as error:
            self.status.setText(str(error))

    def archive_selected(self) -> None:
        self._lifecycle("archive")

    def restore_selected(self) -> None:
        self._lifecycle("restore")

    def _lifecycle(self, operation: str) -> None:
        row = self.selected()
        if not row or not self.project_id:
            return
        try:
            if operation == "archive":
                self.registry.archive(self.project_id, row["id"])
            else:
                self.registry.restore(self.project_id, row["id"])
            self.refresh(force=True)
            self.changed.emit()
        except (ValueError, OSError, sqlite3.Error) as error:
            self.status.setText(str(error))

    def link_resources(self, manual_id: str, discovered_id: str) -> None:
        if not self.project_id:
            return
        try:
            self.registry.link_manual(self.project_id, manual_id, discovered_id)
            self.refresh(force=True)
            self.changed.emit()
        except (ValueError, OSError, sqlite3.Error) as error:
            self.status.setText(str(error))

    def _link_dialog(self) -> None:
        if not self.project_id:
            return
        try:
            rows = self.registry.list_resources(self.project_id, include_archived=True)
        except (ValueError, OSError, sqlite3.Error) as error:
            self.status.setText(str(error))
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Подтвердить соответствие ресурсов")
        form = QFormLayout(dialog)
        note = QLabel(
            "Сохранится ручная карточка и её подписи. Обнаруженный ресурс будет связан с ней "
            "по выбранному ID. История проверок не удаляется."
        )
        note.setWordWrap(True)
        form.addRow(note)
        manual, discovered = QComboBox(), QComboBox()
        for row in rows:
            combo = manual if row.get("origin") == "manual" else discovered
            combo.addItem(
                f"{row.get('label') or row.get('name') or 'Без имени'} · "
                f"{row.get('platform') or '—'} · {row['id']}",
                row["id"],
            )
        form.addRow("Ручная карточка", manual)
        form.addRow("Обнаруженная запись", discovered)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(
            manual.count() > 0 and discovered.count() > 0
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.link_resources(str(manual.currentData()), str(discovered.currentData()))

    def _open_operation(self) -> None:
        row = self.selected()
        if row:
            self.operation_requested.emit(row)

    def _open_details(self) -> None:
        row = self.selected()
        if row:
            self.details_requested.emit(row)

    def _open_map(self) -> None:
        row = self.selected()
        if row:
            self.map_requested.emit(row)

    def _history(self) -> None:
        row = self.selected()
        if not row or not self.project_id:
            return
        try:
            events = self.registry.history(self.project_id, row["id"])
        except (ValueError, OSError, sqlite3.Error) as error:
            self.status.setText(str(error))
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("История изменений карточки")
        dialog.resize(720, 500)
        layout = QVBoxLayout(dialog)
        editor = QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setPlainText(json.dumps(events, ensure_ascii=False, indent=2))
        layout.addWidget(editor)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        dialog.exec()
