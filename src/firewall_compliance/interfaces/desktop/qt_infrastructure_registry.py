"""Editable accumulated infrastructure registry, separate from imported evidence."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from PySide6.QtCore import (
    QAbstractTableModel,
    QDate,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
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


class Registry(Protocol):
    def list_resources(
        self, project_id: str, *, include_archived: bool = False
    ) -> list[dict[str, Any]]: ...
    def add_manual(self, project_id: str, fields: dict[str, Any]) -> str: ...
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


class RegistryRows(QAbstractTableModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.rows: list[dict[str, Any]] = []

    def rowCount(self, parent: Index = EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: Index = EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or index.row() >= len(self.rows):
            return None
        row, key = self.rows[index.row()], COLUMNS[index.column()][0]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return _text(row, key) or ("Неизвестно" if key in DATE_FIELDS else "—")
        if role == Qt.ItemDataRole.UserRole:
            return row
        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section][1]
        return super().headerData(section, orientation, role)

    def replace(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


@dataclass(frozen=True)
class RegistryFilter:
    field: str
    operation: str = "contains"
    value: str = ""
    since: str | None = None
    until: str | None = None


class RegistryProxy(QSortFilterProxyModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.query = ""
        self.conditions: list[RegistryFilter] = []

    def filterAcceptsRow(self, source_row: int, source_parent: Index) -> bool:
        model = self.sourceModel()
        if not isinstance(model, RegistryRows):
            return False
        row = model.rows[source_row]
        haystack = " ".join(_text(row, key) for key, _ in COLUMNS).casefold()
        if self.query.casefold() not in haystack:
            return False
        for condition in self.conditions:
            text = _text(row, condition.field)
            if condition.operation == "empty" and text:
                return False
            if condition.operation == "filled" and not text:
                return False
            if (
                condition.operation == "contains"
                and condition.value.casefold() not in text.casefold()
            ):
                return False
            if condition.operation == "equals" and condition.value.casefold() != text.casefold():
                return False
            if condition.operation == "range":
                stamp = _timestamp(row.get(condition.field))
                if stamp is None:
                    return False
                lower, upper = _timestamp(condition.since), _timestamp(condition.until)
                if lower and stamp < lower or upper and stamp >= upper + timedelta(days=1):
                    return False
        return True

    def lessThan(self, left: Index, right: Index) -> bool:
        model = self.sourceModel()
        if not isinstance(model, RegistryRows):
            return False
        key = COLUMNS[left.column()][0]
        a, b = model.rows[left.row()], model.rows[right.row()]
        if key in DATE_FIELDS:
            first, second = _timestamp(a.get(key)), _timestamp(b.get(key))
            if first is None or second is None:
                return first is None and second is not None
            return first < second
        return _text(a, key).casefold() < _text(b, key).casefold()

    def apply(self, query: str | None = None) -> None:
        modern = hasattr(self, "beginFilterChange") and hasattr(self, "endFilterChange")
        if modern:
            self.beginFilterChange()
        if query is not None:
            self.query = query
        if modern:
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            self.invalidateFilter()


class ResourceEditor(QDialog):
    def __init__(self, row: dict[str, Any] | None = None, parent: QWidget | None = None) -> None:
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
        if any(
            isinstance(value, str) and (len(value) > 16000 or "\x00" in value)
            for value in self.values().values()
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
            reset.setMaximumWidth(34)
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
        return result


class InfrastructureRegistryPanel(QWidget):
    changed = Signal()
    operation_requested = Signal(object)

    def __init__(self, registry: Registry, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.registry = registry
        self.project_id: str | None = None
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
        self.search.setPlaceholderText("Поиск по всем полям, включая описание, размещение и даты")
        self.search.setAccessibleName("Поиск в реестре инфраструктуры")
        self.search.setToolTip(explanation)
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
        # Keep the data rows readable at the supported 1000x650 window size.
        # The global ten-pixel header padding otherwise consumes a filtered row.
        self.table.horizontalHeader().setStyleSheet(
            "QHeaderView::section { padding-top: 4px; padding-bottom: 4px; }"
        )
        layout.addWidget(self.table, 1)
        actions = QHBoxLayout()
        self.add_button = QPushButton("Добавить")
        self.add_button.setToolTip("Добавить устройство вручную до первого сканирования")
        self.add_button.clicked.connect(self._new)
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
        for button in (
            self.add_button,
            self.edit_button,
            self.archive_button,
            self.restore_button,
            self.link_button,
            self.operation_button,
        ):
            actions.addWidget(button)
        layout.addLayout(actions)
        self.status = QLabel("Выберите проект.")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setToolTip(
            explanation + " Неизвестные даты не подменяются текущими; даты отображаются в UTC."
        )
        layout.addWidget(self.status)
        self.search.textChanged.connect(self._apply_filters)
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
            self.clear_filters()
            self.show_archived.blockSignals(True)
            self.show_archived.setChecked(False)
            self.show_archived.blockSignals(False)
        self.project_id = project_id
        if refresh:
            self.refresh()
        else:
            self.model.replace([])
            self._selection_changed()

    def refresh(self, *_: Any) -> None:
        selected = self.selected()
        identity = selected.get("id") if selected else None
        try:
            rows = (
                self.registry.list_resources(
                    self.project_id, include_archived=self.show_archived.isChecked()
                )
                if self.project_id
                else []
            )
            self.model.replace(rows)
            self.proxy.apply()
            if identity:
                for index, row in enumerate(rows):
                    if row["id"] == identity:
                        mapped = self.proxy.mapFromSource(self.model.index(index, 0))
                        if mapped.isValid():
                            self.table.selectRow(mapped.row())
                        break
            self._update_count()
        except (ValueError, OSError, sqlite3.Error) as error:
            self.model.replace([])
            self.status.setText(str(error))
        self.add_button.setEnabled(bool(self.project_id))
        self.link_button.setEnabled(bool(self.project_id))
        self._selection_changed()

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
        row = self.selected()
        self.edit_button.setEnabled(bool(row))
        self.archive_button.setEnabled(
            bool(row) and row.get("lifecycle") == "active" if row else False
        )
        self.restore_button.setEnabled(
            bool(row) and row.get("lifecycle") == "archived" if row else False
        )
        self.operation_button.setEnabled(bool(row and row.get("source")))
        self.audit_button.setEnabled(bool(row))

    def _filter_field_changed(self, *_: Any) -> None:
        is_date = self.filter_field.currentData() in DATE_FIELDS
        range_mode = is_date and self.filter_operation.currentData() in {"contains", "equals"}
        self.date_bounds.setVisible(range_mode)
        self.filter_value.setVisible(
            not is_date and self.filter_operation.currentData() in {"contains", "equals"}
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
        self.active_filters.setVisible(bool(self.proxy.conditions))
        self.proxy.apply(self.search.text())
        self._update_count()
        self._selection_changed()

    def _update_count(self) -> None:
        self.status.setText(
            f"Показано: {self.proxy.rowCount()} из {len(self.model.rows)} · даты UTC"
        )

    def _new(self) -> None:
        editor = ResourceEditor(parent=self)
        if editor.exec() == QDialog.DialogCode.Accepted:
            self.create_resource(editor.values())

    def _edit(self, *_: Any) -> None:
        row = self.selected()
        if not row:
            return
        editor = ResourceEditor(row, self)
        if editor.exec() == QDialog.DialogCode.Accepted:
            self.edit_resource(row["id"], editor.values())

    def create_resource(self, fields: dict[str, Any]) -> str | None:
        if not self.project_id:
            return None
        try:
            identity = self.registry.add_manual(self.project_id, fields)
            self.refresh()
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
            self.refresh()
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
            self.refresh()
            self.changed.emit()
        except (ValueError, OSError, sqlite3.Error) as error:
            self.status.setText(str(error))

    def link_resources(self, manual_id: str, discovered_id: str) -> None:
        if not self.project_id:
            return
        try:
            self.registry.link_manual(self.project_id, manual_id, discovered_id)
            self.refresh()
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
