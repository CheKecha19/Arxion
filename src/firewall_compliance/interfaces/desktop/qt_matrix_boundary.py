"""Карточка закрытой области с явной областью действия."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from uuid import uuid4

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, QTimer, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QCompleter, QDialog, QDialogButtonBox, QFormLayout,
    QHeaderView, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QTableView, QVBoxLayout,
    QWidget,
)

from firewall_compliance.domain.access_matrix import (
    MatrixBoundary, MatrixGroup, MatrixRequirement, MatrixService, MatrixZonePair,
)
from firewall_compliance.interfaces.desktop.qt_matrix_zones import MatrixZoneDialog, ZoneChoices, zone_pair_caption

type _Index = QModelIndex | QPersistentModelIndex
_EMPTY_INDEX = QModelIndex()


def service_from_text(protocol: str, ports: str) -> MatrixService:
    ranges = []
    if ports and ports != "*":
        for value in ports.split(","):
            parts = value.strip().split("-")
            if len(parts) not in {1, 2}:
                raise ValueError("invalid port range")
            ranges.append({"start": int(parts[0]), "end": int(parts[-1])})
    return MatrixService.model_validate({
        "protocol": protocol, "ports": ranges, "any_ports": ports == "*",
    })


def ports_text(service: MatrixService) -> str:
    return "*" if service.any_ports else ",".join(
        str(port.start) if port.start == port.end else f"{port.start}-{port.end}"
        for port in service.ports
    )


def group_combo(groups: Sequence[MatrixGroup], identifier: str = "") -> QComboBox:
    combo = QComboBox()
    combo.setEditable(True)
    combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
    for group in groups:
        combo.addItem(f"{group.name} · {group.group_id}", group.group_id)
    index = combo.findData(identifier)
    combo.setCurrentIndex(index)
    if index < 0:
        combo.setEditText(identifier)
    if completion := combo.completer():
        completion.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completion.setFilterMode(Qt.MatchFlag.MatchContains)
    return combo


def group_identifier(combo: QComboBox) -> str:
    index = combo.currentIndex()
    if index >= 0 and combo.currentText() == combo.itemText(index):
        return str(combo.itemData(index))
    return combo.currentText().strip()


@dataclass(frozen=True, slots=True)
class _AllowedRow:
    identifier: str
    cells: tuple[str, ...]
    group_ids: tuple[str, str]
    search: str


class _AllowedRows(QAbstractTableModel):
    _HEADERS = ("Включить", "ID", "Источник", "Назначение", "Сервис", "Требование")

    def __init__(self, parent: QWidget, change: Callable[[tuple[str, ...], bool], None]) -> None:
        super().__init__(parent)
        self.rows: list[_AllowedRow] = []
        self.allowed: set[str] = set()
        self._change = change

    def replace(self, rows: list[_AllowedRow]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def set_allowed(self, allowed: set[str]) -> None:
        self.allowed = allowed
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, 0), [
                Qt.ItemDataRole.CheckStateRole,
            ])

    def rowCount(self, parent: _Index = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: _Index = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self._HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if (
            role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal
            and 0 <= section < len(self._HEADERS)
        ):
            return self._HEADERS[section]
        return super().headerData(section, orientation, role)

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        if column == 0 and role == Qt.ItemDataRole.CheckStateRole:
            return Qt.CheckState.Checked if row.identifier in self.allowed else Qt.CheckState.Unchecked
        if column in (2, 3) and role == Qt.ItemDataRole.ToolTipRole:
            group_id = row.group_ids[column - 2]
            return f"{row.cells[column - 1]}\nID группы: {group_id}"
        if column > 0 and role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return row.cells[column - 1]
        return None

    def flags(self, index: _Index) -> Qt.ItemFlag:
        flags = super().flags(index)
        if index.isValid() and index.column() == 0:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        return flags

    def setData(self, index: _Index, value: object, role: int = Qt.ItemDataRole.EditRole) -> bool:
        if not index.isValid() or index.column() != 0 or role != Qt.ItemDataRole.CheckStateRole:
            return False
        self._change(
            (self.rows[index.row()].identifier,), value in (Qt.CheckState.Checked, Qt.CheckState.Checked.value),
        )
        return True


class MatrixBoundaryDialog(QDialog):
    def __init__(
        self, groups: Sequence[MatrixGroup], rows: Sequence[MatrixRequirement], scope_id: str,
        boundary: MatrixBoundary | None, parent: QWidget, *, policies: Sequence[str] = (),
        zone_choices: Callable[[str], ZoneChoices] | None = None,
        policy_picker: Callable[[QWidget, str, str], str | None] | None = None,
        seed: MatrixBoundary | None = None, seed_source: str | None = None,
        seed_destination: str | None = None, seed_service_explicit: bool = True,
    ) -> None:
        super().__init__(parent)
        if boundary is not None and seed is not None:
            raise ValueError("Нельзя одновременно редактировать ограничение и создать новое из требований.")
        initial = boundary or seed
        self.boundary: MatrixBoundary | None = None
        self._rows = rows
        self._group_names = {group.group_id: group.name for group in groups}
        self._group_ids_by_name: dict[str, str | None] = {}
        for group in groups:
            name = group.name.casefold()
            self._group_ids_by_name[name] = group.group_id if name not in self._group_ids_by_name else None
        self._available_rows: list[_AllowedRow] = []
        self._available_ids: set[str] = set()
        self._conditional_ids: set[str] = set()
        self._included_ids = dict.fromkeys(initial.allowed_requirement_ids if initial else ())
        self._zone_pair = initial.zone_pair if initial is not None else None
        self._zone_choices = zone_choices
        self._available_context: tuple[str, str | None, MatrixZonePair | None] | None = None
        self.setWindowTitle("Ограничение «Только перечисленный доступ»")
        self.resize(940, 690)
        layout = QVBoxLayout(self)
        note = QLabel(
            "Ограничение действует для указанной пары групп, сервиса, области и политики. "
            "Выберите разрешённые требования в таблице или вставьте их ID. "
            "Остальные взаимодействия должны быть запрещены. "
            "Пустой список означает запрет всей выбранной области."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        if seed is not None:
            scope_note = QLabel(
                "Укажите область, в которой действуют исключения. "
                "Если исключения покрывают её целиком, остатка для проверки запрета нет."
            )
            scope_note.setWordWrap(True)
            layout.addWidget(scope_note)
        form = QFormLayout()
        self.identifier = QLineEdit(initial.boundary_id if initial else "limit-" + uuid4().hex[:12])
        self.identifier.setReadOnly(boundary is not None)
        source = initial.source_group if initial else ""
        destination = initial.destination_group if initial else ""
        if seed is not None:
            source = source if seed_source is None else seed_source
            destination = destination if seed_destination is None else seed_destination
        self.source = group_combo(groups, source)
        self.destination = group_combo(groups, destination)
        self.scope = QLineEdit(initial.scope_id if initial else scope_id)
        self.policy = QLineEdit((initial.policy_id or "") if initial else "")
        if policies:
            self.policy.setPlaceholderText("Введите часть ID политики")
            completion = QCompleter(list(policies), self.policy)
            completion.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
            completion.setFilterMode(Qt.MatchFlag.MatchContains)
            self.policy.setCompleter(completion)
        self.protocol = QComboBox()
        self.protocol.addItems(("ip", "tcp", "udp", "icmp"))
        if seed is not None and not seed_service_explicit:
            self.protocol.setPlaceholderText("Выберите протокол ограничения")
            self.protocol.setCurrentIndex(-1)
        elif initial:
            self.protocol.setCurrentText(initial.service.protocol)
        self.ports = QLineEdit(ports_text(initial.service) if initial and self.protocol.currentIndex() >= 0 else "")
        self.allowed = QPlainTextEdit()
        self.allowed.setMaximumHeight(95)
        self.allowed.setPlaceholderText("Один ID на строку")
        self.allowed.setAccessibleName("ID разрешённых требований")
        self.allowed.hide()
        for label, widget in (
            ("ID", self.identifier), ("Источник", self.source), ("Назначение", self.destination),
            ("Область", self.scope), ("ID политики", self.policy), ("Протокол", self.protocol),
            ("Порты, диапазоны или *", self.ports),
        ):
            widget.setAccessibleName(label)
            form.addRow(label, widget)
        if policy_picker is not None:
            browse = QPushButton("Выбрать политику из снимков…")

            def choose_policy() -> None:
                chosen = policy_picker(self, self.scope.text().strip(), self.policy.text().strip())
                if chosen is not None:
                    self.policy.setText(chosen)
                    self._show_available()

            browse.clicked.connect(choose_policy)
            form.addRow(browse)
        zone_button = QPushButton("Зоны политики…")
        zone_button.clicked.connect(self._edit_zones)
        self.zones = QLabel(zone_pair_caption(self._zone_pair))
        self.zones.setTextFormat(Qt.TextFormat.PlainText)
        self.zones.setWordWrap(True)
        form.addRow(zone_button, self.zones)
        zone_button.setVisible(zone_choices is not None or self._zone_pair is not None)
        layout.addLayout(form)
        group_filters = QHBoxLayout()
        self.exception_source = self._exception_group_filter(groups, "Любой источник", "Фильтр источников исключений")
        self.exception_destination = self._exception_group_filter(
            groups, "Любое назначение", "Фильтр назначений исключений",
        )
        group_filters.addWidget(QLabel("Фильтры исключений"))
        group_filters.addWidget(self.exception_source, 1)
        group_filters.addWidget(self.exception_destination, 1)
        layout.addLayout(group_filters)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск по ID, группе или сервису")
        self.search.setAccessibleName("Поиск разрешённых требований")
        self.search.setClearButtonEnabled(True)
        self.selected_only = QCheckBox("Только включённые")
        self.paste_ids = QPushButton("Ввести или вставить ID")
        self.paste_ids.setCheckable(True)
        self.paste_ids.toggled.connect(self._show_allowed_ids)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.selected_only)
        filters.addWidget(self.paste_ids)
        layout.addLayout(filters)
        layout.addWidget(self.allowed)
        self.available = QTableView()
        self.available_model = _AllowedRows(self.available, self._toggle_exception)
        self.available.setModel(self.available_model)
        self.available.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.available.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.available.setAccessibleName("Разрешения в выбранной области, политике и паре зон")
        self.available.verticalHeader().hide()
        self.available.verticalHeader().setDefaultSectionSize(26)
        self.available.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        header = self.available.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((72, 135, 190, 190, 120)):
            self.available.setColumnWidth(column, width)
        layout.addWidget(self.available, 1)
        actions = QHBoxLayout()
        self.available_status = QLabel()
        self.available_status.setWordWrap(True)
        actions.addWidget(self.available_status, 1)
        self.include_visible = QPushButton("Включить все показанные")
        self.include_visible.setToolTip("Включить исключения из текущей выборки.")
        self.include_visible.clicked.connect(self._include_visible)
        self.include_selected = QPushButton("Включить выделенные")
        self.remove_selected = QPushButton("Убрать выделенные")
        for button in (self.include_visible, self.include_selected, self.remove_selected):
            button.setAutoDefault(False)
        self.include_selected.clicked.connect(lambda: self._apply_selected(True))
        self.remove_selected.clicked.connect(lambda: self._apply_selected(False))
        actions.addWidget(self.include_visible)
        actions.addWidget(self.include_selected)
        actions.addWidget(self.remove_selected)
        layout.addLayout(actions)
        self.conditional_note = QLabel(
            "Среди включённых есть требования с пользовательским условием или расписанием. "
            "Для таких исключений сверка не сможет вычислить запрещённый остаток."
        )
        self.conditional_note.setWordWrap(True)
        self.conditional_note.hide()
        layout.addWidget(self.conditional_note)
        self.error = QLabel()
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.scope.editingFinished.connect(self._show_available)
        self.policy.editingFinished.connect(self._show_available)
        self.allowed.textChanged.connect(self._sync_selection)
        self.available.selectionModel().selectionChanged.connect(self._update_selection_buttons)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(120)
        self._search_timer.timeout.connect(self._filter_available)
        self.search.textChanged.connect(lambda _: self._search_timer.start())
        self.search.returnPressed.connect(self._filter_available)
        self.exception_source.currentTextChanged.connect(lambda _: self._search_timer.start())
        self.exception_destination.currentTextChanged.connect(lambda _: self._search_timer.start())
        self.selected_only.toggled.connect(self._filter_available)
        self._show_available()

    @staticmethod
    def _exception_group_filter(groups: Sequence[MatrixGroup], title: str, accessible_name: str) -> QComboBox:
        combo = group_combo(groups)
        combo.insertItem(0, title, "")
        combo.setCurrentIndex(0)
        combo.setAccessibleName(accessible_name)
        if editor := combo.lineEdit():
            editor.setClearButtonEnabled(True)
            editor.setPlaceholderText(title)
        return combo

    def _group_id(self, combo: QComboBox) -> str:
        value = group_identifier(combo)
        if value and value not in self._group_names:
            index = combo.findText(value)
            if index >= 0:
                return str(combo.itemData(index))
            return self._group_ids_by_name.get(value.casefold()) or value
        return value

    def _context(self) -> tuple[str, str | None, MatrixZonePair | None]:
        return self.scope.text().strip(), self.policy.text().strip() or None, self._zone_pair

    def _matching_requirements(self) -> dict[str, MatrixRequirement]:
        scope, policy, zones = self._context()
        return {
            row.requirement_id: row for row in self._rows
            if row.scope_id == scope
            and row.policy_id in (None, policy)
            and row.zone_pair == zones
            and row.requirement in {"permit", "allow_optional"}
        }

    def _edit_zones(self) -> None:
        choices = self._zone_choices(self.policy.text().strip()) if self._zone_choices else ((), ())
        dialog = MatrixZoneDialog(self._zone_pair, choices, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._zone_pair = dialog.zone_pair
            self.zones.setText(zone_pair_caption(self._zone_pair))
            self._show_available()
        dialog.deleteLater()

    def _show_available(self) -> None:
        context = self._context()
        if context == self._available_context:
            self._filter_available()
            return
        self._available_context = context
        rows = self._matching_requirements()
        self._available_ids = set(rows)
        self._conditional_ids = {
            row.requirement_id for row in rows.values()
            if row.identity is not None or row.schedule is not None or row.access_context is not None
        }
        self._available_rows = []
        for row in rows.values():
            source = self._group_names.get(row.source_group, row.source_group)
            destination = self._group_names.get(row.destination_group, row.destination_group)
            protocol, ports = row.service.protocol.upper(), ports_text(row.service)
            service = f"{protocol}/{ports}" if ports else protocol
            requirement = "Обязательное" if row.requirement == "permit" else "Допустимое"
            if row.requirement_id in self._conditional_ids:
                requirement += " с условием"
            cells = (row.requirement_id, source, destination, service, requirement)
            group_ids = row.source_group, row.destination_group
            searchable = " ".join((*cells, *group_ids)).casefold()
            self._available_rows.append(_AllowedRow(row.requirement_id, cells, group_ids, searchable))
        self.available_model.allowed = set(self._included_ids)
        self._filter_available()

    def _show_allowed_ids(self, visible: bool) -> None:
        if visible:
            self._write_allowed_ids()
        self.allowed.setVisible(visible)
        if visible:
            self.allowed.setFocus()

    def _write_allowed_ids(self) -> None:
        self.allowed.blockSignals(True)
        self.allowed.setPlainText("\n".join(self._included_ids))
        self.allowed.blockSignals(False)

    def _sync_selection(self) -> None:
        self._included_ids = dict.fromkeys(
            value for line in self.allowed.toPlainText().splitlines() if (value := line.strip())
        )
        self._refresh_checked()

    def _refresh_checked(self) -> None:
        allowed = set(self._included_ids)
        if self.selected_only.isChecked():
            self.available_model.allowed = allowed
            self._filter_available()
        else:
            self.available_model.set_allowed(allowed)
            self._update_available_status()

    def _filter_available(self, *_: object) -> None:
        self._search_timer.stop()
        tokens = self.search.text().casefold().split()
        allowed = self.available_model.allowed
        selected_only = self.selected_only.isChecked()
        source = self._group_id(self.exception_source)
        destination = self._group_id(self.exception_destination)
        rows = self._available_rows
        if tokens or selected_only or source or destination:
            rows = [
                row for row in rows
                if (not selected_only or row.identifier in allowed)
                and (not source or row.group_ids[0] == source)
                and (not destination or row.group_ids[1] == destination)
                and all(token in row.search for token in tokens)
            ]
        if rows != self.available_model.rows:
            self.available_model.replace(rows)
        self._update_available_status()
        self._update_selection_buttons()

    def _update_available_status(self) -> None:
        allowed = self.available_model.allowed
        missing = len(allowed - self._available_ids)
        summary = f"Показано {len(self.available_model.rows)} из {len(self._available_rows)} · включено {len(allowed)}"
        if missing:
            summary += f" · вне выбранной области, политики или зон {missing}"
        self.available_status.setText(summary)
        self.conditional_note.setVisible(not allowed.isdisjoint(self._conditional_ids))
        self.include_visible.setEnabled(
            any(row.identifier not in allowed for row in self.available_model.rows)
        )

    def _selected_ids(self) -> tuple[str, ...]:
        return tuple(
            self.available_model.rows[index.row()].identifier
            for index in sorted(self.available.selectionModel().selectedRows(), key=lambda item: item.row())
        )

    def _update_selection_buttons(self, *_: object) -> None:
        selected = self.available.selectionModel().hasSelection()
        self.include_selected.setEnabled(selected)
        self.remove_selected.setEnabled(selected)

    def _include_visible(self) -> None:
        self._show_available()
        self._set_requirements(tuple(row.identifier for row in self.available_model.rows), True)

    def _apply_selected(self, include: bool) -> None:
        selected = set(self._selected_ids())
        self._show_available()
        self._set_requirements(
            tuple(row.identifier for row in self.available_model.rows if row.identifier in selected), include,
        )

    def _toggle_exception(self, identifiers: tuple[str, ...], include: bool) -> None:
        if self._search_timer.isActive() or self._context() != self._available_context:
            self._show_available()
            visible = {row.identifier for row in self.available_model.rows}
            identifiers = tuple(identifier for identifier in identifiers if identifier in visible)
        self._set_requirements(identifiers, include)

    def _set_requirements(self, identifiers: tuple[str, ...], include: bool) -> None:
        if not identifiers:
            return
        if include:
            self._included_ids.update(dict.fromkeys(identifiers))
        else:
            for identifier in identifiers:
                self._included_ids.pop(identifier, None)
        if self.paste_ids.isChecked():
            self._write_allowed_ids()
        self._refresh_checked()
        self._update_selection_buttons()

    def _save(self) -> None:
        ids = tuple(self._included_ids)
        missing = set(ids) - self._matching_requirements().keys()
        source, destination = self._group_id(self.source), self._group_id(self.destination)
        if source not in self._group_names or destination not in self._group_names:
            self.error.setText("Выберите существующие группы источника и назначения.")
            return
        if self.protocol.currentIndex() < 0:
            self.error.setText("Выберите протокол ограничения.")
            self.protocol.setFocus()
            return
        if missing:
            examples = ", ".join(sorted(missing)[:3])
            if len(missing) > 3:
                examples += f" и ещё {len(missing) - 3}"
            self.error.setText(
                f"Проверьте ID разрешений выбранной области, политики и пары зон. Не подходят {examples}."
            )
            return
        try:
            self.boundary = MatrixBoundary(
                boundary_id=self.identifier.text().strip(), source_group=source, destination_group=destination,
                service=service_from_text(self.protocol.currentText(), self.ports.text().strip()),
                scope_id=self.scope.text().strip(), policy_id=self.policy.text().strip() or None,
                zone_pair=self._zone_pair,
                allowed_requirement_ids=ids,
            )
        except ValueError:
            self.error.setText("Проверьте ID, область, политику и сервис ограничения.")
            return
        self.accept()
