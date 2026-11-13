"""Просмотр объявленных разрешений перед добавлением в черновик матрицы."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHeaderView, QHBoxLayout, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QTableView, QVBoxLayout, QWidget,
)

from firewall_compliance.application.matrix_reports import matrix_service_label
from firewall_compliance.domain.access_matrix import MatrixGroup, MatrixRequirement
from firewall_compliance.interfaces.desktop.qt_matrix_zones import zone_pair_caption

type _Index = QModelIndex | QPersistentModelIndex
type _SelectionFilter = Literal["all", "selected", "unselected"]
_EMPTY_INDEX = QModelIndex()
_HEADERS = ("Добавить", "Откуда", "Куда", "Сервис", "Политика", "Зоны", "Основание")
_SKIPPED = (
    ("non_allow", "запреты и отключённые правила"),
    ("unresolved", "неподдержанные условия"),
    ("outside_zone", "другая пара зон"),
    ("duplicate", "повторные условия"),
)


def _search_text(value: str) -> str:
    return value.casefold().replace("/", " ")


@dataclass(frozen=True, slots=True)
class _PreviewRow:
    requirement: MatrixRequirement
    cells: tuple[str, ...]
    search: str
    addresses: tuple[str, str]


def prepare_declared_draft_preview(
    groups: Sequence[MatrixGroup], rows: Sequence[MatrixRequirement],
) -> tuple[_PreviewRow, ...]:
    """Подготовить строки и адресный поиск в фоновом задании."""
    names = {group.group_id: group.name for group in groups}
    prefixes = {
        group.group_id: ", ".join(member.value.casefold() for member in group.members if member.kind == "network")
        for group in groups
    }
    result = []
    for row in rows:
        cells = (
            names.get(row.source_group, row.source_group),
            names.get(row.destination_group, row.destination_group),
            matrix_service_label(row.service),
            row.policy_id or "—",
            zone_pair_caption(row.zone_pair),
            row.reason or "—",
        )
        search = _search_text(" ".join((
            *cells, row.source_group, row.destination_group, row.scope_id, row.requirement_id,
        )))
        addresses = prefixes.get(row.source_group, ""), prefixes.get(row.destination_group, "")
        result.append(_PreviewRow(row, cells, search, addresses))
    return tuple(result)


class _DraftRows(QAbstractTableModel):
    changed = Signal()

    def __init__(self, rows: Sequence[_PreviewRow], parent: QWidget) -> None:
        super().__init__(parent)
        self._rows = rows
        self._selected: set[int] = set()
        self._matching: Sequence[int] = range(len(rows))
        self._visible: Sequence[int] = self._matching
        self._query: tuple[str, ...] = ()
        self._selection_filter: _SelectionFilter = "all"

    def rowCount(self, parent: _Index = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self._visible)

    def columnCount(self, parent: _Index = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(_HEADERS)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if (
            role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal
            and 0 <= section < len(_HEADERS)
        ):
            return _HEADERS[section]
        return super().headerData(section, orientation, role)

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if not index.isValid():
            return None
        position, column = self._visible[index.row()], index.column()
        if column == 0 and role == Qt.ItemDataRole.CheckStateRole:
            return Qt.CheckState.Checked if position in self._selected else Qt.CheckState.Unchecked
        row = self._rows[position]
        if column == 0 and role == Qt.ItemDataRole.AccessibleTextRole:
            return f"Добавить {row.cells[0]} → {row.cells[1]} · {row.cells[2]}"
        if column in (1, 2) and role == Qt.ItemDataRole.ToolTipRole:
            identifier = row.requirement.source_group if column == 1 else row.requirement.destination_group
            addresses = row.addresses[column - 1]
            return f"{row.cells[column - 1]}\nID группы · {identifier}" + (f"\n{addresses}" if addresses else "")
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
        display_row = index.row()
        position = self._visible[display_row]
        checked = value in (Qt.CheckState.Checked, Qt.CheckState.Checked.value)
        if checked == (position in self._selected):
            return True
        if checked:
            self._selected.add(position)
        else:
            self._selected.remove(position)
        if self._selection_filter == "all":
            self._notify_checks(display_row, display_row)
        else:
            remaining = list(self._visible)
            remaining.pop(display_row)
            self.beginRemoveRows(_EMPTY_INDEX, display_row, display_row)
            self._visible = remaining
            self.endRemoveRows()
        self.changed.emit()
        return True

    def filter(self, query: str, selection_filter: _SelectionFilter) -> None:
        terms = tuple(_search_text(query).split())
        if terms != self._query:
            self._query = terms
            self._matching = (
                tuple(
                    index for index, row in enumerate(self._rows)
                    if all(term in row.search or any(term in value for value in row.addresses) for term in terms)
                )
                if terms else range(len(self._rows))
            )
        self._selection_filter = selection_filter
        self._update_visible()

    def _update_visible(self) -> None:
        visible = self._matching
        if self._selection_filter != "all":
            selected = self._selection_filter == "selected"
            visible = tuple(position for position in self._matching if (position in self._selected) == selected)
        if visible != self._visible:
            self.beginResetModel()
            self._visible = visible
            self.endResetModel()

    def _notify_checks(self, first: int, last: int) -> None:
        self.dataChanged.emit(
            self.index(first, 0), self.index(last, 0), [Qt.ItemDataRole.CheckStateRole],
        )

    def mark_visible(self, checked: bool) -> None:
        if not self._visible:
            return
        if checked:
            self._selected.update(self._visible)
        else:
            self._selected.difference_update(self._visible)
        if self._selection_filter == "all":
            self._notify_checks(0, len(self._visible) - 1)
        else:
            self._update_visible()
        self.changed.emit()

    def selected_count(self) -> int:
        return len(self._selected)

    def selected_rows(self) -> tuple[MatrixRequirement, ...]:
        return tuple(self._rows[index].requirement for index in sorted(self._selected))

    def row_at(self, index: _Index) -> _PreviewRow | None:
        return self._rows[self._visible[index.row()]] if index.isValid() else None


class MatrixDeclaredDraftPreview(QDialog):
    """Добавить только явно выбранные пользователем предложения."""

    def __init__(
        self, rows: Sequence[_PreviewRow],
        skipped: Mapping[str, int], parent: QWidget,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Черновик из правил")
        self.resize(1090, 680)
        self._total = len(rows)
        self._model = _DraftRows(rows, self)
        layout = QVBoxLayout(self)

        note = QLabel(
            "Выберите взаимодействия, которые допустимы по вашим требованиям. "
            "Строки попадут в черновик с условием «Доступ допустим». Перед утверждением проверьте условия."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        skipped_summary = " · ".join(f"{label} {skipped[key]}" for key, label in _SKIPPED if skipped.get(key))
        if skipped_summary:
            skipped_note = QLabel(f"Пропущено · {skipped_summary}")
            skipped_note.setWordWrap(True)
            layout.addWidget(skipped_note)

        filters = QHBoxLayout()
        self._search = QLineEdit()
        self._search.setPlaceholderText("Группа, IP, сервис, политика, зона или ID правила")
        self._search.setAccessibleName("Поиск предложений")
        self._search.setClearButtonEnabled(True)
        filters.addWidget(self._search, 1)
        self._selection_filter = QComboBox()
        self._selection_filter.setAccessibleName("Фильтр по отметкам")
        self._selection_filter.addItem("Все предложения", "all")
        self._selection_filter.addItem("Отмеченные", "selected")
        self._selection_filter.addItem("Без отметки", "unselected")
        filters.addWidget(self._selection_filter)
        layout.addLayout(filters)

        self._table = QTableView()
        self._table.setAccessibleName("Предложения для черновика матрицы")
        self._table.setModel(self._model)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().hide()
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        for column in (1, 2, 6):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(0, 82)
        self._table.setColumnWidth(3, 110)
        self._table.setColumnWidth(4, 150)
        self._table.setColumnWidth(5, 140)
        layout.addWidget(self._table, 1)

        actions = QHBoxLayout()
        self._mark = QPushButton("Отметить найденные")
        self._unmark = QPushButton("Снять отметки с найденных")
        for button in (self._mark, self._unmark):
            button.setAutoDefault(False)
            actions.addWidget(button)
        self._mark.clicked.connect(lambda: self._mark_visible(True))
        self._unmark.clicked.connect(lambda: self._mark_visible(False))
        actions.addStretch(1)
        self._count = QLabel()
        actions.addWidget(self._count)
        layout.addLayout(actions)

        self._details = QPlainTextEdit()
        self._details.setAccessibleName("Происхождение выбранного предложения")
        self._details.setReadOnly(True)
        self._details.setPlaceholderText("Выберите строку, чтобы увидеть её происхождение.")
        self._details.setMaximumHeight(90)
        layout.addWidget(self._details)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self._add = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._add.setText("Добавить отмеченные")
        self._add.setAutoDefault(False)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setAutoDefault(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._apply_filter)
        self._search.textChanged.connect(lambda _: self._timer.start())
        self._search.returnPressed.connect(self._apply_filter)
        self._selection_filter.currentIndexChanged.connect(self._apply_filter)
        self._model.changed.connect(self._update_controls)
        self._table.selectionModel().currentChanged.connect(self._show_details)
        self._model.modelReset.connect(self._details.clear)
        self._update_controls()
        self._search.setFocus()

    def selected_rows(self) -> tuple[MatrixRequirement, ...]:
        return self._model.selected_rows()

    def _apply_filter(self) -> None:
        self._timer.stop()
        self._model.filter(self._search.text(), self._selection_filter.currentData())
        self._update_controls()

    def _mark_visible(self, checked: bool) -> None:
        if self._timer.isActive():
            self._apply_filter()
        self._model.mark_visible(checked)

    def _update_controls(self) -> None:
        visible, selected = self._model.rowCount(), self._model.selected_count()
        selection_filter = self._selection_filter.currentData()
        self._count.setText(f"Показано {visible} из {self._total} · отмечено {selected}")
        self._add.setEnabled(selected > 0)
        self._mark.setEnabled(visible > 0 and selected < self._total and selection_filter != "selected")
        self._unmark.setEnabled(visible > 0 and selected > 0 and selection_filter != "unselected")

    def _show_details(self, index: _Index, _: _Index) -> None:
        preview = self._model.row_at(index)
        if preview is None:
            self._details.clear()
            return
        row = preview.requirement
        self._details.setPlainText(
            f"{preview.cells[0]} → {preview.cells[1]} · {preview.cells[2]}\n"
            f"Область · {row.scope_id} · политика {row.policy_id or '—'}\n"
            f"{row.reason or 'Источник правила не указан.'}"
        )
