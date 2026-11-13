"""Просмотр и выбор наблюдений для создания логических сетей."""

from collections.abc import Iterable, Sequence
from typing import Literal

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHeaderView, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTableView, QVBoxLayout, QWidget,
)

from firewall_compliance.interfaces.desktop.logical_network_vlan_draft import LogicalNetworkVlanDraft
from firewall_compliance.interfaces.desktop.qt_models import RowsModel

type _Index = QModelIndex | QPersistentModelIndex
type _Visibility = Literal["all", "eligible", "excluded"]


class _VlanRows(RowsModel):
    marked_changed = Signal()

    def __init__(self, drafts: Sequence[LogicalNetworkVlanDraft]) -> None:
        super().__init__(("Создать", "VLAN", "Логическая сеть", "Устройство", "Площадка", "VRF", "Подсети", "Результат"))
        self.drafts = tuple(drafts)
        self.eligible = frozenset(index for index, draft in enumerate(self.drafts) if draft.reason is None)
        self.marked: set[int] = set()
        self.replace([
            (
                "", draft.vlan_id if draft.vlan_id is not None else "—", draft.name or "—",
                draft.device or "—", draft.site or "Не назначена", draft.vrf or "—",
                ", ".join(draft.subnets) or "—", draft.reason or "Можно создать",
            )
            for draft in self.drafts
        ])

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if index.isValid() and index.column() == 0:
            if role == Qt.ItemDataRole.CheckStateRole and index.row() in self.eligible:
                return Qt.CheckState.Checked if index.row() in self.marked else Qt.CheckState.Unchecked
            if role == Qt.ItemDataRole.AccessibleTextRole and index.row() in self.eligible:
                row = self.rows[index.row()]
                return f"Создать {row[2]} · VLAN {row[1]} · {row[3]}"
        return super().data(index, role)

    def flags(self, index: _Index) -> Qt.ItemFlag:
        flags = super().flags(index)
        if index.isValid() and index.column() == 0 and index.row() in self.eligible:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        return flags

    def setData(self, index: _Index, value: object, role: int = Qt.ItemDataRole.EditRole) -> bool:
        if not index.isValid() or index.column() != 0 or role != Qt.ItemDataRole.CheckStateRole:
            return False
        if index.row() not in self.eligible:
            return False
        self.mark((index.row(),), value in (Qt.CheckState.Checked, Qt.CheckState.Checked.value))
        return True

    def mark(self, positions: Iterable[int], checked: bool) -> None:
        eligible = self.eligible.intersection(positions)
        changed = eligible.difference(self.marked) if checked else eligible.intersection(self.marked)
        if not changed:
            return
        if checked:
            self.marked.update(changed)
        else:
            self.marked.difference_update(changed)
        self.dataChanged.emit(
            self.index(min(changed), 0), self.index(max(changed), 0), [Qt.ItemDataRole.CheckStateRole],
        )
        self.marked_changed.emit()


class _VlanFilter(QSortFilterProxyModel):
    def __init__(self, rows: _VlanRows, parent: QWidget) -> None:
        super().__init__(parent)
        self._rows = rows
        self._search = tuple(
            " ".join((
                *(str(cell) for cell in cells[1:]), draft.site_id, draft.binding_key[0] if draft.binding_key else "",
            )).casefold()
            for draft, cells in zip(rows.drafts, rows.rows, strict=True)
        )
        self._terms: tuple[str, ...] = ()
        self._visibility: _Visibility = "all"
        self.setSourceModel(rows)

    def apply(self, query: str, visibility: _Visibility) -> None:
        self._terms = tuple(query.casefold().split())
        self._visibility = visibility
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, _: QModelIndex) -> bool:
        eligible = source_row in self._rows.eligible
        if (self._visibility == "eligible" and not eligible) or (self._visibility == "excluded" and eligible):
            return False
        return all(term in self._search[source_row] for term in self._terms)

    def visible_positions(self) -> Iterable[int]:
        return (self.mapToSource(self.index(row, 0)).row() for row in range(self.rowCount()))


class VlanBatchPreviewDialog(QDialog):
    """Предпросмотр состава пакета перед записью в реестр."""

    def __init__(self, rows: Sequence[LogicalNetworkVlanDraft], parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Создание логических сетей из VLAN")
        self.resize(1180, 580)
        self._rows = _VlanRows(rows)
        self._filter = _VlanFilter(self._rows, self)
        self._visible_eligible = self._rows.eligible
        layout = QVBoxLayout(self)

        note = QLabel(
            "Отметьте VLAN, для которых нужно создать логические сети. "
            "В предпросмотре видны подсети, площадка и причина исключения. "
            "Для спорного наблюдения откройте его карточку в реестре."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        filters = QHBoxLayout()
        self._search = QLineEdit()
        self._search.setPlaceholderText("VLAN, сеть, устройство, площадка, VRF или подсеть")
        self._search.setAccessibleName("Поиск по предпросмотру логических сетей")
        self._search.setClearButtonEnabled(True)
        filters.addWidget(self._search, 1)
        self._visibility = QComboBox()
        self._visibility.setAccessibleName("Фильтр по результату подготовки")
        self._visibility.addItem("Все наблюдения", "all")
        self._visibility.addItem("Можно создать", "eligible")
        self._visibility.addItem("Исключённые", "excluded")
        filters.addWidget(self._visibility)
        layout.addLayout(filters)

        table = QTableView()
        table.setAccessibleName("Предпросмотр логических сетей")
        table.setModel(self._filter)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.verticalHeader().hide()
        table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((78, 60, 160, 150, 130, 92, 190)):
            table.setColumnWidth(column, width)
        layout.addWidget(table, 1)

        actions = QHBoxLayout()
        self._mark = QPushButton("Отметить подходящие из показанных")
        self._unmark = QPushButton("Снять отметки с показанных")
        for button in (self._mark, self._unmark):
            button.setAutoDefault(False)
            actions.addWidget(button)
        self._mark.setToolTip("Отметить подходящие наблюдения в текущей выборке.")
        self._mark.clicked.connect(lambda: self._mark_visible(True))
        self._unmark.clicked.connect(lambda: self._mark_visible(False))
        actions.addStretch()
        self._status = QLabel()
        actions.addWidget(self._status)
        layout.addLayout(actions)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self._create = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._create.setText("Создать отмеченные")
        self._create.setAutoDefault(False)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setAutoDefault(False)
        buttons.accepted.connect(self._confirm)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._apply_filter)
        self._search.textChanged.connect(lambda _: self._timer.start())
        self._search.returnPressed.connect(self._apply_filter)
        self._visibility.currentIndexChanged.connect(self._apply_filter)
        self._rows.marked_changed.connect(self._update_controls)
        self._update_controls()
        self._search.setFocus()

    def _apply_filter(self) -> None:
        self._timer.stop()
        self._filter.apply(self._search.text(), self._visibility.currentData())
        self._visible_eligible = self._rows.eligible.intersection(self._filter.visible_positions())
        self._update_controls()

    def _mark_visible(self, checked: bool) -> None:
        if self._timer.isActive():
            self._apply_filter()
        self._rows.mark(self._visible_eligible, checked)

    def _update_controls(self) -> None:
        total = len(self._rows.drafts)
        eligible = len(self._rows.eligible)
        selected = len(self._rows.marked)
        self._status.setText(
            f"Показано {self._filter.rowCount()} из {total} · можно создать {eligible} · отмечено {selected}"
        )
        self._create.setEnabled(selected > 0)
        self._mark.setEnabled(not self._visible_eligible.issubset(self._rows.marked))
        self._unmark.setEnabled(not self._visible_eligible.isdisjoint(self._rows.marked))

    def _confirm(self) -> None:
        if self._rows.marked:
            self.accept()

    def selected_candidates(self) -> tuple[LogicalNetworkVlanDraft, ...]:
        return tuple(self._rows.drafts[index] for index in sorted(self._rows.marked))
