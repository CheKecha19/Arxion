"""Редактор объявленных групп матрицы без изменения исходных сетевых объектов."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import uuid4

from PySide6.QtCore import Signal
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
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.domain.access_matrix import MatrixGroup

_KINDS = (
    ("Адрес или подсеть", "network"),
    ("Объект конфигурации по ID", "object"),
    ("Другая группа матрицы по ID", "group"),
)


class MatrixGroupDialog(QDialog):
    def __init__(self, group: MatrixGroup | None, parent: QWidget) -> None:
        super().__init__(parent)
        self.group: MatrixGroup | None = None
        self.setWindowTitle("Группа матрицы доступа")
        self.resize(720, 500)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.identifier = QLineEdit(group.group_id if group else "group-" + uuid4().hex[:8])
        self.identifier.setMaxLength(128)
        self.identifier.setReadOnly(group is not None)
        self.identifier.setAccessibleName("Стабильный ID группы матрицы")
        self.name = QLineEdit(group.name if group else "")
        self.name.setMaxLength(256)
        self.name.setAccessibleName("Название группы матрицы")
        form.addRow("ID группы", self.identifier)
        form.addRow("Название", self.name)
        layout.addLayout(form)
        note = QLabel(
            "Состав задаётся явно. Ссылка на объект относится к выбранной ревизии. "
            "Название группы не определяет её участников и не связывает её с AD."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.members = QTableWidget(0, 2)
        self.members.setHorizontalHeaderLabels(("Вид участника", "Адрес / CIDR / ID"))
        self.members.setColumnWidth(0, 250)
        self.members.horizontalHeader().setStretchLastSection(True)
        self.members.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.members.setAccessibleName("Явный состав группы матрицы")
        layout.addWidget(self.members, 1)
        actions = QHBoxLayout()
        add = QPushButton("Добавить участника")
        add.clicked.connect(lambda: self._add_member())
        remove = QPushButton("Убрать выбранных")
        remove.clicked.connect(self._remove_members)
        actions.addWidget(add)
        actions.addWidget(remove)
        actions.addStretch(1)
        layout.addLayout(actions)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        for member in group.members if group else ():
            self._add_member(member.kind, member.value)

    def _add_member(self, kind: str = "network", value: str = "") -> None:
        if self.members.rowCount() >= 4096:
            return
        row = self.members.rowCount()
        self.members.insertRow(row)
        selector = QComboBox()
        for title, identifier in _KINDS:
            selector.addItem(title, identifier)
        selector.setCurrentIndex(max(0, selector.findData(kind)))
        selector.setAccessibleName(f"Вид участника {row + 1}")
        self.members.setCellWidget(row, 0, selector)
        self.members.setItem(row, 1, QTableWidgetItem(value))
        self.members.setCurrentCell(row, 1)

    def _remove_members(self) -> None:
        rows = {index.row() for index in self.members.selectionModel().selectedRows()}
        for row in sorted(rows, reverse=True):
            self.members.removeRow(row)

    def _save(self) -> None:
        members = []
        for row in range(self.members.rowCount()):
            selector = self.members.cellWidget(row, 0)
            item = self.members.item(row, 1)
            if isinstance(selector, QComboBox) and item is not None:
                members.append({"kind": selector.currentData(), "value": item.text().strip()})
        try:
            group = MatrixGroup.model_validate({
                "group_id": self.identifier.text().strip(),
                "name": self.name.text().strip(),
                "members": members,
            })
        except ValueError:
            QMessageBox.warning(
                self, "Группа матрицы",
                "Укажите ID, название и значения участников. Адреса задаются как IP или CIDR.",
            )
            return
        self.group = group
        self.accept()


class MatrixGroupsWidget(QWidget):
    changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._groups: tuple[MatrixGroup, ...] = ()
        self._undo: list[tuple[MatrixGroup, ...]] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(("Название", "ID группы", "Участников задано"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAccessibleName("Группы матрицы доступа")
        self.table.doubleClicked.connect(lambda _index: self._edit())
        layout.addWidget(self.table)
        actions = QHBoxLayout()
        for title, callback in (
            ("Создать группу", self._new),
            ("Изменить", self._edit),
            ("Убрать из черновика", self._remove),
            ("Отменить изменение", self._restore),
        ):
            button = QPushButton(title)
            button.clicked.connect(callback)
            actions.addWidget(button)
        layout.addLayout(actions)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self._refresh()

    def groups(self) -> tuple[MatrixGroup, ...]:
        return self._groups

    def set_groups(self, groups: Sequence[MatrixGroup]) -> None:
        self._groups = tuple(groups)
        self._undo.clear()
        self._refresh()

    def _remember(self) -> None:
        self._undo.append(self._groups)
        del self._undo[:-10]

    def _refresh(self) -> None:
        self.table.setRowCount(len(self._groups))
        for row, group in enumerate(self._groups):
            for column, value in enumerate((group.name, group.group_id, len(group.members))):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))
        self.summary.setText(
            f"Групп в черновике: {len(self._groups)}. Изменения сохраняются новой версией матрицы."
            if self._groups else "Создайте группы адресов и подсетей для источников и назначений."
        )

    def _new(self) -> None:
        self._edit_group(None)

    def _edit(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self._groups):
            self._edit_group(row)

    def _edit_group(self, row: int | None) -> None:
        if row is None and len(self._groups) >= 256:
            return
        dialog = MatrixGroupDialog(self._groups[row] if row is not None else None, self)
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.group is None:
            return
        if any(
            group.group_id == dialog.group.group_id and index != row
            for index, group in enumerate(self._groups)
        ):
            QMessageBox.warning(self, "Группа матрицы", "Такой ID группы уже используется.")
            return
        self._remember()
        groups = list(self._groups)
        if row is None:
            groups.append(dialog.group)
        else:
            groups[row] = dialog.group
        self._groups = tuple(groups)
        self._refresh()
        self.changed.emit()

    def _remove(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self._groups):
            self._remember()
            self._groups = self._groups[:row] + self._groups[row + 1:]
            self._refresh()
            self.changed.emit()

    def _restore(self) -> None:
        if self._undo:
            self._groups = self._undo.pop()
            self._refresh()
            self.changed.emit()
