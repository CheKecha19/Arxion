"""Постраничное представление списков редактора матрицы."""

from collections.abc import Callable, Sequence

from PySide6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
)


class MatrixTable(QTableWidget):
    PAGE_SIZE = 100

    def __init__(self, headers: Sequence[str]) -> None:
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._indices: Sequence[int] = ()
        self._values: Callable[[int], Sequence[object]] = lambda _: ()
        self._offset = 0
        self.previous = QPushButton("←")
        self.previous.setAccessibleName("Предыдущая страница списка")
        self.previous.clicked.connect(lambda: self._move(-1))
        self.next = QPushButton("→")
        self.next.setAccessibleName("Следующая страница списка")
        self.next.clicked.connect(lambda: self._move(1))
        self.count = QLabel()
        self._refresh()

    def navigation(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        layout.addWidget(self.count, 1)
        layout.addWidget(self.previous)
        layout.addWidget(self.next)
        return layout

    def set_rows(
        self, indices: Sequence[int], values: Callable[[int], Sequence[object]], *, reset: bool = False,
    ) -> None:
        self._indices, self._values = indices, values
        last_offset = max(0, (len(indices) - 1) // self.PAGE_SIZE) * self.PAGE_SIZE
        self._offset = 0 if reset else min(self._offset, last_offset)
        self._refresh()

    def selected_index(self) -> int | None:
        selected = self.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        position = self._offset + selected[0].row()
        return self._indices[position] if 0 <= position < len(self._indices) else None

    def filtered_indices(self) -> Sequence[int]:
        return self._indices

    def show_index(self, index: int) -> bool:
        try:
            position = self._indices.index(index)
        except ValueError:
            return False
        self._offset = position // self.PAGE_SIZE * self.PAGE_SIZE
        self._refresh()
        self.selectRow(position - self._offset)
        return True

    def _move(self, step: int) -> None:
        target = self._offset + step * self.PAGE_SIZE
        if 0 <= target < len(self._indices):
            self._offset = target
            self._refresh()

    def _refresh(self) -> None:
        end = min(self._offset + self.PAGE_SIZE, len(self._indices))
        was_blocked = self.blockSignals(True)
        self.clearSelection()
        self.setRowCount(end - self._offset)
        for row, index in enumerate(self._indices[self._offset:end]):
            for column, value in enumerate(self._values(index)):
                self.setItem(row, column, QTableWidgetItem(str(value)))
        self.blockSignals(was_blocked)
        self.count.setText(
            f"{self._offset + 1}–{end} из {len(self._indices)}" if end else "Нет строк в выборке"
        )
        self.previous.setEnabled(self._offset > 0)
        self.next.setEnabled(end < len(self._indices))
        if not was_blocked:
            self.itemSelectionChanged.emit()
