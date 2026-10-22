"""Модель таблиц с сортировкой и поиском без создания виджета на каждую строку."""

from collections.abc import Sequence
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt
from PySide6.QtGui import QColor

EMPTY_INDEX = QModelIndex()
PRIORITY_COLORS = {
    "Критическая": "#FF8FAD",
    "Высокая": "#FFA785",
    "Средняя": "#F1D27C",
    "Низкая": "#79B8FF",
    "Информационная": "#B7A0FF",
}


class RowsModel(QAbstractTableModel):
    """Строки отображения и отдельные полезные данные для панели подробностей."""

    def __init__(self, headers: Sequence[str]) -> None:
        super().__init__()
        self.headers = tuple(headers)
        self.rows: list[tuple[Any, ...]] = []
        self.payloads: list[Any] = []

    def replace(self, rows: Sequence[Sequence[Any]], payloads: Sequence[Any] = ()) -> None:
        self.beginResetModel()
        self.rows = [tuple(row) for row in rows]
        self.payloads = list(payloads)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if not index.isValid():
            return None
        value = self.rows[index.row()][index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and value in PRIORITY_COLORS:
            return QColor(PRIORITY_COLORS[value])
        if role == Qt.ItemDataRole.UserRole:
            if value in PRIORITY_COLORS:
                return list(PRIORITY_COLORS).index(value)
            return value
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return str(value)
        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        return self.headers[section] if orientation == Qt.Orientation.Horizontal else section + 1
