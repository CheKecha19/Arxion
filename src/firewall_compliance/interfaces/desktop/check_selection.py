"""Дерево выбора проверок с совместимыми флажками профиля проекта."""

from collections.abc import Mapping, Sequence

from PySide6.QtCore import QEvent, QSize, Qt
from PySide6.QtWidgets import QCheckBox, QHeaderView, QTreeWidget, QTreeWidgetItem


class _CheckBox(QCheckBox):
    """Синхронизировать доступность обеих команд одной проверки."""

    excluded: QCheckBox | None = None

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.Type.EnabledChange and self.excluded is not None:
            self.excluded.setEnabled(self.isEnabled())


class CheckSelection(QTreeWidget):
    def __init__(
        self,
        checks: Mapping[str, str],
        groups: Sequence[tuple[str, Sequence[str]]],
        optional: set[str],
    ) -> None:
        super().__init__()
        self.setColumnCount(2)
        self.setHeaderLabels(("Проверять", "Исключить"))
        self.setAccessibleName("Выбор проверок и исключений из запуска")
        self.setIndentation(20)
        self.setExpandsOnDoubleClick(False)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.setColumnWidth(1, 100)
        self.check_boxes: dict[str, QCheckBox] = {}
        for title, check_ids in groups:
            parent = QTreeWidgetItem(self)
            parent.setSizeHint(0, QSize(0, 34))
            group = QCheckBox(title)
            group.setTristate(True)
            self.setItemWidget(parent, 0, group)
            boxes: list[QCheckBox] = []
            for check_id in check_ids:
                row = QTreeWidgetItem(parent)
                row.setSizeHint(0, QSize(0, 30))
                checkbox = _CheckBox(checks[check_id])
                checkbox.setToolTip(check_id)
                checkbox.setChecked(check_id not in optional)
                excluded = QCheckBox()
                excluded.setAccessibleName(f"Исключить из запуска: {checks[check_id]}")
                excluded.setToolTip("Исключить проверку из следующих запусков")
                excluded.setChecked(not checkbox.isChecked())
                checkbox.excluded = excluded
                checkbox.toggled.connect(
                    lambda checked, target=excluded: target.setChecked(not checked)
                )
                excluded.toggled.connect(
                    lambda checked, target=checkbox: target.setChecked(not checked)
                )
                self.setItemWidget(row, 0, checkbox)
                self.setItemWidget(row, 1, excluded)
                self.check_boxes[check_id] = checkbox
                boxes.append(checkbox)
            group.clicked.connect(
                lambda checked, target=group, members=boxes: self._set_group(target, members, checked)
            )
            for checkbox in boxes:
                checkbox.toggled.connect(
                    lambda _checked, target=group, members=boxes: self._sync_group(target, members)
                )
            self._sync_group(group, boxes)
            parent.setExpanded(True)

    @staticmethod
    def _set_group(group: QCheckBox, boxes: Sequence[QCheckBox], checked: bool) -> None:
        for checkbox in boxes:
            if checkbox.isEnabled():
                checkbox.setChecked(checked)
        CheckSelection._sync_group(group, boxes)

    @staticmethod
    def _sync_group(group: QCheckBox, boxes: Sequence[QCheckBox]) -> None:
        count = sum(checkbox.isChecked() for checkbox in boxes)
        state = (
            Qt.CheckState.Checked
            if count == len(boxes)
            else Qt.CheckState.PartiallyChecked
            if count
            else Qt.CheckState.Unchecked
        )
        group.setCheckState(state)
