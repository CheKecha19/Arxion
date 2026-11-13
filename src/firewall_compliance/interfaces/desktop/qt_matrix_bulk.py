"""Выбор групп и предпросмотр пакетного копирования требований."""

from collections.abc import Mapping, Sequence

from PySide6.QtCore import (
    QAbstractListModel, QModelIndex, QPersistentModelIndex, QSignalBlocker, Qt, QTimer, Signal,
)
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QListView,
    QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from firewall_compliance.application.matrix_requirement_sets import CopyEntry
from firewall_compliance.domain.access_matrix import MatrixGroup
from firewall_compliance.interfaces.desktop.qt_matrix_boundary import ports_text
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable


type _Index = QModelIndex | QPersistentModelIndex
_EMPTY_INDEX = QModelIndex()


class _GroupSelectionModel(QAbstractListModel):
    changed = Signal()

    def __init__(self, choices: Sequence[tuple[str, str]], initial_ids: Sequence[str], parent: QWidget) -> None:
        super().__init__(parent)
        self._choices = tuple(sorted(dict(choices).items(), key=lambda choice: (choice[1].casefold(), choice[0])))
        self._search = tuple(f"{label} {identifier}".casefold() for identifier, label in self._choices)
        self._ids = {identifier for identifier, _ in self._choices}
        self._selected = dict.fromkeys(identifier for identifier in initial_ids if identifier in self._ids)
        self._matching = tuple(range(len(self._choices)))

    def rowCount(self, parent: _Index = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self._matching)

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if not index.isValid():
            return None
        identifier, label = self._choices[self._matching[index.row()]]
        if role == Qt.ItemDataRole.CheckStateRole:
            return Qt.CheckState.Checked if identifier in self._selected else Qt.CheckState.Unchecked
        return label if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole) else None

    def flags(self, index: _Index) -> Qt.ItemFlag:
        flags = super().flags(index)
        return flags | Qt.ItemFlag.ItemIsUserCheckable if index.isValid() else flags

    def setData(self, index: _Index, value: object, role: int = Qt.ItemDataRole.EditRole) -> bool:
        if not index.isValid() or role != Qt.ItemDataRole.CheckStateRole:
            return False
        identifier = self._choices[self._matching[index.row()]][0]
        checked = value in (Qt.CheckState.Checked, Qt.CheckState.Checked.value)
        if checked != (identifier in self._selected):
            if checked:
                self._selected[identifier] = None
            else:
                del self._selected[identifier]
            changed = self.index(index.row(), 0)
            self.dataChanged.emit(changed, changed, [Qt.ItemDataRole.CheckStateRole])
            self.changed.emit()
        return True

    def filter(self, query: str) -> None:
        terms = query.casefold().split()
        self.beginResetModel()
        self._matching = tuple(
            index for index, value in enumerate(self._search) if all(term in value for term in terms)
        )
        self.endResetModel()

    def selected_ids(self) -> tuple[str, ...]:
        return tuple(self._selected)

    def selected_count(self) -> int:
        return len(self._selected)

    def select_ids(self, identifiers: Sequence[str]) -> None:
        selected = dict.fromkeys(identifier for identifier in identifiers if identifier in self._ids)
        if tuple(selected) == tuple(self._selected):
            return
        self._selected = selected
        if self._matching:
            self.dataChanged.emit(
                self.index(0, 0), self.index(len(self._matching) - 1, 0), [Qt.ItemDataRole.CheckStateRole],
            )
        self.changed.emit()

    def select_matching(self, checked: bool) -> None:
        matching = tuple(self._choices[index][0] for index in self._matching)
        if checked:
            self.select_ids((*self._selected, *matching))
        else:
            excluded = set(matching)
            self.select_ids(tuple(identifier for identifier in self._selected if identifier not in excluded))


class MatrixGroupSelection(QWidget):
    """Выбор элементов по имени и ID с сохранением отметок при поиске."""

    selection_changed = Signal()

    def __init__(
        self, choices: Sequence[tuple[str, str]], parent: QWidget, *,
        initial_ids: Sequence[str] = (), accessible_name: str = "Группы",
    ) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Имя или ID")
        self.search.setAccessibleName(f"Поиск · {accessible_name}")
        self.search.setClearButtonEnabled(True)
        layout.addWidget(self.search)
        self._model = _GroupSelectionModel(choices, initial_ids, self)
        view = QListView()
        view.setAccessibleName(accessible_name)
        view.setUniformItemSizes(True)
        view.setModel(self._model)
        layout.addWidget(view, 1)
        actions = QHBoxLayout()
        self._mark = QPushButton("Отметить найденные")
        self._unmark = QPushButton("Снять отметки с найденных")
        self._mark.clicked.connect(lambda: self._mark_matching(True))
        self._unmark.clicked.connect(lambda: self._mark_matching(False))
        for button in (self._mark, self._unmark):
            button.setAutoDefault(False)
            actions.addWidget(button)
        actions.addStretch()
        self._matches = QLabel()
        actions.addWidget(self._matches)
        layout.addLayout(actions)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(120)
        self._timer.timeout.connect(self._apply_filter)
        self.search.textChanged.connect(lambda _: self._timer.start())
        self.search.returnPressed.connect(self._apply_filter)
        self._model.changed.connect(self.selection_changed.emit)
        self._update_actions()

    def selected_ids(self) -> tuple[str, ...]:
        return self._model.selected_ids()

    def selected_count(self) -> int:
        return self._model.selected_count()

    def select_ids(self, identifiers: Sequence[str]) -> None:
        self._model.select_ids(identifiers)

    def _apply_filter(self) -> None:
        self._timer.stop()
        self._model.filter(self.search.text())
        self._update_actions()

    def _update_actions(self) -> None:
        count = self._model.rowCount()
        self._matches.setText(f"Найдено {count}")
        self._mark.setEnabled(count > 0)
        self._unmark.setEnabled(count > 0)

    def _mark_matching(self, checked: bool) -> None:
        if self._timer.isActive():
            self._apply_filter()
        self._model.select_matching(checked)


class MatrixCopyTargetsDialog(QDialog):
    def __init__(
        self, groups: Sequence[MatrixGroup], count: int, parent: QWidget, *, linked: bool = False,
        initial_target_ids: Sequence[str] = (), initial_replace_source: bool = True, editing: bool = False,
    ) -> None:
        super().__init__(parent)
        title = "Назначить набор" if linked else "Копировать требования"
        self.setWindowTitle("Изменить группы назначения" if editing else title)
        self.resize(640, 515)
        self.target_ids: tuple[str, ...] = ()
        self._group_ids = {group.group_id for group in groups}
        self._count = count
        self._updating_selection = False
        self._paste_ids_visible = False
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.axis = QComboBox()
        self.axis.addItem("Источники", True)
        self.axis.addItem("Назначения", False)
        self.axis.setCurrentIndex(0 if initial_replace_source else 1)
        self.axis.setEnabled(not editing)
        form.addRow("Назначить на" if linked else "Заменить в копиях", self.axis)
        layout.addLayout(form)
        self._groups = MatrixGroupSelection(
            [(group.group_id, f"{group.name} · {group.group_id}") for group in groups], self,
            initial_ids=initial_target_ids, accessible_name="Группы для пакетной операции",
        )
        layout.addWidget(self._groups, 1)
        self.summary = QLabel()
        layout.addWidget(self.summary)
        paste = QPushButton("Ввести или вставить ID групп")
        paste.setCheckable(True)
        paste.setAutoDefault(False)
        layout.addWidget(paste, 0, Qt.AlignmentFlag.AlignLeft)
        self.ids = QPlainTextEdit()
        self.ids.setPlaceholderText("Один ID группы на строку")
        self.ids.setAccessibleName("ID групп для копирования")
        self.ids.setMaximumHeight(105)
        self.ids.setPlainText("\n".join(initial_target_ids))
        self.ids.hide()
        paste.toggled.connect(self._toggle_paste_ids)
        layout.addWidget(self.ids)
        self.message = QLabel()
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self._ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok.setText("Предварительный просмотр")
        self._ok.setAutoDefault(False)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setAutoDefault(False)
        buttons.accepted.connect(self._preview)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.ids.textChanged.connect(self._read_ids)
        self._groups.selection_changed.connect(self._write_ids)
        self._unknown = tuple(
            identifier for identifier in dict.fromkeys(initial_target_ids) if identifier not in self._group_ids
        )
        if self._unknown:
            paste.setChecked(True)
        self._update_summary()
        self._groups.search.setFocus()

    def _read_ids(self) -> None:
        ids = tuple(dict.fromkeys(line.strip() for line in self.ids.toPlainText().splitlines() if line.strip()))
        self._unknown = tuple(identifier for identifier in ids if identifier not in self._group_ids)
        self._updating_selection = True
        try:
            self._groups.select_ids(ids)
        finally:
            self._updating_selection = False
        self._update_summary()

    def _write_ids(self) -> None:
        if self._updating_selection:
            return
        if self._paste_ids_visible:
            self._sync_ids()
        self._update_summary()

    def _toggle_paste_ids(self, visible: bool) -> None:
        self._paste_ids_visible = visible
        if visible:
            self._sync_ids()
        self.ids.setVisible(visible)

    def _sync_ids(self) -> None:
        with QSignalBlocker(self.ids):
            self.ids.setPlainText("\n".join((*self._groups.selected_ids(), *self._unknown)))

    def _update_summary(self) -> None:
        count = self._groups.selected_count()
        self.summary.setText(f"Выбрано групп: {count} · строк в предпросмотре: {count * self._count}")
        self._ok.setEnabled(bool(count) and not self._unknown)
        if self._unknown:
            examples = ", ".join(self._unknown[:4])
            self.message.setText(f"Не найдены ID групп ({len(self._unknown)}): {examples}")
        else:
            self.message.clear()

    def _preview(self) -> None:
        ids = self._groups.selected_ids()
        if not ids or self._unknown:
            self.message.setText("Введите существующие ID групп, по одному на строку.")
            return
        self.target_ids = ids
        self.accept()


class MatrixCopyPreviewDialog(QDialog):
    def __init__(
        self, entries: tuple[CopyEntry, ...], parent: QWidget, *,
        title: str = "Предварительный просмотр копий", origin_header: str = "Исходная строка",
        group_names: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.additions = tuple(entry.row for entry in entries if entry.disposition == "Добавится")
        conflicts = sum(entry.disposition == "Противоречие" for entry in entries)
        duplicates = len(entries) - len(self.additions) - conflicts
        self.setWindowTitle(title)
        self.resize(940, 560)
        layout = QVBoxLayout(self)
        note = QLabel(
            f"Добавится: {len(self.additions)}. Совпадений: {duplicates}. Противоречий: {conflicts}. "
            "Совпадения и противоречия пропускаются. Предпросмотр сопоставляет ID групп и условия "
            "сервисов. Пересечения состава групп и закрытых областей проверяются отдельно."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        table = MatrixTable((
            "Результат", origin_header, "Источник", "Назначение", "Сервис", "Требование", "Политика", "Связанная строка",
        ))
        groups = group_names or {}
        actions = {
            "permit": "Доступ необходим", "allow_optional": "Доступ допустим",
            "deny": "Запретить", "unregulated": "Не регламентировано",
        }

        def values(index: int) -> tuple[str, ...]:
            entry = entries[index]
            row = entry.row
            return (
                entry.disposition, entry.original_id,
                groups.get(row.source_group, row.source_group), groups.get(row.destination_group, row.destination_group),
                f"{row.service.protocol.upper()} {ports_text(row.service)}".strip(),
                actions[row.requirement], row.policy_id or "Не задана", entry.related_id,
            )

        table.set_rows(range(len(entries)), values)
        layout.addWidget(table, 1)
        layout.addLayout(table.navigation())
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok.setText("Добавить в черновик")
        ok.setEnabled(bool(self.additions))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
