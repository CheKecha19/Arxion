"""Редактор объявленных групп матрицы без изменения исходных сетевых объектов."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from uuid import NAMESPACE_URL, uuid4, uuid5

from PySide6.QtCore import QTimer, Signal
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

from firewall_compliance.domain.access_matrix import MatrixGroup, MatrixMember
from firewall_compliance.interfaces.desktop.qt_matrix_bulk import MatrixGroupSelection
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable

_KINDS = (
    ("Адрес или подсеть", "network"),
    ("Объект конфигурации по ID", "object"),
    ("Другая группа матрицы по ID", "group"),
    ("Логическая сеть проекта по ID", "logical_network"),
    ("Ресурс проекта по ID", "resource"),
)
_CATALOG_KIND = {"logical_network": "Логическая сеть", "resource": "Ресурс"}


def _choose_catalog_items(
    parent: QWidget, catalog: Mapping[tuple[str, str], str], *, create_groups: bool,
    initially_selected: Sequence[tuple[str, str]] = (),
) -> tuple[tuple[str, str], ...]:
    dialog = QDialog(parent)
    dialog.setWindowTitle("Создать группы из каталога" if create_groups else "Добавить участников из каталога")
    dialog.resize(740, 510)
    layout = QVBoxLayout(dialog)
    options = tuple(sorted(catalog, key=lambda key: (catalog[key].casefold(), key)))
    preferred = set(initially_selected)
    choices = [
        (str(index), f"{catalog[key]} · {_CATALOG_KIND.get(key[0], key[0])} · {key[1]}")
        for index, key in enumerate(options)
    ]
    selector = MatrixGroupSelection(
        choices, dialog, initial_ids=tuple(str(index) for index, key in enumerate(options) if key in preferred),
        accessible_name="Логические сети и ресурсы проекта",
    )
    layout.addWidget(selector, 1)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    accept = buttons.button(QDialogButtonBox.StandardButton.Ok)
    accept.setAutoDefault(False)
    buttons.button(QDialogButtonBox.StandardButton.Cancel).setAutoDefault(False)

    def update() -> None:
        count = selector.selected_count()
        accept.setText(f"Создать группы ({count})" if create_groups else f"Добавить участников ({count})")
        accept.setEnabled(count > 0)

    selector.selection_changed.connect(update)
    update()
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    accepted = dialog.exec() == QDialog.DialogCode.Accepted
    chosen = tuple(options[int(index)] for index in selector.selected_ids()) if accepted else ()
    dialog.deleteLater()
    return chosen


class MatrixGroupDialog(QDialog):
    def __init__(
        self, group: MatrixGroup | None, parent: QWidget, *,
        catalog: Mapping[tuple[str, str], str] | None = None,
    ) -> None:
        super().__init__(parent)
        self._catalog = dict(catalog or {})
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
        add.clicked.connect(self._add_empty_member)
        remove = QPushButton("Убрать выбранных")
        remove.clicked.connect(self._remove_members)
        actions.addWidget(add)
        catalog_button = QPushButton("Добавить из каталога проекта")
        catalog_button.setEnabled(bool(self._catalog))
        catalog_button.clicked.connect(self._add_catalog_member)
        actions.addWidget(catalog_button)
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
        row = self.members.rowCount()
        self.members.insertRow(row)
        selector = QComboBox()
        for title, identifier in _KINDS:
            selector.addItem(title, identifier)
        selector.setCurrentIndex(max(0, selector.findData(kind)))
        selector.setAccessibleName(f"Вид участника {row + 1}")
        self.members.setCellWidget(row, 0, selector)
        self.members.setItem(row, 1, QTableWidgetItem(value))

    def _add_empty_member(self) -> None:
        self._add_member()
        self.members.setCurrentCell(self.members.rowCount() - 1, 1)

    def _add_catalog_member(self) -> None:
        existing = {
            (selector.currentData(), item.text().strip())
            for row in range(self.members.rowCount())
            if isinstance(selector := self.members.cellWidget(row, 0), QComboBox)
            and (item := self.members.item(row, 1)) is not None
        }
        choices = {key: value for key, value in self._catalog.items() if key not in existing}
        if not choices:
            QMessageBox.information(self, "Каталог проекта", "Доступные ссылки уже добавлены в группу.")
            return
        selected = _choose_catalog_items(self, choices, create_groups=False)
        if selected:
            first = self.members.rowCount()
            self.members.setUpdatesEnabled(False)
            try:
                for kind, identifier in selected:
                    self._add_member(kind, identifier)
            finally:
                self.members.setUpdatesEnabled(True)
            self.members.setCurrentCell(first, 1)

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

    def __init__(
        self, parent: QWidget | None = None, *, catalog: Mapping[tuple[str, str], str] | None = None,
        catalog_names: Mapping[tuple[str, str], str] | None = None,
        preferred_catalog: Sequence[tuple[str, str]] = (),
    ) -> None:
        super().__init__(parent)
        self._catalog = catalog
        self._catalog_names = catalog_names or catalog or {}
        self._preferred_catalog = tuple(preferred_catalog)
        self._groups: tuple[MatrixGroup, ...] = ()
        self._search_rows: tuple[str, ...] = ()
        self._undo: list[tuple[MatrixGroup, ...]] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск группы по названию или ID")
        self.search.setClearButtonEnabled(True)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(150)
        self._search_timer.timeout.connect(lambda: self._refresh(reset=True))
        self.search.textChanged.connect(lambda _: self._search_timer.start())
        self.search.returnPressed.connect(lambda: self._refresh(reset=True))
        search_button = QPushButton("Найти")
        search_button.clicked.connect(lambda: self._refresh(reset=True))
        filters = QHBoxLayout()
        filters.addWidget(self.search, 1)
        filters.addWidget(search_button)
        layout.addLayout(filters)
        self.table = MatrixTable(("Название", "ID группы", "Участников задано"))
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAccessibleName("Группы матрицы доступа")
        self.table.doubleClicked.connect(lambda _index: self._edit())
        layout.addWidget(self.table)
        layout.addLayout(self.table.navigation())
        actions = QHBoxLayout()
        catalog_action = QPushButton("Создать из каталога…")
        catalog_action.setEnabled(bool(self._catalog))
        catalog_action.clicked.connect(self._new_from_catalog)
        for title, callback in (
            ("Создать группу", self._new),
            ("Изменить", self._edit),
            ("Убрать из черновика", self._remove),
            ("Отменить изменение", self._restore),
        ):
            button = QPushButton(title)
            button.clicked.connect(callback)
            actions.addWidget(button)
        actions.insertWidget(1, catalog_action)
        layout.addLayout(actions)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self._refresh()

    def groups(self) -> tuple[MatrixGroup, ...]:
        return self._groups

    def set_groups(self, groups: Sequence[MatrixGroup]) -> None:
        self._groups = tuple(groups)
        self._index_search()
        self._undo.clear()
        self._refresh()

    def _remember(self) -> None:
        self._undo.append(self._groups)
        del self._undo[:-10]

    def _index_search(self) -> None:
        self._search_rows = tuple(f"{group.name} {group.group_id}".casefold() for group in self._groups)

    def _refresh(self, *, reset: bool = False) -> None:
        self._search_timer.stop()
        terms = self.search.text().casefold().split()
        self.table.set_rows([
            index for index, text in enumerate(self._search_rows) if all(term in text for term in terms)
        ], self._row_values, reset=reset)
        self.summary.setText(
            f"Групп в черновике: {len(self._groups)}. Изменения сохраняются новой версией матрицы."
            if self._groups else "Создайте группы адресов и подсетей для источников и назначений."
        )

    def _row_values(self, index: int) -> tuple[str, str, int]:
        group = self._groups[index]
        return group.name, group.group_id, len(group.members)

    def _new(self) -> None:
        self._edit_group(None)

    def _new_from_catalog(self) -> None:
        present = {
            (group.members[0].kind, group.members[0].value) for group in self._groups if len(group.members) == 1
        }
        choices = {key: value for key, value in (self._catalog or {}).items() if key not in present}
        if not choices:
            QMessageBox.information(self, "Каталог проекта", "Для доступных ресурсов и сетей уже созданы группы.")
            return
        selected = _choose_catalog_items(
            self, choices, create_groups=True, initially_selected=self._preferred_catalog,
        )
        if not selected:
            return
        used = {group.group_id for group in self._groups}
        additions = []
        for key in selected:
            kind, identifier = key
            group_id = f"catalog-{uuid5(NAMESPACE_URL, f'arxion:matrix-group:{kind}:{identifier}').hex}"
            if group_id in used:
                group_id = f"group-{uuid4().hex}"
            used.add(group_id)
            member = MatrixMember.model_validate({"kind": kind, "value": identifier})
            name = self._catalog_names.get(key, identifier).strip()[:256] or identifier[:256]
            additions.append(MatrixGroup(group_id=group_id, name=name, members=(member,)))
        self._remember()
        self._groups += tuple(additions)
        self._index_search()
        self._refresh()
        self.summary.setText(f"Создано групп: {len(additions)}. Они войдут в новую версию матрицы после утверждения.")
        self.changed.emit()

    def _edit(self) -> None:
        row = self.table.selected_index()
        if row is not None:
            self._edit_group(row)

    def _edit_group(self, row: int | None) -> None:
        dialog = MatrixGroupDialog(
            self._groups[row] if row is not None else None, self, catalog=self._catalog,
        )
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
        self._index_search()
        self._refresh()
        self.changed.emit()

    def _remove(self) -> None:
        row = self.table.selected_index()
        if row is not None:
            self._remember()
            self._groups = self._groups[:row] + self._groups[row + 1:]
            self._index_search()
            self._refresh()
            self.changed.emit()

    def _restore(self) -> None:
        if self._undo:
            self._groups = self._undo.pop()
            self._index_search()
            self._refresh()
            self.changed.emit()
