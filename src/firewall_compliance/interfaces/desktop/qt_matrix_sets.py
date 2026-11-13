"""Версии наборов, закреплённые назначения и предпросмотр изменений."""

from collections import Counter
from collections.abc import Sequence

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from firewall_compliance.application.matrix_requirement_sets import CopyEntry
from firewall_compliance.domain.access_matrix import MatrixRequirement, MatrixRequirementSet, MatrixSetAssignment
from firewall_compliance.interfaces.desktop.qt_matrix_boundary import ports_text
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable


class MatrixSetsWidget(QWidget):
    create_requested = Signal()
    revise_requested = Signal()
    view_requested = Signal()
    assign_requested = Signal()
    edit_groups_requested = Signal()
    refresh_requested = Signal()
    remove_requested = Signal()

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.versions: tuple[MatrixRequirementSet, ...] = ()
        self.assignments: tuple[MatrixSetAssignment, ...] = ()
        layout = QVBoxLayout(self)
        note = QLabel(
            "Новая версия набора создаётся из строк на вкладке «Требования». "
            "Действующие назначения закреплены за выбранной версией до явного обновления."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.version_table = MatrixTable(("Набор", "Версия", "Шаблонов", "ID версии"))
        self.version_table.setAccessibleName("Сохранённые версии наборов в черновике")
        self.version_table.doubleClicked.connect(lambda _: self.view_requested.emit())
        layout.addWidget(self.version_table, 1)
        layout.addLayout(self.version_table.navigation())
        actions = QHBoxLayout()
        for title, signal in (
            ("Создать из требований…", self.create_requested),
            ("Новая версия из требований…", self.revise_requested),
            ("Посмотреть шаблоны…", self.view_requested),
            ("Назначить версию…", self.assign_requested),
        ):
            button = QPushButton(title)
            button.clicked.connect(lambda _checked=False, emit=signal.emit: emit())
            actions.addWidget(button)
        layout.addLayout(actions)

        self.assignment_table = MatrixTable(("Назначение", "Набор", "Версия", "Сторона", "Группы"))
        self.assignment_table.setAccessibleName("Закреплённые назначения наборов")
        layout.addWidget(self.assignment_table, 1)
        layout.addLayout(self.assignment_table.navigation())
        actions = QHBoxLayout()
        self._assignment_actions: list[QPushButton] = []
        for title, signal in (
            ("Изменить группы…", self.edit_groups_requested),
            ("Обновить до последней версии…", self.refresh_requested),
            ("Убрать назначение…", self.remove_requested),
        ):
            button = QPushButton(title)
            button.clicked.connect(lambda _checked=False, emit=signal.emit: emit())
            self._assignment_actions.append(button)
            actions.addWidget(button)
        actions.addStretch(1)
        layout.addLayout(actions)
        self.assignment_table.itemSelectionChanged.connect(self._update_assignment_actions)
        self._update_assignment_actions()

    def _update_assignment_actions(self) -> None:
        enabled = self.selected_assignment() is not None
        for button in self._assignment_actions:
            button.setEnabled(enabled)

    def set_entries(
        self, versions: Sequence[MatrixRequirementSet], assignments: Sequence[MatrixSetAssignment],
    ) -> None:
        selected = self.selected_version()
        assigned = self.selected_assignment()
        self.versions = tuple(sorted(versions, key=lambda version: (version.name.casefold(), -version.version)))
        self.assignments = tuple(assignments)
        by_revision = {item.revision_id: item for item in self.versions}

        def version_row(index: int) -> tuple[object, ...]:
            row = self.versions[index]
            return row.name, row.version, len(row.templates), str(row.revision_id)

        def assignment_row(index: int) -> tuple[object, ...]:
            row = self.assignments[index]
            version = by_revision[row.revision_id]
            axis = "Источники" if row.axis == "source_group" else "Назначения"
            return str(row.assignment_id), version.name, version.version, axis, ", ".join(row.group_ids)

        self.version_table.set_rows(range(len(self.versions)), version_row)
        self.assignment_table.set_rows(range(len(self.assignments)), assignment_row)
        if selected is not None:
            for index, row in enumerate(self.versions):
                if row.revision_id == selected.revision_id:
                    self.version_table.show_index(index)
                    break
        if assigned is not None:
            for index, row in enumerate(self.assignments):
                if row.assignment_id == assigned.assignment_id:
                    self.assignment_table.show_index(index)
                    break

    def selected_version(self) -> MatrixRequirementSet | None:
        index = self.version_table.selected_index()
        return self.versions[index] if index is not None else None

    def selected_assignment(self) -> MatrixSetAssignment | None:
        index = self.assignment_table.selected_index()
        return self.assignments[index] if index is not None else None


def _description(row: MatrixRequirement | None) -> str:
    if row is None:
        return ""
    action = {
        "permit": "Необходим", "allow_optional": "Допустим",
        "deny": "Запрещён", "unregulated": "Не регламентирован",
    }[row.requirement]
    service = f"{row.service.protocol.upper()} {ports_text(row.service)}".strip()
    return f"{row.source_group} → {row.destination_group} · {service} · {action} · {row.scope_id}"


class MatrixSetPreviewDialog(QDialog):
    def __init__(
        self, title: str, entries: Sequence[CopyEntry], previous: Sequence[MatrixRequirement],
        parent: QWidget, *, blockers: Sequence[str] = (), preview_only: bool = False,
        version_changed: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(1080, 640)
        layout = QVBoxLayout(self)
        old = {row.requirement_id: row for row in previous}
        proposed = {entry.row.requirement_id for entry in entries}
        changes: list[tuple[str, MatrixRequirement | None, MatrixRequirement | None, str]] = []
        for entry in entries:
            before = old.get(entry.row.requirement_id)
            disposition = entry.disposition
            if preview_only:
                disposition = "Шаблон"
            elif disposition == "Добавится" and before is not None:
                disposition = "Без изменений" if before == entry.row else "Изменится"
            changes.append((disposition, before, entry.row, entry.related_id))
        changes.extend(("Удалится", row, None, "") for identifier, row in old.items() if identifier not in proposed)
        counts = Counter(change[0] for change in changes)
        conflicts = {"Совпадение", "Противоречие"}
        note = QLabel(
            ". ".join(f"{key} {value}" for key, value in counts.items())
            + ". " + ("Закреплённая версия набора обновится. " if version_changed else "")
            + "Совпадения и противоречия проверяются для одинаковых пар групп. "
            + "Пересечения состава групп и закрытых областей оцениваются при сверке."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        if blockers:
            blocking = QPlainTextEdit("\n".join(blockers))
            blocking.setReadOnly(True)
            blocking.setMaximumHeight(95)
            blocking.setAccessibleName("Причины, препятствующие изменению назначения")
            layout.addWidget(blocking)
        table = MatrixTable(("Изменение", "До", "После", "Связанное требование"))
        filters = QComboBox()
        if not preview_only:
            filters.setAccessibleName("Фильтр изменений назначения")
            filters.addItem("Изменения", "changes")
            filters.addItem("Все строки", "all")
            filters.addItem("Совпадения и противоречия", "conflicts")
            layout.addWidget(filters)
        layout.addWidget(table, 1)
        layout.addLayout(table.navigation())
        detail = QPlainTextEdit()
        detail.setReadOnly(True)
        detail.setAccessibleName("Точное содержимое выбранных требований до и после")

        def select() -> None:
            index = table.selected_index()
            if index is None:
                detail.clear()
                return
            _, before, after, _ = changes[index]
            detail.setPlainText("\n\n".join(
                label + "\n" + row.model_dump_json(indent=2)
                for label, row in (("До", before), ("После", after)) if row is not None
            ))

        table.itemSelectionChanged.connect(select)

        def refresh(*_: object) -> None:
            mode = filters.currentData()
            indices = [
                index for index, change in enumerate(changes)
                if (mode != "changes" or change[0] != "Без изменений")
                and (mode != "conflicts" or change[0] in conflicts)
            ]
            table.set_rows(indices, lambda index: (
                changes[index][0], _description(changes[index][1]), _description(changes[index][2]), changes[index][3],
            ), reset=True)
            if indices:
                table.selectRow(0)

        filters.currentIndexChanged.connect(refresh)
        refresh()
        layout.addWidget(detail, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        if not preview_only:
            accept = buttons.addButton("Применить к черновику", QDialogButtonBox.ButtonRole.AcceptRole)
            has_changes = version_changed or any(disposition != "Без изменений" for disposition in counts)
            accept.setEnabled(has_changes and not blockers and not conflicts.intersection(counts))
            buttons.accepted.connect(self.accept)
        else:
            buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Закрыть")
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
