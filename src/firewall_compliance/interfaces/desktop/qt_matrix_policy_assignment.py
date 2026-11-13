"""Пакетное назначение политики строкам выбранной области."""

from collections import Counter
from collections.abc import Callable, Collection
from typing import cast

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QPlainTextEdit, QStackedWidget, QVBoxLayout, QWidget

from firewall_compliance.application.matrix_policy_assignment import MatrixPolicyAssignment, prepare_policy_assignment
from firewall_compliance.application.matrix_reports import matrix_service_label
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixBoundary, MatrixRequirement
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.qt_matrix_bulk import MatrixGroupSelection
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable


class MatrixPolicyAssignmentDialog(QDialog):
    def __init__(
        self, matrix: AccessMatrix, scope_id: str, runner: JobRunner,
        pick_policy: Callable[[QWidget, str, str], str | None], parent: QWidget, *,
        linked: Collection[str], initial_id: str | None = None,
    ) -> None:
        super().__init__(parent)
        self._matrix, self._scope_id, self._runner = matrix, scope_id, runner
        self._pick_policy = pick_policy
        self._closed = False
        self._busy = False
        self._policy_id = ""
        self._rows: tuple[MatrixRequirement | MatrixBoundary, ...] = ()
        self.batch: MatrixPolicyAssignment | None = None
        self.setWindowTitle("Назначить политику строкам")
        self.resize(870, 530)
        self.finished.connect(self._finish)

        self._group_names = {group.group_id: group.name for group in matrix.groups}
        identifiers = Counter(row.requirement_id for row in matrix.requirements)
        identifiers.update(row.boundary_id for row in matrix.boundaries)
        choices: list[tuple[str, str]] = []
        for row in (*matrix.requirements, *matrix.boundaries):
            identifier = self._identifier(row)
            if (row.scope_id != scope_id or row.policy_id is not None or identifier in linked
                    or identifiers[identifier] != 1 or isinstance(row, MatrixRequirement) and row.requirement == "unregulated"):
                continue
            kind = "закрытая область" if isinstance(row, MatrixBoundary) else "требование"
            choices.append((identifier, f"{identifier} · {self._pair(row)} · {matrix_service_label(row.service)} · {kind}"))

        layout = QVBoxLayout(self)
        self._pages = QStackedWidget()
        layout.addWidget(self._pages, 1)
        self._select_page = QWidget()
        selection_layout = QVBoxLayout(self._select_page)
        hint = QLabel(
            "Отметьте требования и закрытые области, которым нужна одна сохранённая политика. "
            "Если разрешение служит исключением в нескольких точках, его политику можно оставить пустой."
        )
        hint.setWordWrap(True)
        selection_layout.addWidget(hint)
        self._selection = MatrixGroupSelection(
            choices, self, initial_ids=(initial_id,) if initial_id is not None else (),
            accessible_name="Требования и закрытые области без политики",
        )
        self._selection.search.setPlaceholderText("ID строки, группы или сервис")
        self._selection.selection_changed.connect(self._update_selection)
        selection_layout.addWidget(self._selection, 1)
        self._errors = QPlainTextEdit()
        self._errors.setReadOnly(True)
        self._errors.setAccessibleName("Несовместимые назначения политики")
        self._errors.setMaximumHeight(130)
        self._errors.hide()
        selection_layout.addWidget(self._errors)
        self._pages.addWidget(self._select_page)

        self._preview_page = QWidget()
        preview_layout = QVBoxLayout(self._preview_page)
        self._summary = QLabel()
        self._summary.setTextFormat(Qt.TextFormat.PlainText)
        self._summary.setWordWrap(True)
        preview_layout.addWidget(self._summary)
        self._table = MatrixTable(("ID", "Откуда → Куда", "Сервис", "Тип строки", "Политика"))
        self._table.setAccessibleName("Предпросмотр назначения политики")
        preview_layout.addWidget(self._table, 1)
        preview_layout.addLayout(self._table.navigation())
        self._pages.addWidget(self._preview_page)

        self._status = QLabel()
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self._preview = buttons.addButton("Выбрать политику…", QDialogButtonBox.ButtonRole.ActionRole)
        self._back_button = buttons.addButton("Назад", QDialogButtonBox.ButtonRole.ActionRole)
        self._apply = buttons.addButton("Назначить в черновике", QDialogButtonBox.ButtonRole.ActionRole)
        for button in (self._preview, self._back_button, self._apply, buttons.button(QDialogButtonBox.StandardButton.Cancel)):
            button.setAutoDefault(False)
        self._preview.clicked.connect(self._choose)
        self._back_button.clicked.connect(self._back)
        self._apply.clicked.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._back()
        if not choices:
            self._status.setText("В этой области нет строк, доступных для назначения политики.")

    @staticmethod
    def _identifier(row: MatrixRequirement | MatrixBoundary) -> str:
        return row.boundary_id if isinstance(row, MatrixBoundary) else row.requirement_id

    def _pair(self, row: MatrixRequirement | MatrixBoundary) -> str:
        source = self._group_names.get(row.source_group, row.source_group)
        destination = self._group_names.get(row.destination_group, row.destination_group)
        return f"{source} → {destination}"

    def _finish(self, _code: int) -> None:
        self._closed = True

    def _update_selection(self) -> None:
        count = self._selection.selected_count()
        self._preview.setEnabled(bool(count) and not self._busy)
        self._status.setText(f"Выбрано строк: {count}")

    def _back(self) -> None:
        self.batch = None
        self._rows = ()
        self._table.set_rows((), self._values, reset=True)
        self._pages.setCurrentWidget(self._select_page)
        self._errors.hide()
        self._preview.show()
        self._back_button.hide()
        self._apply.hide()
        self._update_selection()
        self._selection.search.setFocus()

    def _choose(self) -> None:
        identifiers = self._selection.selected_ids()
        if not identifiers or self._busy:
            return
        selected = self._pick_policy(self, self._scope_id, self._policy_id)
        if not selected or self._closed:
            return
        self._policy_id = selected
        matrix, scope = self._matrix, self._scope_id
        self._busy = True
        self._selection.setEnabled(False)
        self._preview.setEnabled(False)
        self._errors.hide()
        self._status.setText("Проверяем связи выбранных строк…")
        try:
            self._runner.submit(lambda: prepare_policy_assignment(matrix, scope, selected, identifiers), self._show)
        except RuntimeError:
            self._show(JobError("matrix_assignment", "Проверка недоступна. Откройте окно назначения заново."))

    def _show(self, value: object) -> None:
        if self._closed:
            return
        self._busy = False
        self._selection.setEnabled(True)
        self._update_selection()
        if isinstance(value, JobError):
            self._status.setText(value.message)
            return
        batch = cast(MatrixPolicyAssignment, value)
        if batch.errors:
            self._status.setText(f"Проверьте выбранные строки. Сообщений: {len(batch.errors)}.")
            self._errors.setPlainText("\n".join(batch.errors))
            self._errors.show()
            return
        self.batch = batch
        self._rows = (*batch.requirements.values(), *batch.boundaries.values())
        self._summary.setText(
            f"Политика {self._policy_id} · требований {len(batch.requirements)} · закрытых областей {len(batch.boundaries)}."
        )
        self._table.set_rows(range(len(self._rows)), self._values, reset=True)
        self._pages.setCurrentWidget(self._preview_page)
        self._preview.hide()
        self._back_button.show()
        self._apply.show()
        self._apply.setEnabled(bool(self._rows))
        self._status.clear()

    def _values(self, index: int) -> tuple[str, ...]:
        row = self._rows[index]
        kind = "Закрытая область" if isinstance(row, MatrixBoundary) else "Требование"
        return self._identifier(row), self._pair(row), matrix_service_label(row.service), kind, row.policy_id or ""
