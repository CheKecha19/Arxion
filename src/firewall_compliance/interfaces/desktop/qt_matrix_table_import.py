"""Вставка таблицы в черновик с проверкой ссылок и предпросмотром."""

from typing import cast

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QLabel, QPlainTextEdit, QPushButton, QStackedWidget, QVBoxLayout, QWidget,
)

from firewall_compliance.application.matrix_reports import matrix_service_label
from firewall_compliance.application.matrix_table_import import MatrixTableImport, prepare_matrix_table_import
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixBoundary, MatrixRequirement
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable

_ACTIONS = {
    "permit": "Доступ необходим", "allow_optional": "Доступ допустим", "deny": "Запретить",
    "unregulated": "Не регламентировано",
}
_HEADERS = "ID\tОткуда\tКуда\tСервис\tТребование\tПолитика\tИсключения\tЗона источника\tЗона назначения"


class MatrixTableImportDialog(QDialog):
    def __init__(self, matrix: AccessMatrix, scope_id: str, runner: JobRunner, parent: QWidget) -> None:
        super().__init__(parent)
        self._matrix, self._scope_id, self._runner = matrix, scope_id, runner
        self._group_names = {group.group_id: group.name for group in matrix.groups}
        self._closed = False
        self._rows: tuple[MatrixRequirement | MatrixBoundary, ...] = ()
        self.result_batch: MatrixTableImport | None = None
        self.setWindowTitle("Вставить требования из таблицы")
        self.resize(920, 540)
        self.finished.connect(self._finish)

        layout = QVBoxLayout(self)
        self._pages = QStackedWidget()
        layout.addWidget(self._pages, 1)

        self._input_page = QWidget()
        input_layout = QVBoxLayout(self._input_page)
        hint = QLabel(
            f"Область новых строк: {scope_id}. Скопируйте ячейки с разделением столбцов табуляцией.\n"
            "Обязательные столбцы: ID, Откуда, Куда, Сервис, Требование. Дополнительные: Политика, "
            "Исключения, Зона источника, Зона назначения. Заголовок можно оставить.\n"
            "Укажите имена или ID существующих групп. Для закрытой области перечислите ID разрешённых "
            "требований через запятую в столбце «Исключения». Политику можно указать позднее."
        )
        hint.setTextFormat(Qt.TextFormat.PlainText)
        hint.setWordWrap(True)
        input_layout.addWidget(hint)
        copy_headers = QPushButton("Скопировать заголовок")
        copy_headers.setAutoDefault(False)
        copy_headers.clicked.connect(lambda: QApplication.clipboard().setText(_HEADERS))
        input_layout.addWidget(copy_headers, alignment=Qt.AlignmentFlag.AlignLeft)
        self._text = QPlainTextEdit()
        self._text.setAccessibleName("Таблица требований доступа")
        self._text.setPlaceholderText(
            "ID\tОткуда\tКуда\tСервис\tТребование\tПолитика\tИсключения\n"
            "R01\tБухгалтерия\t1С\ttcp/443\tpermit\n"
            "R02\tБухгалтерия\tВнутренние сети\tip\tboundary\t\tR01"
        )
        input_layout.addWidget(self._text, 1)
        self._errors = QPlainTextEdit()
        self._errors.setReadOnly(True)
        self._errors.setAccessibleName("Ошибки строк таблицы")
        self._errors.setMaximumHeight(140)
        self._errors.hide()
        input_layout.addWidget(self._errors)
        self._pages.addWidget(self._input_page)

        self._preview_page = QWidget()
        preview_layout = QVBoxLayout(self._preview_page)
        self._summary = QLabel()
        self._summary.setTextFormat(Qt.TextFormat.PlainText)
        self._summary.setWordWrap(True)
        preview_layout.addWidget(self._summary)
        self._table = MatrixTable(("ID", "Откуда", "Куда", "Сервис", "Требование", "Политика", "Исключения", "Зоны"))
        self._table.setAccessibleName("Предпросмотр новых требований")
        preview_layout.addWidget(self._table, 1)
        preview_layout.addLayout(self._table.navigation())
        self._pages.addWidget(self._preview_page)

        self._status = QLabel()
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self._preview_button = buttons.addButton("Предпросмотр", QDialogButtonBox.ButtonRole.ActionRole)
        self._back_button = buttons.addButton("К таблице", QDialogButtonBox.ButtonRole.ActionRole)
        self._add_button = buttons.addButton("Добавить в черновик", QDialogButtonBox.ButtonRole.ActionRole)
        for button in (self._preview_button, self._back_button, self._add_button,
                       buttons.button(QDialogButtonBox.StandardButton.Cancel)):
            button.setAutoDefault(False)
        self._preview_button.clicked.connect(self._preview)
        self._back_button.clicked.connect(self._back)
        self._add_button.clicked.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._back()

    def _finish(self, _status: int) -> None:
        self._closed = True

    def _back(self) -> None:
        self.result_batch = None
        self._rows = ()
        self._table.set_rows((), self._values, reset=True)
        self._status.clear()
        self._errors.hide()
        self._pages.setCurrentWidget(self._input_page)
        self._preview_button.show()
        self._back_button.hide()
        self._add_button.hide()
        self._text.setFocus()

    def _preview(self) -> None:
        text = self._text.toPlainText()
        matrix, scope_id = self._matrix, self._scope_id
        self._text.setReadOnly(True)
        self._preview_button.setEnabled(False)
        self._errors.hide()
        self._status.setText("Проверяем строки и ссылки…")
        try:
            self._runner.submit(lambda: prepare_matrix_table_import(matrix, text, scope_id), self._show_preview)
        except RuntimeError:
            self._show_preview(JobError("matrix_import", "Проверка недоступна. Откройте окно вставки заново."))

    def _show_preview(self, value: object) -> None:
        if self._closed:
            return
        self._text.setReadOnly(False)
        self._preview_button.setEnabled(True)
        if isinstance(value, JobError):
            self._status.setText(value.message)
            return
        batch = cast(MatrixTableImport, value)
        if batch.errors:
            self._status.setText(f"Исправьте ошибки в таблице. Сообщений: {len(batch.errors)}.")
            self._errors.setPlainText("\n".join(batch.errors))
            self._errors.show()
            return
        self.result_batch = batch
        self._rows = (*batch.requirements, *batch.boundaries)
        self._summary.setText(
            f"Добавится требований: {len(batch.requirements)} · закрытых областей: {len(batch.boundaries)}. "
            f"Уже есть в черновике: {batch.existing}.\n"
            "Сохранение в историю доступно после утверждения новой версии."
        )
        self._table.set_rows(range(len(self._rows)), self._values, reset=True)
        self._status.clear()
        self._pages.setCurrentWidget(self._preview_page)
        self._preview_button.hide()
        self._back_button.show()
        self._add_button.show()
        self._add_button.setEnabled(bool(self._rows))
        self._table.setFocus()

    def _values(self, index: int) -> tuple[str, ...]:
        row = self._rows[index]
        if isinstance(row, MatrixBoundary):
            identifier, action, exceptions = row.boundary_id, "Закрытая область", ", ".join(row.allowed_requirement_ids)
        else:
            identifier, action, exceptions = row.requirement_id, _ACTIONS[row.requirement], ""
        zones = row.zone_pair
        return (
            identifier, self._group_names.get(row.source_group, row.source_group),
            self._group_names.get(row.destination_group, row.destination_group), matrix_service_label(row.service),
            action, row.policy_id or "Не назначена", exceptions,
            f"{zones.source_zone} → {zones.destination_zone}" if zones is not None else "",
        )
