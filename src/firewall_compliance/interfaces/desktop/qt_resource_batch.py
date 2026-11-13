"""Пакетный ввод ручных ресурсов с подтверждёнными адресами."""

import sqlite3
from collections.abc import Callable, Mapping, Sequence
from typing import Any, cast
from uuid import UUID

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner, JobStatus
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable
from firewall_compliance.interfaces.desktop.resource_registry import (
    MATRIX_BINDING_FIELD,
    resource_address_binding,
)

type ResourceBatchRows = tuple[dict[str, Any], ...]


def parse_resource_batch(text: str, site_id: str) -> ResourceBatchRows:
    """Разобрать строки с именем, адресом и необязательным типом ресурса."""
    rows: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        fields = [part.strip() for part in line.split("\t")]
        if len(fields) not in {2, 3} or not fields[0] or not fields[1]:
            raise ValueError(f"В строке {number} нужны имя и адрес в отдельных столбцах.")
        name, address = fields[:2]
        role = fields[2] if len(fields) == 3 else ""
        if any(len(value) > 16000 or "\x00" in value for value in (name, role)):
            raise ValueError(f"Имя и тип в строке {number} могут содержать до 16 000 символов без нулевых байтов.")
        try:
            binding = resource_address_binding({"site_id": site_id, "prefixes": [address]})
        except ValueError:
            raise ValueError(f"Укажите корректный IP-адрес или адрес сети CIDR в строке {number}.") from None
        key = name.casefold(), binding["prefixes"][0]
        if key in seen:
            raise ValueError(f"Ресурс в строке {number} повторяет строку {seen[key]}.")
        seen[key] = number
        row: dict[str, Any] = {"name": name, "category": "unclassified", MATRIX_BINDING_FIELD: binding}
        if role:
            row["resource_type"] = role
        rows.append(row)
    if not rows:
        raise ValueError("Вставьте хотя бы одну строку с именем и адресом.")
    return tuple(rows)


class ResourceBatchDialog(QDialog):
    """Предпросмотр и явное подтверждение ручных карточек."""

    def __init__(
        self, sites: Sequence[Mapping[str, str]], parent: QWidget, *,
        initial_site_id: str | None = None, create: Callable[[ResourceBatchRows], tuple[str, ...]] | None = None,
        runner: JobRunner | None = None,
    ) -> None:
        super().__init__(parent)
        self.rows: ResourceBatchRows = ()
        self.created_ids: tuple[str, ...] = ()
        self._draft: ResourceBatchRows = ()
        self._create = create
        self._runner = runner
        self._saving = False
        self._save_job: UUID | None = None
        self._save_timer = QTimer(self)
        self._save_timer.setInterval(150)
        self._save_timer.timeout.connect(self._check_save_status)
        self.setWindowTitle("Добавить ресурсы списком")
        self.resize(790, 520)
        layout = QVBoxLayout(self)
        self._pages = QStackedWidget()
        layout.addWidget(self._pages, 1)

        self._input_page = QWidget()
        input_layout = QVBoxLayout(self._input_page)
        note = QLabel(
            "Вставьте строки без заголовка. Разделите имя, IP-адрес или сеть CIDR "
            "и необязательный тип или роль табуляцией."
        )
        note.setWordWrap(True)
        input_layout.addWidget(note)
        form = QFormLayout()
        self._site = QComboBox()
        self._site.setAccessibleName("Площадка ресурсов для матрицы")
        self._site.setPlaceholderText("Выберите площадку")
        self._site.addItem("Без площадки", "")
        for site in sites:
            self._site.addItem(site["name"], site["id"])
        self._site.setCurrentIndex(self._site.findData(initial_site_id) if initial_site_id is not None else -1)
        form.addRow("Площадка для матрицы", self._site)
        input_layout.addLayout(form)
        self._text = QPlainTextEdit()
        self._text.setAccessibleName("Таблица ручных ресурсов")
        self._text.setPlaceholderText("DNS-01\t10.10.20.53\tDNS\nNTP-01\t10.10.20.123\tСлужба времени")
        input_layout.addWidget(self._text, 1)
        self._pages.addWidget(self._input_page)

        self._preview_page = QWidget()
        preview_layout = QVBoxLayout(self._preview_page)
        self._summary = QLabel()
        self._summary.setTextFormat(Qt.TextFormat.PlainText)
        self._summary.setWordWrap(True)
        preview_layout.addWidget(self._summary)
        self._table = MatrixTable(("№", "Имя", "Подтверждённый адрес", "Тип или роль"))
        self._table.setAccessibleName("Предпросмотр ручных ресурсов")
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        preview_layout.addWidget(self._table, 1)
        preview_layout.addLayout(self._table.navigation())
        self._pages.addWidget(self._preview_page)

        self._error = QLabel()
        self._error.setTextFormat(Qt.TextFormat.PlainText)
        self._error.setWordWrap(True)
        layout.addWidget(self._error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self._preview_button = buttons.addButton("Предпросмотр", QDialogButtonBox.ButtonRole.ActionRole)
        self._back_button = buttons.addButton("Назад", QDialogButtonBox.ButtonRole.ActionRole)
        self._create_button = buttons.addButton("Создать карточки", QDialogButtonBox.ButtonRole.ActionRole)
        self._cancel_button = buttons.button(QDialogButtonBox.StandardButton.Cancel)
        for button in (self._preview_button, self._back_button, self._create_button, self._cancel_button):
            button.setAutoDefault(False)
        self._back_button.hide()
        self._create_button.hide()
        self._preview_button.clicked.connect(self._preview)
        self._back_button.clicked.connect(self._back)
        self._create_button.clicked.connect(self._confirm)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._text.setFocus()

    def _preview(self) -> None:
        site_id = self._site.currentData()
        if not isinstance(site_id, str):
            self._error.setText("Выберите площадку для адресов ресурсов.")
            self._site.setFocus()
            return
        try:
            self._draft = parse_resource_batch(self._text.toPlainText(), site_id)
        except ValueError as error:
            self._error.setText(str(error))
            self._text.setFocus()
            return
        self._summary.setText(f"Ручных карточек: {len(self._draft)} · площадка: {self._site.currentText()}")
        self._table.set_rows(range(len(self._draft)), self._preview_values, reset=True)
        self._error.clear()
        self._pages.setCurrentWidget(self._preview_page)
        self._preview_button.hide()
        self._back_button.show()
        self._create_button.show()
        self._table.setFocus()

    def _preview_values(self, index: int) -> tuple[int, str, str, str]:
        row = self._draft[index]
        return index + 1, row["name"], row[MATRIX_BINDING_FIELD]["prefixes"][0], row.get("resource_type", "—")

    def _back(self) -> None:
        self._draft = ()
        self._table.set_rows((), self._preview_values, reset=True)
        self._error.clear()
        self._pages.setCurrentWidget(self._input_page)
        self._back_button.hide()
        self._create_button.hide()
        self._preview_button.show()
        self._text.setFocus()

    def _confirm(self) -> None:
        if self._saving or not self._draft:
            return
        create = self._create
        if create is None:
            self._finish_save(())
            return
        draft = self._draft

        def save() -> tuple[str, ...] | JobError:
            try:
                return create(draft)
            except ValueError as error:
                return JobError("resource_batch", str(error))
            except (OSError, sqlite3.Error):
                return JobError("resource_batch", "Не удалось сохранить карточки. Проверьте доступ к хранилищу проекта.")

        self._set_saving(True)
        self._error.setText("Сохраняем карточки…")
        if self._runner is None:
            self._finish_save(save())
            return
        try:
            self._save_job = self._runner.submit(save, self._finish_save)
        except RuntimeError:
            self._finish_save(JobError("resource_batch", "Сохранение недоступно. Откройте окно добавления заново."))
            return
        self._save_timer.start()

    def _set_saving(self, saving: bool) -> None:
        self._saving = saving
        for button in (self._back_button, self._create_button, self._cancel_button):
            button.setEnabled(not saving)

    def _check_save_status(self) -> None:
        if (
            self._runner is not None and self._save_job is not None
            and self._runner.status(self._save_job) == JobStatus.CANCELED
        ):
            self._finish_save(JobError("resource_batch", "Сохранение отменено до начала записи."))

    def _finish_save(self, result: object) -> None:
        self._save_timer.stop()
        self._save_job = None
        self._set_saving(False)
        if isinstance(result, JobError):
            self._error.setText(result.message)
            return
        self.created_ids = cast(tuple[str, ...], result)
        self.rows = self._draft
        self.accept()

    def reject(self) -> None:
        if not self._saving:
            super().reject()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._saving:
            event.ignore()
        else:
            super().closeEvent(event)
