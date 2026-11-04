"""Matrix editor and declared-condition assessment of an explicitly selected revision."""

from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

from PySide6.QtCore import QIODevice, QSaveFile, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QProgressBar, QPushButton,
    QSplitter, QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget,
)

from firewall_compliance.application.access_matrix import evaluate_access_matrix, matrix_diagnostics
from firewall_compliance.application.matrix_artifact import MatrixAssessmentArtifact
from firewall_compliance.application.matrix_reports import (
    MATRIX_STATE_LABELS, matrix_report_csv, matrix_report_html,
)
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixRequirement
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.matrix_store import (
    AccessMatrixStore, MatrixAssessmentSummary, MatrixVersionRecord,
)
from firewall_compliance.interfaces.desktop.qt_matrix_groups import MatrixGroupsWidget

_ACTIONS = {"permit": "Разрешить", "deny": "Запретить", "unregulated": "Не регламентировано"}
_STATES = MATRIX_STATE_LABELS


class AccessMatrixDialog(QDialog):
    """Opening only reads; schema initialization requires explicit Save."""

    def __init__(
        self, store_path: Path, runner: JobRunner, project_id: str,
        revision: DeviceRevision | None = None, parent: QWidget | None = None, *,
        scope_id: str | None = None, profile_id: str = "unspecified",
        profile_version: str = "unspecified", context_valid: Callable[[], bool] | None = None,
        origin_run_id: str | None = None, profile_settings_json: str | None = None,
        origin_item_id: str | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = AccessMatrixStore(store_path)
        self._runner = runner
        self._project_id = project_id
        self._scope_id = scope_id or project_id
        self._profile_id, self._profile_version = profile_id, profile_version
        self._origin_run_id = origin_run_id
        self._origin_item_id = origin_item_id
        self._profile_settings_json = profile_settings_json
        self._artifact: MatrixAssessmentArtifact | None = None
        self._assessments: tuple[MatrixAssessmentSummary, ...] = ()
        self._history_offset = 0
        self._history_count = 0
        self._revision = revision.as_snapshot() if revision is not None else None
        self._context_valid = context_valid or (lambda: True)
        self._closed = False
        self._ticket: object | None = None
        self._versions: tuple[MatrixVersionRecord, ...] = ()
        self._matrix_id = "access-matrix"
        self._version = "1"
        self._requirements: list[dict[str, Any]] = []
        self._selected: int | None = None
        self.setWindowTitle("Матрица доступа — заданные условия правил")
        self.resize(1120, 800)
        root = QVBoxLayout(self)
        note = QLabel(
            "Матрица необязательна для обычных проверок. Отсутствующая строка — не регламентировано.\n"
            "Сверка оценивает заданные условия правил; сквозная доступность не вычисляется."
        )
        note.setWordWrap(True)
        root.addWidget(note)
        self.revision_note = QLabel(
            f"Ревизия: {self._revision.revision_id}; область: {self._scope_id}; "
            f"профиль: {profile_id} / {profile_version}"
            if self._revision else "Ревизия не выбрана. Редактирование доступно, сверка недоступна."
        )
        self.revision_note.setWordWrap(True)
        root.addWidget(self.revision_note)
        version_row = QHBoxLayout()
        self.versions = QComboBox()
        self.versions.setAccessibleName("Сохранённые версии матрицы")
        self.versions.currentIndexChanged.connect(self._load_selected)
        version_row.addWidget(self.versions, 1)
        self.reload = QPushButton("Перечитать историю")
        self.reload.clicked.connect(self._reload)
        version_row.addWidget(self.reload)
        self.save = QPushButton("Сохранить новой версией")
        self.save.clicked.connect(self._save)
        version_row.addWidget(self.save)
        root.addLayout(version_row)
        split = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(split, 1)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(QLabel("Группы источников и назначений"))
        self.groups = MatrixGroupsWidget(self)
        self.groups.changed.connect(self._refresh_group_choices)
        left_layout.addWidget(self.groups)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(("ID", "Источник", "Назначение", "Требование"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._select_row)
        left_layout.addWidget(self.table)
        row_buttons = QHBoxLayout()
        new = QPushButton("Новое требование")
        new.clicked.connect(self._new_row)
        remove = QPushButton("Удалить из черновика")
        remove.clicked.connect(self._remove_row)
        row_buttons.addWidget(new)
        row_buttons.addWidget(remove)
        left_layout.addLayout(row_buttons)
        split.addWidget(left)
        right = QWidget()
        form = QFormLayout(right)
        self.fields: dict[str, QLineEdit] = {}
        self.group_choices: dict[str, QComboBox] = {}
        for key, label in (
            ("requirement_id", "ID требования"), ("source_group", "ID группы источника"),
            ("destination_group", "ID группы назначения"), ("scope_id", "Область"),
            ("policy_id", "ID политики (для сверки)"), ("ports", "Порты: 443,1000-2000 или *"),
            ("owner", "Владелец"), ("review_date", "Пересмотр: ГГГГ-ММ-ДД"),
            ("reason", "Основание"), ("identity", "Пользователь / группа"),
            ("schedule", "Условие расписания"),
        ):
            if key in {"source_group", "destination_group"}:
                selector = QComboBox()
                selector.setEditable(True)
                selector.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
                selector.setAccessibleName(label)
                self.group_choices[key] = selector
                form.addRow("Группа источника" if key == "source_group" else "Группа назначения", selector)
                continue
            field = QLineEdit()
            field.setAccessibleName(label)
            self.fields[key] = field
            form.addRow(label, field)
        self.protocol = QComboBox()
        self.protocol.addItems(("tcp", "udp", "icmp", "ip"))
        form.addRow("Протокол", self.protocol)
        self.action = QComboBox()
        for key, title in _ACTIONS.items():
            self.action.addItem(title, key)
        form.addRow("Требование", self.action)
        self.apply_row = QPushButton("Применить карточку к черновику")
        self.apply_row.clicked.connect(self._apply_row)
        form.addRow(self.apply_row)
        split.addWidget(right)
        controls = QHBoxLayout()
        self.validate = QPushButton("Проверить структуру")
        self.validate.clicked.connect(self._validate)
        self.evaluate = QPushButton("Сверить с выбранной ревизией")
        self.evaluate.clicked.connect(self._evaluate)
        controls.addWidget(self.validate)
        controls.addWidget(self.evaluate)
        self.grid_button = QPushButton("Сетка групп × групп")
        self.grid_button.clicked.connect(self._open_grid)
        controls.addWidget(self.grid_button)
        root.addLayout(controls)
        history = QHBoxLayout()
        history.addWidget(QLabel("Сохранённые сверки"))
        self.assessments = QComboBox()
        self.assessments.setAccessibleName("История сохранённых сверок матрицы")
        history.addWidget(self.assessments, 1)
        self.open_assessment = QPushButton("Открыть результат")
        self.open_assessment.clicked.connect(self._open_assessment)
        history.addWidget(self.open_assessment)
        self.history_previous = QPushButton("← Новее")
        self.history_previous.clicked.connect(lambda: self._history_page(-1))
        self.history_next = QPushButton("Старее →")
        self.history_next.clicked.connect(lambda: self._history_page(1))
        history.addWidget(self.history_previous)
        history.addWidget(self.history_next)
        root.addLayout(history)
        self.history_summary = QLabel()
        root.addWidget(self.history_summary)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        root.addWidget(self.progress)
        self.status = QLabel()
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        result_split = QSplitter(Qt.Orientation.Horizontal)
        self.result_table = QTableWidget(0, 3)
        self.result_table.setHorizontalHeaderLabels(("Требование", "Результат", "Основание"))
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.result_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.result_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.result_table.setAccessibleName("Результаты сохранённой сверки матрицы")
        self.result_table.itemSelectionChanged.connect(self._show_result_row)
        self.result_table.horizontalHeader().setStretchLastSection(True)
        result_split.addWidget(self.result_table)
        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        self.result.setAccessibleName("Диагностика матрицы и доказательства")
        result_split.addWidget(self.result)
        result_split.setMaximumHeight(260)
        root.addWidget(result_split)
        exports = QHBoxLayout()
        self.preview_report = QPushButton("Предпросмотр результата")
        self.preview_report.clicked.connect(self._preview_report)
        exports.addWidget(self.preview_report)
        self.export_buttons: list[QPushButton] = []
        for kind in ("html", "json", "csv"):
            button = QPushButton("Сохранить " + kind.upper())
            button.clicked.connect(lambda _checked=False, kind=kind: self._export_report(kind))
            self.export_buttons.append(button)
            exports.addWidget(button)
        root.addLayout(exports)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self.finished.connect(self._finish)
        self._new_row()
        self._reload()

    def _finish(self, _result: int) -> None:
        self._closed = True
        self._ticket = None

    def _job(self, work: Callable[[], object], done: Callable[[Any], None]) -> None:
        if self._closed or not self._context_valid():
            self.reject()
            return
        ticket = object()
        self._ticket = ticket
        self.progress.show()
        self.status.setText("Выполняется…")
        for widget in self._job_controls():
            widget.setEnabled(False)

        def complete(value: object) -> None:
            if self._closed or self._ticket is not ticket:
                return
            if not self._context_valid():
                self.reject()
                return
            self.progress.hide()
            for widget in self._job_controls():
                widget.setEnabled(True)
            self.evaluate.setEnabled(self._revision is not None)
            self._history_controls()
            self._report_controls()
            if isinstance(value, JobError):
                self.status.setText("Операция не завершена: " + value.message)
                return
            done(value)

        self._runner.submit(work, complete)

    def _job_controls(self) -> tuple[QWidget, ...]:
        return (
            self.save, self.reload, self.validate, self.evaluate, self.versions, self.grid_button,
            self.assessments, self.open_assessment, self.history_previous, self.history_next,
            self.result_table, self.preview_report, *self.export_buttons,
        )

    def _reload(self) -> None:
        def work() -> tuple[tuple[MatrixVersionRecord, ...], tuple[MatrixAssessmentSummary, ...], int]:
            return (
                self._store.list_versions(self._project_id),
                self._store.list_assessments(self._project_id, offset=self._history_offset),
                self._store.assessment_count(self._project_id),
            )

        def done(value: Any) -> None:
            self._show_versions(value[0])
            self._show_assessments(value[1], value[2])

        self._job(work, done)

    def _show_assessments(self, values: tuple[MatrixAssessmentSummary, ...], count: int) -> None:
        self._assessments, self._history_count = values, count
        self.assessments.clear()
        for value in values:
            self.assessments.addItem(
                f"{value.created_at} · {value.device_label} · матрица v{value.matrix_version}",
                value.artifact_id,
            )
        self.history_summary.setText(
            f"Результаты {self._history_offset + 1}–{self._history_offset + len(values)} из {count}."
            if values else "Сохранённых сверок на этой странице нет."
        )
        self._history_controls()

    def _history_controls(self) -> None:
        self.open_assessment.setEnabled(bool(self._assessments))
        self.history_previous.setEnabled(self._history_offset > 0)
        self.history_next.setEnabled(self._history_offset + len(self._assessments) < self._history_count)

    def _history_page(self, direction: int) -> None:
        self._history_offset = max(0, self._history_offset + direction * 100)

        def work() -> tuple[tuple[MatrixAssessmentSummary, ...], int]:
            return (
                self._store.list_assessments(self._project_id, offset=self._history_offset),
                self._store.assessment_count(self._project_id),
            )

        self._job(work, lambda value: self._show_assessments(*value))

    def _open_assessment(self) -> None:
        identifier = self.assessments.currentData()
        if isinstance(identifier, str):
            self._job(
                lambda: self._store.get_assessment(self._project_id, identifier), self._show_artifact,
            )

    def _show_artifact(self, artifact: MatrixAssessmentArtifact) -> None:
        self._artifact = artifact
        value = artifact.assessment
        lines = [
            f"Сохранённая сверка {artifact.artifact_id} · {artifact.created_at.isoformat()}",
            f"Матрица {artifact.matrix.matrix_id} / v{artifact.matrix.version}; ревизия {value.revision_id}",
            f"Область: {value.scope_id}; профиль: {value.profile_id} / {value.profile_version}",
            "Режим: заданные условия правил. Это результат по сохранённым входам, не текущему черновику.",
        ]
        self.result_table.blockSignals(True)
        self.result_table.clearSelection()
        self.result_table.setRowCount(len(value.requirements))
        for index, row in enumerate(value.requirements):
            for column, text in enumerate((row.requirement_id, _STATES[row.state], "; ".join(row.reasons))):
                self.result_table.setItem(index, column, QTableWidgetItem(text))
        self.result_table.blockSignals(False)
        lines.extend(f"{issue.code}: {issue.message}" for issue in value.diagnostics)
        lines.extend(value.limitations)
        lines.append("Выберите требование в таблице для просмотра доказательств.")
        self.result.setPlainText("\n".join(lines))
        self._report_controls()
        self.status.setText("Результат прочитан из истории; повторный анализ не выполнялся.")

    def _show_result_row(self) -> None:
        artifact = self._artifact
        row = self.result_table.currentRow()
        if artifact is None or not 0 <= row < len(artifact.assessment.requirements):
            return
        value = artifact.assessment.requirements[row]
        self.result.setPlainText(
            f"Сверка: {artifact.artifact_id}; матрица v{artifact.matrix.version}\n"
            f"Ревизия: {artifact.revision.revision_id}\n"
            f"{value.requirement_id}: {_STATES[value.state]}\n\n"
            + "\n".join(value.reasons)
            + "\n\nДоказательства и ссылки:\n" + value.model_dump_json(indent=2)
        )

    def _report_controls(self) -> None:
        for widget in (self.preview_report, *self.export_buttons):
            widget.setEnabled(self._artifact is not None)

    def _preview_report(self) -> None:
        artifact = self._artifact
        if artifact is None:
            return
        self._job(lambda: matrix_report_html(artifact), self._show_preview_report)

    def _show_preview_report(self, content: str) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Предпросмотр сохранённой сверки")
        dialog.resize(1000, 720)
        layout = QVBoxLayout(dialog)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(False)
        browser.setOpenLinks(False)
        browser.setHtml(content)
        layout.addWidget(browser)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()
        dialog.deleteLater()

    def _export_report(self, kind: str) -> None:
        artifact = self._artifact
        if artifact is None or kind not in {"html", "json", "csv"}:
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Сохранить результат сверки", f"matrix-{artifact.artifact_id}.{kind}",
            f"{kind.upper()} (*.{kind})",
        )
        if not filename:
            return
        destination = Path(filename)

        def work() -> str:
            if kind == "html":
                text = matrix_report_html(artifact)
            elif kind == "csv":
                text = matrix_report_csv(artifact)
            else:
                text = artifact.model_dump_json(indent=2)
            data = text.encode("utf-8-sig" if kind == "csv" else "utf-8")
            stream = QSaveFile(str(destination))
            if not stream.open(QIODevice.OpenModeFlag.WriteOnly):
                raise OSError("Cannot open report destination")
            if stream.write(data) != len(data):
                stream.cancelWriting()
                raise OSError("Cannot write report")
            if not stream.commit():
                raise OSError("Cannot commit report")
            return destination.name

        self._job(work, lambda name: self.status.setText("Сохранён результат: " + name))

    def _show_versions(self, values: tuple[MatrixVersionRecord, ...]) -> None:
        self._versions = values
        self.versions.blockSignals(True)
        self.versions.clear()
        for value in values:
            self.versions.addItem(f"Версия {value.matrix.version} · {value.created_at}")
        self.versions.setCurrentIndex(len(values) - 1)
        self.versions.blockSignals(False)
        if values:
            self._load_selected()
        self.status.setText(f"Сохранённых версий: {len(values)}. Изменения карточки применяются кнопкой.")

    def _load_selected(self, *_: Any) -> None:
        index = self.versions.currentIndex()
        if not 0 <= index < len(self._versions):
            return
        record = self._versions[index]
        matrix = record.matrix
        self._matrix_id, self._version = matrix.matrix_id, matrix.version
        self.groups.set_groups(matrix.groups)
        self._refresh_group_choices()
        self._requirements = [row.model_dump(mode="json") for row in matrix.requirements]
        self._refresh_rows()
        self._new_row()
        self.status.setText(f"Загружена версия {matrix.version}. SHA-256: {record.checksum}")

    def _refresh_rows(self) -> None:
        self.table.blockSignals(True)
        self.table.setRowCount(len(self._requirements))
        for index, row in enumerate(self._requirements):
            for column, value in enumerate((
                row["requirement_id"], row["source_group"], row["destination_group"],
                _ACTIONS[row["requirement"]],
            )):
                self.table.setItem(index, column, QTableWidgetItem(str(value)))
        self.table.blockSignals(False)

    def _new_row(self) -> None:
        self._selected = None
        self.table.clearSelection()
        for field in self.fields.values():
            field.clear()
        for selector in self.group_choices.values():
            selector.setCurrentIndex(-1)
            selector.clearEditText()
        self.fields["scope_id"].setText(self._scope_id)
        self.action.setCurrentIndex(self.action.findData("unregulated"))

    def _select_row(self) -> None:
        index = self.table.currentRow()
        if not 0 <= index < len(self._requirements):
            return
        self._selected = index
        row = self._requirements[index]
        for key, field in self.fields.items():
            if key != "ports":
                field.setText(str(row.get(key) or ""))
        for key, selector in self.group_choices.items():
            self._set_group_choice(selector, row[key])
        service = row["service"]
        self.protocol.setCurrentText(service["protocol"])
        self.fields["ports"].setText("*" if service["any_ports"] else ",".join(
            str(port["start"]) if port["start"] == port["end"]
            else f"{port['start']}-{port['end']}" for port in service["ports"]
        ))
        self.action.setCurrentIndex(self.action.findData(row["requirement"]))

    def _apply_row(self) -> None:
        try:
            payload: dict[str, Any] = {key: field.text().strip() or None for key, field in self.fields.items()}
            payload.update({key: self._group_choice(selector) for key, selector in self.group_choices.items()})
            ports = payload.pop("ports") or ""
            ranges = []
            if ports and ports != "*":
                for value in ports.split(","):
                    parts = value.strip().split("-")
                    if len(parts) not in {1, 2}:
                        raise ValueError("invalid port range")
                    ranges.append({"start": int(parts[0]), "end": int(parts[-1])})
            if payload["review_date"]:
                payload["review_date"] = date.fromisoformat(payload["review_date"])
            payload["service"] = {"protocol": self.protocol.currentText(), "ports": ranges, "any_ports": ports == "*"}
            payload["requirement"] = self.action.currentData()
            row = MatrixRequirement.model_validate(payload).model_dump(mode="json")
        except (ValueError, TypeError):
            self.status.setText("Проверьте обязательные ID, область, дату и протокол/порты карточки.")
            return
        if self._selected is None:
            self._requirements.append(row)
        else:
            self._requirements[self._selected] = row
        self._refresh_rows()
        self._new_row()
        self.status.setText("Карточка применена к черновику. Для сохранения создайте новую версию.")

    def _remove_row(self) -> None:
        if self._selected is not None:
            self._requirements.pop(self._selected)
            self._refresh_rows()
            self._new_row()

    def _draft(self) -> AccessMatrix | None:
        try:
            return AccessMatrix.model_validate({
                "matrix_id": self._matrix_id, "version": self._version,
                "groups": self.groups.groups(), "requirements": self._requirements,
            })
        except (ValueError, TypeError):
            self.status.setText("Проверьте состав групп и структуру требований. Черновик не сохранён.")
            return None

    def _open_grid(self) -> None:
        from firewall_compliance.interfaces.desktop.qt_matrix_grid import MatrixGridDialog

        if self._closed or not self._context_valid():
            return
        matrix = self._draft()
        if matrix is None:
            return
        dialog = MatrixGridDialog(matrix, self, scope_id=self._scope_id)
        dialog.requirement_requested.connect(self._open_grid_requirement)
        dialog.exec()
        dialog.deleteLater()

    def _open_grid_requirement(self, index: int) -> None:
        if not self._closed and self._context_valid() and 0 <= index < len(self._requirements):
            self.table.selectRow(index)
            self._select_row()

    @staticmethod
    def _group_choice(selector: QComboBox) -> str:
        index = selector.currentIndex()
        if index >= 0 and selector.currentText() == selector.itemText(index):
            return str(selector.itemData(index))
        return selector.currentText().strip()

    @staticmethod
    def _set_group_choice(selector: QComboBox, identifier: str) -> None:
        index = selector.findData(identifier)
        selector.setCurrentIndex(index)
        if index < 0:
            selector.setEditText(identifier)

    def _refresh_group_choices(self) -> None:
        for selector in self.group_choices.values():
            previous = self._group_choice(selector)
            selector.blockSignals(True)
            selector.clear()
            for group in self.groups.groups():
                selector.addItem(f"{group.name} · {group.group_id}", group.group_id)
            self._set_group_choice(selector, previous)
            selector.blockSignals(False)

    def _validate(self) -> None:
        matrix = self._draft()
        if matrix is not None:
            def done(values: Any) -> None:
                self._artifact = None
                self.result_table.setRowCount(0)
                self._report_controls()
                self.result.setPlainText(
                    "\n".join(
                        f"{value.code}: {value.message}; группы {value.group_ids}; требования {value.requirement_ids}"
                        for value in values
                    ) or "Структурных противоречий не найдено. Это не результат сверки доступа."
                )

            self._job(lambda: matrix_diagnostics(matrix), done)

    def _save(self) -> None:
        matrix = self._draft()
        if matrix is None:
            return

        def work() -> tuple[MatrixVersionRecord, ...]:
            self._store.initialize()
            self._store.append(self._project_id, matrix)
            return self._store.list_versions(self._project_id)

        self._job(work, self._show_versions)

    def _evaluate(self) -> None:
        matrix = self._draft()
        revision = self._revision
        if matrix is None or revision is None:
            return
        selected = self.versions.currentIndex()
        if not 0 <= selected < len(self._versions) or matrix != self._versions[selected].matrix:
            self.status.setText("Сначала сохраните изменения новой версией матрицы, затем выполните сверку.")
            return
        matrix = self._versions[selected].matrix

        def work() -> tuple[MatrixAssessmentArtifact, tuple[MatrixAssessmentSummary, ...], int]:
            value = evaluate_access_matrix(
                matrix, revision, scope_id=self._scope_id,
                profile_id=self._profile_id, profile_version=self._profile_version,
            )
            artifact = MatrixAssessmentArtifact(
                origin_project_id=self._project_id, origin_run_id=self._origin_run_id,
                origin_item_id=self._origin_item_id,
                matrix=matrix, revision=revision, profile_settings_json=self._profile_settings_json,
                assessment=value,
            )
            self._store.initialize()
            identifier = self._store.save_assessment(artifact)
            return (
                self._store.get_assessment(self._project_id, identifier),
                self._store.list_assessments(self._project_id),
                self._store.assessment_count(self._project_id),
            )

        def done(value: Any) -> None:
            self._history_offset = 0
            self._show_artifact(value[0])
            self._show_assessments(value[1], value[2])

        self._job(work, done)
