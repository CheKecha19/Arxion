"""Редактор цепочки требований и разбор её участков по сохранённым сверкам."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from firewall_compliance.application.access_journey import JourneyAssessment, evaluate_journey, evaluate_scope_journey
from firewall_compliance.application.access_journey_observations import (
    JourneyObservationAssessment, evaluate_journey_observations, evaluate_scope_journey_observations,
)
from firewall_compliance.application.matrix_artifact import MatrixAssessmentArtifact
from firewall_compliance.application.matrix_reports import matrix_evidence_preview, matrix_packet_detail
from firewall_compliance.application.matrix_scope_assessment import MatrixScopeAssessment, matrix_scope_checksum
from firewall_compliance.domain.access_journey import AccessJourney, JourneyStep, validate_journey
from firewall_compliance.domain.access_journey_observations import JourneyObservationSnapshot
from firewall_compliance.domain.access_matrix import AccessMatrix
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.matrix_store import AccessMatrixStore, MatrixAssessmentSummary
from firewall_compliance.interfaces.desktop.qt_batch_report import write_report_file
from firewall_compliance.interfaces.desktop.qt_matrix_inputs import select_matrix_input
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable


class MatrixJourneyEditor(QDialog):
    def __init__(
        self, matrix: AccessMatrix, scope_id: str, current: AccessJourney | None, parent: QWidget,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Цепочка требований доступа")
        self.resize(860, 420)
        self.value: AccessJourney | None = None
        self._matrix = matrix
        self._scope = current.scope_id if current is not None else scope_id
        self._identifier = current.journey_id if current is not None else uuid4().hex
        self._steps = list(current.steps) if current is not None else []
        self._groups = {group.group_id: group.name for group in matrix.groups}
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self._name = QLineEdit(current.name if current is not None else "")
        form.addRow("Название", self._name)
        layout.addLayout(form)
        self._table = MatrixTable(("Участок", "Источник", "Назначение", "Требование"))
        self._table.setAccessibleName("Участки цепочки доступа по порядку")
        self._table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self._table, 1)
        layout.addLayout(self._table.navigation())
        actions = QHBoxLayout()
        for title, action in (
            ("Добавить требование…", self._add_requirement),
            ("Добавить участок без требования…", self._add_gap),
            ("Заменить требованием…", self._replace),
            ("Отметить пробел…", self._replace_with_gap), ("Убрать участок", self._remove),
        ):
            button = QPushButton(title)
            button.clicked.connect(action)
            actions.addWidget(button)
        layout.addLayout(actions)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._refresh()

    def _refresh(self) -> None:
        def values(index: int) -> tuple[str, str, str, str]:
            row = self._steps[index]
            return (
                row.name, self._groups.get(row.source_group, row.source_group),
                self._groups.get(row.destination_group, row.destination_group),
                row.requirement_id or "Нужно описать",
            )

        self._table.set_rows(range(len(self._steps)), values)

    def _add_requirement(self) -> None:
        self._pick_requirement(len(self._steps))

    def _replace(self) -> None:
        index = self._table.selected_index()
        if index is not None:
            self._pick_requirement(index)

    def _pick_requirement(self, position: int) -> None:
        source = self._steps[position - 1].destination_group if position else None
        destination = self._steps[position + 1].source_group if position + 1 < len(self._steps) else None
        rows = [
            row for row in self._matrix.requirements if row.scope_id == self._scope and row.requirement == "permit"
            and (source is None or source == row.source_group)
            and (destination is None or destination == row.destination_group)
        ]
        if not rows:
            QMessageBox.information(self, "Участок цепочки", "Нет обязательного требования с подходящими группами.")
            return
        choice = select_matrix_input(self, [
            f"{row.requirement_id} · {self._groups.get(row.source_group, row.source_group)} → "
            f"{self._groups.get(row.destination_group, row.destination_group)} · {row.service.protocol.upper()}"
            for row in rows
        ], title="Обязательное требование участка", placeholder="ID или имя группы")
        if choice is None:
            return
        row = rows[choice]
        step_id = self._steps[position].step_id if position < len(self._steps) else uuid4().hex
        step = JourneyStep(
            step_id=step_id, name=f"Требование {row.requirement_id}", source_group=row.source_group,
            destination_group=row.destination_group, requirement_id=row.requirement_id,
        )
        self._steps[position:position + 1] = [step]
        self._refresh()
        self._table.show_index(position)

    def _add_gap(self) -> None:
        self._put_gap(len(self._steps))

    def _replace_with_gap(self) -> None:
        index = self._table.selected_index()
        if index is not None:
            self._put_gap(index)

    def _put_gap(self, position: int) -> None:
        groups = tuple(self._groups)

        def choose(title: str) -> str | None:
            index = select_matrix_input(self, [f"{self._groups[key]} · {key}" for key in groups],
                                        title=title, placeholder="Имя или ID группы")
            return groups[index] if index is not None else None

        current = self._steps[position] if position < len(self._steps) else None
        source = self._steps[position - 1].destination_group if position else (
            current.source_group if current and current.source_group in self._groups else choose("Источник участка")
        )
        if source is None:
            return
        destination = self._steps[position + 1].source_group if position + 1 < len(self._steps) else (
            current.destination_group if current and current.destination_group in self._groups else choose("Назначение участка")
        )
        if destination is None:
            return
        name, accepted = QInputDialog.getText(self, "Участок без требования", "Какого взаимодействия не хватает?",
                                              text=current.name if current and current.requirement_id is None else "")
        if accepted and name.strip():
            try:
                step = JourneyStep(step_id=current.step_id if current else uuid4().hex, name=name.strip(),
                                   source_group=source, destination_group=destination)
            except ValueError:
                QMessageBox.warning(self, "Участок цепочки", "Проверьте длину названия участка.")
                return
            self._steps[position:position + 1] = [step]
            self._refresh()
            self._table.show_index(position)

    def _remove(self) -> None:
        index = self._table.selected_index()
        if index is not None:
            del self._steps[index]
            self._refresh()

    def _save(self) -> None:
        try:
            value = AccessJourney(
                journey_id=self._identifier, name=self._name.text().strip(), scope_id=self._scope,
                steps=tuple(self._steps),
            )
            validate_journey(self._matrix, value)
        except ValueError:
            QMessageBox.warning(self, "Цепочка доступа", "Укажите название и проверьте, что участки последовательно соединены.")
            return
        self.value = value
        self.accept()


class MatrixJourneyReview(QDialog):
    def __init__(
        self, store: AccessMatrixStore, runner: JobRunner, project_id: str, matrix: AccessMatrix,
        journey: AccessJourney, summaries: tuple[MatrixAssessmentSummary, ...],
        current: MatrixAssessmentArtifact | None, context_valid: Callable[[], bool], parent: QWidget,
        *, scope_result: MatrixScopeAssessment | None = None, scope_artifact_id: UUID | None = None,
        scope_revision: Callable[[UUID], DeviceRevision] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Доказательства по участкам цепочки")
        self.resize(940, 630)
        self._store, self._runner, self._project_id = store, runner, project_id
        self._matrix, self._journey = matrix, journey
        self._summaries = {item.artifact_id: item for item in summaries}
        self._choices: dict[str, str] = {}
        self._valid = context_valid
        self._current = current
        self._scope_result, self._scope_artifact_id = scope_result, scope_artifact_id
        self._scope_revision = scope_revision
        self._group_names = {group.group_id: group.name for group in matrix.groups}
        self._result: JourneyAssessment | None = None
        self._observations: JourneyObservationAssessment | None = None
        self._observation_indices: dict[str, list[int]] = {}
        self._closed = False
        self._busy = False
        self.finished.connect(self._finish)
        layout = QVBoxLayout(self)
        title_text = f"{journey.name} · Матрица v{matrix.version}"
        if scope_result is not None:
            title_text += f" · сверка области от {scope_result.created_at.isoformat(timespec='minutes')}"
        title = QLabel(title_text)
        title.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(title)
        self._table = MatrixTable(("Участок", "Сохранённая сверка", "Наблюдения", "Основание"))
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.itemSelectionChanged.connect(self._show_step)
        layout.addWidget(self._table, 1)
        layout.addLayout(self._table.navigation())
        actions = QHBoxLayout()
        self._pick_button = QPushButton("Выбрать сверку участка…")
        self._pick_button.clicked.connect(self._pick)
        self._clear_button = QPushButton("Убрать сверку участка")
        self._clear_button.clicked.connect(self._clear)
        self._export_button = QPushButton("Экспорт JSON…")
        self._export_button.clicked.connect(self._export)
        for button in (self._pick_button, self._clear_button):
            if scope_result is None:
                actions.addWidget(button)
            else:
                button.hide()
        actions.addWidget(self._export_button)
        layout.addLayout(actions)
        observation_actions = QHBoxLayout()
        self._observation_button = QPushButton("Загрузить наблюдения JSON…")
        self._observation_button.clicked.connect(self._open_observations)
        self._template_button = QPushButton("Сохранить шаблон JSON…")
        self._template_button.clicked.connect(self._save_observation_template)
        self._clear_observation_button = QPushButton("Убрать наблюдения")
        self._clear_observation_button.clicked.connect(lambda: self._update(clear_observations=True))
        self._transactions_button = QPushButton("Транзакции…")
        self._transactions_button.clicked.connect(self._show_transactions)
        for button in (self._observation_button, self._template_button, self._clear_observation_button,
                       self._transactions_button):
            observation_actions.addWidget(button)
        observation_actions.addStretch()
        layout.addLayout(observation_actions)
        self._details = QPlainTextEdit()
        self._details.setReadOnly(True)
        layout.addWidget(self._details, 1)
        self._status = QLabel()
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        if scope_result is None and current is not None and current.matrix == matrix and current.assessment.scope_id == journey.scope_id:
            found = {row.requirement_id for row in current.assessment.requirements if row.mode is not None}
            self._choices.update((step.step_id, str(current.artifact_id)) for step in journey.steps
                                 if step.requirement_id in found)
        self._update()

    def _finish(self, _result: int) -> None:
        self._closed = True

    def _refresh(self) -> None:
        selected = self._table.selected_index()

        def values(index: int) -> tuple[str, str, str, str]:
            step = self._journey.steps[index]
            summary = self._summaries.get(self._choices.get(step.step_id, ""))
            result = self._result.steps[index] if self._result is not None else None
            outcome = result.message if result is not None else "Ожидает разбора"
            source = f"{summary.device_label} · {summary.created_at}" if summary else "—"
            if self._scope_result is not None and result is not None and result.device_label:
                source = result.device_label
                if result.source_captured_at is not None:
                    source += f" · {result.source_captured_at.isoformat(timespec='minutes')}"
            observed = self._observation_indices.get(step.step_id, ())
            return step.name, source, str(len(observed)) if observed else "—", outcome

        self._table.set_rows(range(len(self._journey.steps)), values)
        self._table.show_index(selected if selected is not None else 0)

    def _show_step(self) -> None:
        index = self._table.selected_index()
        step = self._journey.steps[index] if index is not None else None
        self._pick_button.setEnabled(not self._busy and step is not None and step.requirement_id is not None
                                     and self._scope_result is None and bool(self._summaries))
        self._clear_button.setEnabled(not self._busy and step is not None and self._scope_result is None
                                      and step.step_id in self._choices)
        self._export_button.setEnabled(not self._busy and self._result is not None)
        self._observation_button.setEnabled(not self._busy and (self._scope_result is None or self._scope_revision is not None))
        self._template_button.setEnabled(not self._busy)
        self._clear_observation_button.setEnabled(not self._busy and self._observations is not None)
        self._transactions_button.setEnabled(not self._busy and self._observations is not None
                                             and bool(self._observations.transactions))
        if self._result is None:
            self._details.clear()
            return
        if index is None:
            self._details.setPlainText("\n".join(self._result.limitations))
            return
        outcome = self._result.steps[index]
        current_step = self._journey.steps[index]
        source = self._group_names.get(current_step.source_group, current_step.source_group)
        destination = self._group_names.get(current_step.destination_group, current_step.destination_group)
        details = [f"{source} → {destination}", outcome.message, f"ID участка · {current_step.step_id}"]
        if outcome.revision_id is not None:
            details.append(f"Ревизия политики · {outcome.revision_id}")
        if outcome.assessment is not None:
            details.extend(reason for reason in outcome.assessment.reasons if reason != outcome.message)
            preview = matrix_evidence_preview(outcome.assessment.evidence)
            for evidence in preview:
                details.extend((evidence.summary, ", ".join(evidence.related_rule_ids)))
                if detail := matrix_packet_detail(evidence):
                    details.append(detail)
                details.extend(
                    f"{anchor.source_name} · {anchor.object_path or anchor.line_start or anchor.object_id}"
                    for anchor in evidence.source_locations
                )
            if len(preview) < len(outcome.assessment.evidence):
                details.append("Все основания доступны в JSON.")
        observation_report = self._observations
        if observation_report is not None:
            indices = self._observation_indices.get(outcome.step_id, [])
            details.append("")
            details.append(f"Записей наблюдения по участку · {len(indices)}")
            for position in indices[:12]:
                finding = observation_report.observations[position]
                sample = observation_report.snapshot.observations[finding.observation_index]
                details.extend((
                    f"{sample.source_ip} → {sample.destination_ip} · {sample.protocol.upper()}"
                    + (f"/{sample.destination_port}" if sample.destination_port is not None else ""),
                    finding.message,
                    f"{sample.origin.source_name} · {sample.origin.record_id} · {sample.origin.observed_at.isoformat()}",
                ))
                if sample.zone_pair is not None:
                    details.append(f"Зоны · {sample.zone_pair.source_zone} → {sample.zone_pair.destination_zone}")
            if len(indices) > 12:
                details.append("Все записи доступны в JSON.")
        self._details.setPlainText("\n".join(line for line in details if line))

    def _pick(self) -> None:
        index = self._table.selected_index()
        if index is None:
            return
        step = self._journey.steps[index]
        candidates = tuple(self._summaries.values())
        choice = select_matrix_input(self, [
            f"{item.device_label} · {item.created_at} · {item.artifact_id}" for item in candidates
        ], title="Сохранённая сверка участка", placeholder="Устройство, время или ID сверки")
        if choice is not None:
            self._choices[step.step_id] = candidates[choice].artifact_id
            self._update()

    def _clear(self) -> None:
        index = self._table.selected_index()
        if index is not None:
            self._choices.pop(self._journey.steps[index].step_id, None)
            self._update()

    def _open_observations(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Наблюдения по цепочке", "", "JSON (*.json)")
        if filename:
            self._update(observation_path=Path(filename))

    def _save_observation_template(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(self, "Сохранить шаблон наблюдений", "journey-observations.json", "JSON (*.json)")
        if not filename:
            return
        def work() -> None:
            template = JourneyObservationSnapshot(
                project_id=self._project_id, scope_id=self._journey.scope_id, matrix_id=self._matrix.matrix_id,
                matrix_version=self._matrix.version, matrix_checksum=matrix_scope_checksum(self._matrix),
                journey_id=self._journey.journey_id, captured_at=datetime.now(UTC), observations=(),
            )
            write_report_file(Path(filename), template.model_dump_json(indent=2))

        self._write_in_background(work, "Сохраняем шаблон…", "Шаблон наблюдений сохранён.")

    def _update(self, *, observation_path: Path | None = None, clear_observations: bool = False) -> None:
        previous_config = self._result
        previous_observations = self._observations
        snapshot = previous_observations.snapshot if previous_observations is not None and not clear_observations else None
        self._busy = True
        self._result = None
        self._observations = None
        self._observation_indices = {}
        self._status.setText("Читаем сохранённые доказательства…")
        self._refresh()
        choices = self._choices.copy()

        def work() -> JourneyAssessment | JourneyObservationAssessment:
            observed = (JourneyObservationSnapshot.model_validate_json(observation_path.read_bytes())
                        if observation_path is not None else snapshot)
            if self._scope_result is not None:
                if observed is not None and self._scope_revision is not None:
                    return evaluate_scope_journey_observations(
                        self._matrix, self._journey, self._scope_result, observed, project_id=self._project_id,
                        artifact_id=self._scope_artifact_id, load_revision=self._scope_revision,
                    )
                return evaluate_scope_journey(
                    self._matrix, self._journey, self._scope_result,
                    project_id=self._project_id, artifact_id=self._scope_artifact_id,
                )
            artifacts = {}
            for identifier in set(choices.values()):
                artifacts[identifier] = self._current if self._current and str(self._current.artifact_id) == identifier else (
                    self._store.get_assessment(self._project_id, identifier)
                )
            assessments = {key: artifacts[value] for key, value in choices.items()}
            if observed is not None:
                return evaluate_journey_observations(self._matrix, self._journey, assessments, observed,
                                                    project_id=self._project_id)
            return evaluate_journey(self._matrix, self._journey, assessments, project_id=self._project_id)

        def done(value: object) -> None:
            if self._closed:
                return
            if not self._valid():
                self.reject()
                return
            self._busy = False
            if isinstance(value, JourneyObservationAssessment):
                self._result = value.configuration
                self._show_observations(value)
            elif isinstance(value, JourneyAssessment):
                self._result = value
                self._status.setText("Результаты показывают доказательства каждого участка.")
            elif isinstance(value, JobError):
                if observation_path is not None:
                    self._result = previous_config
                    if previous_observations is not None:
                        self._show_observations(previous_observations)
                self._status.setText(value.message)
            self._refresh()

        self._runner.submit(work, done)

    def _show_observations(self, value: JourneyObservationAssessment) -> None:
        self._observations = value
        indices: dict[str, list[int]] = defaultdict(list)
        for index, sample in enumerate(value.observations):
            indices[sample.step_id].append(index)
        self._observation_indices = dict(indices)
        counts = Counter(sample.disposition for sample in value.observations)
        complete = sum(row.disposition == "observed_completed" for row in value.transactions)
        self._status.setText(
            f"Записей {len(value.observations)} · установлений и ответов {counts['observed_success']} · "
            f"явных отказов {counts['observed_denial']}"
            + (f" · подтверждённых записанных транзакций {complete} из {len(value.transactions)}" if value.transactions else "")
            + ". Результаты относятся к указанным попыткам."
        )

    def _show_transactions(self) -> None:
        result = self._observations
        if result is None or not result.transactions:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Записанные транзакции цепочки")
        dialog.resize(920, 540)
        layout = QVBoxLayout(dialog)
        table = MatrixTable(("ID транзакции", "Результат", "Источник записи"))
        table.horizontalHeader().setStretchLastSection(True)
        details = QPlainTextEdit()
        details.setReadOnly(True)

        def values(index: int) -> tuple[str, str, str]:
            row = result.transactions[index]
            sample = result.snapshot.transactions[row.transaction_index]
            status = "Завершение подтверждено записью" if row.disposition == "observed_completed" else "Недостаточно сведений"
            return row.trace_id, status, sample.origin.source_name

        def show() -> None:
            index = table.selected_index()
            if index is None:
                details.clear()
                return
            row = result.transactions[index]
            sample = result.snapshot.transactions[row.transaction_index]
            details.setPlainText("\n".join((
                row.message, f"Период · {sample.started_at.isoformat()} — {sample.completed_at.isoformat()}",
                f"Запись · {sample.origin.source_name} · {sample.origin.record_id}",
                f"Связанных попыток · {len(row.observation_indices)}",
            )))

        table.itemSelectionChanged.connect(show)
        table.set_rows(range(len(result.transactions)), values)
        table.show_index(0)
        layout.addWidget(table, 1)
        layout.addLayout(table.navigation())
        layout.addWidget(details, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()
        dialog.deleteLater()

    def _export(self) -> None:
        result = self._observations or self._result
        if result is None:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Экспорт разбора цепочки", "access-journey.json", "JSON (*.json)")
        if not filename:
            return
        self._write_in_background(lambda: write_report_file(Path(filename), result.model_dump_json(indent=2)),
                                  "Сохраняем разбор цепочки…", "Разбор сохранён.")

    def _write_in_background(self, work: Callable[[], None], pending: str, success: str) -> None:
        self._busy = True
        self._show_step()
        self._status.setText(pending)

        def done(value: object) -> None:
            if self._closed:
                return
            self._busy = False
            self._show_step()
            self._status.setText(value.message if isinstance(value, JobError) else success)

        self._runner.submit(work, done)
