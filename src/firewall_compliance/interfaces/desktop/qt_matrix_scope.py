"""Сверка утверждённой матрицы по текущему или историческому срезу области."""

from __future__ import annotations

import sqlite3
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Lock
from typing import cast
from uuid import UUID

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QVBoxLayout, QWidget,
)

from firewall_compliance.application.access_context import assigned_session_context, matrix_session_search
from firewall_compliance.application.matrix_catalog_bindings import split_catalog_bindings
from firewall_compliance.application.matrix_comparison import compare_matrix_scope_assessments
from firewall_compliance.application.matrix_policy import matrix_catalog_switch_policy_contexts
from firewall_compliance.application.matrix_reports import (
    MATRIX_STATE_LABELS, matrix_evidence_preview, matrix_packet_detail, matrix_scope_comparison_html, matrix_scope_report_csv,
    matrix_scope_source_notes, matrix_service_label,
)
from firewall_compliance.application.matrix_scope_assessment import (
    HISTORICAL_BASELINE_NOTE, SOURCE_FALLBACK_NOTE,
    MatrixScopeAssessment, MatrixScopeEvaluationCache, MatrixScopeInput, MatrixScopeRowAssessment,
    MatrixScopeSource, MatrixScopeTarget,
    evaluate_matrix_scope, matrix_scope_checksum, verify_scope_rows,
)
from firewall_compliance.application.matrix_scope_cloud import (
    matrix_scope_cloud_inputs, matrix_scope_cloud_policy_ids, matrix_scope_vmware_inputs,
    matrix_scope_vmware_policy_ids, matrix_scope_vmware_replacing_scan_id,
)
from firewall_compliance.application.workspace_profile import ProfileVersion, analysis_settings
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixDiagnostic, MatrixRequirementAssessment
from firewall_compliance.domain.matrix_context_inputs import MatrixContextInputs
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.matrix_catalog import (
    MatrixCatalog, matrix_catalog_accepts_source, matrix_cloud_catalog_sites, matrix_revision_catalog_sites,
)
from firewall_compliance.interfaces.desktop.matrix_scope_findings import (
    MatrixFindingSources, load_matrix_finding_rows, matrix_finding_sources,
)
from firewall_compliance.interfaces.desktop.matrix_scope_portable import decode_scope_result, encode_scope_result
from firewall_compliance.interfaces.desktop.matrix_scope_store import MatrixScopeStore, MatrixScopeSummary
from firewall_compliance.interfaces.desktop.matrix_store import AccessMatrixStore, MatrixVersionSummary
from firewall_compliance.interfaces.desktop.project_store import MatrixBaselineRun, ProjectStore
from firewall_compliance.interfaces.desktop.qt_batch_report import write_report_file
from firewall_compliance.interfaces.desktop.qt_matrix_boundary_review import (
    BoundaryGroupView, MatrixBoundaryReview, prepare_boundary_review,
)
from firewall_compliance.interfaces.desktop.qt_matrix_comparison import (
    MatrixScopeComparisonDialog, MatrixScopeComparisonView, prepare_matrix_scope_comparison,
)
from firewall_compliance.interfaces.desktop.qt_matrix_comparison_findings import (
    MatrixFindingComparisonRow, prepare_matrix_finding_rows,
)
from firewall_compliance.interfaces.desktop.qt_matrix_context import MatrixContextInputsDialog
from firewall_compliance.interfaces.desktop.qt_matrix_inputs import edit_matrix_source_binding, select_matrix_input
from firewall_compliance.interfaces.desktop.qt_matrix_journey import MatrixJourneyReview
from firewall_compliance.interfaces.desktop.qt_matrix_path import MatrixPathDialog, matrix_path_prefill
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable


_ATTENTION_STATES = frozenset({
    "excess_allow", "declared_conflict", "requirement_conflict", "partial_match", "insufficient_evidence",
})
_SWITCH_PATH_PLATFORMS = frozenset({"aos-cx", "aos-switch", "comware"})
_BASELINE_STATES = {
    "completed": "завершён", "interrupted": "прерван", "cancelled": "отменён",
}
type _PreparedComparison = tuple[
    MatrixScopeAssessment, MatrixScopeAssessment, MatrixScopeComparisonView, AccessMatrix | None, MatrixFindingSources,
]


def _comparison_time(result: MatrixScopeAssessment) -> datetime:
    for issue in result.diagnostics:
        if issue.code == HISTORICAL_BASELINE_NOTE:
            parts = issue.message.split(" · ", maxsplit=3)
            if len(parts) >= 2:
                try:
                    cutoff = datetime.fromisoformat(parts[1].removeprefix("файловый запуск "))
                except ValueError:
                    break
                if cutoff.tzinfo is not None:
                    return cutoff
    return result.created_at


def _needs_attention(assessment: MatrixRequirementAssessment) -> bool:
    return assessment.state in _ATTENTION_STATES or assessment.attachment_limited


def _matches_state(assessment: MatrixRequirementAssessment, state: str | None) -> bool:
    if state == "attention":
        return _needs_attention(assessment)
    return state is None or assessment.state == state


@dataclass(frozen=True, slots=True)
class _ScopeView:
    result: MatrixScopeAssessment
    search: tuple[str, ...]
    matrix: AccessMatrix | None
    group_names: dict[str, str]
    group_search: dict[str, str]
    services: dict[tuple[str, str], str]
    artifact_id: str | None = None
    history_warning: str = ""
    boundary_groups: tuple[BoundaryGroupView, ...] = ()
    local_matrix: bool = True
    calculated_here: bool = False
    baseline_run_id: str | None = None


class MatrixScopeDialog(QDialog):
    def __init__(
        self, store: ProjectStore, runner: JobRunner, project_id: str, site_id: str | None,
        scope_label: str, context_valid: Callable[[], bool], parent: QWidget,
        *, evaluation_cache: MatrixScopeEvaluationCache | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Сверка политик области")
        self.resize(1080, 700)
        self._store, self._runner, self._project = store, runner, project_id
        self._site = site_id
        self._scope = site_id or project_id
        self._matrix_store = AccessMatrixStore(store.path)
        self._history_store = MatrixScopeStore(store.path)
        self._evaluation_cache = evaluation_cache or MatrixScopeEvaluationCache()
        self._valid = context_valid
        self._closed = False
        self._busy = False
        self._cancel: Event | None = None
        self._result: MatrixScopeAssessment | None = None
        self._result_is_historical = False
        self._result_baseline_run_id: str | None = None
        self._artifact_id: str | None = None
        self._history_rows: tuple[MatrixScopeSummary, ...] = ()
        self._source_by_revision: dict[UUID, MatrixScopeSource] = {}
        self._switch_sources: dict[UUID, MatrixScopeSource] = {}
        self._path_source_choices: tuple[MatrixScopeSource, ...] = ()
        self._notes_by_requirement: dict[str, tuple[str, ...]] = {}
        self._matrix: AccessMatrix | None = None
        self._local_matrix = False
        self._baseline_runs: tuple[MatrixBaselineRun, ...] = ()
        self._baseline: MatrixBaselineRun | None = None
        self._targets: dict[tuple[str, str | None], dict[str, MatrixScopeTarget]] = {}
        self._view_targets: dict[str, MatrixScopeTarget] | None = None
        self._context_by_version: dict[str, MatrixContextInputs] = {}
        self._search: tuple[str, ...] = ()
        self._group_names: dict[str, str] = {}
        self._group_search: dict[str, str] = {}
        self._services: dict[tuple[str, str], str] = {}
        self._boundary_groups: tuple[BoundaryGroupView, ...] = ()
        self._progress_value = (0, 0)
        self._progress_lock = Lock()
        self.finished.connect(self._finish)

        layout = QVBoxLayout(self)
        title = QLabel(scope_label)
        title.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(title)
        actions = QHBoxLayout()
        self._versions = QComboBox()
        self._versions.setAccessibleName("Версия матрицы для сверки области")
        self._versions.currentIndexChanged.connect(self._controls)
        actions.addWidget(self._versions, 1)
        self._run_button = QPushButton("Сверить последние снимки")
        self._run_button.setToolTip("Подобрать сохранённые конфигурации и облачные политики для утверждённых требований")
        self._run_button.clicked.connect(lambda: self._run())
        self._baseline_button = QPushButton("Срез: последние снимки…")
        self._baseline_button.setAccessibleName("Выбрать исторический срез сохранённых политик")
        self._baseline_button.setToolTip("Выбрать момент по сохранённому файловому запуску")
        self._baseline_button.clicked.connect(self._choose_baseline)
        self._context_button = QPushButton("Сеансы…")
        self._context_button.setToolTip("Свидетельства членства, устройства и адреса сеанса офиса или VPN")
        self._context_button.clicked.connect(self._edit_context_inputs)
        self._open_button = QPushButton("Открыть результат JSON…")
        self._open_button.clicked.connect(self._open)
        self._export_button = QPushButton("Сохранить результат JSON…")
        self._export_button.clicked.connect(self._export)
        self._cancel_button = QPushButton("Остановить")
        self._cancel_button.clicked.connect(self._cancel_run)
        for button in (self._baseline_button, self._context_button, self._run_button, self._cancel_button):
            actions.addWidget(button)
        layout.addLayout(actions)
        history = QHBoxLayout()
        self._history = QComboBox()
        self._history.setAccessibleName("Сохранённые сверки области")
        self._history.currentIndexChanged.connect(self._controls)
        history.addWidget(self._history, 1)
        self._restore_button = QPushButton("Открыть из истории")
        self._restore_button.clicked.connect(self._restore)
        self._compare_button = QPushButton("Сравнить с открытой")
        self._compare_button.setToolTip("Сравнить выбранную запись истории с открытой сверкой той же версии матрицы")
        self._compare_button.clicked.connect(self._compare)
        self._journey_button = QPushButton("Цепочки доступа…")
        self._journey_button.setToolTip("Показать участки цепочки по результатам открытой сверки")
        self._journey_button.clicked.connect(self._open_journey)
        self._boundary_groups_button = QPushButton("Закрытые области…")
        self._boundary_groups_button.setToolTip("Сводка результатов по точкам контроля закрытых областей")
        self._boundary_groups_button.clicked.connect(self._open_boundary_groups)
        for button in (
            self._restore_button, self._compare_button, self._boundary_groups_button,
            self._journey_button, self._open_button, self._export_button,
        ):
            history.addWidget(button)
        layout.addLayout(history)
        self._status = QLabel()
        self._status.setWordWrap(True)
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._status)
        self._progress = QProgressBar()
        self._progress.hide()
        layout.addWidget(self._progress)
        self._progress_timer = QTimer(self)
        self._progress_timer.setInterval(120)
        self._progress_timer.timeout.connect(self._update_progress)

        filters = QHBoxLayout()
        self._query = QLineEdit()
        self._query.setPlaceholderText("Требование, группа, политика или сеанс")
        self._query.setAccessibleName("Поиск по результатам всей области")
        self._source_query = QLineEdit()
        self._source_query.setPlaceholderText("Откуда · группа")
        self._source_query.setAccessibleName("Фильтр по группе источника")
        self._source_query.setToolTip("Имя или ID группы, откуда начинается доступ.")
        self._destination_query = QLineEdit()
        self._destination_query.setPlaceholderText("Куда · группа")
        self._destination_query.setAccessibleName("Фильтр по группе назначения")
        self._destination_query.setToolTip("Имя или ID группы, к которой проверяется доступ.")
        self._query_timer = QTimer(self)
        self._query_timer.setSingleShot(True)
        self._query_timer.setInterval(150)
        self._query_timer.timeout.connect(self._refresh)
        for field in (self._query, self._source_query, self._destination_query):
            field.setClearButtonEnabled(True)
            field.textChanged.connect(lambda _text: self._query_timer.start())
            field.returnPressed.connect(self._refresh)
            filters.addWidget(field, 2 if field is self._query else 1)
        self._state = QComboBox()
        self._state.addItem("Все результаты", None)
        self._state.addItem("Требуют внимания", "attention")
        for state, label in MATRIX_STATE_LABELS.items():
            self._state.addItem(label, state)
        self._state.currentIndexChanged.connect(self._refresh)
        filters.addWidget(self._state)
        self._export_selection_button = QPushButton("CSV выборки…")
        self._export_selection_button.clicked.connect(self._export_selection)
        filters.addWidget(self._export_selection_button)
        layout.addLayout(filters)

        selection = QHBoxLayout()
        self._choose_button = QPushButton("Выбрать устройство для требования…")
        self._choose_button.clicked.connect(self._choose_target)
        self._clear_button = QPushButton("Снять выбор")
        self._clear_button.clicked.connect(self._clear_target)
        self._bulk_targets = QCheckBox("Для всех неоднозначных строк этой политики")
        for widget in (self._choose_button, self._clear_button, self._bulk_targets):
            selection.addWidget(widget)
        selection.addStretch()
        layout.addLayout(selection)

        split = QSplitter(Qt.Orientation.Horizontal)
        result_page = QWidget()
        result_layout = QVBoxLayout(result_page)
        self._table = MatrixTable(("Источник → назначение", "Сервис", "Результат"))
        self._table.horizontalHeader().setStretchLastSection(True)
        result_layout.addWidget(self._table, 1)
        result_layout.addLayout(self._table.navigation())
        split.addWidget(result_page)
        detail_page = QWidget()
        detail_layout = QVBoxLayout(detail_page)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setAccessibleName("Источники и доказательства выбранного требования")
        detail_layout.addWidget(self._text, 1)
        self._path_button = QPushButton("Разобрать путь…")
        self._path_button.setToolTip("Разбор настроенного пути по сохранённой ревизии коммутатора")
        self._path_button.clicked.connect(self._open_path)
        self._bind_addresses_button = QPushButton("Подтвердить адреса ресурса…")
        self._bind_addresses_button.setToolTip("Использовать подтверждённые адреса только для этого источника сверки")
        self._bind_addresses_button.clicked.connect(self._edit_source_addresses)
        detail_actions = QHBoxLayout()
        detail_actions.addStretch()
        detail_actions.addWidget(self._bind_addresses_button)
        detail_actions.addWidget(self._path_button)
        detail_layout.addLayout(detail_actions)
        split.addWidget(detail_page)
        self._table.itemSelectionChanged.connect(self._details)
        split.setStretchFactor(0, 2)
        layout.addWidget(split, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._submit(
            lambda: (self._matrix_store.list_version_summaries(project_id),
                     self._history_store.list_summaries(project_id, selected_site_id=self._site),
                     self._store.matrix_baseline_runs(project_id)),
            self._show_initial,
            "Читаем утверждённые версии матрицы…",
        )

    def _finish(self, _result: int) -> None:
        self._closed = True
        self._progress_timer.stop()
        if self._cancel is not None:
            self._cancel.set()

    def _controls(self, *_: object) -> None:
        version = self._versions.currentData()
        context = self._context_by_version.get(version) if isinstance(version, str) else None
        self._versions.setEnabled(not self._busy)
        self._run_button.setEnabled(not self._busy and isinstance(version, str))
        self._baseline_button.setEnabled(not self._busy and bool(self._baseline_runs))
        self._context_button.setEnabled(not self._busy and isinstance(version, str))
        self._context_button.setText(f"Сеансы ({len(context.sessions)})…" if context else "Сеансы…")
        self._open_button.setEnabled(not self._busy)
        self._export_button.setEnabled(not self._busy and self._result is not None)
        self._export_selection_button.setEnabled(not self._busy and self._result is not None)
        history_id = self._history.currentData()
        self._history.setEnabled(not self._busy)
        self._restore_button.setEnabled(not self._busy and isinstance(history_id, str))
        self._compare_button.setEnabled(not self._busy and self._result is not None and isinstance(history_id, str)
                                        and history_id != self._artifact_id)
        self._journey_button.setEnabled(bool(
            not self._busy and self._result is not None and self._matrix is not None
            and any(journey.scope_id == self._scope for journey in self._matrix.journeys)
        ))
        self._boundary_groups_button.setVisible(bool(self._boundary_groups))
        self._boundary_groups_button.setEnabled(not self._busy and bool(self._boundary_groups))
        self._cancel_button.setVisible(self._cancel is not None)
        self._cancel_button.setEnabled(self._cancel is not None and not self._cancel.is_set())
        self._selection_controls()

    def _selection_controls(self) -> None:
        result = self._result
        index = self._table.selected_index()
        row = (result.requirements[index] if result is not None and index is not None
               and 0 <= index < len(result.requirements) else None)
        self._path_button.setEnabled(bool(
            not self._busy and self._matrix is not None and result is not None and row is not None
            and self._path_sources(result, row)
        ))
        source = self._source_by_revision.get(row.revision_id) if row is not None and row.revision_id else None
        self._bind_addresses_button.setVisible(bool(
            self._local_matrix and result is not None and source is not None
            and self._baseline is None and not self._result_is_historical
            and self._versions.currentData() == result.matrix_version
            and (
                source.platform in _SWITCH_PATH_PLATFORMS
                or source.platform.startswith(("ugos-", "ideco-classic-", "cloud-ru-"))
            )
        ))
        self._bind_addresses_button.setEnabled(not self._busy)
        if (result is None or row is None or not self._local_matrix or self._busy
                or self._versions.currentData() != result.matrix_version or not self._result_matches_cut()):
            self._choose_button.setEnabled(False)
            self._clear_button.setEnabled(False)
            self._bulk_targets.setEnabled(False)
            return
        candidates = result.candidate_revisions(row)
        self._choose_button.setEnabled(bool(candidates))
        self._bulk_targets.setEnabled(bool(candidates))
        self._clear_button.setEnabled(row.requirement_id in self._result_targets(result))

    def _result_matches_cut(self) -> bool:
        if self._baseline is None:
            return not self._result_is_historical
        return self._result_baseline_run_id == self._baseline.run_id

    def _result_targets(self, result: MatrixScopeAssessment) -> dict[str, MatrixScopeTarget]:
        return self._view_targets if self._view_targets is not None else result.targets_by_requirement

    def _editable_targets(self, result: MatrixScopeAssessment) -> dict[str, MatrixScopeTarget]:
        if self._view_targets is None:
            self._view_targets = dict(result.targets_by_requirement)
            self._targets[result.matrix_version, self._result_baseline_run_id] = self._view_targets
        return self._view_targets

    def _submit[T](self, work: Callable[[], T], done: Callable[[T], None], status: str) -> None:
        self._busy = True
        self._status.setText(status)
        self._controls()

        def completed(value: object) -> None:
            if self._closed:
                return
            if not self._valid():
                self.reject()
                return
            self._busy = False
            self._cancel = None
            self._progress_timer.stop()
            self._progress.hide()
            self._controls()
            if isinstance(value, JobError):
                self._status.setText(value.message)
            else:
                done(cast(T, value))

        self._runner.submit(work, completed)

    def _show_versions(self, values: tuple[MatrixVersionSummary, ...]) -> None:
        self._versions.blockSignals(True)
        for value in reversed(values):
            self._versions.addItem(f"Матрица v{value.version} · {value.created_at}", value.version)
        self._versions.blockSignals(False)
        self._status.setText(
            "Выберите версию и запустите сверку политик выбранной области."
            if values else "Сначала утвердите матрицу требований в редакторе."
        )
        self._controls()

    def _show_initial(self, value: tuple[
        tuple[MatrixVersionSummary, ...], tuple[MatrixScopeSummary, ...], tuple[MatrixBaselineRun, ...],
    ]) -> None:
        versions, history, self._baseline_runs = value
        self._show_versions(versions)
        self._show_history(history)

    def _choose_baseline(self) -> None:
        choices = ["Последние доступные снимки выбранной области"]
        choices.extend(
            f"{run.created_at} · {_BASELINE_STATES.get(run.state, run.state)} · {run.run_id}"
            for run in self._baseline_runs
        )
        selected = select_matrix_input(
            self, choices, title="Срез сохранённых политик",
            placeholder="Поиск по времени, состоянию или ID файлового запуска",
        )
        if selected is None:
            return
        self._baseline = self._baseline_runs[selected - 1] if selected else None
        self._baseline_button.setText(
            f"Срез: {self._baseline.created_at[:10]}…" if self._baseline else "Срез: последние снимки…"
        )
        self._baseline_button.setToolTip(
            f"{self._baseline.created_at} · {self._baseline.run_id}" if self._baseline
            else "Выбрать момент по сохранённому файловому запуску"
        )
        self._run_button.setText("Сверить выбранный срез" if self._baseline else "Сверить последние снимки")
        self._details()

    def _show_history(self, rows: tuple[MatrixScopeSummary, ...]) -> None:
        self._history_rows = rows
        previous = self._history.currentData()
        self._history.blockSignals(True)
        self._history.clear()
        for row in rows:
            status = {"complete": "завершена", "partial": "частичная", "cancelled": "остановлена"}.get(row.status, row.status)
            self._history.addItem(f"{row.created_at} · v{row.matrix_version} · {status}", row.artifact_id)
        if previous is not None and (index := self._history.findData(previous)) >= 0:
            self._history.setCurrentIndex(index)
        self._history.blockSignals(False)
        self._controls()

    def _select_previous_comparison(self, result: MatrixScopeAssessment) -> None:
        timestamp = result.created_at.astimezone(UTC).isoformat()
        previous = next(
            (
                row.artifact_id for row in self._history_rows
                if row.artifact_id != self._artifact_id and row.matrix_version == result.matrix_version
                and row.status != "cancelled" and row.created_at < timestamp
            ),
            None,
        )
        if previous is not None:
            self._history.setCurrentIndex(self._history.findData(previous))

    def _cancel_run(self) -> None:
        if self._cancel is not None:
            self._cancel.set()
            self._cancel_button.setEnabled(False)
            self._status.setText("Останавливаем сверку…")

    def _record_progress(self, completed: int, total: int) -> None:
        with self._progress_lock:
            self._progress_value = completed, total

    def _update_progress(self) -> None:
        with self._progress_lock:
            completed, total = self._progress_value
        if total > 0:
            self._progress.setRange(0, total)
            self._progress.setValue(completed)

    def _edit_context_inputs(self) -> None:
        version = self._versions.currentData()
        if self._busy or not isinstance(version, str):
            return
        old_status = self._status.text()

        def done(matrix: AccessMatrix) -> None:
            if not any(row.scope_id == self._scope and row.access_context is not None for row in matrix.requirements):
                self._status.setText("В этой версии нет требований к сеансам для выбранной области.")
                return
            dialog = MatrixContextInputsDialog(
                matrix, self._project, self._scope, self._context_by_version.get(version), self._runner, self,
            )
            if dialog.exec() == QDialog.DialogCode.Accepted:
                if dialog.inputs is not None:
                    self._context_by_version[version] = dialog.inputs
                    self._status.setText(
                        f"Контекстов: {len(dialog.inputs.contexts)} · назначений: {len(dialog.inputs.sessions)}."
                    )
                else:
                    self._context_by_version.pop(version, None)
                    self._status.setText("Следующая сверка будет выполнена без сведений о сеансах.")
                self._controls()
            else:
                self._status.setText(old_status)
            dialog.deleteLater()

        self._submit(lambda: self._matrix_store.get_version(self._project, version).matrix, done,
                     "Открываем утверждённые требования…")

    def _legacy_vmware_catalog_sites(self, run_id: str) -> tuple[str, ...]:
        scan = self._store.run_cloud_scan_header(self._project, run_id)
        return matrix_cloud_catalog_sites(scan, self._site)

    def _run(self, *, keep_row: tuple[str, str] | None = None) -> None:
        version = self._versions.currentData()
        if not isinstance(version, str):
            return
        cancel = Event()
        self._cancel = cancel
        self._record_progress(0, 0)
        self._progress.setRange(0, 0)
        self._progress.show()
        self._progress_timer.start()
        context = self._context_by_version.get(version)
        baseline = self._baseline
        baseline_run_id = baseline.run_id if baseline else None
        local_targets = self._targets.get((version, baseline_run_id))
        target_snapshot = local_targets.copy() if local_targets is not None else None

        def work() -> tuple[_ScopeView, tuple[MatrixScopeSummary, ...] | None] | str:
            record = self._matrix_store.get_version(self._project, version)
            matrix = record.matrix
            if matrix.schema_version != "2.0.0":
                return "Для сверки области утвердите версию матрицы формата 2.0.0."
            targets = target_snapshot
            targets_warning = ""
            if targets is None and baseline is None:
                try:
                    targets = self._history_store.latest_current_targets(
                        self._project, matrix, selected_site_id=self._site, cancelled=cancel.is_set,
                    )
                except (OSError, ValueError, sqlite3.Error):
                    targets_warning = "Не удалось восстановить сохранённые назначения источников."
            profile = ProfileVersion.from_settings(
                self._project, 1, analysis_settings(self._store.get_project(self._project)["settings"]),
            )
            sources: list[MatrixScopeInput] = []
            bindings_by_revision: dict[UUID, dict[tuple[str, str], tuple[str, ...]]] = {}
            bindings_by_vrf_by_revision: dict[UUID, dict[str, dict[tuple[str, str], tuple[str, ...]]]] = {}
            uses_catalog = any(member.kind in {"resource", "logical_network"}
                               for group in matrix.groups for member in group.members)
            assignments = self._store.workspace_metadata.device_sites(self._project) if uses_catalog else {}
            catalog = MatrixCatalog(self._store, self._project) if uses_catalog else None
            policy_revisions, path_revisions = self._store.latest_matrix_scope_revisions(
                self._project, self._site, baseline_run_id=baseline_run_id, cancelled=cancel.is_set,
            )
            for run_id, item_id, payload in policy_revisions:
                if cancel.is_set():
                    break
                revision = DeviceRevision.model_validate(payload)
                sources.append(MatrixScopeInput(run_id=run_id, item_id=item_id, revision=revision))
            cloud_notes: list[MatrixDiagnostic] = []
            unavailable_cloud_policies: set[str] = set()
            cloud_policies = matrix_scope_cloud_policy_ids(matrix, scope_id=self._scope)
            vmware_policies = matrix_scope_vmware_policy_ids(matrix, scope_id=self._scope)
            if not cancel.is_set() and (cloud_policies or vmware_policies):
                scans = self._store.latest_matrix_cloud_scans(
                    self._project, self._site, baseline_run_id=baseline_run_id, cancelled=cancel.is_set,
                    vmware_policy_ids=vmware_policies, include_security_groups=bool(cloud_policies),
                )
            else:
                scans = ()
            if scans and cloud_policies:
                orders = self._matrix_store.cloud_order_selections(
                    self._project, self._scope,
                    tuple(scan["id"] for scan in scans if scan["config"].get("platform") in {"advanced", "evolution"}),
                    cloud_policies,
                    cancelled=cancel.is_set,
                )
                sources.extend(matrix_scope_cloud_inputs(
                    matrix, scans, project_id=self._project, scope_id=self._scope, selected_site_id=self._site,
                    cancelled=cancel.is_set, recorded_orders=orders, diagnostics=cloud_notes,
                ))
            if scans and vmware_policies and not cancel.is_set():
                expected_by_scan: dict[str, set[str]] = defaultdict(set)
                retained: list[MatrixScopeInput] = []
                for source in sources:
                    if cancel.is_set():
                        break
                    scan_id = matrix_scope_vmware_replacing_scan_id(
                        source.revision, scans, vmware_policy_ids=vmware_policies,
                    )
                    if scan_id is None:
                        retained.append(source)
                    else:
                        policy_id = source.revision.parse_result.rules[0].policy_id
                        if policy_id is not None:
                            expected_by_scan[scan_id].add(policy_id)
                if not cancel.is_set():
                    sources = retained
                    sources.extend(matrix_scope_vmware_inputs(
                        matrix, scans, project_id=self._project, scope_id=self._scope, selected_site_id=self._site,
                        cancelled=cancel.is_set, diagnostics=cloud_notes, expected_policies_by_scan=expected_by_scan,
                        unavailable_policy_ids=unavailable_cloud_policies,
                    ))
            if catalog is not None:
                scans_by_id = {scan["id"]: scan for scan in scans}
                legacy_sites: dict[str, tuple[str, ...]] = {}
                for source in sources:
                    if cancel.is_set():
                        break
                    revision = source.revision
                    if not matrix_catalog_accepts_source(revision) and revision.parse_result.switch_facts is None:
                        continue
                    cloud_origin = source.cloud_selection or source.vmware_origin
                    if cloud_origin is not None:
                        sites = matrix_cloud_catalog_sites(scans_by_id.get(cloud_origin.scan_id), self._site)
                    elif revision.device.platform == "cloud-ru-vmware-nsxt" and source.run_id:
                        if source.run_id not in legacy_sites:
                            legacy_sites[source.run_id] = self._legacy_vmware_catalog_sites(source.run_id)
                        sites = legacy_sites[source.run_id]
                    else:
                        sites = matrix_revision_catalog_sites(revision, assignments, self._site)
                    if bindings := catalog.for_revision(revision, sites):
                        bindings_by_revision[revision.revision_id] = bindings
                    if by_vrf := catalog.for_vrfs(revision, sites):
                        bindings_by_vrf_by_revision[revision.revision_id] = by_vrf
                for path_source, default_switch in path_revisions:
                    if cancel.is_set():
                        break
                    if bindings := catalog.for_path_source(
                        path_source, assignments, self._site, default_switch=default_switch,
                    ):
                        bindings_by_revision[path_source.revision_id] = bindings
            result = evaluate_matrix_scope(
                matrix, tuple(sources), scope_id=self._scope, project_id=self._project,
                profile_id=f"matrix-scope:{self._project}", profile_version=profile.fingerprint,
                selected_site_id=self._site, targets_by_requirement=targets,
                bindings_by_revision=bindings_by_revision, context_inputs=context,
                bindings_by_vrf_by_revision=bindings_by_vrf_by_revision,
                path_sources=tuple(source for source, _ in path_revisions),
                unavailable_policy_ids=frozenset(unavailable_cloud_policies),
                cancelled=cancel.is_set, progress=self._record_progress, coverage_cache=self._evaluation_cache,
            )
            notes = list(cloud_notes)
            if baseline is None and not cancel.is_set():
                by_revision = defaultdict(list)
                for row in result.requirements:
                    if row.revision_id is not None:
                        by_revision[row.revision_id].append(row.requirement_id)
                failed = self._store.matrix_newer_source_failures(
                    self._project,
                    tuple((source.run_id, source.item_id) for source in result.sources
                          if source.revision_id in by_revision
                          and source.run_id is not None and source.item_id is not None),
                    cancelled=cancel.is_set,
                )
                fallback_count = 0
                for source in result.sources:
                    if source.run_id is None or source.item_id is None:
                        continue
                    attempt = failed.get((source.run_id, source.item_id))
                    identifiers = tuple(by_revision.get(source.revision_id, ()))
                    if attempt and identifiers:
                        fallback_count += 1
                        notes.append(MatrixDiagnostic(
                            code=SOURCE_FALLBACK_NOTE, requirement_ids=identifiers,
                            message=(
                                f"{source.device_label}: использован снимок от {source.captured_at.isoformat()}. "
                                f"Более поздняя попытка {attempt[0]} ({attempt[1]}) не дала нового снимка."
                            ),
                        ))
                if fallback_count:
                    result = result.model_copy(update={"limitations": (
                        *result.limitations,
                        f"Более поздние попытки не обновили снимки для {fallback_count} источников. "
                        "Оценки этих требований относятся к датам использованных снимков.",
                    )})
            if baseline is not None:
                message = (
                    f"Исторический срез · файловый запуск {baseline.created_at} · {baseline.run_id} "
                    f"· {_BASELINE_STATES.get(baseline.state, baseline.state)}"
                )
                notes.append(MatrixDiagnostic(code=HISTORICAL_BASELINE_NOTE, message=message))
                result = result.model_copy(update={
                    "baseline_run_id": baseline.run_id,
                    "limitations": (
                        *result.limitations, message,
                        "В срез входят выбранный запуск и предшествующие операции, завершившиеся к его началу. "
                        "Версия матрицы, каталог, назначения площадок, профиль и сеансы взяты из входов этой сверки.",
                    ),
                })
            if notes:
                result = result.model_copy(update={"diagnostics": (*result.diagnostics, *notes)})
            view = replace(
                self._prepare_view(result, matrix), calculated_here=True,
                history_warning=targets_warning,
            )
            try:
                artifact_id = self._history_store.save(result)
            except (OSError, ValueError, sqlite3.Error):
                warning = f"{targets_warning} История не записана. Доступен экспорт JSON.".strip()
                return replace(view, history_warning=warning), None
            view = replace(view, artifact_id=artifact_id)
            try:
                history = self._history_store.list_summaries(self._project, selected_site_id=self._site)
            except (OSError, ValueError, sqlite3.Error):
                warning = f"{targets_warning} Результат сохранён. Список истории не обновился.".strip()
                return replace(view, history_warning=warning), None
            return view, history

        def done(value: tuple[_ScopeView, tuple[MatrixScopeSummary, ...] | None] | str) -> None:
            if isinstance(value, str):
                self._show_result(value)
                return
            view, history = value
            if history is not None:
                self._show_history(history)
            self._show_result(view)
            if baseline is None and view.result.status != "cancelled":
                self._select_previous_comparison(view.result)
            if keep_row is not None:
                index = next((
                    index for index, row in enumerate(view.result.requirements)
                    if (row.kind, row.requirement_id) == keep_row
                ), None)
                if index is not None:
                    self._show_atomic(index)

        self._submit(work, done, "Подбираем сохранённые снимки и сверяем политики…")

    @staticmethod
    def _prepare_view(
        result: MatrixScopeAssessment, matrix: AccessMatrix | None, artifact_id: str | None = None,
        *, local_matrix: bool = True,
    ) -> _ScopeView:
        groups: dict[str, str] = {}
        services: dict[tuple[str, str], str] = {}
        if matrix is not None:
            group_counts = Counter(group.group_id for group in matrix.groups)
            groups = {group.group_id: group.name for group in matrix.groups if group_counts[group.group_id] == 1}
            requirement_counts = Counter(row.requirement_id for row in matrix.requirements)
            services.update({
                ("requirement", row.requirement_id): matrix_service_label(row.service)
                for row in matrix.requirements if requirement_counts[row.requirement_id] == 1
            })
            boundary_counts = Counter(row.boundary_id for row in matrix.boundaries)
            services.update({
                ("boundary", row.boundary_id): matrix_service_label(row.service)
                for row in matrix.boundaries if boundary_counts[row.boundary_id] == 1
            })
        devices = {item.revision_id: f"{item.device_label} {item.device_id}" for item in result.sources}
        sessions = matrix_session_search(result.context_inputs)
        group_ids = {key for row in result.requirements for key in (row.source_group, row.destination_group)}
        group_search = {key: f"{groups.get(key, '')} {key}".casefold() for key in group_ids}
        search = tuple(
            " ".join((row.assessment.requirement_id, row.source_group, row.destination_group,
                      groups.get(row.source_group, ""), groups.get(row.destination_group, ""),
                      services.get((row.kind, row.requirement_id), ""),
                      sessions.get(row.requirement_id, ""),
                      (resolution.source_cidr or "") if (resolution := row.assessment.context_resolution) else "",
                      row.policy_id or "", row.policy_vrf or "",
                      devices.get(row.revision_id, "") if row.revision_id else "")).casefold()
            for row in result.requirements
        )
        return _ScopeView(
            result, search, matrix, groups, group_search, services, artifact_id,
            boundary_groups=prepare_boundary_review(matrix, result, groups) if matrix is not None else (),
            local_matrix=matrix is not None and local_matrix,
            baseline_run_id=result.historical_run(),
        )

    def _show_result(self, value: _ScopeView | str) -> None:
        if isinstance(value, str):
            self._status.setText(value)
            return
        self._result, self._search, self._matrix = value.result, value.search, value.matrix
        self._view_targets = None
        self._result_is_historical = value.result.historical
        self._result_baseline_run_id = value.baseline_run_id
        self._local_matrix = value.local_matrix
        self._group_names = value.group_names
        self._group_search = value.group_search
        self._services = value.services
        self._boundary_groups = value.boundary_groups
        self._boundary_groups_button.setText(f"Закрытые области ({len(self._boundary_groups)})…")
        self._artifact_id = value.artifact_id
        result = self._result
        self._source_by_revision = {source.revision_id: source for source in result.sources}
        self._switch_sources = {
            source.revision_id: source for source in result.sources
            if source.run_id is not None and source.platform in _SWITCH_PATH_PLATFORMS
        }
        self._path_source_choices = tuple(sorted(
            self._switch_sources.values(),
            key=lambda source: (source.device_label.casefold(), source.platform, source.device_context or ""),
        ))
        self._notes_by_requirement = matrix_scope_source_notes(result)
        if self._local_matrix:
            if value.calculated_here and result.status != "cancelled":
                self._targets[(result.matrix_version, value.baseline_run_id)] = dict(result.targets_by_requirement)
            if result.context_inputs is not None:
                self._context_by_version[result.matrix_version] = result.context_inputs
            else:
                self._context_by_version.pop(result.matrix_version, None)
            self._versions.setCurrentIndex(self._versions.findData(result.matrix_version))
        else:
            self._versions.setCurrentIndex(-1)
        counts = Counter(row.routing for row in result.requirements)
        attention = sum(_needs_attention(row.assessment) for row in result.requirements)
        status = {"complete": "Завершена", "partial": "Частичная", "cancelled": "Остановлена"}.get(result.status, result.status)
        baseline_note = next((issue.message for issue in result.diagnostics if issue.code == HISTORICAL_BASELINE_NOTE), "")
        fallback_count = sum(issue.code == SOURCE_FALLBACK_NOTE for issue in result.diagnostics)
        self._status.setText(
            f"{status} · v{result.matrix_version} · снимков {len(result.sources)} · "
            f"строк {len(result.requirements)} из {result.total_requirements} · "
            f"требуют внимания {attention} · с подходящим снимком {counts['resolved']}"
            + (f" · неоднозначных {counts['ambiguous']}" if counts['ambiguous'] else "")
            + (f" · с неполными источниками {counts['incomplete_policy_sources']}"
               if counts['incomplete_policy_sources'] else "")
            + (" · требования по файлу" if self._matrix is None else "")
            + (" · матрица из файла результата" if self._matrix is not None and not self._local_matrix else "")
            + (f"\n{baseline_note}" if baseline_note else "")
            + (f"\nПредыдущие снимки после неудачного обновления: {fallback_count}." if fallback_count else "")
            + (
                f"\nЗакрытых областей с лишними разрешениями: "
                f"{sum(bool(group.excess_count) for group in self._boundary_groups)} · с пробелами: "
                f"{sum(bool(group.gap_count) for group in self._boundary_groups)}."
                if self._boundary_groups else ""
            )
            + (f". {value.history_warning}" if value.history_warning else "")
        )
        self._refresh()
        self._controls()

    def _refresh(self, *_: object) -> None:
        self._query_timer.stop()
        result = self._result
        if result is None:
            return

        def values(index: int) -> tuple[str, str, str]:
            row = result.requirements[index]
            label = MATRIX_STATE_LABELS[row.assessment.state]
            if row.assessment.context_resolution is not None and row.assessment.context_resolution.status == "resolved":
                label += " · сеанс"
            return (
                self._interaction(row.source_group, row.destination_group),
                self._services.get((row.kind, row.requirement_id), "—"),
                label,
            )

        self._table.set_rows(self._filtered_indices(result), values, reset=True)

    def _filtered_indices(self, result: MatrixScopeAssessment) -> list[int]:
        state = self._state.currentData()
        general, sources, destinations = (
            field.text().casefold().split() for field in (self._query, self._source_query, self._destination_query)
        )

        def matched_groups(terms: list[str]) -> set[str] | None:
            return {
                identifier for identifier, text in self._group_search.items() if all(term in text for term in terms)
            } if terms else None

        source_groups, destination_groups = matched_groups(sources), matched_groups(destinations)
        return [
            index for index, row in enumerate(result.requirements)
            if _matches_state(row.assessment, state)
            and (source_groups is None or row.source_group in source_groups)
            and (destination_groups is None or row.destination_group in destination_groups)
            and (not general or all(term in self._search[index] for term in general))
        ]

    def _interaction(self, source: str, destination: str) -> str:
        return f"{self._group_names.get(source, source)} → {self._group_names.get(destination, destination)}"

    def _details(self) -> None:
        self._selection_controls()
        result, index = self._result, self._table.selected_index()
        if result is None:
            return
        if index is None or not 0 <= index < len(result.requirements):
            self._text.setPlainText("\n".join(result.limitations))
            return
        row = result.requirements[index]
        lines = [self._interaction(row.source_group, row.destination_group), row.requirement_id, *row.assessment.reasons]
        if row.policy_id:
            lines.insert(2, f"Политика · {row.policy_id}")
        elif self._switch_sources:
            lines.append("Настроенный маршрут или общий VLAN можно проверить по сохранённому снимку коммутатора.")
        if row.zone_pair is not None:
            lines.insert(1, f"Зоны · {row.zone_pair.source_zone} → {row.zone_pair.destination_zone}")
        if row.policy_vrf is not None:
            lines.insert(1, f"VRF политики · {row.policy_vrf}")
        lines.extend(self._notes_by_requirement.get(row.requirement_id, ()))
        sources = self._source_by_revision
        if row.revision_id is not None and (source := sources.get(row.revision_id)) is not None:
            lines.extend((f"Устройство · {source.device_label}", f"Ревизия · {source.revision_id}"))
            if source.cloud_selection is not None:
                lines.extend((f"Облачный сбор · {source.cloud_selection.scan_id}",
                              f"Интерфейс · {source.cloud_selection.interface_id}"))
            elif source.vmware_origin is not None:
                origin = source.vmware_origin
                lines.extend((f"Сбор VMware · {origin.scan_id}", f"Edge Gateway · {origin.resource_id}"))
            elif source.run_id and source.item_id:
                lines.append(f"Запуск · {source.run_id} · снимок {source.item_id}")
        candidates = result.candidate_revisions(row)
        if candidates:
            lines.append(f"Подходящих снимков · {len(candidates)}")
            lines.extend(f"{sources[key].device_label} · {key}" for key in candidates[:20])
            if len(candidates) > 20:
                lines.append("Полный список доступен в JSON.")
        target = self._result_targets(result).get(row.requirement_id)
        if target is not None:
            lines.append(f"Явный выбор · {target.device_id} · {target.device_context or 'без отдельного контекста'}")
        if (context := row.assessment.context_resolution) is not None:
            if context.message not in row.assessment.reasons:
                lines.append(context.message)
            if context.session_id:
                vrf = assigned_session_context(result.context_inputs, row.requirement_id, context.session_id)
                lines.append(" · ".join(part for part in (
                    f"Сеанс {context.session_id}", vrf, context.source_cidr or "адрес не подтверждён",
                ) if part))
            if context.evaluated_at is not None:
                lines.append(f"Время сеанса · {context.evaluated_at.isoformat()}")
        preview = matrix_evidence_preview(row.assessment.evidence)
        for item in preview:
            lines.append(item.summary)
            if detail := matrix_packet_detail(item):
                lines.append(detail)
            lines.extend(f"{anchor.source_name} · {anchor.object_path or anchor.line_start or anchor.object_id}"
                         for anchor in item.source_locations)
        if len(preview) < len(row.assessment.evidence):
            lines.append(f"Ещё {len(row.assessment.evidence) - len(preview)} оснований доступны в полном JSON.")
        self._text.setPlainText("\n".join(lines))

    def _edit_source_addresses(self) -> None:
        matrix, result, index = self._matrix, self._result, self._table.selected_index()
        if matrix is None or result is None or index is None or self._busy or not self._local_matrix:
            return
        row = result.requirements[index]
        source = self._source_by_revision.get(row.revision_id) if row.revision_id is not None else None
        if source is None:
            return
        target = MatrixScopeTarget(
            device_id=source.device_id, platform=source.platform, device_context=source.device_context,
        )
        counts = Counter(group.group_id for group in matrix.groups)
        by_group = {group.group_id: group for group in matrix.groups if counts[group.group_id] == 1}
        groups = [row.source_group, row.destination_group]
        if row.kind == "boundary":
            boundary = next((item for item in matrix.boundaries if item.boundary_id == row.requirement_id), None)
            if boundary is not None:
                exceptions = set(boundary.allowed_requirement_ids)
                for requirement in matrix.requirements:
                    if requirement.requirement_id in exceptions:
                        groups.extend((requirement.source_group, requirement.destination_group))
        seen: set[str] = set()
        resources: set[str] = set()
        while groups:
            identifier = groups.pop()
            if identifier in seen or (group := by_group.get(identifier)) is None:
                continue
            seen.add(identifier)
            for member in group.members:
                if member.kind == "group":
                    groups.append(member.value)
                elif member.kind == "resource":
                    resources.add(member.value)
        if not resources:
            self._status.setText("В этой строке нет ссылок на карточки реестра ресурсов.")
            return

        previous_status = self._status.text()

        def work() -> tuple[MatrixCatalog, tuple[tuple[str, str], ...], str | None]:
            revision = self._history_store.get_source_revision(result, source.revision_id, matrix=matrix)
            vrf = matrix_catalog_switch_policy_contexts(revision).get(row.policy_id or "")
            if vrf is None and not matrix_catalog_accepts_source(revision):
                raise ValueError("Для источника нужно подтвердить VRF конкретной политики.")
            origin = source.cloud_selection or source.vmware_origin
            if origin is not None:
                header = self._store.get_cloud_scan_header(self._project, origin.scan_id)
                sites = matrix_cloud_catalog_sites(header, self._site)
            elif source.platform == "cloud-ru-vmware-nsxt" and source.run_id:
                sites = self._legacy_vmware_catalog_sites(source.run_id)
            else:
                assignments = self._store.workspace_metadata.device_sites(self._project)
                sites = matrix_revision_catalog_sites(revision, assignments, self._site)
            names = {site["id"]: site["name"] for site in self._store.workspace_metadata.list_sites()}
            choices = tuple((site, names[site] if site else "Без площадки") for site in sites if not site or site in names)
            return MatrixCatalog(self._store, self._project), choices, vrf

        def loaded(value: tuple[MatrixCatalog, tuple[tuple[str, str], ...], str | None]) -> None:
            catalog, sites, vrf = value
            current_resources = {catalog.resource_redirects.get(key, key) for key in resources}
            available = tuple(sorted(
                ((key, catalog.resources[key]) for key in current_resources if key in catalog.resources),
                key=lambda item: (item[1].casefold(), item[0]),
            ))
            if not available or not sites:
                self._status.setText("Нужна активная карточка ресурса и подтверждённая площадка источника сверки.")
                return
            site_ids = tuple(site for site, _ in sites)
            label = f"{source.device_label} · {f'VRF {vrf}' if vrf else source.device_context or source.platform}"
            selected = edit_matrix_source_binding(
                self, device_label=label,
                resources=available, sites=sites, existing=catalog.existing(target, site_ids, vrf),
                suggested=catalog.suggested(current_resources, site_ids) if vrf in (None, "default") else {},
            )
            if selected is None or not self._valid():
                self._status.setText(previous_status)
                return
            resource_id, site_id, prefixes = selected

            def save() -> None:
                self._store.resource_registry.set_matrix_source_binding(
                    self._project, resource_id, site_id=site_id, device_id=target.device_id,
                    platform=target.platform, device_context=target.device_context, prefixes=prefixes, vrf=vrf,
                )

            self._submit(
                save, lambda _: self._run(keep_row=(row.kind, row.requirement_id)),
                "Сохраняем подтверждённые адреса…",
            )

        self._submit(work, loaded, "Читаем источник и карточки ресурсов выбранной строки…")

    def _path_sources(
        self, result: MatrixScopeAssessment, row: MatrixScopeRowAssessment,
    ) -> tuple[MatrixScopeSource, ...]:
        if row.revision_id is not None:
            source = self._switch_sources.get(row.revision_id)
            return (source,) if source is not None else ()
        candidates = result.candidate_revisions(row)
        if candidates:
            return tuple(self._switch_sources[key] for key in candidates if key in self._switch_sources)
        return self._path_source_choices

    def _open_path(self) -> None:
        result, index = self._result, self._table.selected_index()
        matrix = self._matrix
        if result is None or matrix is None or index is None or not self._path_button.isEnabled():
            return
        row = result.requirements[index]
        candidates = self._path_sources(result, row)
        if not candidates:
            return
        source = candidates[0]
        if len(candidates) > 1:
            choice = select_matrix_input(self, [
                f"{item.device_label} · {item.platform} · {item.device_context or 'без отдельного контекста'}"
                f" · {item.captured_at.isoformat()}" for item in candidates
            ], title="Снимок коммутатора для разбора пути", placeholder="Поиск по устройству, контексту или времени")
            if choice is None:
                return
            source = candidates[choice]
        old_status = self._status.text()

        def work() -> tuple[DeviceRevision, dict[str, str]]:
            revision = self._history_store.get_source_revision(result, source.revision_id, matrix=matrix)
            bindings, by_vrf = split_catalog_bindings((*source.path_bindings, *source.bindings))
            prefill = matrix_path_prefill(
                matrix, revision, row.assessment, scope_id=result.scope_id,
                bindings=bindings, bindings_by_vrf=by_vrf,
                policy_source_matches=row.revision_id == source.revision_id,
                context_inputs=result.context_inputs,
            ) if revision.parse_result.switch_facts is not None else {}
            return revision, prefill

        def done(value: tuple[DeviceRevision, dict[str, str]]) -> None:
            revision, prefill = value
            if revision.parse_result.switch_facts is None:
                self._status.setText("В сохранённом снимке нет настроенных интерфейсов и маршрутов для разбора.")
                return
            self._status.setText(old_status)
            dialog = MatrixPathDialog(revision, prefill, self)
            dialog.exec()
            dialog.deleteLater()

        self._submit(work, done, "Открываем сохранённый снимок коммутатора…")

    def _open_journey(self) -> None:
        matrix, result = self._matrix, self._result
        if matrix is None or result is None or self._busy:
            return
        journeys = tuple(journey for journey in matrix.journeys if journey.scope_id == result.scope_id)
        if not journeys:
            return
        choice: int | None = 0
        if len(journeys) > 1:
            choice = select_matrix_input(
                self, [f"{journey.name} · участков {len(journey.steps)}" for journey in journeys],
                title="Цепочка доступа", placeholder="Поиск по имени цепочки",
            )
            if choice is None:
                return
        artifact_id = UUID(self._artifact_id) if self._artifact_id is not None else None

        def load_revision(revision_id: UUID) -> DeviceRevision:
            try:
                return self._history_store.get_source_revision(result, revision_id, matrix=matrix)
            except sqlite3.Error as error:
                raise OSError("Не удалось прочитать сохранённый снимок участка") from error

        dialog = MatrixJourneyReview(
            self._matrix_store, self._runner, self._project, matrix, journeys[choice], (), None, self._valid, self,
            scope_result=result, scope_artifact_id=artifact_id,
            scope_revision=load_revision,
        )
        dialog.exec()
        dialog.deleteLater()

    def _open_boundary_groups(self) -> None:
        result = self._result
        if result is None or not self._boundary_groups or self._busy or self._closed or not self._valid():
            return
        dialog = MatrixBoundaryReview(self._boundary_groups, self)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        index = dialog.atomic_index
        dialog.deleteLater()
        if (
            not accepted or index is None or not 0 <= index < len(result.requirements)
            or self._closed or not self._valid() or self._result is not result
        ):
            return
        self._show_atomic(index)

    def _show_atomic(self, index: int) -> None:
        result = self._result
        if result is None or not 0 <= index < len(result.requirements):
            return
        if self._query_timer.isActive():
            self._refresh()
        if self._table.show_index(index):
            return
        row = result.requirements[index]
        for field, value in (
            (self._query, self._search[index]),
            (self._source_query, self._group_search[row.source_group]),
            (self._destination_query, self._group_search[row.destination_group]),
        ):
            if not all(term in value for term in field.text().casefold().split()):
                previous = field.blockSignals(True)
                field.clear()
                field.blockSignals(previous)
        if not _matches_state(row.assessment, self._state.currentData()):
            previous = self._state.blockSignals(True)
            self._state.setCurrentIndex(0)
            self._state.blockSignals(previous)
        self._refresh()
        self._table.show_index(index)

    def _choose_target(self) -> None:
        result, index = self._result, self._table.selected_index()
        if result is None or index is None or not self._choose_button.isEnabled():
            return
        row = result.requirements[index]
        candidates = tuple(self._source_by_revision[key] for key in result.candidate_revisions(row))
        choice = select_matrix_input(self, [
            f"{item.device_label} · {item.device_id} · {item.platform} · {item.device_context or 'без отдельного контекста'}"
            for item in candidates
        ], title="Устройство политики", placeholder="Имя, устройство или контекст")
        if choice is None:
            return
        source = candidates[choice]
        target = MatrixScopeTarget(device_id=source.device_id, platform=source.platform,
                                   device_context=source.device_context)
        targets = self._editable_targets(result)
        affected = [row.requirement_id]
        if self._bulk_targets.isChecked():
            affected = [item.requirement_id for item in result.requirements if item.policy_id == row.policy_id
                        and item.routing in {"ambiguous", "target_not_found", "incomplete_policy_sources"}]
        targets.update((key, target) for key in affected)
        self._status.setText(f"Выбрано устройство для {len(affected)} строк. Запустите сверку для обновления вывода.")
        self._details()

    def _clear_target(self) -> None:
        result, index = self._result, self._table.selected_index()
        if result is not None and index is not None and self._clear_button.isEnabled():
            self._editable_targets(result).pop(result.requirements[index].requirement_id, None)
            self._status.setText("Выбор снят. Запустите сверку для обновления вывода.")
            self._details()

    def _open(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Открыть результат сверки области", "", "JSON (*.json)")
        if not filename:
            return

        def work() -> _ScopeView | str:
            result, packaged_matrix = decode_scope_result(Path(filename).read_bytes())
            if (result.project_id, result.scope_id, result.selected_site_id) != (self._project, self._scope, self._site):
                return "Результат относится к другому проекту или области."
            try:
                record = self._matrix_store.get_version(self._project, result.matrix_version)
            except ValueError:
                approved = None
            else:
                approved = record.matrix if matrix_scope_checksum(record.matrix) == result.matrix_checksum else None
            matrix = approved or packaged_matrix
            if approved is not None and packaged_matrix is None:
                verify_scope_rows(approved, result)
            return self._prepare_view(result, matrix, local_matrix=approved is not None)

        self._submit(work, self._show_result, "Читаем сохранённый результат…")

    def _restore(self) -> None:
        identifier = self._history.currentData()
        if not isinstance(identifier, str):
            return

        def work() -> _ScopeView:
            result = self._history_store.get(self._project, identifier, selected_site_id=self._site)
            matrix = self._matrix_store.get_version(self._project, result.matrix_version).matrix
            return self._prepare_view(result, matrix, identifier)

        self._submit(work, self._show_result, "Открываем сверку из истории…")

    def _compare(self) -> None:
        opened, identifier = self._result, self._history.currentData()
        if opened is None or not isinstance(identifier, str) or identifier == self._artifact_id:
            return

        opened_matrix = self._matrix

        def work() -> _PreparedComparison | str:
            selected = self._history_store.get(self._project, identifier, selected_site_id=self._site)
            before, after = sorted(
                (selected, opened), key=lambda result: (_comparison_time(result), result.created_at),
            )
            matrix = opened_matrix
            if matrix is None and selected.matrix_checksum == opened.matrix_checksum:
                matrix = self._matrix_store.get_version(self._project, selected.matrix_version).matrix
            try:
                changes = compare_matrix_scope_assessments(before, after, matrix=matrix)
                prepared = prepare_matrix_scope_comparison(before, after, changes, matrix)
                return before, after, prepared, matrix, matrix_finding_sources(before, after, changes)
            except ValueError as error:
                return str(error)

        def done(value: _PreparedComparison | str) -> None:
            if isinstance(value, str):
                self._status.setText(value)
                return
            self._show_comparison(*value)

        self._submit(work, done, "Сопоставляем сохранённые сверки…")

    def _show_comparison(
        self, before: MatrixScopeAssessment, after: MatrixScopeAssessment,
        prepared: MatrixScopeComparisonView, matrix: AccessMatrix | None, finding_sources: MatrixFindingSources,
    ) -> None:
        dialog = MatrixScopeComparisonDialog(
            before, after, prepared.changes, matrix, self, prepared=prepared,
            finding_sources=tuple((key, pair.label) for key, pair in finding_sources.pairs.items()),
            finding_sources_by_requirement=finding_sources.by_requirement,
            findings_overview=finding_sources.overview,
        )
        opened = True
        findings_closed = Event()

        def load_findings(key: str) -> None:
            pair = finding_sources.pairs.get(key)
            if pair is None:
                return

            def work() -> tuple[tuple[MatrixFindingComparisonRow, ...], tuple[str, ...]] | str:
                if findings_closed.is_set():
                    return (), ()
                try:
                    rows, diagnostics = load_matrix_finding_rows(self._store, self._project, pair)
                except ValueError as error:
                    return str(error)
                if findings_closed.is_set():
                    return (), ()
                return prepare_matrix_finding_rows(rows), diagnostics

            def done(value: object) -> None:
                if not opened or self._closed or not self._valid():
                    return
                if isinstance(value, JobError):
                    dialog.set_findings_error(key, value.message)
                elif isinstance(value, str):
                    dialog.set_findings_error(key, value)
                else:
                    rows, diagnostics = cast(
                        tuple[tuple[MatrixFindingComparisonRow, ...], tuple[str, ...]], value,
                    )
                    dialog.set_findings_result(key, rows, diagnostics)

            self._runner.submit(work, done)

        def export() -> None:
            filename, _ = QFileDialog.getSaveFileName(
                dialog, "Экспорт сравнения", "matrix-scope-comparison.html", "HTML (*.html)",
            )
            if filename:
                dialog.set_export_status("Формируем полный отчёт…", busy=True)

                def write() -> None:
                    report = matrix_scope_comparison_html(before, after, matrix=matrix, changes=prepared.changes)
                    write_report_file(Path(filename), report)

                def exported(value: object) -> None:
                    if self._closed or not self._valid():
                        return
                    message = value.message if isinstance(value, JobError) else "Сравнение сохранено."
                    self._status.setText(message)
                    if opened:
                        dialog.set_export_status(message)

                self._runner.submit(write, exported)

        def finished(_: int) -> None:
            nonlocal opened
            opened = False
            findings_closed.set()
            dialog.deleteLater()

        self._status.setText("Сравнение готово.")
        dialog.findings_requested.connect(load_findings)
        dialog.export_requested.connect(export)
        dialog.finished.connect(finished)
        dialog.open()

    def _export(self) -> None:
        result, matrix = self._result, self._matrix
        if result is None:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Сохранить сверку области", "matrix-scope.json", "JSON (*.json)")
        if filename:
            self._submit(lambda: write_report_file(Path(filename), encode_scope_result(result, matrix)),
                         lambda _: self._status.setText("Результат сохранён."), "Сохраняем результат…")

    def _export_selection(self) -> None:
        result, matrix = self._result, self._matrix
        if result is None:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Сохранить выборку", "matrix-scope-selection.csv", "CSV (*.csv)")
        if not filename:
            return
        indices = tuple(self._filtered_indices(result))
        self._submit(lambda: write_report_file(Path(filename), "\ufeff" + matrix_scope_report_csv(result, indices, matrix=matrix)),
                     lambda _: self._status.setText(f"Сохранена выборка из {len(indices)} строк."), "Сохраняем выборку…")
