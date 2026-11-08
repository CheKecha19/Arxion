"""Project-scoped technical-control evidence with explicit profile selection."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any, Protocol

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.application.analysis_result import AnalysisResult
from firewall_compliance.application.control_assessment import (
    DISCLAIMER,
    ControlAssessment,
    assess_controls,
    export_control_assessment_csv,
    export_control_assessment_html,
    export_control_assessment_json,
    internal_control_catalogue,
)
from firewall_compliance.domain.controls import ControlCatalogue, OrganizationControlProfile
from firewall_compliance.interfaces.desktop.control_assessment_store import ControlAssessmentStore
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner


class ControlsProjectStore(Protocol):
    path: Path

    def list_analysis_results(self, project_id: str) -> list[dict[str, Any]]: ...

    def get_analysis_result(self, project_id: str, analysis_id: str) -> AnalysisResult: ...


@dataclass(frozen=True)
class _Listing:
    sources: list[dict[str, Any]]
    assessments: list[dict[str, Any]]


def _read(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("Selected JSON exceeds 64 MiB")
    return data.decode("utf-8-sig")


def _label(text: str) -> QLabel:
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    return label


class ControlsPanel(QWidget):
    """All validation/replay/persistence runs on a dedicated worker.

    Cancellation suppresses stale delivery and checks before saving. A SQLite
    commit already in progress may finish in its original project; it never
    changes the project or snapshot captured by the submitted operation.
    """

    def __init__(self, store: ControlsProjectStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.store = store
        self.assessment_store = ControlAssessmentStore(store.path)
        self.runner = JobRunner()
        self.project_id: str | None = None
        self.profile: OrganizationControlProfile | None = None
        self.catalogue = internal_control_catalogue()
        self.active_assessment: ControlAssessment | None = None
        self._profile_path: Path | None = None
        self._catalogue_path: Path | None = None
        self._ticket = object()
        self._cancel = Event()
        self._busy = False
        self._closed = False
        layout = QVBoxLayout(self)
        layout.addWidget(_label(DISCLAIMER))
        layout.addWidget(_label("Результат для оценки"))
        source_row = QHBoxLayout()
        self.source_selector = QComboBox()
        self.source_selector.setAccessibleName("Общий результат для оценки контролей")
        self.source_selector.currentIndexChanged.connect(self._update_actions)
        source_row.addWidget(self.source_selector, 1)
        self.refresh_button = QPushButton("Обновить результаты")
        self.refresh_button.clicked.connect(self.refresh_results)
        source_row.addWidget(self.refresh_button)
        layout.addLayout(source_row)
        profile_row = QHBoxLayout()
        self.profile_button = QPushButton("Загрузить профиль организации…")
        self.profile_button.clicked.connect(self._choose_profile)
        profile_row.addWidget(self.profile_button)
        self.catalogue_button = QPushButton("Загрузить каталог…")
        self.catalogue_button.clicked.connect(self._choose_catalogue)
        profile_row.addWidget(self.catalogue_button)
        self.internal_catalogue_button = QPushButton("Внутренний каталог")
        self.internal_catalogue_button.clicked.connect(self._use_internal_catalogue)
        profile_row.addWidget(self.internal_catalogue_button)
        layout.addLayout(profile_row)
        self.profile_label = _label(
            "Для новой оценки: профиль не выбран. Автоматического утверждения нет."
        )
        self.catalogue_label = _label("")
        layout.addWidget(self.profile_label)
        layout.addWidget(self.catalogue_label)
        operation_row = QHBoxLayout()
        self.evaluate_button = QPushButton("Оценить и сохранить свидетельства")
        self.evaluate_button.clicked.connect(lambda: self.evaluate_current())
        operation_row.addWidget(self.evaluate_button)
        self.cancel_button = QPushButton("Отменить ожидание")
        self.cancel_button.clicked.connect(self.cancel_current)
        operation_row.addWidget(self.cancel_button)
        layout.addLayout(operation_row)
        layout.addWidget(_label("История оценок"))
        self.assessment_selector = QComboBox()
        self.assessment_selector.setAccessibleName("История оценок внутренних контролей")
        self.assessment_selector.currentIndexChanged.connect(self.load_selected_assessment)
        layout.addWidget(self.assessment_selector)
        self.summary_label = _label("Сохранённая оценка не выбрана.")
        layout.addWidget(self.summary_label)
        self.browser = QTextBrowser()
        self.browser.setOpenLinks(False)
        self.browser.setOpenExternalLinks(False)
        self.browser.setAccessibleName("Исходы, охват и доказательства контролей")
        layout.addWidget(self.browser, 1)
        export_row = QHBoxLayout()
        self.export_buttons: dict[str, QPushButton] = {}
        for format_name in ("json", "csv", "html"):
            button = QPushButton(f"Экспорт {format_name.upper()}…")
            button.clicked.connect(lambda _=False, name=format_name: self._choose_export(name))
            self.export_buttons[format_name] = button
            export_row.addWidget(button)
        layout.addLayout(export_row)
        self.status_label = _label("Выберите проект и сохранённый общий результат.")
        layout.addWidget(self.status_label)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.poll_jobs)
        self._timer.start(40)
        owned_runner = self.runner
        self.destroyed.connect(lambda: owned_runner.shutdown())
        self._update_catalogue_label()
        self._update_actions()

    def poll_jobs(self) -> None:
        if not self._closed:
            self.runner.poll()

    def _update_actions(self, *_: Any) -> None:
        enabled = bool(self.project_id) and not self._busy and not self._closed
        for widget in (
            self.source_selector,
            self.refresh_button,
            self.profile_button,
            self.catalogue_button,
            self.internal_catalogue_button,
            self.assessment_selector,
        ):
            widget.setEnabled(enabled)
        self.evaluate_button.setEnabled(
            enabled and self.profile is not None and bool(self.source_selector.currentData())
        )
        self.cancel_button.setEnabled(self._busy and not self._closed)
        for button in self.export_buttons.values():
            button.setEnabled(enabled and self.active_assessment is not None)

    def _submit(self, work: Callable[[Event], object], completed: Callable[[object], None]) -> None:
        if not self.project_id or self._closed or self._busy:
            return
        project_id = self.project_id
        ticket = object()
        self._ticket = ticket
        cancellation = Event()
        self._cancel = cancellation
        self._busy = True
        self.status_label.setText("Проверка сохранённых данных выполняется…")
        self._update_actions()

        def done(value: object) -> None:
            if self._closed or self.project_id != project_id or self._ticket is not ticket:
                return
            self._busy = False
            if cancellation.is_set():
                self.status_label.setText("Ожидание отменено; результат не открыт.")
            elif isinstance(value, JobError):
                if self.active_assessment is None:
                    self.summary_label.setText("Результат оценки не получен.")
                self.status_label.setText(
                    "Операция не выполнена: проверьте профиль, область, версии и доступ к файлам."
                )
            else:
                completed(value)
            self._update_actions()

        self.runner.submit(lambda: work(cancellation), done)

    def cancel_current(self) -> None:
        self._cancel.set()
        self._ticket = object()
        self.runner.cancel_pending()
        self._busy = False
        self.status_label.setText(
            "Ожидание отменено. Уже начатое сохранение может завершиться в исходном проекте."
        )
        self._update_actions()

    def set_project_context(self, project_id: str | None, *, refresh: bool = True) -> None:
        if self._closed:
            return
        if self.project_id == project_id:
            if refresh:
                self.refresh_results()
            return
        self.cancel_current()
        self.project_id = project_id
        self.profile = None
        self.catalogue = internal_control_catalogue()
        self._profile_path = None
        self._catalogue_path = None
        self.active_assessment = None
        self.source_selector.clear()
        self.assessment_selector.blockSignals(True)
        self.assessment_selector.clear()
        self.assessment_selector.blockSignals(False)
        self.browser.clear()
        self.summary_label.setText("Сохранённая оценка не выбрана.")
        self.profile_label.setText(
            "Для новой оценки: профиль не выбран. Автоматического утверждения нет."
        )
        self._update_catalogue_label()
        self._update_actions()
        if project_id and refresh:
            self.refresh_results()
        elif project_id:
            self.status_label.setText("Сохранённые оценки ещё не загружены.")
        else:
            self.status_label.setText("Выберите проект.")

    def refresh_results(self, *_: Any, preferred_id: str | None = None) -> None:
        project_id = self.project_id
        if not project_id:
            return
        source_id = self.source_selector.currentData()
        assessment_id = preferred_id or self.assessment_selector.currentData()

        def work(cancellation: Event) -> object:
            sources = self.store.list_analysis_results(project_id)
            if cancellation.is_set():
                return None
            return _Listing(sources, self.assessment_store.list(project_id))

        def done(value: object) -> None:
            if not isinstance(value, _Listing):
                return
            self.source_selector.blockSignals(True)
            self.source_selector.clear()
            for row in value.sources:
                self.source_selector.addItem(
                    f"{row['created_at']} · {row['analysis_id']} · {row['state']}",
                    row["analysis_id"],
                )
            index = self.source_selector.findData(source_id)
            self.source_selector.setCurrentIndex(max(0, index) if value.sources else -1)
            self.source_selector.blockSignals(False)
            self.assessment_selector.blockSignals(True)
            self.assessment_selector.clear()
            for row in value.assessments:
                self.assessment_selector.addItem(
                    f"{row['assessed_at']} · {row['profile_id']} v{row['profile_version']} · "
                    f"{row['assessment_id']}",
                    row["assessment_id"],
                )
            index = self.assessment_selector.findData(assessment_id)
            self.assessment_selector.setCurrentIndex(max(0, index) if value.assessments else -1)
            self.assessment_selector.blockSignals(False)
            self.status_label.setText(
                f"Общих результатов: {len(value.sources)}; "
                f"сохранённых оценок: {len(value.assessments)}."
            )
            if value.assessments and (
                self.active_assessment is None
                or str(self.active_assessment.assessment_id)
                != self.assessment_selector.currentData()
            ):
                self.load_selected_assessment()

        self._submit(work, done)

    def _choose_profile(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Профиль организации", "", "JSON (*.json)")
        if path:
            self.load_profile_path(Path(path))

    def load_profile_path(self, path: Path) -> None:
        def done(value: object) -> None:
            if isinstance(value, OrganizationControlProfile):
                self.profile = value
                self._profile_path = path
                self.profile_label.setText(
                    f"Для новой оценки: {value.profile_id} v{value.version}; "
                    f"организация: {value.organization}; область: {value.scope_reference}. "
                    "Загрузка файла не означает автоматического утверждения."
                )
                self.status_label.setText("Профиль загружен; оценка ещё не выполнялась.")

        self._submit(lambda _: OrganizationControlProfile.model_validate_json(_read(path)), done)

    def _choose_catalogue(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Версионированный каталог", "", "JSON (*.json)")
        if path:
            self.load_catalogue_path(Path(path))

    def load_catalogue_path(self, path: Path) -> None:
        def done(value: object) -> None:
            if isinstance(value, ControlCatalogue):
                self.catalogue = value
                self._catalogue_path = path
                self._update_catalogue_label()
                self.status_label.setText("Каталог загружен; прежние оценки не изменены.")

        self._submit(lambda _: ControlCatalogue.model_validate_json(_read(path)), done)

    def _use_internal_catalogue(self) -> None:
        if not self._busy:
            self.catalogue = internal_control_catalogue()
            self._catalogue_path = None
            self._update_catalogue_label()

    def _update_catalogue_label(self) -> None:
        self.catalogue_label.setText(
            f"Каталог для новой оценки: {self.catalogue.catalogue_id} v{self.catalogue.version}; "
            "показывает технические свидетельства, не сертификацию."
        )

    def evaluate_current(self, *, assessed_at: datetime | None = None) -> None:
        project_id = self.project_id
        analysis_id = self.source_selector.currentData()
        profile = self.profile
        catalogue = self.catalogue
        if not project_id or not analysis_id or profile is None or self._busy or self._closed:
            return
        date = assessed_at or datetime.now(UTC)
        self.active_assessment = None
        self.browser.clear()
        self.summary_label.setText("Новая оценка выполняется; результат ещё не получен.")

        def work(cancellation: Event) -> object:
            source = self.store.get_analysis_result(project_id, str(analysis_id))
            if cancellation.is_set():
                return None
            result = assess_controls(source, profile, catalogue, assessed_at=date)
            if cancellation.is_set():
                return None
            self.assessment_store.save(project_id, result)
            return result

        def done(value: object) -> None:
            if isinstance(value, ControlAssessment):
                self._show_assessment(value)
                self.status_label.setText("Технические свидетельства сохранены в исходном проекте.")
                self.refresh_results(preferred_id=str(value.assessment_id))

        self._submit(work, done)

    def load_selected_assessment(self, *_: Any) -> None:
        project_id = self.project_id
        identifier = self.assessment_selector.currentData()
        if not project_id or not identifier or self._busy:
            return
        self.active_assessment = None
        self.browser.clear()
        self.summary_label.setText("Загрузка сохранённой оценки…")

        def done(value: object) -> None:
            if isinstance(value, ControlAssessment):
                self._show_assessment(value)
                self.status_label.setText(
                    "Историческая оценка открыта с сохранёнными профилем и каталогом."
                )

        self._submit(lambda _: self.assessment_store.get(project_id, str(identifier)), done)

    def _show_assessment(self, result: ControlAssessment) -> None:
        self.active_assessment = result
        coverage = result.coverage
        assert coverage is not None
        self.summary_label.setText(
            f"Оценка {result.assessment_id}; источник {result.source.analysis_id}; "
            f"профиль {result.profile.profile_id} v{result.profile.version}; "
            f"каталог {result.catalogue.catalogue_id} v{result.catalogue.version}.\n"
            f"Технические нарушения: {coverage.violations}; без нарушения в проверенной области: "
            f"{coverage.no_violations_in_examined_scope}; недостаточно данных: "
            f"{coverage.insufficient_evidence}; неприменимо: {coverage.not_applicable}. "
            f"Полностью исследовано: {coverage.fully_examined_evaluations}/"
            f"{coverage.applicable_evaluations}; выполнено checks: "
            f"{coverage.executed_check_evaluations}/{coverage.expected_check_evaluations}."
        )
        self.browser.setHtml(export_control_assessment_html(result))

    def _choose_export(self, format_name: str) -> None:
        result = self.active_assessment
        if result is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт технических свидетельств",
            f"controls-{result.assessment_id}.{format_name}",
            f"{format_name.upper()} (*.{format_name})",
        )
        if path:
            self.export_current(Path(path), format_name)

    def export_current(self, path: Path, format_name: str) -> None:
        result = self.active_assessment
        if result is None:
            return
        renderers = {
            "json": export_control_assessment_json,
            "csv": export_control_assessment_csv,
            "html": export_control_assessment_html,
        }
        protected = (
            self.store.path,
            self._profile_path,
            self._catalogue_path,
            *(
                self.store.path.with_name(self.store.path.name + suffix)
                for suffix in ("-wal", "-shm", "-journal")
            ),
        )

        def work(cancellation: Event) -> object:
            if format_name not in renderers:
                raise ValueError("Unsupported export format")
            for source in protected:
                if source is not None and (
                    path.resolve() == source.resolve()
                    or path.exists()
                    and source.exists()
                    and path.samefile(source)
                ):
                    raise ValueError("Export aliases a selected input or database")
            text = renderers[format_name](result)
            if not cancellation.is_set():
                path.write_text(text, encoding="utf-8")
            return path

        self._submit(
            work, lambda _: self.status_label.setText("Экспорт сохранён без повторного анализа.")
        )

    def shutdown(self) -> None:
        if not self._closed:
            self._closed = True
            self._cancel.set()
            self._ticket = object()
            self._timer.stop()
            self.runner.shutdown()
            self._update_actions()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.shutdown()
        super().closeEvent(event)
