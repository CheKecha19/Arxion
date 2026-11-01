"""Explicit rule-governance evidence applied to an immutable saved policy snapshot."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from threading import Event
from typing import Any, Literal, Protocol, cast

from PySide6.QtCore import QIODevice, QSaveFile, Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.application.analysis_reports import (
    export_analysis_csv,
    export_analysis_html,
    export_analysis_json,
)
from firewall_compliance.application.analysis_result import AnalysisResult, PolicyComponent
from firewall_compliance.application.governance_workflow import (
    GOVERNANCE_CHECK_IDS,
    assess_governance,
)
from firewall_compliance.domain.policy_governance import (
    PolicyGovernanceInputs,
    PolicyGovernanceProfile,
)
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner


class GovernanceProjectStore(Protocol):
    def list_analysis_results(self, project_id: str) -> list[dict[str, Any]]: ...

    def get_analysis_result(self, project_id: str, analysis_id: str) -> AnalysisResult: ...

    def save_analysis_result(self, project_id: str, result: AnalysisResult) -> str: ...


def _read(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("JSON exceeds 64 MiB")
    return data.decode("utf-8-sig")


def _label(text: str) -> QLabel:
    result = QLabel(text)
    result.setWordWrap(True)
    result.setTextFormat(Qt.TextFormat.PlainText)
    return result


class GovernancePanel(QWidget):
    """Project-scoped worker workflow; source files are never reread for analysis.

    Cancel suppresses delivery and is checked before persistence. A commit already
    in progress may finish in the captured original project, never a new project.
    """

    result_saved = Signal(str)

    def __init__(self, store: GovernanceProjectStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.store = store
        self.runner = JobRunner()
        self.project_id: str | None = None
        self.active_result: AnalysisResult | None = None
        self.profile: PolicyGovernanceProfile | None = None
        self.inputs: PolicyGovernanceInputs | None = None
        self._profile_path: Path | None = None
        self._inputs_path: Path | None = None
        self._ticket = object()
        self._cancel = Event()
        self._cancel_holder = [self._cancel]
        self._closed = False
        self._busy = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        contents = QWidget()
        self.scroll_area.setWidget(contents)
        outer.addWidget(self.scroll_area)
        layout = QVBoxLayout(contents)
        layout.addWidget(
            _label(
                "Владелец, основание, сроки и статистика правил проверяются по явным данным. "
                "Отсутствующие сведения остаются неизвестными; автоматического удаления правил нет."
            )
        )
        source_row = QHBoxLayout()
        self.source_selector = QComboBox()
        self.source_selector.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.source_selector.setMinimumContentsLength(16)
        self.source_selector.setAccessibleName("Сохранённый общий результат для проверки правил")
        self.source_selector.currentIndexChanged.connect(self.load_selected_result)
        source_row.addWidget(self.source_selector, 1)
        self.refresh_button = QPushButton("Обновить результаты")
        self.refresh_button.clicked.connect(self.refresh_results)
        source_row.addWidget(self.refresh_button)
        layout.addLayout(source_row)
        self.component_selector = QComboBox()
        self.component_selector.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.component_selector.setMinimumContentsLength(16)
        self.component_selector.setAccessibleName("Точная сохранённая policy-ревизия")
        self.component_selector.currentIndexChanged.connect(self._update_actions)
        layout.addWidget(self.component_selector)
        inputs_row = QHBoxLayout()
        self.profile_button = QPushButton("Загрузить профиль JSON…")
        self.profile_button.clicked.connect(self._choose_profile)
        self.inputs_button = QPushButton("Загрузить данные правил JSON…")
        self.inputs_button.clicked.connect(self._choose_inputs)
        self.clear_inputs_button = QPushButton("Без данных правил")
        self.clear_inputs_button.clicked.connect(self.clear_inputs)
        for button in (self.profile_button, self.inputs_button, self.clear_inputs_button):
            inputs_row.addWidget(button)
        layout.addLayout(inputs_row)
        self.profile_label = _label(
            "Профиль не выбран. Формат: DOCUMENTATION.md."
        )
        self.inputs_label = _label("Данные правил не заданы: метаданные и статистика неизвестны.")
        layout.addWidget(self.profile_label)
        layout.addWidget(self.inputs_label)
        operation_row = QHBoxLayout()
        self.evaluate_button = QPushButton("Проверить сейчас и сохранить новый результат")
        self.evaluate_button.clicked.connect(lambda: self.evaluate_current())
        self.cancel_button = QPushButton("Отменить ожидание")
        self.cancel_button.clicked.connect(self.cancel_current)
        operation_row.addWidget(self.evaluate_button)
        operation_row.addWidget(self.cancel_button)
        layout.addLayout(operation_row)
        self.summary_label = _label("Сохранённый результат не выбран.")
        layout.addWidget(self.summary_label)
        self.browser = QTextBrowser()
        self.browser.setAccessibleName("Результаты проверок метаданных и статистики правил")
        self.browser.setOpenLinks(False)
        self.browser.setOpenExternalLinks(False)
        self.browser.setMinimumHeight(120)
        layout.addWidget(self.browser, 1)
        export_row = QHBoxLayout()
        self.export_buttons: dict[str, QPushButton] = {}
        for name in ("json", "csv", "html"):
            button = QPushButton("Экспорт " + name.upper() + "…")
            button.clicked.connect(lambda _=False, selected=name: self._choose_export(selected))
            self.export_buttons[name] = button
            export_row.addWidget(button)
        layout.addLayout(export_row)
        self.status_label = _label("Выберите проект и сохранённый общий результат.")
        layout.addWidget(self.status_label)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.poll_jobs)
        self._timer.start(40)
        runner = self.runner
        cancellation_holder = self._cancel_holder

        def stop_owned_worker() -> None:
            cancellation_holder[0].set()
            runner.shutdown()

        self.destroyed.connect(stop_owned_worker)
        self._update_actions()

    def poll_jobs(self) -> None:
        if not self._closed:
            self.runner.poll()

    def _update_actions(self, *_: Any) -> None:
        enabled = bool(self.project_id) and not self._busy and not self._closed
        for control in (
            self.source_selector,
            self.component_selector,
            self.refresh_button,
            self.profile_button,
            self.inputs_button,
            self.clear_inputs_button,
        ):
            control.setEnabled(enabled)
        self.evaluate_button.setEnabled(
            enabled
            and self.profile is not None
            and self.active_result is not None
            and bool(self.component_selector.currentData())
        )
        self.cancel_button.setEnabled(self._busy and not self._closed)
        for button in self.export_buttons.values():
            button.setEnabled(enabled and self.active_result is not None)

    def _submit(self, work: Callable[[Event], object], done: Callable[[object], None]) -> None:
        if self._closed or self._busy or not self.project_id:
            return
        project_id = self.project_id
        ticket = object()
        cancellation = Event()
        self._cancel = cancellation
        self._cancel_holder[0] = cancellation
        self._ticket = ticket
        self._busy = True
        self.status_label.setText("Проверяем сохранённые данные…")
        self._update_actions()

        def completed(value: object) -> None:
            if self._closed or self.project_id != project_id or self._ticket is not ticket:
                return
            self._busy = False
            if cancellation.is_set():
                self.status_label.setText("Ожидание отменено.")
            elif isinstance(value, JobError):
                self.status_label.setText(
                    "Операция не выполнена: проверьте JSON, версию, "
                    "точную ревизию и доступ к файлам."
                )
            else:
                done(value)
            self._update_actions()

        self.runner.submit(lambda: work(cancellation), completed)

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
        self.inputs = None
        self._profile_path = None
        self._inputs_path = None
        self.active_result = None
        self.source_selector.blockSignals(True)
        self.source_selector.clear()
        self.source_selector.blockSignals(False)
        self.component_selector.clear()
        self.browser.clear()
        self.profile_label.setText(
            "Профиль не выбран. Формат: DOCUMENTATION.md."
        )
        self.inputs_label.setText("Данные правил не заданы: метаданные и статистика неизвестны.")
        self.summary_label.setText("Сохранённый результат не выбран.")
        self._update_actions()
        if project_id and refresh:
            self.refresh_results()
        elif project_id:
            self.status_label.setText("Сохранённые результаты ещё не загружены.")
        else:
            self.status_label.setText("Выберите проект.")

    def refresh_results(self, *_: Any, preferred_id: str | None = None) -> None:
        project_id = self.project_id
        if not project_id:
            return
        selected = preferred_id or self.source_selector.currentData()

        def done(value: object) -> None:
            if not isinstance(value, list):
                return
            self.source_selector.blockSignals(True)
            self.source_selector.clear()
            for row in value:
                self.source_selector.addItem(
                    f"{row['finished_at']} · {row['state']} · {row['analysis_id']}",
                    row["analysis_id"],
                )
            index = self.source_selector.findData(selected)
            self.source_selector.setCurrentIndex(max(0, index) if value else -1)
            self.source_selector.blockSignals(False)
            if value:
                self.load_selected_result()
            else:
                self.active_result = None
                self.component_selector.clear()
                self.browser.clear()
                self.summary_label.setText("Сохранённых результатов нет.")
                self.status_label.setText("Сначала сохраните общий результат policy-проверки.")

        self._submit(lambda _: self.store.list_analysis_results(project_id), done)

    def _show_result(self, result: AnalysisResult) -> None:
        self.active_result = result
        self.component_selector.clear()
        stages = []
        for component in result.components:
            if isinstance(component, PolicyComponent):
                self.component_selector.addItem(
                    f"{component.component_id} · {component.revision.device.device_id} · "
                    f"ревизия {component.revision.revision_id}",
                    component.component_id,
                )
                if component.options.check_ids == GOVERNANCE_CHECK_IDS:
                    stages.append(component)
        if not stages:
            self.summary_label.setText(
                "Проверка метаданных и статистики ещё не выполнялась для этого результата."
            )
            self.browser.setPlainText(
                "Выберите сохранённую policy-ревизию и явный профиль. "
                "Отсутствие данных означает неизвестность, а не нарушение или нулевой счётчик."
            )
            return
        stage = stages[-1]
        profile = stage.options.governance_profile
        self.summary_label.setText(
            f"Последняя оценка: {stage.result.analyzed_at.isoformat()} · "
            f"профиль {profile.profile_id if profile else '?'} "
            f"v{profile.version if profile else '?'} · "
            f"находок: {sum(len(check.findings) for check in stage.result.checks)}"
        )
        rows = [
            "<h3>Метаданные и статистика правил</h3>",
            "<p>Ревизия: " + escape(str(stage.revision.revision_id)) + "</p>",
            "<p>Источник: "
            + escape(stage.revision.parse_result.configuration.source_name)
            + "; SHA-256: "
            + escape(stage.revision.parse_result.configuration.content_sha256)
            + "</p>",
        ]
        for check in stage.result.checks:
            rows.append(
                "<h4>" + escape(check.check_id) + " · " + escape(check.status.value) + "</h4>"
            )
            for limitation in check.limitations:
                rows.append("<p>" + escape(limitation.code + ": " + limitation.message) + "</p>")
            for finding in check.findings:
                rows.extend(
                    (
                        "<p><b>" + escape(finding.title) + "</b></p>",
                        "<pre>" + escape(finding.evidence.model_dump_json(indent=2)) + "</pre>",
                    )
                )
        self.browser.setHtml("".join(rows))

    def load_selected_result(self, *_: Any) -> None:
        project_id, analysis_id = self.project_id, self.source_selector.currentData()
        if not project_id or not isinstance(analysis_id, str) or self._busy:
            return
        self.active_result = None
        self.component_selector.clear()
        self.browser.clear()

        def done(value: object) -> None:
            if isinstance(value, AnalysisResult):
                self._show_result(value)
                self.status_label.setText("Сохранённый снимок загружен без чтения конфигурации.")

        self._submit(lambda _: self.store.get_analysis_result(project_id, analysis_id), done)

    def load_profile(self, path: Path) -> None:
        def done(value: object) -> None:
            if isinstance(value, PolicyGovernanceProfile):
                self.profile = value
                self._profile_path = path
                self.profile_label.setText(f"Для новой оценки: {value.profile_id} v{value.version}")

        self._submit(lambda _: PolicyGovernanceProfile.model_validate_json(_read(path)), done)

    def load_inputs(self, path: Path) -> None:
        def done(value: object) -> None:
            if isinstance(value, PolicyGovernanceInputs):
                self.inputs = value
                self._inputs_path = path
                self.inputs_label.setText(
                    f"Данные {value.input_id}; ревизия {value.revision_id}; "
                    f"метаданных: {len(value.metadata)}, статистики: {len(value.statistics)}"
                )

        self._submit(lambda _: PolicyGovernanceInputs.model_validate_json(_read(path)), done)

    def clear_inputs(self) -> None:
        if self._busy or self._closed:
            return
        self.inputs = None
        self._inputs_path = None
        self.inputs_label.setText("Данные правил не заданы: метаданные и статистика неизвестны.")

    def evaluate_current(self, *, assessed_at: datetime | None = None) -> None:
        project_id = self.project_id
        source, profile, inputs = self.active_result, self.profile, self.inputs
        component_id = self.component_selector.currentData()
        if not project_id or source is None or profile is None or not isinstance(component_id, str):
            return
        moment = assessed_at if assessed_at is not None else datetime.now(UTC)

        def work(cancellation: Event) -> object:
            result = assess_governance(source, component_id, profile, inputs, assessed_at=moment)
            if cancellation.is_set():
                return None
            self.store.save_analysis_result(project_id, result)
            return result

        def done(value: object) -> None:
            if isinstance(value, AnalysisResult):
                self._show_result(value)
                identity = str(value.analysis_id)
                self.result_saved.emit(identity)
                self.status_label.setText(
                    "Новая оценка сохранена. Исходный результат сохранён отдельно."
                )
                self.refresh_results(preferred_id=identity)

        self._submit(work, done)

    def export_current(self, format_name: Literal["json", "csv", "html"], path: Path) -> None:
        result = self.active_result
        if result is None:
            return
        protected = (
            self._profile_path,
            self._inputs_path,
            *(Path(s.source_name) for s in result.sources),
        )

        def work(cancellation: Event) -> object:
            for source in protected:
                if (
                    source is not None
                    and source.exists()
                    and (
                        source.resolve() == path.resolve()
                        or (path.exists() and path.samefile(source))
                    )
                ):
                    raise ValueError("Output aliases input")
            renderers = {
                "json": export_analysis_json,
                "csv": export_analysis_csv,
                "html": export_analysis_html,
            }
            data = renderers[format_name](result).encode("utf-8")
            if cancellation.is_set():
                return None
            output = QSaveFile(str(path))
            if not output.open(QIODevice.OpenModeFlag.WriteOnly):
                raise OSError("Cannot open output")
            if output.write(data) != len(data) or cancellation.is_set():
                output.cancelWriting()
                raise OSError("Output cancelled or incomplete")
            if not output.commit():
                raise OSError("Cannot commit output")
            return True

        self._submit(work, lambda _: self.status_label.setText("Экспорт сохранён."))

    def _choose_profile(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Профиль проверки правил", "", "JSON (*.json)")
        if path:
            self.load_profile(Path(path))

    def _choose_inputs(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Метаданные и статистика правил", "", "JSON (*.json)"
        )
        if path:
            self.load_inputs(Path(path))

    def _choose_export(self, format_name: str) -> None:
        if format_name not in {"json", "csv", "html"}:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт сохранённого результата",
            f"governance.{format_name}",
            f"{format_name.upper()} (*.{format_name})",
        )
        if path:
            self.export_current(cast(Literal["json", "csv", "html"], format_name), Path(path))

    def shutdown(self) -> None:
        if self._closed:
            return
        self._cancel.set()
        self._ticket = object()
        self._closed = True
        self._timer.stop()
        self.runner.shutdown()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.shutdown()
        super().closeEvent(event)
