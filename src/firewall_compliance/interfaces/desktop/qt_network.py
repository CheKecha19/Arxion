"""Расширенные сетевые API ASA в Qt; документы остаются только в памяти."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, Literal, cast
from uuid import UUID

from pydantic import BaseModel, TypeAdapter
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.forwarding import FlowApplicability, ForwardingContext
from firewall_compliance.domain.reachability import AnalysisReason, ReachabilityQuery
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.backend import AnalysisSession
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.map_network_facts import MapNetworkFacts
from firewall_compliance.interfaces.desktop.network_backend import (
    SUPPORTED_FORWARDING_PROFILE,
    ForwardingQueryResult,
    NetworkDocumentDraft,
    import_documents,
    parse_forwarding,
    run_bound_forwarding_query,
    run_forwarding_query,
    run_network_query,
)
from firewall_compliance.interfaces.desktop.qt_network_forms import (
    ContractKind,
    NetworkContractForm,
)
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseResult


@dataclass(frozen=True, slots=True)
class NetworkFactsSnapshot:
    """Exact in-memory inputs for a future map bridge, without label matching."""

    base_revision: DeviceRevision
    imported: NetworkImportResult | None
    parsed: ForwardingParseResult | None
    input_generation: int = 0
    bound_context: ForwardingContext | None = None


@dataclass(frozen=True, slots=True)
class NetworkQuerySnapshot:
    """Completed query identity and its original typed facts/result."""

    facts: NetworkFactsSnapshot
    profile_id: str
    query: ReachabilityQuery | None
    result: BaseModel | ForwardingQueryResult | JobError
    input_generation: int
    project_reference: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class JsonEditor(QPlainTextEdit):
    """Редактор явного JSON-контракта без угадывания полноты и наблюдения."""

    def __init__(self, value: object) -> None:
        super().__init__(json.dumps(value, ensure_ascii=False, indent=2))
        self.setMinimumHeight(130)

    def values(self) -> dict[str, Any]:
        value = json.loads(self.toPlainText())
        if not isinstance(value, dict):
            raise ValueError("Ожидается JSON-объект")
        return cast(dict[str, Any], value)


class NetworkWidget(QWidget):
    """Контекстные формы импорта, локальных решений и forwarding-инвентаря."""

    # None explicitly invalidates the current facts/result for bridge users.
    facts_changed = Signal(object)  # NetworkFactsSnapshot | None
    query_result_changed = Signal(object)  # NetworkQuerySnapshot | None

    def __init__(
        self, sessions_provider: Callable[[], tuple[AnalysisSession, ...]], runner: JobRunner
    ) -> None:
        super().__init__()
        self.provider = sessions_provider
        self.runner = runner
        self.sessions: tuple[AnalysisSession, ...] = ()
        self.imported: dict[UUID, NetworkImportResult] = {}
        self.drafts: dict[UUID, list[NetworkDocumentDraft]] = {}
        self.results: dict[tuple[UUID, str], BaseModel | ForwardingQueryResult] = {}
        self.forwarding_results: dict[UUID, BaseModel] = {}
        self.tickets: dict[tuple[UUID, str], object] = {}
        self.current_result: BaseModel | ForwardingQueryResult | None = None
        self._project_context: str | None = None
        self.query_snapshots: dict[tuple[UUID, str], NetworkQuerySnapshot] = {}
        self._query_generation = 0
        layout = QVBoxLayout(self)
        warning = QLabel(
            "Расширенный анализ только ASA. Выбор маршрута и локальная ACL не доказывают "
            "итоговую доступность. NAT/PBR и полный путь не вычисляются. Полнота и время "
            "наблюдения требуют явных оснований. Документы и сетевые результаты — в памяти "
            "до закрытия; оригинальный JSON можно экспортировать."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        bar = QHBoxLayout()
        self.base_combo = QComboBox()
        self.base_combo.currentIndexChanged.connect(self.context_changed)
        self.base_combo.currentIndexChanged.connect(self._query_inputs_changed)
        bar.addWidget(self.base_combo, 1)
        self.button(bar, "Обновить сессии", self.refresh_sessions)
        layout.addLayout(bar)
        self.status = QLabel("Импортируйте конфигурацию ASA или подключите её исходник.")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.build_import()
        self.build_inventory()
        self.build_query()
        self.build_forwarding()
        self.output_tab, output_layout = self.tab("Результаты / JSON")
        self.saved = QComboBox()
        self.saved.currentIndexChanged.connect(self.show_saved)
        output_layout.addWidget(self.saved)
        self.button(output_layout, "Экспорт оригинального JSON", self.export_result)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        output_layout.addWidget(self.output)
        self.refresh_sessions()

    @staticmethod
    def button(layout: QHBoxLayout | QVBoxLayout, title: str, action: Callable[[], None]) -> None:
        button = QPushButton(title)
        button.clicked.connect(action)
        layout.addWidget(button)

    def tab(self, title: str) -> tuple[QWidget, QVBoxLayout]:
        content = QWidget()
        layout = QVBoxLayout(content)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        self.tabs.addTab(scroll, title)
        return scroll, layout

    @staticmethod
    def editor(layout: QVBoxLayout, title: str, value: object) -> JsonEditor:
        label = QLabel(title)
        label.setWordWrap(True)
        layout.addWidget(label)
        editor = JsonEditor(value)
        layout.addWidget(editor)
        return editor

    @staticmethod
    def typed_editor(
        layout: QVBoxLayout, title: str, kind: ContractKind, value: dict[str, Any]
    ) -> NetworkContractForm:
        label = QLabel(title)
        label.setWordWrap(True)
        layout.addWidget(label)
        editor = NetworkContractForm(kind, value)
        layout.addWidget(editor)
        return editor

    def file_field(self, layout: QVBoxLayout) -> QLineEdit:
        bar = QHBoxLayout()
        field = QLineEdit()
        bar.addWidget(field, 1)

        def choose() -> None:
            path, _ = QFileDialog.getOpenFileName(self, "Выбрать локальный документ")
            if path:
                field.setText(path)

        self.button(bar, "Выбрать файл", choose)
        layout.addLayout(bar)
        return field

    def build_import(self) -> None:
        _, layout = self.tab("Сетевые документы")
        self.network_path = self.file_field(layout)
        self.metadata = self.typed_editor(
            layout,
            "Metadata: команду, версию и provenance задаёт оператор. "
            "Роли: asa_running_config_interfaces / asa_running_config_static_routes / "
            "asa_ipv4_rib.",
            "metadata",
            {
                "source_kind": "asa_running_config_interfaces",
                "context_mode": "single",
                "context": None,
                "firewall_mode": "routed",
                "declared_version": "",
                "version_provenance": "operator_declared",
                "version_reference": "",
                "origin": "operator_declared",
                "origin_reference": "",
                "address_family": "ipv4",
                "table_role": "data",
                "table_id": "default",
                "command": "",
                "encoding": "utf-8",
                "selection": "partial",
                "extent": "excerpt",
                "capture_success": False,
                "complete": False,
                "completeness_reference": None,
            },
        )
        self.observation = self.typed_editor(
            layout, "Наблюдение состояния из файла", "observation", {}
        )
        self.baseline_observation = self.typed_editor(
            layout, "Наблюдение базовой конфигурации", "observation", {}
        )
        self.observation_window = self.typed_editor(
            layout, "Согласованный интервал наблюдений", "window", {}
        )
        self.button(layout, "Добавить документ", self.stage)
        self.draft_list = QListWidget()
        layout.addWidget(self.draft_list)
        self.button(layout, "Убрать выбранный документ", self.remove_draft)
        self.button(layout, "Импортировать → новая ревизия", self.import_network)

    def build_inventory(self) -> None:
        _, layout = self.tab("Интерфейсы / маршруты")
        layout.addWidget(QLabel("Configured routes не заменяют наблюдаемую RIB."))
        self.inventory = QListWidget()
        self.inventory.currentRowChanged.connect(self.show_document)
        layout.addWidget(self.inventory)
        self.button(layout, "Полный NetworkImportResult", self.show_import)

    def build_query(self) -> None:
        _, layout = self.tab("Маршрут / локальная ACL")
        self.query_profile = QComboBox()
        self.query_profile.setAccessibleName("Профиль выполнения сетевого запроса")
        self.query_profile.addItem("Legacy — существующие локальные API", "legacy")
        self.query_profile.addItem(
            "Neutral — ASA 9.16 single/routed/IPv4/data/default (условная policy)",
            SUPPORTED_FORWARDING_PROFILE,
        )
        profile_label = QLabel("Явный профиль запроса:")
        profile_label.setBuddy(self.query_profile)
        layout.addWidget(profile_label)
        layout.addWidget(self.query_profile)
        self.query_hint = QLabel(
            "Neutral поддерживает только явно выбранный профиль ASA 9.16. "
            "Ingress и egress задаются вручную; egress не выбирается по маршруту. "
            "Условный policy trace не доказывает итоговую достижимость."
        )
        self.query_hint.setTextFormat(Qt.TextFormat.PlainText)
        self.query_hint.setWordWrap(True)
        layout.addWidget(self.query_hint)
        form = QFormLayout()
        self.query_fields: dict[str, QLineEdit] = {}
        for key, title, default in (
            ("ingress_interface_id", "Входной interface_id", ""),
            ("egress_interface_id", "Явный выходной interface_id (neutral)", ""),
            ("source_ip", "Source IP (acl_input)", ""),
            ("destination_ip", "Destination IP (acl_input)", ""),
            ("protocol", "Протокол tcp/udp/icmp", "tcp"),
            ("destination_port", "Destination port", ""),
            ("table_id", "Таблица", "default"),
        ):
            field = QLineEdit(default)
            self.query_fields[key] = field
            field.textChanged.connect(self._query_inputs_changed)
            form.addRow(title, field)
        layout.addLayout(form)
        self.binding = self.typed_editor(
            layout,
            "PolicyBindingEvidence: source mapping, label↔interface, "
            "основания complete/terminal. Наличие ACL не доказывает полноту цепочки.",
            "binding",
            {
                "policy_id": "",
                "direction": "in",
                "interface_id": "",
                "interface_label": "",
                "interface_mapping_reference": "",
                "source_document_id": "",
                "binding_location": {"source_name": "", "line_start": None},
                "complete": False,
                "completeness_reference": None,
                "declaration_origin": "operator_declared",
                "implicit_action": "unknown",
                "terminal": False,
                "terminal_reference": None,
                "coordinate_space": "acl_input",
            },
        )
        self.binding.textChanged.connect(self._query_inputs_changed)
        self.query_flow = self.editor(
            layout,
            "Neutral FlowApplicability: явные признаки применимости; {} = unknown. "
            "query привязывается к введённому запросу, если не задан явно.",
            {},
        )
        self.query_flow.textChanged.connect(self._query_inputs_changed)
        bar = QHBoxLayout()
        self.query_operation_buttons: list[QPushButton] = []
        for title, operation in (
            ("Выбор RIB", "route"),
            ("Предварительный результат", "reachability"),
            ("Админ. интерфейс", "interface"),
            ("Одна ACL", "policy"),
            ("Локальная композиция", "device"),
        ):
            button = QPushButton(title)
            button.clicked.connect(partial(self.query, operation))
            bar.addWidget(button)
            self.query_operation_buttons.append(button)
        layout.addLayout(bar)
        self.neutral_query_button = QPushButton("Условная policy (neutral; итог unknown)")
        self.neutral_query_button.clicked.connect(self.query_forwarding)
        layout.addWidget(self.neutral_query_button)
        self.query_profile.currentIndexChanged.connect(self._query_profile_changed)
        self._query_profile_changed()

    def _query_inputs_changed(self, *_: Any) -> None:
        self._query_generation += 1
        self.query_result_changed.emit(None)
        self.current_result = None
        if hasattr(self, "output"):
            self.output.clear()
        try:
            self.facts_changed.emit(self.facts_snapshot())
        except ValueError:
            self.facts_changed.emit(None)

    def _query_profile_changed(self, *_: Any) -> None:
        legacy = self.query_profile.currentData() == "legacy"
        for button in self.query_operation_buttons:
            button.setEnabled(legacy)
        self.neutral_query_button.setEnabled(not legacy)
        self.query_flow.setEnabled(not legacy)
        self._query_inputs_changed()

    def facts_snapshot(self) -> NetworkFactsSnapshot:
        """Return exact currently selected facts; never reconstruct parsed data."""
        selected = self.base_combo.currentData()
        if isinstance(selected, MapNetworkFacts):
            return NetworkFactsSnapshot(
                selected.network_import.revision,
                selected.network_import,
                None,
                self._query_generation,
                selected.forwarding,
            )
        revision = self.base().revision
        raw = self.forwarding_results.get(revision.revision_id)
        return NetworkFactsSnapshot(
            revision,
            self.imported.get(revision.revision_id),
            raw if isinstance(raw, ForwardingParseResult) else None,
            self._query_generation,
        )

    def set_map_network_facts(self, record: MapNetworkFacts) -> None:
        """Select saved typed inputs without constructing a session or parser result."""
        saved = MapNetworkFacts(record.network_import, record.forwarding, record.owner)
        previous_block = self.base_combo.blockSignals(True)
        try:
            while self.base_combo.count() > len(self.sessions):
                self.base_combo.removeItem(self.base_combo.count() - 1)
            revision = saved.network_import.revision
            self.base_combo.addItem(
                f"Сохранённый сетевой снимок · {revision.device.device_id} · "
                f"{revision.revision_id}",
                saved,
            )
            self.base_combo.setCurrentIndex(self.base_combo.count() - 1)
        finally:
            self.base_combo.blockSignals(previous_block)
        flow_block = self.query_flow.blockSignals(True)
        try:
            self.query_flow.setPlainText("{}")
        finally:
            self.query_flow.blockSignals(flow_block)
        self._query_inputs_changed()
        self.inventory.clear()
        self.draft_list.clear()
        saved_block = self.saved.blockSignals(True)
        try:
            self.saved.clear()
        finally:
            self.saved.blockSignals(saved_block)
        for document in saved.network_import.documents:
            self.inventory.addItem(
                f"{document.source.source_name} · {document.scope} · {document.status.value}"
            )
        self.status.setText(
            "Сохранённый снимок загружен. Выберите neutral-профиль и задайте новый поток."
        )

    def build_forwarding(self) -> None:
        _, layout = self.tab("Forwarding ASA")
        label = QLabel(
            "Отдельный parser-инвентарь сам по себе не доказывает binding. "
            "Neutral-запрос проверяет точные snapshots; итоговая достижимость остаётся unknown."
        )
        label.setWordWrap(True)
        layout.addWidget(label)
        self.forward_path = self.file_field(layout)
        self.forward_metadata = self.typed_editor(
            layout,
            "ForwardingSource: точная команда, версия и provenance",
            "forward_metadata",
            {
                "purpose": "configuration",
                "command": "",
                "declared_version": "",
                "version_provenance": "operator_declared",
                "version_reference": "",
                "origin": "operator_declared",
                "origin_reference": "",
                "selection": "partial",
                "extent": "excerpt",
                "encoding": "utf-8",
                "capture_success": False,
                "complete_scopes": [],
                "completeness_reference": None,
            },
        )
        self.forward_observation = self.typed_editor(
            layout, "Наблюдение forwarding-документа", "observation", {}
        )
        self.forward_profile = self.typed_editor(
            layout, "Необязательный профиль forwarding", "profile", {}
        )
        self.button(layout, "Разобрать forwarding-контекст", self.forwarding)

    def refresh_sessions(self) -> None:
        self._query_inputs_changed()
        previous = self.base_combo.currentData()
        self.sessions = tuple(
            s for s in self.provider() if s.parse_result.configuration.platform == "asa-9.16"
        )
        self.base_combo.blockSignals(True)
        self.base_combo.clear()
        for session in self.sessions:
            self.base_combo.addItem(
                f"{session.report.device_id} · {session.path.name} · "
                f"{session.revision.revision_id}",
                str(session.revision.revision_id),
            )
        index = self.base_combo.findData(previous)
        if index >= 0:
            self.base_combo.setCurrentIndex(index)
        self.base_combo.blockSignals(False)
        self.context_changed()

    def base(self) -> AnalysisSession:
        index = self.base_combo.currentIndex()
        if index < 0 or index >= len(self.sessions):
            raise ValueError("Нужна реальная ASA-сессия текущего запуска или проверенный исходник.")
        return self.sessions[index]

    def set_project_context(self, project_id: str | None) -> None:
        """Invalidate queued query delivery when the owning project changes."""
        if project_id != self._project_context:
            self._project_context = project_id
            self.query_snapshots.clear()
            self._query_inputs_changed()

    def context_changed(self) -> None:
        selected = self.base_combo.currentData()
        if isinstance(selected, MapNetworkFacts):
            self.set_map_network_facts(selected)
            return
        self.current_result = None
        self.query_result_changed.emit(None)
        try:
            self.facts_changed.emit(self.facts_snapshot())
        except ValueError:
            self.facts_changed.emit(None)
        if hasattr(self, "output"):
            self.output.clear()
            self.inventory.clear()
            self.draft_list.clear()
            self.saved.blockSignals(True)
            self.saved.clear()
            try:
                base_id = self.base().revision.revision_id
                for draft in self.drafts.get(base_id, []):
                    self.draft_list.addItem(
                        f"{draft.path.name} · {draft.metadata.get('source_kind')}"
                    )
                imported = self.imported.get(base_id)
                if imported:
                    for document in imported.documents:
                        self.inventory.addItem(
                            f"{document.source.source_name} · {document.scope} · "
                            f"{document.status.value}"
                        )
                for result_id, label in self.results:
                    if result_id == base_id:
                        self.saved.addItem(label)
                self.status.setText(
                    "Сеть импортирована."
                    if imported
                    else "Сеть не импортирована; полнота неизвестна."
                )
            except ValueError:
                self.status.setText("Для этого раздела нужна ASA-конфигурация текущего запуска.")
            self.saved.blockSignals(False)

    def invalid(self) -> None:
        self.status.setText(
            "Входные данные не приняты. Проверьте подсказку под формой, обязательные поля и файл."
        )

    def stage(self) -> None:
        try:
            base_id = self.base().revision.revision_id
            if not self.network_path.text().strip():
                raise ValueError("Нет файла")
            draft = NetworkDocumentDraft(
                Path(self.network_path.text()),
                self.metadata.values(),
                self.observation.values() or None,
            )
            self.drafts.setdefault(base_id, []).append(draft)
            self.context_changed()
        except (ValueError, TypeError):
            self.invalid()

    def remove_draft(self) -> None:
        index = self.draft_list.currentRow()
        if index >= 0:
            self.drafts[self.base().revision.revision_id].pop(index)
            self.context_changed()

    def run(
        self,
        label: str,
        work: Callable[[], object],
        *,
        query_facts: NetworkFactsSnapshot | None = None,
        query: ReachabilityQuery | None = None,
        query_profile_id: str = "legacy",
        query_generation: int | None = None,
    ) -> None:
        base_id = (
            query_facts.base_revision.revision_id
            if query_facts is not None
            else self.base().revision.revision_id
        )
        ticket = object()
        project_reference = self._project_context
        started_at = datetime.now(UTC)
        self.tickets[base_id, label] = ticket
        self.current_result = None
        self.output.clear()
        self.query_result_changed.emit(None)
        self.status.setText(f"{label}: выполняется; текущий анализ нельзя прервать.")

        def receive(result: object) -> None:
            if self.tickets.get((base_id, label)) is not ticket:
                return
            if project_reference != self._project_context:
                return
            facts_updated = False
            if isinstance(result, (BaseModel, ForwardingQueryResult)):
                self.results[base_id, label] = result
                if isinstance(result, NetworkImportResult):
                    self.imported[base_id] = result
                    facts_updated = True
                if label == "Forwarding (связь не доказана)" and isinstance(result, BaseModel):
                    self.forwarding_results[base_id] = result
                    facts_updated = True
            try:
                same = self.facts_snapshot().base_revision.revision_id == base_id
            except ValueError:
                same = False
            if query_generation is not None and query_generation != self._query_generation:
                return
            if same:
                if facts_updated:
                    self._query_inputs_changed()
                if isinstance(result, JobError):
                    self.status.setText(result.message)
                    if query_facts is not None and query_generation is not None:
                        snapshot = NetworkQuerySnapshot(
                            query_facts,
                            query_profile_id,
                            query,
                            result,
                            query_generation,
                            project_reference,
                            started_at,
                            datetime.now(UTC),
                        )
                        self.query_snapshots[base_id, label] = snapshot
                        self.query_result_changed.emit(snapshot)
                elif isinstance(result, (BaseModel, ForwardingQueryResult)):
                    if not isinstance(self.base_combo.currentData(), MapNetworkFacts):
                        self.context_changed()
                    self.show_result(result)
                    self.status.setText(
                        f"{label}: {type(result).__name__}; ограничения сохранены в JSON."
                    )
                    if isinstance(result, ForwardingQueryResult):
                        reason_text = "; ".join(
                            f"{reason.code}: {reason.message}" for reason in result.reasons
                        )
                        self.status.setText(
                            f"Neutral: {result.status}. Условная policy; "
                            "итоговая достижимость unknown. "
                            + (
                                reason_text
                                or "Ограничения и conditional trace сохранены в результате."
                            )
                        )
                    if query_facts is not None and query_generation is not None:
                        completed_query = query
                        if completed_query is None and isinstance(result, BaseModel):
                            candidate = getattr(result, "query", None)
                            if isinstance(candidate, ReachabilityQuery):
                                completed_query = candidate
                        snapshot = NetworkQuerySnapshot(
                            query_facts,
                            query_profile_id,
                            completed_query,
                            result,
                            query_generation,
                            project_reference,
                            started_at,
                            datetime.now(UTC),
                        )
                        self.query_snapshots[base_id, label] = snapshot
                        self.query_result_changed.emit(snapshot)

        self.runner.submit(work, receive)

    def import_network(self) -> None:
        try:
            base = self.base().revision
            drafts = tuple(self.drafts.get(base.revision_id, []))
            observation = self.baseline_observation.values() or None
            window = self.observation_window.values() or None
            self.run(
                "Сетевой импорт",
                lambda: import_documents(
                    base, drafts, baseline_observation=observation, observation_window=window
                ),
            )
        except (ValueError, TypeError):
            self.invalid()

    def query(self, operation: str) -> None:
        if self.query_profile.currentData() != "legacy" or isinstance(
            self.base_combo.currentData(), MapNetworkFacts
        ):
            self.query_forwarding()
            return
        self._query_inputs_changed()
        try:
            base = self.base().revision
            imported = self.imported.get(base.revision_id)
            revision = imported.revision if imported else base
            values: dict[str, Any] = {
                key: field.text().strip()
                for key, field in self.query_fields.items()
                if key != "egress_interface_id"
            }
            if operation != "interface":
                values["destination_port"] = (
                    int(values["destination_port"]) if values["destination_port"] else None
                )
            binding = self.binding.values() if operation in {"policy", "device"} else None
            query = (
                None
                if operation == "interface"
                else ReachabilityQuery.model_validate(
                    {
                        **values,
                        "revision_id": revision.revision_id,
                        "device_id": revision.device.device_id,
                        "device_context": revision.device.context,
                    }
                )
            )
            op = cast(Literal["route", "reachability", "interface", "policy", "device"], operation)
            self.run(
                f"API {operation}",
                lambda: run_network_query(
                    revision, op, values, binding_values=binding, imported=imported
                ),
                query_facts=self.facts_snapshot(),
                query=query,
                query_generation=self._query_generation,
            )
        except (ValueError, TypeError):
            self.invalid()

    def _forwarding_issue(self, code: str, message: str, *, unsupported: bool = False) -> None:
        reason = AnalysisReason(
            code=code,
            category="unsupported" if unsupported else "missing_evidence",
            message=message,
        )
        self.show_result(reason)
        self.status.setText(f"Neutral: unknown · {code} · {message}")
        self.query_result_changed.emit(
            NetworkQuerySnapshot(
                self.facts_snapshot(),
                str(self.query_profile.currentData()),
                None,
                reason,
                self._query_generation,
                self._project_context,
                datetime.now(UTC),
                datetime.now(UTC),
            )
        )

    def query_forwarding(self) -> None:
        """Dispatch explicit conditional policy with exact imported/parser facts."""
        self._query_inputs_changed()
        try:
            profile_id = self.query_profile.currentData()
            if profile_id != SUPPORTED_FORWARDING_PROFILE:
                self._forwarding_issue(
                    "profile_unsupported", "Выберите явный neutral-профиль.", unsupported=True
                )
                return
            facts = self.facts_snapshot()
            imported = facts.imported
            if imported is None:
                self._forwarding_issue(
                    "network_import_missing", "Нет NetworkImportResult выбранной ревизии."
                )
                return
            saved_inputs = isinstance(self.base_combo.currentData(), MapNetworkFacts)
            raw = self.forwarding_results.get(facts.base_revision.revision_id)
            if not saved_inputs and raw is not None and not isinstance(raw, ForwardingParseResult):
                self._forwarding_issue(
                    "forwarding_parse_contract_unsupported",
                    "Нужен исходный ForwardingParseResult с source_map/diagnostics. "
                    "ForwardingContext или bound-контекст не преобразуется; "
                    "требуется backend adapter.",
                    unsupported=True,
                )
                return
            values: dict[str, Any] = {
                key: field.text().strip() for key, field in self.query_fields.items()
            }
            ingress = values["ingress_interface_id"]
            egress = values.pop("egress_interface_id") or None
            if not ingress:
                self._forwarding_issue(
                    "interface_pair_missing", "Явный ingress отсутствует; интерфейс не угадывается."
                )
                return
            values["destination_port"] = (
                int(values["destination_port"]) if values["destination_port"] else None
            )
            revision = imported.revision
            values.update(
                revision_id=revision.revision_id,
                device_id=revision.device.device_id,
                device_context=revision.device.context,
            )
            query = ReachabilityQuery.model_validate(values)
            flow_values = self.query_flow.values()
            flow = None
            if flow_values:
                flow_values.setdefault("query", query)
                flow = FlowApplicability.model_validate(flow_values)
            generation = self._query_generation
            work = (
                (
                    lambda: run_bound_forwarding_query(
                        imported,
                        facts.bound_context,
                        query,
                        profile_id=profile_id,
                        ingress_interface_id=ingress,
                        egress_interface_id=egress,
                        flow=flow,
                    )
                )
                if saved_inputs or facts.bound_context is not None
                else (
                    lambda: run_forwarding_query(
                        imported,
                        facts.parsed,
                        query,
                        profile_id=profile_id,
                        ingress_interface_id=ingress,
                        egress_interface_id=egress,
                        flow=flow,
                    )
                )
            )
            self.run(
                "Neutral conditional policy (итоговая достижимость unknown)",
                work,
                query_facts=facts,
                query=query,
                query_profile_id=profile_id,
                query_generation=generation,
            )
        except (ValueError, TypeError):
            self.invalid()
            self.query_result_changed.emit(None)

    def forwarding(self) -> None:
        try:
            base = self.base().revision
            if not self.forward_path.text().strip():
                raise ValueError("Нет файла")
            draft = NetworkDocumentDraft(
                Path(self.forward_path.text()),
                self.forward_metadata.values(),
                self.forward_observation.values() or None,
            )
            profile = self.forward_profile.values()
            self.run(
                "Forwarding (связь не доказана)", lambda: parse_forwarding(base, draft, profile)
            )
        except (ValueError, TypeError):
            self.invalid()

    @staticmethod
    def result_json(result: BaseModel | ForwardingQueryResult) -> str:
        if isinstance(result, BaseModel):
            return result.model_dump_json(indent=2)
        return TypeAdapter(ForwardingQueryResult).dump_json(result, indent=2).decode("utf-8")

    def show_result(self, result: BaseModel | ForwardingQueryResult) -> None:
        self.query_result_changed.emit(None)
        self.current_result = result
        self.output.setPlainText(self.result_json(result))
        self.tabs.setCurrentWidget(self.output_tab)

    def show_import(self) -> None:
        try:
            result = self.imported.get(self.base().revision.revision_id)
            if result:
                self.show_result(result)
        except ValueError:
            self.invalid()

    def show_document(self, index: int) -> None:
        try:
            result = self.imported.get(self.base().revision.revision_id)
            if result and 0 <= index < len(result.documents):
                self.show_result(result.documents[index])
        except ValueError:
            self.invalid()

    def show_saved(self) -> None:
        try:
            result = self.results.get((self.base().revision.revision_id, self.saved.currentText()))
            if result:
                self.show_result(result)
                snapshot = self.query_snapshots.get(
                    (self.base().revision.revision_id, self.saved.currentText())
                )
                if snapshot is not None:
                    self.query_result_changed.emit(snapshot)
        except ValueError:
            self.invalid()

    def export_result(self) -> None:
        if self.current_result is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Оригинальный JSON", "network-result.json", "JSON (*.json)"
        )
        if path:
            try:
                Path(path).write_text(self.result_json(self.current_result), encoding="utf-8")
                self.status.setText("Оригинальный JSON сохранён.")
            except OSError:
                self.status.setText("Не удалось сохранить файл. Проверьте доступ.")


def create_widget(
    sessions_provider: Callable[[], tuple[AnalysisSession, ...]], runner: JobRunner
) -> NetworkWidget:
    """Создать Qt-панель; poll фонового обработчика выполняет главное окно."""
    return NetworkWidget(sessions_provider, runner)
