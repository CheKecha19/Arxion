"""Matrix editor and declared-condition assessment of an explicitly selected revision."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import date
from itertools import chain
from pathlib import Path
from threading import Event, Lock
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from PySide6.QtCore import QIODevice, QSaveFile, Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox, QCompleter, QDialog, QDialogButtonBox, QFormLayout, QFileDialog, QGridLayout, QHBoxLayout, QInputDialog,
    QCheckBox, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSplitter, QTabWidget,
    QTextBrowser, QVBoxLayout, QWidget,
)

from firewall_compliance.application.access_context import assigned_session_context, matrix_session_search
from firewall_compliance.application.access_matrix import evaluate_access_matrix, matrix_diagnostics
from firewall_compliance.application.matrix_artifact import MatrixAssessmentArtifact
from firewall_compliance.application.matrix_catalog_bindings import (
    CatalogBindings, freeze_catalog_bindings, split_catalog_bindings,
)
from firewall_compliance.application.matrix_policy import (
    MatrixCoverageCache, matrix_binding_policy_id, matrix_catalog_switch_policy_contexts,
    matrix_policy_supports_zones, matrix_policy_zones,
)
from firewall_compliance.application.matrix_reports import (
    MATRIX_STATE_LABELS, matrix_evidence_preview, matrix_packet_detail, matrix_report_csv, matrix_report_html,
)
from firewall_compliance.application.matrix_requirement_sets import (
    CopyEntry, assignment_ids, assignment_preview, copy_preview, linked_requirements, new_requirements_preview,
)
from firewall_compliance.domain.access_matrix import (
    AccessMatrix, MatrixBoundary, MatrixBoundaryGroup, MatrixCatalogBinding, MatrixRequirement,
    MatrixRequirementSet, MatrixSetAssignment, MatrixZonePair,
)
from firewall_compliance.domain.access_context import AccessContextCondition
from firewall_compliance.domain.access_journey import AccessJourney
from firewall_compliance.domain.matrix_context_inputs import MatrixContextInputs
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.matrix_store import (
    AccessMatrixStore, MatrixAssessmentSummary, MatrixVersionRecord, MatrixVersionSummary,
)
from firewall_compliance.interfaces.desktop.qt_matrix_groups import MatrixGroupsWidget
from firewall_compliance.interfaces.desktop.qt_matrix_context import MatrixContextConditionDialog, MatrixContextInputsDialog
from firewall_compliance.interfaces.desktop.qt_matrix_boundary import MatrixBoundaryDialog, service_from_text
from firewall_compliance.interfaces.desktop.qt_matrix_boundary_groups import (
    MatrixBoundaryGroupDialog, boundary_domain,
)
from firewall_compliance.interfaces.desktop.qt_matrix_bulk import (
    MatrixCopyPreviewDialog, MatrixCopyTargetsDialog,
)
from firewall_compliance.interfaces.desktop.qt_matrix_draft import declared_draft
from firewall_compliance.interfaces.desktop.qt_matrix_draft_preview import (
    MatrixDeclaredDraftPreview, prepare_declared_draft_preview,
)
from firewall_compliance.interfaces.desktop.qt_matrix_inputs import select_matrix_input
from firewall_compliance.interfaces.desktop.qt_matrix_journey import MatrixJourneyEditor, MatrixJourneyReview
from firewall_compliance.interfaces.desktop.qt_matrix_new_requirements import MatrixNewRequirementsDialog
from firewall_compliance.interfaces.desktop.qt_matrix_policy_assignment import MatrixPolicyAssignmentDialog
from firewall_compliance.interfaces.desktop.qt_matrix_portable import (
    ImportedMatrixDraft, MatrixDraftFile, MatrixDraftReferenceError, load_matrix_draft,
    matrix_draft_scopes, remap_matrix_scope,
)
from firewall_compliance.interfaces.desktop.qt_matrix_sets import MatrixSetPreviewDialog, MatrixSetsWidget
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable
from firewall_compliance.interfaces.desktop.qt_matrix_table_import import MatrixTableImportDialog
from firewall_compliance.interfaces.desktop.qt_matrix_zones import MatrixZoneDialog, ZoneChoices, zone_pair_caption

if TYPE_CHECKING:
    from firewall_compliance.application.cloud_sg_revision import CloudSGSelection
    from firewall_compliance.interfaces.desktop.matrix_policy_catalog import MatrixDraftSourceChoice

_ACTIONS = {
    "permit": "Доступ необходим", "allow_optional": "Доступ допустим",
    "deny": "Запретить", "unregulated": "Не регламентировано",
}
_STATES = MATRIX_STATE_LABELS
_MODES = {"declared_rules": "Условия правил", "local_policy": "Локальная политика", "mixed": "Смешанный"}
_STATUSES = {"complete": "Завершена", "partial": "Частичная", "cancelled": "Остановлена"}
type _DraftSourcePicker = Callable[[QWidget], tuple[MatrixDraftSourceChoice, Callable[[], DeviceRevision]] | None]


def _result_lookup(artifact: MatrixAssessmentArtifact) -> tuple[str, ...]:
    groups = {group.group_id: group.name for group in artifact.matrix.groups}
    subjects: dict[str, MatrixRequirement | MatrixBoundary] = {
        row.requirement_id: row for row in artifact.matrix.requirements
    }
    subjects.update((row.boundary_id, row) for row in artifact.matrix.boundaries)
    search_subjects = {
        key: f"{row.source_group} {groups.get(row.source_group, '')} "
             f"{row.destination_group} {groups.get(row.destination_group, '')}"
        for key, row in subjects.items()
    }
    sessions = matrix_session_search(artifact.context_inputs)
    return tuple(
        " ".join((row.requirement_id, search_subjects.get(row.requirement_id, ""), sessions.get(row.requirement_id, ""),
                  (row.context_resolution.source_cidr or "") if row.context_resolution else "",
                  *(key for evidence in row.evidence for key in evidence.related_rule_ids))).casefold()
        for row in artifact.assessment.requirements
    )


def _requirement_search_entry(row: Mapping[str, Any]) -> tuple[str, str]:
    service = row["service"]
    protocol = service["protocol"]
    ports = tuple(
        str(port["start"]) if port["start"] == port["end"] else f"{port['start']}–{port['end']}"
        for port in service["ports"]
    )
    if service["any_ports"]:
        ports = ("*",)
    label = f"{protocol.upper()} {', '.join(ports)}".rstrip()
    lookup = " ".join((
        row["requirement_id"], row.get("policy_id") or "", label,
        *(f"{protocol}/{port.replace('–', '-')}" for port in ports),
    )).casefold()
    return label, lookup


def _write_text(destination: Path, content: str, encoding: str = "utf-8") -> str:
    data = content.encode(encoding)
    stream = QSaveFile(str(destination))
    if not stream.open(QIODevice.OpenModeFlag.WriteOnly):
        raise OSError("Cannot open destination")
    if stream.write(data) != len(data):
        stream.cancelWriting()
        raise OSError("Cannot write destination")
    if not stream.commit():
        raise OSError("Cannot commit destination")
    return destination.name


class AccessMatrixDialog(QDialog):
    """Opening only reads; schema initialization requires explicit Save."""

    def __init__(
        self, store_path: Path, runner: JobRunner, project_id: str,
        revision: DeviceRevision | None = None, parent: QWidget | None = None, *,
        scope_id: str | None = None, profile_id: str = "unspecified",
        profile_version: str = "unspecified", context_valid: Callable[[], bool] | None = None,
        origin_run_id: str | None = None, profile_settings_json: str | None = None,
        origin_item_id: str | None = None,
        bindings: Mapping[tuple[str, str], tuple[str, ...]] | None = None,
        binding_labels: Mapping[tuple[str, str], str] | None = None,
        binding_names: Mapping[tuple[str, str], str] | None = None,
        preferred_catalog: Sequence[tuple[str, str]] = (),
        bindings_by_vrf: Mapping[str, CatalogBindings] | None = None,
        cloud_selection: CloudSGSelection | None = None,
        policy_picker: Callable[[QWidget, str, str], str | None] | None = None,
        draft_source_picker: _DraftSourcePicker | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = AccessMatrixStore(store_path)
        self._runner = runner
        self._project_id = project_id
        self._scope_id = scope_id or project_id
        self._profile_id, self._profile_version = profile_id, profile_version
        self._origin_run_id = origin_run_id
        self._origin_item_id = origin_item_id
        self._cloud_selection = cloud_selection
        self._policy_picker = policy_picker
        self._draft_source_picker = draft_source_picker
        self._context_inputs: MatrixContextInputs | None = None
        self._row_context: AccessContextCondition | None = None
        self._row_zones: MatrixZonePair | None = None
        self._zone_choices_by_policy: dict[str, ZoneChoices] = {}
        self._profile_settings_json = profile_settings_json
        self._bindings = dict(bindings or {})
        self._bindings_by_vrf = dict(bindings_by_vrf or {})
        self._artifact: MatrixAssessmentArtifact | None = None
        self._result_lookup: tuple[str, ...] = ()
        self._result_vrfs: dict[str, str] = {}
        self._result_summary = ""
        self._assessments: tuple[MatrixAssessmentSummary, ...] = ()
        self._history_offset = 0
        self._history_count = 0
        self._revision = revision.as_snapshot() if revision is not None else None
        self._coverage_cache = MatrixCoverageCache(self._revision) if self._revision is not None else None
        self._policies: list[str] = []
        if self._revision is not None:
            parsed = self._revision.parse_result
            switch_bindings = parsed.switch_policies.bindings if parsed.switch_policies is not None else ()
            configured = {
                matrix_binding_policy_id(binding) for binding in switch_bindings if binding.configured_profile is not None
            }
            self._policies = sorted(
                {rule.policy_id for rule in parsed.rules if rule.policy_id is not None},
                key=lambda policy: (policy not in configured, policy),
            )
        self._context_valid = context_valid or (lambda: True)
        self._closed = False
        self._ticket: object | None = None
        self._cancel: Event | None = None
        self._progress_lock = Lock()
        self._progress_value = (0, 0)
        self._progress_timer = QTimer(self)
        self._progress_timer.setInterval(100)
        self._progress_timer.timeout.connect(self._show_progress)
        self._versions: tuple[MatrixVersionSummary, ...] = ()
        self._loaded_version: MatrixVersionRecord | None = None
        self._matrix_id = "access-matrix"
        self._version = "1"
        self._schema_version = "2.0.0"
        self._requirements: list[dict[str, Any]] = []
        self._requirement_search: list[tuple[str, str]] = []
        self._group_labels: dict[str, str] = {}
        self._group_search: dict[str, str] = {}
        self._boundaries: list[MatrixBoundary] = []
        self._boundary_groups: list[MatrixBoundaryGroup] = []
        self._boundary_group_terms: tuple[str, ...] = ()
        self._requirement_sets: list[MatrixRequirementSet] = []
        self._set_assignments: list[MatrixSetAssignment] = []
        self._journeys: list[AccessJourney] = []
        self._linked_rows: dict[str, UUID] = {}
        self._selected: int | None = None
        self.setWindowTitle("Матрица требований доступа")
        self.resize(1120, 800)
        root = QVBoxLayout(self)
        note = QLabel(
            "Вне явного ограничения отсутствие требования означает «не регламентировано». "
            "Сверка показывает условия правил и поддержанные решения локальных политик."
        )
        note.setWordWrap(True)
        root.addWidget(note)
        self.revision_note = QLabel(
            f"Ревизия: {self._revision.revision_id}; область: {self._scope_id}; "
            f"профиль: {profile_id} / {profile_version}"
            if self._revision else "Редактор требований выбранной области. Для сверки откройте «Сверить область»."
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
        self.load_json = QPushButton("Импорт черновика…")
        self.load_json.clicked.connect(self._import_matrix_json)
        version_row.addWidget(self.load_json)
        self.save_json = QPushButton("Экспорт черновика…")
        self.save_json.clicked.connect(self._export_matrix_json)
        version_row.addWidget(self.save_json)
        self.save = QPushButton("Утвердить и сохранить новую версию")
        self.save.clicked.connect(self._save)
        version_row.addWidget(self.save)
        root.addLayout(version_row)
        self.editor = QTabWidget()
        root.addWidget(self.editor, 1)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.editor.addTab(split, "Требования")
        left = QWidget()
        left_layout = QVBoxLayout(left)
        self.groups = MatrixGroupsWidget(
            self, catalog=binding_labels, catalog_names=binding_names, preferred_catalog=preferred_catalog,
        )
        self.groups.changed.connect(self._refresh_group_choices)
        self.editor.addTab(self.groups, "Группы")
        filters = QHBoxLayout()
        self.source_filter = QLineEdit()
        self.source_filter.setPlaceholderText("Откуда · имя или ID")
        self.source_filter.setAccessibleName("Фильтр по группе источника")
        self.destination_filter = QLineEdit()
        self.destination_filter.setPlaceholderText("Куда · имя или ID")
        self.destination_filter.setAccessibleName("Фильтр по группе назначения")
        self.requirement_query = QLineEdit()
        self.requirement_query.setPlaceholderText("ID, политика или сервис")
        self.requirement_query.setAccessibleName("Поиск по требованиям черновика")
        self.requirement_query.setToolTip("Например, R01, USERS-IN или TCP/443.")
        self._requirement_query_timer = QTimer(self)
        self._requirement_query_timer.setSingleShot(True)
        self._requirement_query_timer.setInterval(150)
        self._requirement_query_timer.timeout.connect(lambda: self._refresh_rows(reset=True))
        for field in (self.source_filter, self.destination_filter, self.requirement_query):
            field.setClearButtonEnabled(True)
            field.textChanged.connect(lambda _text: self._requirement_query_timer.start())
            field.returnPressed.connect(lambda: self._refresh_rows(reset=True))
            filters.addWidget(field, 1)
        left_layout.addLayout(filters)
        self.table = MatrixTable(("ID", "Источник", "Назначение", "Требование", "Сервис"))
        self.table.itemSelectionChanged.connect(self._select_row)
        left_layout.addWidget(self.table)
        left_layout.addLayout(self.table.navigation())
        row_buttons = QHBoxLayout()
        new = QPushButton("Новое требование")
        new.clicked.connect(self._new_row)
        remove = QPushButton("Удалить из черновика")
        remove.clicked.connect(self._remove_row)
        row_buttons.addWidget(new)
        row_buttons.addWidget(remove)
        self.import_draft = QPushButton("Черновик из правил…")
        self.import_draft.setEnabled(self._revision is not None or self._draft_source_picker is not None)
        self.import_draft.clicked.connect(self._import_declared_draft)
        row_buttons.addWidget(self.import_draft)
        copy = QPushButton("Копировать…")
        copy.clicked.connect(self._copy_requirements)
        row_buttons.addWidget(copy)
        left_layout.addLayout(row_buttons)
        batch_actions = QGridLayout()
        add_services = QPushButton("Задать несколько сервисов…")
        add_services.setAutoDefault(False)
        add_services.clicked.connect(lambda: self._new_requirements())
        batch_actions.addWidget(add_services, 0, 0)
        paste = QPushButton("Вставить из таблицы…")
        paste.setAutoDefault(False)
        paste.clicked.connect(self._import_matrix_table)
        batch_actions.addWidget(paste, 0, 1)
        from_requirements = QPushButton("Создать ограничение из требований…")
        from_requirements.setAutoDefault(False)
        from_requirements.clicked.connect(self._boundary_from_requirements)
        batch_actions.addWidget(from_requirements, 1, 0)
        if self._policy_picker is not None:
            assign = QPushButton("Назначить политику…")
            assign.setAutoDefault(False)
            assign.clicked.connect(self._assign_policy_to_rows)
            batch_actions.addWidget(assign, 1, 1)
        batch_actions.setColumnStretch(2, 1)
        left_layout.addLayout(batch_actions)
        split.addWidget(left)
        right = QWidget()
        form = QFormLayout(right)
        self.optional_fields = QWidget()
        optional_form = QFormLayout(self.optional_fields)
        optional_form.setContentsMargins(0, 0, 0, 0)
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
                if (completion := selector.completer()) is not None:
                    completion.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
                    completion.setFilterMode(Qt.MatchFlag.MatchContains)
                self.group_choices[key] = selector
                form.addRow("Группа источника" if key == "source_group" else "Группа назначения", selector)
                continue
            field = QLineEdit()
            field.setAccessibleName(label)
            self.fields[key] = field
            target_form = optional_form if key in {"owner", "review_date", "reason", "identity", "schedule"} else form
            target_form.addRow(label, field)
        policies = self._policy_ids()
        if policies:
            self.fields["policy_id"].setPlaceholderText("Введите часть ID политики")
            policy_completion = QCompleter(policies, self.fields["policy_id"])
            policy_completion.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
            policy_completion.setFilterMode(Qt.MatchFlag.MatchContains)
            self.fields["policy_id"].setCompleter(policy_completion)
        if self._policy_picker is not None:
            browse = QPushButton("Выбрать политику из снимков…")
            browse.clicked.connect(self._pick_row_policy)
            form.addRow(browse)
        self.protocol = QComboBox()
        self.protocol.addItems(("tcp", "udp", "icmp", "ip"))
        form.addRow("Протокол", self.protocol)
        self.action = QComboBox()
        for key, title in _ACTIONS.items():
            self.action.addItem(title, key)
        form.addRow("Требование", self.action)
        self.context_condition = QPushButton("Условия пользователя и устройства…")
        self.context_condition.clicked.connect(self._edit_context_condition)
        optional_form.addRow(self.context_condition)
        self.context_label = QLabel()
        self.context_label.setTextFormat(Qt.TextFormat.PlainText)
        self.context_label.setWordWrap(True)
        optional_form.addRow(self.context_label)
        self.zone_button = QPushButton("Зоны политики…")
        self.zone_button.clicked.connect(self._edit_row_zones)
        self.zone_label = QLabel()
        self.zone_label.setTextFormat(Qt.TextFormat.PlainText)
        self.zone_label.setWordWrap(True)
        form.addRow(self.zone_button, self.zone_label)
        self.optional_toggle = QPushButton("Дополнительные условия и владелец")
        self.optional_toggle.setCheckable(True)
        self.optional_toggle.toggled.connect(self.optional_fields.setVisible)
        form.addRow(self.optional_toggle)
        form.addRow(self.optional_fields)
        self.optional_fields.hide()
        self.apply_row = QPushButton("Применить карточку к черновику")
        self.apply_row.clicked.connect(self._apply_row)
        form.addRow(self.apply_row)
        self.requirement_origin = QLabel()
        self.requirement_origin.setTextFormat(Qt.TextFormat.PlainText)
        self.requirement_origin.setWordWrap(True)
        form.addRow(self.requirement_origin)
        editor_scroll = QScrollArea()
        editor_scroll.setWidgetResizable(True)
        editor_scroll.setWidget(right)
        split.addWidget(editor_scroll)
        self.boundary_page = QWidget()
        boundary_layout = QVBoxLayout(self.boundary_page)
        self.boundary_table = MatrixTable(("ID", "Источник", "Назначение", "Политика", "Разрешений"))
        self.boundary_table.doubleClicked.connect(lambda _: self._edit_boundary())
        boundary_layout.addWidget(self.boundary_table, 1)
        boundary_layout.addLayout(self.boundary_table.navigation())
        boundary_actions = QHBoxLayout()
        for title, action in (
            ("Добавить ограничение…", lambda: self._edit_boundary(new=True)),
            ("Изменить…", self._edit_boundary), ("Копировать в другую точку…", self._copy_boundary),
            ("Убрать из черновика", self._remove_boundary),
        ):
            button = QPushButton(title)
            button.clicked.connect(action)
            boundary_actions.addWidget(button)
        boundary_layout.addLayout(boundary_actions)
        if self._policy_picker is not None:
            assign_boundary = QPushButton("Назначить политику строкам…")
            assign_boundary.setAutoDefault(False)
            assign_boundary.clicked.connect(self._assign_policy_to_rows)
            boundary_layout.addWidget(assign_boundary, alignment=Qt.AlignmentFlag.AlignLeft)
        self.editor.addTab(self.boundary_page, "Только перечисленный доступ")
        boundary_group_page = QWidget()
        boundary_group_layout = QVBoxLayout(boundary_group_page)
        self.boundary_group_search = QLineEdit()
        self.boundary_group_search.setPlaceholderText("Название, ID или точка проверки")
        self.boundary_group_search.setAccessibleName("Поиск общих ограничений")
        self.boundary_group_search.textChanged.connect(lambda _: self._refresh_boundary_groups(reset=True))
        boundary_group_layout.addWidget(self.boundary_group_search)
        self.boundary_group_table = MatrixTable(("Общее ограничение", "ID", "Точки проверки", "Область"))
        self.boundary_group_table.setAccessibleName("Общие ограничения доступа")
        self.boundary_group_table.doubleClicked.connect(lambda _: self._edit_boundary_group())
        boundary_group_layout.addWidget(self.boundary_group_table, 1)
        boundary_group_layout.addLayout(self.boundary_group_table.navigation())
        boundary_group_actions = QHBoxLayout()
        for title, action in (
            ("Объединить ограничения…", lambda: self._edit_boundary_group(new=True)),
            ("Изменить…", self._edit_boundary_group),
            ("Убрать объединение", self._remove_boundary_group),
        ):
            button = QPushButton(title)
            button.clicked.connect(action)
            boundary_group_actions.addWidget(button)
        boundary_group_actions.addStretch()
        boundary_group_layout.addLayout(boundary_group_actions)
        self.editor.addTab(boundary_group_page, "Общие ограничения")
        self.sets = MatrixSetsWidget(self)
        self.sets.create_requested.connect(self._create_set)
        self.sets.revise_requested.connect(lambda: self._create_set(revise=True))
        self.sets.view_requested.connect(self._view_set)
        self.sets.assign_requested.connect(self._assign_set)
        self.sets.edit_groups_requested.connect(self._edit_assignment_groups)
        self.sets.refresh_requested.connect(self._refresh_assignment)
        self.sets.remove_requested.connect(self._remove_assignment)
        self.editor.addTab(self.sets, "Наборы требований")
        journey_page = QWidget()
        journey_layout = QVBoxLayout(journey_page)
        self.journey_table = MatrixTable(("Цепочка", "Участки", "Область"))
        self.journey_table.setAccessibleName("Цепочки требований доступа")
        self.journey_table.horizontalHeader().setStretchLastSection(True)
        journey_layout.addWidget(self.journey_table, 1)
        journey_layout.addLayout(self.journey_table.navigation())
        journey_actions = QHBoxLayout()
        for title, action in (
            ("Добавить цепочку…", lambda: self._edit_journey(new=True)),
            ("Изменить…", self._edit_journey), ("Убрать из черновика", self._remove_journey),
            ("Разобрать по сохранённым сверкам…", self._review_journey),
        ):
            button = QPushButton(title)
            button.clicked.connect(action)
            journey_actions.addWidget(button)
        journey_layout.addLayout(journey_actions)
        self.editor.addTab(journey_page, "Цепочки доступа")
        controls = QHBoxLayout()
        self.validate = QPushButton("Проверить структуру")
        self.validate.clicked.connect(self._validate)
        self.evaluate = QPushButton("Сверить с выбранной ревизией")
        self.evaluate.clicked.connect(self._evaluate)
        controls.addWidget(self.validate)
        controls.addWidget(self.evaluate)
        self.context_inputs_button = QPushButton("Свидетельства о сеансах…")
        self.context_inputs_button.clicked.connect(self._edit_context_inputs)
        controls.addWidget(self.context_inputs_button)
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
        self.compare_assessment = QPushButton("Сравнить с открытой сверкой")
        self.compare_assessment.clicked.connect(self._compare_assessment)
        self.assessments.currentIndexChanged.connect(self._history_controls)
        history.addWidget(self.compare_assessment)
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
        self.cancel = QPushButton("Остановить сверку")
        self.cancel.clicked.connect(self._cancel_evaluation)
        self.cancel.hide()
        root.addWidget(self.cancel)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        result_split = QSplitter(Qt.Orientation.Horizontal)
        self.result_table = MatrixTable(("Требование", "Результат", "Основание"))
        self.result_table.setAccessibleName("Результаты сохранённой сверки матрицы")
        self.result_table.itemSelectionChanged.connect(self._show_result_row)
        self.result_table.horizontalHeader().setStretchLastSection(True)
        result_page = QWidget()
        result_layout = QVBoxLayout(result_page)
        self.result_filter = QComboBox()
        self.result_filter.addItem("Все результаты", None)
        for state, label in _STATES.items():
            self.result_filter.addItem(label, state)
        self.result_filter.currentIndexChanged.connect(self._refresh_results)
        self.result_query = QLineEdit()
        self.result_query.setPlaceholderText("Группа, требование, правило или сеанс")
        self.result_query.setAccessibleName("Поиск по всем строкам сверки")
        self._result_query_timer = QTimer(self)
        self._result_query_timer.setSingleShot(True)
        self._result_query_timer.setInterval(150)
        self._result_query_timer.timeout.connect(self._refresh_results)
        self.result_query.textChanged.connect(lambda _text: self._result_query_timer.start())
        filters = QHBoxLayout()
        filters.addWidget(self.result_query, 1)
        filters.addWidget(self.result_filter)
        result_layout.addLayout(filters)
        result_layout.addWidget(self.result_table, 1)
        result_layout.addLayout(self.result_table.navigation())
        result_split.addWidget(result_page)
        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        self.result.setAccessibleName("Диагностика матрицы и доказательства")
        details_page = QWidget()
        details_layout = QVBoxLayout(details_page)
        details_layout.addWidget(self.result, 1)
        self.path_button = QPushButton("Разобрать путь между IP…")
        self.path_button.clicked.connect(self._open_path)
        details_layout.addWidget(self.path_button, 0, Qt.AlignmentFlag.AlignLeft)
        result_split.addWidget(details_page)
        result_split.setMaximumHeight(260)
        root.addWidget(result_split)
        exports = QHBoxLayout()
        self.filtered_report = QCheckBox("Текущая выборка в HTML и CSV")
        self.filtered_report.setChecked(True)
        exports.addWidget(self.filtered_report)
        self.preview_report = QPushButton("Предпросмотр результата")
        self.preview_report.clicked.connect(self._preview_report)
        exports.addWidget(self.preview_report)
        self.export_buttons: list[QPushButton] = []
        for kind in ("html", "json", "csv"):
            button = QPushButton("Сохранить " + kind.upper())
            if kind == "json":
                button.setToolTip("Полный артефакт сверки с исходными данными и доказательствами")
            button.clicked.connect(lambda _checked=False, kind=kind: self._export_report(kind))
            self.export_buttons.append(button)
            exports.addWidget(button)
        root.addLayout(exports)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self.finished.connect(self._finish)
        self._report_controls()
        self._new_row()
        self._reload()

    def _finish(self, _result: int) -> None:
        self._closed = True
        self._ticket = None
        self._cancel_evaluation()
        self._progress_timer.stop()
        self._requirement_query_timer.stop()

    def _cancel_evaluation(self) -> None:
        if self._cancel is not None:
            self._cancel.set()
            self.cancel.setEnabled(False)
            self.status.setText("Останавливаем сверку после текущего участка…")

    def _record_progress(self, completed: int, total: int) -> None:
        with self._progress_lock:
            self._progress_value = completed, total

    def _show_progress(self) -> None:
        with self._progress_lock:
            completed, total = self._progress_value
        if total > 0:
            self.progress.setRange(0, total)
            self.progress.setValue(completed)
            self.progress.setFormat(f"Проверено {completed} из {total}")

    def _job(self, work: Callable[[], object], done: Callable[[Any], None]) -> None:
        if self._closed or not self._context_valid():
            self.reject()
            return
        ticket = object()
        self._ticket = ticket
        self.progress.setRange(0, 0)
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
            self._ticket = None
            self._cancel = None
            self._progress_timer.stop()
            self.cancel.hide()
            self.progress.hide()
            for widget in self._job_controls():
                widget.setEnabled(True)
            self.evaluate.setEnabled(self._revision is not None)
            self.import_draft.setEnabled(self._revision is not None or self._draft_source_picker is not None)
            self._history_controls()
            self._report_controls()
            if isinstance(value, JobError):
                self.status.setText("Операция не завершена: " + value.message)
                return
            done(value)

        self._runner.submit(work, complete)

    def _job_controls(self) -> tuple[QWidget, ...]:
        return (
            self.save, self.reload, self.load_json, self.save_json,
            self.validate, self.evaluate, self.import_draft, self.versions, self.grid_button, self.editor,
            self.context_inputs_button,
            self.assessments, self.open_assessment, self.compare_assessment,
            self.history_previous, self.history_next,
            self.result_table, self.result_filter, self.result_query, self.filtered_report,
            self.path_button, self.preview_report, *self.export_buttons,
        )

    def _reload(self) -> None:
        def work() -> tuple[tuple[MatrixVersionSummary, ...], tuple[MatrixAssessmentSummary, ...], int]:
            return (
                self._store.list_version_summaries(self._project_id),
                self._store.list_assessments(self._project_id, offset=self._history_offset),
                self._store.assessment_count(self._project_id),
            )

        def done(value: Any) -> None:
            self._show_assessments(value[1], value[2])
            self._show_versions(value[0])

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
        if not hasattr(self, "history_previous"):
            return
        self.open_assessment.setEnabled(bool(self._assessments))
        selected = self.assessments.currentData()
        self.compare_assessment.setEnabled(
            self._artifact is not None and isinstance(selected, str)
            and selected != str(self._artifact.artifact_id)
        )
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
        if not isinstance(identifier, str):
            return

        def work() -> tuple[MatrixAssessmentArtifact, tuple[str, ...]]:
            artifact = self._store.get_assessment(self._project_id, identifier)
            return artifact, _result_lookup(artifact)

        self._job(work, lambda value: self._show_artifact(*value))

    def _compare_assessment(self) -> None:
        from firewall_compliance.application.matrix_reports import matrix_comparison_html

        before = self._artifact
        identifier = self.assessments.currentData()
        if before is None or not isinstance(identifier, str) or identifier == str(before.artifact_id):
            return

        def work() -> tuple[MatrixAssessmentArtifact, str]:
            after = self._store.get_assessment(self._project_id, identifier)
            return after, matrix_comparison_html(before, after, preview_limit=100)

        def done(value: tuple[MatrixAssessmentArtifact, str]) -> None:
            after, content = value

            def export() -> None:
                filename, _ = QFileDialog.getSaveFileName(
                    self, "Сохранить полное сравнение", "matrix-comparison.html", "HTML (*.html)",
                )
                if filename:
                    self._job(lambda: _write_text(Path(filename), matrix_comparison_html(before, after)),
                              lambda name: self.status.setText("Сохранено сравнение: " + name))

            self._show_preview_report(content, on_export=export)

        self._job(work, done)

    def _show_artifact(self, artifact: MatrixAssessmentArtifact, lookup: tuple[str, ...]) -> None:
        self._artifact = artifact
        self._result_lookup = lookup
        policy_vrfs = matrix_catalog_switch_policy_contexts(artifact.revision)
        identifiers = Counter(row.requirement_id for row in artifact.matrix.requirements)
        identifiers.update(row.boundary_id for row in artifact.matrix.boundaries)
        self._result_vrfs = {
            identifier: vrf
            for identifier, policy_id in chain(
                ((row.requirement_id, row.policy_id) for row in artifact.matrix.requirements),
                ((row.boundary_id, row.policy_id) for row in artifact.matrix.boundaries),
            )
            if identifiers[identifier] == 1 and (vrf := policy_vrfs.get(policy_id or "")) is not None
        }
        value = artifact.assessment
        lines = [
            f"Сохранённая сверка {artifact.artifact_id} · {artifact.created_at.isoformat()}",
            f"Матрица {artifact.matrix.matrix_id} / v{artifact.matrix.version}; ревизия {value.revision_id}",
            f"Область: {value.scope_id}; профиль: {value.profile_id} / {value.profile_version}",
            f"Режим: {_MODES.get(value.mode, value.mode)}. "
            f"Сверка: {_STATUSES.get(value.status, value.status)}. Использованы сохранённые входы.",
        ]
        self.result_filter.blockSignals(True)
        self.result_filter.setCurrentIndex(0)
        self.result_filter.blockSignals(False)
        self.result_query.blockSignals(True)
        self.result_query.clear()
        self.result_query.blockSignals(False)
        self._result_query_timer.stop()
        lines.extend(issue.message for issue in value.diagnostics[:10])
        if len(value.diagnostics) > 10:
            lines.append(f"Сообщений диагностики: {len(value.diagnostics)}. Полный список доступен в HTML.")
        lines.extend(value.limitations)
        lines.append("Выберите требование в таблице для просмотра доказательств.")
        self._result_summary = "\n".join(lines)
        self._refresh_results()
        self._report_controls()
        self._history_controls()
        self.status.setText(f"Сохранённая сверка · {_STATUSES.get(value.status, value.status)}.")

    def _refresh_results(self, *_: object) -> None:
        artifact = self._artifact
        if artifact is None:
            self.result_table.set_rows((), lambda _: (), reset=True)
            return
        state = self.result_filter.currentData()
        terms = self.result_query.text().casefold().split()
        rows = artifact.assessment.requirements

        def values(index: int) -> tuple[str, str, str]:
            row = rows[index]
            state_label = _STATES.get(row.state, row.state)
            if row.attachment_limited:
                state_label += " · Нужны данные о пути"
            return row.requirement_id, state_label, "; ".join(row.reasons)

        indices = [
            index for index, row in enumerate(rows) if state is None or row.state == state
            if all(term in self._result_lookup[index] for term in terms)
        ] if state is not None or terms else range(len(rows))
        self.result_table.set_rows(indices, values, reset=True)

    def _show_result_row(self) -> None:
        artifact = self._artifact
        row = self.result_table.selected_index()
        if artifact is None:
            return
        if row is None:
            self.result.setPlainText(self._result_summary)
            return
        value = artifact.assessment.requirements[row]
        mode = value.mode or artifact.assessment.mode
        evidence_lines: list[str] = []
        if vrf := self._result_vrfs.get(value.requirement_id):
            evidence_lines.append(f"VRF политики · {vrf}")
        preview = matrix_evidence_preview(value.evidence)
        for evidence in preview:
            evidence_lines.append(evidence.summary)
            if detail := matrix_packet_detail(evidence):
                evidence_lines.append(detail)
            if evidence.related_rule_ids:
                evidence_lines.append("Правила · " + ", ".join(evidence.related_rule_ids))
            for location in evidence.source_locations:
                reference = location.object_path or location.object_id
                if reference is None and location.line_start is not None:
                    reference = f"строки {location.line_start}–{location.line_end or location.line_start}"
                evidence_lines.append(f"{location.source_name} · {reference}" if reference else location.source_name)
            evidence_lines.extend(evidence.limitations)
        if len(preview) < len(value.evidence):
            evidence_lines.append(f"Ещё {len(value.evidence) - len(preview)} оснований доступны в полном JSON.")
        if value.context_resolution is not None:
            context = value.context_resolution
            evidence_lines.append(context.message)
            if context.session_id:
                vrf = assigned_session_context(artifact.context_inputs, value.requirement_id, context.session_id)
                evidence_lines.append(" · ".join(part for part in (
                    f"Сеанс {context.session_id}", vrf, context.source_cidr or "адрес не подтверждён",
                ) if part))
        self.result.setPlainText(
            f"Сверка: {artifact.artifact_id}; матрица v{artifact.matrix.version}\n"
            f"Ревизия: {artifact.revision.revision_id}\n"
            f"{value.requirement_id}: {_STATES.get(value.state, value.state)}\n"
            f"Режим: {_MODES.get(mode, mode)}\n\n"
            + "\n".join(value.reasons)
            + ("\n\nДоказательства и ссылки\n" + "\n".join(evidence_lines) if evidence_lines else "")
        )

    def _report_controls(self) -> None:
        for widget in (self.filtered_report, self.preview_report, *self.export_buttons):
            widget.setEnabled(self._artifact is not None)
        revision = self._artifact.revision if self._artifact is not None else self._revision
        self.path_button.setVisible(revision is not None and revision.parse_result.switch_facts is not None)

    def _open_path(self) -> None:
        from firewall_compliance.interfaces.desktop.qt_matrix_path import MatrixPathDialog, matrix_path_prefill

        artifact = self._artifact
        revision = artifact.revision if artifact is not None else self._revision
        if revision is None or revision.parse_result.switch_facts is None:
            return
        status = self.status.text()

        def show(witness: Mapping[str, object]) -> None:
            self.status.setText(status)
            dialog = MatrixPathDialog(revision, witness, self)
            dialog.exec()
            dialog.deleteLater()

        index = self.result_table.selected_index()
        if artifact is not None and index is not None:
            def work() -> dict[str, str]:
                base, by_vrf = split_catalog_bindings(artifact.bindings)
                return matrix_path_prefill(
                    artifact.matrix, artifact.revision, artifact.assessment.requirements[index],
                    scope_id=artifact.assessment.scope_id, bindings=base,
                    bindings_by_vrf=by_vrf, context_inputs=artifact.context_inputs,
                )

            self._job(work, show)
        else:
            show({})

    def _report_indices(self) -> tuple[int, ...] | None:
        if not self.filtered_report.isChecked():
            return None
        if self._result_query_timer.isActive():
            self._result_query_timer.stop()
            self._refresh_results()
        if self.result_filter.currentData() is None and not self.result_query.text().strip():
            return None
        return tuple(self.result_table.filtered_indices())

    def _preview_report(self) -> None:
        artifact = self._artifact
        if artifact is None:
            return
        indices = self._report_indices()
        self._job(lambda: matrix_report_html(artifact, indices, preview_limit=100), self._show_preview_report)

    def _show_preview_report(self, content: str, *, on_export: Callable[[], None] | None = None) -> None:
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
        if on_export is not None:
            buttons.addButton("Сохранить полный отчёт…", QDialogButtonBox.ButtonRole.AcceptRole)
            buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        dialog.deleteLater()
        if accepted and on_export is not None:
            on_export()

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
        indices = self._report_indices() if kind in {"html", "csv"} else None

        def work() -> str:
            if kind == "html":
                text = matrix_report_html(artifact, indices)
            elif kind == "csv":
                text = matrix_report_csv(artifact, indices)
            else:
                text = artifact.model_dump_json(indent=2)
            return _write_text(destination, text, "utf-8-sig" if kind == "csv" else "utf-8")

        self._job(work, lambda name: self.status.setText("Сохранён результат: " + name))

    def _show_versions(self, values: tuple[MatrixVersionSummary, ...]) -> None:
        self._versions = values
        self.versions.blockSignals(True)
        self.versions.clear()
        for value in values:
            self.versions.addItem(f"Версия {value.version} · {value.created_at}")
        self.versions.setCurrentIndex(len(values) - 1)
        self.versions.blockSignals(False)
        if values:
            self._load_selected()
        else:
            self.status.setText("Сохранённых версий пока нет. Заполните черновик требований.")

    def _load_selected(self, *_: Any) -> None:
        index = self.versions.currentIndex()
        if not 0 <= index < len(self._versions):
            return
        version = self._versions[index].version
        self._loaded_version = None
        self._job(lambda: self._store.get_version(self._project_id, version), self._show_version)

    def _show_version(self, record: MatrixVersionRecord) -> None:
        self._loaded_version = record
        self._set_draft_matrix(record.matrix)
        self.status.setText(f"Загружена версия {record.matrix.version}. SHA-256: {record.checksum}")

    def _set_draft_matrix(self, matrix: AccessMatrix) -> None:
        self._context_inputs = None
        self._matrix_id, self._version = matrix.matrix_id, matrix.version
        self._schema_version = matrix.schema_version
        self.groups.set_groups(matrix.groups)
        self._requirements = [row.model_dump(mode="json") for row in matrix.requirements]
        self._requirement_search = [_requirement_search_entry(row) for row in self._requirements]
        self._boundaries = list(matrix.boundaries)
        self._boundary_groups = list(matrix.boundary_groups)
        self._index_boundary_groups()
        self._requirement_sets = list(matrix.requirement_sets)
        self._set_assignments = list(matrix.set_assignments)
        self._journeys = list(matrix.journeys)
        self._refresh_sets()
        self._refresh_journeys()
        self._new_row()
        self._refresh_group_choices()
        self._refresh_boundaries()
        self.boundary_group_search.clear()
        self._refresh_boundary_groups(reset=True)

    def _export_matrix_json(self) -> None:
        matrix = self._draft()
        if matrix is None:
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Экспорт черновика матрицы", "matrix-draft.json", "JSON (*.json)",
        )
        if not filename:
            return
        destination = Path(filename)
        revision_id = str(self._revision.revision_id) if self._revision else None

        def work() -> str:
            package = MatrixDraftFile(
                project_id=self._project_id, revision_id=revision_id, matrix=matrix,
                bindings=self._catalog_bindings(matrix),
            )
            return _write_text(destination, package.model_dump_json(indent=2))

        self._job(work, lambda name: self.status.setText(f"Черновик экспортирован в {name}."))

    def _import_matrix_json(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self, "Импорт черновика матрицы", "", "JSON (*.json)",
        )
        if not filename:
            return
        source = Path(filename)
        revision_id = str(self._revision.revision_id) if self._revision else None

        def work() -> ImportedMatrixDraft | str:
            try:
                return load_matrix_draft(source.read_text(encoding="utf-8-sig"), self._project_id, revision_id)
            except MatrixDraftReferenceError as error:
                return str(error)

        self._job(work, self._preview_imported_draft)

    def _import_matrix_table(self) -> None:
        if self._closed or not self._context_valid() or self._ticket is not None:
            return
        if not self.groups.groups():
            self.editor.setCurrentWidget(self.groups)
            self.status.setText("Сначала создайте группы источников и назначений. Их можно выбрать из каталога.")
            return
        matrix = self._draft()
        if matrix is None:
            return
        dialog = MatrixTableImportDialog(matrix, self._scope_id, self._runner, self)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        batch = dialog.result_batch if accepted else None
        dialog.deleteLater()
        if self._closed or not self._context_valid():
            self.reject()
            return
        if batch is None or batch.errors or not (batch.requirements or batch.boundaries):
            return
        first_requirement, first_boundary = len(self._requirements), len(self._boundaries)
        self._extend_requirements(batch.requirements)
        self._boundaries.extend(batch.boundaries)
        self._schema_version = "2.0.0"
        visible = self._refresh_rows(select=first_requirement if batch.requirements else None)
        self._refresh_boundaries()
        if not batch.requirements and batch.boundaries:
            self.editor.setCurrentWidget(self.boundary_page)
            self.boundary_table.show_index(first_boundary)
        note = " Текущие фильтры скрывают первую добавленную строку." if batch.requirements and not visible else ""
        self.status.setText(
            f"В черновик добавлено требований: {len(batch.requirements)} · закрытых областей: {len(batch.boundaries)}. "
            f"Утвердите новую версию.{note}"
        )

    def _preview_imported_draft(self, imported: ImportedMatrixDraft | str) -> None:
        if isinstance(imported, str):
            self.status.setText(imported)
            return
        matrix = imported.matrix
        scopes = sorted(matrix_draft_scopes(matrix))
        scope_label = ", ".join(scopes[:10]) or "нет"
        if len(scopes) > 10:
            scope_label += f" и ещё {len(scopes) - 10}"
        preview = QMessageBox(self)
        preview.setWindowTitle("Импорт черновика матрицы")
        preview.setTextFormat(Qt.TextFormat.PlainText)
        lines = [
            "Импорт заменит текущий черновик в редакторе.",
            f"Групп {len(matrix.groups)}, требований {len(matrix.requirements)}, ограничений {len(matrix.boundaries)}.",
            f"Общих ограничений {len(matrix.boundary_groups)}, версий наборов {len(matrix.requirement_sets)}, "
            f"назначений {len(matrix.set_assignments)}.",
            f"Области в файле: {scope_label}. Текущая область: {self._scope_id}.",
            "Для записи в историю используйте «Утвердить и сохранить новую версию».",
        ]
        if imported.frozen_references:
            lines.append(f"Ссылок исходного каталога, перенесённых как явные адреса: {imported.frozen_references}.")
        elif imported.same_project:
            lines.append("Ссылки из файла будут оцениваться по каталогу текущего проекта.")
        if imported.context_bound:
            lines.append("Область контекстных требований сохраняется из файла.")
        preview.setText("\n".join(lines))
        preserve = preview.addButton("Заменить черновик", QMessageBox.ButtonRole.AcceptRole)
        remap = None
        if len(scopes) == 1 and scopes[0] != self._scope_id and not imported.context_bound:
            remap = preview.addButton("Заменить и перенести в текущую область", QMessageBox.ButtonRole.ActionRole)
        cancel = preview.addButton(QMessageBox.StandardButton.Cancel)
        preview.setDefaultButton(cancel)
        preview.exec()
        clicked = preview.clickedButton()
        if remap is not None and clicked is remap:
            matrix = remap_matrix_scope(matrix, self._scope_id)
        elif clicked is not preserve:
            return
        self._loaded_version = None
        self.versions.blockSignals(True)
        self.versions.setCurrentIndex(-1)
        self.versions.blockSignals(False)
        self.source_filter.clear()
        self.destination_filter.clear()
        self.requirement_query.clear()
        self._set_draft_matrix(matrix)
        self.status.setText("Файл открыт как черновик. Проверьте области, политики и состав групп перед утверждением.")

    def _assign_policy_to_rows(self) -> None:
        picker = self._policy_picker
        if picker is None or self._closed or not self._context_valid() or self._ticket is not None:
            return
        matrix = self._draft()
        if matrix is None:
            return
        initial_id = None
        if self.editor.currentWidget() is self.boundary_page:
            boundary = self.boundary_table.selected_index()
            if boundary is not None:
                initial_id = self._boundaries[boundary].boundary_id
        else:
            requirement = self.table.selected_index()
            if requirement is not None:
                initial_id = self._requirements[requirement]["requirement_id"]
        dialog = MatrixPolicyAssignmentDialog(
            matrix, self._scope_id, self._runner, picker, self, linked=self._linked_rows, initial_id=initial_id,
        )
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        batch = dialog.batch if accepted else None
        dialog.deleteLater()
        if self._closed or not self._context_valid():
            self.reject()
            return
        if batch is None or batch.errors:
            return
        for index, row in batch.requirements.items():
            data = row.model_dump(mode="json")
            self._requirements[index] = data
            self._requirement_search[index] = _requirement_search_entry(data)
        for index, boundary_row in batch.boundaries.items():
            self._boundaries[index] = boundary_row
        self._schema_version = "2.0.0"
        selected = self.table.selected_index()
        visible = self._refresh_rows(select=selected)
        if not visible and self._selected in batch.requirements:
            self._new_row()
        boundary = self.boundary_table.selected_index()
        self._refresh_boundaries()
        if boundary is not None:
            self.boundary_table.show_index(boundary)
        self.status.setText(
            f"Политика назначена в черновике. Требований {len(batch.requirements)} · "
            f"закрытых областей {len(batch.boundaries)}. Утвердите новую версию."
        )

    def _select_requirement_indices(self, title: str) -> tuple[int, ...] | None:
        if self._requirement_query_timer.isActive():
            self._refresh_rows(reset=True)
        filtered = self.table.filtered_indices()
        selected = self.table.selected_index()
        if not filtered:
            self.status.setText("В выборке нет требований.")
            return None
        whole_selection = f"Текущая выборка целиком ({len(filtered)} строк со всех страниц)"
        options = ["Выбранная строка", whole_selection] if selected is not None else [whole_selection]
        choice, accepted = QInputDialog.getItem(
            self, title, "Какие строки использовать", options, editable=False,
        )
        if not accepted:
            return None
        return (selected,) if choice == options[0] and selected is not None else tuple(filtered)

    def _copy_requirements(self) -> None:
        indices = self._select_requirement_indices("Копирование требований")
        if indices is None:
            return
        dialog = MatrixCopyTargetsDialog(self.groups.groups(), len(indices), self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        targets, replace_source = dialog.target_ids, bool(dialog.axis.currentData())
        rows = tuple(self._requirements)

        def work() -> tuple[CopyEntry, ...]:
            existing = tuple(MatrixRequirement.model_validate(row) for row in rows)
            return copy_preview(tuple(existing[index] for index in indices), existing, targets, replace_source)

        self._job(work, self._show_copy_preview)

    def _show_copy_preview(self, entries: tuple[CopyEntry, ...]) -> None:
        dialog = MatrixCopyPreviewDialog(entries, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        group_ids = {group.group_id for group in self._boundary_groups}
        if any(row.requirement_id in group_ids for row in dialog.additions):
            self.status.setText("ID копии совпадает с общим ограничением. Повторите копирование.")
            return
        self._extend_requirements(dialog.additions)
        self._refresh_rows()
        self.status.setText(f"В черновик добавлено {len(dialog.additions)} требований. Утвердите их новой версией.")

    def _new_requirements(self, pair: tuple[str, str] | None = None) -> None:
        if self._closed or not self._context_valid() or self._ticket is not None:
            return
        groups = self.groups.groups()
        if not groups:
            self.editor.setCurrentWidget(self.groups)
            self.status.setText("Сначала создайте группы источников и назначений. Можно выбрать их из каталога.")
            return
        index = self.table.selected_index() if pair is None else None
        current = self._requirements[index] if index is not None else {}
        source_group, destination_group = pair or (current.get("source_group", ""), current.get("destination_group", ""))
        policy_id, zone_pair = "", None
        if current.get("scope_id") == self._scope_id:
            policy_id = current.get("policy_id") or ""
            zone_pair = MatrixZonePair.model_validate(current["zone_pair"]) if current.get("zone_pair") else None
        dialog = MatrixNewRequirementsDialog(
            groups, self._scope_id, self, source_group=source_group, destination_group=destination_group,
            policy_id=policy_id, zone_pair=zone_pair, policy_picker=self._policy_picker,
            zone_choices=self._zone_choices if self._can_pick_zones() else None,
        )
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        candidates = dialog.requirements if accepted else ()
        dialog.deleteLater()
        if not candidates:
            return
        rows = tuple(self._requirements)
        reserved = {row.boundary_id for row in self._boundaries} | {group.group_id for group in self._boundary_groups}

        def work() -> tuple[CopyEntry, ...]:
            existing = tuple(MatrixRequirement.model_validate(row) for row in rows)
            return new_requirements_preview(candidates, existing, reserved_ids=reserved)

        self._job(work, self._show_new_requirements_preview)

    def _show_new_requirements_preview(self, entries: tuple[CopyEntry, ...]) -> None:
        dialog = MatrixCopyPreviewDialog(
            entries, self, title="Предпросмотр требований", origin_header="Сервис №",
            group_names={group.group_id: group.name for group in self.groups.groups()},
        )
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        additions = dialog.additions if accepted else ()
        dialog.deleteLater()
        if self._closed or not self._context_valid():
            self.reject()
            return
        if not additions:
            self.status.setText("Предпросмотр закрыт. Черновик не изменён.")
            return
        first = len(self._requirements)
        self._extend_requirements(additions)
        self._schema_version = "2.0.0"
        self.editor.setCurrentIndex(0)
        visible = self._refresh_rows(select=first)
        note = "" if visible else " Текущие фильтры скрывают первую добавленную строку."
        self.status.setText(f"В черновик добавлено {len(additions)} требований. Утвердите их новой версией.{note}")

    def _refresh_sets(self) -> None:
        self._linked_rows = linked_requirements(self._set_assignments, self._requirement_sets)
        self.sets.set_entries(self._requirement_sets, self._set_assignments)

    def _create_set(self, *, revise: bool = False) -> None:
        old = self.sets.selected_version() if revise else None
        if revise and old is None:
            self.status.setText("Выберите набор, для которого нужно создать версию.")
            return
        title = "Новая версия набора" if old is not None else "Создать набор требований"
        indices = self._select_requirement_indices(title)
        if indices is None:
            return
        name, accepted = QInputDialog.getText(self, title, "Название", text=old.name if old else "")
        if not accepted:
            return
        name = name.strip()
        if not name or len(name) > 256:
            self.status.setText("Название набора должно содержать от 1 до 256 символов.")
            return
        set_id = old.set_id if old else uuid4().hex
        version = 1 + max((row.version for row in self._requirement_sets if row.set_id == set_id), default=0)
        chosen = tuple(self._requirements[index] for index in indices)

        def work() -> MatrixRequirementSet:
            templates = tuple(MatrixRequirement.model_validate(row) for row in chosen)
            return MatrixRequirementSet.create(set_id, version, name, templates)

        def done(new: MatrixRequirementSet) -> None:
            self._requirement_sets.append(new)
            self._schema_version = "2.0.0"
            self._refresh_sets()
            self.status.setText(f"Создана версия {version} набора. Утвердите матрицу после проверки черновика.")

        self._job(work, done)

    def _view_set(self) -> None:
        version = self.sets.selected_version()
        if version is None:
            self.status.setText("Выберите версию набора.")
            return
        rows = tuple(CopyEntry(row, row.requirement_id, "Шаблон") for row in version.templates)
        MatrixSetPreviewDialog("Шаблоны набора", rows, (), self, preview_only=True).exec()

    def _assign_set(self) -> None:
        version = self.sets.selected_version()
        if version is None:
            self.status.setText("Выберите версию набора для назначения.")
            return
        targets = MatrixCopyTargetsDialog(self.groups.groups(), len(version.templates), self, linked=True)
        if targets.exec() != QDialog.DialogCode.Accepted:
            return
        assignment = MatrixSetAssignment(
            assignment_id=uuid4(), set_id=version.set_id, revision_id=version.revision_id,
            axis="source_group" if targets.axis.currentData() else "destination_group",
            group_ids=targets.target_ids,
        )
        self._preview_assignment_change(None, assignment)

    def _edit_assignment_groups(self) -> None:
        assignment = self.sets.selected_assignment()
        if assignment is None:
            return
        version = next(row for row in self._requirement_sets if row.revision_id == assignment.revision_id)
        dialog = MatrixCopyTargetsDialog(
            self.groups.groups(), len(version.templates), self, linked=True, editing=True,
            initial_target_ids=assignment.group_ids, initial_replace_source=assignment.axis == "source_group",
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        if set(dialog.target_ids) == set(assignment.group_ids):
            self.status.setText("Состав групп назначения не изменился.")
            return
        self._preview_assignment_change(assignment, assignment.model_copy(update={"group_ids": dialog.target_ids}))

    def _refresh_assignment(self) -> None:
        assignment = self.sets.selected_assignment()
        if assignment is None:
            self.status.setText("Выберите назначение для обновления.")
            return
        latest = max((row for row in self._requirement_sets if row.set_id == assignment.set_id),
                     key=lambda row: row.version)
        if latest.revision_id == assignment.revision_id:
            self.status.setText("Назначение уже закреплено за последней версией набора.")
            return
        self._preview_assignment_change(assignment, assignment.model_copy(update={"revision_id": latest.revision_id}))

    def _remove_assignment(self) -> None:
        assignment = self.sets.selected_assignment()
        if assignment is None:
            self.status.setText("Выберите назначение для удаления.")
            return
        self._preview_assignment_change(assignment, None)

    def _preview_assignment_change(
        self, previous: MatrixSetAssignment | None, proposed: MatrixSetAssignment | None,
    ) -> None:
        revisions = {row.revision_id: row for row in self._requirement_sets}
        old_ids = set(assignment_ids(previous, revisions[previous.revision_id])) if previous else set()
        raw = tuple(self._requirements)
        group_ids = {group.group_id for group in self.groups.groups()}
        boundaries = tuple(self._boundaries)
        boundary_group_ids = {group.group_id for group in self._boundary_groups}
        journeys = tuple(self._journeys)

        def work() -> tuple[
            tuple[CopyEntry, ...], tuple[MatrixRequirement, ...], tuple[str, ...],
            dict[str, tuple[dict[str, Any], tuple[str, str]]],
        ]:
            previous_rows: list[MatrixRequirement] = []
            existing: list[MatrixRequirement] = []
            for raw_row in raw:
                row = MatrixRequirement.model_validate(raw_row)
                (previous_rows if row.requirement_id in old_ids else existing).append(row)
            before = tuple(previous_rows)
            previous_by_id = {row.requirement_id: row for row in before}
            entries = assignment_preview(
                proposed, revisions[proposed.revision_id], existing, unchanged=previous_by_id,
            ) if proposed else ()
            after = {entry.row.requirement_id: entry.row for entry in entries}
            new_ids = set(after)
            removed = old_ids - new_ids
            modified = {identifier for identifier, row in after.items() if row != previous_by_id.get(identifier)}
            blockers = []
            if any(removed.intersection(boundary.allowed_requirement_ids) for boundary in boundaries):
                blockers.append("Сначала измените ограничения, которые ссылаются на удаляемые требования.")
            if any(
                row is None or (row.requirement, row.scope_id, row.source_group, row.destination_group)
                != ("permit", journey.scope_id, step.source_group, step.destination_group)
                for journey in journeys for step in journey.steps
                if step.requirement_id is not None and (step.requirement_id in removed or step.requirement_id in modified)
                for row in (after.get(step.requirement_id),)
            ):
                blockers.append("Сначала обновите участки цепочек, которые ссылаются на изменяемые требования.")
            if any(
                row.requirement not in {"permit", "allow_optional"}
                or row.scope_id != boundary.scope_id
                or row.policy_id not in (None, boundary.policy_id)
                or row.zone_pair != boundary.zone_pair
                for boundary in boundaries
                for key in modified.intersection(boundary.allowed_requirement_ids)
                for row in (after[key],)
            ):
                blockers.append("Новая строка нарушает область или действие связанного ограничения.")
            if any(boundary.boundary_id in new_ids for boundary in boundaries):
                blockers.append("ID назначенной строки совпадает с ID ограничения.")
            if boundary_group_ids.intersection(new_ids):
                blockers.append("ID назначенной строки совпадает с ID общего ограничения.")
            if any(entry.row.source_group not in group_ids or entry.row.destination_group not in group_ids for entry in entries):
                blockers.append("Некоторые группы шаблона отсутствуют в текущей матрице.")
            if len(after) != len(entries):
                blockers.append("Несколько назначаемых строк имеют одинаковый ID.")
            if len(previous_by_id) != len(before):
                blockers.append("В текущем назначении повторяются ID строк.")
            changed = {}
            if not blockers and all(entry.disposition == "Добавится" for entry in entries):
                for identifier, row in after.items():
                    if identifier in modified:
                        payload = row.model_dump(mode="json")
                        changed[identifier] = payload, _requirement_search_entry(payload)
            return entries, before, tuple(blockers), changed

        def done(value: Any) -> None:
            entries, before, blockers, changed = value
            version_changed = (
                previous is not None and proposed is not None and previous.revision_id != proposed.revision_id
            )
            preview = MatrixSetPreviewDialog(
                "Изменение назначения набора", entries, before, self, blockers=blockers, version_changed=version_changed,
            )
            accepted = preview.exec() == QDialog.DialogCode.Accepted
            preview.deleteLater()
            if not accepted or blockers or any(entry.disposition != "Добавится" for entry in entries):
                return
            next_ids = {entry.row.requirement_id for entry in entries}
            rows, searches = [], []
            for row, search in zip(self._requirements, self._requirement_search, strict=True):
                identifier = row["requirement_id"]
                if identifier in old_ids:
                    if identifier not in next_ids:
                        continue
                    row, search = changed.pop(identifier, (row, search))
                rows.append(row)
                searches.append(search)
            for row, search in changed.values():
                rows.append(row)
                searches.append(search)
            self._requirements = rows
            self._requirement_search = searches
            if previous is not None:
                index = self._set_assignments.index(previous)
                if proposed is None:
                    self._set_assignments.pop(index)
                else:
                    self._set_assignments[index] = proposed
            elif proposed is not None:
                self._set_assignments.append(proposed)
            self._schema_version = "2.0.0"
            self._refresh_sets()
            self._new_row()
            self._refresh_rows()
            self.status.setText("Назначение изменено в черновике. Утвердите новую версию матрицы.")

        self._job(work, done)

    def _extend_requirements(self, additions: Iterable[MatrixRequirement]) -> None:
        for requirement in additions:
            row = requirement.model_dump(mode="json")
            self._requirements.append(row)
            self._requirement_search.append(_requirement_search_entry(row))

    def _refresh_rows(self, *, reset: bool = False, select: int | None = None) -> bool:
        self._requirement_query_timer.stop()
        selected = self.table.selected_index()
        sources, destinations, query = (
            field.text().casefold().split()
            for field in (self.source_filter, self.destination_filter, self.requirement_query)
        )

        def values(index: int) -> tuple[str, str, str, str, str]:
            row = self._requirements[index]
            return (
                row["requirement_id"], self._group_labels.get(row["source_group"], row["source_group"]),
                self._group_labels.get(row["destination_group"], row["destination_group"]),
                _ACTIONS[row["requirement"]], self._requirement_search[index][0],
            )

        def matching_groups(terms: list[str]) -> set[str]:
            return {
                key for key, value in self._group_search.items() if all(term in value for term in terms)
            } if terms else set()

        def matches_group(key: str, terms: list[str], matches: set[str]) -> bool:
            return not terms or key in matches or (
                key not in self._group_search and all(term in key.casefold() for term in terms)
            )

        matching_sources = matching_groups(sources)
        matching_destinations = matching_groups(destinations)
        indices: Sequence[int] = range(len(self._requirements))
        if sources or destinations or query:
            indices = [
                index for index, row in enumerate(self._requirements)
                if matches_group(row["source_group"], sources, matching_sources)
                and matches_group(row["destination_group"], destinations, matching_destinations)
                and (not query or all(term in self._requirement_search[index][1] for term in query))
            ]
        self.table.set_rows(indices, values, reset=reset)
        if select is not None:
            return self.table.show_index(select)
        if selected is not None:
            was_blocked = self.table.blockSignals(True)
            try:
                return self.table.show_index(selected)
            finally:
                self.table.blockSignals(was_blocked)
        return False

    def _new_row(self) -> None:
        self._selected = None
        self._row_context = None
        self._row_zones = None
        self.optional_toggle.setChecked(False)
        self.table.clearSelection()
        for field in self.fields.values():
            field.clear()
        for selector in self.group_choices.values():
            selector.setCurrentIndex(-1)
            selector.clearEditText()
        self.fields["scope_id"].setText(self._scope_id)
        policies = self._policy_ids()
        if len(policies) == 1:
            self.fields["policy_id"].setText(policies[0])
        self.action.setCurrentIndex(self.action.findData("unregulated"))
        self.apply_row.setEnabled(True)
        self.context_condition.setEnabled(True)
        self.zone_button.setEnabled(True)
        self.zone_button.setVisible(self._can_pick_zones())
        self.zone_label.clear()
        self._show_context_condition()
        self.requirement_origin.clear()

    def _select_row(self) -> None:
        index = self.table.selected_index()
        if index is None:
            return
        self._selected = index
        row = self._requirements[index]
        linked = row["requirement_id"] in self._linked_rows
        self.apply_row.setEnabled(not linked)
        self.context_condition.setEnabled(not linked)
        self.zone_button.setEnabled(not linked)
        self._row_context = (
            AccessContextCondition.model_validate(row["access_context"]) if row.get("access_context") else None
        )
        if any(row.get(key) for key in ("access_context", "owner", "review_date", "reason", "identity", "schedule")):
            self.optional_toggle.setChecked(True)
        self._show_context_condition()
        self._row_zones = MatrixZonePair.model_validate(row["zone_pair"]) if row.get("zone_pair") else None
        self.zone_button.setVisible(self._can_pick_zones() or self._row_zones is not None)
        self.zone_label.setText(zone_pair_caption(self._row_zones))
        self.requirement_origin.setText(
            "Строка закреплена за набором. Измените версию или назначение на вкладке «Наборы требований»."
            if linked else ""
        )
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
        current = self._requirements[self._selected] if self._selected is not None else {}
        if current.get("requirement_id") in self._linked_rows:
            return
        try:
            payload: dict[str, Any] = {key: field.text().strip() or None for key, field in self.fields.items()}
            payload.update({key: self._group_choice(selector) for key, selector in self.group_choices.items()})
            if payload["review_date"]:
                payload["review_date"] = date.fromisoformat(payload["review_date"])
            payload["service"] = service_from_text(self.protocol.currentText(), payload.pop("ports") or "")
            payload["requirement"] = self.action.currentData()
            payload["access_context"] = self._row_context
            payload["zone_pair"] = self._row_zones
            row = MatrixRequirement.model_validate(payload).model_dump(mode="json")
        except (ValueError, TypeError):
            self.status.setText("Проверьте ID, область, политику, зоны, дату и сервис карточки.")
            return
        if any(
            existing["requirement_id"] == row["requirement_id"] and index != self._selected
            for index, existing in enumerate(self._requirements)
        ) or any(boundary.boundary_id == row["requirement_id"] for boundary in self._boundaries) or any(
            group.group_id == row["requirement_id"] for group in self._boundary_groups
        ):
            self.status.setText("Такой ID уже используется требованием или ограничением.")
            return
        index = self._selected
        adding = index is None
        search = _requirement_search_entry(row)
        if index is None:
            index = len(self._requirements)
            self._requirements.append(row)
            self._requirement_search.append(search)
        else:
            old_id = self._requirements[index]["requirement_id"]
            if any(
                old_id in boundary.allowed_requirement_ids and (
                    row["requirement_id"] != old_id or row["requirement"] not in {"permit", "allow_optional"}
                    or row["scope_id"] != boundary.scope_id or row["policy_id"] not in (None, boundary.policy_id)
                    or self._row_zones != boundary.zone_pair
                ) for boundary in self._boundaries
            ):
                self.status.setText("Сначала обновите исключения, которые ссылаются на это требование.")
                return
            if any(current.get(key) != row[key] for key in (
                "requirement_id", "requirement", "scope_id", "source_group", "destination_group",
            )) and self._journey_uses(old_id):
                self.status.setText("Сначала обновите связанные участки на вкладке «Цепочки доступа».")
                return
            self._requirements[index] = row
            self._requirement_search[index] = search
        if row["requirement"] == "allow_optional" or row.get("access_context") is not None or self._row_zones is not None:
            self._schema_version = "2.0.0"
        if adding:
            self._new_row()
            self._refresh_rows()
            visible = index in self.table.filtered_indices()
        else:
            visible = self._refresh_rows(select=index)
        self.status.setText(
            "Карточка применена к черновику. Для сохранения создайте новую версию."
            + (" Текущие фильтры скрывают эту строку." if not visible else "")
        )

    def _show_context_condition(self) -> None:
        value = self._row_context
        self.context_label.setText(
            f"{value.group_id} · {'VPN' if value.channel == 'vpn' else 'офис'}"
            + (f" · устройство {value.device_id}" if value.device_id else "")
            + (" · корпоративное устройство обязательно" if value.corporate_device_required else "")
            if value is not None else ""
        )

    def _zone_choices(self, policy_id: str) -> ZoneChoices:
        if self._revision is None:
            return (), ()
        if policy_id not in self._zone_choices_by_policy:
            self._zone_choices_by_policy[policy_id] = matrix_policy_zones(self._revision, policy_id)
        return self._zone_choices_by_policy[policy_id]

    def _can_pick_zones(self) -> bool:
        return self._revision is None or matrix_policy_supports_zones(self._revision)

    def _edit_row_zones(self) -> None:
        dialog = MatrixZoneDialog(self._row_zones, self._zone_choices(self.fields["policy_id"].text().strip()), self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._row_zones = dialog.zone_pair
            self.zone_label.setText(zone_pair_caption(self._row_zones))
        dialog.deleteLater()

    def _edit_context_condition(self) -> None:
        dialog = MatrixContextConditionDialog(self._row_context, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._row_context = dialog.condition
            self._show_context_condition()
        dialog.deleteLater()

    def _edit_context_inputs(self) -> None:
        record = self._loaded_version
        if record is None or self._draft() != record.matrix:
            self.status.setText("Сначала утвердите версию требований для сверки сеансов.")
            return
        if not any(row.access_context is not None and row.scope_id == self._scope_id
                   for row in record.matrix.requirements):
            self.status.setText("В этой области нет требований с условиями пользователя и устройства.")
            return
        dialog = MatrixContextInputsDialog(
            record.matrix, self._project_id, self._scope_id, self._context_inputs, self._runner, self,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._context_inputs = dialog.inputs
            self.status.setText(
                f"Контекстов: {len(dialog.inputs.contexts)} · требований с назначенным сеансом: {len(dialog.inputs.sessions)}."
                if dialog.inputs is not None else "Сверка будет выполнена без снимка сеансов."
            )
        dialog.deleteLater()

    def _remove_row(self) -> None:
        if self._requirement_query_timer.isActive():
            self._refresh_rows(reset=True)
        index = self.table.selected_index()
        if index is None:
            self.status.setText("Выберите требование в таблице.")
            return
        if self._requirements[index]["requirement_id"] in self._linked_rows:
            self.status.setText("Уберите связанное назначение на вкладке «Наборы требований».")
            return
        if self._boundary_uses(self._requirements[index]["requirement_id"]):
            self.status.setText("Перед удалением уберите ссылку на требование из ограничений.")
            return
        if self._journey_uses(self._requirements[index]["requirement_id"]):
            self.status.setText("Перед удалением обновите связанные участки на вкладке «Цепочки доступа».")
            return
        self._requirements.pop(index)
        self._requirement_search.pop(index)
        self._new_row()
        self._refresh_rows()

    def _boundary_uses(self, identifier: str) -> bool:
        return any(identifier in boundary.allowed_requirement_ids for boundary in self._boundaries)

    def _journey_uses(self, identifier: str) -> bool:
        return any(step.requirement_id == identifier for journey in self._journeys for step in journey.steps)

    def _refresh_boundaries(self) -> None:
        def values(index: int) -> tuple[object, ...]:
            row = self._boundaries[index]
            policy = " · ".join(value for value in (row.policy_id, zone_pair_caption(row.zone_pair)) if value)
            return row.boundary_id, row.source_group, row.destination_group, policy, len(row.allowed_requirement_ids)

        self.boundary_table.set_rows(range(len(self._boundaries)), values)

    def _copy_boundary(self) -> None:
        index = self.boundary_table.selected_index()
        if index is not None:
            self._edit_boundary(new=True, template=self._boundaries[index])

    def _boundary_from_requirements(self) -> None:
        if self._closed or not self._context_valid() or self._ticket is not None:
            return
        indices = self._select_requirement_indices("Исключения для нового ограничения")
        if not indices:
            return
        raw = tuple(self._requirements)

        def done(rows: tuple[MatrixRequirement, ...]) -> None:
            self._prepare_boundary_from_requirements(rows, indices)

        self._job(lambda: tuple(MatrixRequirement.model_validate(row) for row in raw), done)

    def _prepare_boundary_from_requirements(
        self, rows: tuple[MatrixRequirement, ...], indices: tuple[int, ...],
    ) -> None:
        if self._closed or not self._context_valid() or self._ticket is not None:
            return
        selected = tuple(rows[index] for index in indices)
        if any(row.requirement not in {"permit", "allow_optional"} for row in selected):
            self.status.setText("Для исключений выберите только необходимые или допустимые взаимодействия.")
            return
        if any(
            row.identity is not None or row.schedule is not None or row.access_context is not None for row in selected
        ):
            self.status.setText("Исключения для всей области требуют адресных строк без условий пользователя или расписания.")
            return
        first = selected[0]
        policies = {row.policy_id for row in selected if row.policy_id is not None}
        if len(policies) > 1 or any(
            row.scope_id != first.scope_id or row.zone_pair != first.zone_pair for row in selected
        ):
            self.status.setText("Выберите разрешения одной области и пары зон, связанные максимум с одной политикой.")
            return
        identifiers = tuple(row.requirement_id for row in selected)
        counts = Counter(row.requirement_id for row in rows)
        counts.update(row.boundary_id for row in self._boundaries)
        counts.update(group.group_id for group in self._boundary_groups)
        if any(counts[identifier] != 1 for identifier in identifiers):
            self.status.setText("ID каждого исключения должен однозначно указывать на одно требование.")
            return
        seed = MatrixBoundary(
            boundary_id="limit-" + uuid4().hex[:12], source_group=first.source_group,
            destination_group=first.destination_group, service=first.service, scope_id=first.scope_id,
            policy_id=next(iter(policies), None), zone_pair=first.zone_pair, allowed_requirement_ids=identifiers,
        )
        self._show_boundary_editor(
            rows, None, None, copied=False, seed=seed,
            seed_source=first.source_group if all(row.source_group == first.source_group for row in selected) else "",
            seed_destination=(
                first.destination_group if all(row.destination_group == first.destination_group for row in selected) else ""
            ),
            seed_service_explicit=all(row.service == first.service for row in selected),
        )

    def _edit_boundary(
        self, *, new: bool = False, template: MatrixBoundary | None = None,
    ) -> None:
        if self._closed or not self._context_valid() or self._ticket is not None:
            return
        index = None if new else self.boundary_table.selected_index()
        if index is None and not new:
            return
        initial = self._boundaries[index] if index is not None else None
        if template is not None:
            initial = template.model_copy(update={
                "boundary_id": "limit-" + uuid4().hex[:12], "policy_id": None, "zone_pair": None,
            })
        raw = tuple(self._requirements)

        def done(rows: tuple[MatrixRequirement, ...]) -> None:
            self._show_boundary_editor(rows, index, initial, copied=template is not None)

        self._job(lambda: tuple(MatrixRequirement.model_validate(row) for row in raw), done)

    def _show_boundary_editor(
        self, rows: tuple[MatrixRequirement, ...], index: int | None, initial: MatrixBoundary | None, *,
        copied: bool, seed: MatrixBoundary | None = None, seed_source: str | None = None,
        seed_destination: str | None = None, seed_service_explicit: bool = True,
    ) -> None:
        if self._closed or not self._context_valid() or self._ticket is not None:
            return
        dialog = MatrixBoundaryDialog(
            self.groups.groups(), rows, self._scope_id, initial, self,
            policies=self._policy_ids(), zone_choices=self._zone_choices if self._can_pick_zones() else None,
            policy_picker=self._policy_picker, seed=seed, seed_source=seed_source, seed_destination=seed_destination,
            seed_service_explicit=seed_service_explicit,
        )
        if copied:
            dialog.identifier.setReadOnly(False)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        value = dialog.boundary
        dialog.deleteLater()
        if not accepted or value is None:
            self.status.setText("Редактор ограничения закрыт.")
            return
        if self._closed or not self._context_valid():
            self.reject()
            return
        if any(row.requirement_id == value.boundary_id for row in rows) or any(
            boundary.boundary_id == value.boundary_id and position != index
            for position, boundary in enumerate(self._boundaries)
        ) or any(
            group.group_id == value.boundary_id for group in self._boundary_groups
        ):
            self.status.setText("Такой ID уже используется требованием или ограничением.")
            return
        if index is None:
            self._boundaries.append(value)
        else:
            current = self._boundaries[index]
            if (
                current.boundary_id != value.boundary_id or boundary_domain(current) != boundary_domain(value)
            ) and self._show_boundary_group_reference(current.boundary_id):
                return
            self._boundaries[index] = value
        self._schema_version = "2.0.0"
        self._refresh_boundaries()
        self.boundary_table.show_index(len(self._boundaries) - 1 if index is None else index)
        self.editor.setCurrentWidget(self.boundary_page)
        self.status.setText("Ограничение в черновике. Сохраните новую версию для сверки.")

    def _remove_boundary(self) -> None:
        index = self.boundary_table.selected_index()
        if index is not None and not self._show_boundary_group_reference(self._boundaries[index].boundary_id):
            self._boundaries.pop(index)
            self._refresh_boundaries()

    def _show_boundary_group_reference(self, identifier: str) -> bool:
        group = next((row for row in self._boundary_groups if identifier in row.boundary_ids), None)
        if group is None:
            return False
        self.status.setText(
            f"Сначала уберите точку из общего ограничения «{group.name}» ({group.group_id})."
        )
        return True

    def _refresh_boundary_groups(self, *, reset: bool = False) -> None:
        tokens = self.boundary_group_search.text().casefold().split()

        def values(index: int) -> tuple[str, str, int, str]:
            group = self._boundary_groups[index]
            return group.name, group.group_id, len(group.boundary_ids), group.scope_id

        indices = (
            [index for index, text in enumerate(self._boundary_group_terms) if all(token in text for token in tokens)]
            if tokens else range(len(self._boundary_groups))
        )
        self.boundary_group_table.set_rows(indices, values, reset=reset)

    def _index_boundary_groups(self) -> None:
        self._boundary_group_terms = tuple(
            " ".join((group.name, group.group_id, *group.boundary_ids, *group.point_names.values())).casefold()
            for group in self._boundary_groups
        )

    def _edit_boundary_group(self, *, new: bool = False) -> None:
        index = None if new else self.boundary_group_table.selected_index()
        if index is None and not new:
            return
        current = self._boundary_groups[index] if index is not None else None
        atomic_ids = Counter(row["requirement_id"] for row in self._requirements)
        atomic_ids.update(row.boundary_id for row in self._boundaries)
        eligible = tuple(row for row in self._boundaries if atomic_ids[row.boundary_id] == 1)
        domains = Counter(boundary_domain(row) for row in eligible if row.scope_id == self._scope_id)
        if current is None and max(domains.values(), default=0) < 2:
            self.status.setText("Добавьте два ограничения с одинаковыми группами, сервисом и областью.")
            return
        unavailable = set(atomic_ids)
        unavailable.update(group.group_id for position, group in enumerate(self._boundary_groups) if position != index)
        dialog = MatrixBoundaryGroupDialog(
            eligible, {group.group_id: group.name for group in self.groups.groups()},
            self._scope_id, current, unavailable, self,
        )
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        value = dialog.value
        dialog.deleteLater()
        if not accepted or value is None:
            return
        if index is None:
            index = len(self._boundary_groups)
            self._boundary_groups.append(value)
        else:
            self._boundary_groups[index] = value
        self._schema_version = "2.0.0"
        self._index_boundary_groups()
        self.boundary_group_search.clear()
        self._refresh_boundary_groups()
        self.boundary_group_table.show_index(index)
        self.status.setText("Общее ограничение в черновике. Утвердите новую версию для сверки области.")

    def _remove_boundary_group(self) -> None:
        index = self.boundary_group_table.selected_index()
        if index is not None:
            self._boundary_groups.pop(index)
            self._index_boundary_groups()
            self._refresh_boundary_groups()
            self.status.setText("Объединение убрано. Точки проверки доступны как отдельные ограничения.")

    def _import_declared_draft(self) -> None:
        revision = self._revision
        if self._ticket is not None:
            return
        if revision is None:
            if self._draft_source_picker is None:
                return
            picked = self._draft_source_picker(self)
            if picked is None:
                return
            source, load_revision = picked

            def loaded(value: DeviceRevision) -> None:
                self._preview_declared_draft(value, source.policy_id, source.provenance)

            self._job(load_revision, loaded)
            return

        policies = self._policy_ids()
        if not policies:
            self.status.setText("В ревизии отсутствуют правила с указанной политикой.")
            return
        if len(policies) > 1:
            index = select_matrix_input(self, policies, title="Политика для черновика", placeholder="ID политики")
            if index is None:
                return
            policy_id = policies[index]
        else:
            policy_id = policies[0]
        self._preview_declared_draft(revision, policy_id)

    def _preview_declared_draft(self, revision: DeviceRevision, policy_id: str, provenance: str = "") -> None:
        zone_pair = None
        choices = matrix_policy_zones(revision, policy_id)
        if any(choices):
            dialog = MatrixZoneDialog(None, choices, self)
            confirmed = dialog.exec() == QDialog.DialogCode.Accepted
            zone_pair = dialog.zone_pair
            dialog.deleteLater()
            if not confirmed:
                self.status.setText("Выбор зоны отменён.")
                return
        existing = self.groups.groups()
        raw_rows = tuple(self._requirements)

        def done(value: Any) -> None:
            groups, rows, skipped = value
            if not rows:
                self.status.setText(
                    f"Нет новых разрешений для предпросмотра. Повторов {skipped['duplicate']}, "
                    f"неподдержанных условий {skipped['unresolved']}, других пар зон {skipped['outside_zone']}, "
                    f"запретов и отключённых правил {skipped['non_allow']}."
                )
                return
            preview = MatrixDeclaredDraftPreview(rows, skipped, self)
            accepted = preview.exec() == QDialog.DialogCode.Accepted
            selected = preview.selected_rows() if accepted else ()
            preview.deleteLater()
            if self._closed or not self._context_valid():
                self.reject()
                return
            if not selected:
                self.status.setText("Предпросмотр закрыт. Черновик не изменён.")
                return
            group_ids = {group.group_id for group in self._boundary_groups}
            if any(row.requirement_id in group_ids for row in selected):
                self.status.setText("ID новой строки совпадает с общим ограничением. Повторите импорт.")
                return
            used = {key for row in selected for key in (row.source_group, row.destination_group)}
            self.groups.set_groups((*existing, *(group for group in groups if group.group_id in used)))
            first_new_row = len(self._requirements)
            self._extend_requirements(selected)
            self._schema_version = "2.0.0"
            self._refresh_group_choices()
            visible = self.table.show_index(first_new_row)
            filter_note = "" if visible else "Первая добавленная строка скрыта текущими фильтрами. "
            self.status.setText(
                f"Добавлено в черновик: {len(selected)} из {len(rows)} предложений. "
                f"{filter_note}Проверьте допустимые взаимодействия перед утверждением."
            )

        def work() -> object:
            groups, rows, skipped = declared_draft(
                revision, self._scope_id, policy_id, existing,
                tuple(MatrixRequirement.model_validate(row) for row in raw_rows),
                zone_pair=zone_pair, provenance=provenance,
            )
            return groups, prepare_declared_draft_preview((*existing, *groups), rows), skipped

        self._job(work, done)

    def _pick_row_policy(self) -> None:
        if self._policy_picker is None:
            return
        policy, scope = self.fields["policy_id"], self.fields["scope_id"]
        selected = self._policy_picker(self, scope.text().strip() or self._scope_id, policy.text().strip())
        if selected is not None:
            policy.setText(selected)

    def _policy_ids(self) -> list[str]:
        return self._policies

    def _refresh_journeys(self) -> None:
        def values(index: int) -> tuple[str, str, str]:
            journey = self._journeys[index]
            return journey.name, str(len(journey.steps)), journey.scope_id

        self.journey_table.set_rows(range(len(self._journeys)), values)

    def _edit_journey(self, *, new: bool = False) -> None:
        index = None if new else self.journey_table.selected_index()
        if not new and index is None:
            return
        matrix = self._draft(include_journeys=False)
        if matrix is None:
            return
        current = self._journeys[index] if index is not None else None
        dialog = MatrixJourneyEditor(matrix, self._scope_id, current, self)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        value = dialog.value
        dialog.deleteLater()
        if not accepted or value is None:
            return
        if index is None:
            index = len(self._journeys)
            self._journeys.append(value)
        else:
            self._journeys[index] = value
        self._schema_version = "2.0.0"
        self._refresh_journeys()
        self.journey_table.show_index(index)
        self.status.setText("Цепочка сохранена в черновике. Утвердите новую версию матрицы.")

    def _remove_journey(self) -> None:
        index = self.journey_table.selected_index()
        if index is not None:
            del self._journeys[index]
            self._refresh_journeys()

    def _review_journey(self) -> None:
        index = self.journey_table.selected_index()
        if index is None:
            return
        record = self._loaded_version
        if record is None or self._draft() != record.matrix:
            self.status.setText("Утвердите версию матрицы, чтобы собрать доказательства по цепочке.")
            return
        journey, current = self._journeys[index], self._artifact

        def done(summaries: tuple[MatrixAssessmentSummary, ...]) -> None:
            dialog = MatrixJourneyReview(
                self._store, self._runner, self._project_id, record.matrix,
                journey, summaries, current, self._context_valid, self,
            )
            dialog.exec()
            dialog.deleteLater()

        self._job(lambda: self._store.assessment_summaries_for_version(self._project_id, record.matrix.version), done)

    def _draft(self, *, include_journeys: bool = True) -> AccessMatrix | None:
        try:
            return AccessMatrix.model_validate({
                "schema_version": self._schema_version, "matrix_id": self._matrix_id, "version": self._version,
                "groups": self.groups.groups(), "requirements": self._requirements,
                "boundaries": self._boundaries,
                "boundary_groups": self._boundary_groups,
                "requirement_sets": self._requirement_sets, "set_assignments": self._set_assignments,
                "journeys": self._journeys if include_journeys else (),
            })
        except (ValueError, TypeError):
            self.status.setText("Проверьте группы, требования и ссылки в цепочках и общих ограничениях.")
            return None

    def _open_grid(self) -> None:
        from firewall_compliance.interfaces.desktop.qt_matrix_grid import MatrixGridDialog

        if self._closed or not self._context_valid():
            return
        matrix = self._draft()
        if matrix is None:
            return
        dialog = MatrixGridDialog(matrix, self, scope_id=self._scope_id)
        boundary_index: int | None = None
        new_pair: tuple[str, str] | None = None

        def select_boundary(index: int) -> None:
            nonlocal boundary_index
            boundary_index = index

        def select_new_pair(source: str, destination: str) -> None:
            nonlocal new_pair
            new_pair = source, destination

        dialog.requirement_requested.connect(self._open_grid_requirement)
        dialog.boundary_requested.connect(select_boundary)
        dialog.new_requirements_requested.connect(select_new_pair)
        dialog.exec()
        dialog.deleteLater()
        if boundary_index is not None:
            self._open_grid_boundary(boundary_index)
        elif new_pair is not None:
            self._new_requirements(new_pair)

    def _open_grid_requirement(self, index: int) -> None:
        if self._closed or not self._context_valid() or not 0 <= index < len(self._requirements):
            return
        row = self._requirements[index]
        changed = False
        for field, value in (
            (self.source_filter, self._group_search.get(row["source_group"], row["source_group"].casefold())),
            (self.destination_filter, self._group_search.get(row["destination_group"], row["destination_group"].casefold())),
            (self.requirement_query, self._requirement_search[index][1]),
        ):
            if not all(term in value for term in field.text().casefold().split()):
                was_blocked = field.blockSignals(True)
                field.clear()
                field.blockSignals(was_blocked)
                changed = True
        if changed or self._requirement_query_timer.isActive():
            self._refresh_rows(reset=True, select=index)
        else:
            self.table.show_index(index)
        self.editor.setCurrentIndex(0)

    def _open_grid_boundary(self, index: int) -> None:
        if self._closed or not self._context_valid() or not 0 <= index < len(self._boundaries):
            return
        self.editor.setCurrentWidget(self.boundary_page)
        if self.boundary_table.show_index(index):
            self._edit_boundary()

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
        groups = self.groups.groups()
        self._group_labels = {group.group_id: f"{group.name} · {group.group_id}" for group in groups}
        self._group_search = {key: label.casefold() for key, label in self._group_labels.items()}
        for selector in self.group_choices.values():
            previous = self._group_choice(selector)
            selector.blockSignals(True)
            selector.clear()
            for group in groups:
                selector.addItem(f"{group.name} · {group.group_id}", group.group_id)
            self._set_group_choice(selector, previous)
            selector.blockSignals(False)
        if any(member.kind in {"logical_network", "resource"} for group in groups for member in group.members):
            self._schema_version = "2.0.0"
        self._refresh_rows()

    def _validate(self) -> None:
        matrix = self._draft()
        if matrix is not None:
            def done(values: Any) -> None:
                self._artifact = None
                self._refresh_results()
                self._report_controls()
                self._history_controls()
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

        def work() -> tuple[MatrixVersionSummary, ...]:
            self._store.initialize()
            self._store.append(self._project_id, matrix)
            return self._store.list_version_summaries(self._project_id)

        self._job(work, self._show_versions)

    def _catalog_bindings(self, matrix: AccessMatrix, *, scoped: bool = False) -> tuple[MatrixCatalogBinding, ...]:
        referenced = {
            (member.kind, member.value) for group in matrix.groups for member in group.members
            if member.kind in {"logical_network", "resource"}
        }
        return freeze_catalog_bindings(
            self._bindings, self._bindings_by_vrf if scoped and matrix.schema_version == "2.0.0" else None,
            referenced=referenced,
        )

    def _evaluate(self) -> None:
        matrix = self._draft()
        revision = self._revision
        if matrix is None or revision is None:
            return
        if self._cloud_selection is not None and matrix.schema_version == "1.0.0":
            answer = QMessageBox.question(
                self, "Версия матрицы", "Для сверки облачных групп нужна матрица 2.0.0. "
                "Подготовить черновик новой версии?",
            )
            if answer == QMessageBox.StandardButton.Yes:
                self._schema_version = "2.0.0"
                self.status.setText("Черновик переведён в формат 2.0.0. Утвердите версию перед сверкой.")
            return
        record = self._loaded_version
        if record is None or matrix != record.matrix:
            self.status.setText("Сначала сохраните изменения новой версией матрицы, затем выполните сверку.")
            return
        matrix = record.matrix
        context_inputs = self._context_inputs if matrix.schema_version == "2.0.0" else None
        if context_inputs is not None:
            contextual = {row.requirement_id for row in matrix.requirements if row.access_context is not None}
            context_inputs = context_inputs.model_copy(update={
                "sessions": tuple(item for item in context_inputs.sessions if item.requirement_id in contextual),
            })
        cancel = Event()
        self._cancel = cancel
        self._record_progress(0, 0)
        self.cancel.setEnabled(matrix.schema_version == "2.0.0")
        self.cancel.setVisible(matrix.schema_version == "2.0.0")
        self._progress_timer.start()

        def work() -> tuple[MatrixAssessmentArtifact, tuple[str, ...], tuple[MatrixAssessmentSummary, ...], int]:
            bindings = self._catalog_bindings(matrix, scoped=True)
            base, by_vrf = split_catalog_bindings(bindings)
            value = evaluate_access_matrix(
                matrix, revision, scope_id=self._scope_id,
                profile_id=self._profile_id, profile_version=self._profile_version,
                bindings=base, bindings_by_vrf=by_vrf,
                cancelled=cancel.is_set, progress=self._record_progress,
                context_inputs=context_inputs, project_id=self._project_id,
                coverage_cache=self._coverage_cache,
            )
            artifact = MatrixAssessmentArtifact(
                schema_version=matrix.schema_version,
                origin_project_id=self._project_id, origin_run_id=self._origin_run_id,
                origin_item_id=self._origin_item_id,
                matrix=matrix, revision=revision, profile_settings_json=self._profile_settings_json,
                assessment=value,
                bindings=bindings,
                cloud_selection=self._cloud_selection if matrix.schema_version == "2.0.0" else None,
                context_inputs=context_inputs,
            )
            self._store.initialize()
            identifier = self._store.save_assessment(artifact)
            saved = self._store.get_assessment(self._project_id, identifier)
            return (
                saved, _result_lookup(saved),
                self._store.list_assessments(self._project_id),
                self._store.assessment_count(self._project_id),
            )

        def done(value: Any) -> None:
            self._history_offset = 0
            self._show_artifact(value[0], value[1])
            self._show_assessments(value[2], value[3])

        self._job(work, done)
