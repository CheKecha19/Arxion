"""Постраничное сравнение двух сохранённых сверок матрицы."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from uuid import UUID

from PySide6.QtCore import QSignalBlocker, QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QHeaderView, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QSplitter, QTabWidget, QVBoxLayout, QWidget,
)

from firewall_compliance.application.matrix_boundary_groups import (
    MatrixBoundaryGroupAssessment, MatrixBoundaryPointAssessment, evaluate_boundary_groups,
)
from firewall_compliance.application.matrix_comparison import MatrixScopeChange
from firewall_compliance.application.matrix_reports import (
    MATRIX_BOUNDARY_GROUP_LABELS, MATRIX_BOUNDARY_POINT_LABELS, MATRIX_MODE_LABELS, MATRIX_STATE_LABELS,
    matrix_evidence_preview, matrix_packet_detail, matrix_scope_source_notes, matrix_service_label,
)
from firewall_compliance.application.matrix_scope_assessment import (
    HISTORICAL_BASELINE_NOTE, MatrixScopeAssessment, MatrixScopeRowAssessment, MatrixScopeSource,
)
from firewall_compliance.domain.access_matrix import AccessMatrix
from firewall_compliance.interfaces.desktop.qt_matrix_comparison_findings import (
    MatrixComparisonFindings, MatrixFindingComparisonRow,
)
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable

_OUTCOMES = {
    "changed": "Изменился вывод",
    "source_changed": "Изменился источник",
    "evidence_changed": "Изменились основания",
    "inconclusive": "Недостаточно данных для сравнения",
    "unchanged": "Без изменений",
}
_DIRECTIONS = {
    "improved": "Устранено отклонение",
    "regressed": "Появилось отклонение",
}
_ORDER = {
    key: index for index, key in enumerate((
        "regressed", "inconclusive", "changed", "source_changed", "evidence_changed", "improved", "unchanged",
    ))
}
_ASSESSMENT_STATUS = {"complete": "завершена", "partial": "частичная", "cancelled": "отменена"}


@dataclass(frozen=True, slots=True)
class _ComparisonRow:
    columns: tuple[str, str, str, str, str, str]
    search: str


@dataclass(frozen=True, slots=True)
class _ComparedPoint:
    identifier: str
    columns: tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class _ComparedBoundary:
    columns: tuple[str, str, str]
    points: tuple[_ComparedPoint, ...]


@dataclass(frozen=True, slots=True)
class MatrixScopeComparisonView:
    changes: tuple[MatrixScopeChange, ...]
    rows: tuple[_ComparisonRow, ...]
    row_order: tuple[int, ...]
    boundaries: tuple[_ComparedBoundary, ...]
    indices_by_id: Mapping[str, int]
    before_sources: Mapping[UUID, MatrixScopeSource]
    after_sources: Mapping[UUID, MatrixScopeSource]
    before_notes: Mapping[str, tuple[str, ...]]
    after_notes: Mapping[str, tuple[str, ...]]


def _search_key(value: str) -> str:
    return value.casefold().replace("/", " ")


def _row_status(row: MatrixScopeRowAssessment | None) -> str:
    if row is None:
        return "Строка отсутствует"
    assessment = row.assessment
    result = MATRIX_STATE_LABELS[assessment.state]
    if assessment.attachment_limited:
        return result + " · нужны данные о пути"
    return result


def _boundary_label(result: MatrixBoundaryGroupAssessment) -> str:
    return (
        f"{MATRIX_BOUNDARY_GROUP_LABELS[result.state]} · лишние разрешения {result.excess_count}"
        f" · пробелы {result.gap_count}"
    )


def _point_label(point: MatrixBoundaryPointAssessment) -> str:
    value = MATRIX_BOUNDARY_POINT_LABELS[point.status]
    return f"{value} · {point.gap}" if point.gap else value


def _prepare_boundaries(
    matrix: AccessMatrix, before: MatrixScopeAssessment, after: MatrixScopeAssessment,
) -> tuple[_ComparedBoundary, ...]:
    old = {summary.group.group_id: summary for summary in evaluate_boundary_groups(matrix, before)}
    result = []
    for current in evaluate_boundary_groups(matrix, after):
        group = current.group
        previous = old[group.group_id]
        points = []
        for old_point, new_point in zip(previous.points, current.points, strict=True):
            identifier = new_point.boundary.boundary_id
            name = group.point_names.get(identifier, identifier)
            label = name if name == identifier else f"{name} · {identifier}"
            points.append(_ComparedPoint(identifier, (label, _point_label(old_point), _point_label(new_point))))
        name = group.name if group.name == group.group_id else f"{group.name} · {group.group_id}"
        result.append(_ComparedBoundary((name, _boundary_label(previous), _boundary_label(current)), tuple(points)))
    return tuple(result)


def prepare_matrix_scope_comparison(
    before: MatrixScopeAssessment, after: MatrixScopeAssessment,
    changes: Sequence[MatrixScopeChange], matrix: AccessMatrix | None,
) -> MatrixScopeComparisonView:
    """Подготовить подписи и поиск до открытия окна сравнения."""
    groups = {group.group_id: group.name for group in matrix.groups} if matrix is not None else {}
    services: dict[tuple[str, str], str] = {}
    if matrix is not None:
        services.update(
            (("requirement", row.requirement_id), matrix_service_label(row.service)) for row in matrix.requirements
        )
        services.update((("boundary", row.boundary_id), matrix_service_label(row.service)) for row in matrix.boundaries)
    before_sources = {source.revision_id: source for source in before.sources}
    after_sources = {source.revision_id: source for source in after.sources}
    rows = []
    ordered: list[list[int]] = [[] for _ in _ORDER]
    for index, change in enumerate(changes):
        subject = change.after or change.before
        pair, service = "—", "—"
        terms = [change.requirement_id]
        if subject is not None:
            source_name = groups.get(subject.source_group, subject.source_group)
            destination_name = groups.get(subject.destination_group, subject.destination_group)
            pair = f"{source_name} → {destination_name}"
            service = services.get((subject.kind, change.requirement_id), "—")
            terms.extend((pair, subject.source_group, subject.destination_group, service))
            if subject.kind == "boundary":
                terms.append("закрытая область")
        for row, sources in ((change.before, before_sources), (change.after, after_sources)):
            if row is None:
                continue
            terms.extend((row.policy_id or "", row.policy_vrf or ""))
            if row.zone_pair is not None:
                terms.extend((row.zone_pair.source_zone, row.zone_pair.destination_zone))
            if row.revision_id is not None and (source := sources.get(row.revision_id)) is not None:
                terms.extend((source.device_label, source.device_id))
        columns = (
            change.requirement_id, pair, service, _row_status(change.before), _row_status(change.after),
            _DIRECTIONS[change.direction] if change.direction is not None else _OUTCOMES[change.state],
        )
        rows.append(_ComparisonRow(columns, _search_key(" ".join(terms))))
        ordered[_ORDER[change.direction or change.state]].append(index)
    return MatrixScopeComparisonView(
        tuple(changes), tuple(rows), tuple(index for bucket in ordered for index in bucket),
        _prepare_boundaries(matrix, before, after) if matrix is not None and matrix.boundary_groups else (),
        {change.requirement_id: index for index, change in enumerate(changes)}, before_sources, after_sources,
        matrix_scope_source_notes(before), matrix_scope_source_notes(after),
    )


def _snapshot_caption(result: MatrixScopeAssessment, title: str) -> str:
    text = f"{title} · {result.created_at.isoformat(timespec='seconds')} · сверка {_ASSESSMENT_STATUS[result.status]}"
    historical = next((note.message for note in result.diagnostics if note.code == HISTORICAL_BASELINE_NOTE), None)
    return f"{text}\n{historical}" if historical else text


def _details(
    row: MatrixScopeRowAssessment | None, result: MatrixScopeAssessment,
    sources: Mapping[UUID, MatrixScopeSource], notes: Mapping[str, tuple[str, ...]],
) -> str:
    if row is None:
        return "Строка отсутствует в сохранённой сверке."
    assessment = row.assessment
    lines = [_row_status(row), MATRIX_MODE_LABELS[assessment.mode or result.mode]]
    if assessment.coverage_complete is False:
        lines.append("Охват проверен частично.")
    if row.policy_id:
        lines.append(f"Политика · {row.policy_id}")
    if row.policy_vrf:
        lines.append(f"VRF политики · {row.policy_vrf}")
    if row.zone_pair:
        lines.append(f"Зоны · {row.zone_pair.source_zone} → {row.zone_pair.destination_zone}")
    if row.revision_id is not None and (source := sources.get(row.revision_id)) is not None:
        lines.extend((
            f"Источник · {source.device_label} · {source.device_id} · {source.platform}",
            f"Ревизия · {source.revision_id} · {source.captured_at.isoformat(timespec='seconds')}",
        ))
        if source.device_context:
            lines.append(f"Контекст устройства · {source.device_context}")
        if cloud := source.cloud_selection:
            direction = "входящий" if cloud.direction == "ingress" else "исходящий"
            lines.append(f"Сбор · {cloud.scan_id} · интерфейс {cloud.interface_id} · {direction} IPv{cloud.family}")
            if cloud.group_id:
                lines.append(f"Группа безопасности · {cloud.group_id}")
        elif vmware := source.vmware_origin:
            lines.append(f"Сбор VMware · {vmware.scan_id} · Edge Gateway {vmware.resource_id} · запись {vmware.record_index}")
        elif source.run_id and source.item_id:
            lines.append(f"Запуск · {source.run_id} · снимок {source.item_id}")
    if context := assessment.context_resolution:
        lines.append(context.message)
        if context.session_id:
            lines.append(f"Сеанс · {context.session_id}")
        if context.source_cidr:
            lines.append(f"Адрес сеанса · {context.source_cidr}")
        if context.evaluated_at:
            lines.append(f"Время оценки сеанса · {context.evaluated_at.isoformat(timespec='seconds')}")
    lines.extend(assessment.reasons)
    lines.extend(notes.get(row.requirement_id, ()))
    evidence = matrix_evidence_preview(assessment.evidence)
    lines = list(dict.fromkeys(lines))
    for item in evidence:
        lines.extend(("", item.summary))
        if packet := matrix_packet_detail(item):
            lines.append(packet)
        if item.related_rule_ids:
            lines.append("Правила · " + ", ".join(item.related_rule_ids))
        lines.extend(
            f"{location.source_name} · {location.object_path or location.line_start or location.object_id or '—'}"
            for location in item.source_locations
        )
        lines.extend(item.limitations)
    if len(evidence) < len(assessment.evidence):
        lines.extend(("", f"Оснований показано {len(evidence)} из {len(assessment.evidence)}. Все доступны в HTML."))
    return "\n".join(lines)


def _matches_outcome(change: MatrixScopeChange, outcome: str) -> bool:
    if outcome == "attention":
        return change.state != "unchanged"
    return outcome == "all" or outcome in (change.state, change.direction)


class MatrixScopeComparisonDialog(QDialog):
    export_requested = Signal()
    findings_requested = Signal(str)

    def __init__(
        self, before: MatrixScopeAssessment, after: MatrixScopeAssessment, changes: Sequence[MatrixScopeChange],
        matrix: AccessMatrix | None, parent: QWidget, *, prepared: MatrixScopeComparisonView | None = None,
        finding_sources: Sequence[tuple[str, str]] | None = None, findings_overview: Sequence[str] = (),
        finding_sources_by_requirement: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self._before, self._after = before, after
        self._prepared = prepared if prepared is not None else prepare_matrix_scope_comparison(
            before, after, changes, matrix,
        )
        self._changes = self._prepared.changes
        self._finding_sources_by_requirement = dict(finding_sources_by_requirement or {})
        self._findings_page: MatrixComparisonFindings | None = None
        self.setWindowTitle("Сравнение политик области")
        self.resize(1150, 760)
        layout = QVBoxLayout(self)
        counts = Counter(change.state for change in self._changes)
        heading = QLabel(
            f"Матрица v{after.matrix_version} · область {after.scope_id}\n"
            + " · ".join(f"{label.lower()} {counts[key]}" for key, label in _OUTCOMES.items())
            + "\nСравниваются сохранённые политики. Для проверки всего пути нужны данные о маршруте."
        )
        heading.setTextFormat(Qt.TextFormat.PlainText)
        heading.setWordWrap(True)
        layout.addWidget(heading)
        self._tabs = QTabWidget()
        self._rows_page = self._build_rows(counts)
        self._tabs.addTab(self._rows_page, "Строки сравнения")
        if self._prepared.boundaries:
            self._tabs.addTab(self._build_boundaries(), "Закрытые области")
        if finding_sources or findings_overview:
            self._findings_page = MatrixComparisonFindings(finding_sources or (), findings_overview, self._tabs)
            self._tabs.addTab(self._findings_page, "Находки в снимках")
            self._findings_page.requested.connect(self.findings_requested.emit)
            self._tabs.currentChanged.connect(self._activate_findings)
        layout.addWidget(self._tabs, 1)
        footer = QHBoxLayout()
        self._export_status = QLabel()
        self._export_status.setTextFormat(Qt.TextFormat.PlainText)
        self._export_status.setWordWrap(True)
        footer.addWidget(self._export_status, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self._export_button = buttons.addButton("Сохранить сравнение матрицы…", QDialogButtonBox.ButtonRole.ActionRole)
        self._export_button.setAutoDefault(False)
        buttons.button(QDialogButtonBox.StandardButton.Close).setAutoDefault(False)
        self._export_button.clicked.connect(lambda: self.export_requested.emit())
        buttons.rejected.connect(self.reject)
        footer.addWidget(buttons)
        layout.addLayout(footer)
        self._refresh()
        self._query.setFocus()

    def set_export_status(self, text: str, busy: bool = False) -> None:
        self._export_status.setText(text)
        self._export_button.setEnabled(not busy)

    def set_findings_result(
        self, source_id: str, rows: Sequence[MatrixFindingComparisonRow], diagnostics: Sequence[str] = (),
    ) -> None:
        if self._findings_page is not None:
            self._findings_page.set_result(source_id, rows, diagnostics)

    def set_findings_error(self, source_id: str, message: str) -> None:
        if self._findings_page is not None:
            self._findings_page.set_error(source_id, message)

    def _activate_findings(self, _: int) -> None:
        page = self._findings_page
        if page is not None and self._tabs.currentWidget() is page:
            page.start()

    def _open_row_findings(self) -> None:
        page, index = self._findings_page, self._table.selected_index()
        if page is None or index is None:
            return
        source = self._finding_sources_by_requirement.get(self._changes[index].requirement_id)
        if source is not None and page.select_source(source):
            self._tabs.setCurrentWidget(page)

    def _build_rows(self, counts: Counter[str]) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        filters = QHBoxLayout()
        self._query = QLineEdit()
        self._query.setPlaceholderText("ID, группа, сервис или устройство")
        self._query.setAccessibleName("Поиск по строкам сравнения")
        self._query.setClearButtonEnabled(True)
        filters.addWidget(self._query, 1)
        self._outcome = QComboBox()
        self._outcome.setAccessibleName("Фильтр по результату сравнения")
        self._outcome.addItem("Изменения и пробелы", "attention")
        self._outcome.addItem("Все строки", "all")
        directions = Counter(change.direction for change in self._changes)
        for key, label in reversed(_DIRECTIONS.items()):
            self._outcome.addItem(f"{label} ({directions[key]})", key)
        for key, label in _OUTCOMES.items():
            self._outcome.addItem(f"{label} ({counts[key]})", key)
        self._outcome.setCurrentIndex(0 if sum(counts.values()) > counts["unchanged"] else 1)
        filters.addWidget(self._outcome)
        layout.addLayout(filters)

        vertical = QSplitter(Qt.Orientation.Vertical)
        list_panel = QWidget()
        list_layout = QVBoxLayout(list_panel)
        list_layout.setContentsMargins(0, 0, 0, 0)
        self._table = MatrixTable(("ID", "Источник → назначение", "Сервис", "Было", "Стало", "Сравнение"))
        self._table.setAccessibleName("Сравнение требований доступа")
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setColumnWidth(3, 170)
        self._table.setColumnWidth(4, 170)
        self._table.setColumnWidth(5, 220)
        self._table.verticalHeader().setDefaultSectionSize(48)
        self._configure_navigation(self._table)
        list_layout.addWidget(self._table, 1)
        list_layout.addLayout(self._table.navigation())
        vertical.addWidget(list_panel)

        lower = QWidget()
        lower_layout = QVBoxLayout(lower)
        lower_layout.setContentsMargins(0, 0, 0, 0)
        self._reason = QLabel()
        self._reason.setTextFormat(Qt.TextFormat.PlainText)
        self._reason.setWordWrap(True)
        reason_row = QHBoxLayout()
        reason_row.addWidget(self._reason, 1)
        self._row_findings = QPushButton("Находки этого источника")
        self._row_findings.setAutoDefault(False)
        self._row_findings.setEnabled(False)
        self._row_findings.setVisible(bool(self._finding_sources_by_requirement))
        self._row_findings.clicked.connect(self._open_row_findings)
        reason_row.addWidget(self._row_findings)
        lower_layout.addLayout(reason_row)
        split = QSplitter(Qt.Orientation.Horizontal)
        self._old_details = self._snapshot_panel(split, self._before, "Было")
        self._new_details = self._snapshot_panel(split, self._after, "Стало")
        split.setSizes([520, 520])
        lower_layout.addWidget(split, 1)
        vertical.addWidget(lower)
        vertical.setSizes([300, 330])
        layout.addWidget(vertical, 1)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._refresh)
        self._query.textChanged.connect(lambda _: self._timer.start())
        self._query.returnPressed.connect(self._refresh)
        self._outcome.currentIndexChanged.connect(self._refresh)
        self._table.itemSelectionChanged.connect(self._show_row)
        return page

    def _snapshot_panel(self, split: QSplitter, result: MatrixScopeAssessment, title: str) -> QPlainTextEdit:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        heading = QLabel(_snapshot_caption(result, title))
        heading.setTextFormat(Qt.TextFormat.PlainText)
        heading.setWordWrap(True)
        heading.setToolTip("\n".join(result.limitations))
        layout.addWidget(heading)
        details = QPlainTextEdit()
        details.setReadOnly(True)
        details.setAccessibleName(f"{title} · основания и источник сверки")
        layout.addWidget(details, 1)
        split.addWidget(panel)
        return details

    def _refresh(self, *_: object) -> None:
        self._timer.stop()
        terms = _search_key(self._query.text()).split()
        outcome = self._outcome.currentData()
        selected = self._table.selected_index()
        indices = [
            index for index in self._prepared.row_order
            if _matches_outcome(self._changes[index], outcome)
            and all(term in self._prepared.rows[index].search for term in terms)
        ]
        if indices != self._table.filtered_indices():
            self._table.set_rows(indices, lambda index: self._prepared.rows[index].columns, reset=True)
        elif selected is not None:
            return
        if indices:
            page = indices[:self._table.PAGE_SIZE]
            self._table.selectRow(page.index(selected) if selected is not None and selected in page else 0)

    def _configure_navigation(self, table: MatrixTable) -> None:
        for button in (table.previous, table.next):
            button.setAutoDefault(False)
            button.clicked.connect(lambda: table.selectRow(0))

    def _show_row(self) -> None:
        index = self._table.selected_index()
        if index is None:
            self._row_findings.setEnabled(False)
            self._reason.setText(
                "Выберите строку сравнения." if self._table.filtered_indices() else "По выбранным фильтрам строк нет."
            )
            self._old_details.clear()
            self._new_details.clear()
            return
        change = self._changes[index]
        self._row_findings.setEnabled(
            self._findings_page is not None and change.requirement_id in self._finding_sources_by_requirement,
        )
        prepared = self._prepared
        if change.direction is not None:
            self._reason.setText(f"{_DIRECTIONS[change.direction]} в локальной политике. {change.reason}")
        else:
            self._reason.setText(change.reason)
        self._old_details.setPlainText(_details(change.before, self._before, prepared.before_sources, prepared.before_notes))
        self._new_details.setPlainText(_details(change.after, self._after, prepared.after_sources, prepared.after_notes))

    def _build_boundaries(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self._boundaries = MatrixTable(("Закрытая область", "Было", "Стало"))
        self._boundaries.setAccessibleName("Сравнение закрытых областей")
        self._boundaries.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._boundaries.horizontalHeader().setStretchLastSection(True)
        self._boundaries.setColumnWidth(0, 260)
        self._boundaries.verticalHeader().setDefaultSectionSize(54)
        self._configure_navigation(self._boundaries)
        self._boundaries.set_rows(range(len(self._prepared.boundaries)), lambda index: self._prepared.boundaries[index].columns)
        layout.addWidget(self._boundaries, 1)
        layout.addLayout(self._boundaries.navigation())
        self._points = MatrixTable(("Точка контроля", "Было", "Стало"))
        self._points.setAccessibleName("Сравнение точек контроля выбранной области")
        self._points.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._points.horizontalHeader().setStretchLastSection(True)
        self._points.setColumnWidth(0, 260)
        self._points.setWordWrap(True)
        self._points.verticalHeader().setDefaultSectionSize(72)
        self._configure_navigation(self._points)
        layout.addWidget(self._points, 1)
        layout.addLayout(self._points.navigation())
        self._open_point = QPushButton("Открыть сравнение точки")
        self._open_point.clicked.connect(self._jump_to_point)
        self._open_point.setEnabled(False)
        self._open_point.setAutoDefault(False)
        layout.addWidget(self._open_point)
        self._boundaries.itemSelectionChanged.connect(self._show_points)
        self._points.itemSelectionChanged.connect(self._point_controls)
        self._points.itemActivated.connect(lambda _: self._jump_to_point())
        self._boundaries.selectRow(0)
        return page

    def _show_points(self) -> None:
        index = self._boundaries.selected_index()
        points = self._prepared.boundaries[index].points if index is not None else ()
        self._points.set_rows(range(len(points)), lambda position: points[position].columns, reset=True)
        if points:
            self._points.selectRow(0)

    def _point_index(self) -> int | None:
        boundary, point = self._boundaries.selected_index(), self._points.selected_index()
        if boundary is None or point is None:
            return None
        identifier = self._prepared.boundaries[boundary].points[point].identifier
        return self._prepared.indices_by_id.get(identifier)

    def _point_controls(self) -> None:
        self._open_point.setEnabled(self._point_index() is not None)

    def _jump_to_point(self) -> None:
        if (index := self._point_index()) is None:
            return
        self._tabs.setCurrentWidget(self._rows_page)
        if self._timer.isActive():
            self._refresh()
        if self._table.show_index(index):
            return
        with QSignalBlocker(self._query), QSignalBlocker(self._outcome):
            if not _matches_outcome(self._changes[index], self._outcome.currentData()):
                self._outcome.setCurrentIndex(self._outcome.findData("all"))
            if not all(term in self._prepared.rows[index].search for term in _search_key(self._query.text()).split()):
                self._query.clear()
        self._refresh()
        self._table.show_index(index)
