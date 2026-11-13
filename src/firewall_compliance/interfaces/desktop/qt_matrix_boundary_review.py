"""Просмотр связанных точек закрытой области по сохранённой сверке."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QSplitter, QVBoxLayout, QWidget,
)

from firewall_compliance.application.matrix_boundary_groups import MatrixBoundaryPointAssessment, evaluate_boundary_groups
from firewall_compliance.application.matrix_reports import (
    MATRIX_BOUNDARY_GROUP_LABELS, MATRIX_BOUNDARY_POINT_LABELS, MATRIX_STATE_LABELS,
    matrix_evidence_preview, matrix_packet_detail, matrix_scope_source_notes, matrix_service_label,
)
from firewall_compliance.application.matrix_scope_assessment import MatrixScopeAssessment
from firewall_compliance.domain.access_matrix import AccessMatrix
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable


@dataclass(frozen=True, slots=True)
class BoundaryPointView:
    values: tuple[str, str, str]
    assessment: MatrixBoundaryPointAssessment
    atomic_index: int | None
    source_notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BoundaryGroupView:
    values: tuple[str, str, str, str]
    search: str
    points: tuple[BoundaryPointView, ...]
    excess_count: int
    gap_count: int


def prepare_boundary_review(
    matrix: AccessMatrix, result: MatrixScopeAssessment, names: Mapping[str, str],
) -> tuple[BoundaryGroupView, ...]:
    if not matrix.boundary_groups:
        return ()
    atomic_indices = {
        row.requirement_id: index for index, row in enumerate(result.requirements)
        if row.kind == "boundary"
    }
    source_notes = matrix_scope_source_notes(result)
    groups = []
    for summary in evaluate_boundary_groups(matrix, result):
        points = []
        search = [summary.group.group_id, summary.group.name]
        for point in summary.points:
            boundary, row, source = point.boundary, point.row, point.source
            identifier = boundary.boundary_id
            point_name = summary.group.point_names.get(identifier, identifier)
            state = MATRIX_BOUNDARY_POINT_LABELS[point.status]
            points.append(BoundaryPointView(
                (point_name, state, point.gap or "—"),
                point,
                atomic_indices.get(identifier) if row is not None else None,
                source_notes.get(identifier, ()),
            ))
            search.extend((
                identifier, point_name, boundary.policy_id or "",
                source.device_label if source else "", source.device_id if source else "",
            ))
        boundary = summary.points[0].boundary
        interaction = (
            f"{names.get(boundary.source_group, boundary.source_group)} → "
            f"{names.get(boundary.destination_group, boundary.destination_group)}"
        )
        service = matrix_service_label(boundary.service)
        groups.append(BoundaryGroupView(
            (
                f"{summary.group.name} · {summary.group.group_id}", f"{interaction} · {service}",
                MATRIX_BOUNDARY_GROUP_LABELS[summary.state], f"{summary.excess_count} / {summary.gap_count}",
            ),
            " ".join((*search, interaction, service, boundary.source_group, boundary.destination_group)).casefold(),
            tuple(points), summary.excess_count, summary.gap_count,
        ))
    return tuple(groups)


def _point_details(view: BoundaryPointView) -> str:
    point = view.assessment
    boundary, row, source = point.boundary, point.row, point.source
    point_name, state, _gap = view.values
    title = point_name if point_name == boundary.boundary_id else f"{point_name} · {boundary.boundary_id}"
    lines = [title, state]
    if boundary.policy_id:
        lines.append(f"Политика · {boundary.policy_id}")
    if boundary.zone_pair is not None:
        lines.append(f"Зоны · {boundary.zone_pair.source_zone} → {boundary.zone_pair.destination_zone}")
    if point.gap:
        lines.append(point.gap)
    lines.extend(view.source_notes)
    if source is not None:
        lines.extend((
            f"Устройство · {source.device_label} · {source.device_id}",
            f"Ревизия · {source.revision_id} · {source.captured_at.isoformat()}",
        ))
        if source.cloud_selection is not None:
            lines.append(f"Сохранённый сбор · {source.cloud_selection.scan_id}")
        elif source.vmware_origin is not None:
            lines.extend((f"Сбор VMware · {source.vmware_origin.scan_id}",
                          f"Edge Gateway · {source.vmware_origin.resource_id}"))
        elif source.run_id and source.item_id:
            lines.append(f"Запуск · {source.run_id} · снимок {source.item_id}")
    if row is not None:
        if row.policy_vrf is not None:
            lines.append(f"VRF политики · {row.policy_vrf}")
        lines.append(MATRIX_STATE_LABELS[row.assessment.state])
        lines.extend(row.assessment.reasons)
        preview = matrix_evidence_preview(row.assessment.evidence)
        for item in preview:
            lines.append(item.summary)
            if detail := matrix_packet_detail(item):
                lines.append(detail)
            if item.related_rule_ids:
                lines.append("ID правил · " + ", ".join(item.related_rule_ids))
            lines.extend(
                f"{location.source_name} · {location.object_path or location.line_start or location.object_id}"
                for location in item.source_locations
            )
        if len(preview) < len(row.assessment.evidence):
            lines.append(f"Ещё {len(row.assessment.evidence) - len(preview)} оснований доступны в JSON.")
    return "\n".join(dict.fromkeys(lines))


class MatrixBoundaryReview(QDialog):
    def __init__(self, groups: tuple[BoundaryGroupView, ...], parent: QWidget) -> None:
        super().__init__(parent)
        self._groups = groups
        self.atomic_index: int | None = None
        self.setWindowTitle("Закрытые области · несколько точек контроля")
        self.resize(1080, 690)
        layout = QVBoxLayout(self)
        heading = QLabel(
            "Результаты относятся к перечисленным точкам контроля. Пробелы видны рядом с найденными разрешениями."
        )
        heading.setWordWrap(True)
        layout.addWidget(heading)
        filters = QHBoxLayout()
        self._query = QLineEdit()
        self._query.setPlaceholderText("Имя области, ID, группа, сервис или точка контроля")
        self._query.setAccessibleName("Поиск закрытых областей")
        filters.addWidget(self._query, 1)
        self._state = QComboBox()
        self._state.setAccessibleName("Фильтр закрытых областей")
        self._state.addItem("Все области", None)
        self._state.addItem("Есть лишнее разрешение", "excess")
        self._state.addItem("Есть пробелы", "gaps")
        filters.addWidget(self._state)
        layout.addLayout(filters)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._refresh)
        self._query.textChanged.connect(lambda _: self._timer.start())
        self._state.currentIndexChanged.connect(self._refresh)

        self._table = MatrixTable(("Закрытая область", "Источник → назначение · сервис", "Результат", "Лишние / пробелы"))
        self._table.setAccessibleName("Закрытые области с несколькими точками контроля")
        self._table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self._table, 1)
        layout.addLayout(self._table.navigation())
        lower = QSplitter(Qt.Orientation.Horizontal)
        point_panel = QWidget()
        point_layout = QVBoxLayout(point_panel)
        point_layout.setContentsMargins(0, 0, 0, 0)
        self._points = MatrixTable(("Точка контроля", "Результат", "Недостающие сведения"))
        self._points.setAccessibleName("Точки контроля выбранной закрытой области")
        self._points.horizontalHeader().setStretchLastSection(True)
        point_layout.addWidget(self._points)
        point_layout.addLayout(self._points.navigation())
        lower.addWidget(point_panel)
        self._details = QPlainTextEdit()
        self._details.setReadOnly(True)
        self._details.setAccessibleName("Основания для выбранной точки контроля")
        lower.addWidget(self._details)
        layout.addWidget(lower, 2)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self._open = QPushButton("Открыть исходную строку")
        buttons.addButton(self._open, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.rejected.connect(self.reject)
        self._open.clicked.connect(self._open_atomic)
        layout.addWidget(buttons)
        self._table.itemSelectionChanged.connect(self._show_group)
        self._points.itemSelectionChanged.connect(self._show_point)
        self._points.cellDoubleClicked.connect(self._open_atomic)
        self._refresh()
        if self._groups:
            self._table.selectRow(0)

    def _refresh(self, *_: object) -> None:
        self._timer.stop()
        state = self._state.currentData()
        terms = self._query.text().casefold().split()
        rows = [
            index for index, group in enumerate(self._groups)
            if (state is None or (group.excess_count if state == "excess" else group.gap_count))
            and all(term in group.search for term in terms)
        ]
        self._table.set_rows(rows, lambda index: self._groups[index].values, reset=True)

    def _selected_points(self) -> tuple[BoundaryPointView, ...]:
        index = self._table.selected_index()
        return self._groups[index].points if index is not None else ()

    def _show_group(self) -> None:
        points = self._selected_points()
        self._points.set_rows(range(len(points)), lambda index: points[index].values, reset=True)
        if points:
            self._points.selectRow(0)

    def _selected_point(self) -> BoundaryPointView | None:
        points = self._selected_points()
        index = self._points.selected_index()
        return points[index] if index is not None and index < len(points) else None

    def _show_point(self) -> None:
        point = self._selected_point()
        self._details.setPlainText(_point_details(point) if point else "Выберите закрытую область и точку контроля.")
        self._open.setEnabled(point is not None and point.atomic_index is not None)

    def _open_atomic(self, *_: object) -> None:
        point = self._selected_point()
        if point is not None and point.atomic_index is not None:
            self.atomic_index = point.atomic_index
            self.accept()
