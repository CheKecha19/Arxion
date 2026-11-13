"""Сводка закрытой области по её отдельным сохранённым точкам проверки."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from typing import Literal

from firewall_compliance.application.matrix_scope_assessment import (
    SOURCE_FALLBACK_NOTE,
    MatrixScopeAssessment,
    MatrixScopeRowAssessment,
    MatrixScopeSource,
    matrix_scope_checksum,
)
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixBoundary, MatrixBoundaryGroup


type PointStatus = Literal["excess_allow", "confirmed", "unverified"]
type GroupState = Literal["excess_allow", "declared_match", "insufficient_evidence"]


@dataclass(frozen=True, slots=True)
class MatrixBoundaryPointAssessment:
    boundary: MatrixBoundary
    row: MatrixScopeRowAssessment | None
    source: MatrixScopeSource | None
    status: PointStatus
    gap: str | None = None


@dataclass(frozen=True, slots=True)
class MatrixBoundaryGroupAssessment:
    group: MatrixBoundaryGroup
    state: GroupState
    points: tuple[MatrixBoundaryPointAssessment, ...]

    @property
    def excess_count(self) -> int:
        return sum(point.status == "excess_allow" for point in self.points)

    @property
    def gap_count(self) -> int:
        return sum(point.gap is not None for point in self.points)

    @property
    def coverage_complete(self) -> bool:
        return self.gap_count == 0


_ROUTING_GAPS = {
    "missing_policy": "Для точки ещё не указана политика.",
    "policy_not_found": "В доступных снимках не найдена политика этой точки.",
    "target_not_found": "В доступных снимках нет политики выбранного устройства или контекста.",
    "ambiguous": "Политика найдена в нескольких снимках. Укажите устройство и контекст.",
    "incomplete_policy_sources": "Часть источников политики недоступна. Укажите устройство или обновите сбор.",
    "conflict": "Конфликт требования или исключений не позволяет оценить точку.",
}


def _point(
    boundary: MatrixBoundary,
    row: MatrixScopeRowAssessment | None,
    source: MatrixScopeSource | None,
    *,
    stale: bool,
) -> MatrixBoundaryPointAssessment:
    if row is None:
        return MatrixBoundaryPointAssessment(
            boundary, None, None, "unverified", "Сверка завершилась до обработки этой точки.",
        )
    if row.routing != "resolved":
        gap = _ROUTING_GAPS.get(row.routing, "Для точки не получен вывод по сохранённой политике.")
        return MatrixBoundaryPointAssessment(boundary, row, source, "unverified", gap)
    assessment = row.assessment
    excess = assessment.state == "excess_allow"
    gaps: list[str] = []
    if stale:
        gaps.append("Более поздняя попытка сбора не обновила снимок этой точки.")
    if assessment.mode != "local_policy":
        gaps.append("Локальное решение политики этой точки не подтверждено.")
    if assessment.coverage_complete is not True:
        gaps.append("Полный охват закрытой области в этой точке не подтверждён.")
    if assessment.attachment_limited:
        gaps.append("Для применимости политики к пути нужны дополнительные сведения о привязке.")
    if assessment.state == "not_applicable":
        gaps.append("Исключения покрывают всю область. Для проверки запрета остатка не осталось.")
    elif assessment.state not in {"declared_match", "excess_allow"}:
        gaps.append("В этой точке нет итогового вывода о запрете остатка.")
    status: PointStatus = "excess_allow" if excess else "unverified" if gaps else "confirmed"
    return MatrixBoundaryPointAssessment(boundary, row, source, status, " ".join(gaps) or None)


def evaluate_boundary_groups(
    matrix: AccessMatrix, result: MatrixScopeAssessment,
) -> tuple[MatrixBoundaryGroupAssessment, ...]:
    """Свести только явно перечисленные точки без вычисления сквозного доступа."""
    groups = tuple(group for group in matrix.boundary_groups if group.scope_id == result.scope_id)
    if not groups:
        return ()
    if (
        (matrix.matrix_id, matrix.version) != (result.matrix_id, result.matrix_version)
        or matrix_scope_checksum(matrix) != result.matrix_checksum
    ):
        raise ValueError("Версия матрицы не соответствует сохранённой сверке закрытых областей")

    boundary_ids = {identifier for group in groups for identifier in group.boundary_ids}
    boundaries = {boundary.boundary_id: boundary for boundary in matrix.boundaries}
    rows: dict[str, MatrixScopeRowAssessment] = {}
    for row in result.requirements:
        identifier = row.requirement_id
        if identifier not in boundary_ids:
            continue
        boundary = boundaries[identifier]
        if identifier in rows or (
            row.kind, row.source_group, row.destination_group, row.policy_id, row.zone_pair
        ) != (
            "boundary", boundary.source_group, boundary.destination_group, boundary.policy_id, boundary.zone_pair
        ):
            raise ValueError("Сохранённый результат не соответствует точке проверки закрытой области")
        rows[identifier] = row
    if result.status != "cancelled" and boundary_ids - rows.keys():
        raise ValueError("В сохранённом результате отсутствует точка проверки закрытой области")
    stale = {
        identifier for issue in result.diagnostics if issue.code == SOURCE_FALLBACK_NOTE
        for identifier in issue.requirement_ids
    }
    sources = {source.revision_id: source for source in result.sources}
    by_id: dict[str, MatrixBoundaryPointAssessment] = {}
    for identifier in boundary_ids:
        row = rows.get(identifier)
        source = sources.get(row.revision_id) if row is not None and row.revision_id is not None else None
        by_id[identifier] = _point(boundaries[identifier], row, source, stale=identifier in stale)

    assessments = []
    for group in groups:
        points = tuple(by_id[identifier] for identifier in group.boundary_ids)
        destinations = Counter(
            (point.row.revision_id, point.row.policy_id, point.row.zone_pair)
            for point in points if point.row is not None and point.row.routing == "resolved"
        )
        points = tuple(
            replace(
                point,
                status="unverified" if point.status == "confirmed" else point.status,
                gap=" ".join(filter(None, (
                    point.gap, "Эта политика и ревизия повторяются в другой точке того же ограничения.",
                ))),
            )
            if point.row is not None and point.row.routing == "resolved"
            and destinations[(point.row.revision_id, point.row.policy_id, point.row.zone_pair)] > 1
            else point
            for point in points
        )
        state: GroupState
        if any(point.status == "excess_allow" for point in points):
            state = "excess_allow"
        elif any(point.gap is not None for point in points):
            state = "insufficient_evidence"
        else:
            state = "declared_match"
        assessments.append(MatrixBoundaryGroupAssessment(group, state, points))
    return tuple(assessments)
