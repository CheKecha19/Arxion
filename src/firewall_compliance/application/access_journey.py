"""Составление отчёта о цепочке по уже сохранённым сверкам требований."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance.application.matrix_scope_assessment import (
    MatrixScopeAssessment, MatrixScopeRouting, matrix_scope_checksum,
)
from firewall_compliance.domain.access_journey import AccessJourney, JourneyStep, validate_journey
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixRequirementAssessment
from firewall_compliance.domain.controls import ControlModel

if TYPE_CHECKING:
    from firewall_compliance.application.matrix_artifact import MatrixAssessmentArtifact

JourneyStepStatus = Literal[
    "missing_requirement", "missing_assessment", "missing_result", "incompatible_artifact", "declared_condition",
    "declared_conflict", "local_permit", "local_conflict", "partial", "unknown",
]


class JourneyStepAssessment(ControlModel):
    step_id: str
    requirement_id: str | None = None
    status: JourneyStepStatus
    message: str
    artifact_id: UUID | None = None
    artifact_created_at: datetime | None = None
    revision_id: UUID | None = None
    source_captured_at: datetime | None = None
    device_id: str | None = None
    device_label: str | None = None
    assessment: MatrixRequirementAssessment | None = None
    routing: MatrixScopeRouting | None = None

    @model_serializer(mode="wrap")
    def serialize_routing(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        payload = handler(self)
        if self.routing is None:
            payload.pop("routing", None)
        return payload


class JourneyScopeReference(ControlModel):
    artifact_id: UUID | None = None
    created_at: AwareDatetime
    checksum: str = Field(pattern=r"^[a-f0-9]{64}$")
    matrix_checksum: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["complete", "partial", "cancelled"]


class JourneyAssessment(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    journey: AccessJourney
    project_id: str = Field(min_length=1)
    matrix_id: str
    matrix_version: str
    steps: tuple[JourneyStepAssessment, ...]
    scope_assessment: JourneyScopeReference | None = None
    limitations: tuple[str, ...] = (
        "Связь участков задана группами матрицы. Снимки могут отличаться по времени и составу групп.",
        "Сквозная доступность, маршруты, NAT, работа промежуточных приложений и обратный трафик не оценены.",
    )

    @model_serializer(mode="wrap")
    def serialize_scope_reference(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        payload = handler(self)
        if self.scope_assessment is None:
            payload.pop("scope_assessment", None)
        return payload

    @model_validator(mode="after")
    def validate_steps(self) -> Self:
        if tuple((row.step_id, row.requirement_id) for row in self.steps) != tuple(
            (step.step_id, step.requirement_id) for step in self.journey.steps
        ):
            raise ValueError("Результаты участков должны соответствовать порядку цепочки")
        if self.scope_assessment is None:
            if any(row.routing is not None for row in self.steps):
                raise ValueError("Назначения источников требуют ссылки на общую сверку")
        elif any(
            row.artifact_id is not None or row.artifact_created_at is not None
            or (row.routing == "resolved") != (row.revision_id is not None)
            or (row.routing is not None) != (row.assessment is not None)
            for row in self.steps
        ):
            raise ValueError("Источники участков должны соответствовать общей сверке")
        return self


def _outcome(
    row: MatrixRequirementAssessment, assessment_mode: Literal["local_policy", "declared_rules", "mixed"],
) -> tuple[JourneyStepStatus, str]:
    mode = row.mode or assessment_mode
    if row.state == "declared_conflict" and mode == "local_policy":
        if row.attachment_limited:
            return "local_conflict", "Найдено противоположное локальное решение. Для участка нужны отдельные сведения о пути."
        return "local_conflict", "В локальной политике найдено противоположное решение для части или всего условия."
    if row.state == "declared_conflict" and mode == "declared_rules":
        return "declared_conflict", "Найдено противоположное объявленное условие."
    if row.state == "partial_match" or (row.state == "declared_match" and row.coverage_complete is False):
        return "partial", "Сверка подтверждает часть условия."
    if row.state == "declared_match" and mode == "local_policy" and row.coverage_complete is True:
        if row.attachment_limited:
            return "partial", "Политика содержит разрешение. Для участка нужны отдельные сведения о пути."
        return "local_permit", "Локальная политика разрешает запросы в пределах проверенного условия."
    if row.state == "declared_match" and mode == "declared_rules":
        return "declared_condition", "В снимке найдено покрывающее объявленное разрешение."
    return "unknown", "Сохранённая оценка не даёт достаточного вывода по участку."


def _unbound_step(step: JourneyStep) -> JourneyStepAssessment:
    if step.requirement_id is None:
        return JourneyStepAssessment(
            step_id=step.step_id, status="missing_requirement",
            message="Для участка не задано требование. Уточните сервис и добавьте требование для этих групп.",
        )
    return JourneyStepAssessment(
        step_id=step.step_id, requirement_id=step.requirement_id, status="missing_assessment",
        message="Для участка не выбрана сохранённая сверка. Нужен снимок политики, проверяющей это требование.",
    )


def evaluate_journey(
    matrix: AccessMatrix, journey: AccessJourney, assessments: Mapping[str, MatrixAssessmentArtifact], *,
    project_id: str,
) -> JourneyAssessment:
    """Сохранить независимые выводы по участкам одной версии требований и области."""
    validate_journey(matrix, journey)
    step_ids = {step.step_id for step in journey.steps if step.requirement_id is not None}
    if assessments.keys() - step_ids:
        raise ValueError("Сверку можно назначить только участку с указанным требованием")

    indexed: dict[UUID, tuple[MatrixAssessmentArtifact, dict[str, MatrixRequirementAssessment] | None]] = {}
    results: list[JourneyStepAssessment] = []
    for step in journey.steps:
        artifact = assessments.get(step.step_id)
        if artifact is None:
            results.append(_unbound_step(step))
            continue
        entry = indexed.get(artifact.artifact_id)
        if entry is None:
            compatible = (
                artifact.origin_project_id == project_id and artifact.assessment.scope_id == journey.scope_id
                and artifact.matrix == matrix
            )
            rows = {row.requirement_id: row for row in artifact.assessment.requirements} if compatible else None
            indexed[artifact.artifact_id] = artifact, rows
        else:
            original, rows = entry
            if original is not artifact and original != artifact:
                raise ValueError("Один ID сверки имеет разные сохранённые данные")
        if rows is None:
            results.append(JourneyStepAssessment(
                step_id=step.step_id, requirement_id=step.requirement_id, status="incompatible_artifact",
                message="Выберите сверку из этого проекта, версии матрицы и области цепочки.",
            ))
            continue
        row = rows.get(step.requirement_id) if step.requirement_id is not None else None
        status: JourneyStepStatus
        if row is None:
            status, message = "missing_result", "В выбранной сверке отсутствует результат для этого требования."
        else:
            status, message = _outcome(row, artifact.assessment.mode)
        revision = artifact.revision
        results.append(JourneyStepAssessment(
            step_id=step.step_id, requirement_id=step.requirement_id, status=status, message=message,
            artifact_id=artifact.artifact_id, artifact_created_at=artifact.created_at,
            revision_id=revision.revision_id, source_captured_at=revision.parse_result.configuration.captured_at,
            device_id=revision.device.device_id, device_label=revision.device.hostname or revision.device.device_id,
            assessment=row,
        ))
    return JourneyAssessment(
        journey=journey, project_id=project_id, matrix_id=matrix.matrix_id, matrix_version=matrix.version,
        steps=tuple(results),
    )


def evaluate_scope_journey(
    matrix: AccessMatrix, journey: AccessJourney, result: MatrixScopeAssessment, *,
    project_id: str, artifact_id: UUID | None = None,
) -> JourneyAssessment:
    """Связать участки с результатами одной общей сверки и её источниками."""
    validate_journey(matrix, journey)
    if (
        journey not in matrix.journeys
        or (result.project_id, result.scope_id) != (project_id, journey.scope_id)
        or result.scope_id != (result.selected_site_id or project_id)
        or (result.matrix_id, result.matrix_version, result.matrix_checksum)
        != (matrix.matrix_id, matrix.version, matrix_scope_checksum(matrix))
    ):
        raise ValueError("Для цепочки нужна общая сверка утверждённой версии матрицы из той же области проекта")

    requirements = {row.requirement_id: row for row in matrix.requirements}
    row_counts = Counter(row.requirement_id for row in result.requirements)
    rows = {row.requirement_id: row for row in result.requirements if row.kind == "requirement"}
    sources = {source.revision_id: source for source in result.sources}
    results: list[JourneyStepAssessment] = []
    for step in journey.steps:
        identifier = step.requirement_id
        if identifier is None:
            results.append(_unbound_step(step))
            continue
        expected = requirements[identifier]
        row = rows.get(identifier)
        status: JourneyStepStatus
        if row_counts[identifier] == 0:
            status = "missing_result"
            message = (
                "Сверка была остановлена до получения результата этого требования."
                if result.status == "cancelled" else "В общей сверке отсутствует результат этого требования."
            )
        elif row_counts[identifier] != 1 or row is None or (
            row.source_group, row.destination_group, row.policy_id, row.zone_pair
        ) != (step.source_group, step.destination_group, expected.policy_id, expected.zone_pair):
            status = "incompatible_artifact"
            message = "Строка общей сверки не совпадает с утверждённым требованием участка."
            row = None
        elif row.routing != "resolved":
            status = "unknown" if row.routing in {"unregulated", "conflict"} else "missing_assessment"
            message = " ".join(row.assessment.reasons) or "Для участка не подтверждён снимок политики."
        else:
            status, message = _outcome(row.assessment, result.mode)
            if status == "unknown" and row.assessment.reasons:
                message = " ".join(row.assessment.reasons)
        source = sources.get(row.revision_id) if row is not None and row.revision_id is not None else None
        results.append(JourneyStepAssessment(
            step_id=step.step_id, requirement_id=identifier, status=status, message=message,
            revision_id=source.revision_id if source is not None else None,
            source_captured_at=source.captured_at if source is not None else None,
            device_id=source.device_id if source is not None else None,
            device_label=source.device_label if source is not None else None,
            assessment=row.assessment if row is not None else None,
            routing=row.routing if row is not None else None,
        ))

    return JourneyAssessment(
        journey=journey, project_id=project_id, matrix_id=matrix.matrix_id, matrix_version=matrix.version,
        steps=tuple(results),
        scope_assessment=JourneyScopeReference(
            artifact_id=artifact_id, created_at=result.created_at,
            checksum=result.payload_checksum,
            matrix_checksum=result.matrix_checksum, status=result.status,
        ),
    )
