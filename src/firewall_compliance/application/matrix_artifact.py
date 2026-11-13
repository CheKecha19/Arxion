"""Воспроизводимый результат сверки: сохранённые входы, без повторного анализа."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, SerializerFunctionWrapHandler, field_validator, model_serializer, model_validator

from firewall_compliance import __version__
from firewall_compliance.application.access_context import matrix_context_sources_by_digest
from firewall_compliance.application.access_matrix_v2 import MatrixSessionResolver
from firewall_compliance.application.cloud_sg_revision import CloudSGSelection
from firewall_compliance.application.matrix_catalog_bindings import split_catalog_bindings
from firewall_compliance.application.matrix_policy import matrix_catalog_switch_policy_contexts, matrix_policy_contexts
from firewall_compliance.application.workspace_profile import ProfileVersion
from firewall_compliance.domain.access_context import AccessContextResolution, AccessSession
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixAssessment, MatrixCatalogBinding
from firewall_compliance.domain.controls import ControlModel
from firewall_compliance.domain.matrix_context_inputs import MatrixContextInputs
from firewall_compliance.domain.revision import DeviceRevision


class MatrixContextEvidenceValidator:
    """Проверка происхождения сохранённых выводов по сеансам разных контекстов."""

    def __init__(self, inputs: MatrixContextInputs) -> None:
        self._resolver = MatrixSessionResolver(inputs)
        self._sources = matrix_context_sources_by_digest(inputs)
        self._evidence_ids: dict[str, set[str]] = {}
        self._sessions: dict[str, dict[str, AccessSession]] = {}
        for digest, source in self._sources.items():
            snapshot = source.snapshot
            self._evidence_ids[digest] = {
                item.evidence_id
                for facts in (snapshot.memberships, snapshot.devices, snapshot.sessions, snapshot.pools) for item in facts
            }
            self._sessions[digest] = {session.session_id: session for session in snapshot.sessions}

    def validate(self, requirement_id: str, result: AccessContextResolution, *, strict_time: bool = True) -> str:
        digest = result.snapshot_digest
        source = self._sources.get(digest)
        selected = self._resolver.session_for(requirement_id)
        if (
            source is None or result.session_id != selected
            or (selected is not None and source.snapshot.context_id != self.expected_context(requirement_id, None))
            or not self._evidence_ids[digest].issuperset(result.evidence_ids)
            or ((strict_time or result.status == "resolved") and result.evaluated_at != source.evaluated_at)
        ):
            raise ValueError("Результат сопоставления не относится к сохранённым свидетельствам")
        if result.status == "resolved":
            session = self._sessions[digest].get(result.session_id or "")
            if session is None:
                raise ValueError("Подтверждённый адрес не относится к сохранённому сеансу")
            address = ip_address(session.assigned_ip)
            if (
                source.evaluated_at > source.snapshot.captured_at or not session.active_at(source.evaluated_at)
                or session.evidence_id not in result.evidence_ids
                or result.source_cidr != f"{address}/{address.max_prefixlen}"
            ):
                raise ValueError("Подтверждённый адрес не относится к сохранённому сеансу")
        return source.snapshot.context_id

    def expected_context(self, requirement_id: str, policy_context: str | None) -> str:
        return self._resolver.source_for(requirement_id, policy_context).snapshot.context_id


class MatrixAssessmentArtifact(ControlModel):
    schema_version: Literal["1.0.0", "2.0.0"] = "1.0.0"
    artifact_id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    application_version: str = Field(default=__version__, min_length=1)
    origin_project_id: str = Field(min_length=1)
    origin_run_id: str | None = Field(default=None, min_length=1)
    origin_item_id: str | None = Field(default=None, min_length=1)
    matrix: AccessMatrix
    revision: DeviceRevision
    profile_settings_json: str | None = None
    assessment: MatrixAssessment
    bindings: tuple[MatrixCatalogBinding, ...] = ()
    cloud_selection: CloudSGSelection | None = None
    context_inputs: MatrixContextInputs | None = None

    @model_serializer(mode="wrap")
    def serialize_bindings(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload = handler(self)
        if self.schema_version == "1.0.0":
            payload.pop("bindings", None)
        if self.cloud_selection is None:
            payload.pop("cloud_selection", None)
        if self.context_inputs is None:
            payload.pop("context_inputs", None)
        return payload

    @field_validator("profile_settings_json")
    @classmethod
    def validate_profile(cls, value: str | None) -> str | None:
        if value is None:
            return None
        settings = json.loads(value)
        return ProfileVersion.from_settings("artifact-validation", 1, settings).settings_json

    @model_validator(mode="after")
    def validate_inputs(self) -> Self:
        if self.created_at.utcoffset() is None:
            raise ValueError("Assessment timestamp must include a timezone")
        if (self.origin_run_id is None) != (self.origin_item_id is None):
            raise ValueError("Run and item references must be supplied together")
        if self.cloud_selection is not None and (
            self.origin_run_id is not None or self.schema_version == "1.0.0"
        ):
            raise ValueError("Standalone cloud evidence requires assessment v2 and a single origin")
        result = self.assessment
        if (result.matrix_id, result.matrix_version) != (self.matrix.matrix_id, self.matrix.version):
            raise ValueError("Assessment does not refer to the embedded matrix")
        if result.revision_id != self.revision.revision_id:
            raise ValueError("Assessment does not refer to the embedded revision")
        if self.schema_version != self.matrix.schema_version or result.schema_version != self.matrix.schema_version:
            raise ValueError("Matrix, assessment and artifact schema versions differ")
        expected = Counter(row.requirement_id for row in self.matrix.requirements)
        expected.update(row.boundary_id for row in self.matrix.boundaries)
        actual = Counter(row.requirement_id for row in result.requirements)
        if (result.status != "cancelled" and expected != actual) or actual - expected:
            raise ValueError("Assessment requirements differ from the embedded matrix")
        referenced = {(member.kind, member.value) for group in self.matrix.groups for member in group.members}
        keys = {(binding.kind, binding.value) for binding in self.bindings}
        if not keys.issubset(referenced):
            raise ValueError("Invalid matrix catalog binding snapshot")
        _, scoped = split_catalog_bindings(self.bindings)
        if scoped and (
            self.schema_version != "2.0.0"
            or not scoped.keys() <= set(matrix_catalog_switch_policy_contexts(self.revision).values())
        ):
            raise ValueError("Состав каталога относится к неподтверждённому VRF ревизии")
        self._validate_context()
        rule_ids = {rule.rule_id for rule in self.revision.parse_result.rules}
        if any(
            identifier not in rule_ids
            for row in result.requirements
            for evidence in row.evidence
            for identifier in evidence.related_rule_ids
        ):
            raise ValueError("Assessment evidence refers to another revision")
        return self

    def _validate_context(self) -> None:
        results = [(row, resolution) for row in self.assessment.requirements
                   if (resolution := row.context_resolution) is not None]
        inputs = self.context_inputs
        if inputs is None:
            if results:
                raise ValueError("Context evidence is missing")
            return
        snapshot = inputs.snapshot
        if (
            self.schema_version != "2.0.0" or snapshot.project_id != self.origin_project_id
            or snapshot.scope_id != self.assessment.scope_id
        ):
            raise ValueError("Сведения о сеансах относятся к другому проекту или области")
        multiple_contexts = bool(inputs.additional_contexts)
        contextual = {
            row.requirement_id: row for row in self.matrix.requirements
            if row.access_context is not None and (not multiple_contexts or row.scope_id == self.assessment.scope_id)
        }
        referenced = {item.requirement_id for item in inputs.sessions}
        referenced.update(row.requirement_id for row, _ in results)
        if referenced - contextual.keys():
            raise ValueError("Сеансы указаны для требований без пользовательского контекста")
        if multiple_contexts and referenced:
            counts = Counter(row.requirement_id for row in self.matrix.requirements if row.requirement_id in referenced)
            counts.update(row.boundary_id for row in self.matrix.boundaries if row.boundary_id in referenced)
            if any(counts[key] != 1 for key in referenced):
                raise ValueError("Сеансы должны относиться к однозначным требованиям этой области")
        if not results:
            return
        validator = MatrixContextEvidenceValidator(inputs)
        policy_contexts = matrix_policy_contexts(self.revision) if multiple_contexts else {}
        for row, result in results:
            key = row.requirement_id
            source = validator.validate(key, result, strict_time=multiple_contexts)
            if not multiple_contexts:
                continue
            policy_context = policy_contexts.get(contextual[key].policy_id or "", self.revision.device.context)
            if source != validator.expected_context(key, policy_context) or (
                result.status == "resolved" and source != policy_context
            ):
                raise ValueError("Результат сопоставления относится к другому сетевому контексту")
            if self.assessment.status == "complete" or row.coverage_complete is not False:
                raise ValueError("Результат по одному сеансу не подтверждает полный охват требований")
            if result.status != "resolved" and (
                row.state not in {"insufficient_evidence", "requirement_conflict", "unregulated"} or row.evidence
            ):
                raise ValueError("Адресная оценка требует подтверждённого сеанса")
