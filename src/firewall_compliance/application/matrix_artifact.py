"""Воспроизводимый результат сверки: сохранённые входы, без повторного анализа."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from firewall_compliance import __version__
from firewall_compliance.application.workspace_profile import ProfileVersion
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixAssessment
from firewall_compliance.domain.controls import ControlModel
from firewall_compliance.domain.revision import DeviceRevision


class MatrixAssessmentArtifact(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
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
        result = self.assessment
        if (result.matrix_id, result.matrix_version) != (self.matrix.matrix_id, self.matrix.version):
            raise ValueError("Assessment does not refer to the embedded matrix")
        if result.revision_id != self.revision.revision_id:
            raise ValueError("Assessment does not refer to the embedded revision")
        expected = sorted(row.requirement_id for row in self.matrix.requirements)
        if expected != sorted(row.requirement_id for row in result.requirements):
            raise ValueError("Assessment requirements differ from the embedded matrix")
        rule_ids = {rule.rule_id for rule in self.revision.parse_result.rules}
        if any(
            identifier not in rule_ids
            for row in result.requirements
            for evidence in row.evidence
            for identifier in evidence.related_rule_ids
        ):
            raise ValueError("Assessment evidence refers to another revision")
        return self
