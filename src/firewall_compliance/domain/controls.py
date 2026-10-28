"""Versioned organizational technical controls; no assertion of certification."""

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import ConfigDict, Field, JsonValue, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.snapshot import freeze_snapshot_fields

ControlState = Literal[
    "technical_violation",
    "no_violation_in_examined_scope",
    "insufficient_evidence",
    "not_applicable",
]


def _plain(value: Any) -> Any:
    if isinstance(value, DomainModel):
        return value.model_dump(mode="python")
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


class ControlModel(DomainModel):
    """Validate construction/copies and freeze nested caller-owned values."""

    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def validate_nested(cls, value: Any) -> Any:
        return _plain(value)

    @model_validator(mode="after")
    def freeze(self) -> Self:
        freeze_snapshot_fields(self)
        return self

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        payload = self.model_dump(mode="python")
        payload.update(update or {})
        return self.__class__.model_validate(payload)


class ControlDefinition(ControlModel):
    control_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    statement: str = Field(min_length=1, max_length=4096)
    limitations: tuple[str, ...] = Field(min_length=1, max_length=64)


class CheckControlMapping(ControlModel):
    mapping_id: str = Field(min_length=1, max_length=128)
    control_id: str = Field(min_length=1, max_length=128)
    check_id: str = Field(min_length=1, max_length=128)
    check_versions: tuple[str, ...] = Field(min_length=1, max_length=16)
    source: str = Field(min_length=1, max_length=512)
    edition: str = Field(min_length=1, max_length=128)
    source_control_id: str = Field(min_length=1, max_length=128)
    rationale: str = Field(min_length=1, max_length=4096)
    covered_part: str = Field(min_length=1, max_length=4096)
    limits: tuple[str, ...] = Field(min_length=1, max_length=64)


class ControlCatalogue(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    catalogue_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    controls: tuple[ControlDefinition, ...] = Field(min_length=1, max_length=256)
    mappings: tuple[CheckControlMapping, ...] = Field(max_length=1024)

    @model_validator(mode="after")
    def validate_links(self) -> Self:
        ids = [control.control_id for control in self.controls]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate control IDs")
        links = [mapping.mapping_id for mapping in self.mappings]
        if len(set(links)) != len(links):
            raise ValueError("duplicate mapping IDs")
        pairs = [(mapping.control_id, mapping.check_id) for mapping in self.mappings]
        if len(set(pairs)) != len(pairs):
            raise ValueError("one control/check pair requires one explicit versioned mapping")
        if any(mapping.control_id not in ids for mapping in self.mappings):
            raise ValueError("mapping references unknown control")
        if len(self.model_dump_json().encode("utf-8")) > 1024 * 1024:
            raise ValueError("control catalogue exceeds 1 MiB")
        return self


class ControlRequirement(ControlModel):
    control_id: str = Field(min_length=1, max_length=128)
    applicable: bool = Field(strict=True)
    justification: str = Field(min_length=1, max_length=4096)
    # Values are compared to exact PolicyAnalysisOptions values, never treated as settings.
    parameters: dict[str, JsonValue] = Field(default_factory=dict, max_length=16)

    @model_validator(mode="after")
    def validate_parameters(self) -> Self:
        allowed = {"require_logging", "require_comments", "management_profile", "exposure_profile"}
        if set(self.parameters) - allowed:
            raise ValueError("unsupported policy assessment parameter")
        for name in ("require_logging", "require_comments"):
            if name in self.parameters and type(self.parameters[name]) is not bool:
                raise ValueError("boolean policy requirements require explicit booleans")
        if len(json.dumps(self.parameters, allow_nan=False).encode("utf-8")) > 128 * 1024:
            raise ValueError("assessment parameters exceed 128 KiB")
        return self


class ControlException(ControlModel):
    exception_id: str = Field(min_length=1, max_length=128)
    control_id: str = Field(min_length=1, max_length=128)
    component_id: str = Field(min_length=1, max_length=256)
    finding_id: UUID
    reason: str = Field(min_length=1, max_length=4096)
    approved_by: str = Field(min_length=1, max_length=256)
    approved_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if self.approved_at.utcoffset() is None or self.expires_at.utcoffset() is None:
            raise ValueError("exception dates require timezones")
        if self.expires_at <= self.approved_at:
            raise ValueError("exception expiry must follow approval")
        return self


class OrganizationControlProfile(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    profile_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    organization: str = Field(min_length=1, max_length=256)
    scope_reference: str = Field(min_length=1, max_length=4096)
    # None selects every policy component in the retained bundle, not every asset in inventory.
    component_ids: tuple[str, ...] | None = Field(default=None, max_length=1000)
    requirements: tuple[ControlRequirement, ...] = Field(min_length=1, max_length=256)
    exceptions: tuple[ControlException, ...] = Field(default=(), max_length=4096)

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        ids = [item.control_id for item in self.requirements]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate profile requirements")
        if self.component_ids is not None and (
            not self.component_ids
            or len(set(self.component_ids)) != len(self.component_ids)
            or any(not value.strip() for value in self.component_ids)
        ):
            raise ValueError("explicit assessment scope requires unique nonempty component IDs")
        exceptions = [item.exception_id for item in self.exceptions]
        targets = [
            (item.control_id, item.component_id, item.finding_id) for item in self.exceptions
        ]
        if len(set(exceptions)) != len(exceptions) or len(set(targets)) != len(targets):
            raise ValueError("duplicate profile exception")
        if any(item.control_id not in ids for item in self.exceptions):
            raise ValueError("exception references an unselected control")
        if self.component_ids is not None and any(
            item.component_id not in self.component_ids for item in self.exceptions
        ):
            raise ValueError("exception outside explicit component scope")
        return self


class ControlCheckEvidence(ControlModel):
    mapping_id: str
    check_id: str
    check_version: str | None = None
    execution: Literal["complete", "partial", "not_applicable", "not_executed", "missing"]
    sufficient: bool = Field(strict=True)
    finding_ids: tuple[UUID, ...] = ()
    active_exception_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


class ControlEvaluation(ControlModel):
    control_id: str
    component_id: str | None
    revision_id: UUID | None = None
    state: ControlState
    evidence: tuple[ControlCheckEvidence, ...] = ()
    limitations: tuple[str, ...] = ()


class ControlCoverage(ControlModel):
    evaluations: int = Field(ge=0)
    applicable_evaluations: int = Field(ge=0)
    fully_examined_evaluations: int = Field(ge=0)
    expected_check_evaluations: int = Field(ge=0)
    executed_check_evaluations: int = Field(ge=0)
    sufficient_check_evaluations: int = Field(ge=0)
    violations: int = Field(ge=0)
    no_violations_in_examined_scope: int = Field(ge=0)
    insufficient_evidence: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
