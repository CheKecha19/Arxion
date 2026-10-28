"""Explicit organization requirements and revision-bound rule governance evidence."""

from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import ConfigDict, Field, StrictBool, StrictInt, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.source import SourceLocation


class PolicyGovernanceProfile(DomainModel):
    """Unknown requirements are distinct from an explicitly disabled requirement."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    schema_version: Literal["1.0.0"] = "1.0.0"
    profile_id: str = Field(default="rule-governance", min_length=1, max_length=128)
    version: str = Field(default="1", min_length=1, max_length=64)
    lifecycle_enabled: StrictBool | None = None
    require_owner: StrictBool | None = None
    require_justification: StrictBool | None = None
    require_temporary_expiry: StrictBool | None = None
    require_review_date: StrictBool | None = None
    include_disabled_rules: StrictBool = False
    unused_enabled: StrictBool | None = None
    unused_min_observation_seconds: StrictInt | None = Field(default=None, ge=1, le=315360000)
    unused_max_age_seconds: StrictInt | None = Field(default=None, ge=0, le=315360000)


class _RuleEvidence(DomainModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    evidence_id: str = Field(min_length=1, max_length=128)
    revision_id: UUID
    rule_id: str = Field(min_length=1, max_length=256)
    observed_at: datetime
    reference: str = Field(min_length=1, max_length=2048)
    source_location: SourceLocation

    @model_validator(mode="after")
    def validate_time(self) -> Self:
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must include a timezone")
        return self


class RuleGovernanceMetadata(_RuleEvidence):
    """None is unknown; an explicitly empty owner/justification means known absence."""

    owner: str | None = Field(default=None, max_length=256)
    justification: str | None = Field(default=None, max_length=4096)
    temporary: StrictBool | None = None
    expiry_status: Literal["known", "absent", "unknown"] = "unknown"
    expires_at: datetime | None = None
    review_status: Literal["known", "absent", "unknown"] = "unknown"
    review_at: datetime | None = None

    @model_validator(mode="after")
    def validate_dates(self) -> Self:
        for status, value in (
            (self.expiry_status, self.expires_at),
            (self.review_status, self.review_at),
        ):
            if (status == "known") != (value is not None):
                raise ValueError(
                    "known date requires a value; absent/unknown must not carry a date"
                )
            if value is not None and value.tzinfo is None:
                raise ValueError("governance dates must include a timezone")
        return self


class RuleObservationStatistics(_RuleEvidence):
    """A sample alone cannot establish a zero-hit interval or stable policy coverage."""

    window_start: datetime | None = None
    window_end: datetime | None = None
    hits: StrictInt | None = Field(default=None, ge=0, le=18446744073709551615)
    count_kind: Literal["window_delta", "cumulative_sample", "unknown"] = "unknown"
    coverage: Literal["complete", "partial", "unknown"] = "unknown"
    counter_resets: StrictInt | None = Field(default=None, ge=0, le=1000000)
    revision_stable: StrictBool | None = None

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if (self.window_start is None) != (self.window_end is None):
            raise ValueError("observation window requires both start and end")
        if self.window_start is not None and self.window_end is not None:
            if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
                raise ValueError("observation window must include timezones")
            if self.window_end < self.window_start or self.observed_at < self.window_end:
                raise ValueError("observation window must precede collection and have valid order")
        return self


class PolicyGovernanceInputs(DomainModel):
    """One immutable input document targets exactly one saved revision, never a rule name guess."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    schema_version: Literal["1.0.0"] = "1.0.0"
    input_id: str = Field(min_length=1, max_length=128)
    revision_id: UUID
    metadata: tuple[RuleGovernanceMetadata, ...] = Field(default=(), max_length=4096)
    statistics: tuple[RuleObservationStatistics, ...] = Field(default=(), max_length=4096)

    @model_validator(mode="after")
    def validate_links(self) -> Self:
        records = (*self.metadata, *self.statistics)
        if any(record.revision_id != self.revision_id for record in records):
            raise ValueError("all evidence records must reference the input revision")
        if len({record.evidence_id for record in records}) != len(records):
            raise ValueError("evidence IDs must be unique")
        for collection in (self.metadata, self.statistics):
            if len({record.rule_id for record in collection}) != len(collection):
                raise ValueError("each collection permits one evidence record per rule")
        return self
