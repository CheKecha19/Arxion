"""Локальные решения ACL и административного состояния, не итог потока."""

from typing import Any, Literal
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.reachability import (
    AnalysisReason,
    ReachabilityQuery,
    RouteSelectionResult,
)
from firewall_compliance.domain.revision import Interface, RevisionSource
from firewall_compliance.domain.snapshot import freeze_snapshot_fields
from firewall_compliance.domain.source import SourceLocation

PolicyDecisionStatus = Literal[
    "allow", "deny", "drop", "reject", "no_match", "implicit_deny", "unknown", "not_enough_evidence"
]


class _DecisionSnapshot(DomainModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    @field_validator("*", mode="before")
    @classmethod
    def revalidate_nested(cls, value: Any) -> Any:
        if isinstance(value, DomainModel):
            return value.model_dump(mode="python")
        if isinstance(value, (tuple, list)):
            return [cls.revalidate_nested(item) for item in value]
        if isinstance(value, dict):
            return {key: cls.revalidate_nested(item) for key, item in value.items()}
        return value

    @model_validator(mode="after")
    def freeze(self) -> "_DecisionSnapshot":
        freeze_snapshot_fields(self)
        return self


class PolicyBindingEvidence(_DecisionSnapshot):
    schema_version: Literal["0.1.0"] = "0.1.0"
    policy_id: str = Field(min_length=1)
    direction: Literal["in", "out"]
    interface_id: str = Field(min_length=1)
    interface_label: str = Field(min_length=1)
    interface_mapping_reference: str = Field(min_length=1)
    source_document_id: UUID
    binding_location: SourceLocation
    complete: bool = Field(default=False, strict=True)
    completeness_reference: str | None = Field(default=None, min_length=1)
    declaration_origin: Literal["synthetic", "operator_declared"]
    implicit_action: Literal["deny", "unknown"] = "unknown"
    terminal: bool = Field(default=False, strict=True)
    terminal_reference: str | None = Field(default=None, min_length=1)
    coordinate_space: Literal["acl_input"]

    @field_validator(
        "policy_id",
        "interface_id",
        "interface_label",
        "interface_mapping_reference",
        "completeness_reference",
        "terminal_reference",
    )
    @classmethod
    def reject_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("идентификатор или основание не может состоять из пробелов")
        return value

    @model_validator(mode="after")
    def validate_completeness(self) -> "PolicyBindingEvidence":
        if self.complete and not self.completeness_reference:
            raise ValueError("полнота ACL требует явного основания")
        if self.terminal and not self.terminal_reference:
            raise ValueError("конец цепочки ACL требует явного основания")
        return self


class PolicyTraceEntry(_DecisionSnapshot):
    rule_id: str = Field(min_length=1)
    sequence: int = Field(ge=0, strict=True)
    outcome: Literal["disabled", "no_match", "match", "unknown"]
    source_location: SourceLocation


class PolicyDecisionResult(_DecisionSnapshot):
    schema_version: Literal["0.1.0"] = "0.1.0"
    engine_version: Literal["0.1.0"] = "0.1.0"
    query: ReachabilityQuery
    binding: PolicyBindingEvidence
    status: PolicyDecisionStatus
    matched_rule_id: str | None = Field(default=None, min_length=1)
    trace: tuple[PolicyTraceEntry, ...] = ()
    reasons: tuple[AnalysisReason, ...] = ()
    sources: tuple[RevisionSource, ...]
    evidence: Evidence

    @model_validator(mode="after")
    def validate_decision(self) -> "PolicyDecisionResult":
        ids = [entry.rule_id for entry in self.trace]
        if len(set(ids)) != len(ids):
            raise ValueError("trace не должен повторять правила")
        sequences = [entry.sequence for entry in self.trace]
        if sequences != sorted(set(sequences)):
            raise ValueError("trace требует однозначного возрастающего порядка")
        if any(entry.outcome in {"match", "unknown"} for entry in self.trace[:-1]):
            raise ValueError("trace завершается на первом совпадении или неизвестном условии")
        explicit = self.status in {"allow", "deny", "drop", "reject"}
        if explicit:
            if not self.trace or self.trace[-1].outcome != "match":
                raise ValueError("явное решение требует последнего совпавшего правила")
            if self.matched_rule_id != self.trace[-1].rule_id:
                raise ValueError("matched_rule_id не совпадает с trace")
        elif self.matched_rule_id is not None:
            raise ValueError("неявное или неопределённое решение не имеет matched_rule_id")
        if self.status in {"unknown", "not_enough_evidence"} and not self.reasons:
            raise ValueError("неопределённое решение требует причин")
        if self.status not in {"unknown", "not_enough_evidence"}:
            if not self.binding.complete or self.reasons:
                raise ValueError("локальное решение требует полноты без противоречий")
            if any(entry.outcome == "unknown" for entry in self.trace):
                raise ValueError("неизвестный предшественник исключает локальное решение")
        if self.status == "implicit_deny" and (
            self.binding.implicit_action != "deny" or not self.binding.terminal
        ):
            raise ValueError("implicit deny требует доказанного конца цепочки")
        if self.status in {"no_match", "implicit_deny"} and (
            not self.trace
            or any(entry.outcome not in {"disabled", "no_match"} for entry in self.trace)
        ):
            raise ValueError("no_match требует проверенного непустого набора правил")
        return self


class InterfaceDecisionResult(_DecisionSnapshot):
    schema_version: Literal["0.1.0"] = "0.1.0"
    interface_id: str = Field(min_length=1)
    status: Literal["administratively_enabled", "administratively_disabled", "unknown"]
    interface: Interface | None = None
    reasons: tuple[AnalysisReason, ...] = ()
    evidence: Evidence

    @model_validator(mode="after")
    def validate_interface(self) -> "InterfaceDecisionResult":
        if self.interface is not None and self.interface.interface_id != self.interface_id:
            raise ValueError("решение относится к другому интерфейсу")
        if self.status == "unknown":
            if not self.reasons:
                raise ValueError("неизвестное состояние требует причины")
        else:
            if (
                self.interface is None
                or self.interface.data_status != DataStatus.KNOWN
                or self.reasons
            ):
                raise ValueError("известное состояние требует факта интерфейса")
            expected = self.status == "administratively_enabled"
            if self.interface.enabled is not expected:
                raise ValueError("административное состояние не соответствует факту")
        return self


class SingleDeviceDecisionResult(_DecisionSnapshot):
    schema_version: Literal["0.1.0"] = "0.1.0"
    status: Literal["unknown", "not_enough_evidence"]
    route_selection: RouteSelectionResult
    interfaces: tuple[InterfaceDecisionResult, ...]
    policy: PolicyDecisionResult
    reasons: tuple[AnalysisReason, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_query(self) -> "SingleDeviceDecisionResult":
        if self.route_selection.query != self.policy.query:
            raise ValueError("локальные этапы должны относиться к одному запросу")
        ids = [item.interface_id for item in self.interfaces]
        if len(set(ids)) != len(ids):
            raise ValueError("решения интерфейсов не должны повторяться")
        return self
