"""Условный результат цепочки политик, отдельно от достижимости потока."""

from typing import Literal

from pydantic import Field, model_validator

from firewall_compliance.domain.forwarding import (
    ForwardingContext,
    ForwardingLocation,
    ForwardingModel,
)
from firewall_compliance.domain.policy_decision import PolicyTraceEntry
from firewall_compliance.domain.reachability import AnalysisReason

type ForwardingPolicyStatus = Literal[
    "allow", "deny", "drop", "reject", "implicit_deny", "unknown", "not_enough_evidence"
]
type ForwardingStageName = Literal[
    "applicability",
    "coordinates",
    "same_security",
    "ingress_acl",
    "global_acl",
    "inbound_default",
    "egress_acl",
    "runtime",
]
STAGE_ORDER: tuple[ForwardingStageName, ...] = (
    "applicability",
    "coordinates",
    "same_security",
    "ingress_acl",
    "global_acl",
    "inbound_default",
    "egress_acl",
    "runtime",
)


class ForwardingPolicyStage(ForwardingModel):
    stage: ForwardingStageName
    outcome: Literal[
        "passed",
        "allow",
        "deny",
        "drop",
        "reject",
        "no_match",
        "implicit_deny",
        "unknown",
        "not_enough_evidence",
        "not_applicable",
        "skipped",
    ]
    policy_id: str | None = Field(default=None, min_length=1)
    matched_rule_id: str | None = Field(default=None, min_length=1)
    rule_trace: tuple[PolicyTraceEntry, ...] = ()
    locations: tuple[ForwardingLocation, ...] = ()
    reasons: tuple[AnalysisReason, ...] = ()

    @model_validator(mode="after")
    def validate_trace(self) -> "ForwardingPolicyStage":
        if self.rule_trace:
            sequences = [entry.sequence for entry in self.rule_trace]
            if sequences != sorted(set(sequences)):
                raise ValueError("порядок ACE в этапе должен быть однозначным")
            if len({entry.rule_id for entry in self.rule_trace}) != len(self.rule_trace):
                raise ValueError("этап не должен повторять ACE")
            if any(entry.outcome in {"match", "unknown"} for entry in self.rule_trace[:-1]):
                raise ValueError("first-match trace завершается на совпадении или неизвестности")
        if self.matched_rule_id is not None and (
            self.policy_id is None
            or not self.rule_trace
            or self.rule_trace[-1].rule_id != self.matched_rule_id
            or self.rule_trace[-1].outcome != "match"
            or self.outcome not in {"allow", "deny", "drop", "reject"}
        ):
            raise ValueError("совпавший ACE должен подтверждаться trace этапа")
        if self.outcome in {"unknown", "not_enough_evidence"} and not self.reasons:
            raise ValueError("неопределённый этап требует причин")
        if (
            self.stage in {"ingress_acl", "global_acl", "egress_acl"}
            and self.outcome
            in {
                "allow",
                "deny",
                "drop",
                "reject",
            }
            and self.matched_rule_id is None
        ):
            raise ValueError("явное ACL решение требует совпавшего ACE")
        return self


class ForwardingPolicyResult(ForwardingModel):
    schema_version: Literal["0.1.0"] = "0.1.0"
    engine_version: Literal["0.1.0"] = "0.1.0"
    context: ForwardingContext
    ingress_interface_id: str = Field(min_length=1)
    egress_interface_id: str = Field(min_length=1)
    egress_basis: Literal["caller_supplied_conditional"] = "caller_supplied_conditional"
    status: Literal["unknown", "not_enough_evidence"]
    policy_status: ForwardingPolicyStatus
    trace: tuple[ForwardingPolicyStage, ...]
    reasons: tuple[AnalysisReason, ...]

    @model_validator(mode="after")
    def validate_result(self) -> "ForwardingPolicyResult":
        # Локальный импорт отделяет схемы от сервиса, который использует эти схемы этапов.
        from firewall_compliance.domain.forwarding_policy_evaluation import derive_forwarding_policy

        if tuple(entry.stage for entry in self.trace) != STAGE_ORDER:
            raise ValueError("результат должен сохранять все этапы в установленном порядке")
        if not any(reason.code == "runtime_pending" for reason in self.reasons):
            raise ValueError("итоговая достижимость требует непроверенных runtime этапов")
        if self.policy_status not in {"unknown", "not_enough_evidence"}:
            if self.status != "unknown" or any(
                entry.outcome in {"unknown", "not_enough_evidence"} for entry in self.trace[:-1]
            ):
                raise ValueError("условное решение не скрывает неизвестные предшествующие этапы")
            decisive = [
                entry.outcome
                for entry in self.trace[:-1]
                if entry.outcome
                in {
                    "allow",
                    "deny",
                    "drop",
                    "reject",
                    "implicit_deny",
                }
            ]
            if not decisive or decisive[-1] != self.policy_status:
                raise ValueError("условное решение не соответствует последнему решающему этапу")
        calculated = derive_forwarding_policy(
            self.context,
            ingress_interface_id=self.ingress_interface_id,
            egress_interface_id=self.egress_interface_id,
        )
        if (self.status, self.policy_status, self.trace, self.reasons) != (
            calculated.status,
            calculated.policy_status,
            calculated.trace,
            calculated.reasons,
        ):
            raise ValueError("результат не соответствует повторному расчёту цепочки")
        return self
