"""Bounded metadata and observed-usage checks without inferred rule properties or I/O."""

import json
from hashlib import sha256
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult, CheckStatus
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import FindingCategory, Severity
from firewall_compliance.domain.finding import Evidence, Finding
from firewall_compliance.domain.policy_governance import (
    PolicyGovernanceInputs,
    PolicyGovernanceProfile,
    RuleGovernanceMetadata,
    RuleObservationStatistics,
)

CHECK_VERSION = "1.0.0"


def _fingerprint(
    value: PolicyGovernanceProfile
    | PolicyGovernanceInputs
    | RuleGovernanceMetadata
    | RuleObservationStatistics,
) -> str:
    payload = json.dumps(
        value.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return sha256(payload.encode("utf-8")).hexdigest()


class _LimitReached(Exception):
    pass


class _Budget:
    def __init__(self, maximum: int) -> None:
        self.remaining = maximum

    def spend(self, amount: int = 1) -> None:
        self.remaining -= amount
        if self.remaining < 0:
            raise _LimitReached


def _limit(code: str, message: str, rule_id: str | None = None) -> CheckLimitation:
    return CheckLimitation(code=code, message=message, rule_ids=(rule_id,) if rule_id else ())


class _GovernanceCheck:
    check_id: str

    def __init__(
        self,
        profile: PolicyGovernanceProfile | None = None,
        inputs: PolicyGovernanceInputs | None = None,
        *,
        max_operations: int = 100000,
    ) -> None:
        if type(max_operations) is not int or not 1 <= max_operations <= 10000000:
            raise ValueError("max_operations must be an integer in 1..10000000")
        self.profile = PolicyGovernanceProfile.model_validate(
            (profile or PolicyGovernanceProfile()).model_dump(mode="python")
        ).as_snapshot()
        self.inputs = (
            PolicyGovernanceInputs.model_validate(inputs.model_dump(mode="python")).as_snapshot()
            if inputs is not None
            else None
        )
        self.max_operations = max_operations
        self.profile_sha256 = _fingerprint(self.profile)
        self.inputs_sha256 = _fingerprint(self.inputs) if self.inputs is not None else None

    def _result(
        self,
        context: PolicyCheckContext,
        findings: list[Finding],
        limitations: list[CheckLimitation],
        executed: bool,
    ) -> CheckResult:
        parsed = context.revision.parse_result
        if (
            parsed.errors
            or parsed.warnings
            or parsed.unsupported_constructs
            or parsed.coverage.coverage_ratio < 1
        ):
            limitations.append(
                _limit("INCOMPLETE_PARSE", "Источник правил разобран с ограничениями.")
            )
        if not executed and limitations:
            limitations.append(
                _limit("CHECK_NOT_EXECUTED", "Нет достаточных данных для выполнения проверки.")
            )
        unique = {(item.code, item.message, item.rule_ids): item for item in limitations}
        return CheckResult(
            check_id=self.check_id,
            check_version=CHECK_VERSION,
            status=CheckStatus.PARTIAL if unique else CheckStatus.COMPLETE,
            findings=tuple(findings),
            limitations=tuple(unique.values()),
        )

    def _not_applicable(self) -> CheckResult:
        return CheckResult(
            check_id=self.check_id, check_version=CHECK_VERSION, status=CheckStatus.NOT_APPLICABLE
        )

    def _rules(
        self, context: PolicyCheckContext, budget: _Budget
    ) -> tuple[list[Rule], list[CheckLimitation]]:
        if self.inputs is None:
            return [], [
                _limit(
                    "GOVERNANCE_INPUTS_UNKNOWN", "Не заданы явные метаданные или статистика правил."
                )
            ]
        if self.inputs.revision_id != context.revision.revision_id:
            return [], [
                _limit("GOVERNANCE_REVISION_MISMATCH", "Доказательства относятся к другой ревизии.")
            ]
        if context.analyzed_at.tzinfo is None:
            raise ValueError("analyzed_at must include a timezone")
        rules = []
        seen = set()
        for rule in context.revision.parse_result.rules:
            budget.spend()
            if rule.rule_id in seen:
                return [], [
                    _limit("AMBIGUOUS_RULE_ID", "ID правила неоднозначен в ревизии.", rule.rule_id)
                ]
            seen.add(rule.rule_id)
            if rule.enabled or self.profile.include_disabled_rules:
                rules.append(rule)
        issues = []
        for record in (*self.inputs.metadata, *self.inputs.statistics):
            budget.spend()
            if record.rule_id not in seen:
                issues.append(
                    _limit(
                        "ORPHAN_RULE_EVIDENCE",
                        "Доказательство ссылается на неизвестный ID правила.",
                        record.rule_id,
                    )
                )
        return rules, issues

    def _finding(
        self,
        context: PolicyCheckContext,
        rule: Rule,
        record: RuleGovernanceMetadata | RuleObservationStatistics,
        violations: list[str],
        budget: _Budget,
    ) -> Finding:
        budget.spend(len(rule.sources) + len(rule.destinations) + len(rule.services) + 1)
        for endpoint in (*rule.sources, *rule.destinations):
            budget.spend(len(endpoint.cidrs) + len(endpoint.ip_ranges))
        for service in rule.services:
            budget.spend(len(service.port_ranges))
        unused = isinstance(record, RuleObservationStatistics)
        title = (
            "Кандидат в неиспользуемые правила по наблюдённому интервалу."
            if unused
            else "Метаданные правила нарушают организационные требования."
        )
        record_hash = _fingerprint(record)
        return Finding(
            finding_id=uuid5(
                NAMESPACE_URL,
                f"{context.revision.revision_id}:{self.check_id}:{CHECK_VERSION}:{self.profile_sha256}:{record_hash}:{violations}",
            ),
            check_id=self.check_id,
            category=FindingCategory.POLICY,
            severity=Severity.LOW if unused else Severity.MEDIUM,
            title=title,
            description="; ".join(violations),
            configuration_id=context.revision.parse_result.configuration.configuration_id,
            revision_id=context.revision.revision_id,
            device_id=context.revision.device.device_id,
            affected_rule_ids=(rule.rule_id,),
            evidence=Evidence(
                summary=title,
                source_locations=(rule.source_location, record.source_location),
                related_rule_ids=(rule.rule_id,),
                facts={
                    "basis": "observed_usage_candidate"
                    if unused
                    else "explicit_rule_governance_metadata",
                    "profile_id": self.profile.profile_id,
                    "profile_version": self.profile.version,
                    "profile_sha256": self.profile_sha256,
                    "input_id": self.inputs.input_id if self.inputs is not None else None,
                    "input_sha256": self.inputs_sha256,
                    "evidence_id": record.evidence_id,
                    "evidence_sha256": record_hash,
                    "evaluated_at": context.analyzed_at.isoformat(),
                    "violations": violations,
                    "record": record.model_dump(mode="json"),
                    "rule": rule.model_dump(mode="json"),
                },
                limitations=(
                    "Вывод основан на явных метаданных или наблюдениях; комментарии "
                    "и отсутствие данных не интерпретируются как доказательство.",
                    "Кандидат или истёкший срок не доказывает безопасность удаления "
                    "правила и не подтверждает сетевую достижимость.",
                ),
            ),
            recommendation=(
                "Проверить владельца, назначение и исключения; согласовать изменение "
                "с ответственным. Не удалять правило автоматически."
            ),
            confidence=1.0,
            first_seen=context.analyzed_at,
            last_seen=context.analyzed_at,
        )
