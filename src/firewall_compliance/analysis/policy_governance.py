"""Bounded metadata and observed-usage checks without inferred rule properties or I/O."""

import json
from hashlib import sha256
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.analysis.policy_checks import PolicyCheckContext
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


class RuleGovernanceCheck(_GovernanceCheck):
    """Assess required metadata and dates at the explicitly supplied analysis time."""

    check_id = "FW-RULE-GOVERNANCE"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        enabled = self.profile.lifecycle_enabled
        if enabled is False:
            return self._not_applicable()
        if enabled is None:
            return self._result(
                context,
                [],
                [
                    _limit(
                        "GOVERNANCE_POLICY_UNKNOWN",
                        "Не задано требование контроля жизненного цикла.",
                    )
                ],
                False,
            )
        requirements = {
            "owner": self.profile.require_owner,
            "justification": self.profile.require_justification,
            "temporary_expiry": self.profile.require_temporary_expiry,
            "review_date": self.profile.require_review_date,
        }
        if all(value is False for value in requirements.values()):
            return self._not_applicable()
        findings: list[Finding] = []
        limitations = [
            _limit("GOVERNANCE_POLICY_UNKNOWN", f"Не определено требование {name}.")
            for name, required in requirements.items()
            if required is None
        ]
        executed = False
        budget = _Budget(self.max_operations)
        try:
            rules, issues = self._rules(context, budget)
            limitations.extend(issues)
            metadata = (
                {record.rule_id: record for record in self.inputs.metadata} if self.inputs else {}
            )
            for rule in rules:
                budget.spend()
                record = metadata.get(rule.rule_id)
                if record is None:
                    limitations.append(
                        _limit(
                            "RULE_METADATA_UNKNOWN", "Нет явных метаданных правила.", rule.rule_id
                        )
                    )
                    continue
                if record.observed_at > context.analyzed_at:
                    limitations.append(
                        _limit(
                            "FUTURE_EVIDENCE",
                            "Метаданные наблюдены позже даты оценки.",
                            rule.rule_id,
                        )
                    )
                    continue
                violations, issues, assessed = self._assess(context, record, requirements, budget)
                executed |= assessed
                limitations.extend(issues)
                if violations:
                    findings.append(self._finding(context, rule, record, violations, budget))
        except _LimitReached:
            limitations.append(
                _limit(
                    "GOVERNANCE_LIMIT_REACHED",
                    "Исчерпан бюджет операций; оставшиеся правила не проверены.",
                )
            )
        return self._result(context, findings, limitations, executed)

    @staticmethod
    def _assess(
        context: PolicyCheckContext,
        record: RuleGovernanceMetadata,
        requirements: dict[str, bool | None],
        budget: _Budget,
    ) -> tuple[list[str], list[CheckLimitation], bool]:
        violations = []
        issues = []
        assessed = False
        for name in ("owner", "justification"):
            budget.spend()
            if requirements[name] is not True:
                continue
            value = record.owner if name == "owner" else record.justification
            if value is None:
                issues.append(
                    _limit("RULE_METADATA_UNKNOWN", f"Значение {name} неизвестно.", record.rule_id)
                )
            else:
                assessed = True
                if not value:
                    violations.append(f"MISSING_{name.upper()}")
        budget.spend()
        if requirements["temporary_expiry"] is True:
            if record.temporary is None:
                issues.append(
                    _limit(
                        "RULE_METADATA_UNKNOWN",
                        "Неизвестно, является ли правило временным.",
                        record.rule_id,
                    )
                )
            elif record.temporary:
                if record.expiry_status == "unknown":
                    issues.append(
                        _limit(
                            "RULE_METADATA_UNKNOWN",
                            "Срок временного правила неизвестен.",
                            record.rule_id,
                        )
                    )
                else:
                    assessed = True
                    if record.expiry_status == "absent":
                        violations.append("MISSING_TEMPORARY_EXPIRY")
                    elif record.expires_at is not None and record.expires_at <= context.analyzed_at:
                        violations.append("TEMPORARY_PERMISSION_EXPIRED")
            else:
                assessed = True
        budget.spend()
        if requirements["review_date"] is True:
            if record.review_status == "unknown":
                issues.append(
                    _limit("RULE_METADATA_UNKNOWN", "Дата пересмотра неизвестна.", record.rule_id)
                )
            else:
                assessed = True
                if record.review_status == "absent":
                    violations.append("MISSING_REVIEW_DATE")
                elif record.review_at is not None and record.review_at <= context.analyzed_at:
                    violations.append("REVIEW_OVERDUE")
        return violations, issues, assessed


class UnusedRuleCandidatesCheck(_GovernanceCheck):
    """A zero-hit candidate requires a sufficient complete stable window without resets."""

    check_id = "FW-UNUSED-CANDIDATE"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        if self.profile.unused_enabled is False:
            return self._not_applicable()
        if (
            self.profile.unused_enabled is None
            or self.profile.unused_min_observation_seconds is None
            or self.profile.unused_max_age_seconds is None
        ):
            return self._result(
                context,
                [],
                [
                    _limit(
                        "GOVERNANCE_POLICY_UNKNOWN",
                        "Не заданы требования к периоду и актуальности наблюдения.",
                    )
                ],
                False,
            )
        findings: list[Finding] = []
        limitations: list[CheckLimitation] = []
        executed = False
        budget = _Budget(self.max_operations)
        try:
            rules, issues = self._rules(context, budget)
            limitations.extend(issues)
            statistics = (
                {record.rule_id: record for record in self.inputs.statistics} if self.inputs else {}
            )
            for rule in rules:
                budget.spend()
                record = statistics.get(rule.rule_id)
                if record is None:
                    limitations.append(
                        _limit(
                            "RULE_STATISTICS_UNKNOWN",
                            "Нет статистики для точной ревизии и правила.",
                            rule.rule_id,
                        )
                    )
                    continue
                issues = self._assess(context, record, budget)
                limitations.extend(issues)
                if issues:
                    continue
                executed = True
                if record.hits == 0:
                    findings.append(
                        self._finding(
                            context, rule, record, ["ZERO_HITS_IN_QUALIFIED_WINDOW"], budget
                        )
                    )
        except _LimitReached:
            limitations.append(
                _limit(
                    "GOVERNANCE_LIMIT_REACHED",
                    "Исчерпан бюджет операций; оставшиеся правила не проверены.",
                )
            )
        return self._result(context, findings, limitations, executed)

    def _assess(
        self, context: PolicyCheckContext, record: RuleObservationStatistics, budget: _Budget
    ) -> list[CheckLimitation]:
        budget.spend(8)
        issues = []
        if record.observed_at > context.analyzed_at:
            issues.append(
                _limit("FUTURE_EVIDENCE", "Статистика наблюдена позже даты оценки.", record.rule_id)
            )
        if record.hits is None or record.count_kind != "window_delta":
            issues.append(
                _limit(
                    "UNPROVEN_WINDOW_COUNTER",
                    "Не подтверждено число совпадений за интервал.",
                    record.rule_id,
                )
            )
        if record.coverage != "complete":
            issues.append(
                _limit(
                    "INCOMPLETE_OBSERVATION", "Полнота наблюдения не подтверждена.", record.rule_id
                )
            )
        if record.counter_resets != 0:
            issues.append(
                _limit(
                    "COUNTER_RESET_UNKNOWN_OR_PRESENT",
                    "Отсутствие сбросов счётчика не подтверждено.",
                    record.rule_id,
                )
            )
        if record.revision_stable is not True:
            issues.append(
                _limit(
                    "UNSTABLE_POLICY_WINDOW",
                    "Не подтверждена неизменность ревизии на всём интервале.",
                    record.rule_id,
                )
            )
        if record.window_start is None or record.window_end is None:
            issues.append(
                _limit(
                    "OBSERVATION_WINDOW_UNKNOWN", "Интервал наблюдения неизвестен.", record.rule_id
                )
            )
        else:
            minimum = self.profile.unused_min_observation_seconds
            maximum_age = self.profile.unused_max_age_seconds
            if (
                minimum is None
                or (record.window_end - record.window_start).total_seconds() < minimum
            ):
                issues.append(
                    _limit(
                        "OBSERVATION_WINDOW_TOO_SHORT",
                        "Период наблюдения меньше требования профиля.",
                        record.rule_id,
                    )
                )
            if (
                maximum_age is None
                or (context.analyzed_at - record.window_end).total_seconds() > maximum_age
            ):
                issues.append(
                    _limit(
                        "OBSERVATION_TOO_OLD",
                        "Наблюдение не удовлетворяет требованию актуальности.",
                        record.rule_id,
                    )
                )
        return issues
