"""RuleGovernanceCheck implementation."""

from __future__ import annotations

from firewall_compliance.checks.governance.rules_common import (
    _Budget,
    _GovernanceCheck,
    _limit,
    _LimitReached,
)
from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult
from firewall_compliance.domain.finding import Finding
from firewall_compliance.domain.policy_governance import RuleGovernanceMetadata


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
