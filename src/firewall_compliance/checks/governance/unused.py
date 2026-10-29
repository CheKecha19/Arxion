"""UnusedRuleCandidatesCheck implementation."""

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
from firewall_compliance.domain.policy_governance import RuleObservationStatistics


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
