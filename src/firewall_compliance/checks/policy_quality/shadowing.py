"""Policy check implementation."""

from firewall_compliance.checks.common.ordered_coverage import (
    CoverageSearchLimit,
    OrderedCoverageIndex,
)
from firewall_compliance.checks.common.policy import (
    PolicyCheckContext,
    _finding,
    _limitation,
    _pair_groups,
    _result,
    _same_effect,
)
from firewall_compliance.domain import Finding, Severity
from firewall_compliance.domain.assurance import CheckResult


class ShadowedRulesCheck:
    """Полное затенение одним более ранним терминальным правилом."""

    check_id = "FW-SHADOWED"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        groups, limitations = _pair_groups(context, enforce_pair_limit=False)
        findings: list[Finding] = []
        for rules in groups:
            if len(rules) < 2:
                continue
            coverage = OrderedCoverageIndex(rules, context.max_pair_rules)
            for position, rule in enumerate(rules):
                try:
                    earlier = coverage.first_covering((position,), before=position)
                except CoverageSearchLimit:
                    limitations.append(
                        _limitation(
                            "COVER_CANDIDATE_LIMIT",
                            "Исчерпан бюджет точных сравнений. Затенение от указанного правила "
                            "до конца этой области проверено не полностью.",
                            rule,
                        )
                    )
                    break
                if earlier is not None and (
                    coverage.matches[earlier] != coverage.matches[position]
                    or not _same_effect(rules[earlier], rule)
                ):
                    findings.append(
                        _finding(
                            context,
                            self.check_id,
                            (rules[earlier], rule),
                            "Правило полностью затенено более ранним правилом "
                            "в той же политике.",
                            Severity.MEDIUM,
                            "Проверить порядок и назначение обоих правил; "
                            "изменить условия или порядок после проверки влияния.",
                        )
                    )
        return _result(self.check_id, context, findings, limitations)
