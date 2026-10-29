"""Policy check implementation."""

from firewall_compliance.analysis.policy_matching import RuleMatch, resolve_rule
from firewall_compliance.checks.common.policy import (
    PolicyCheckContext,
    _finding,
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
        groups, limitations = _pair_groups(context)
        findings: list[Finding] = []
        for rules in groups:
            for index, rule in enumerate(rules):
                match = resolve_rule(rule)
                assert isinstance(match, RuleMatch)
                for earlier in rules[:index]:
                    earlier_match = resolve_rule(earlier)
                    assert isinstance(earlier_match, RuleMatch)
                    if earlier_match.covers(match):
                        if earlier_match != match or not _same_effect(earlier, rule):
                            findings.append(
                                _finding(
                                    context,
                                    self.check_id,
                                    (earlier, rule),
                                    "Правило полностью затенено более ранним правилом "
                                    "в той же политике.",
                                    Severity.MEDIUM,
                                    "Проверить порядок и назначение обоих правил; "
                                    "изменить условия или порядок после проверки влияния.",
                                )
                            )
                        break
        return _result(self.check_id, context, findings, limitations)
