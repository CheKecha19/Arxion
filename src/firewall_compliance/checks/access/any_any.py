"""Policy check implementation."""

from firewall_compliance.analysis.policy_matching import resolve_rule
from firewall_compliance.checks.common.policy import (
    PolicyCheckContext,
    _finding,
    _limitation,
    _result,
)
from firewall_compliance.domain import Finding, RuleAction, Severity
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult
from firewall_compliance.domain.switch_policy import is_transit_rule


class AnyAnyCheck:
    """Широкое разрешение между любыми адресами для любого известного сервиса."""

    check_id = "FW-ANY-ANY"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        findings: list[Finding] = []
        limitations: list[CheckLimitation] = []
        for rule in context.revision.parse_result.rules:
            if not is_transit_rule(rule):
                continue
            if rule.enabled and rule.action == RuleAction.UNKNOWN:
                limitations.append(
                    _limitation("UNKNOWN_ACTION", "Действие правила неизвестно.", rule)
                )
            if not rule.enabled or rule.action != RuleAction.ALLOW:
                continue
            match = resolve_rule(rule)
            if match is None:
                limitations.append(
                    _limitation("UNKNOWN_MATCH", "Условия правила не полностью известны.", rule)
                )
                continue
            universal = (((0, 2**32 - 1),), ((0, 2**128 - 1),))
            broad_family = any(
                source == destination == universe
                for source, destination, universe in zip(
                    match.sources, match.destinations, universal, strict=True
                )
            )
            if broad_family:
                findings.append(
                    _finding(
                        context,
                        self.check_id,
                        (rule,),
                        "Разрешение между любыми адресами.",
                        Severity.HIGH,
                        "Ограничить источники и назначения согласно назначению правила; "
                        "проверить необходимость сервисов.",
                    )
                )
        return _result(self.check_id, context, findings, limitations)
