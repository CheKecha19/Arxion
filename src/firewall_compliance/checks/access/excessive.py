"""ExcessiveAccessCheck implementation."""

from __future__ import annotations

from firewall_compliance.checks.access.scope_common import (
    _address_count,
    _addresses_covered,
    _Budget,
    _intersects,
    _interval_count,
    _LimitReached,
    _networks,
    _parse_limitations,
    _ProfileCheck,
    _result,
    _services_covered,
)
from firewall_compliance.checks.common.transit import transit_limitations
from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult
from firewall_compliance.domain.enums import RuleAction
from firewall_compliance.domain.finding import Finding
from firewall_compliance.domain.policy_matching import resolve_rule
from firewall_compliance.domain.switch_policy import is_transit_rule


class ExcessiveAccessCheck(_ProfileCheck):
    """CHECKS-003: excessive breadth and access outside an explicit resource-role policy."""

    check_id = "FW-EXCESSIVE-ACCESS"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        threshold_enabled = self.profile.excessive_access_enabled
        role_requirements = self.profile.role_requirements
        if threshold_enabled is False and role_requirements == ():
            return _result(self.check_id, context, [], [], applicable=False)
        findings: list[Finding] = []
        limitations = _parse_limitations(context)
        budget = _Budget(self.max_operations)
        if threshold_enabled is None:
            limitations.append(
                CheckLimitation(
                    code="EXCESSIVE_THRESHOLDS_UNKNOWN",
                    message="Пороговые требования организации не определены.",
                )
            )
        if role_requirements is None:
            limitations.append(
                CheckLimitation(
                    code="ROLE_ACCESS_POLICY_UNKNOWN",
                    message="Ролевые требования к доступу не определены.",
                )
            )
        try:
            for rule in context.revision.parse_result.rules:
                if not is_transit_rule(rule):
                    continue
                budget.spend()
                if not rule.enabled or rule.action != RuleAction.ALLOW:
                    continue
                if rule.rule_id in self.profile.exception_rule_ids:
                    continue
                match = resolve_rule(rule)
                if match is None:
                    limitations.append(
                        CheckLimitation(
                            code="UNKNOWN_RULE_CONDITION",
                            message="Условие разрешающего правила нельзя полностью разрешить.",
                            rule_ids=(rule.rule_id,),
                        )
                    )
                    continue
                violations: dict[str, int] = {}
                if threshold_enabled:
                    for field, actual, limit in (
                        (
                            "source_addresses",
                            _address_count(match.sources),
                            self.profile.max_source_addresses,
                        ),
                        (
                            "destination_addresses",
                            _address_count(match.destinations),
                            self.profile.max_destination_addresses,
                        ),
                        (
                            "destination_ports",
                            sum(_interval_count(ports) for _, ports in match.services),
                            self.profile.max_destination_ports,
                        ),
                    ):
                        if limit is not None and actual > limit:
                            violations[field] = actual
                if violations:
                    findings.append(
                        self._finding(
                            context,
                            key=f"threshold:{rule.rule_id}:{sorted(violations)}",
                            title="Разрешающее правило превышает утверждённые пределы доступа.",
                            rules=(rule,),
                            facts={
                                "basis": "configured_allow_breadth",
                                "violations": violations,
                                "thresholds": {
                                    "source_addresses": self.profile.max_source_addresses,
                                    "destination_addresses": self.profile.max_destination_addresses,
                                    "destination_ports": self.profile.max_destination_ports,
                                },
                                "rule": rule.model_dump(mode="json"),
                            },
                        )
                    )
                for requirement in role_requirements or ():
                    budget.spend()
                    if not _intersects(
                        match.destinations, _networks(requirement.destination_networks), budget
                    ):
                        continue
                    source_ok = _addresses_covered(
                        _networks(requirement.approved_source_networks), match.sources
                    )
                    service_ok = _services_covered(requirement, match, budget)
                    if not source_ok or not service_ok:
                        findings.append(
                            self._finding(
                                context,
                                key=f"role:{requirement.requirement_id}:{rule.rule_id}",
                                title="Разрешающее правило выходит за утверждённый ролевой доступ.",
                                rules=(rule,),
                                facts={
                                    "basis": "role_access_requirement",
                                    "requirement": requirement.model_dump(mode="json"),
                                    "source_within_policy": source_ok,
                                    "service_within_policy": service_ok,
                                    "rule": rule.model_dump(mode="json"),
                                },
                            )
                        )
        except _LimitReached:
            limitations.append(
                CheckLimitation(
                    code="POLICY_SCOPE_LIMIT_REACHED",
                    message="Лимит операций исчерпан; отсутствие других findings не доказано.",
                )
            )
        limitations.extend(transit_limitations(context.revision.parse_result))
        if not context.revision.parse_result.rules and limitations:
            limitations.append(
                CheckLimitation(
                    code="CHECK_NOT_EXECUTED", message="Нет правил для выполнения проверки."
                )
            )
        return _result(self.check_id, context, findings, limitations)
