"""Policy check implementation."""

from firewall_compliance.analysis.policy_matching import resolve_rule
from firewall_compliance.checks.common.policy import (
    PolicyCheckContext,
    _finding,
    _limitation,
    _pair_groups,
    _result,
    _same_effect,
)
from firewall_compliance.domain import DataStatus, Finding, Severity
from firewall_compliance.domain.assurance import CheckResult


class DuplicateRulesCheck:
    """Полное совпадение условий, действия и известной настройки логирования."""

    check_id = "FW-DUPLICATE"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        groups, limitations = _pair_groups(context)
        findings: list[Finding] = []
        for rules in groups:
            for index, rule in enumerate(rules):
                for earlier in rules[:index]:
                    if (
                        resolve_rule(earlier) == resolve_rule(rule)
                        and earlier.action == rule.action
                        and (
                            earlier.logging_status != DataStatus.KNOWN
                            or rule.logging_status != DataStatus.KNOWN
                            or earlier.logging_enabled is None
                            or rule.logging_enabled is None
                        )
                    ):
                        limitations.append(
                            _limitation(
                                "UNKNOWN_DUPLICATE_EFFECT",
                                "Неизвестно логирование правил с одинаковыми условиями.",
                                earlier,
                                rule,
                            )
                        )
                    if resolve_rule(earlier) == resolve_rule(rule) and _same_effect(earlier, rule):
                        findings.append(
                            _finding(
                                context,
                                self.check_id,
                                (earlier, rule),
                                "Правило повторяет условия, действие "
                                "и логирование предыдущего правила.",
                                Severity.LOW,
                                "Проверить владельцев и основания правил "
                                "перед удалением дубликата.",
                            )
                        )
                        break
        return _result(self.check_id, context, findings, limitations)
