"""Policy check implementation."""

from firewall_compliance.analysis.policy_matching import RuleMatch, resolve_rule
from firewall_compliance.checks.common.policy import (
    PolicyCheckContext,
    _finding,
    _limitation,
    _pair_groups,
    _result,
)
from firewall_compliance.domain import DataStatus, Finding, Rule, RuleAction, Severity
from firewall_compliance.domain.assurance import CheckResult


class DuplicateRulesCheck:
    """Полное совпадение условий, действия и известной настройки логирования."""

    check_id = "FW-DUPLICATE"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        groups, limitations = _pair_groups(context, enforce_pair_limit=False)
        findings: list[Finding] = []
        for rules in groups:
            first_by_condition: dict[tuple[RuleMatch, RuleAction], dict[bool | None, Rule]] = {}
            for rule in rules:
                match = resolve_rule(rule)
                if match is None:
                    continue
                first_by_logging = first_by_condition.setdefault((match, rule.action), {})
                logging = rule.logging_enabled if rule.logging_status == DataStatus.KNOWN else None
                duplicate = first_by_logging.get(logging) if logging is not None else None
                uncertain = (
                    next(iter(first_by_logging.values()), None)
                    if logging is None
                    else first_by_logging.get(None)
                )
                # Для каждого правила достаточно первого примера неизвестности.
                if uncertain is not None and (
                    duplicate is None or uncertain.sequence < duplicate.sequence
                ):
                    limitations.append(
                        _limitation(
                            "UNKNOWN_DUPLICATE_EFFECT",
                            "Неизвестно логирование правил с одинаковыми условиями.",
                            uncertain,
                            rule,
                        )
                    )
                if duplicate is not None:
                    findings.append(
                        _finding(
                            context,
                            self.check_id,
                            (duplicate, rule),
                            "Правило повторяет условия, действие "
                            "и логирование предыдущего правила.",
                            Severity.LOW,
                            "Проверить владельцев и основания правил "
                            "перед удалением дубликата.",
                        )
                    )
                first_by_logging.setdefault(logging, rule)
        return _result(self.check_id, context, findings, limitations)
