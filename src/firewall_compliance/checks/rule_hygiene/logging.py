"""Policy check implementation."""

from firewall_compliance.checks.common.policy import (
    PolicyCheckContext,
    _finding,
    _limitation,
    _result,
    check_version,
)
from firewall_compliance.domain import DataStatus, Finding, RuleAction, Severity
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult, CheckStatus
from firewall_compliance.domain.switch_policy import is_transit_rule


class LoggingCheck:
    """Отсутствие логирования в активном разрешающем правиле по заданной политике."""

    check_id = "FW-LOGGING"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        if not context.require_logging:
            return CheckResult(
                check_id=self.check_id,
                check_version=check_version(context),
                status=CheckStatus.NOT_APPLICABLE,
            )
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
            if rule.logging_status != DataStatus.KNOWN or rule.logging_enabled is None:
                limitations.append(
                    _limitation("UNKNOWN_LOGGING", "Настройка логирования неизвестна.", rule)
                )
            elif not rule.logging_enabled:
                findings.append(
                    _finding(
                        context,
                        self.check_id,
                        (rule,),
                        "Разрешающее правило не включает логирование.",
                        Severity.MEDIUM,
                        "Включить логирование по принятой политике аудита, "
                        "учитывая нагрузку и объём событий.",
                    )
                )
        return _result(self.check_id, context, findings, limitations)
