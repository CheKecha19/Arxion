"""Policy check implementation."""

from firewall_compliance.checks.common.policy import PolicyCheckContext, _finding, _result
from firewall_compliance.domain import Severity
from firewall_compliance.domain.assurance import CheckResult


class DisabledRulesCheck:
    """Инвентаризация отключённых правил без заявления о текущем риске доступа."""

    check_id = "FW-DISABLED"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        findings = [
            _finding(
                context,
                self.check_id,
                (rule,),
                "Обнаружено отключённое правило.",
                Severity.INFO,
                "Проверить причину отключения и необходимость сохранения правила.",
            )
            for rule in context.revision.parse_result.rules
            if not rule.enabled
        ]
        return _result(self.check_id, context, findings, [])
