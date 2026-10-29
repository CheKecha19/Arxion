"""Policy check implementation."""

from firewall_compliance.checks.common.policy import (
    PolicyCheckContext,
    _finding,
    _limitation,
    _result,
    check_version,
)
from firewall_compliance.domain import DataStatus, Finding, Severity
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult, CheckStatus


class CommentsCheck:
    """Отсутствие описания назначения активного правила по заданной политике."""

    check_id = "FW-COMMENTS"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        if not context.require_comments:
            return CheckResult(
                check_id=self.check_id,
                check_version=check_version(context),
                status=CheckStatus.NOT_APPLICABLE,
            )
        findings: list[Finding] = []
        limitations: list[CheckLimitation] = []
        for rule in context.revision.parse_result.rules:
            if not rule.enabled:
                continue
            if rule.description_status not in {DataStatus.KNOWN, DataStatus.ABSENT}:
                limitations.append(
                    _limitation(
                        "UNKNOWN_DESCRIPTION", "Сведения об описании правила неизвестны.", rule
                    )
                )
            elif not rule.description or not rule.description.strip():
                findings.append(
                    _finding(
                        context,
                        self.check_id,
                        (rule,),
                        "Активное правило не содержит описания назначения.",
                        Severity.LOW,
                        "Указать назначение правила, владельца и основание доступа.",
                    )
                )
        return _result(self.check_id, context, findings, limitations)
