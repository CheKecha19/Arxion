"""PolicyAttachmentCheck implementation."""

from __future__ import annotations

from firewall_compliance.checks.access.scope_common import (
    _parse_limitations,
    _ProfileCheck,
    _result,
)
from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.finding import Finding


class PolicyAttachmentCheck(_ProfileCheck):
    """CHECKS-005: unbound policies and missing required filtering declarations."""

    check_id = "FW-ACL-ATTACHMENT"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        required = self.profile.required_attachments
        completeness = self.profile.attachment_inventory_complete
        if completeness is False and required == ():
            return _result(self.check_id, context, [], [], applicable=False)
        findings: list[Finding] = []
        limitations = _parse_limitations(context)
        parsed = context.revision.parse_result
        if completeness is not True:
            limitations.append(
                CheckLimitation(
                    code="ATTACHMENT_INVENTORY_INCOMPLETE"
                    if completeness is False
                    else "ATTACHMENT_INVENTORY_UNKNOWN",
                    message=(
                        "Полнота инвентаря привязок ACL не подтверждена; отсутствие "
                        "нельзя трактовать как нарушение."
                    ),
                )
            )
            if required is None:
                limitations.append(
                    CheckLimitation(
                        code="REQUIRED_FILTERING_UNKNOWN",
                        message="Обязательные интерфейсы, направления или роли не заданы.",
                    )
                )
            return _result(self.check_id, context, findings, limitations)
        policy_rules: dict[str, list[Rule]] = {}
        for rule in parsed.rules:
            if rule.policy_id is None:
                limitations.append(
                    CheckLimitation(
                        code="POLICY_ID_UNKNOWN",
                        message="Правило без policy_id исключено из проверки привязок.",
                        rule_ids=(rule.rule_id,),
                    )
                )
            else:
                policy_rules.setdefault(rule.policy_id, []).append(rule)
        attached = {value.policy_id for value in parsed.policy_attachments}
        for policy_id, rules in sorted(policy_rules.items()):
            if policy_id not in attached:
                findings.append(
                    self._finding(
                        context,
                        key=f"unbound:{policy_id}",
                        title="Политика не имеет объявленной привязки.",
                        rules=tuple(rules),
                        facts={
                            "basis": "complete_attachment_inventory",
                            "policy_id": policy_id,
                            "attachment_inventory_complete": True,
                        },
                    )
                )
        if required is None:
            limitations.append(
                CheckLimitation(
                    code="REQUIRED_FILTERING_UNKNOWN",
                    message="Обязательные интерфейсы, направления или роли не заданы.",
                )
            )
        for requirement in required or ():
            matches = [
                value
                for value in parsed.policy_attachments
                if value.subject_kind == requirement.subject_kind
                and value.subject_id == requirement.subject_id
                and value.direction == requirement.direction
                and (
                    not requirement.allowed_policy_ids
                    or value.policy_id in requirement.allowed_policy_ids
                )
            ]
            if not matches:
                findings.append(
                    self._finding(
                        context,
                        key=f"required:{requirement.requirement_id}",
                        title="Отсутствует обязательная привязка фильтрации.",
                        facts={
                            "basis": "required_policy_attachment",
                            "requirement": requirement.model_dump(mode="json"),
                            "attachment_inventory_complete": True,
                        },
                    )
                )
        return _result(self.check_id, context, findings, limitations)
