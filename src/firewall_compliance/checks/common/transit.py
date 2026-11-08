"""Ограничения применимости проверок транзитных политик коммутаторов."""

from firewall_compliance.domain.assurance import CheckLimitation
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.switch_policy import is_transit_rule, rule_purpose


def transit_limitations(parsed: ParseResult) -> list[CheckLimitation]:
    """Не объявлять отсутствие транзитных правил успешной проверкой всей сети."""
    if parsed.switch_policies is None:
        return []
    limitations: list[CheckLimitation] = []
    if not any(is_transit_rule(rule) and rule.enabled for rule in parsed.rules):
        limitations.append(
            CheckLimitation(
                code="NO_TRANSIT_POLICY",
                message="Транзитные ACL в представленном файле не обнаружены; "
                "управляющие ограничения не подтверждают фильтрацию пользовательского трафика.",
            )
        )
    excluded = tuple(
        rule.rule_id
        for rule in parsed.rules
        if rule.enabled and rule_purpose(rule) in {"unbound", "unknown"}
    )
    if excluded:
        limitations.append(
            CheckLimitation(
                code="TRANSIT_PURPOSE_UNCONFIRMED",
                message="Записи без подтверждённого транзитного применения исключены из проверки.",
                rule_ids=excluded,
            )
        )
    return limitations
