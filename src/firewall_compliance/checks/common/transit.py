"""Ограничения применимости проверок транзитных политик коммутаторов."""

from collections import Counter, defaultdict
from dataclasses import dataclass

from firewall_compliance.domain.assurance import CheckLimitation
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import RuleAction
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.policy_matching import resolve_rule, scope_key
from firewall_compliance.domain.switch_policy import (
    AclBinding,
    AclDeclaration,
    is_transit_rule,
    rule_purpose,
)

_ACE_ACTIONS = {"permit": RuleAction.ALLOW, "deny": RuleAction.DENY}


@dataclass(frozen=True, slots=True)
class ConfiguredComwarePolicy:
    binding: AclBinding
    rules: tuple[Rule, ...]
    alias_ids: frozenset[str]


def configured_comware_policy_id(binding: AclBinding) -> str | None:
    if binding.configured_profile != "hpe-flexfabric-5944-5945-r6622":
        return None
    name = binding.acl_id.removeprefix("ipv4:")
    return f"acl:{name}@{binding.subject}:{binding.direction}"


def configured_comware_policies(parsed: ParseResult) -> dict[str, ConfiguredComwarePolicy]:
    """Связать настроенный ACL с отдельной полной проекцией его применения."""
    policies = parsed.switch_policies
    if (
        policies is None or parsed.errors
        or (parsed.configuration.vendor, parsed.configuration.platform) != ("hp-h3c", "comware")
    ):
        return {}
    configured = [
        (key, binding) for binding in policies.bindings
        if (key := configured_comware_policy_id(binding)) is not None
    ]
    if not configured:
        return {}
    attachments = Counter((binding.subject, binding.direction) for binding in policies.bindings)
    declarations: dict[str, list[AclDeclaration]] = defaultdict(list)
    for declaration in policies.declarations:
        declarations[declaration.acl_id].append(declaration)
    policy_keys = {key for key, _ in configured}
    rule_counts = Counter(rule.rule_id for rule in parsed.rules)
    unique_rules = {rule.rule_id: rule for rule in parsed.rules if rule_counts[rule.rule_id] == 1}
    projected: dict[str, list[Rule]] = defaultdict(list)
    for rule in parsed.rules:
        if rule.policy_id is not None and rule.policy_id in policy_keys:
            projected[rule.policy_id].append(rule)

    result = {}
    for policy_id, binding in configured:
        if attachments[binding.subject, binding.direction] != 1:
            continue
        acl = declarations[binding.acl_id]
        if len(acl) != 1 or acl[0].match_order != "config":
            continue
        rules = projected[policy_id]
        if len(rules) != len(acl[0].entries) or not rules:
            continue
        expected_scope = (policy_id, "in", f"{binding.subject}:routed-in", None)
        if len({rule.sequence for rule in rules}) != len(rules) or any(
            rule.rule_id not in unique_rules or rule.policy_purpose != "transit"
            or not rule.enabled or scope_key(rule) != expected_scope or resolve_rule(rule) is None
            for rule in rules
        ):
            continue
        by_id = {rule.rule_id: rule for rule in rules}
        matched: set[str] = set()
        alias_ids: set[str] = set()
        alias_policy_id = f"acl:{acl[0].name}"
        for entry in acl[0].entries:
            candidates = [by_id[key] for key in entry.rule_ids if key in by_id]
            action = _ACE_ACTIONS.get(entry.action)
            if not entry.valid or len(candidates) != 1 or action is None:
                break
            rule = candidates[0]
            if (
                rule.rule_id in matched or rule.sequence != entry.sequence
                or rule.action != action or rule.source_location not in entry.source_locations
            ):
                break
            matched.add(rule.rule_id)
            alias_ids.update(
                key for key in entry.rule_ids
                if (alias := unique_rules.get(key)) is not None
                and alias.policy_id == alias_policy_id and alias.policy_purpose == "unbound"
                and alias.sequence == rule.sequence and alias.action == rule.action
                and alias.source_location == rule.source_location
            )
        if matched == by_id.keys():
            result[policy_id] = ConfiguredComwarePolicy(
                binding, tuple(sorted(rules, key=lambda rule: rule.sequence)), frozenset(alias_ids),
            )
    return result


def transit_limitations(
    parsed: ParseResult, *, represented_alias_ids: frozenset[str] = frozenset(),
) -> list[CheckLimitation]:
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
        and rule.rule_id not in represented_alias_ids
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
