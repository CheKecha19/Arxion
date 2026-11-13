"""Независимые проверки качества firewall-политик."""

from dataclasses import dataclass as dataclass
from datetime import datetime as datetime
from functools import cached_property
from typing import Any
from typing import Literal as Literal
from typing import Protocol as CheckProtocol
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.analysis.policy_coverage import (
    CoverageBudget,
    CoverageLimitError,
    UnsupportedCoverageError,
    packet_boxes,
    subtract_boxes,
)
from firewall_compliance.analysis.policy_coverage import PacketBox as PacketBox
from firewall_compliance.analysis.policy_matching import RuleMatch as RuleMatch
from firewall_compliance.analysis.policy_matching import ScopeKey as ScopeKey
from firewall_compliance.analysis.policy_matching import (
    resolve_rule,
    scope_key,
)
from firewall_compliance.checks.common.transit import (
    ConfiguredComwarePolicy,
    configured_comware_policies,
    configured_comware_policy_id,
    transit_limitations,
)
from firewall_compliance.domain import (
    DataStatus,
    Evidence,
    FindingCategory,
)
from firewall_compliance.domain import DeviceRevision as DeviceRevision
from firewall_compliance.domain import Finding as Finding
from firewall_compliance.domain import Rule as Rule
from firewall_compliance.domain import RuleAction as RuleAction
from firewall_compliance.domain import Severity as Severity
from firewall_compliance.domain.assurance import CheckLimitation as CheckLimitation
from firewall_compliance.domain.assurance import CheckResult as CheckResult
from firewall_compliance.domain.assurance import CheckStatus
from firewall_compliance.domain.switch_policy import is_transit_rule

CHECK_VERSION = "1.0.0"
ARUBA_CHECK_VERSION = "1.1.0"
PLATFORM_SCOPE_WARNINGS = {"HP_ARUBA_SCOPE_LIMITED"}
ARUBA_METADATA_WARNINGS = {"HP_ARUBA_LOGGING_VERSION_UNKNOWN", "HP_ARUBA_COMMENT_LIMITED"}
TERMINAL_ACTIONS = {RuleAction.ALLOW, RuleAction.DENY, RuleAction.DROP, RuleAction.REJECT}
CONFIGURED_COMWARE_CHECKS = frozenset({"FW-DUPLICATE", "FW-SHADOWED", "FW-MERGE-CANDIDATE"})


@dataclass(frozen=True)
class PolicyCheckContext:
    """Вход проверки без файлового ввода и вендорских зависимостей."""

    revision: DeviceRevision
    analyzed_at: datetime
    require_logging: bool = True
    require_comments: bool = True
    max_pair_rules: int = 1000

    @cached_property
    def comware_policies(self) -> dict[str, ConfiguredComwarePolicy]:
        return configured_comware_policies(self.revision.parse_result)


def check_version(context: PolicyCheckContext) -> str:
    """Версия семантики проверок для текущего adapter без изменения старых результатов."""
    if context.revision.parse_result.switch_policies is not None:
        return "1.2.0"
    if context.revision.parse_result.configuration.vendor == "hp-aruba":
        return ARUBA_CHECK_VERSION
    return CHECK_VERSION


class PolicyCheck(CheckProtocol):
    """Расширяемый контракт одной независимой проверки."""

    check_id: str

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        """Вернуть findings и ограничения достоверности."""


def _limitation(code: str, message: str, *rules: Rule) -> CheckLimitation:
    return CheckLimitation(code=code, message=message, rule_ids=tuple(r.rule_id for r in rules))


def _result(
    check_id: str,
    context: PolicyCheckContext,
    findings: list[Finding],
    limitations: list[CheckLimitation],
) -> CheckResult:
    parsed = context.revision.parse_result
    comware = context.comware_policies if check_id in CONFIGURED_COMWARE_CHECKS else {}
    aliases = frozenset(alias for policy in comware.values() for alias in policy.alias_ids)
    limitations.extend(transit_limitations(parsed, represented_alias_ids=aliases))
    aruba = parsed.configuration.vendor == "hp-aruba"
    scope_warnings = PLATFORM_SCOPE_WARNINGS | ARUBA_METADATA_WARNINGS if aruba else set()
    if comware:
        scope_warnings = {"LIMITED_COMWARE_SCOPE"}
    relevant_warnings = [issue for issue in parsed.warnings if issue.code not in scope_warnings]
    relevant_unsupported = [
        issue
        for issue in parsed.unsupported_constructs
        if not aruba or issue.construct_type not in {"logging", "comment"}
    ]
    explained_metadata = aruba and any(
        issue.code in ARUBA_METADATA_WARNINGS for issue in parsed.warnings
    )
    if (
        parsed.errors
        or relevant_warnings
        or relevant_unsupported
        or parsed.coverage.coverage_ratio < 1
        and not explained_metadata
    ):
        limitations.append(
            _limitation(
                "INCOMPLETE_PARSE",
                "Источник разобран с ограничениями; отсутствие findings "
                "не доказывает корректность всей политики.",
            )
        )
    if parsed.configuration.vendor == "hp-aruba":
        candidates = [rule for rule in parsed.rules if rule.enabled and is_transit_rule(rule)]
        if check_id in {"FW-ANY-ANY", "FW-LOGGING"}:
            candidates = [
                rule for rule in candidates if rule.action in {RuleAction.ALLOW, RuleAction.UNKNOWN}
            ]
        unknown_all = False
        if candidates and check_id == "FW-ANY-ANY":
            unknown_all = all(
                resolve_rule(rule) is None or rule.action == RuleAction.UNKNOWN
                for rule in candidates
            )
        elif candidates and check_id == "FW-LOGGING":
            unknown_all = all(
                rule.logging_status != DataStatus.KNOWN
                or rule.logging_enabled is None
                or rule.action == RuleAction.UNKNOWN
                for rule in candidates
            )
        elif candidates and check_id == "FW-COMMENTS":
            unknown_all = all(
                rule.description_status not in {DataStatus.KNOWN, DataStatus.ABSENT}
                for rule in candidates
            )
        if (unknown_all or (not parsed.rules and limitations)) and not any(
            issue.code == "CHECK_NOT_EXECUTED" for issue in limitations
        ):
            limitations.append(
                _limitation(
                    "CHECK_NOT_EXECUTED",
                    "Нет правил с достаточными данными для выполнения проверки.",
                )
            )
    return CheckResult(
        check_id=check_id,
        check_version=check_version(context),
        status=CheckStatus.PARTIAL if limitations else CheckStatus.COMPLETE,
        findings=tuple(findings),
        limitations=tuple(limitations),
    )


def _finding(
    context: PolicyCheckContext,
    check_id: str,
    rules: tuple[Rule, ...],
    title: str,
    severity: Severity,
    recommendation: str,
) -> Finding:
    revision = context.revision
    configuration = revision.parse_result.configuration
    rule_ids = tuple(rule.rule_id for rule in rules)
    locations = [rule.source_location for rule in rules]
    facts: dict[str, Any] = {
        "revision_id": str(revision.revision_id),
        "check_version": check_version(context),
        "rules": [rule.model_dump(mode="json") for rule in rules],
    }
    if configuration.vendor == "hp-aruba":
        for rule in rules:
            for prefix in ("binding", "description"):
                location = revision.parse_result.source_map.get(f"{prefix}:{rule.rule_id}")
                if location is not None and location not in locations:
                    locations.append(location)
    elif check_id in CONFIGURED_COMWARE_CHECKS and (
        policy := context.comware_policies.get(rules[0].policy_id or "")
    ) is not None:
        locations.extend(loc for loc in policy.binding.source_locations if loc not in locations)
        facts.update(
            configured_profile=policy.binding.configured_profile,
            binding_id=policy.binding.binding_id,
            vrf=policy.binding.vrf,
        )
    return Finding(
        finding_id=uuid5(
            NAMESPACE_URL, f"{revision.revision_id}:{check_version(context)}:{check_id}:{rule_ids}"
        ),
        check_id=check_id,
        category=FindingCategory.POLICY,
        severity=severity,
        title=title,
        description=title,
        configuration_id=configuration.configuration_id,
        revision_id=revision.revision_id,
        device_id=revision.device.device_id,
        affected_rule_ids=rule_ids,
        evidence=Evidence(
            summary=title,
            source_locations=tuple(locations),
            related_rule_ids=rule_ids,
            facts=facts,
            limitations=(
                "Вывод относится к нормализованным условиям политики; "
                "достижимость и влияние NAT не вычислялись.",
            ),
        ),
        recommendation=recommendation,
        confidence=1.0,
        first_seen=context.analyzed_at,
        last_seen=context.analyzed_at,
    )


def _aruba_blocked_acls(context: PolicyCheckContext) -> tuple[set[str], bool]:
    """Связать реальные ограничения с ACL по source mapping; не угадывать область."""
    parsed = context.revision.parse_result
    ranges = [
        (key, location)
        for key, location in parsed.source_map.items()
        if key.startswith(("acl-range:", "acl-binding:"))
    ]
    acl_names = {
        rule.policy_id.split("@", 1)[0][4:]
        for rule in parsed.rules
        if rule.policy_id and rule.policy_id.startswith("acl:")
    }
    issues = [
        issue.source_location
        for issue in parsed.warnings
        if issue.code not in PLATFORM_SCOPE_WARNINGS | ARUBA_METADATA_WARNINGS
    ]
    issues.extend(
        issue.source_location
        for issue in parsed.unsupported_constructs
        if issue.construct_type not in {"logging", "comment"}
    )
    blocked: set[str] = set()
    for location in issues:
        if location is None or location.line_start is None:
            return blocked, True
        matched = {
            acl
            for acl in acl_names
            for key, span in ranges
            if key.startswith((f"acl-range:{acl}:", f"acl-binding:{acl}:"))
            and span.source_name == location.source_name
            and span.line_start is not None
            and span.line_start <= location.line_start <= (span.line_end or span.line_start)
        }
        if matched:
            blocked.update(matched)
            continue
        # Management-инвентарь не участвует в сравнении transit ACL.
        management = any(
            rule.policy_id
            and rule.policy_id.startswith("management:")
            and rule.source_location == location
            for rule in parsed.rules
        )
        if not management:
            return blocked, True
    # Неполнота без объяснённой причины не разрешает попарные выводы.
    explained = any(issue.code not in PLATFORM_SCOPE_WARNINGS for issue in parsed.warnings)
    unexplained = parsed.coverage.coverage_ratio < 1 and not (
        explained or parsed.unsupported_constructs
    )
    return blocked, bool(parsed.errors) or unexplained


def _comware_pair_groups(
    context: PolicyCheckContext, *, enforce_pair_limit: bool,
) -> tuple[list[list[Rule]], list[CheckLimitation]]:
    policies = context.comware_policies
    inventory = context.revision.parse_result.switch_policies
    candidates = {
        key for binding in inventory.bindings
        if (key := configured_comware_policy_id(binding)) is not None
    } if inventory is not None else set()
    limitations = [
        _limitation(
            "INCOMPLETE_ACL",
            f"Для {policy_id} не подтверждена полная связь настроенного ACL с его правилами.",
        )
        for policy_id in sorted(candidates - policies.keys())
    ]
    groups = []
    for policy in policies.values():
        if enforce_pair_limit and len(policy.rules) > context.max_pair_rules:
            limitations.append(
                _limitation("PAIR_LIMIT", "Превышен лимит правил для попарного анализа области.")
            )
        else:
            groups.append(list(policy.rules))
    if not groups:
        limitations.append(
            _limitation(
                "CHECK_NOT_EXECUTED",
                "Для Comware требуется полностью разобранный ACL с подтверждённым "
                "порядком config и входящим маршрутизируемым применением к VLAN-интерфейсу.",
            )
        )
    return groups, limitations


def _pair_groups(
    context: PolicyCheckContext,
    *,
    enforce_pair_limit: bool = True,
) -> tuple[list[list[Rule]], list[CheckLimitation]]:
    parsed = context.revision.parse_result
    if (parsed.configuration.vendor, parsed.configuration.platform) == ("hp-h3c", "comware"):
        return _comware_pair_groups(context, enforce_pair_limit=enforce_pair_limit)
    aruba = parsed.configuration.vendor == "hp-aruba"
    if not aruba and (
        parsed.errors
        or parsed.warnings
        or parsed.unsupported_constructs
        or parsed.coverage.coverage_ratio < 1
    ):
        return [], []
    blocked_acls, block_all = _aruba_blocked_acls(context) if aruba else (set(), False)
    if block_all:
        return [], [
            _limitation(
                "CHECK_NOT_EXECUTED",
                "Нельзя достоверно связать ограничения разбора с конкретными ACL; "
                "попарная проверка не выполнена.",
            )
        ]
    groups: dict[ScopeKey, list[Rule]] = {}
    limitations: list[CheckLimitation] = []
    for rule in parsed.rules:
        if not rule.enabled or not is_transit_rule(rule):
            continue
        key = scope_key(rule)
        if key is None:
            if aruba:
                limitations.append(
                    _limitation(
                        "UNKNOWN_SCOPE",
                        "Пропущена область с неизвестной привязкой или management-семантикой.",
                        rule,
                    )
                )
                continue
            return [], [
                _limitation(
                    "UNKNOWN_SCOPE",
                    "Не определены область, направление или first-match семантика политики.",
                    rule,
                )
            ]
        groups.setdefault(key, []).append(rule)
    eligible: list[list[Rule]] = []
    for rules in groups.values():
        acl_name = (rules[0].policy_id or "").split("@", 1)[0][4:]
        if aruba and acl_name in blocked_acls:
            limitations.append(
                _limitation(
                    "INCOMPLETE_ACL",
                    "ACL содержит неподдержанные или неоднозначные конструкции; "
                    "эта область не сравнивалась.",
                    *rules,
                )
            )
        elif enforce_pair_limit and len(rules) > context.max_pair_rules:
            limitations.append(
                _limitation("PAIR_LIMIT", "Превышен лимит правил для попарного анализа области.")
            )
        elif len({rule.sequence for rule in rules}) != len(rules):
            limitations.append(
                _limitation("AMBIGUOUS_ORDER", "Порядок правил неоднозначен.", *rules)
            )
        elif any(
            resolve_rule(rule) is None or rule.action not in TERMINAL_ACTIONS for rule in rules
        ):
            limitations.append(
                _limitation(
                    "UNKNOWN_MATCH",
                    "Область содержит неполные условия или неизвестные действия.",
                    *rules,
                )
            )
        else:
            eligible.append(sorted(rules, key=lambda rule: rule.sequence))
    if aruba and not eligible:
        limitations.append(
            _limitation(
                "CHECK_NOT_EXECUTED",
                "Нет полностью разобранных ACL с известной областью и порядком правил.",
            )
        )
    return eligible, limitations


def _same_effect(before: Rule, after: Rule) -> bool:
    return (
        before.action == after.action
        and before.logging_status == after.logging_status == DataStatus.KNOWN
        and before.logging_enabled is not None
        and before.logging_enabled == after.logging_enabled
    )


COVERAGE_CHECK_VERSION = "1.0.0"


def _coverage_groups(
    context: PolicyCheckContext, complete_scopes: frozenset[ScopeKey] | None
) -> tuple[list[list[Rule]], set[str], list[CheckLimitation]]:
    """Establish scope/order from real source evidence, retaining unknown predicates."""
    parsed = context.revision.parse_result
    active = [rule for rule in parsed.rules if rule.enabled and is_transit_rule(rule)]
    limitations: list[CheckLimitation] = []
    unknown: set[str] = set()
    aruba = parsed.configuration.vendor == "hp-aruba"
    blocked_acls, blocked = _aruba_blocked_acls(context) if aruba else (set(), False)
    diagnostics = [
        issue.source_location
        for issue in parsed.warnings
        if not aruba or issue.code not in PLATFORM_SCOPE_WARNINGS | ARUBA_METADATA_WARNINGS
    ]
    diagnostics.extend(
        issue.source_location
        for issue in parsed.unsupported_constructs
        if not aruba or issue.construct_type not in {"logging", "comment"}
    )
    if not aruba:
        for location in diagnostics:
            matches = []
            if location is not None:
                for rule in parsed.rules:
                    source = rule.source_location
                    if source.source_name != location.source_name:
                        continue
                    if (
                        (
                            source.object_path
                            and location.object_path
                            and (
                                location.object_path == source.object_path
                                or location.object_path.startswith(source.object_path + "/")
                            )
                        )
                        or (source.object_id is not None and source.object_id == location.object_id)
                        or (
                            source.line_start is not None
                            and location.line_start is not None
                            and source.line_start
                            <= location.line_start
                            <= (source.line_end or source.line_start)
                        )
                    ):
                        matches.append(rule)
            if not matches:
                blocked = True
            unknown.update(rule.rule_id for rule in matches)
    unexplained_coverage = not aruba and (
        parsed.coverage.discovered_constructs - parsed.coverage.recognized_constructs > len(unknown)
        or parsed.coverage.coverage_ratio < 1
        and not diagnostics
    )
    if parsed.errors or blocked or unexplained_coverage:
        return (
            [],
            unknown,
            [
                _limitation(
                    "CHECK_NOT_EXECUTED",
                    "Не подтверждены полнота условий или область диагностики разбора.",
                )
            ],
        )
    groups: dict[tuple[str, str | None, str | None], list[Rule]] = {}
    unknown_policies: set[str | None] = set()
    for rule in active:
        location = rule.source_location
        if location.line_start is None and not (location.object_path or location.object_id):
            unknown.add(rule.rule_id)
            limitations.append(
                _limitation(
                    "MISSING_SOURCE_MAPPING", "Не подтверждена позиция правила в источнике.", rule
                )
            )
        key = scope_key(rule)
        if key is None:
            unknown_policies.add(rule.policy_id)
            limitations.append(
                _limitation("UNKNOWN_SCOPE", "Область или first-match семантика неизвестна.", rule)
            )
        else:
            groups.setdefault((key[0], key[2], key[3]), []).append(rule)
    eligible = []
    for group_key, rules in groups.items():
        sequences: dict[int, list[Rule]] = {}
        for rule in rules:
            sequences.setdefault(rule.sequence, []).append(rule)
        ambiguous = any(
            len(same) > 1
            and (
                any(rule.policy_direction == "global" for rule in same)
                or len({rule.policy_direction for rule in same}) != len(same)
            )
            for same in sequences.values()
        )
        if None in unknown_policies or group_key[0] in unknown_policies:
            limitations.append(
                _limitation(
                    "INCOMPLETE_SCOPE", "В политике есть правило с неизвестной областью.", *rules
                )
            )
        elif aruba and (group_key[0].split("@", 1)[0][4:]) in blocked_acls:
            limitations.append(
                _limitation("INCOMPLETE_ACL", "ACL содержит неподтверждённые конструкции.", *rules)
            )
        elif complete_scopes is not None and any(
            scope_key(rule) not in complete_scopes for rule in rules
        ):
            limitations.append(
                _limitation(
                    "INCOMPLETE_SCOPE",
                    "Область не входит в заданное ограничение complete_scopes.",
                    *rules,
                )
            )
        elif len(rules) > context.max_pair_rules:
            limitations.append(_limitation("PAIR_LIMIT", "Превышен лимит правил области.", *rules))
        elif ambiguous or len({rule.rule_id for rule in rules}) != len(rules):
            limitations.append(
                _limitation(
                    "AMBIGUOUS_ORDER", "Неоднозначны порядок или идентификаторы правил.", *rules
                )
            )
        else:
            eligible.append(sorted(rules, key=lambda rule: (rule.sequence, rule.rule_id)))
    if active and not eligible:
        limitations.append(
            _limitation("CHECK_NOT_EXECUTED", "Нет области с доказанным first-match порядком.")
        )
    return eligible, unknown, limitations


def _coverage_finding(
    context: PolicyCheckContext,
    check_id: str,
    target: Rule,
    contributors: list[Rule],
    covered: PacketBox,
    residual: tuple[PacketBox, ...],
    uncertain: list[Rule],
    overlaps: list[tuple[Rule, PacketBox]],
    evidence_version: Literal["1.0.0", "1.1.0"],
) -> Finding:
    full = not residual
    title = (
        "Правило полностью затенено объединением более ранних правил."
        if full
        else "Часть условий правила затенена более ранними правилами."
    )
    result = _finding(
        context,
        check_id,
        (*contributors, target),
        title,
        Severity.MEDIUM,
        "Проверить порядок и назначение правил; не удалять правило без проверки остатка условий.",
    )
    facts = {
        **result.evidence.facts,
        "check_version": evidence_version,
        "coverage_kind": "full_union" if full else "partial",
        "target_rule_id": target.rule_id,
        "covering_rule_ids": [rule.rule_id for rule in contributors],
        "uncertain_predecessor_ids": [rule.rule_id for rule in uncertain],
        "first_match_owners_known": not uncertain,
        "covered_witness": covered.witness(),
        "residual_witness": residual[0].witness() if residual else None,
        "residual_fragments": len(residual),
        "scope": {
            "policy_id": target.policy_id,
            "direction": target.policy_direction,
            "source_zone": target.source_zone,
            "destination_zone": target.destination_zone,
        },
    }
    if evidence_version == "1.1.0":
        ordered_overlaps: list[dict[str, Any]] = []
        for earlier, witness in overlaps:
            opposite = (earlier.action == RuleAction.ALLOW) != (target.action == RuleAction.ALLOW)
            classification = (
                "opposite_decision"
                if opposite
                else "same_action_redundancy"
                if earlier.action == target.action
                else "different_denial_actions"
            )
            ordered_overlaps.append(
                {
                    "earlier_rule_id": earlier.rule_id,
                    "target_rule_id": target.rule_id,
                    "earlier_sequence": earlier.sequence,
                    "target_sequence": target.sequence,
                    "earlier_action": earlier.action.value,
                    "target_action": target.action.value,
                    "classification": classification,
                    "first_match_owner_known": not uncertain,
                    "decision_order_dependent": None if uncertain else opposite,
                    "action_order_dependent": None
                    if uncertain
                    else earlier.action != target.action,
                    "overlap_witness": witness.witness(),
                }
            )
        classifications = {item["classification"] for item in ordered_overlaps}
        facts["ordered_overlaps"] = ordered_overlaps
        facts["overlap_classification"] = (
            next(iter(classifications)) if len(classifications) == 1 else "mixed_decisions"
        )
        facts["decision_order_dependent"] = (
            None
            if uncertain
            else any(item["decision_order_dependent"] for item in ordered_overlaps)
        )
        facts["action_order_dependent"] = (
            None if uncertain else any(item["action_order_dependent"] for item in ordered_overlaps)
        )
    evidence = result.evidence.model_copy(update={"facts": facts})
    return result.model_copy(
        update={
            "finding_id": uuid5(
                NAMESPACE_URL,
                f"{context.revision.revision_id}:{COVERAGE_CHECK_VERSION}:{check_id}:{result.affected_rule_ids}",
            ),
            "evidence": evidence,
        }
    )


def _evaluate_coverage(
    check_id: str,
    context: PolicyCheckContext,
    *,
    full: bool,
    complete_scopes: frozenset[ScopeKey] | None,
    max_fragments: int,
    max_operations: int,
    evidence_version: Literal["1.0.0", "1.1.0"],
) -> CheckResult:
    groups, diagnostic_unknown, limitations = _coverage_groups(context, complete_scopes)
    budget = CoverageBudget(max_fragments, max_operations)
    findings: list[Finding] = []
    evaluated_targets = 0
    for rules in groups:
        try:
            boxes: dict[str, tuple[PacketBox, ...] | None] = {}
            for rule in rules:
                match = resolve_rule(rule) if rule.rule_id not in diagnostic_unknown else None
                try:
                    boxes[rule.rule_id] = (
                        packet_boxes(match, rule.policy_direction, budget)
                        if match is not None and rule.policy_direction is not None
                        else None
                    )
                except UnsupportedCoverageError:
                    boxes[rule.rule_id] = None
                if boxes[rule.rule_id] is None or rule.action not in TERMINAL_ACTIONS:
                    limitations.append(
                        _limitation(
                            "UNKNOWN_MATCH",
                            "Условия или терминальное действие правила неизвестны.",
                            rule,
                        )
                    )
            for index, target in enumerate(rules):
                initial = boxes[target.rule_id]
                if initial is None or target.action not in TERMINAL_ACTIONS:
                    continue
                remaining = initial
                contributors: list[Rule] = []
                overlaps: list[tuple[Rule, PacketBox]] = []
                uncertain: list[Rule] = []
                covered_witness = None
                for earlier in rules[:index]:
                    before = boxes[earlier.rule_id]
                    if before is None or earlier.action not in TERMINAL_ACTIONS:
                        # Unknown conditions in a proven disjoint direction cannot affect target.
                        relevant = (
                            earlier.policy_direction == "global"
                            or target.policy_direction == "global"
                            or earlier.policy_direction == target.policy_direction
                        )
                        if relevant and before is not None:
                            relevant = False
                            for left in initial:
                                for right in before:
                                    budget.charge()
                                    if left.intersection(right) is not None:
                                        relevant = True
                                        break
                                if relevant:
                                    break
                        if relevant:
                            uncertain.append(earlier)
                        continue
                    remaining, covered = subtract_boxes(remaining, before, budget)
                    if covered:
                        contributors.append(earlier)
                        overlaps.append((earlier, covered[0]))
                        covered_witness = covered_witness or covered[0]
                    if not remaining:
                        break
                if remaining and uncertain:
                    evaluated_targets += 1
                    limitations.append(
                        _limitation(
                            "UNKNOWN_EARLIER_MATCH",
                            "Неизвестный предшественник не позволяет доказать, "
                            "что остаток не затенён.",
                            *uncertain,
                            target,
                        )
                    )
                    continue
                evaluated_targets += 1
                if covered_witness is not None and (
                    (full and not remaining and len(contributors) > 1) or (not full and remaining)
                ):
                    findings.append(
                        _coverage_finding(
                            context,
                            check_id,
                            target,
                            contributors,
                            covered_witness,
                            remaining,
                            uncertain,
                            overlaps,
                            evidence_version,
                        )
                    )
        except CoverageLimitError:
            limitations.append(
                _limitation(
                    "COVERAGE_LIMIT",
                    "Превышен лимит фрагментов или операций; "
                    "незавершённое вычитание не является доказательством покрытия.",
                    *rules,
                )
            )
            if budget.operations > budget.max_operations:
                break
    # Keep stable explanatory limits without multiplying the same rule diagnostic.
    unique = {(value.code, value.message, value.rule_ids): value for value in limitations}
    if groups and not evaluated_targets:
        value = _limitation(
            "CHECK_NOT_EXECUTED",
            "Нет правил с достаточными условиями и завершённым анализом покрытия.",
        )
        unique[value.code, value.message, value.rule_ids] = value
    result = _result(check_id, context, findings, list(unique.values()))
    return result.model_copy(update={"check_version": evidence_version})
