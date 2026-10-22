"""Независимые проверки качества firewall-политик."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol as CheckProtocol
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.analysis.policy_matching import (
    RuleMatch,
    ScopeKey,
    resolve_rule,
    scope_key,
)
from firewall_compliance.domain import (
    DataStatus,
    DeviceRevision,
    Evidence,
    Finding,
    FindingCategory,
    Rule,
    RuleAction,
    Severity,
)
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult, CheckStatus

CHECK_VERSION = "1.0.0"
ARUBA_CHECK_VERSION = "1.1.0"
PLATFORM_SCOPE_WARNINGS = {"HP_ARUBA_SCOPE_LIMITED"}
ARUBA_METADATA_WARNINGS = {"HP_ARUBA_LOGGING_VERSION_UNKNOWN", "HP_ARUBA_COMMENT_LIMITED"}
TERMINAL_ACTIONS = {RuleAction.ALLOW, RuleAction.DENY, RuleAction.DROP, RuleAction.REJECT}


@dataclass(frozen=True)
class PolicyCheckContext:
    """Вход проверки без файлового ввода и вендорских зависимостей."""

    revision: DeviceRevision
    analyzed_at: datetime
    require_logging: bool = True
    require_comments: bool = True
    max_pair_rules: int = 1000


def check_version(context: PolicyCheckContext) -> str:
    """Версия семантики проверок для текущего adapter без изменения старых результатов."""
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
    aruba = parsed.configuration.vendor == "hp-aruba"
    scope_warnings = PLATFORM_SCOPE_WARNINGS | ARUBA_METADATA_WARNINGS if aruba else set()
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
        candidates = [rule for rule in parsed.rules if rule.enabled]
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
    if configuration.vendor == "hp-aruba":
        for rule in rules:
            for prefix in ("binding", "description"):
                location = revision.parse_result.source_map.get(f"{prefix}:{rule.rule_id}")
                if location is not None and location not in locations:
                    locations.append(location)
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
            facts={
                "revision_id": str(revision.revision_id),
                "check_version": check_version(context),
                "rules": [rule.model_dump(mode="json") for rule in rules],
            },
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


class AnyAnyCheck:
    """Широкое разрешение между любыми адресами для любого известного сервиса."""

    check_id = "FW-ANY-ANY"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        findings: list[Finding] = []
        limitations: list[CheckLimitation] = []
        for rule in context.revision.parse_result.rules:
            if rule.enabled and rule.action == RuleAction.UNKNOWN:
                limitations.append(
                    _limitation("UNKNOWN_ACTION", "Действие правила неизвестно.", rule)
                )
            if not rule.enabled or rule.action != RuleAction.ALLOW:
                continue
            match = resolve_rule(rule)
            if match is None:
                limitations.append(
                    _limitation("UNKNOWN_MATCH", "Условия правила не полностью известны.", rule)
                )
                continue
            universal = (((0, 2**32 - 1),), ((0, 2**128 - 1),))
            broad_family = any(
                source == destination == universe
                for source, destination, universe in zip(
                    match.sources, match.destinations, universal, strict=True
                )
            )
            if broad_family:
                findings.append(
                    _finding(
                        context,
                        self.check_id,
                        (rule,),
                        "Разрешение между любыми адресами.",
                        Severity.HIGH,
                        "Ограничить источники и назначения согласно назначению правила; "
                        "проверить необходимость сервисов.",
                    )
                )
        return _result(self.check_id, context, findings, limitations)


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


def _pair_groups(context: PolicyCheckContext) -> tuple[list[list[Rule]], list[CheckLimitation]]:
    parsed = context.revision.parse_result
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
        if not rule.enabled:
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
        elif len(rules) > context.max_pair_rules:
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


class ShadowedRulesCheck:
    """Полное затенение одним более ранним терминальным правилом."""

    check_id = "FW-SHADOWED"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        groups, limitations = _pair_groups(context)
        findings: list[Finding] = []
        for rules in groups:
            for index, rule in enumerate(rules):
                match = resolve_rule(rule)
                assert isinstance(match, RuleMatch)
                for earlier in rules[:index]:
                    earlier_match = resolve_rule(earlier)
                    assert isinstance(earlier_match, RuleMatch)
                    if earlier_match.covers(match):
                        if earlier_match != match or not _same_effect(earlier, rule):
                            findings.append(
                                _finding(
                                    context,
                                    self.check_id,
                                    (earlier, rule),
                                    "Правило полностью затенено более ранним правилом "
                                    "в той же политике.",
                                    Severity.MEDIUM,
                                    "Проверить порядок и назначение обоих правил; "
                                    "изменить условия или порядок после проверки влияния.",
                                )
                            )
                        break
        return _result(self.check_id, context, findings, limitations)


class MergeCandidateCheck:
    """Соседние правила с одинаковыми эффектами и одной различающейся осью."""

    check_id = "FW-MERGE-CANDIDATE"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        groups, limitations = _pair_groups(context)
        findings: list[Finding] = []
        for rules in groups:
            for index, (before, after) in enumerate(zip(rules, rules[1:], strict=False)):
                left, right = resolve_rule(before), resolve_rule(after)
                assert isinstance(left, RuleMatch) and isinstance(right, RuleMatch)
                earlier_matches = [resolve_rule(rule) for rule in rules[:index]]
                if any(
                    match is not None and (match.covers(left) or match.covers(right))
                    for match in earlier_matches
                ):
                    continue
                if before.action == after.action and (
                    before.logging_status != DataStatus.KNOWN
                    or after.logging_status != DataStatus.KNOWN
                    or before.logging_enabled is None
                    or after.logging_enabled is None
                ):
                    limitations.append(
                        _limitation(
                            "UNKNOWN_MERGE_METADATA",
                            "Нет достоверного логирования для объединения.",
                            before,
                            after,
                        )
                    )
                if not _same_effect(before, after):
                    continue
                if before.description_status not in {
                    DataStatus.KNOWN,
                    DataStatus.ABSENT,
                } or after.description_status not in {DataStatus.KNOWN, DataStatus.ABSENT}:
                    limitations.append(
                        _limitation(
                            "UNKNOWN_MERGE_METADATA",
                            "Нет достоверных описаний для оценки объединения.",
                            before,
                            after,
                        )
                    )
                    continue
                different_axes = sum(
                    (
                        left.sources != right.sources,
                        left.destinations != right.destinations,
                        left.services != right.services,
                    )
                )
                if (
                    different_axes == 1
                    and before.description == after.description
                    and before.owner == after.owner
                    and not left.covers(right)
                    and not right.covers(left)
                ):
                    findings.append(
                        _finding(
                            context,
                            self.check_id,
                            (before, after),
                            "Соседние правила являются кандидатами на объединение "
                            "по одной оси условий.",
                            Severity.INFO,
                            "Вручную проверить возможность объединения значений одной оси "
                            "без расширения остальных условий.",
                        )
                    )
        return _result(self.check_id, context, findings, limitations)
