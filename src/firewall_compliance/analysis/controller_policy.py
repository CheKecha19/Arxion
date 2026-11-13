"""Статический анализ и осторожная оценка session-политик ArubaOS Controller."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING, Any, Literal
from uuid import NAMESPACE_URL, uuid5
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.controller import ControllerInventory, ControllerObject
from firewall_compliance.domain.controller_analysis import (
    ControllerAnalysis,
    ControllerPolicyFinding,
    ControllerRoleDecision,
    ControllerTrace,
    RolePolicySummary,
)
from firewall_compliance.domain.enums import FindingCategory, RuleAction, Severity
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult, CheckStatus
from firewall_compliance.domain.finding import Evidence, Finding
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.policy_matching import RuleMatch, resolve_rule

if TYPE_CHECKING:
    from firewall_compliance.checks.common.policy import PolicyCheckContext

_ROLE_ORDER_REFERENCE = (
    "https://arubanetworking.hpe.com/techdocs/ArubaOS-8.x-Books/86/"
    "ArubaOS-8.6.0.0-User-Guide.pdf"
)
_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "gre": 47, "esp": 50}
_ACTIONS = {"permit": "allow", "deny": "deny"}
_LIMITATION = (
    "Проверены объявления session ACL; findings не доказывают применение роли или сетевую доступность."
)


def _inventory(parsed: ParseResult) -> ControllerInventory | None:
    return getattr(parsed, "controller_inventory", None)


def _objects(inventory: ControllerInventory, kind: str) -> dict[str, ControllerObject]:
    return {item.name: item for item in inventory.objects if item.kind == kind}


def _rules(parsed: ParseResult) -> dict[str, list[Rule]]:
    groups: dict[str, list[Rule]] = defaultdict(list)
    for rule in parsed.rules:
        if (rule.policy_id or "").startswith("controller-session:"):
            groups[rule.policy_id or ""].append(rule)
    return {key: sorted(values, key=lambda rule: (rule.sequence, rule.source_location.line_start or 0))
            for key, values in groups.items()}


def _intersects(first: RuleMatch, second: RuleMatch) -> bool:
    def addresses(left: Any, right: Any) -> bool:
        return any(
            any(max(a, c) <= min(b, d) for a, b in family_a for c, d in family_b)
            for family_a, family_b in zip(left, right, strict=True)
        )

    if not addresses(first.sources, second.sources) or not addresses(first.destinations, second.destinations):
        return False
    return any(
        (protocol_a == protocol_b or "ip" in {protocol_a, protocol_b})
        and any(max(a, c) <= min(b, d) for a, b in ports_a for c, d in ports_b)
        for protocol_a, ports_a in first.services for protocol_b, ports_b in second.services
    )


def _universal(addresses: Any) -> bool:
    return addresses[0] == ((0, 2**32 - 1),) or addresses[1] == ((0, 2**128 - 1),)


def _role_chain(
    parsed: ParseResult, inventory: ControllerInventory, role_name: str,
    ap_group: str | None = None, family: int | None = None,
) -> tuple[list[str], list[str]]:
    role = _objects(inventory, "role").get(role_name)
    if role is None:
        return [], ["Роль не объявлена в представленном источнике."]
    reasons = []
    if role.state != "declared":
        reasons.append("Роль содержит неподдержанные или неоднозначные параметры.")
    refs = [reference for reference in inventory.references
            if reference.source_id == role.object_id and reference.relation == "acl"]
    # Explicit positions are meaningful only when every application has a distinct position.
    if not refs:
        return [], [*reasons, "У роли нет подтверждённого списка session ACL."]
    if any(reference.position is None for reference in refs):
        reasons.append("Порядок ACL роли не подтверждён.")
    positions = [reference.position for reference in refs]
    if len(set(positions)) != len(positions):
        reasons.append("Позиции ACL роли неоднозначны.")
    refs = sorted(refs, key=lambda reference: reference.position or 0)
    acls = _objects(inventory, "acl_session")
    names: list[str] = []
    attachments = {attachment.source_location.line_start: attachment
                   for attachment in parsed.policy_attachments if attachment.subject_id == role_name}
    for reference in refs:
        attachment = next((attachments.get(location.line_start) for location in reference.source_locations
                           if location.line_start in attachments), None)
        if attachment is None:
            reasons.append(f"Условия применения ACL {reference.target_name} неизвестны.")
        scope = attachment.scope_reference if attachment else None
        if scope == "ipv6" and family == 4:
            continue
        if scope and scope.startswith("ap-group:"):
            scope = scope.removeprefix("ap-group:")
            if ap_group is None:
                reasons.append("ACL ограничена AP-group; контекст AP-group запроса неизвестен.")
            elif ap_group != scope:
                continue
        if reference.status != "known" or reference.target_name not in acls:
            reasons.append(f"ACL {reference.target_name} отсутствует или её ссылка не разрешена.")
        elif acls[reference.target_name].state != "declared":
            reasons.append(f"ACL {reference.target_name} содержит неполные объявления.")
        names.append(reference.target_name)
    if not role.attributes.get("acl_order_complete", False):
        reasons.append("Полнота/порядок списка ACL роли не подтверждены парсером.")
    return names, list(dict.fromkeys(reasons))


def _context_reasons(inventory: ControllerInventory) -> list[str]:
    reasons = []
    version = inventory.declared_version or ""
    if not re.match(r"^8\.(?:6|10)(?:\.|$)", version):
        reasons.append("Семантика оценки проверена только для профилей ArubaOS 8.6 и 8.10.")
    if not inventory.configuration_complete:
        reasons.append("Источник не заявлен полным экспортом конфигурации.")
    if inventory.configuration_view not in {"effective", "effective_detail"}:
        reasons.append("Нет подтверждения effective-конфигурации с учётом наследования.")
    return reasons


def analyze_controller(parsed: ParseResult, *, max_pairs: int = 20000) -> ControllerAnalysis:
    """Найти совпадения/пересечения статических условий без имитации runtime."""
    if max_pairs < 1:
        raise ValueError("max_pairs must be positive")
    inventory = _inventory(parsed)
    if inventory is None:
        return ControllerAnalysis(limitations=("Каталог ArubaOS Controller отсутствует.",))
    groups = _rules(parsed)
    findings: list[ControllerPolicyFinding] = []
    limitations = [_LIMITATION, *_context_reasons(inventory)]
    inspected = 0
    budget_exhausted = False
    for policy_id, rules in groups.items():
        known: list[tuple[Rule, RuleMatch]] = []
        for rule in rules:
            match = resolve_rule(rule)
            if match is None or rule.action not in {RuleAction.ALLOW, RuleAction.DENY}:
                limitations.append(f"{rule.name}: динамические или неподдержанные условия не сравнивались.")
                continue
            if rule.action == RuleAction.ALLOW and (
                _universal(match.sources) or _universal(match.destinations)
            ):
                both = _universal(match.sources) and _universal(match.destinations)
                findings.append(ControllerPolicyFinding(
                    code="CONTROLLER_BROAD_PERMISSION", severity="high" if both else "medium",
                    title="Широкое объявленное разрешение.", policy_id=policy_id,
                    rule_ids=(rule.rule_id,), source_locations=(rule.source_location,),
                    details={"any_source": _universal(match.sources),
                             "any_destination": _universal(match.destinations),
                             "services": [service.model_dump(mode="json") for service in rule.services],
                             "basis": "declared_conditions"},
                ))
            for earlier, earlier_match in known:
                inspected += 1
                if inspected > max_pairs:
                    budget_exhausted = True
                    break
                if not _intersects(earlier_match, match):
                    continue
                duplicate = earlier_match == match and earlier.action == rule.action
                covers = earlier_match.covers(match)
                findings.append(ControllerPolicyFinding(
                    code="CONTROLLER_DUPLICATE_CONDITION" if duplicate else
                    "CONTROLLER_COVERED_CONDITION" if covers else "CONTROLLER_OVERLAP",
                    severity="low" if duplicate else "medium" if earlier.action != rule.action else "info",
                    title="Повтор условий правила." if duplicate else
                    "Более раннее правило охватывает условия последующего." if covers else
                    "Условия правил пересекаются; результат зависит от порядка.",
                    policy_id=policy_id, rule_ids=(earlier.rule_id, rule.rule_id),
                    source_locations=(earlier.source_location, rule.source_location),
                    details={"earlier_action": earlier.action.value, "later_action": rule.action.value,
                             "full_coverage": covers, "basis": "static_declared_conditions",
                             "scope": "one_session_acl"},
                ))
            known.append((rule, match))
            if budget_exhausted:
                break
        if budget_exhausted:
            limitations.append("Достигнут лимит попарного анализа; оставшиеся пары не проверялись.")
            break
    summaries = []
    for role_name in _objects(inventory, "role"):
        names, reasons = _role_chain(parsed, inventory, role_name)
        role_rules = [rule for name in names for rule in groups.get(f"controller-session:{name}", ())]
        reasons.extend(_context_reasons(inventory))
        if any(resolve_rule(rule) is None for rule in role_rules):
            reasons.append("Роль содержит динамические или неподдержанные условия.")
        summaries.append(RolePolicySummary(
            role_name=role_name, acl_names=tuple(names), rule_count=len(role_rules),
            known_rules=sum(resolve_rule(rule) is not None for rule in role_rules),
            complete=not reasons, limitations=tuple(dict.fromkeys(reasons)),
        ))
    return ControllerAnalysis(
        findings=tuple(findings), roles=tuple(summaries),
        limitations=tuple(dict.fromkeys(limitations)),
    )


def controller_check_result(
    context: PolicyCheckContext, check_id: str, analysis: ControllerAnalysis | None = None,
) -> CheckResult | None:
    """Включить доказательные Controller-наблюдения в обычный отчёт проверок."""
    parsed = context.revision.parse_result
    if _inventory(parsed) is None:
        return None
    codes = {
        "FW-ANY-ANY": {"CONTROLLER_BROAD_PERMISSION"},
        "FW-DUPLICATE": {"CONTROLLER_DUPLICATE_CONDITION"},
        "FW-SHADOWED": {"CONTROLLER_COVERED_CONDITION"},
        "FW-PARTIAL-SHADOWED": {"CONTROLLER_OVERLAP"},
    }
    if check_id not in codes:
        return None
    report = analysis or analyze_controller(parsed, max_pairs=max(1, context.max_pair_rules**2))
    configuration = parsed.configuration
    findings = []
    for observation in report.findings:
        if observation.code not in codes[check_id]:
            continue
        if check_id == "FW-ANY-ANY" and not (
            observation.details.get("any_source") and observation.details.get("any_destination")
        ):
            continue
        findings.append(Finding(
            finding_id=uuid5(
                NAMESPACE_URL,
                f"{context.revision.revision_id}:controller-1.0.0:{check_id}:{observation.rule_ids}",
            ),
            check_id=check_id, category=FindingCategory.POLICY,
            severity=Severity(observation.severity), title=observation.title,
            description=observation.title, configuration_id=configuration.configuration_id,
            revision_id=context.revision.revision_id, device_id=context.revision.device.device_id,
            affected_rule_ids=observation.rule_ids,
            evidence=Evidence(
                summary=observation.title, source_locations=observation.source_locations,
                related_rule_ids=observation.rule_ids, facts=observation.details,
                limitations=(_LIMITATION,),
            ),
            recommendation="Проверить назначение роли, порядок политик и необходимость объявленных условий.",
            confidence=1.0, first_seen=context.analyzed_at, last_seen=context.analyzed_at,
        ))
    return CheckResult(
        check_id=check_id, check_version="controller-1.0.0", status=CheckStatus.PARTIAL,
        findings=tuple(findings), limitations=tuple(
            CheckLimitation(code="CONTROLLER_DECLARED_SCOPE", message=message)
            for message in report.limitations
        ),
    )


def _protocol_number(protocol: str) -> int:
    value = protocol.casefold()
    number = int(value) if value.isdecimal() else _PROTOCOLS.get(value, -1)
    if not 0 <= number <= 255:
        raise ValueError("protocol must be an IP protocol name or number 0..255")
    return number


def _address_matches(
    tokens: tuple[str, ...], address: str, family: int, parsed: ParseResult,
    inventory: ControllerInventory, user_ip: str | None, local_ip: str | None,
    user_roles: Mapping[str, str] | None,
) -> bool | None:
    if not tokens:
        return None
    head = tokens[0]
    if head == "any":
        return True
    if head in {"user", "localip"}:
        expected = user_ip if head == "user" else local_ip
        return None if expected is None else ip_address(address) == ip_address(expected)
    if head == "userrole":
        return None if len(tokens) != 2 or user_roles is None or address not in user_roles else user_roles[address] == tokens[1]
    try:
        target = ip_address(address)
        if head == "host" and len(tokens) == 2:
            return target == ip_address(tokens[1])
        if head == "network" and len(tokens) in {2, 3}:
            network = ip_network("/".join(tokens[1:]), strict=False)
            return target.version == network.version and target in network
        if head == "alias" and len(tokens) == 2:
            obj = _objects(inventory, "address" if family == 4 else "address6").get(tokens[1])
            if obj is None or obj.attributes.get("invert") or obj.attributes.get("duplicate_declaration"):
                return None
            members = obj.attributes.get("members", [])
            if not isinstance(members, (list, tuple)) or not members:
                return None
            unknown = False
            for member in members:
                if not isinstance(member, Mapping) or member.get("status") != "known":
                    unknown = True
                    continue
                cidr = member.get("cidr")
                if cidr:
                    network = ip_network(str(cidr), strict=False)
                    if target.version == network.version and target in network:
                        return True
                elif member.get("type") == "range":
                    first, last = ip_address(str(member["start"])), ip_address(str(member["end"]))
                    if target.version == first.version and int(first) <= int(target) <= int(last):
                        return True
                else:
                    unknown = True
            return None if unknown else False
    except (ValueError, KeyError, TypeError):
        return None
    return None


def _service_matches(
    tokens: tuple[str, ...], protocol: int, port: int | None,
    source_port: int | None, inventory: ControllerInventory,
) -> bool | None:
    if not tokens:
        return None
    if tokens == ("any",):
        return True
    if len(tokens) == 1 and tokens[0] not in _PROTOCOLS and not tokens[0].isdecimal():
        service = _objects(inventory, "service").get(tokens[0])
        if service is None or service.state != "declared" or service.attributes.get("status") != "known":
            return None
        attributes = service.attributes
        try:
            expected = attributes.get("ip_protocol")
            if expected is None:
                expected = _protocol_number(str(attributes.get("protocol", "")))
            if int(expected) != protocol:
                return False
            ranges = attributes.get("ports", [])
            return not ranges or port is not None and any(int(start) <= port <= int(end) for start, end in ranges)
        except (ValueError, TypeError):
            return None
    try:
        expected = _protocol_number(tokens[0])
        if expected != protocol:
            return False
        if len(tokens) == 1:
            return True
        rest = tokens[1:]
        selected_port = port
        if rest[:1] == ("source",):
            selected_port, rest = source_port, rest[1:]
        if expected not in {6, 17} or not 1 <= len(rest) <= 2:
            return None
        if selected_port is None:
            return None
        first, last = int(rest[0]), int(rest[-1])
        return first <= selected_port <= last
    except ValueError:
        return None


def _time_matches(name: str, at_time: datetime | None, inventory: ControllerInventory) -> bool | None:
    if at_time is None or at_time.tzinfo is None:
        return None
    schedule = _objects(inventory, "time_range").get(name)
    if schedule is None or schedule.state != "declared":
        return None
    device = next((obj for obj in inventory.objects if obj.kind == "device"), None)
    zone = schedule.attributes.get("timezone") or (device.attributes.get("timezone") if device else None)
    if not isinstance(zone, str):
        return None
    words = zone.split()
    if not words:
        return None
    try:
        local = at_time.astimezone(ZoneInfo(words[0]))
    except ZoneInfoNotFoundError:
        offset_text = "".join(words[-2:]) if len(words) >= 3 else words[-1]
        offset = re.fullmatch(r"(?:UTC)?([+-])(\d{2}):?(\d{2})", offset_text)
        if not offset:
            return None
        if int(offset[2]) > 23 or int(offset[3]) > 59:
            return None
        minutes = (int(offset[2]) * 60 + int(offset[3])) * (-1 if offset[1] == "-" else 1)
        local = at_time.astimezone(timezone(timedelta(minutes=minutes)))
    if schedule.attributes.get("mode") == "absolute":
        specification = schedule.attributes.get("specification", ())
        bounds: dict[str, datetime] = {}
        try:
            index = 0
            while index < len(specification):
                name = specification[index]
                if name not in {"start", "end"} or name in bounds:
                    return None
                bounds[name] = datetime.strptime(
                    f"{specification[index + 1]} {specification[index + 2]}", "%m/%d/%Y %H:%M"
                )
                index += 3
        except (IndexError, TypeError, ValueError):
            return None
        if not bounds:
            return None
        moment = local.replace(tzinfo=None)
        if any(moment.strftime("%Y-%m-%d %H:%M") == value.strftime("%Y-%m-%d %H:%M")
               for value in bounds.values()):
            return None
        if "start" in bounds and "end" in bounds and bounds["start"] > bounds["end"]:
            return None
        return ("start" not in bounds or moment > bounds["start"]) and (
            "end" not in bounds or moment < bounds["end"]
        )
    if schedule.attributes.get("mode") != "periodic":
        return None
    day_sets = {"daily": set(range(7)), "weekday": set(range(5)), "weekend": {5, 6}}
    day_sets.update({day: {index} for index, day in enumerate(
        ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
    )})
    unknown = False
    for interval in schedule.attributes.get("intervals", []):
        try:
            days = str(interval["days"]).casefold()
            if days not in day_sets:
                unknown = True
                continue
            if local.weekday() not in day_sets[days]:
                continue
            start, end = str(interval["start"]), str(interval["end"])
            datetime.strptime(start, "%H:%M")
            datetime.strptime(end, "%H:%M")
            current = local.strftime("%H:%M")
            if start > end:
                unknown = True
                continue
            # Endpoints are intentionally not guessed until exact platform boundary semantics are proved.
            if current in {start, end}:
                unknown = True
            elif start < current < end:
                return True
        except (KeyError, TypeError, ValueError):
            unknown = True
    return None if unknown else False


def evaluate_controller_role(
    parsed: ParseResult, role_name: str, source_ip: str, destination_ip: str,
    protocol: str, port: int | None = None, *, source_port: int | None = None,
    at_time: datetime | None = None, user_ip: str | None = None, local_ip: str | None = None,
    user_roles: Mapping[str, str] | None = None, ap_group: str | None = None,
) -> ControllerRoleDecision:
    """Оценить явное первое совпадение полного effective-среза без моделирования пути."""
    source, destination = ip_address(source_ip), ip_address(destination_ip)
    if source.version != destination.version:
        raise ValueError("source and destination must have the same address family")
    number = _protocol_number(protocol)
    if number in {6, 17} and (port is None or not 0 <= port <= 65535):
        raise ValueError("TCP/UDP query requires destination port 0..65535")
    if source_port is not None and not 0 <= source_port <= 65535:
        raise ValueError("source_port must be 0..65535")
    for value in (user_ip, local_ip):
        if value is not None:
            ip_address(value)
    inventory = _inventory(parsed)
    if inventory is None:
        return ControllerRoleDecision(role_name=role_name, reasons=("Каталог контроллера отсутствует.",))
    acl_names, reasons = _role_chain(parsed, inventory, role_name, ap_group, source.version)
    reasons.extend(_context_reasons(inventory))
    if reasons:
        return ControllerRoleDecision(role_name=role_name, reasons=tuple(dict.fromkeys(reasons)))
    entries = [obj for obj in inventory.objects if obj.kind == "ace"
               and obj.attributes.get("acl_kind") == "acl_session"]
    trace: list[ControllerTrace] = []
    uncertain = False
    for acl_name in acl_names:
        selected = sorted((entry for entry in entries if entry.attributes.get("acl_name") == acl_name),
                          key=lambda entry: int(entry.attributes.get("position", 0)))
        for entry in selected:
            attributes = entry.attributes
            family = 6 if attributes.get("address_family") == "ipv6" else 4
            if source.version != family:
                continue
            rule_id = str(attributes.get("rule_id") or "") or None
            values = [
                _address_matches(tuple(attributes.get("source_tokens", ())), str(source), family,
                                 parsed, inventory, user_ip, local_ip, user_roles),
                _address_matches(tuple(attributes.get("destination_tokens", ())), str(destination), family,
                                 parsed, inventory, user_ip, local_ip, user_roles),
                _service_matches(tuple(attributes.get("service_tokens", ())), number, port,
                                 source_port, inventory),
            ]
            if attributes.get("time_range"):
                values.append(_time_matches(str(attributes["time_range"]), at_time, inventory))
            if False in values:
                result: Literal["yes", "no", "unknown"] = "no"
                reason = "Известное условие не совпало."
            elif None in values or not attributes.get("semantics_supported", False):
                result, reason = "unknown", "Условие или дополнительное действие не разрешено полностью."
                uncertain = True
            else:
                result, reason = "yes", "Явные условия совпали с заданным tuple."
            action = str(attributes.get("action") or "unknown")
            trace.append(ControllerTrace(
                acl_name=acl_name, rule_id=rule_id, match=result, action=action,
                reason=reason, source_locations=entry.source_locations,
            ))
            if result != "yes":
                continue
            decision = _ACTIONS.get(action)
            if uncertain or decision is None:
                return ControllerRoleDecision(
                    role_name=role_name, trace=tuple(trace), reasons=(
                        "Более раннее неизвестное условие либо сложное действие не позволяет доказать решение.",
                    ),
                )
            return ControllerRoleDecision(
                role_name=role_name, decision="allow" if decision == "allow" else "deny",
                matched_rule_id=rule_id, trace=tuple(trace), reasons=(
                    "Результат явного первого совпадения в заданной последовательности ACL роли.",
                    "Основание порядка: " + _ROLE_ORDER_REFERENCE,
                ),
            )
    return ControllerRoleDecision(
        role_name=role_name, trace=tuple(trace), reasons=(
            "Явное терминальное совпадение не найдено. Неявный deny после каждой ACL не синтезируется; "
            "терминальная семантика всей роли требует отдельного подтверждения.",
        ),
    )
