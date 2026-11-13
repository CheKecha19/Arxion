"""Явные привязки IPv4 ACL в сохранённой конфигурации FlexFabric Release 6622."""

import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field

from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.domain.switch_facts import SwitchFacts, SwitchInterface
from firewall_compliance.domain.switch_policy import (
    AclBinding,
    AclDeclaration,
    ConfiguredAclProfile,
    PolicyImportIssue,
)
from firewall_compliance.parsers.contracts import SourceDocument


_PROFILE: ConfiguredAclProfile = "hpe-flexfabric-5944-5945-r6622"
_MODEL = re.compile(r"HPE (?:FF|FlexFabric) ([0-9]{4})(?: [\w./-]+)* Switch uptime is .+", re.I)
_RELEASE = re.compile(
    r"(?:HPE Comware Software, Version|version) "
    r"([0-9]+\.[0-9]+\.[0-9]+), Release ([0-9]+(?:P[0-9]+)?)", re.I,
)
_VLAN_INTERFACE = re.compile(r"Vlan-interface ?([1-9][0-9]{0,3})", re.I)
_ACL_HEADER = re.compile(r"acl (?:number|advanced|basic) ([0-9]{4})(?: .*)?")
_CONFIGURED_ACL_HEADER = re.compile(r"acl (?:number|advanced) 3[0-9]{3} match-order config")
_MANAGEMENT = re.compile(r"(?:ssh server|telnet server|ip http|ip https) acl ([0-9]{4})(?: .*)?")
_MANAGEMENT_ACCESS = re.compile(r"(?:acl|ntp-service access \S+) ([0-9]{4})(?: inbound| outbound)?")


@dataclass
class _Section:
    header: int
    commands: list[tuple[int, str]] = field(default_factory=list)
    vlan_id: str | None = None
    interface: bool = False


@dataclass(frozen=True)
class _Filter:
    line: int
    tokens: tuple[str, ...]
    section: _Section | None


def _profile_lines(lines: Sequence[str], source: SourceDocument) -> tuple[int, ...]:
    models: list[tuple[str, int]] = []
    releases: dict[tuple[str, str], int] = {}
    version_origins: Counter[str] = Counter()
    sysnames = 0
    for number, raw in enumerate(lines, 1):
        line = " ".join(raw.split())
        if line.casefold().startswith("sysname ") and raw == raw.lstrip():
            sysnames += 1
        if model := _MODEL.fullmatch(line):
            models.append((model[1], number))
        if release := _RELEASE.fullmatch(line):
            version_origins[line.partition(" ")[0].lower()] += 1
            releases.setdefault((release[1], release[2].upper()), number)
    if (
        source.configuration_view != "pending" and source.configuration_node_path is None
        and len(models) == 1 and models[0][0] in {"5944", "5945"} and len(releases) == 1
        and sysnames <= 1 and all(count == 1 for count in version_origins.values())
    ):
        (version, release_name), release_line = next(iter(releases.items()))
        if version.startswith("7.1.") and release_name == "6622":
            return models[0][1], release_line
    return ()


def _scan(
    lines: Sequence[str],
) -> tuple[dict[str, list[_Section]], dict[str, list[_Section]], list[_Filter], list[int], set[str]]:
    acls: dict[str, list[_Section]] = defaultdict(list)
    vlans: dict[str, list[_Section]] = defaultdict(list)
    filters: list[_Filter] = []
    conflicts: list[int] = []
    management: set[str] = set()
    section: _Section | None = None
    for number, raw in enumerate(lines, 1):
        line = " ".join(raw.split())
        if not line:
            continue
        if line.startswith(("#", "!", ";")) or line in {"quit", "return", "exit"}:
            section = None
            continue
        if not raw[0].isspace():
            section = None
            if line.startswith("interface "):
                section = _Section(header=number, interface=True)
                interface = _VLAN_INTERFACE.fullmatch(line.removeprefix("interface "))
                if interface is not None and int(interface[1]) <= 4094:
                    section.vlan_id = interface[1]
                    vlans[interface[1]].append(section)
                continue
            if header := _ACL_HEADER.fullmatch(line):
                section = _Section(header=number)
                acls[header[1]].append(section)
                continue
        elif section is not None:
            section.commands.append((number, line))
        if target := _MANAGEMENT.fullmatch(line) or _MANAGEMENT_ACCESS.fullmatch(line):
            management.add(target[1])
        if line.startswith(("acl copy ", "undo acl ", "qos apply ", "qos vlan-policy ", "traffic-policy ")):
            conflicts.append(number)
        if not line.startswith(("packet-filter ", "undo packet-filter ")):
            continue
        if line == "packet-filter default deny" and section is None:
            continue  # Явно совпавшие ACE не зависят от действия для остатка.
        tokens = tuple(line.split())
        if (
            tokens[:2] == ("packet-filter", "filter")
            and section is not None and section.vlan_id is not None
        ):
            continue  # route/all проверяются внутри конкретной привязки.
        if (
            section is None or not section.interface or "vlan-interface" in tokens
            or tokens[0] == "undo" or tokens[1] in {"default", "permit-flag", "filter"}
        ):
            conflicts.append(number)
        if tokens[0] == "packet-filter" and tokens[1] not in {"filter", "default", "permit-flag"}:
            filters.append(_Filter(number, tokens, section))
    return acls, vlans, filters, conflicts, management


def _acl_reference(item: _Filter) -> str:
    words = item.tokens[1:]
    family = words[0] if words[0] in {"ipv6", "mac", "user-defined"} else "ipv4"
    if family != "ipv4":
        words = words[1:]
    if words and words[0] == "name":
        words = words[1:]
    if words and re.fullmatch(r"[A-Za-z0-9_.-]+", words[0]):
        return f"{family}:{words[0]}"
    return f"unknown:packet-filter:{item.line}"


def _interface_context(
    section: _Section, interfaces: Sequence[SwitchInterface],
) -> tuple[str, tuple[int, ...]] | None:
    if len(interfaces) != 1:
        return None
    interface = interfaces[0]
    address_lines = tuple(
        location.line_start for item in interface.addresses
        if item.status == "known" and item.cidr and ":" not in item.cidr
        for location in item.source_locations if location.line_start is not None
    )
    if (
        interface.kind != "vlan" or interface.mode != "l3" or interface.admin_state == "disabled"
        or not address_lines
        or not any(item.line_start == section.header for item in interface.source_locations)
    ):
        return None
    bindings = [
        (number, command) for number, command in section.commands
        if re.match(r"(?:undo )?(?:ip binding|vrf)(?: |$)", command)
    ]
    if not bindings:
        return ("default", address_lines[:1]) if interface.vrf == "default" else None
    if len(bindings) == 1:
        number, command = bindings[0]
        match = re.fullmatch(r"ip binding vpn-instance (\S+)", command)
        if match is not None and match[1] == interface.vrf:
            return match[1], (number, *address_lines[:1])
    return None


def _complete_entries(section: _Section, declaration: AclDeclaration, rules: Sequence[Rule]) -> bool:
    rule_lines = set()
    for line, command in section.commands:
        if re.match(r"rule [0-9]+ (?:permit|deny) (?:ip|tcp|udp|icmp)(?: |$)", command):
            rule_lines.add(line)
        elif not (command.startswith("description ") or re.fullmatch(r"step [0-9]+", command)):
            return False
    represented = {
        (location.line_start, entry.sequence,
         "allow" if entry.action == "permit" else "deny", entry.rule_ids[0])
        for entry in declaration.entries if entry.valid and len(entry.rule_ids) == 1
        for location in entry.source_locations
    }
    return bool(
        rules and len(rules) == len(rule_lines) == len(declaration.entries) == len(represented)
        and len({rule.sequence for rule in rules}) == len(rules)
        and all(rule.match_status == DataStatus.KNOWN and rule.action.value in {"allow", "deny"}
                for rule in rules)
        and rule_lines == {rule.source_location.line_start for rule in rules}
        and represented == {
            (rule.source_location.line_start, rule.sequence, rule.action.value, rule.rule_id)
            for rule in rules
        }
    )


def configured_bindings(
    source: SourceDocument, lines: Sequence[str], declarations: Sequence[AclDeclaration],
    rules: Sequence[Rule], facts: SwitchFacts, other_bindings: Sequence[AclBinding],
) -> tuple[list[AclBinding], list[PolicyImportIssue]]:
    """Сохранить наблюдаемые назначения и подтвердить только документированный срез."""
    acls, vlans, filters, conflicts, management = _scan(lines)
    if not filters:
        return [], []
    profile = _profile_lines(lines, source)
    declared = {item.acl_id: item for item in declarations}
    management.update(
        item.acl_id.removeprefix("ipv4:") for item in other_bindings if item.purpose == "management"
    )
    acl_rules: dict[str, list[Rule]] = defaultdict(list)
    by_vlan: dict[str, list[SwitchInterface]] = defaultdict(list)
    filters_by_vlan: dict[str, list[_Filter]] = defaultdict(list)
    for rule in rules:
        if rule.policy_id is not None:
            acl_rules[rule.policy_id].append(rule)
    for interface in facts.interfaces:
        if match := _VLAN_INTERFACE.fullmatch(interface.name):
            by_vlan[match[1]].append(interface)
    for item in filters:
        if item.section is not None and item.section.vlan_id is not None:
            filters_by_vlan[item.section.vlan_id].append(item)
    route_commands = {
        vlan: [(number, command) for number, command in sections[0].commands
               if command.startswith("packet-filter filter ")]
        for vlan, sections in vlans.items() if len(sections) == 1 and vlan in filters_by_vlan
    }
    eligible_entries: dict[str, bool] = {}

    def entries_complete(number: str, section: _Section, declaration: AclDeclaration) -> bool:
        if number not in eligible_entries:
            eligible_entries[number] = _complete_entries(
                section, declaration, acl_rules.get(f"acl:{number}", ()),
            )
        return eligible_entries[number]

    def location(number: int) -> SourceLocation:
        return SourceLocation(source_name=source.source_name, line_start=number, line_end=number)

    bindings = []
    issues = []
    for item in filters:
        reference = _acl_reference(item)
        acl_number = reference.removeprefix("ipv4:")
        sections = acls.get(acl_number, ())
        declaration = declared.get(reference)
        section = item.section
        vlan = section.vlan_id if section else None
        subject = f"interface:vlan:{vlan}" if vlan is not None else "unknown"
        routes = route_commands.get(vlan, ()) if vlan is not None else ()
        direction = "in" if "inbound" in item.tokens else "out" if "outbound" in item.tokens else None
        anchors = [item.line]
        vrf = None
        reason = None
        if not profile:
            reason = "Нет однозначного подтверждения модели FlexFabric 5944/5945 и Release 6622."
        elif (
            section is None or vlan is None or len(vlans[vlan]) != 1 or len(filters_by_vlan[vlan]) != 1
            or item.tokens != ("packet-filter", acl_number, "inbound")
            or not re.fullmatch(r"3[0-9]{3}", acl_number)
        ):
            reason = (
                "Поддерживается одно прямое входящее назначение IPv4 ACL 3000–3999 на VLAN-интерфейсе."
            )
        elif len(routes) != 1 or routes[0][1] != "packet-filter filter route":
            reason = "На VLAN-интерфейсе требуется явная область packet-filter filter route."
        elif conflicts:
            reason = "В снимке есть другие применения фильтра, изменения ACL или политики QoS."
            anchors.append(conflicts[0])
        elif acl_number in management:
            reason = "Та же ACL используется для управления."
        elif (
            declaration is None or declaration.match_order != "config" or len(sections) != 1
            or not _CONFIGURED_ACL_HEADER.fullmatch(" ".join(lines[sections[0].header - 1].split()))
        ):
            reason = "Требуется единственное объявление IPv4 ACL с явным порядком match-order config."
        elif not entries_complete(acl_number, sections[0], declaration):
            reason = "Не подтверждены уникальные номера и поддерживаемые условия всех правил ACL."
        elif (context := _interface_context(section, by_vlan.get(vlan, ()))) is None:
            reason = "Не подтверждён один маршрутизируемый IPv4 VLAN-интерфейс и его контекст."
        else:
            vrf, context_anchors = context
            direction = "routed-in"
            anchors.extend((section.header, routes[0][0], sections[0].header, *profile, *context_anchors))
        if reason is not None:
            issues.append(PolicyImportIssue(
                code="BINDING_COMWARE_UNVERIFIED", message=reason, source_location=location(item.line),
            ))
        bindings.append(AclBinding(
            binding_id=f"switch-binding:{item.line}", acl_id=reference,
            purpose="transit" if vrf is not None else "unknown", subject=subject,
            direction=direction, vrf=vrf, semantics="first_match" if vrf is not None else None,
            configured_profile=_PROFILE if vrf is not None else None,
            source_locations=tuple(location(number) for number in dict.fromkeys(anchors)),
        ))
    return bindings, issues
