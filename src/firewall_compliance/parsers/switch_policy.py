"""Сохранение объявлений ACL отдельно от сервисных и интерфейсных привязок."""

import re
import shlex
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Literal, cast

from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus, EndpointKind, ParseIssueLevel, Protocol
from firewall_compliance.domain.network import Endpoint, PortRange, Service
from firewall_compliance.domain.parse_result import ParseIssue, ParseResult
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.domain.switch_facts import SwitchFacts
from firewall_compliance.domain.switch_policy import (
    AceDeclaration,
    AclBinding,
    AclDeclaration,
    AclMatchOrder,
    ManagerAccess,
    PolicyAreaCoverage,
    PolicyImportIssue,
    SwitchPolicies,
)
from firewall_compliance.parsers.contracts import SourceDocument
from firewall_compliance.parsers.platform_detection import detect_switch_platform

type _AclKind = Literal["standard", "extended"]
type _ConfiguredBindingsReader = Callable[
    [SourceDocument, list[str], tuple[AclDeclaration, ...], tuple[Rule, ...], SwitchFacts, list[AclBinding]],
    tuple[list[AclBinding], list[PolicyImportIssue]],
]


@dataclass
class _DeclaredConditions:
    source_raw: str | None = None
    destination_raw: str | None = None
    source_ports_raw: str | None = None
    destination_ports_raw: str | None = None
    protocol_raw: str = "ip"
    sources: tuple[Endpoint, ...] = ()
    destinations: tuple[Endpoint, ...] = ()
    services: tuple[Service, ...] = ()
    valid: bool = False


def _endpoint(raw: str, identifier: str, *, wildcard: bool) -> Endpoint:
    """Нормализовать только поддержанный IPv4 операнд без расширения unknown до ANY."""
    tokens = raw.split()
    if tokens == ["any"]:
        return Endpoint(endpoint_id=identifier, name="any", kind=EndpointKind.ANY)
    try:
        if tokens and tokens[0] == "host":
            tokens = tokens[1:]
        if not tokens or len(tokens) > 2:
            raise ValueError("неподдержанный операнд")
        address = tokens[0]
        if len(tokens) == 2:
            mask = int(IPv4Address("0.0.0.0" if tokens[1] == "0" else tokens[1]))
            if not wildcard or mask & (mask + 1):
                raise ValueError("неподдержанная wildcard mask")
            address = f"{address}/{32 - mask.bit_count()}"
        network = IPv4Network(address if "/" in address else f"{address}/32", strict=False)
        return Endpoint(
            endpoint_id=identifier, name=raw,
            kind=EndpointKind.HOST if network.prefixlen == 32 else EndpointKind.SUBNET,
            cidrs=(str(network),),
        )
    except ValueError:
        return Endpoint(
            endpoint_id=identifier, name=raw or "неизвестный адрес", kind=EndpointKind.OBJECT,
            resolution_status=DataStatus.UNKNOWN,
        )


def _address_operand(tokens: list[str], index: int, *, wildcard: bool) -> tuple[str, int]:
    if index >= len(tokens):
        raise ValueError("нет адресного операнда")
    start = index
    token = tokens[index]
    index += 1
    if token == "host":
        if index >= len(tokens):
            raise ValueError("нет host-адреса")
        index += 1
    elif wildcard and token != "any" and "/" not in token and index < len(tokens):
        # Повреждённая dotted mask тоже входит в raw-операнд, но не считается известной.
        if re.fullmatch(r"[0-9.,]+|ip#?\d+", tokens[index], re.IGNORECASE):
            index += 1
    return " ".join(tokens[start:index]), index


def _port_operand(tokens: list[str], index: int) -> tuple[str | None, int]:
    if index >= len(tokens) or tokens[index] not in {"eq", "gt", "lt", "range", "neq", "group"}:
        return None, index
    length = 3 if tokens[index] == "range" else 2
    return " ".join(tokens[index:index + length]), min(index + length, len(tokens))


def _declared_conditions(
    body: list[str], platform: str, kind: str | None, identifier: str,
) -> _DeclaredConditions:
    """Восстановить объявленные условия независимо от management-представления Rule."""
    result = _DeclaredConditions()
    if not body or body[0] not in {"permit", "deny"}:
        return result
    try:
        index = 1
        if kind == "extended":
            if index >= len(body):
                return result
            result.protocol_raw = body[index]
            index += 1
        if platform == "comware":
            while index < len(body):
                keyword = body[index]
                index += 1
                if keyword in {"source", "destination"}:
                    value, index = _address_operand(body, index, wildcard=True)
                    if keyword == "source":
                        if result.source_raw is not None:
                            return result
                        result.source_raw = value
                    else:
                        if result.destination_raw is not None:
                            return result
                        result.destination_raw = value
                elif keyword == "destination-port":
                    result.destination_ports_raw, index = _port_operand(body, index)
                    if result.destination_ports_raw is None:
                        return result
                elif keyword == "source-port":
                    result.source_ports_raw, index = _port_operand(body, index)
                    if result.source_ports_raw is None:
                        return result
                elif keyword == "logging":
                    continue
                elif keyword == "comment":
                    break
                else:
                    return result
        else:
            result.source_raw, index = _address_operand(body, index, wildcard=platform == "aos-switch")
            if kind == "extended":
                result.source_ports_raw, index = _port_operand(body, index)
                result.destination_raw, index = _address_operand(body, index, wildcard=platform == "aos-switch")
                result.destination_ports_raw, index = _port_operand(body, index)
            if any(token not in {"log", "count"} for token in body[index:]):
                return result
        source = _endpoint(result.source_raw or "any", f"{identifier}:source", wildcard=platform != "aos-cx")
        destination = _endpoint(result.destination_raw or "any", f"{identifier}:destination", wildcard=platform != "aos-cx")
        protocol = {"any": Protocol.IP, "ip": Protocol.IP, "tcp": Protocol.TCP,
                    "udp": Protocol.UDP, "icmp": Protocol.ICMP}.get(result.protocol_raw, Protocol.OTHER)
        ports: tuple[PortRange, ...] = ()
        service_valid = protocol != Protocol.OTHER and result.source_ports_raw is None
        if result.destination_ports_raw:
            words = result.destination_ports_raw.split()
            aliases = {"ssh": 22, "telnet": 23, "http": 80, "www": 80, "https": 443,
                       "snmp": 161, "snmptrap": 162, "domain": 53, "dns": 53,
                       "ntp": 123, "tftp": 69, "ftp": 21}
            values = [int(word) if word.isdigit() else aliases[word] for word in words[1:]]
            if protocol not in {Protocol.TCP, Protocol.UDP} or not values:
                service_valid = False
            elif words[0] == "eq" and len(values) == 1:
                ports = (PortRange(start=values[0], end=values[0]),)
            elif words[0] == "range" and len(values) == 2:
                ports = (PortRange(start=values[0], end=values[1]),)
            elif words[0] == "gt" and len(values) == 1 and values[0] < 65535:
                ports = (PortRange(start=values[0] + 1, end=65535),)
            else:
                service_valid = False
        result.sources = (source,)
        result.destinations = (destination,)
        result.services = (Service(
            service_id=f"{identifier}:service", name=result.protocol_raw, protocol=protocol,
            port_ranges=ports, resolution_status=DataStatus.KNOWN if service_valid else DataStatus.UNKNOWN,
        ),)
        result.valid = service_valid and source.resolution_status == destination.resolution_status == DataStatus.KNOWN
    except (IndexError, KeyError, ValueError):
        # Raw-операнды остаются доступны, даже если их нельзя нормализовать.
        result.valid = False
    return result


def parse_switch_policies(
    source: SourceDocument, parsed: ParseResult, *, facts: SwitchFacts | None = None,
    read_configured_bindings: _ConfiguredBindingsReader | None = None,
) -> SwitchPolicies:
    """Извлечь независимые объявления и все поддержанные места применения."""
    platform = parsed.configuration.platform
    lines = source.content.decode("utf-8-sig").splitlines()
    detection = detect_switch_platform(source.content.decode("utf-8-sig"))
    documented_cx_implicit = platform == "aos-cx" and bool(re.match(
        r"(?:[A-Z]+\.)?10\.10\.", detection.version or "", re.IGNORECASE,
    ))
    headers: dict[str, tuple[str, int, _AclKind | None]] = {}
    orders: dict[str, AclMatchOrder] = {}
    entries: dict[str, list[AceDeclaration]] = {}
    sequences: dict[str, set[int]] = defaultdict(set)
    largest_sequences: dict[str, int] = {}
    rules_by_line: dict[int, list[Rule]] = defaultdict(list)
    for rule in parsed.rules:
        if rule.source_location.line_start is not None:
            rules_by_line[rule.source_location.line_start].append(rule)
    unsupported_lines = {item.source_location.line_start for item in parsed.unsupported_constructs}
    unsupported_acl_lines = {
        item.source_location.line_start for item in parsed.unsupported_constructs
        if item.construct_type not in {"logging", "comment"}
    }
    bindings: list[AclBinding] = []
    managers: list[ManagerAccess] = []
    issues: list[PolicyImportIssue] = []
    current: str | None = None
    scope: str | None = None
    community: str | None = None

    def loc(number: int) -> SourceLocation:
        return SourceLocation(source_name=source.source_name, line_start=number, line_end=number)

    def issue(code: str, message: str, number: int) -> None:
        issues.append(PolicyImportIssue(code=code, message=message, source_location=loc(number)))

    def acl_id(name: str) -> str:
        return f"ipv4:{name}"

    def bind(
        name: str, number: int, subject: str, *, service: str | None = None,
        vrf: str | None = None, direction: str | None = None,
        management: bool | None = True, implicit: str = "unknown",
    ) -> None:
        bindings.append(AclBinding(
            binding_id=f"switch-binding:{number}", acl_id=acl_id(name),
            purpose="unknown" if management is None else "management" if management else "transit",
            subject=subject,
            service=service, vrf=vrf, direction=direction, source_locations=(loc(number),),
            implicit_action="deny" if implicit == "deny" and documented_cx_implicit else "unknown",
            semantics="first_match" if management is False else None,
            implicit_action_reference=(
                "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.10/PDF/acls_6300-6400-8360.pdf"
                if implicit == "deny" and documented_cx_implicit else None
            ),
        ))

    def declare(name: str, number: int, kind: _AclKind | None) -> None:
        nonlocal current, scope
        current = name
        scope = None
        if name in headers:
            issue("ACL_REDECLARED", "Повторное объявление ACL; полнота порядка требует проверки.", number)
        else:
            headers[name] = (name, number, kind)
        entries.setdefault(name, [])

    def entry(name: str, tokens: list[str], number: int) -> None:
        related = rules_by_line.get(number, [])
        sequence = (
            int(tokens[0]) if tokens and tokens[0].isdigit()
            else related[0].sequence if related
            else largest_sequences.get(name, 0) + 10
        )
        body = tokens[1:] if tokens and tokens[0].isdigit() else tokens
        if not body or body[0] not in {"permit", "deny"}:
            return
        identifier = f"{acl_id(name)}:line:{number}"
        conditions = _declared_conditions(body, platform, headers[name][2], identifier)
        valid = conditions.valid and bool(related) and all(
            r.action.value in {"allow", "deny"} for r in related
        )
        if number in unsupported_acl_lines:
            valid = False
        if not valid:
            issue("ACE_UNRESOLVED", "Условия ACE повреждены, неизвестны или не полностью поддержаны.", number)
        if sequence in sequences[name]:
            issue("ACE_ORDER_CONFLICT", "Повторный номер ACE не доказывает порядок применения.", number)
        sequences[name].add(sequence)
        largest_sequences[name] = max(largest_sequences.get(name, sequence), sequence)
        entries.setdefault(name, []).append(AceDeclaration(
            entry_id=identifier, sequence=sequence, action=body[0],
            source_locations=(loc(number),), raw_source=conditions.source_raw,
            raw_destination=conditions.destination_raw, protocol=conditions.protocol_raw,
            raw_source_ports=conditions.source_ports_raw,
            raw_destination_ports=conditions.destination_ports_raw,
            sources=conditions.sources, destinations=conditions.destinations,
            services=conditions.services,
            rule_ids=tuple(rule.rule_id for rule in related), valid=valid,
        ))

    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(("!", "#", ";")):
            if line in {"#", "!"}:
                current = scope = community = None
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            if "access-list" in line or line.startswith(("acl ", "rule ", "ip authorized-managers")):
                issue("POLICY_TOKENIZATION", "Некорректные кавычки в политике.", number)
            continue
        if not tokens:
            continue
        if line in {"exit", "quit", "return"}:
            current = scope = community = None
            continue
        if not raw[:1].isspace():
            community = None
            if tokens[0] not in {"interface", "vlan"}:
                scope = None
        match = re.fullmatch(r"acl (?:number|basic|advanced) (\S+)(?: .*)?", line)
        switch_header = re.fullmatch(r"ip access-list (?:standard|extended) (\S+)", line)
        if match or switch_header:
            found = match or switch_header
            assert found is not None
            kind: _AclKind = "extended" if (
                (match and (tokens[1] == "advanced" or found[1].isdigit() and 3000 <= int(found[1]) <= 3999))
                or (switch_header and tokens[2] == "extended")
            ) else "standard"
            declare(found[1], number, kind)
            if platform == "comware" and headers[found[1]][1] == number:
                order = re.fullmatch(
                    r"acl (?:number|advanced|basic) [0-9]{4} match-order (config|auto)", " ".join(tokens),
                )
                if order is not None:
                    orders[found[1]] = cast(AclMatchOrder, order[1])
            continue
        if tokens[:2] == ["access-list", "ip"] and len(tokens) == 3:
            declare(tokens[2], number, "extended")
            continue
        if tokens[0] == "access-list" and len(tokens) > 2 and tokens[1].isdigit():
            name = tokens[1]
            if name not in headers:
                headers[name] = (name, number, "standard" if int(name) < 100 else "extended")
            current = scope = None
            entry(name, tokens[2:], number)
            continue
        if current is not None:
            body = tokens[1:] if tokens[0] == "rule" else tokens
            if body and (body[0].isdigit() or body[0] in {"permit", "deny"}):
                entry(current, body, number)
                continue
            if tokens[0] in {"description", "remark", "comment"}:
                continue
            if platform == "comware" and len(tokens) == 2 and tokens[0] == "step" and tokens[1].isdigit():
                continue
            current = None
        if tokens[0] in {"interface", "vlan"}:
            scope = ":".join(tokens)
        if tokens[:2] == ["snmp-server", "community"]:
            community = f"community-line:{number}"
        if tokens[:3] == ["snmp-agent", "community", "read"] or tokens[:3] == ["snmp-agent", "community", "write"]:
            if "acl" in tokens:
                index = tokens.index("acl")
                if index + 1 < len(tokens):
                    bind(tokens[index + 1], number, f"community-line:{number}", service="snmp")
        if tokens[:3] == ["ssh", "server", "acl"] and len(tokens) == 4:
            bind(tokens[3], number, "ssh-server", service="ssh")
        if community and tokens[:2] == ["access-list", "ipv4"] and len(tokens) == 3:
            bind(tokens[2], number, community, service="snmp")
        if tokens[:3] == ["apply", "access-list", "ip"] and len(tokens) >= 5:
            if len(tokens) == 7 and tokens[4:6] == ["control-plane", "vrf"]:
                bind(tokens[3], number, "control-plane", vrf=tokens[6], implicit="deny")
            elif tokens[4] in {"in", "out", "routed-in", "routed-out"} and scope:
                bind(tokens[3], number, scope, direction=tokens[4], management=False, implicit="deny")
            else:
                issue("BINDING_UNRESOLVED", "Область применения ACL не поддержана.", number)
                bind(tokens[3], number, "unknown", management=None)
        if tokens[:2] == ["ip", "access-group"] and len(tokens) == 4 and scope:
            if tokens[3] in {"in", "out", "routed-in", "routed-out"}:
                bind(tokens[2], number, scope, direction=tokens[3], management=False)
            else:
                issue("BINDING_UNRESOLVED", "Неизвестное направление применения ACL.", number)
                bind(tokens[2], number, scope, management=None)
        if tokens[:2] == ["ip", "authorized-managers"] and len(tokens) >= 3:
            mask = (
                tokens[3] if len(tokens) > 3 and tokens[3] not in {"access", "access-method"}
                else "255.255.255.255"
            )
            cidr: str | None = None
            try:
                cidr = str(IPv4Network(f"{tokens[2]}/{mask}", strict=False))
            except ValueError:
                issue("MANAGER_ADDRESS_INVALID", "Некорректный адрес источника управления.", number)
            method = tokens[tokens.index("access-method") + 1] if "access-method" in tokens and tokens.index("access-method") + 1 < len(tokens) else "all"
            privilege = tokens[tokens.index("access") + 1] if "access" in tokens and tokens.index("access") + 1 < len(tokens) else "manager"
            valid_manager = cidr is not None and method in {"all", "ssh", "snmp", "telnet", "web", "tftp"} and privilege in {"manager", "operator"}
            valid_manager = valid_manager and bool(rules_by_line.get(number)) and number not in unsupported_lines
            if not valid_manager and cidr is not None:
                issue("MANAGER_SCOPE_UNRESOLVED", "Метод или права управляющего доступа не поддержаны.", number)
            managers.append(ManagerAccess(
                manager_id=f"authorized-manager:{number}", source_raw=f"{tokens[2]} {mask}",
                source_cidr=cidr, method=method, privilege=privilege, valid=valid_manager,
                source_locations=(loc(number),),
            ))
    declarations = tuple(AclDeclaration(
        acl_id=acl_id(name), name=name, entries=tuple(entries.get(name, ())),
        acl_type=kind, source_locations=(loc(number),), match_order=orders.get(name),
    ) for name, (_, number, kind) in headers.items())
    if read_configured_bindings is not None:
        from firewall_compliance.parsers.switch_facts import parse_switch_facts

        observed, unsupported = read_configured_bindings(
            source, lines, declarations, parsed.rules, facts or parse_switch_facts(source, platform), bindings,
        )
        bindings.extend(observed)
        issues.extend(unsupported)
    declared_ids = {item.acl_id for item in declarations}
    for binding in bindings:
        if binding.acl_id.startswith("ipv4:") and binding.acl_id not in declared_ids:
            issue("BINDING_WITHOUT_ACL", "Привязка ссылается на отсутствующее объявление ACL.", binding.source_locations[0].line_start or 1)
    coverage: list[PolicyAreaCoverage] = []
    areas: tuple[tuple[Literal["acl", "bindings", "managers"], int, tuple[SourceLocation, ...]], ...] = (
        ("acl", sum(len(values) for values in entries.values()),
         tuple(loc(number) for _, number, _ in headers.values())),
        ("bindings", len(bindings), tuple(location for b in bindings for location in b.source_locations)),
        ("managers", len(managers), tuple(location for m in managers for location in m.source_locations)),
    )
    for area, recognized, anchors in areas:
        relevant = tuple(item for item in issues if (
            area == "acl" and (item.code.startswith(("ACE_", "ACL_")) or item.code == "POLICY_TOKENIZATION")
            or area == "bindings" and item.code.startswith("BINDING_")
            or area == "managers" and item.code.startswith("MANAGER_")
        ))
        coverage.append(PolicyAreaCoverage(
            area=area, state="partial" if recognized or anchors else "unknown" if relevant else "not_observed",
            recognized_constructs=recognized, unsupported_constructs=len(relevant),
            source_locations=anchors,
        ))
    return SwitchPolicies(
        declarations=declarations,
        bindings=tuple(bindings), managers=tuple(managers), issues=tuple(issues),
        coverage=tuple(coverage),
        detection_reasons=detection.reasons, source_name=source.source_name,
        content_sha256=source.content_sha256,
    )


def _project_configured_rules(
    parsed: ParseResult, policies: SwitchPolicies,
) -> tuple[tuple[Rule, ...], tuple[Endpoint, ...], SwitchPolicies, dict[str, SourceLocation]]:
    bindings_by_acl: dict[str, list[AclBinding]] = defaultdict(list)
    for binding in policies.bindings:
        if binding.configured_profile is not None:
            bindings_by_acl[binding.acl_id].append(binding)
    if not bindings_by_acl:
        return parsed.rules, parsed.endpoints, policies, parsed.source_map

    rules = {rule.rule_id: rule for rule in parsed.rules}
    projections = []
    declarations = []
    ipv4_endpoints: dict[str, Endpoint] = {}
    source_map = dict(parsed.source_map)

    def ipv4_only(endpoints: tuple[Endpoint, ...], location: SourceLocation) -> tuple[Endpoint, ...]:
        result = []
        for endpoint in endpoints:
            if endpoint.kind != EndpointKind.ANY:
                result.append(endpoint)
                continue
            key = f"{endpoint.endpoint_id}:ipv4"
            if key not in ipv4_endpoints:
                ipv4_endpoints[key] = Endpoint(
                    endpoint_id=key, name=endpoint.name, kind=EndpointKind.SUBNET, cidrs=("0.0.0.0/0",),
                )
                source_map[key] = location
            result.append(ipv4_endpoints[key])
        return tuple(result)

    for declaration in policies.declarations:
        bindings = bindings_by_acl.get(declaration.acl_id)
        if bindings is None:
            declarations.append(declaration)
            continue
        entries = []
        for entry in declaration.entries:
            original = rules[entry.rule_ids[0]]
            sources = ipv4_only(original.sources, original.source_location)
            destinations = ipv4_only(original.destinations, original.source_location)
            identifiers = list(entry.rule_ids)
            for binding in bindings:
                zone = f"{binding.subject}:{binding.direction}"
                identifier = f"{original.rule_id}@{zone}"
                projections.append(original.model_copy(update={
                    "rule_id": identifier,
                    "name": f"ACL {declaration.name} / {entry.sequence} · {binding.subject}",
                    "policy_id": f"acl:{declaration.name}@{zone}",
                    "sources": sources, "destinations": destinations,
                    "policy_direction": "in", "policy_semantics": "first_match", "policy_purpose": "transit",
                    "source_zone": zone, "zone_status": DataStatus.KNOWN,
                    "logging_enabled": bool(original.logging_enabled), "logging_status": DataStatus.KNOWN,
                }))
                source_map[identifier] = original.source_location
                source_map[f"binding:{identifier}"] = binding.source_locations[0]
                identifiers.append(identifier)
            entries.append(entry.model_copy(update={"rule_ids": tuple(identifiers)}))
        declarations.append(declaration.model_copy(update={"entries": tuple(entries)}))
    return (
        (*parsed.rules, *projections), (*parsed.endpoints, *ipv4_endpoints.values()),
        policies.model_copy(update={"declarations": tuple(declarations)}), source_map,
    )


def enrich_switch_result(
    source: SourceDocument, parsed: ParseResult, *,
    read_configured_bindings: _ConfiguredBindingsReader | None = None,
) -> ParseResult:
    """Добавить версионированные факты, не меняя исторические ревизии."""
    from firewall_compliance.parsers.switch_facts import parse_switch_facts

    platform = parsed.configuration.platform
    facts = parse_switch_facts(source, platform)
    policies = parse_switch_policies(source, parsed, facts=facts, read_configured_bindings=read_configured_bindings)
    native_rules, endpoints, source_map = parsed.rules, parsed.endpoints, parsed.source_map
    if read_configured_bindings is not None:
        native_rules, endpoints, policies, source_map = _project_configured_rules(parsed, policies)
    purposes: dict[int, set[str]] = {}
    applications: dict[int, set[tuple[str, str]]] = {}
    bindings_by_acl: dict[str, list[AclBinding]] = defaultdict(list)
    for binding in policies.bindings:
        bindings_by_acl[binding.acl_id].append(binding)
    for acl in policies.declarations:
        acl_bindings = bindings_by_acl.get(acl.acl_id, ())
        bound = {b.purpose for b in acl_bindings}
        transit = {
            (
                f"acl:{acl.name}@{binding.subject}:{binding.direction}",
                "in" if binding.direction in {"in", "routed-in"} else "out",
            )
            for binding in acl_bindings if binding.purpose == "transit"
        }
        for entry in acl.entries:
            for location in entry.source_locations:
                if location.line_start is not None:
                    purposes[location.line_start] = bound
                    applications[location.line_start] = transit
    rules = []
    for rule in native_rules:
        line_number = rule.source_location.line_start or 0
        bound = purposes.get(line_number, set())
        transit_application = (
            rule.policy_semantics == "first_match"
            and (rule.policy_id, rule.policy_direction) in applications.get(line_number, ())
        )
        if (rule.policy_id or "").startswith("management:"):
            purpose = "management"
        elif transit_application:
            purpose = "transit"
        elif bound == {"management"}:
            purpose = "management"
        elif platform == "comware" and bound == {"transit"}:
            # Сохраняем прежний ID объявления для старых требований матрицы.
            purpose = "unbound"
        elif bound:
            purpose = "unknown"
        else:
            purpose = "unbound"
        rules.append(rule.model_copy(update={"policy_purpose": purpose}))
    warnings = list(parsed.warnings)
    warnings.extend(ParseIssue(
        code=issue.code, level=ParseIssueLevel.WARNING,
        message=issue.message, source_location=issue.source_location,
    ) for issue in policies.issues)
    if not any(binding.purpose == "transit" for binding in policies.bindings):
        observed_comware = platform == "comware" and any(
            binding.purpose == "unknown" for binding in policies.bindings
        )
        warnings.append(ParseIssue(
            code="NO_TRANSIT_ACL", level=ParseIssueLevel.WARNING,
            message=(
                "В файле есть неподтверждённые назначения packet-filter. Подтверждённых транзитных ACL нет."
                if observed_comware else
                "Транзитные ACL в представленном файле не обнаружены; "
                "это не доказательство разрешения всего трафика."
            ),
        ))
    return ParseResult.model_validate({
        **parsed.model_dump(mode="python"), "rules": rules, "endpoints": endpoints, "source_map": source_map,
        "switch_policies": policies, "switch_facts": facts, "warnings": tuple(warnings),
    })
