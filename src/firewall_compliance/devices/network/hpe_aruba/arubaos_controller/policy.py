"""Bounded ArubaOS 8.10 session-ACL declarations; never an effective role evaluator."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from urllib.parse import quote

from firewall_compliance.domain import (
    Configuration,
    DataStatus,
    Endpoint,
    EndpointKind,
    IpRange,
    ParseCoverage,
    ParseIssue,
    ParseIssueLevel,
    ParseResult,
    PortRange,
    Protocol,
    Rule,
    RuleAction,
    Service,
    SourceLocation,
    UnsupportedConstruct,
)
from firewall_compliance.domain.policy_attachment import PolicyAttachment
from firewall_compliance.parsers.contracts import (
    DetectionResult,
    ParseFailure,
    ParseOutcome,
    ParseRequest,
    ParserMetadata,
    SourceDocument,
)

_VERSION = re.compile(r"(?mi)^\s*(?:!\s*)?(?:arubaos\s+)?version\s+8\.10(?:\.\d+){0,3}\s*$")
_MIXED = re.compile(
    r"(?mi)^\s*(?:!\s*)?(?:aruba\s+instant\b|instant\s+version\b|"
    r"arubaos-cx\b|aos-cx\b|arubaos-switch\b|comware\b|"
    r"access-list\s+ip\b|acl\s+number\b|sysname\b|"
    r"version\s+(?!8\.10(?:[.\s]|$))\d)"
)


@dataclass
class _State:
    source: str
    discovered: set[int] = field(default_factory=set)
    rejected: set[int] = field(default_factory=set)
    warnings: list[ParseIssue] = field(default_factory=list)
    unsupported: list[UnsupportedConstruct] = field(default_factory=list)
    source_map: dict[str, SourceLocation] = field(default_factory=dict)

    def location(self, line: int) -> SourceLocation:
        return SourceLocation(source_name=self.source, line_start=line, line_end=line)

    def reject(self, line: int, code: str, message: str) -> None:
        self.discovered.add(line)
        if line in self.rejected:
            return
        self.rejected.add(line)
        location = self.location(line)
        self.warnings.append(
            ParseIssue(
                code=code, level=ParseIssueLevel.WARNING, message=message, source_location=location
            )
        )
        self.unsupported.append(
            UnsupportedConstruct(
                construct_type="controller-declaration", message=message, source_location=location
            )
        )


def _tokens(line: str) -> tuple[str, ...]:
    return tuple(shlex.split(line, comments=False, posix=True))


def _supported(text: str) -> bool:
    return bool(
        _VERSION.search(text)
        and not _MIXED.search(text)
        and re.search(r"(?m)^\s*ip access-list session\s+\S", text)
        and re.search(r"(?m)^\s*user-role\s+\S", text)
    )


class ArubaControllerParser:
    """A separate, conservative declaration inventory for explicit 8.10 exports."""

    _metadata = ParserMetadata(parser_id="aruba-aos-controller", version="0.1.0", vendor="aruba")

    def __init__(
        self,
        *,
        max_bytes: int = 8 * 1024 * 1024,
        max_lines: int = 100000,
        max_objects: int = 4096,
        max_rules: int = 10000,
    ) -> None:
        for value in (max_bytes, max_lines, max_objects, max_rules):
            if type(value) is not int or value < 1:
                raise ValueError("Parser budgets must be positive integers")
        self.max_bytes, self.max_lines = max_bytes, max_lines
        self.max_objects, self.max_rules = max_objects, max_rules

    @property
    def metadata(self) -> ParserMetadata:
        return self._metadata

    def detect(self, source: SourceDocument) -> DetectionResult:
        try:
            matches = len(source.content) <= self.max_bytes and _supported(
                source.content.decode("utf-8-sig")
            )
        except UnicodeError:
            matches = False
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=matches,
            confidence=0.99 if matches else 0,
            reasons=("Explicit 8.10 session ACL/user-role declarations; authenticity unverified.",)
            if matches
            else (),
        )

    def _failure(self, request: ParseRequest, code: str, message: str) -> ParseFailure:
        return ParseFailure(
            parser_id=self.metadata.parser_id,
            source_name=request.source.source_name,
            content_sha256=request.source.content_sha256,
            errors=(ParseIssue(code=code, level=ParseIssueLevel.ERROR, message=message),),
        )

    def parse(self, request: ParseRequest) -> ParseOutcome:
        if len(request.source.content) > self.max_bytes:
            return self._failure(
                request, "CONTROLLER_INPUT_LIMIT", "Превышен лимит размера источника."
            )
        try:
            text = request.source.content.decode("utf-8-sig")
        except UnicodeError:
            return self._failure(request, "CONTROLLER_ENCODING", "Нужен текст UTF-8.")
        if not _supported(text):
            return self._failure(
                request,
                "CONTROLLER_FORMAT",
                "Нужен однозначный export ArubaOS 8.10 session ACL/user-role.",
            )
        lines = text.splitlines()
        if len(lines) > self.max_lines:
            return self._failure(
                request, "CONTROLLER_INPUT_LIMIT", "Превышен лимит строк источника."
            )
        state = _State(request.source.source_name)
        aliases: dict[str, list[tuple[int, tuple[str, ...]]]] = {}
        service_defs: dict[str, tuple[int, tuple[str, ...]]] = {}
        duplicate_objects: set[tuple[str, str]] = set()
        duplicate_acls: set[str] = set()
        acl_names: set[str] = set()
        entries: list[tuple[str, int, tuple[str, ...]]] = []
        bindings: list[PolicyAttachment] = []
        kind, name, hostname = "", "", None
        for number, raw in enumerate(lines, 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("!"):
                if stripped == "!":
                    kind, name = "", ""
                continue
            try:
                tokens = _tokens(stripped)
            except ValueError:
                if kind or stripped.startswith(
                    ("ip access-list session", "netdestination", "netservice", "user-role")
                ):
                    state.reject(
                        number,
                        "CONTROLLER_TOKEN_INVALID",
                        "Повреждённые кавычки; декларация не восстановлена.",
                    )
                    if kind == "acl":
                        entries.append((name, number, ()))
                    elif kind == "alias":
                        aliases[name].append((number, ()))
                continue
            if not tokens:
                continue
            if tokens[0] == "hostname" and len(tokens) == 2:
                hostname = tokens[1]
            header: tuple[str, str] | None = None
            if tokens[:3] == ("ip", "access-list", "session") and len(tokens) == 4:
                header = ("acl", tokens[3])
            elif tokens[0] in {"netdestination", "user-role"} and len(tokens) == 2:
                header = ("alias" if tokens[0] == "netdestination" else "role", tokens[1])
            if header:
                kind, name = header
                if len(name) > 128:
                    return self._failure(
                        request,
                        "CONTROLLER_NAME_LIMIT",
                        "Имя декларации превышает лимит 128 символов.",
                    )
                state.discovered.add(number)
                state.source_map[f"controller-{kind}:{quote(name, safe='')}:{number}"] = (
                    state.location(number)
                )
                if kind == "alias":
                    state.source_map.setdefault(f"controller-alias:{name}", state.location(number))
                    if name in aliases:
                        duplicate_objects.add((kind, name))
                        state.reject(
                            number,
                            "CONTROLLER_DUPLICATE_OBJECT",
                            "Повторное определение адресного alias неоднозначно.",
                        )
                    aliases.setdefault(name, [])
                if kind == "acl":
                    if name in acl_names:
                        duplicate_acls.add(name)
                        state.reject(
                            number,
                            "CONTROLLER_DUPLICATE_ACL",
                            "Повторная ACL не доказывает порядок правил.",
                        )
                    acl_names.add(name)
                continue
            if tokens[0] == "netservice" and len(tokens) >= 2:
                kind, name = "", ""
                state.discovered.add(number)
                service_name = tokens[1]
                if len(service_name) > 128:
                    return self._failure(
                        request,
                        "CONTROLLER_NAME_LIMIT",
                        "Имя сервиса превышает лимит 128 символов.",
                    )
                state.source_map.setdefault(
                    f"controller-service:{service_name}", state.location(number)
                )
                if service_name in service_defs:
                    duplicate_objects.add(("service", service_name))
                    state.reject(
                        number,
                        "CONTROLLER_DUPLICATE_OBJECT",
                        "Повторное определение сервиса неоднозначно.",
                    )
                service_defs[service_name] = (number, tokens[2:])
                state.source_map[f"controller-service:{quote(service_name, safe='')}:{number}"] = (
                    state.location(number)
                )
                continue
            if tokens[0] in {"netdestination", "user-role", "netservice"} or tokens[:3] == (
                "ip",
                "access-list",
                "session",
            ):
                state.reject(
                    number,
                    "CONTROLLER_HEADER_INVALID",
                    "Повреждённый заголовок декларации; область не восстановлена.",
                )
                kind, name = "", ""
                continue
            if kind == "alias":
                state.discovered.add(number)
                state.source_map[f"controller-alias-member:{quote(name, safe='')}:{number}"] = (
                    state.location(number)
                )
                aliases[name].append((number, tokens))
            elif kind == "acl":
                state.discovered.add(number)
                if tokens[0] == "description":
                    state.source_map[
                        f"controller-acl-description:{quote(name, safe='')}:{number}"
                    ] = state.location(number)
                else:
                    entries.append((name, number, tokens))
            elif kind == "role":
                state.discovered.add(number)
                try:
                    binding = _binding(name, tokens, state.location(number))
                except ValueError:
                    state.reject(
                        number,
                        "CONTROLLER_ROLE_UNSUPPORTED",
                        "Настройка роли не является поддержанной session ACL привязкой.",
                    )
                else:
                    bindings.append(binding)
            if len(aliases) + len(service_defs) > self.max_objects or len(entries) > self.max_rules:
                return self._failure(
                    request,
                    "CONTROLLER_CONSTRUCT_LIMIT",
                    "Превышен лимит объектов или правил; частичный успех не заявляется.",
                )
        if (
            len(aliases) + len(service_defs) + len(acl_names) > self.max_objects
            or len(entries) > self.max_rules
        ):
            return self._failure(
                request, "CONTROLLER_CONSTRUCT_LIMIT", "Превышен лимит деклараций."
            )
        if not acl_names:
            return self._failure(
                request, "CONTROLLER_FORMAT", "Нет корректного заголовка session ACL."
            )
        configuration = Configuration(
            source_name=request.source.source_name,
            device_id=hostname or f"aruba-controller:{request.source.content_sha256[:16]}",
            vendor=self.metadata.vendor,
            platform="arubaos-controller-8.10",
            parser_version=self.metadata.version,
            content_sha256=request.source.content_sha256,
            captured_at=request.source.captured_at,
            imported_at=request.imported_at,
        )
        endpoints: dict[str, Endpoint] = {}
        for alias, members in aliases.items():
            try:
                if ("alias", alias) in duplicate_objects:
                    raise ValueError("duplicate alias")
                endpoints[alias] = _alias(alias, members)
            except ValueError:
                endpoints[alias] = _unknown_endpoint(alias)
                if not members:
                    header_line = state.source_map[f"controller-alias:{alias}"].line_start or 1
                    state.reject(
                        header_line,
                        "CONTROLLER_ALIAS_UNSUPPORTED",
                        "Пустой alias не доказывает ANY или отсутствие адресов.",
                    )
                for line, _ in members:
                    state.reject(
                        line,
                        "CONTROLLER_ALIAS_UNSUPPORTED",
                        "Alias содержит неизвестное/динамическое условие; весь alias неизвестен.",
                    )
        services: dict[str, Service] = {}
        for service_name, (number, values) in service_defs.items():
            try:
                if ("service", service_name) in duplicate_objects:
                    raise ValueError("duplicate service")
                if not values or values[0] not in {"tcp", "udp", "1"}:
                    raise ValueError("unsupported netservice grammar")
                services[service_name] = _service(service_name, values)
            except ValueError:
                services[service_name] = _unknown_service(service_name)
                state.reject(
                    number,
                    "CONTROLLER_SERVICE_UNSUPPORTED",
                    "Сервис содержит неподдержанные или неоднозначные условия.",
                )
        rules = []
        sequences: dict[str, int] = {}
        for acl, number, tokens in entries:
            sequences[acl] = sequences.get(acl, 0) + 1
            rule = _rule(
                configuration,
                acl,
                number,
                sequences[acl],
                tokens,
                endpoints,
                services,
                state,
                acl in duplicate_acls,
            )
            rules.append(rule)
            state.source_map[rule.rule_id] = rule.source_location
        for binding in bindings:
            state.source_map[binding.attachment_id] = binding.source_location
            if binding.policy_id.removeprefix("controller-session:") not in acl_names:
                state.reject(
                    binding.source_location.line_start or 1,
                    "CONTROLLER_BINDING_WITHOUT_ACL",
                    "Роль ссылается на отсутствующую в источнике ACL.",
                )
        all_endpoints = {value.endpoint_id: value for value in endpoints.values()}
        all_services = {value.service_id: value for value in services.values()}
        for rule in rules:
            all_endpoints.update(
                (value.endpoint_id, value) for value in (*rule.sources, *rule.destinations)
            )
            all_services.update((value.service_id, value) for value in rule.services)
        scope = ParseIssue(
            code="CONTROLLER_DECLARATIONS_ONLY",
            level=ParseIssueLevel.WARNING,
            message=(
                "Только заданные IPv4 session ACL/alias/service и привязки ролей. "
                "Эффективный порядок роли, runtime user addresses, stateful, NAT "
                "и путь не вычислены."
            ),
            source_location=state.location(1),
        )
        return ParseResult(
            configuration=configuration,
            rules=tuple(rules),
            policy_attachments=tuple(bindings),
            endpoints=tuple(all_endpoints.values()),
            services=tuple(all_services.values()),
            warnings=(scope, *state.warnings),
            unsupported_constructs=tuple(state.unsupported),
            source_map=state.source_map,
            coverage=ParseCoverage(
                discovered_constructs=len(state.discovered),
                recognized_constructs=len(state.discovered - state.rejected),
                unsupported_constructs=len(state.rejected),
            ),
        )


def _unknown_endpoint(name: str) -> Endpoint:
    return Endpoint(
        endpoint_id=f"controller-alias:{name}",
        name=name,
        kind=EndpointKind.OBJECT,
        resolution_status=DataStatus.UNSUPPORTED,
    )


def _unknown_service(name: str) -> Service:
    return Service(
        service_id=f"controller-service:{name}",
        name=name,
        protocol=Protocol.OTHER,
        resolution_status=DataStatus.UNSUPPORTED,
    )


def _network(values: tuple[str, ...]) -> str:
    if len(values) == 1:
        if "/" not in values[0]:
            raise ValueError("network needs prefix or mask")
        return str(IPv4Network(values[0], strict=False))
    if len(values) == 2:
        # Aruba uses a netmask, never a Cisco ACL wildcard mask.
        mask = IPv4Address(values[1])
        bits = f"{int(mask):032b}"
        if "01" in bits:
            raise ValueError("noncontiguous netmask")
        return str(IPv4Network(f"{values[0]}/{bits.count('1')}", strict=False))
    raise ValueError("invalid network")


def _alias(name: str, members: list[tuple[int, tuple[str, ...]]]) -> Endpoint:
    cidrs: list[str] = []
    ranges: list[IpRange] = []
    for _, values in members:
        if values[:1] == ("host",) and len(values) == 2:
            cidrs.append(f"{IPv4Address(values[1])}/32")
        elif values[:1] == ("network",):
            cidrs.append(_network(values[1:]))
        elif values[:1] == ("range",) and len(values) == 3:
            first, last = IPv4Address(values[1]), IPv4Address(values[2])
            if int(last) - int(first) > 15:
                raise ValueError("vendor range limit")
            ranges.append(IpRange(start=str(first), end=str(last)))
        elif values[:1] != ("description",):
            raise ValueError("unsupported alias member")
    if not cidrs and not ranges:
        raise ValueError("empty alias not ANY")
    return Endpoint(
        endpoint_id=f"controller-alias:{name}",
        name=name,
        kind=EndpointKind.GROUP,
        cidrs=tuple(cidrs),
        ip_ranges=tuple(ranges),
    )


def _service(name: str, values: tuple[str, ...]) -> Service:
    ranges: tuple[PortRange, ...]
    if values == ("any",):
        protocol, ranges = Protocol.IP, ()
    elif values in {("icmp",), ("1",)}:
        protocol, ranges = Protocol.ICMP, ()
    elif values and values[0] in {"tcp", "udp"}:
        protocol = Protocol(values[0])
        ports = values[1:]
        if len(ports) == 2 and ports[0] == "list":
            numbers = ports[1].split(",")
            if not 1 <= len(numbers) <= 6:
                raise ValueError("invalid port list")
            ranges = tuple(PortRange(start=int(value), end=int(value)) for value in numbers)
        elif len(ports) in {1, 2}:
            ranges = (PortRange(start=int(ports[0]), end=int(ports[-1])),)
        else:
            raise ValueError("explicit ports required")
    else:
        raise ValueError("unsupported protocol/service")
    return Service(
        service_id=f"controller-service:{name}", name=name, protocol=protocol, port_ranges=ranges
    )


def _endpoint(
    tokens: tuple[str, ...], aliases: dict[str, Endpoint]
) -> tuple[Endpoint, tuple[str, ...]]:
    if not tokens:
        raise ValueError("missing endpoint")
    word = tokens[0]
    if word == "any":
        return Endpoint(
            endpoint_id="controller:any:ipv4",
            name="any (IPv4)",
            kind=EndpointKind.SUBNET,
            cidrs=("0.0.0.0/0",),
        ), tokens[1:]
    if word == "alias" and len(tokens) >= 2:
        return aliases.get(tokens[1], _unknown_endpoint(tokens[1])), tokens[2:]
    if word == "host" and len(tokens) >= 2:
        value = str(IPv4Address(tokens[1]))
        return Endpoint(
            endpoint_id=f"controller-host:{value}",
            name=value,
            kind=EndpointKind.HOST,
            cidrs=(f"{value}/32",),
        ), tokens[2:]
    if word == "network" and len(tokens) >= 2:
        count = 1 if "/" in tokens[1] else 2
        value = _network(tokens[1 : 1 + count])
        return Endpoint(
            endpoint_id=f"controller-network:{value}",
            name=value,
            kind=EndpointKind.SUBNET,
            cidrs=(value,),
        ), tokens[1 + count :]
    raise ValueError("dynamic/unknown endpoint")


def _rule(
    config: Configuration,
    acl: str,
    line: int,
    sequence: int,
    tokens: tuple[str, ...],
    aliases: dict[str, Endpoint],
    services: dict[str, Service],
    state: _State,
    duplicate: bool,
) -> Rule:
    location = state.location(line)
    rule_id = f"controller-rule:{quote(acl, safe='')}:{line}"
    sources: tuple[Endpoint, ...] = ()
    destinations: tuple[Endpoint, ...] = ()
    selected_services: tuple[Service, ...] = ()
    action = RuleAction.UNKNOWN
    logging = None
    known = False
    try:
        source, rest = _endpoint(tokens, aliases)
        sources = (source,)
        destination, rest = _endpoint(rest, aliases)
        destinations = (destination,)
        action_indexes = [index for index, word in enumerate(rest) if word in {"permit", "deny"}]
        if len(action_indexes) != 1:
            raise ValueError("unknown action")
        index = action_indexes[0]
        service_tokens, action_tokens = rest[:index], rest[index:]
        action = RuleAction.ALLOW if action_tokens[0] == "permit" else RuleAction.DENY
        if service_tokens and service_tokens[0] in {"tcp", "udp"} and len(service_tokens) != 2:
            raise ValueError("inline service requires one destination port")
        if len(service_tokens) == 1 and service_tokens[0] not in {"any", "icmp", "1"}:
            service = services.get(service_tokens[0], _unknown_service(service_tokens[0]))
        else:
            service = _service(" ".join(service_tokens), service_tokens)
        selected_services = (service,)
        if action_tokens[1:] not in {(), ("log",)}:
            raise ValueError("unsupported extended condition/action")
        logging = action_tokens[1:] == ("log",)
        known = not duplicate and all(
            value.resolution_status == DataStatus.KNOWN for value in (source, destination, service)
        )
        if not known:
            raise ValueError("unknown resolved condition or order")
    except (ValueError, IndexError):
        state.reject(
            line,
            "CONTROLLER_RULE_UNSUPPORTED",
            "Условие/действие session ACL не полностью представимо; unknown не заменяется ANY.",
        )
    return Rule(
        rule_id=rule_id,
        configuration_id=config.configuration_id,
        name=f"{acl} #{sequence}",
        sequence=sequence,
        action=action,
        enabled=True,
        sources=sources,
        destinations=destinations,
        services=selected_services,
        policy_id=f"controller-session:{acl}",
        policy_semantics=None,
        source_location=location,
        match_status=DataStatus.KNOWN if known else DataStatus.UNSUPPORTED,
        source_status=DataStatus.KNOWN
        if sources and sources[0].resolution_status == DataStatus.KNOWN
        else DataStatus.UNSUPPORTED,
        destination_status=DataStatus.KNOWN
        if destinations and destinations[0].resolution_status == DataStatus.KNOWN
        else DataStatus.UNSUPPORTED,
        service_status=DataStatus.KNOWN
        if selected_services and selected_services[0].resolution_status == DataStatus.KNOWN
        else DataStatus.UNSUPPORTED,
        logging_enabled=logging if known else None,
        logging_status=DataStatus.KNOWN if known else DataStatus.UNKNOWN,
    )


def _binding(role: str, tokens: tuple[str, ...], location: SourceLocation) -> PolicyAttachment:
    if tokens[:2] == ("access-list", "session"):
        rest = tokens[2:]
    elif tokens[:1] == ("session-acl",):
        rest = tokens[1:]
    else:
        raise ValueError("unsupported role attribute")
    if not rest:
        raise ValueError("missing ACL")
    acl, tail = rest[0], rest[1:]
    position, ap_group = None, None
    if tail[:1] == ("ap-group",) and len(tail) >= 2:
        ap_group, tail = tail[1], tail[2:]
    if tail[:1] == ("position",) and len(tail) == 2:
        position, tail = int(tail[1]), ()
    if tail:
        raise ValueError("unsupported attachment qualifier")
    if position is not None and position < 1:
        raise ValueError("attachment position starts at one")
    return PolicyAttachment(
        attachment_id=f"controller-attachment:{location.line_start}",
        policy_id=f"controller-session:{acl}",
        subject_kind="user_role",
        subject_id=role,
        declaration_position=position,
        scope_reference=f"ap-group:{ap_group}" if ap_group is not None else None,
        source_location=location,
    )
