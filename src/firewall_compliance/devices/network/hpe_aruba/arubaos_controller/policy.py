"""Общая грамматика ArubaOS Controller 8.x, отдельно от оценки роли."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
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

_VERSION = re.compile(
    r"(?mi)^\s*(?:!\s*)?(?:arubaos\s+)?version\s+(8\.\d+)(?:\.\d+){0,3}\s*$"
)
_MIXED = re.compile(
    r"(?mi)^\s*(?:!\s*)?(?:aruba\s+instant\b|instant\s+version\b|"
    r"arubaos-cx\b|aos-cx\b|arubaos-switch\b|comware\b|"
    r"access-list\s+ip\b|acl\s+number\b|sysname\b|"
    r"version\s+(?!8\.\d+(?:[.\s]|$))\d)"
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
    from firewall_compliance.parsers.platform_detection import detect_switch_platform

    detected = detect_switch_platform(text)
    return bool(
        _VERSION.search(text) and not _MIXED.search(text)
        and detected.platform == "arubaos-controller" and not detected.ambiguous
    )


class ArubaControllerParser:
    """Импорт объявлений IPv4/IPv6, с проверенными профилями 8.6 и 8.10."""

    _metadata = ParserMetadata(parser_id="aruba-aos-controller", version="0.2.0", vendor="aruba")

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
            reasons=("ArubaOS Controller 8.x; подлинность и полнота источника не подтверждены.",)
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
                "Нужен однозначный export ArubaOS Controller 8.x.",
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
        role_names: set[str] = set()
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
            elif (
                tokens[0] in {"netdestination", "netdestination6", "user-role"}
                and len(tokens) == 2
            ):
                family_name = "ipv6:" + tokens[1] if tokens[0] == "netdestination6" else tokens[1]
                header = ("alias" if tokens[0] != "user-role" else "role", family_name)
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
                if kind == "role":
                    if name in role_names:
                        state.reject(
                            number, "CONTROLLER_DUPLICATE_ROLE",
                            "Повторная роль не доказывает порядок её ACL и настройки.",
                        )
                    role_names.add(name)
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
            if (
                tokens[0] in {"netdestination", "netdestination6", "user-role", "netservice"}
                or tokens[:3] == ("ip", "access-list", "session")
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
                    # Настройки VLAN/AAA/QoS роли извлекает отдельный inventory parser.
                    if (
                        tokens[:2] == ("access-list", "session")
                        or tokens[:1] in {("session-acl",), ("ipv6",)}
                    ):
                        state.reject(
                            number, "CONTROLLER_ROLE_UNSUPPORTED",
                            "Привязка session ACL не разобрана.",
                        )
                else:
                    bindings.append(binding)
            if (
                len(aliases) + len(service_defs) > self.max_objects
                or len(entries) > self.max_rules
                or len(bindings) > min(self.max_rules, 10000)
            ):
                return self._failure(
                    request,
                    "CONTROLLER_CONSTRUCT_LIMIT",
                    "Превышен лимит объектов или правил; частичный успех не заявляется.",
                )
        if (
            len(aliases) + len(service_defs) + len(acl_names) + len(role_names) > self.max_objects
            or len(entries) > self.max_rules
        ):
            return self._failure(
                request, "CONTROLLER_CONSTRUCT_LIMIT", "Превышен лимит деклараций."
            )
        version_match = _VERSION.search(text)
        assert version_match is not None
        if version_match[1] not in {"8.6", "8.10"}:
            state.warnings.append(ParseIssue(
                code="CONTROLLER_VERSION_UNVERIFIED", level=ParseIssueLevel.WARNING,
                message="Общая грамматика AOS 8.x; особенности этого minor не подтверждены. "
                "Проверенные профили: 8.6 и 8.10. Эффективная политика не заявляется.",
                source_location=state.location(1),
            ))
        configuration = Configuration(
            source_name=request.source.source_name,
            device_id=hostname or f"aruba-controller:{request.source.content_sha256[:16]}",
            vendor=self.metadata.vendor,
            platform=f"arubaos-controller-{version_match[1]}",
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
                if endpoints[alias].resolution_status != DataStatus.KNOWN:
                    for line, values in members:
                        if (
                            values[:1] in {("name",), ("invert",)}
                            or values[:2] == ("host", "vlan")
                        ):
                            state.warnings.append(ParseIssue(
                                code="CONTROLLER_ALIAS_DYNAMIC", level=ParseIssueLevel.WARNING,
                                message="Сохранён статический состав; DNS, инверсия или VLAN-offset "
                                "требуют отдельного контекста и не превращены в ANY.",
                                source_location=state.location(line),
                            ))
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
                "Объявления IPv4/IPv6 session ACL/alias/service и привязки ролей. "
                "Эффективный порядок роли, runtime user addresses, stateful, NAT "
                "и путь не вычислены."
            ),
            source_location=state.location(1),
        )
        result = ParseResult(
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
        from firewall_compliance.parsers.controller_inventory import parse_controller_inventory

        inventory = parse_controller_inventory(request.source, result)
        return ParseResult.model_validate({
            **result.model_dump(mode="python"), "controller_inventory": inventory,
        })


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
        return str(ip_network(values[0], strict=False))
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
    dynamic: list[str] = []
    description: str | None = None
    family = 6 if name.startswith("ipv6:") else 4
    uncertain = False
    for _, values in members:
        if values[:1] == ("host",) and len(values) == 2:
            address = ip_address(values[1])
            if address.version != family:
                raise ValueError("address family mismatch")
            cidrs.append(f"{address}/{128 if family == 6 else 32}")
        elif values[:1] == ("network",):
            network = _network(values[1:])
            if ip_network(network).version != family:
                raise ValueError("address family mismatch")
            cidrs.append(network)
        elif values[:1] == ("range",) and len(values) == 3:
            first, last = ip_address(values[1]), ip_address(values[2])
            if first.version != family or last.version != family:
                raise ValueError("address family mismatch")
            if int(last) - int(first) > 15:
                raise ValueError("vendor range limit")
            ranges.append(IpRange(start=str(first), end=str(last)))
        elif values[:1] == ("description",):
            description = " ".join(values[1:])
        elif values[:1] == ("name",) and len(values) == 2:
            dynamic.append(values[1])
            uncertain = True
        elif values[:1] == ("invert",) or values[:2] == ("host", "vlan"):
            # Инверсия нескольких элементов не равна простому дополнению их объединения.
            uncertain = True
        else:
            raise ValueError("unsupported alias member")
    if not cidrs and not ranges and not dynamic and not uncertain:
        raise ValueError("empty alias not ANY")
    return Endpoint(
        endpoint_id=f"controller-alias:{name}",
        name=name,
        kind=EndpointKind.GROUP,
        cidrs=tuple(cidrs),
        ip_ranges=tuple(ranges),
        description=description,
        resolution_status=DataStatus.UNKNOWN if uncertain else DataStatus.KNOWN,
    )


def _service(name: str, values: tuple[str, ...]) -> Service:
    alg: str | None = None
    if "alg" in values:
        index = values.index("alg")
        if len(values) != index + 2:
            raise ValueError("invalid ALG")
        alg, values = values[-1], values[:index]
        if alg not in {
            "dhcp", "dns", "facetime", "ftp", "h323", "jabber", "noe", "rtsp",
            "sccp", "sip", "sips", "svp", "tftp", "vocera",
        }:
            raise ValueError("unsupported ALG")
    elif values and values[-1] in {"http-proxy", "https-proxy"}:
        alg, values = values[-1], values[:-1]
    ranges: tuple[PortRange, ...]
    source_ranges: tuple[PortRange, ...] = ()
    protocol_number: int | None = None
    if values == ("any",):
        protocol, ranges = Protocol.IP, ()
    elif values in {("icmp",), ("1",)}:
        protocol, ranges = Protocol.ICMP, ()
    elif values and values[0] in {"tcp", "udp"}:
        protocol = Protocol(values[0])
        ports = values[1:]
        if ports[:1] == ("source",):
            source_tokens = ports[1:]
            if "destination" in source_tokens:
                split = source_tokens.index("destination")
                source_tokens, ports = source_tokens[:split], source_tokens[split + 1:]
            elif len(source_tokens) <= 2:
                ports = ()
            elif len(source_tokens) in {3, 4}:
                source_tokens, ports = source_tokens[:2], source_tokens[2:]
            else:
                raise ValueError("ambiguous source ports")
            if not 1 <= len(source_tokens) <= 2:
                raise ValueError("missing source ports")
            source_ranges = (
                PortRange(start=int(source_tokens[0]), end=int(source_tokens[-1])),
            )
        if len(ports) == 2 and ports[0] == "list":
            numbers = re.split(r"[,\s]+", ports[1].strip())
            if not 1 <= len(numbers) <= 6:
                raise ValueError("invalid port list")
            ranges = tuple(PortRange(start=int(value), end=int(value)) for value in numbers)
        elif len(ports) in {1, 2}:
            ranges = (PortRange(start=int(ports[0]), end=int(ports[-1])),)
        elif not ports and source_ranges:
            ranges = ()
        else:
            raise ValueError("explicit ports required")
    elif len(values) == 1 and values[0].isdigit() and 0 <= int(values[0]) <= 255:
        protocol_number, ranges = int(values[0]), ()
        protocol = Protocol.OTHER
    elif values in {("icmpv6",), ("ipv6-icmp",)}:
        protocol_number, protocol, ranges = 58, Protocol.OTHER, ()
    else:
        raise ValueError("unsupported protocol/service")
    return Service(
        service_id=f"controller-service:{name}", name=name, protocol=protocol, port_ranges=ranges,
        source_port_ranges=source_ranges, protocol_number=protocol_number, alg=alg,
    )


def _endpoint(
    tokens: tuple[str, ...], aliases: dict[str, Endpoint], family: int = 4,
) -> tuple[Endpoint, tuple[str, ...]]:
    if not tokens:
        raise ValueError("missing endpoint")
    word = tokens[0]
    if word == "any":
        return Endpoint(
            endpoint_id=f"controller:any:ipv{family}",
            name=f"any (IPv{family})",
            kind=EndpointKind.SUBNET,
            cidrs=("::/0" if family == 6 else "0.0.0.0/0",),
        ), tokens[1:]
    if word == "alias" and len(tokens) >= 2:
        alias_name = "ipv6:" + tokens[1] if family == 6 else tokens[1]
        return aliases.get(alias_name, _unknown_endpoint(alias_name)), tokens[2:]
    if word == "host" and len(tokens) >= 2:
        address = ip_address(tokens[1])
        if address.version != family:
            raise ValueError("address family mismatch")
        value = str(address)
        return Endpoint(
            endpoint_id=f"controller-host:{value}",
            name=value,
            kind=EndpointKind.HOST,
            cidrs=(f"{value}/{128 if family == 6 else 32}",),
        ), tokens[2:]
    if word == "network" and len(tokens) >= 2:
        count = 1 if "/" in tokens[1] else 2
        value = _network(tokens[1 : 1 + count])
        if ip_network(value).version != family:
            raise ValueError("address family mismatch")
        return Endpoint(
            endpoint_id=f"controller-network:{value}",
            name=value,
            kind=EndpointKind.SUBNET,
            cidrs=(value,),
        ), tokens[1 + count :]
    if word in {"user", "localip", "userrole"}:
        size = 2 if word == "userrole" and len(tokens) >= 2 else 1
        return Endpoint(
            endpoint_id=f"controller-dynamic:ipv{family}:" + ":".join(tokens[:size]),
            name=" ".join(tokens[:size]), kind=EndpointKind.OBJECT,
            resolution_status=DataStatus.UNKNOWN,
        ), tokens[size:]
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
    syntax_known = False
    try:
        family = 6 if tokens[:1] == ("ipv6",) else 4
        if family == 6:
            tokens = tokens[1:]
        source, rest = _endpoint(tokens, aliases, family)
        sources = (source,)
        destination, rest = _endpoint(rest, aliases, family)
        destinations = (destination,)
        action_indexes = [index for index, word in enumerate(rest) if word in {"permit", "deny"}]
        if len(action_indexes) != 1:
            raise ValueError("unknown action")
        index = action_indexes[0]
        service_tokens, action_tokens = rest[:index], rest[index:]
        action = RuleAction.ALLOW if action_tokens[0] == "permit" else RuleAction.DENY
        if (
            len(service_tokens) == 1
            and service_tokens[0] not in {"any", "icmp", "icmpv6", "ipv6-icmp"}
            and not service_tokens[0].isdigit()
        ):
            service = services.get(service_tokens[0], _unknown_service(service_tokens[0]))
        else:
            service = _service(" ".join(service_tokens), service_tokens)
        selected_services = (service,)
        extra = action_tokens[1:]
        logging = "log" in extra
        conditional = False
        while extra:
            if extra[0] in {"log", "mirror"}:
                extra = extra[1:]
            elif len(extra) >= 2 and extra[0] == "queue" and extra[1] in {"high", "low"}:
                extra = extra[2:]
            elif (
                len(extra) >= 2 and extra[0] in {"tos", "dot1p-priority"}
                and extra[1].isdigit()
            ):
                extra = extra[2:]
            elif len(extra) >= 2 and extra[0] == "time-range":
                conditional = True
                extra = extra[2:]
            else:
                raise ValueError("conditional or unsupported extended action")
        if duplicate:
            raise ValueError("duplicate ACL order")
        if any(
            value.resolution_status == DataStatus.UNSUPPORTED
            for value in (source, destination, service)
        ):
            raise ValueError("unresolved object declaration")
        syntax_known = True
        known = not conditional and all(
            value.resolution_status == DataStatus.KNOWN for value in (source, destination, service)
        )
        if not known:
            state.warnings.append(ParseIssue(
                code="CONTROLLER_DYNAMIC_CONDITION", level=ParseIssueLevel.WARNING,
                message="Условие требует адреса пользователя, DNS, времени или иного контекста; "
                "оно сохранено без замены на ANY.", source_location=location,
            ))
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
        policy_id=f"controller-session:{acl}", policy_purpose="unknown",
        policy_semantics=None,
        source_location=location,
        match_status=DataStatus.KNOWN if known else (
            DataStatus.UNKNOWN if syntax_known else DataStatus.UNSUPPORTED
        ),
        source_status=sources[0].resolution_status if sources else DataStatus.UNSUPPORTED,
        destination_status=(
            destinations[0].resolution_status if destinations else DataStatus.UNSUPPORTED
        ),
        service_status=(
            selected_services[0].resolution_status if selected_services else DataStatus.UNSUPPORTED
        ),
        logging_enabled=logging if syntax_known else None,
        logging_status=DataStatus.KNOWN if syntax_known else DataStatus.UNKNOWN,
    )


def _binding(role: str, tokens: tuple[str, ...], location: SourceLocation) -> PolicyAttachment:
    family = "ipv6" if tokens[:1] == ("ipv6",) else None
    if family:
        tokens = tokens[1:]
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
        scope_reference=(f"ap-group:{ap_group}" if ap_group is not None else family),
        source_location=location,
    )
