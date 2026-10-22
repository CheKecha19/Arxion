"""Ограниченный parser adapter текстовых ACL Cisco ASA 9.16."""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import ip_address, ip_network
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.domain import (
    Configuration,
    DataStatus,
    Endpoint,
    EndpointKind,
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
from firewall_compliance.parsers.contracts import (
    DetectionResult,
    ParseFailure,
    ParseOutcome,
    ParseRequest,
    ParserMetadata,
    SourceDocument,
)

type _AccessBinding = tuple[str | None, Literal["in", "out"] | None]


class CiscoAsaParser:
    """Преобразует ограниченный набор ACL Cisco ASA 9.16 в каноническую модель."""

    _metadata = ParserMetadata(parser_id="cisco-asa-9.16", version="0.2.0", vendor="cisco")
    _named_ports = {"domain": 53, "http": 80, "https": 443, "ntp": 123, "ssh": 22}

    @property
    def metadata(self) -> ParserMetadata:
        """Вернуть идентичность и версию адаптера."""
        return self._metadata

    def detect(self, source: SourceDocument) -> DetectionResult:
        """Распознать характерные директивы Cisco ASA без изменения документа."""
        try:
            lines = tuple(self._lines(source.content))
        except UnicodeDecodeError:
            return DetectionResult(
                parser_id=self.metadata.parser_id, is_match=False, confidence=0.0
            )
        has_access_list = any(line.split()[0] == "access-list" for _, line in lines)
        has_asa_context = any(
            line.split()[0] in {"access-group", "nat"}
            or line.split()[:2] in (["object", "network"], ["object", "service"])
            for _, line in lines
        )
        is_match = has_access_list and has_asa_context
        reasons = ("Обнаружены директивы access-list и Cisco ASA context.",) if is_match else ()
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=is_match,
            confidence=0.95 if is_match else 0.0,
            reasons=reasons,
        )

    def parse(self, request: ParseRequest) -> ParseOutcome:
        """Разобрать поддерживаемые ACL и вернуть диагностику ограничений формата."""
        try:
            lines = tuple(self._lines(request.source.content))
        except UnicodeDecodeError:
            return ParseFailure(
                parser_id=self.metadata.parser_id,
                source_name=request.source.source_name,
                content_sha256=request.source.content_sha256,
                errors=(
                    ParseIssue(
                        code="INVALID_ENCODING",
                        level=ParseIssueLevel.ERROR,
                        message="Конфигурация должна быть в UTF-8.",
                    ),
                ),
            )
        if not self.detect(request.source).is_match:
            return ParseFailure(
                parser_id=self.metadata.parser_id,
                source_name=request.source.source_name,
                content_sha256=request.source.content_sha256,
                errors=(
                    ParseIssue(
                        code="FORMAT_NOT_RECOGNIZED",
                        level=ParseIssueLevel.ERROR,
                        message="Документ не соответствует ограниченному формату Cisco ASA 9.16.",
                    ),
                ),
            )

        networks, services, groups, service_groups, discovered, object_issues = self._parse_objects(
            tuple(self._lines(request.source.content, preserve_indent=True)),
            request.source.source_name,
        )
        access_groups = self._parse_access_groups(lines)
        rules: list[Rule] = []
        warnings: list[ParseIssue] = list(object_issues)
        unsupported: list[UnsupportedConstruct] = []
        remarks: dict[str, list[str]] = {}

        configuration = self._configuration(request, self._hostname(lines))
        for line_number, line in lines:
            tokens = line.split()
            if tokens[0] == "access-list":
                discovered += 1
                if len(tokens) >= 3 and tokens[2] == "remark":
                    remark = line.split(maxsplit=3)[3] if len(tokens) > 3 else ""
                    remarks.setdefault(tokens[1], []).append(remark)
                    if not remark:
                        warnings.append(
                            self._issue(
                                "UNSUPPORTED_ACCESS_LIST", line_number, configuration.source_name
                            )
                        )
                    continue
                pending = remarks.pop(tokens[1], []) if len(tokens) > 1 else []
                description = "\n".join(pending) or None
                description_status = (
                    DataStatus.UNKNOWN
                    if pending and not all(pending)
                    else DataStatus.KNOWN
                    if description
                    else DataStatus.ABSENT
                )
                try:
                    parsed = self._parse_rule(
                        line_number,
                        line,
                        configuration,
                        networks,
                        services,
                        groups,
                        service_groups,
                        access_groups,
                        description,
                        description_status,
                    )
                except (ValueError, IndexError):
                    parsed = self._issue(
                        "UNSUPPORTED_ACCESS_LIST", line_number, configuration.source_name
                    )
                if isinstance(parsed, Rule):
                    rules.append(parsed)
                elif parsed is not None:
                    warnings.append(parsed)
            elif tokens[0] == "nat":
                discovered += 1
                location = SourceLocation(
                    source_name=request.source.source_name, line_start=line_number
                )
                unsupported.append(
                    UnsupportedConstruct(
                        construct_type="nat",
                        message="NAT не входит в первый срез Cisco ASA parser adapter.",
                        source_location=location,
                    )
                )
                warnings.append(
                    ParseIssue(
                        code="UNSUPPORTED_NAT",
                        level=ParseIssueLevel.WARNING,
                        message="NAT сохранён как неподдержанная конструкция.",
                        source_location=location,
                    )
                )

        unsupported.extend(
            UnsupportedConstruct(
                construct_type="access-list"
                if issue.code == "UNSUPPORTED_ACCESS_LIST"
                else "object",
                message=issue.message,
                source_location=issue.source_location,
            )
            for issue in warnings
            if issue.code != "UNSUPPORTED_NAT" and issue.source_location is not None
        )
        source_map = {rule.rule_id: rule.source_location for rule in rules}
        endpoints = self._unique_endpoints(
            endpoint for rule in rules for endpoint in (*rule.sources, *rule.destinations)
        )
        parsed_services = self._unique_services(
            service for rule in rules for service in rule.services
        )
        return ParseResult(
            configuration=configuration,
            rules=tuple(rules),
            endpoints=endpoints,
            services=parsed_services,
            warnings=tuple(warnings),
            unsupported_constructs=tuple(unsupported),
            source_map=source_map,
            coverage=ParseCoverage(
                discovered_constructs=discovered,
                recognized_constructs=discovered - len(unsupported),
                unsupported_constructs=len(unsupported),
            ),
        )

    @staticmethod
    def _lines(content: bytes, preserve_indent: bool = False) -> Iterable[tuple[int, str]]:
        for line_number, raw_line in enumerate(content.decode("utf-8").splitlines(), start=1):
            line = raw_line.strip()
            if line and not line.startswith("!"):
                yield line_number, raw_line.rstrip() if preserve_indent else line

    @staticmethod
    def _issue(code: str, line_number: int, source_name: str) -> ParseIssue:
        return ParseIssue(
            code=code,
            level=ParseIssueLevel.WARNING,
            message="Конструкция неполна или не поддерживается; её семантика не расширяется.",
            source_location=SourceLocation(source_name=source_name, line_start=line_number),
        )

    def _parse_objects(
        self, lines: tuple[tuple[int, str], ...], source_name: str
    ) -> tuple[
        dict[str, Endpoint],
        dict[str, Service],
        dict[str, Endpoint],
        dict[str, Service],
        int,
        tuple[ParseIssue, ...],
    ]:
        networks: dict[str, Endpoint] = {}
        services: dict[str, Service] = {}
        groups: dict[str, Endpoint] = {}
        service_groups: dict[str, Service] = {}
        discovered = 0
        issues: list[ParseIssue] = []
        blocks: list[tuple[int, list[str], list[str]]] = []
        index = 0
        while index < len(lines):
            line_number, line = lines[index]
            tokens = line.split()
            if tokens[0] not in {"object", "object-group"}:
                index += 1
                continue
            discovered += 1
            body: list[str] = []
            index += 1
            while index < len(lines):
                child = lines[index][1]
                if not child[0].isspace() and child.split()[0] not in {
                    "host",
                    "subnet",
                    "range",
                    "fqdn",
                    "description",
                    "service",
                    "network-object",
                    "service-object",
                    "port-object",
                    "group-object",
                }:
                    break
                body.append(child.strip())
                index += 1
            blocks.append((line_number, tokens, body))

        # Сначала объекты, затем группы: forward references не теряют членов.
        for line_number, tokens, body in sorted(blocks, key=lambda block: block[1][0] != "object"):
            try:
                if len(tokens) < 3 or tokens[1] not in {"network", "service"}:
                    raise ValueError("unsupported object header")
                name = tokens[2]
                values = [value for value in body if value.split()[0] != "description"]
                if tokens[:2] == ["object", "network"]:
                    values = [value for value in values if not value.startswith("nat ")]
                    endpoint = self._network_object(name, values[0]) if len(values) == 1 else None
                    if len(tokens) != 3 or name in networks or endpoint is None:
                        raise ValueError("invalid network object")
                    networks[name] = endpoint
                    if endpoint.resolution_status != DataStatus.KNOWN:
                        raise ValueError("unsupported network object")
                elif tokens[:2] == ["object", "service"]:
                    if len(tokens) != 3 or name in services or len(values) != 1:
                        raise ValueError("invalid service object")
                    service = self._service_from_object(name, values[0])
                    if service is None:
                        raise ValueError("missing service")
                    services[name] = service
                elif tokens[:2] == ["object-group", "network"]:
                    if len(tokens) != 3 or name in groups or not values:
                        raise ValueError("invalid network group")
                    cidrs: list[str] = []
                    for value in values:
                        member = value.split()
                        if member[:2] == ["network-object", "object"] and len(member) == 3:
                            endpoint = networks.get(member[2])
                            if endpoint is None or endpoint.resolution_status != DataStatus.KNOWN:
                                raise ValueError("unresolved member")
                            cidrs.extend(endpoint.cidrs)
                        elif member[:2] == ["network-object", "host"] and len(member) == 3:
                            cidrs.append(f"{self._ipv4(member[2])}/32")
                        elif member[:1] == ["network-object"] and len(member) == 3:
                            cidrs.append(self._ipv4_network(member[1], member[2]))
                        else:
                            raise ValueError("unsupported network member")
                    groups[name] = Endpoint(
                        endpoint_id=f"group:{name}",
                        name=name,
                        kind=EndpointKind.GROUP,
                        cidrs=tuple(cidrs),
                    )
                else:
                    if len(tokens) != 4 or tokens[3] not in {"tcp", "udp"}:
                        raise ValueError("unsupported service group protocol")
                    if name in service_groups or not values:
                        raise ValueError("invalid service group")
                    protocol = self._protocol(tokens[3])
                    members: list[Service] = []
                    for value in values:
                        member = value.split()
                        if member[:2] == ["service-object", "object"] and len(member) == 3:
                            service = services.get(member[2])
                        elif member[:1] == ["service-object"]:
                            service = self._service_from_tokens(name, member[1:])
                        elif member[:1] == ["port-object"]:
                            service = self._service_from_tokens(name, [tokens[3], *member[1:]])
                        else:
                            raise ValueError("unsupported service member")
                        if (
                            service is None
                            or service.resolution_status != DataStatus.KNOWN
                            or service.protocol != protocol
                        ):
                            raise ValueError("unresolved or mixed service member")
                        members.append(service)
                    # Пустые порты означают весь протокол, а не пустое множество.
                    port_ranges = (
                        ()
                        if any(not service.port_ranges for service in members)
                        else tuple(port for service in members for port in service.port_ranges)
                    )
                    service_groups[name] = Service(
                        service_id=f"service-group:{name}",
                        name=name,
                        protocol=protocol,
                        port_ranges=port_ranges,
                    )
            except (ValueError, IndexError):
                issues.append(self._issue("UNSUPPORTED_OBJECT", line_number, source_name))
                if len(tokens) >= 3 and tokens[1] == "network":
                    is_group = tokens[0] == "object-group"
                    (groups if is_group else networks)[tokens[2]] = Endpoint(
                        endpoint_id=f"{'group' if is_group else 'object'}:{tokens[2]}",
                        name=tokens[2],
                        kind=EndpointKind.GROUP if is_group else EndpointKind.OBJECT,
                        resolution_status=DataStatus.UNSUPPORTED,
                    )
                elif len(tokens) >= 3 and tokens[1] == "service":
                    is_group = tokens[0] == "object-group"
                    (service_groups if is_group else services)[tokens[2]] = Service(
                        service_id=f"{'service-group' if is_group else 'service'}:{tokens[2]}",
                        name=tokens[2],
                        protocol=Protocol.OTHER,
                        resolution_status=DataStatus.UNSUPPORTED,
                    )
        return networks, services, groups, service_groups, discovered, tuple(issues)

    def _parse_access_groups(self, lines: tuple[tuple[int, str], ...]) -> dict[str, _AccessBinding]:
        bindings: dict[str, set[_AccessBinding]] = {}
        for _, line in lines:
            tokens = line.split()
            if tokens[0] != "access-group" or len(tokens) < 2:
                continue
            if (
                len(tokens) == 5
                and tokens[0] == "access-group"
                and tokens[2] in {"in", "out"}
                and tokens[3] == "interface"
            ):
                binding: _AccessBinding = (tokens[4], "in" if tokens[2] == "in" else "out")
            else:
                binding = (None, None)
            bindings.setdefault(tokens[1], set()).add(binding)
        return {
            name: next(iter(values)) if len(values) == 1 else (None, None)
            for name, values in bindings.items()
        }

    def _parse_rule(
        self,
        line_number: int,
        line: str,
        configuration: Configuration,
        networks: dict[str, Endpoint],
        services: dict[str, Service],
        groups: dict[str, Endpoint],
        service_groups: dict[str, Service],
        access_groups: dict[str, _AccessBinding],
        description: str | None,
        description_status: DataStatus,
    ) -> Rule | ParseIssue | None:
        tokens = line.split()
        if (
            len(tokens) < 5
            or tokens[2:4] != ["extended", "permit"]
            and tokens[2:4] != ["extended", "deny"]
        ):
            return ParseIssue(
                code="UNSUPPORTED_ACCESS_LIST",
                level=ParseIssueLevel.WARNING,
                message="Поддерживаются только extended access-list с действиями permit или deny.",
                source_location=SourceLocation(
                    source_name=configuration.source_name, line_start=line_number
                ),
            )
        acl_name = tokens[1]
        action = RuleAction.ALLOW if tokens[3] == "permit" else RuleAction.DENY
        position = 4
        service, position = self._read_service(tokens, position, services, service_groups)
        source, position = self._read_endpoint(tokens, position, networks, groups)
        destination, position = self._read_endpoint(tokens, position, networks, groups)
        if (
            service is None
            or source is None
            or destination is None
            or any(
                value.resolution_status != DataStatus.KNOWN
                for value in (service, source, destination)
            )
        ):
            return ParseIssue(
                code="UNSUPPORTED_ACCESS_LIST",
                level=ParseIssueLevel.WARNING,
                message="Не удалось разобрать сервис, источник или назначение access-list.",
                source_location=SourceLocation(
                    source_name=configuration.source_name, line_start=line_number
                ),
            )
        if position < len(tokens) and tokens[position] in {"eq", "range"}:
            length = 2 if tokens[position] == "eq" else 3
            if len(tokens[position:]) < length:
                raise ValueError("incomplete destination ports")
            if service.port_ranges or tokens[4] not in {"tcp", "udp"}:
                raise ValueError("unsupported additional service restriction")
            service = self._service_with_ports(service, tokens[position : position + length])
            position += length
        logging_enabled = False
        enabled = True
        seen: set[str] = set()
        while position < len(tokens):
            suffix = tokens[position]
            if suffix in seen or suffix not in {"log", "inactive"}:
                raise ValueError("unsupported ACL suffix")
            seen.add(suffix)
            position += 1
            if suffix == "inactive":
                enabled = False
            else:
                logging_enabled = True
                if position < len(tokens) and tokens[position] == "disable":
                    logging_enabled = False
                    position += 1
        interface, direction = access_groups.get(acl_name, (None, None))
        location = SourceLocation(source_name=configuration.source_name, line_start=line_number)
        rule_id = f"asa:{configuration.content_sha256[:12]}:{acl_name}:{line_number}"
        return Rule(
            rule_id=rule_id,
            configuration_id=configuration.configuration_id,
            name=f"{acl_name} line {line_number}",
            sequence=line_number,
            action=action,
            enabled=enabled,
            sources=(source,),
            destinations=(destination,),
            services=(service,),
            source_zone=interface if direction == "in" else None,
            destination_zone=interface if direction == "out" else None,
            policy_id=acl_name,
            policy_direction=direction,
            policy_semantics="first_match",
            match_status=DataStatus.KNOWN,
            description=description,
            description_status=description_status,
            logging_enabled=logging_enabled,
            source_location=location,
            zone_status=DataStatus.KNOWN if interface and direction else DataStatus.UNKNOWN,
            logging_status=DataStatus.KNOWN,
        )

    def _read_service(
        self,
        tokens: list[str],
        position: int,
        services: dict[str, Service],
        service_groups: dict[str, Service],
    ) -> tuple[Service | None, int]:
        if position >= len(tokens):
            return None, position
        if tokens[position] == "object" and position + 1 < len(tokens):
            return services.get(tokens[position + 1]), position + 2
        if tokens[position] == "object-group" and position + 1 < len(tokens):
            return service_groups.get(tokens[position + 1]), position + 2
        return Service(
            service_id=f"protocol:{tokens[position]}",
            name=tokens[position],
            protocol=self._protocol(tokens[position]),
        ), position + 1

    def _read_endpoint(
        self,
        tokens: list[str],
        position: int,
        networks: dict[str, Endpoint],
        groups: dict[str, Endpoint],
    ) -> tuple[Endpoint | None, int]:
        if position >= len(tokens):
            return None, position
        token = tokens[position]
        if token == "any":
            return Endpoint(endpoint_id="any", name="any", kind=EndpointKind.ANY), position + 1
        if token == "object" and position + 1 < len(tokens):
            return networks.get(tokens[position + 1]), position + 2
        if token == "object-group" and position + 1 < len(tokens):
            return groups.get(tokens[position + 1]), position + 2
        if token == "host" and position + 1 < len(tokens):
            value = self._ipv4(tokens[position + 1])
            return Endpoint(
                endpoint_id=f"host:{value}",
                name=value,
                kind=EndpointKind.HOST,
                cidrs=(f"{value}/32",),
            ), position + 2
        if position + 1 < len(tokens):
            try:
                cidr = self._ipv4_network(tokens[position], tokens[position + 1])
            except ValueError:
                return None, position
            return Endpoint(
                endpoint_id=f"subnet:{cidr}", name=cidr, kind=EndpointKind.SUBNET, cidrs=(cidr,)
            ), position + 2
        return None, position

    def _network_object(self, name: str, value_line: str) -> Endpoint:
        tokens = value_line.split()
        if tokens[:1] == ["host"] and len(tokens) == 2:
            cidr = f"{self._ipv4(tokens[1])}/32"
            return Endpoint(
                endpoint_id=f"object:{name}", name=name, kind=EndpointKind.OBJECT, cidrs=(cidr,)
            )
        if tokens[:1] == ["subnet"] and len(tokens) == 3:
            cidr = self._ipv4_network(tokens[1], tokens[2])
            return Endpoint(
                endpoint_id=f"object:{name}", name=name, kind=EndpointKind.OBJECT, cidrs=(cidr,)
            )
        return Endpoint(
            endpoint_id=f"object:{name}",
            name=name,
            kind=EndpointKind.OBJECT,
            resolution_status=DataStatus.UNSUPPORTED,
        )

    def _service_from_object(self, name: str, value_line: str) -> Service | None:
        tokens = value_line.split()
        if tokens[:1] != ["service"]:
            raise ValueError("missing service declaration")
        return self._service_from_tokens(name, tokens[1:])

    def _service_from_tokens(self, name: str, tokens: list[str]) -> Service | None:
        if not tokens:
            return None
        protocol = self._protocol(tokens[0])
        return self._service_with_ports(
            Service(service_id=f"service:{name}", name=name, protocol=protocol), tokens[1:]
        )

    def _service_with_ports(self, service: Service, tokens: list[str]) -> Service:
        if not tokens:
            return service
        if tokens[:1] == ["destination"]:
            tokens = tokens[1:]
        if service.protocol not in {Protocol.TCP, Protocol.UDP}:
            raise ValueError("ports require TCP or UDP")
        if len(tokens) == 2 and tokens[:1] == ["eq"]:
            port = self._port(tokens[1])
            return self._with_port_ranges(service, (PortRange(start=port, end=port),))
        if len(tokens) == 3 and tokens[:1] == ["range"]:
            return self._with_port_ranges(
                service,
                (PortRange(start=self._port(tokens[1]), end=self._port(tokens[2])),),
            )
        raise ValueError("unsupported service restriction")

    @staticmethod
    def _with_port_ranges(service: Service, port_ranges: tuple[PortRange, ...]) -> Service:
        return Service(
            service_id=service.service_id,
            name=service.name,
            protocol=service.protocol,
            port_ranges=port_ranges,
            description=service.description,
            resolution_status=service.resolution_status,
        )

    def _port(self, value: str) -> int:
        return self._named_ports[value] if value in self._named_ports else int(value)

    @staticmethod
    def _protocol(value: str) -> Protocol:
        if value not in {"tcp", "udp", "icmp", "ip"}:
            raise ValueError("unsupported protocol")
        return Protocol(value)

    @staticmethod
    def _ipv4(value: str) -> str:
        address = ip_address(value)
        if address.version != 4:
            raise ValueError("IPv6 is unsupported")
        return str(address)

    @classmethod
    def _ipv4_network(cls, address: str, mask: str) -> str:
        cls._ipv4(address)
        cls._ipv4(mask)
        network = ip_network(f"{address}/{mask}", strict=False)
        # ASA использует netmask, а не IOS wildcard mask.
        if str(network.netmask) != mask:
            raise ValueError("unsupported or noncontiguous netmask")
        return str(network)

    def _configuration(self, request: ParseRequest, hostname: str | None) -> Configuration:
        configuration_id = uuid5(NAMESPACE_URL, f"cisco-asa-9.16:{request.source.content_sha256}")
        return Configuration(
            configuration_id=configuration_id,
            source_name=request.source.source_name,
            device_id=f"cisco-asa:{hostname or request.source.content_sha256[:12]}",
            vendor=self.metadata.vendor,
            platform="asa-9.16",
            parser_version=self.metadata.version,
            content_sha256=request.source.content_sha256,
            captured_at=request.source.captured_at,
            imported_at=request.imported_at,
        )

    @staticmethod
    def _hostname(lines: tuple[tuple[int, str], ...]) -> str | None:
        for _, line in lines:
            tokens = line.split(maxsplit=1)
            if len(tokens) == 2 and tokens[0] == "hostname":
                return tokens[1]
        return None

    @staticmethod
    def _unique_endpoints(endpoints: Iterable[Endpoint]) -> tuple[Endpoint, ...]:
        return tuple({endpoint.endpoint_id: endpoint for endpoint in endpoints}.values())

    @staticmethod
    def _unique_services(services: Iterable[Service]) -> tuple[Service, ...]:
        return tuple({service.service_id: service for service in services}.values())
