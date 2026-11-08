"""Ограниченный разбор IPv4 ACL HP/H3C Comware и их назначения."""

import re
from ipaddress import IPv4Address, ip_address, ip_network

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
from firewall_compliance.parsers.platform_detection import detect_switch_platform


class ComwareParser:
    """Сохраняет ACL и management scope; не вычисляет транзитную достижимость."""

    _metadata = ParserMetadata(parser_id="hp-h3c-comware", version="0.2.0", vendor="hp-h3c")

    @property
    def metadata(self) -> ParserMetadata:
        """Вернуть идентичность адаптера."""
        return self._metadata

    def detect(self, source: SourceDocument) -> DetectionResult:
        """Распознать версию и характерный контекст Comware, в том числе без ACL."""
        try:
            text = source.content.decode("utf-8-sig")
        except UnicodeDecodeError:
            return DetectionResult(parser_id=self.metadata.parser_id, is_match=False, confidence=0)
        detection = detect_switch_platform(text)
        match = detection.platform == "comware"
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=match,
            confidence=detection.confidence if match else 0,
            reasons=detection.reasons,
        )

    @staticmethod
    def _endpoint(address: str, wildcard: str, identifier: str) -> Endpoint:
        if address == "any":
            return Endpoint(endpoint_id=identifier, name="any", kind=EndpointKind.ANY)
        try:
            parsed = ip_address(address)
            if parsed.version != 4:
                raise ValueError("только IPv4")
            mask = IPv4Address(0 if wildcard == "0" else wildcard)
            netmask = IPv4Address((2**32 - 1) ^ int(mask))
            network = ip_network(f"{address}/{netmask}", strict=False)
            return Endpoint(
                endpoint_id=identifier,
                name=f"{address} wildcard {wildcard}",
                kind=EndpointKind.HOST if network.prefixlen == 32 else EndpointKind.SUBNET,
                cidrs=(str(network),),
            )
        except ValueError:
            return Endpoint(
                endpoint_id=identifier,
                name=f"{address} wildcard {wildcard}",
                kind=EndpointKind.OBJECT,
                resolution_status=DataStatus.UNKNOWN,
            )

    def parse(self, request: ParseRequest) -> ParseOutcome:
        """Разобрать правила без раскрытия непрочитанных команд и секретов."""
        try:
            detection = detect_switch_platform(request.source.content.decode("utf-8-sig"))
        except UnicodeDecodeError:
            detection = None
        if detection is not None and detection.ambiguous:
            return ParseFailure(
                parser_id=self.metadata.parser_id,
                source_name=request.source.source_name,
                content_sha256=request.source.content_sha256,
                errors=(ParseIssue(
                    code="PLATFORM_AMBIGUOUS", level=ParseIssueLevel.ERROR,
                    message=" ".join(detection.reasons),
                ),),
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
                        message="Не распознана конфигурация Comware.",
                    ),
                ),
            )
        lines = request.source.content.decode("utf-8-sig").splitlines()
        hostname = next(
            (
                line.strip().split(maxsplit=1)[1]
                for line in lines
                if line.strip().startswith("sysname ")
            ),
            request.source.source_name,
        )
        config = Configuration(
            source_name=request.source.source_name,
            device_id=hostname,
            vendor=self.metadata.vendor,
            platform="comware",
            parser_version=self.metadata.version,
            content_sha256=request.source.content_sha256,
            captured_at=request.source.captured_at,
            imported_at=request.imported_at,
        )
        management_acls: dict[str, set[str]] = {}
        binding_locations: dict[str, list[SourceLocation]] = {}
        declared_acls: set[str] = set()
        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            binding = re.fullmatch(r"ssh server acl (\S+)", line)
            method = "ssh"
            if line.startswith("snmp-agent community "):
                binding = re.search(r"\bacl (\S+)\s*$", line)
                method = "snmp"
            if binding:
                acl_id = binding.group(1)
                management_acls.setdefault(acl_id, set()).add(method)
                binding_locations.setdefault(acl_id, []).append(
                    SourceLocation(
                        source_name=request.source.source_name,
                        line_start=lineno,
                        line_end=lineno,
                    )
                )
        rules: list[Rule] = []
        unsupported: list[UnsupportedConstruct] = []
        warnings = [
            ParseIssue(
                code="LIMITED_COMWARE_SCOPE",
                level=ParseIssueLevel.WARNING,
                message="Разобраны IPv4 ACL и назначения SSH/SNMP. Порядок auto, "
                "effective-применение, QoS и транзитная достижимость не вычисляются. "
                "Coverage относится к ACL-входу.",
            )
        ]
        acl: str | None = None
        advanced = False
        acl_identifier_known = True
        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            header = re.match(r"acl (number|basic|advanced) (\S+)(.*)$", line)
            if header:
                acl = header.group(2)
                declared_acls.add(acl)
                acl_identifier_known = acl.isdigit()
                advanced = header.group(1) == "advanced" or (
                    acl_identifier_known and 3000 <= int(acl) <= 3999
                )
                if not acl_identifier_known:
                    warnings.append(
                        ParseIssue(
                            code="UNKNOWN_ACL_IDENTIFIER",
                            level=ParseIssueLevel.WARNING,
                            message="Номер ACL неизвестен или замаскирован; "
                            "тип и область не подтверждены.",
                            source_location=SourceLocation(
                                source_name=request.source.source_name,
                                line_start=lineno,
                                line_end=lineno,
                            ),
                        )
                    )
                continue
            if line in {"#", "quit", "return"}:
                acl = None
                continue
            if not line.startswith("rule ") or acl is None:
                continue
            location = SourceLocation(
                source_name=request.source.source_name, line_start=lineno, line_end=lineno
            )
            identifier = f"comware:acl:{acl}:line:{lineno}"
            tokens = line.split()
            valid = len(tokens) >= 3 and tokens[1].isdigit() and tokens[2] in {"permit", "deny"}
            sequence = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else lineno
            action = (
                RuleAction.ALLOW
                if valid and tokens[2] == "permit"
                else (RuleAction.DENY if valid else RuleAction.UNKNOWN)
            )
            cursor = 3
            protocol = Protocol.IP
            if advanced or (
                not acl_identifier_known
                and cursor < len(tokens)
                and tokens[cursor] in {"ip", "tcp", "udp", "icmp"}
            ):
                if cursor < len(tokens) and tokens[cursor] in {"ip", "tcp", "udp", "icmp"}:
                    protocol = Protocol(tokens[cursor])
                    cursor += 1
                else:
                    valid = False
            source = self._endpoint("any", "0", identifier + ":src")
            destination = self._endpoint("any", "0", identifier + ":dst")
            ports: tuple[PortRange, ...] = ()
            logging: bool | None = None
            description: str | None = None
            seen: set[str] = set()
            while valid and cursor < len(tokens):
                keyword = tokens[cursor]
                cursor += 1
                if keyword in seen:
                    valid = False
                    break
                seen.add(keyword)
                if keyword in {"source", "destination"}:
                    if cursor >= len(tokens):
                        valid = False
                        break
                    address = tokens[cursor]
                    cursor += 1
                    wildcard = "0"
                    if address != "any":
                        if cursor >= len(tokens):
                            valid = False
                            break
                        wildcard = tokens[cursor]
                        cursor += 1
                    endpoint = self._endpoint(address, wildcard, identifier + ":" + keyword)
                    if keyword == "source":
                        source = endpoint
                    else:
                        destination = endpoint
                elif keyword == "destination-port" and protocol in {Protocol.TCP, Protocol.UDP}:
                    try:
                        operator = tokens[cursor]
                        start = int(tokens[cursor + 1])
                        if operator == "eq":
                            ports = (PortRange(start=start, end=start),)
                            cursor += 2
                        elif operator == "range":
                            ports = (PortRange(start=start, end=int(tokens[cursor + 2])),)
                            cursor += 3
                        else:
                            valid = False
                    except (ValueError, IndexError):
                        valid = False
                elif keyword == "logging":
                    logging = True
                elif keyword == "comment":
                    description = " ".join(tokens[cursor:]) or None
                    cursor = len(tokens)
                else:
                    valid = False
            known_addresses = (
                source.resolution_status == destination.resolution_status == DataStatus.KNOWN
            )
            match_status = (
                DataStatus.KNOWN
                if valid and known_addresses and acl_identifier_known
                else (DataStatus.UNKNOWN if valid else DataStatus.UNSUPPORTED)
            )
            if match_status != DataStatus.KNOWN:
                unsupported.append(
                    UnsupportedConstruct(
                        construct_type="comware_acl_condition",
                        message="Условие ACL неизвестно или не поддержано; оно не заменено на any.",
                        source_location=location,
                    )
                )
            management = acl in management_acls
            methods = "/".join(sorted(management_acls.get(acl, ())))
            if management:
                destination = Endpoint(
                    endpoint_id=identifier + ":management",
                    name=f"Управление {methods.upper()}",
                    kind=EndpointKind.ZONE,
                    zone=f"management:{methods}",
                    resolution_status=DataStatus.UNKNOWN,
                )
                match_status = DataStatus.UNKNOWN
            service = Service(
                service_id=identifier + ":service",
                name=f"{methods.upper()} management scope" if management else protocol.value,
                protocol=Protocol.OTHER if management else protocol,
                port_ranges=() if management else ports,
                resolution_status=DataStatus.UNKNOWN if management else DataStatus.KNOWN,
            )
            rule = Rule(
                rule_id=identifier,
                configuration_id=config.configuration_id,
                name=f"ACL {acl} / {sequence}"
                + (
                    f" · управление {methods.upper()}"
                    if management
                    else " · назначение не подтверждено"
                ),
                sequence=sequence,
                action=action,
                enabled=True,
                sources=(source,),
                destinations=(destination,),
                services=(service,),
                source_status=source.resolution_status if valid else DataStatus.UNSUPPORTED,
                destination_status=destination.resolution_status
                if valid
                else DataStatus.UNSUPPORTED,
                service_status=(DataStatus.UNKNOWN if management else DataStatus.KNOWN)
                if valid
                else DataStatus.UNSUPPORTED,
                match_status=match_status,
                policy_id=(f"management:{methods}:" if management else "") + f"acl:{acl}",
                source_zone=f"management:{methods}" if management else None,
                zone_status=DataStatus.UNKNOWN,
                logging_enabled=logging,
                logging_status=DataStatus.KNOWN if logging is not None else DataStatus.UNKNOWN,
                description=description,
                description_status=DataStatus.KNOWN,
                source_location=location,
            )
            rules.append(rule)
        for acl_id, locations in binding_locations.items():
            if acl_id not in declared_acls:
                warnings.extend(
                    ParseIssue(
                        code="COMWARE_BINDING_WITHOUT_ACL",
                        level=ParseIssueLevel.WARNING,
                        message="Привязка управления ссылается на необъявленную ACL.",
                        source_location=location,
                    )
                    for location in locations
                )
        if not rules:
            warnings.append(
                ParseIssue(
                    code="NO_ACL_RULES",
                    level=ParseIssueLevel.WARNING,
                    message="В области парсера правила ACL не найдены.",
                )
            )
        from firewall_compliance.parsers.management import parse_management
        from firewall_compliance.parsers.switch_policy import enrich_switch_result

        result = ParseResult(
            configuration=config,
            management=parse_management(request.source, "comware"),
            rules=tuple(rules),
            endpoints=tuple(item for rule in rules for item in (*rule.sources, *rule.destinations)),
            services=tuple(item for rule in rules for item in rule.services),
            warnings=tuple(warnings),
            unsupported_constructs=tuple(unsupported),
            source_map={rule.rule_id: rule.source_location for rule in rules},
            coverage=ParseCoverage(
                discovered_constructs=len(rules),
                recognized_constructs=len(rules) - len(unsupported),
                unsupported_constructs=len(unsupported),
            ),
        )
        return enrich_switch_result(request.source, result)
