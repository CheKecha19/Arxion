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


class ComwareParser:
    """Сохраняет ACL и management scope; не вычисляет транзитную достижимость."""

    _metadata = ParserMetadata(parser_id="hp-h3c-comware", version="0.1.0", vendor="hp-h3c")

    @property
    def metadata(self) -> ParserMetadata:
        """Вернуть идентичность адаптера."""
        return self._metadata

    def detect(self, source: SourceDocument) -> DetectionResult:
        """Требовать характерную конфигурацию Comware, а не отдельное слово acl."""
        try:
            text = source.content.decode("utf-8-sig")
        except UnicodeDecodeError:
            return DetectionResult(parser_id=self.metadata.parser_id, is_match=False, confidence=0)
        match = bool(
            re.search(r"^\s*acl (?:number|basic|advanced)\b", text, re.M)
            and (
                re.search(r"^\s*version (?:5\.20\.|7\.1\.)", text, re.M)
                or re.search(r"\bComware\b", text, re.I)
            )
            and not re.search(r"\b(?:Huawei|VRP)\b", text, re.I)
        )
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=match,
            confidence=0.9 if match else 0,
            reasons=("ACL и характерный контекст Comware.",) if match else (),
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
        management_acls = set()
        for line in lines:
            if line.strip().startswith("snmp-agent "):
                found = re.search(r"\bacl (\S+)", line)
                if found:
                    management_acls.add(found.group(1))
        rules: list[Rule] = []
        unsupported: list[UnsupportedConstruct] = []
        warnings = [
            ParseIssue(
                code="LIMITED_COMWARE_SCOPE",
                level=ParseIssueLevel.WARNING,
                message="Разобраны IPv4 ACL. Применение ACL, порядок auto, управление SNMP, "
                "QoS и транзитная достижимость не вычисляются. Coverage относится к ACL-входу.",
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
            valid = len(tokens) >= 4 and tokens[1].isdigit() and tokens[2] in {"permit", "deny"}
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
            if management:
                destination = Endpoint(
                    endpoint_id=identifier + ":management",
                    name="Управление SNMP",
                    kind=EndpointKind.ZONE,
                    zone="management:snmp",
                    resolution_status=DataStatus.UNKNOWN,
                )
                match_status = DataStatus.UNKNOWN
            service = Service(
                service_id=identifier + ":service",
                name="SNMP management scope" if management else protocol.value,
                protocol=Protocol.OTHER if management else protocol,
                port_ranges=() if management else ports,
                resolution_status=DataStatus.UNKNOWN if management else DataStatus.KNOWN,
            )
            rule = Rule(
                rule_id=identifier,
                configuration_id=config.configuration_id,
                name=f"ACL {acl} / {sequence}"
                + (" · управление SNMP" if management else " · назначение не подтверждено"),
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
                policy_id=("management:snmp:" if management else "") + f"acl:{acl}",
                source_zone="management:snmp" if management else None,
                zone_status=DataStatus.UNKNOWN,
                logging_enabled=logging,
                logging_status=DataStatus.KNOWN if logging is not None else DataStatus.UNKNOWN,
                description=description,
                description_status=DataStatus.KNOWN,
                source_location=location,
            )
            rules.append(rule)
        if not rules:
            warnings.append(
                ParseIssue(
                    code="NO_ACL_RULES",
                    level=ParseIssueLevel.WARNING,
                    message="В области парсера правила ACL не найдены.",
                )
            )
        from firewall_compliance.parsers.management import parse_management

        return ParseResult(
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
