"""Ограниченный адаптер forwarding для конфигурации ASA 9.16."""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface
from typing import Literal

from pydantic import ValidationError

from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus, ParseIssueLevel
from firewall_compliance.domain.forwarding import (
    FEATURE_SCOPES,
    FeatureInventory,
    ForwardingAcl,
    ForwardingBinding,
    ForwardingContext,
    ForwardingFeature,
    ForwardingInterface,
    ForwardingLocation,
    ForwardingSource,
    ForwardingToggle,
)
from firewall_compliance.domain.parse_result import ParseCoverage, ParseIssue, UnsupportedConstruct
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.parsers.cisco_asa import CiscoAsaParser
from firewall_compliance.parsers.contracts import (
    DetectionResult,
    ParseFailure,
    ParseRequest,
    ParserMetadata,
    SourceDocument,
)
from firewall_compliance.parsers.forwarding_contracts import (
    ForwardingParseOutcome,
    ForwardingParseRequest,
    ForwardingParseResult,
)

_VERSION = re.compile(r"9\.16(?:\([0-9]+\)[0-9]*|(?:\.[0-9]+)+)?")
_PHYSICAL = re.compile(r"(?:GigabitEthernet|TenGigabitEthernet|Ethernet)[0-9]+/[0-9]+")
type _Direction = Literal["in", "out", "global"]
type _ToggleName = Literal["inter_interface", "intra_interface", "permit_vpn"]


@dataclass
class _InterfaceBlock:
    identifier: str
    start: int
    end: int
    label: str | None = None
    level: int | None = None
    has_ip: bool = False
    excluded: bool = False
    seen: set[str] = field(default_factory=set)
    invalid: set[str] = field(default_factory=set)


class CiscoAsaForwardingParser:
    _metadata = ParserMetadata(
        parser_id="cisco-asa-forwarding-9.16", version="0.1.0", vendor="cisco"
    )

    @property
    def metadata(self) -> ParserMetadata:
        return self._metadata

    @staticmethod
    def _boundary(source: SourceDocument, metadata: ForwardingSource | None) -> str | None:
        if metadata is None:
            return "Для forwarding требуются метаданные источника."
        if metadata is not None:
            if (
                metadata.purpose != "configuration"
                or metadata.command not in {"show running-config", "show running-config all"}
                or not _VERSION.fullmatch(metadata.declared_version)
            ):
                return "Неподдержанная команда, роль или версия источника."
            if (
                metadata.source_name != source.source_name
                or metadata.content_sha256.lower() != source.content_sha256
                or metadata.captured_at != source.captured_at
                or metadata.observation != source.observation
            ):
                return "Метаданные не соответствуют документу."
        try:
            text = source.content.decode(metadata.encoding if metadata else "utf-8")
        except UnicodeDecodeError:
            return "Байты не соответствуют кодировке."
        headers = [
            line.strip().removeprefix("ASA Version ")
            for line in text.splitlines()
            if line.strip().startswith("ASA Version ")
        ]
        if len(headers) != 1:
            return "Требуется ровно один заголовок ASA 9.16."
        if any(
            not _VERSION.fullmatch(version)
            or (metadata.declared_version != "9.16" and version != metadata.declared_version)
            for version in headers
        ):
            return "Заголовок ASA не соответствует заявленной версии."
        return None

    def detect(
        self, source: SourceDocument, metadata: ForwardingSource | None = None
    ) -> DetectionResult:
        problem: str | None
        try:
            source = SourceDocument.model_validate(source.model_dump(mode="python"))
            if metadata is not None:
                metadata = ForwardingSource.model_validate(metadata.model_dump(mode="python"))
        except ValidationError:
            problem = "Некорректный документ или метаданные источника."
        else:
            problem = self._boundary(source, metadata)
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=problem is None,
            confidence=0.95 if problem is None else 0.0,
            reasons=(problem or "Источник конфигурации ASA 9.16.",),
        )

    def _failure(self, source: SourceDocument, code: str, message: str) -> ParseFailure:
        return ParseFailure(
            parser_id=self.metadata.parser_id,
            source_name=source.source_name,
            content_sha256=source.content_sha256,
            errors=(ParseIssue(code=code, level=ParseIssueLevel.ERROR, message=message),),
        )

    def parse(self, request: ForwardingParseRequest) -> ForwardingParseOutcome:
        try:
            request = ForwardingParseRequest.model_validate(request.model_dump(mode="python"))
        except ValidationError:
            return self._failure(
                request.source, "ASA_FORWARDING_INPUT_INVALID", "Некорректный вход."
            )
        problem = self._boundary(request.source, request.metadata)
        if problem:
            return self._failure(request.source, "ASA_FORWARDING_SOURCE_UNSUPPORTED", problem)
        if (
            request.context_mode not in {None, "single"}
            or request.firewall_mode not in {None, "routed"}
            or request.address_family not in {None, "ipv4"}
            or request.table_role not in {None, "data"}
            or request.table_id not in {None, "default"}
            or request.metadata.device_context is not None
        ):
            return self._failure(
                request.source, "ASA_FORWARDING_PROFILE_UNSUPPORTED", "Профиль не поддерживается."
            )
        return _parse(request, request.source.content.decode(request.metadata.encoding))


def _parse(request: ForwardingParseRequest, text: str) -> ForwardingParseResult:
    metadata = request.metadata
    warnings: list[ParseIssue] = []
    errors: list[ParseIssue] = []
    unsupported: list[UnsupportedConstruct] = []
    source_map: dict[str, SourceLocation] = {}
    damaged: set[ForwardingFeature] = set()
    all_classified = True
    discovered = 0
    rejected_lines: set[int] = set()
    failed_lines: set[int] = set()

    def anchor(start: int, end: int | None = None) -> ForwardingLocation:
        return ForwardingLocation(
            source_document_id=metadata.source_document_id,
            location=SourceLocation(
                source_name=request.source.source_name, line_start=start, line_end=end or start
            ),
        )

    def issue(code: str, message: str, number: int, *, error: bool = False) -> None:
        if error:
            failed_lines.add(number)
        location = anchor(number).location
        source_map[f"diagnostic:{code}:{number}"] = location
        (errors if error else warnings).append(
            ParseIssue(
                code=code,
                level=ParseIssueLevel.ERROR if error else ParseIssueLevel.WARNING,
                message=message,
                source_location=location,
            )
        )

    def reject(kind: str, number: int, message: str) -> None:
        rejected_lines.add(number)
        location = anchor(number).location
        unsupported.append(
            UnsupportedConstruct(construct_type=kind, message=message, source_location=location)
        )
        source_map[f"unsupported:{len(unsupported)}"] = location
        issue("ASA_FORWARDING_UNSUPPORTED", message, number)

    old = CiscoAsaParser()
    old_request = ParseRequest(source=request.source, imported_at=request.imported_at)
    lines = tuple(old._lines(request.source.content, preserve_indent=True))
    networks, services, groups, service_groups, _, object_issues = old._parse_objects(
        lines, request.source.source_name
    )
    bad_objects = {
        item.source_location.line_start
        for item in object_issues
        if item.source_location is not None
    }
    configuration = old._configuration(old_request, old._hostname(lines))
    configuration = configuration.model_copy(update={"configuration_id": request.configuration_id})
    blocks: list[_InterfaceBlock] = []
    current: _InterfaceBlock | None = None
    object_start: int | None = None
    object_bad = False
    route_map = False
    acl_lines: dict[str, list[int]] = defaultdict(list)
    acl_rules: dict[str, list[Rule]] = defaultdict(list)
    bad_acls: set[str] = set()
    remarks: dict[str, list[str]] = defaultdict(list)
    binding_claims: dict[tuple[_Direction, str | None], list[tuple[str, int]]] = defaultdict(list)
    toggle_claims: dict[_ToggleName, list[tuple[bool, int]]] = defaultdict(list)
    extra_locations: dict[ForwardingFeature, list[ForwardingLocation]] = defaultdict(list)

    for number, raw in enumerate(text.splitlines(), 1):
        statement = raw.strip()
        if not statement or statement.startswith("!"):
            if statement.startswith("!"):
                current = None
                object_start = None
                route_map = False
            continue
        discovered += 1
        tokens = statement.split()
        indented = raw[0].isspace()
        if not indented:
            current = None
            object_start = None
            route_map = False
        if indented and tokens[0] in {
            "interface",
            "object",
            "object-group",
            "access-list",
            "access-group",
            "same-security-traffic",
            "sysopt",
            "route-map",
            "ASA",
            "hostname",
            "domain-name",
        }:
            all_classified = False
            if current is not None:
                current.excluded = True
            reject("unknown-command", number, "Команда вне допустимого уровня вложенности.")
            continue
        if tokens[0] == "interface":
            if len(tokens) == 2:
                current = _InterfaceBlock(tokens[1], number, number)
                blocks.append(current)
                if not _PHYSICAL.fullmatch(tokens[1]):
                    current.excluded = True
                    extra_locations["exceptions"].append(anchor(number))
                    reject("interface", number, "Неподдержанный тип интерфейса.")
                    damaged.add("interfaces")
            else:
                reject("interface", number, "Неполный заголовок интерфейса.")
                damaged.add("interfaces")
            continue
        if tokens[0] in {"object", "object-group"}:
            object_start = number
            object_bad = number in bad_objects
            if object_bad:
                damaged.add("acl_definitions")
                reject("object", number, "Объект не разрешён ACL-парсером.")
            continue
        if tokens[0] == "nat":
            extra_locations["configured_nat"].append(anchor(number))
            reject("nat", number, "NAT не поддерживается.")
            if indented and object_start is None:
                all_classified = False
            continue
        if tokens[0] in {"route-map", "policy-route"}:
            extra_locations["pbr"].append(anchor(number))
            reject("pbr", number, "PBR не поддерживается.")
            route_map = tokens[0] == "route-map"
            if tokens[0] == "policy-route" and (not indented or current is None):
                all_classified = False
            continue
        if route_map and indented and tokens[0] in {"match", "set"}:
            extra_locations["pbr"].append(anchor(number))
            reject("pbr", number, "Условие или действие PBR не поддерживается.")
            continue
        if current is not None and indented:
            current.end = number
            key = tokens[0]
            if tokens[:2] == ["ip", "address"]:
                key = "ip"
            if key in {"nameif", "security-level", "ip"}:
                if key in current.seen:
                    current.invalid.add(key)
                    damaged.add("interfaces")
                    issue(
                        "ASA_FORWARDING_INTERFACE_CONFLICT",
                        "Повторное свойство интерфейса.",
                        number,
                        error=True,
                    )
                current.seen.add(key)
                valid = False
                if key == "nameif" and len(tokens) == 2:
                    current.label = tokens[1]
                    valid = True
                elif key == "security-level" and len(tokens) == 2 and tokens[1].isdigit():
                    level = int(tokens[1])
                    if 0 <= level <= 100:
                        current.level = level
                        valid = True
                elif key == "ip" and len(tokens) == 4 and tokens[:2] == ["ip", "address"]:
                    try:
                        host = IPv4Address(tokens[2])
                        if host.is_unspecified or host.is_multicast or int(host) == 0xFFFFFFFF:
                            raise ValueError("интерфейс требует конкретный unicast IPv4")
                        mask = int(IPv4Address(tokens[3]))
                        inverse = mask ^ 0xFFFFFFFF
                        if inverse & (inverse + 1):
                            raise ValueError("непрерывная маска обязательна")
                        IPv4Interface(f"{host}/{mask.bit_count()}")
                        current.has_ip = True
                        valid = True
                    except ValueError:
                        pass
                if not valid:
                    current.invalid.add(key)
                    damaged.add("interfaces")
                    reject("interface", number, "Неподдержанное свойство интерфейса.")
                source_map[f"interface-property:{current.identifier}:{number}"] = anchor(
                    number
                ).location
                continue
            if statement in {
                "shutdown",
                "no shutdown",
                "no ip address",
                "no nameif",
                "no security-level",
            }:
                if statement == "no ip address":
                    current.invalid.add("ip")
                    current.has_ip = False
                elif statement == "no nameif":
                    current.invalid.add("nameif")
                elif statement == "no security-level":
                    current.invalid.add("security-level")
                continue
            if tokens[0] in {"bridge-group", "management-only", "ipv6", "vlan", "channel-group"}:
                current.excluded = True
                damaged.add("interfaces")
                extra_locations["exceptions"].append(anchor(number))
                reject("interface", number, "Интерфейс вне физического IPv4 L3-профиля.")
                continue
            if tokens[0] == "description" and len(tokens) > 1:
                continue
        if (
            object_start is not None
            and indented
            and tokens[0]
            in {
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
            }
        ):
            source_map[f"object-child:{number}"] = anchor(number).location
            if object_bad:
                reject("object", number, "Содержимое неразрешённого объекта.")
            continue
        if tokens[0] == "access-list":
            if len(tokens) < 3:
                reject("access-list", number, "Неполное определение ACL.")
                damaged.add("acl_definitions")
                if len(tokens) == 2:
                    acl_lines[tokens[1]].append(number)
                    bad_acls.add(tokens[1])
                continue
            name = tokens[1]
            acl_lines[name].append(number)
            if tokens[2] == "remark":
                remark = statement.split(maxsplit=3)[3] if len(tokens) > 3 else ""
                remarks[name].append(remark)
                if not remark:
                    bad_acls.add(name)
                    reject("access-list", number, "Пустой remark ACL.")
                continue
            pending = remarks.pop(name, [])
            try:
                rule = old._parse_rule(
                    number,
                    statement,
                    configuration,
                    networks,
                    services,
                    groups,
                    service_groups,
                    {},
                    "\n".join(pending) or None,
                    DataStatus.KNOWN if pending and all(pending) else DataStatus.ABSENT,
                )
            except (ValueError, IndexError):
                rule = None
            if isinstance(rule, Rule):
                acl_rules[name].append(rule)
                source_map[rule.rule_id] = rule.source_location
            else:
                bad_acls.add(name)
                reject("access-list", number, "ACE не поддерживается ACL-парсером.")
            continue
        if tokens[0] == "access-group":
            direction: _Direction
            label: str | None
            if len(tokens) == 3 and tokens[2] == "global":
                direction, label = "global", None
            elif len(tokens) == 5 and tokens[2] in {"in", "out"} and tokens[3] == "interface":
                direction = "in" if tokens[2] == "in" else "out"
                label = tokens[4]
            else:
                damaged.add("acl_bindings")
                reject("access-group", number, "Неподдержанный ACL binding.")
                if len(tokens) >= 2 and tokens[1] not in acl_lines:
                    acl_lines[tokens[1]].append(number)
                    bad_acls.add(tokens[1])
                continue
            binding_claims[direction, label].append((tokens[1], number))
            continue
        negative = tokens[0] == "no"
        positive = tokens[1:] if negative else tokens
        name_toggle: _ToggleName | None = None
        if positive == ["same-security-traffic", "permit", "inter-interface"]:
            name_toggle = "inter_interface"
        elif positive == ["same-security-traffic", "permit", "intra-interface"]:
            name_toggle = "intra_interface"
        elif positive == ["sysopt", "connection", "permit-vpn"]:
            name_toggle = "permit_vpn"
        if name_toggle is not None:
            if indented:
                all_classified = False
                reject("unknown-command", number, "Настройка вне допустимого уровня вложенности.")
                continue
            toggle_claims[name_toggle].append((not negative, number))
            continue
        if tokens[0] in {
            "crypto",
            "service-policy",
            "policy-map",
            "class-map",
            "context",
            "failover",
            "cluster",
            "firewall",
            "mode",
            "tunnel-group",
        }:
            extra_locations["exceptions"].append(anchor(number))
            reject("exception", number, "Конструкция вне поддержанного профиля.")
            continue
        if (
            (tokens[:2] == ["ASA", "Version"] and len(tokens) == 3)
            or (tokens[0] in {"hostname", "domain-name"} and len(tokens) == 2)
            or statement in {"end", ": end"}
            or (tokens[0] == "description" and len(tokens) > 1 and not indented)
        ):
            continue
        all_classified = False
        if current is not None:
            current.excluded = True
        reject("unknown-command", number, "Неизвестная команда исключает доказательство полноты.")

    interfaces: list[ForwardingInterface] = []
    id_counts = Counter(block.identifier for block in blocks)
    label_counts = Counter(block.label.casefold() for block in blocks if block.label is not None)
    for block in blocks:
        if (
            block.label is None
            or "nameif" in block.invalid
            or id_counts[block.identifier] != 1
            or label_counts[block.label.casefold()] != 1
        ):
            damaged.add("interfaces")
            issue(
                "ASA_FORWARDING_INTERFACE_UNRESOLVED",
                "Имя интерфейса не доказано однозначно.",
                block.start,
                error=True,
            )
            continue
        interface_level = None if "security-level" in block.invalid else block.level
        interface = ForwardingInterface(
            interface_id=block.identifier,
            label=block.label,
            physical_l3=True
            if (
                _PHYSICAL.fullmatch(block.identifier)
                and block.has_ip
                and not block.invalid
                and not block.excluded
            )
            else None,
            security_level=interface_level,
            security_status=DataStatus.KNOWN if interface_level is not None else DataStatus.UNKNOWN,
            location=anchor(block.start, block.end),
        )
        interfaces.append(interface)
        source_map[f"interface:{interface.interface_id}"] = interface.location.location

    bindings: list[ForwardingBinding] = []
    by_label = {interface.label: interface.interface_id for interface in interfaces}
    for (direction, label), claims in binding_claims.items():
        for policy, number in claims:
            if policy not in acl_lines:
                acl_lines[policy].append(number)
                bad_acls.add(policy)
                issue(
                    "ASA_FORWARDING_ACL_MISSING",
                    "Binding ссылается на отсутствующее определение ACL.",
                    number,
                    error=True,
                )
        if len(claims) != 1:
            damaged.add("acl_bindings")
            for _, number in claims:
                issue(
                    "ASA_FORWARDING_BINDING_CONFLICT",
                    "Повторный binding одной позиции.",
                    number,
                    error=True,
                )
            continue
        policy, number = claims[0]
        if label is not None and label not in by_label:
            damaged.add("acl_bindings")
            issue(
                "ASA_FORWARDING_BINDING_INTERFACE_MISSING",
                "Интерфейс binding не разрешён.",
                number,
                error=True,
            )
            continue
        binding = ForwardingBinding(
            policy_id=policy,
            direction=direction,
            interface_id=by_label[label] if label is not None else None,
            location=anchor(number),
        )
        bindings.append(binding)
        source_map[f"binding:{direction}:{label}"] = binding.location.location

    def scope_complete(feature: ForwardingFeature) -> bool:
        return (
            metadata.command == "show running-config all"
            and metadata.capture_success
            and metadata.selection == "all"
            and metadata.extent == "full"
            and metadata.observation is not None
            and bool(metadata.completeness_reference)
            and FEATURE_SCOPES[feature] <= set(metadata.complete_scopes)
            and all_classified
            and feature not in damaged
            and feature != "effective_nat"
        )

    acls: list[ForwardingAcl] = []
    for policy, numbers in acl_lines.items():
        complete = (
            scope_complete("acl_definitions") and policy not in bad_acls and bool(acl_rules[policy])
        )
        acl = ForwardingAcl(
            policy_id=policy,
            configuration_id=request.configuration_id,
            status=DataStatus.KNOWN if complete else DataStatus.UNKNOWN,
            complete=complete,
            rules=tuple(acl_rules[policy]),
            location=anchor(numbers[0]),
            reference=metadata.completeness_reference if complete else None,
        )
        acls.append(acl)
        source_map[f"acl:{policy}"] = acl.location.location
        for number in numbers:
            source_map[f"acl-line:{policy}:{number}"] = anchor(number).location

    toggles: list[ForwardingToggle] = []
    toggle_names: tuple[_ToggleName, ...] = ("inter_interface", "intra_interface", "permit_vpn")
    for name in toggle_names:
        claims_toggle = toggle_claims[name]
        known = len(claims_toggle) == 1
        if len(claims_toggle) > 1:
            damaged.add("vpn_bypass" if name == "permit_vpn" else "same_security")
            for _, number in claims_toggle:
                issue(
                    "ASA_FORWARDING_TOGGLE_CONFLICT",
                    "Повторная настройка разрешения.",
                    number,
                    error=True,
                )
        toggle = ForwardingToggle(
            name=name,
            status=DataStatus.KNOWN if known else DataStatus.UNKNOWN,
            value=claims_toggle[0][0] if known else None,
            location=anchor(claims_toggle[0][1]) if claims_toggle else None,
        )
        toggles.append(toggle)
        if toggle.location is not None:
            source_map[f"toggle:{name}"] = toggle.location.location

    locations: dict[ForwardingFeature, list[ForwardingLocation]] = {
        "interfaces": [item.location for item in interfaces],
        "acl_definitions": [item.location for item in acls],
        "acl_bindings": [item.location for item in bindings],
        "same_security": [
            item.location for item in toggles if item.name != "permit_vpn" and item.location
        ],
        "vpn_bypass": [
            item.location for item in toggles if item.name == "permit_vpn" and item.location
        ],
        "configured_nat": extra_locations["configured_nat"],
        "effective_nat": [],
        "pbr": extra_locations["pbr"],
        "exceptions": extra_locations["exceptions"],
    }
    inventories: list[FeatureInventory] = []
    for feature in FEATURE_SCOPES:
        count = len(locations[feature])
        if feature == "same_security":
            count = 2
        elif feature == "vpn_bypass":
            count = 1
        enumeration = scope_complete(feature) and len(locations[feature]) >= count
        semantic = enumeration
        if feature == "interfaces":
            semantic = semantic and all(
                item.physical_l3 is True and item.security_status == DataStatus.KNOWN
                for item in interfaces
            )
        elif feature == "acl_definitions":
            semantic = semantic and all(item.complete for item in acls)
        elif feature in {"same_security", "vpn_bypass"}:
            semantic = semantic and all(
                item.status == DataStatus.KNOWN
                for item in toggles
                if (item.name == "permit_vpn") == (feature == "vpn_bypass")
            )
        detected_unsupported = feature in {"configured_nat", "pbr", "exceptions"} and count > 0
        status: Literal[
            DataStatus.KNOWN, DataStatus.ABSENT, DataStatus.UNKNOWN, DataStatus.UNSUPPORTED
        ] = DataStatus.UNKNOWN
        if detected_unsupported:
            status = DataStatus.UNSUPPORTED
            semantic = False
        elif semantic:
            status = DataStatus.KNOWN if count else DataStatus.ABSENT
        diagnostics = () if semantic else ("Полнота или семантика области не доказана.",)
        inventories.append(
            FeatureInventory(
                feature=feature,
                status=status,
                item_count=count,
                complete=semantic,
                enumeration_complete=enumeration,
                source_document_ids=(metadata.source_document_id,),
                locations=tuple(locations[feature]),
                reference=metadata.completeness_reference if enumeration else None,
                diagnostics=diagnostics,
            )
        )
        for index, location in enumerate(locations[feature]):
            source_map[f"inventory:{feature}:{index}"] = location.location

    if any(item.status == DataStatus.UNKNOWN for item in inventories):
        warnings.append(
            ParseIssue(
                code="ASA_FORWARDING_INCOMPLETE",
                level=ParseIssueLevel.WARNING,
                message="Неизвестные области сохранены; effective NAT конфигурацией не доказан.",
            )
        )
    context = ForwardingContext(
        revision_id=request.revision_id,
        configuration_id=request.configuration_id,
        device_id=metadata.device_id,
        device_context=metadata.device_context,
        context_mode=request.context_mode,
        firewall_mode=request.firewall_mode,
        address_family=request.address_family,
        table_role=request.table_role,
        table_id=request.table_id,
        profile_reference=request.profile_reference,
        imported_at=request.imported_at,
        observed_at=metadata.observation.observed_at if metadata.observation else None,
        sources=(metadata,),
        inventories=tuple(inventories),
        interfaces=tuple(interfaces),
        acls=tuple(acls),
        bindings=tuple(bindings),
        toggles=tuple(toggles),
    )
    return ForwardingParseResult(
        context=context,
        warnings=tuple(warnings),
        errors=tuple(errors),
        unsupported_constructs=tuple(unsupported),
        source_map=source_map,
        coverage=ParseCoverage(
            discovered_constructs=discovered,
            recognized_constructs=discovered - len(rejected_lines | failed_lines),
            unsupported_constructs=len(rejected_lines),
        ),
    )
