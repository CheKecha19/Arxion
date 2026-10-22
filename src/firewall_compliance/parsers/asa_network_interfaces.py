"""Узкий разбор физических IPv4-интерфейсов ASA."""

import re
from collections import Counter
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface

from firewall_compliance.domain import (
    DataOrigin,
    DataStatus,
    Interface,
    ParseCoverage,
    ParseIssue,
    ParseIssueLevel,
    SourceLocation,
    UnsupportedConstruct,
)
from firewall_compliance.parsers.asa_network_common import ParsedNetworkFacts
from firewall_compliance.parsers.network_contracts import InterfaceSettings, NetworkParseRequest

_PHYSICAL = re.compile(r"(?:GigabitEthernet|Ethernet)[0-9]+/[0-9]+")


@dataclass
class _Block:
    start: int
    end: int
    name: str | None
    label: str | None = None
    security_level: int | None = None
    addresses: tuple[str, ...] = ()
    addresses_status: DataStatus = DataStatus.UNKNOWN
    enabled: bool | None = None
    status: DataStatus = DataStatus.KNOWN
    seen: set[str] = field(default_factory=set)
    invalid: set[str] = field(default_factory=set)
    settings_locations: list[SourceLocation] = field(default_factory=list)


def parse_interfaces(request: NetworkParseRequest, text: str) -> ParsedNetworkFacts:
    """Сохранить явные факты, неизвестность и неподдержанные строки."""
    blocks: list[_Block] = []
    current: _Block | None = None
    errors: list[ParseIssue] = []
    warnings: list[ParseIssue] = []
    unsupported: list[UnsupportedConstruct] = []
    label_claims: Counter[str] = Counter()
    discovered = recognized = 0

    def location(start: int, end: int | None = None) -> SourceLocation:
        return SourceLocation(
            source_name=request.source.source_name, line_start=start, line_end=end or start
        )

    def error(code: str, message: str, number: int) -> None:
        errors.append(
            ParseIssue(
                code=code,
                level=ParseIssueLevel.ERROR,
                message=message,
                source_location=location(number),
            )
        )

    def reject(number: int, message: str) -> None:
        unsupported.append(
            UnsupportedConstruct(
                construct_type="asa_interface", message=message, source_location=location(number)
            )
        )
        warnings.append(
            ParseIssue(
                code="ASA_INTERFACE_UNSUPPORTED",
                level=ParseIssueLevel.WARNING,
                message=message,
                source_location=location(number),
            )
        )

    for number, raw in enumerate(text.splitlines(), 1):
        statement = raw.strip()
        if not statement:
            continue
        if statement.startswith("!"):
            current = None
            continue
        discovered += 1
        tokens = statement.split()
        if tokens[0] == "interface":
            name = tokens[1] if len(tokens) == 2 and _PHYSICAL.fullmatch(tokens[1]) else None
            current = _Block(start=number, end=number, name=name)
            blocks.append(current)
            if name is None:
                reject(number, "Неподдержанный или повреждённый заголовок интерфейса")
            else:
                recognized += 1
            continue
        if len(tokens) == 2 and tokens[0] == "nameif" and len(tokens[1]) <= 48:
            label_claims[tokens[1].casefold()] += 1
        if current is None or not raw[:1].isspace():
            current = None
            reject(number, "Команда вне поддержанного блока интерфейса")
            continue
        current.end = number
        if current.name is None:
            reject(number, "Команда неподдержанного интерфейса")
            continue

        key: str | None = None
        if tokens[0] in {"nameif", "security-level"}:
            key = tokens[0]
        elif tokens[:2] == ["ip", "address"] or tokens[:3] == ["no", "ip", "address"]:
            key = "address"
        elif tokens[0] == "shutdown" or tokens[:2] == ["no", "shutdown"]:
            key = "enabled"
        if key is not None and key in current.seen:
            current.invalid.add(key)
            current.status = DataStatus.UNKNOWN
            error("ASA_INTERFACE_DUPLICATE_ATTRIBUTE", "Повторная настройка интерфейса", number)
            continue
        if key is not None:
            current.seen.add(key)
        valid = True
        if key == "nameif":
            if len(tokens) == 2 and len(tokens[1]) <= 48:
                current.label = tokens[1]
                current.settings_locations.append(location(number))
            else:
                valid = False
        elif key == "security-level":
            if len(tokens) == 2 and re.fullmatch(r"[0-9]{1,3}", tokens[1]):
                value = int(tokens[1])
                if 0 <= value <= 100:
                    current.security_level = value
                    current.settings_locations.append(location(number))
                else:
                    valid = False
            else:
                valid = False
        elif key == "enabled":
            if tokens == ["shutdown"]:
                current.enabled = False
            elif tokens == ["no", "shutdown"]:
                current.enabled = True
            else:
                valid = False
        elif key == "address":
            if tokens == ["no", "ip", "address"]:
                current.addresses_status = DataStatus.ABSENT
            elif len(tokens) >= 3 and tokens[2] in {"dhcp", "pppoe"}:
                current.addresses_status = DataStatus.UNSUPPORTED
                current.status = DataStatus.UNSUPPORTED
                reject(number, "Динамическая адресация не поддерживается: " + statement)
                continue
            elif len(tokens) == 4 and tokens[:2] == ["ip", "address"]:
                try:
                    host = IPv4Address(tokens[2])
                    if host.is_unspecified or host.is_multicast or int(host) == 0xFFFFFFFF:
                        raise ValueError("интерфейс требует конкретный unicast IPv4")
                    mask = int(IPv4Address(tokens[3]))
                    inverse = mask ^ 0xFFFFFFFF
                    if inverse & (inverse + 1):
                        raise ValueError("непрерывная маска обязательна")
                    prefix = mask.bit_count()
                    current.addresses = (str(IPv4Interface(f"{host}/{prefix}")),)
                    current.addresses_status = DataStatus.KNOWN
                except ValueError:
                    valid = False
            else:
                valid = False
        else:
            current.status = DataStatus.UNSUPPORTED
            if tokens[0] == "ipv6":
                current.addresses_status = DataStatus.UNSUPPORTED
            reject(number, "Неподдержанная настройка интерфейса: " + statement)
            continue
        if valid:
            recognized += 1
        else:
            current.invalid.add(key or "unknown")
            current.status = DataStatus.UNKNOWN
            error("ASA_INTERFACE_INVALID_ATTRIBUTE", "Повреждённая настройка интерфейса", number)

    names = Counter(block.name for block in blocks if block.name is not None)
    interfaces: list[Interface] = []
    settings: list[InterfaceSettings] = []
    labels: dict[str, str] = {}
    for block in blocks:
        if block.name is None:
            continue
        if names[block.name] > 1:
            error("ASA_INTERFACE_DUPLICATE_ID", "Повторный физический интерфейс", block.start)
            continue
        label = block.label if "nameif" not in block.invalid else None
        if label is not None and label_claims[label.casefold()] > 1:
            error("ASA_INTERFACE_DUPLICATE_LABEL", "Неоднозначная привязка nameif", block.start)
            block.status = DataStatus.UNKNOWN
        interface_id = "interface:" + block.name
        if label is not None and block.status == DataStatus.KNOWN:
            labels[label.casefold()] = interface_id
        interfaces.append(
            Interface(
                interface_id=interface_id,
                name=block.name,
                device_id=request.metadata.device_id,
                origin=DataOrigin.IMPORTED,
                data_status=block.status,
                source_document_id=request.metadata.source_document_id,
                source_location=location(block.start, block.end),
                addresses=() if "address" in block.invalid else block.addresses,
                addresses_status=(
                    DataStatus.UNKNOWN if "address" in block.invalid else block.addresses_status
                ),
                enabled=None if "enabled" in block.invalid else block.enabled,
            )
        )
        settings.append(
            InterfaceSettings(
                interface_id=interface_id,
                label=label,
                security_level=(
                    None if "security-level" in block.invalid else block.security_level
                ),
                source_locations=tuple(block.settings_locations),
            )
        )
    return ParsedNetworkFacts(
        interfaces=tuple(interfaces),
        interface_labels=labels,
        interface_settings=tuple(settings),
        errors=tuple(errors),
        warnings=tuple(warnings),
        unsupported_constructs=tuple(unsupported),
        coverage=ParseCoverage(
            discovered_constructs=discovered,
            recognized_constructs=recognized,
            unsupported_constructs=len(unsupported),
        ),
    )
