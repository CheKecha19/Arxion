"""Нормализация объявлений SG из сохранённого сбора Cloud.ru без обращения к API."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from ipaddress import ip_address, ip_network
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from firewall_compliance.domain.cloud_security_groups import (
    CloudSecurityGroupSnapshot,
    CloudSGAssignment,
    CloudSGDeclaration,
    CloudSGDiagnostic,
    CloudSGInterface,
    CloudSGPeer,
    CloudSGPlatform,
    CloudSGRule,
    CloudSGService,
    SGDirection,
    SGResolution,
    SGStatus,
)
from firewall_compliance.domain.network import PortRange
from firewall_compliance.domain.source import SourceLocation

type AddressFamily = Literal[4, 6]
type RuleAction = Literal["allow", "deny", "unknown"]
type ScanStatus = Literal["completed", "partial", "failed", "cancelled", "interrupted", "unknown"]

_PROTOCOL_NUMBERS = {"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "icmpv6": 58}
_PORT_RANGE = re.compile(r"([0-9]{1,5})(?:\s*[:-]\s*([0-9]{1,5}))?")


def _object(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string(value: object) -> str | None:
    return (value.strip() or None) if isinstance(value, str) else None


def _identifier(value: object) -> str | None:
    text = _string(value.get("id") if isinstance(value, Mapping) else value)
    if text is None or any(char.isspace() or ord(char) < 32 for char in text):
        return None
    try:
        return str(UUID(text))
    except ValueError:
        return text


def _number(value: object, low: int, high: int) -> int | None:
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value.strip()):
        value = int(value)
    return value if type(value) is int and low <= value <= high else None


def _token(value: object) -> str | None:
    text = _string(value)
    return text.casefold() if text else None


def _digest(value: object) -> str:
    digest = sha256()
    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    for chunk in encoder.iterencode(value):
        digest.update(chunk.encode("utf-8"))
    return digest.hexdigest()


def _aware_time(value: object) -> datetime | None:
    text = _string(value)
    if text is not None:
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.utcoffset() is not None:
            return parsed
    return None


def _capture_time(scan: Mapping[str, Any]) -> datetime:
    captured = _aware_time(scan.get("finished_at")) or _aware_time(scan.get("created_at"))
    if captured is not None:
        return captured
    raise ValueError("В сохранённом облачном сборе отсутствует время с часовым поясом.")


def _scan_status(value: object) -> ScanStatus:
    if value == "completed":
        return "completed"
    if value == "partial":
        return "partial"
    if value == "failed":
        return "failed"
    if value == "cancelled":
        return "cancelled"
    if value == "interrupted":
        return "interrupted"
    return "unknown"


def _endpoint_host(value: object) -> str | None:
    url = _string(value)
    if url is None:
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _location(source: str, path: str, identifier: str | None = None) -> SourceLocation:
    return SourceLocation(source_name=source, object_path=path, object_id=identifier)


def _family(raw: Mapping[str, Any]) -> AddressFamily | None:
    values = {
        _token(raw[key]) for key in ("ethertype", "ether_type") if raw.get(key) is not None
    }
    if values and values <= {"ipv4", "ether_type_ipv4"}:
        return 4
    if values and values <= {"ipv6", "ether_type_ipv6"}:
        return 6
    return None


def _direction(value: object) -> SGDirection | None:
    token = _token(value)
    if token in {"ingress", "traffic_direction_ingress"}:
        return "ingress"
    if token in {"egress", "traffic_direction_egress"}:
        return "egress"
    return None


def _protocol(raw: Mapping[str, Any], platform: CloudSGPlatform) -> str | int | None:
    fields = ("ip_protocol", "protocol") if platform == "evolution" else ("protocol",)
    values: set[str | int | None] = set()
    for field in fields:
        if field not in raw:
            continue
        value = raw[field]
        token = _token(value)
        if token is not None:
            token = token.removeprefix("ip_protocol_")
        if token in {"any", "all"} or (value is None and platform == "advanced"):
            values.add("any")
        elif token == "ipv6-icmp":
            values.add(58)
        elif token is not None and token in _PROTOCOL_NUMBERS:
            values.add(_PROTOCOL_NUMBERS[token])
        else:
            values.add(_number(value, 0, 255))
    return next(iter(values)) if len(values) == 1 else None


def _port_range(value: object) -> PortRange | None:
    match = _PORT_RANGE.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        return None
    low = int(match[1])
    high = int(match[2] or match[1])
    return PortRange(start=low, end=high) if 1 <= low <= high <= 65535 else None


def _ports(raw: Mapping[str, Any], platform: CloudSGPlatform) -> tuple[PortRange, ...] | None:
    """Пустой кортеж обозначает явно указанный диапазон всех портов."""
    low, high = raw.get("port_range_min"), raw.get("port_range_max")
    values: tuple[PortRange, ...] | None = None
    if "port_range_min" in raw or "port_range_max" in raw:
        if low is None and high is None and {"port_range_min", "port_range_max"} <= raw.keys():
            values = ()
        else:
            start, end = _number(low, 1, 65535), _number(high, 1, 65535)
            if start is None or end is None or start > end:
                return None
            values = (PortRange(start=start, end=end),)
    if platform == "evolution" and "port_range" in raw:
        expression = raw["port_range"]
        port_range = _port_range(expression)
        if expression in (None, "") or _token(expression) == "any":
            parsed: tuple[PortRange, ...] = ()
        elif port_range is not None:
            parsed = (port_range,)
        else:
            return None
        if values is not None and values != parsed:
            return None
        values = parsed
    return values


def _service(
    raw: Mapping[str, Any], platform: CloudSGPlatform, family: AddressFamily | None,
) -> CloudSGService | None:
    protocol = _protocol(raw, platform)
    if protocol in (6, 17):
        ports = _ports(raw, platform)
        if ports is None:
            return None
        return CloudSGService(
            protocol="tcp" if protocol == 6 else "udp", ports=ports, any_ports=not ports,
        )
    if protocol in (1, 58):
        if (family == 4 and protocol == 58) or (family == 6 and protocol == 1):
            return None
        if platform == "evolution" and protocol != 1:
            return None
        if raw.get("port_range") not in (None, "", "any", "ANY"):
            return None
        raw_type, raw_code = raw.get("port_range_min"), raw.get("port_range_max")
        icmp_type, icmp_code = _number(raw_type, 0, 255), _number(raw_code, 0, 255)
        if (raw_type is not None and icmp_type is None) or (raw_code is not None and icmp_code is None):
            return None
        return CloudSGService(
            protocol="icmp" if protocol == 1 else "icmpv6", icmp_type=icmp_type, icmp_code=icmp_code,
        )
    if (
        raw.get("port_range_min") is not None or raw.get("port_range_max") is not None
        or raw.get("port_range") not in (None, "", "any", "ANY")
    ):
        return None
    if protocol == "any":
        return CloudSGService(protocol="any")
    if type(protocol) is int and platform == "advanced":
        return CloudSGService(protocol="number", protocol_number=protocol)
    return None


def _action(raw: Mapping[str, Any], platform: CloudSGPlatform) -> RuleAction:
    action = _token(raw.get("action"))
    if platform == "evolution":
        # В API Evolution действие отдельно не хранится: это набор разрешений.
        return "allow" if "action" not in raw or action == "allow" else "unknown"
    if action == "allow":
        return "allow"
    if action == "deny":
        return "deny"
    return "unknown"


def _project(raw: Mapping[str, Any]) -> str | None:
    return _identifier(raw.get("project_id")) or _identifier(raw.get("tenant_id"))


def _zone(raw: Mapping[str, Any]) -> str | None:
    return _identifier(raw.get("zone")) or _identifier(raw.get("zone_id"))


def _different(left: str | None, right: str | None) -> bool:
    return left is not None and right is not None and left != right


def _invalid_context(raw: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    values = [_identifier(raw[field]) for field in fields if raw.get(field) is not None]
    return None in values or len(set(values)) > 1


def _group_reference(
    group_id: str, groups: Mapping[str, CloudSGDeclaration], project_id: str | None, zone_id: str | None,
) -> SGResolution:
    group = groups.get(group_id)
    if group is None:
        return "missing"
    if group.rules_status == "ambiguous":
        return "ambiguous"
    if (
        group.rules_status == "outside_scope"
        or _different(project_id, group.project_id)
        or _different(zone_id, group.zone_id)
    ):
        return "outside_scope"
    return "present"


def _peer(
    raw: Mapping[str, Any], family: AddressFamily | None, group: CloudSGDeclaration,
    groups: Mapping[str, CloudSGDeclaration],
) -> CloudSGPeer:
    if any(raw.get(key) is not None and _identifier(raw[key]) is None
           for key in ("remote_group_id", "remote_security_group", "remote_address_group_id")):
        return CloudSGPeer(kind="unknown")
    if any(raw.get(key) is not None and not isinstance(raw[key], str)
           for key in ("remote_ip_prefix", "remote_cidr")):
        return CloudSGPeer(kind="unknown")
    cidrs = {raw[key] for key in ("remote_ip_prefix", "remote_cidr")
             if isinstance(raw.get(key), str) and raw[key].strip()}
    sg_ids = {
        value for key in ("remote_group_id", "remote_security_group")
        if (value := _identifier(raw.get(key))) is not None
    }
    address_group = _identifier(raw.get("remote_address_group_id"))
    if len(cidrs) + len(sg_ids) + bool(address_group) != 1:
        return CloudSGPeer(kind="unknown")
    if cidrs:
        cidr = next(iter(cidrs))
        try:
            network = ip_network(cidr, strict=False)
        except ValueError:
            return CloudSGPeer(kind="unknown")
        if family is None or network.version != family or "%" in cidr:
            return CloudSGPeer(kind="unknown")
        return CloudSGPeer(kind="network", cidr=str(network))
    if sg_ids:
        identifier = next(iter(sg_ids))
        return CloudSGPeer(
            kind="security_group", reference_id=identifier,
            reference_state=_group_reference(identifier, groups, group.project_id, group.zone_id),
        )
    return CloudSGPeer(kind="address_group", reference_id=address_group, reference_state="missing")


def _rule(
    raw: Mapping[str, Any], group: CloudSGDeclaration, groups: Mapping[str, CloudSGDeclaration],
    platform: CloudSGPlatform, source: str, path: str,
) -> CloudSGRule:
    identifier = _identifier(raw.get("id"))
    family = _family(raw)
    direction = _direction(raw.get("direction"))
    action = _action(raw, platform) if raw else "unknown"
    priority = _number(raw.get("priority"), 1, 100) if platform == "advanced" else None
    limitations = []
    if identifier is None:
        limitations.append("Идентификатор правила API отсутствует.")
    if family is None or (platform == "evolution" and family != 4):
        limitations.append("Семейство адресов отсутствует или не поддерживается.")
        family = None
    if direction is None:
        limitations.append("Направление правила неизвестно.")
    if action == "unknown":
        limitations.append("Действие правила не установлено.")
    if platform == "advanced" and priority is None:
        limitations.append("Приоритет правила Advanced не подтверждён.")
    service = _service(raw, platform, family)
    if service is None:
        limitations.append("Не удалось определить условия протокола и портов.")
    peer = _peer(raw, family, group, groups)
    if peer.kind == "unknown" or peer.reference_state not in {None, "present"}:
        limitations.append("Удалённая сторона правила не подтверждена в области этого сбора.")
    owner = _identifier(raw.get("security_group_id")) or _identifier(raw.get("security_group"))
    if (
        _invalid_context(raw, ("security_group_id", "security_group"))
        or _invalid_context(raw, ("project_id", "tenant_id"))
        or _different(owner, group.group_id)
        or _different(_project(raw), group.project_id)
    ):
        action = "unknown"
        limitations.append("В правиле указана другая группа или другой проект.")
    enabled = raw.get("enabled")
    return CloudSGRule(
        rule_id=identifier, direction=direction, family=family, action=action, priority=priority,
        enabled=enabled if type(enabled) is bool else None, provider_status=_string(raw.get("status")),
        service=service, peer=peer, location=_location(source, path, identifier), limitations=tuple(limitations),
    )


@dataclass(frozen=True, slots=True)
class _InterfaceObservation:
    raw: Mapping[str, Any]
    location: SourceLocation
    vm_id: str | None
    authoritative_membership: bool


def _interface_addresses(raw: Mapping[str, Any], platform: CloudSGPlatform) -> tuple[str, ...] | None:
    if platform == "advanced":
        fixed = raw.get("fixed_ips")
        if not isinstance(fixed, list):
            return None
        values = [_object(entry).get("ip_address") for entry in fixed]
    elif "ip_address" in raw:
        values = [raw["ip_address"]]
    else:
        return None
    addresses: set[str] = set()
    for value in values:
        try:
            if not isinstance(value, str) or "%" in value:
                return None
            address = ip_address(value)
        except ValueError:
            return None
        if platform == "evolution" and address.version != 4:
            return None
        addresses.add(str(address))
    return tuple(sorted(addresses))


def _single[T](values: Sequence[T | None]) -> T | None:
    first = next((value for value in values if value is not None), None)
    return first if all(value is None or value == first for value in values) else None


def _memberships(
    observations: Sequence[_InterfaceObservation], source: str,
) -> tuple[dict[str, list[SourceLocation]], SGStatus]:
    observed: dict[str, list[SourceLocation]] = defaultdict(list)
    sets: set[frozenset[str]] = set()
    invalid = False
    for item in observations:
        if not item.authoritative_membership or "security_groups" not in item.raw:
            continue
        raw_members = item.raw["security_groups"]
        if not isinstance(raw_members, list):
            invalid = True
            continue
        identifiers = set()
        for position, raw in enumerate(raw_members):
            identifier = _identifier(raw)
            if identifier is None or identifier in identifiers:
                invalid = True
                continue
            identifiers.add(identifier)
            observed[identifier].append(_location(
                source, f"{item.location.object_path}/security_groups/{position}", identifier,
            ))
        sets.add(frozenset(identifiers))
    if len(sets) > 1:
        return observed, "ambiguous"
    if invalid:
        return observed, "partial"
    return observed, "present" if sets else "missing"


def _interface(
    interface_id: str, observations: Sequence[_InterfaceObservation], platform: CloudSGPlatform,
    scope: str, project_id: str | None, groups: Mapping[str, CloudSGDeclaration], source: str,
) -> CloudSGInterface:
    projects = [_project(item.raw) for item in observations]
    zones = [_zone(item.raw) for item in observations]
    networks = [
        _identifier(item.raw.get("network_id")) or _identifier(item.raw.get("net_id"))
        for item in observations
    ]
    subnets = [
        _identifier(item.raw.get("subnet")) or _identifier(item.raw.get("subnet_id"))
        for item in observations
    ]
    addresses = [_interface_addresses(item.raw, platform) for item in observations]
    vms = [item.vm_id for item in observations]
    flags = [
        item.raw[key] for item in observations for key in ("interface_security_enabled", "port_security_enabled")
        if item.raw.get(key) is not None
    ]
    security = [value for value in flags if type(value) is bool]
    observed, status = _memberships(observations, source)
    if project_id is None or any(_different(value, project_id) for value in projects):
        status = "outside_scope"
    elif (
        any(len({value for value in values if value is not None}) > 1
            for values in (projects, zones, networks, subnets, addresses, vms, security))
        or len(flags) != len(security)
        or any(
            _invalid_context(item.raw, ("project_id", "tenant_id"))
            or _invalid_context(item.raw, ("zone", "zone_id"))
            or _invalid_context(item.raw, ("subnet", "subnet_id"))
            or _invalid_context(item.raw, ("vm", "vm_id"))
            or _invalid_context(item.raw, ("network_id", "net_id"))
            for item in observations
        )
    ):
        status = "ambiguous"
    zone = _single(zones)
    assignments = []
    for group_id, locations in observed.items():
        state: SGResolution = (
            status if status in ("outside_scope", "ambiguous")
            else _group_reference(group_id, groups, project_id, zone)
        )
        assignments.append(CloudSGAssignment(
            group_id=group_id, state=state, locations=tuple(locations),
        ))
    return CloudSGInterface(
        interface_id=interface_id,
        name=_single([_string(item.raw.get("name")) for item in observations]) or interface_id,
        scope_id=scope, project_id=_single(projects) or project_id, vm_id=_single(vms), subnet_id=_single(subnets),
        zone_id=zone, network_id=_single(networks), addresses=_single(addresses) or (),
        security_enabled=_single(security), assignments=tuple(assignments), assignments_status=status,
        locations=tuple(item.location for item in observations),
    )


@dataclass(frozen=True, slots=True)
class CloudSGScanHeader:
    platform: CloudSGPlatform
    scan_id: str
    scope_id: str
    scope_data: Mapping[str, str | None]
    captured_at: datetime
    started_at: datetime
    workspace_site_ids: tuple[str, ...]


def security_group_scan_header(scan: Mapping[str, Any]) -> CloudSGScanHeader:
    """Восстановить идентификаторы и область сбора без разбора его записей."""
    config = _object(scan.get("config"))
    raw_platform = config.get("platform")
    scan_id = _string(scan.get("id"))
    if raw_platform not in ("advanced", "evolution") or scan_id is None:
        raise ValueError("Выберите сохранённый сбор Cloud.ru Advanced или Evolution.")
    platform: CloudSGPlatform = "advanced" if raw_platform == "advanced" else "evolution"
    captured = _capture_time(scan)
    project = _identifier(config.get("project_id"))
    scope_data = {
        "workspace": _string(scan.get("project_id")), "platform": platform, "project": project,
        "region": _string(config.get("region")),
        "vpc_endpoint": _endpoint_host(config.get("vpc_endpoint")),
        "ecs_endpoint": _endpoint_host(config.get("ecs_endpoint")),
    }
    reusable_scope = project is not None and (platform == "evolution" or scope_data["region"] is not None)
    scope = f"cloud-sg:{_digest(scope_data)}" if reusable_scope else f"cloud-sg:scan:{_digest((scope_data, scan_id))}"
    raw_sites = _object(scan.get("selection")).get("workspace_site_ids")
    sites = tuple(dict.fromkeys(
        value for value in raw_sites if isinstance(value, str) and value
    )) if isinstance(raw_sites, (list, tuple)) else ()
    return CloudSGScanHeader(
        platform, scan_id, scope, scope_data, captured, _aware_time(scan.get("created_at")) or captured, sites,
    )


def security_group_snapshot(scan: Mapping[str, Any]) -> CloudSecurityGroupSnapshot:
    """Разобрать объявления и ссылки одного сохранённого сбора. O(записи + правила + связи)."""
    header = security_group_scan_header(scan)
    platform, scan_id, scope = header.platform, header.scan_id, header.scope_id
    project = header.scope_data["project"]
    captured = header.captured_at
    source = f"Cloud.ru {platform.capitalize()} / {scan_id}"
    result = _object(scan.get("result"))
    records = result.get("records")
    diagnostics = []
    if not isinstance(records, list):
        diagnostics.append(CloudSGDiagnostic(
            code="missing_records", message="В сборе нет списка записей.",
            location=_location(source, "/result/records"),
        ))
        records = []
    if project is None:
        diagnostics.append(CloudSGDiagnostic(
            code="unknown_project", message="Облачный проект сбором не подтверждён.",
            location=_location(source, "/config/project_id"),
        ))
    source_records: list[int] = []
    group_records: dict[str, list[tuple[Mapping[str, Any], str]]] = defaultdict(list)
    interface_records: dict[str, list[_InterfaceObservation]] = defaultdict(list)

    def interface(
        raw: object, path: str, vm_id: str | None, explicit: bool, record_id: str | None = None,
    ) -> None:
        value = _object(raw)
        field = "id" if platform == "evolution" or explicit else "port_id"
        identifier = _identifier(value.get(field)) or record_id
        declared_vm = _identifier(value.get("vm")) or _identifier(value.get("vm_id"))
        if platform == "advanced" and explicit:
            declared_vm = _identifier(value.get("device_id"))
        if not value or not identifier or _different(identifier, record_id) or _different(declared_vm, vm_id):
            diagnostics.append(CloudSGDiagnostic(
                code="invalid_interface", message="Идентичность интерфейса не подтверждена.",
                location=_location(source, path, identifier),
            ))
            return
        interface_records[identifier].append(_InterfaceObservation(
            value, _location(source, path, identifier), vm_id or declared_vm, explicit,
        ))

    def advanced_port(attachment: Mapping[str, Any], path: str, vm_id: str) -> None:
        if attachment.get("vpc_port_status") != "present":
            return
        port = _object(attachment.get("vpc_port"))
        attachment_id = _identifier(attachment.get("port_id"))
        network = _identifier(attachment.get("net_id"))
        if (
            attachment_id is None or _identifier(port.get("id")) != attachment_id
            or _identifier(port.get("device_id")) != vm_id
            or _different(network, _identifier(port.get("network_id")))
        ):
            diagnostics.append(CloudSGDiagnostic(
                code="invalid_port_scope", message="Связь порта VPC с интерфейсом ECS не подтверждена.",
                location=_location(source, path, attachment_id),
            ))
            return
        interface(port, path, vm_id, True, attachment_id)

    for index, record in enumerate(records):
        path = f"/result/records/{index}"
        if not isinstance(record, Mapping):
            diagnostics.append(CloudSGDiagnostic(
                code="invalid_record", message="Некорректная запись сбора.",
                location=_location(source, path),
            ))
            source_records.append(index)
            continue
        kind = record.get("type")
        identifier = _identifier(record.get("id"))
        inventory = _object(record.get("inventory"))
        if kind == "security_groups":
            source_records.append(index)
            if identifier is None:
                diagnostics.append(CloudSGDiagnostic(
                    code="missing_group_id", message="У SG отсутствует ID.",
                    location=_location(source, path),
                ))
            else:
                group_records[identifier].append((record, path))
        elif (
            (kind == "interfaces" and platform == "evolution")
            or (kind == "ports" and platform == "advanced")
        ):
            source_records.append(index)
            interface(inventory, f"{path}/inventory", None, True, identifier)
        elif kind == "vms":
            vm_networks = _object(record.get("data")).get("vm_networks")
            if not isinstance(vm_networks, list):
                continue
            source_records.append(index)
            if (
                identifier is None or _different(_identifier(inventory.get("id")), identifier)
                or _invalid_context(inventory, ("project_id", "tenant_id"))
                or _different(_project(inventory), project)
            ):
                diagnostics.append(CloudSGDiagnostic(
                    code="invalid_vm_scope", message="Связь интерфейсов с ВМ в области сбора не подтверждена.",
                    location=_location(source, path, identifier),
                ))
                continue
            for position, raw in enumerate(vm_networks):
                interface_path = f"{path}/data/vm_networks/{position}"
                interface(raw, interface_path, identifier, platform == "evolution")
                if platform == "advanced":
                    advanced_port(_object(raw), f"{interface_path}/vpc_port", identifier)

    groups: dict[str, CloudSGDeclaration] = {}
    for identifier, entries in group_records.items():
        first, _ = entries[0]
        inventory = _object(first.get("inventory"))
        declared_project = _project(inventory)
        status: SGStatus = "missing"
        if (
            len(entries) > 1 or _different(_identifier(inventory.get("id")), identifier)
            or _invalid_context(inventory, ("project_id", "tenant_id"))
            or _invalid_context(inventory, ("zone", "zone_id"))
        ):
            status = "ambiguous"
        elif project is None or _different(project, declared_project):
            status = "outside_scope"
        groups[identifier] = CloudSGDeclaration(
            group_id=identifier, name=_string(first.get("name")) or identifier, scope_id=scope,
            project_id=declared_project or project, zone_id=_zone(inventory),
            network_id=_identifier(inventory.get("vpc_id")),
            locations=tuple(_location(source, path, identifier) for _, path in entries), rules_status=status,
        )
    for identifier, group in groups.items():
        if group.rules_status != "missing":
            continue
        record, path = group_records[identifier][0]
        raw_rules = _object(record.get("data")).get("security_rules")
        if not isinstance(raw_rules, list):
            continue
        rules = tuple(
            _rule(_object(raw), group, groups, platform, source, f"{path}/data/security_rules/{position}")
            for position, raw in enumerate(raw_rules)
        )
        duplicates = Counter(rule.rule_id for rule in rules if rule.rule_id is not None)
        if any(count > 1 for count in duplicates.values()):
            rules = tuple(
                rule.model_copy(update={
                    "action": "unknown", "limitations": (*rule.limitations, "ID правила повторяется в группе."),
                }) if rule.rule_id is not None and duplicates[rule.rule_id] > 1 else rule for rule in rules
            )
        groups[identifier] = group.model_copy(update={
            "rules": rules, "rules_status": "partial" if any(rule.limitations for rule in rules) else "present",
        })
    scan_status = _scan_status(scan.get("state", result.get("state")))
    selection = _object(scan.get("selection"))
    return CloudSecurityGroupSnapshot(
        platform=platform, scope_id=scope, scan_id=scan_id, scan_status=scan_status,
        captured_at=captured, project_id=project, record_indices=tuple(source_records),
        workspace_site_ids=header.workspace_site_ids,
        source_sha256=_digest({
            "scope": dict(header.scope_data), "scan_id": scan_id, "status": scan_status,
            "captured_at": captured.isoformat(),
            "selection": dict(selection), "result": dict(result),
        }),
        rule_semantics="advanced_priority" if platform == "advanced" else "evolution_allow_union",
        groups=tuple(groups.values()),
        interfaces=tuple(_interface(key, values, platform, scope, project, groups, source)
                         for key, values in interface_records.items()),
        diagnostics=tuple(diagnostics),
    )
