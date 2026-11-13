"""Project-wide inventory and declared ACL relationships, independent of Qt."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

from firewall_compliance.application.asset_catalog import CatalogObservation, SnapshotAddressIndex
from firewall_compliance.application.cloud_analysis import vmware_record_revision
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus, EndpointKind
from firewall_compliance.domain.network import Endpoint
from firewall_compliance.domain.revision import DeviceRevision, Interface
from firewall_compliance.interfaces.desktop.cloud_map_references import (
    canonical_cloud_reference,
    cloud_references,
    vdc_reference,
)
from firewall_compliance.interfaces.desktop.cloud_rule_presentation import security_group_action

CONTOUR = "contour"
EXTERNAL = "external"


def identity(*parts: object) -> str:
    return sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:24]


def cloud_area(config: Mapping[str, Any]) -> str:
    fields = {
        key: config.get(key, "vmware" if key == "platform" else None)
        for key in ("platform", "site", "tenant", "project_id", "region")
    }
    fields.update({key: config[key] for key in ("ecs_endpoint", "vpc_endpoint") if config.get(key)})
    return "cloud:" + identity(fields)


def subnet_zone(address: str) -> str:
    """IPv4 groups use the first three octets; no address space is expanded."""
    try:
        network = ip_network(address, strict=False)
    except ValueError:
        return "Без адреса"
    prefix = 24 if network.version == 4 else 64
    if network.prefixlen < prefix:
        return str(network)
    return str(ip_network(f"{network.network_address}/{prefix}", strict=False))


def _private(address: str) -> bool:
    network = ip_network(address, strict=False)
    ranges: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
    if network.version == 6:
        ranges = ("fc00::/7", "fe80::/10")
    return any(
        network.version == (other := ip_network(value)).version
        and int(network.network_address) >= int(other.network_address)
        and int(network.broadcast_address) <= int(other.broadcast_address)
        for value in ranges
    )


@dataclass(frozen=True)
class ProjectMapNode:
    key: str
    label: str
    kind: str
    area: str
    zone: str
    addresses: tuple[str, ...] = ()
    details: tuple[str, ...] = ()
    scope: str = ""


@dataclass(frozen=True)
class RuleEvidence:
    device: str
    rule_id: str
    name: str
    action: str
    enabled: bool
    services: tuple[str, ...]
    source: str
    destination: str
    status: str
    location: str
    owner_id: str = ""
    direction: str = ""
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProjectMapEdge:
    source: str
    target: str
    kind: str
    action: str = ""
    enabled: bool = True
    status: str = "known"
    rules: tuple[RuleEvidence, ...] = ()
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProjectMap:
    project_id: str
    nodes: tuple[ProjectMapNode, ...] = ()
    edges: tuple[ProjectMapEdge, ...] = ()
    areas: Mapping[str, str] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    rule_inputs: Mapping[tuple[str, str], Rule] = field(default_factory=dict)


def resource_addresses(record: Mapping[str, Any]) -> tuple[str, ...]:
    """Read explicit inventory IP fields; ACL prefixes are never host addresses."""
    found: set[str] = set()
    keys = {
        "ipaddress",
        "ip_address",
        "private_ip",
        "public_ip",
        "ip",
        "addr",
        "ip_addresses",
        "private_ip_address",
        "public_ip_address",
    }

    def visit(value: object, address_field: bool = False) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, str(key).lower() in keys)
        elif isinstance(value, list):
            for child in value:
                visit(child, address_field)
        elif address_field and isinstance(value, str):
            with suppress(ValueError):
                found.add(str(ip_address(value)))

    visit(record.get("inventory", {}))
    visit(record.get("data", {}).get("vm_networks", {}))
    return tuple(sorted(found))


def resource_aliases(record: Mapping[str, Any]) -> tuple[str, ...]:
    """Retain explicitly supplied names without deriving identity from them."""
    aliases: list[str] = []
    inventory = record.get("inventory", {})
    for value in (record.get("name"), inventory.get("name"), inventory.get("hostname")):
        if isinstance(value, str) and value.strip():
            aliases.append(value)
    supplied = record.get("aliases", ())
    if isinstance(supplied, (tuple, list)):
        aliases.extend(value for value in supplied if isinstance(value, str) and value.strip())
    return tuple(dict.fromkeys(aliases))


def build_project_map(
    project_id: str,
    devices: Sequence[dict[str, Any]],
    clouds: Sequence[dict[str, Any]],
    integrations: Sequence[dict[str, Any]] = (),
    *,
    revisions: Mapping[str, DeviceRevision] | None = None,
    group_rule_pairs: bool = False,
    include_switch_structure: bool = False,
    resolve_cloud_references: bool = True,
    resolve_cloud_rule_addresses: bool = True,
    cancelled: Callable[[], bool] | None = None,
) -> ProjectMap:
    """Combine latest device snapshots and cloud inventory without invented links."""
    nodes: dict[str, ProjectMapNode] = {}
    structural_edges: list[ProjectMapEdge] = []
    rule_inputs: dict[tuple[str, str], Rule] = {}
    areas = {CONTOUR: "Внутренний контур", EXTERNAL: "Внешние адреса и условия ACL"}
    warnings: list[str] = []
    parsed: list[tuple[DeviceRevision, str, str]] = []
    address_index = SnapshotAddressIndex()
    observations: dict[str, str] = {}
    scope_areas: dict[str, str] = {}

    def check_cancelled() -> None:
        if cancelled is not None and cancelled():
            raise InterruptedError("Построение карты отменено.")

    def integration(config: dict[str, Any]) -> str:
        area = cloud_area(config)
        platform = str(config.get("platform", "vmware"))
        label = "Cloud.ru · " + {
            "vmware": "VMware",
            "advanced": "Advanced",
            "evolution": "Evolution",
        }.get(platform, platform)
        context = str(config.get("tenant") or config.get("project_id") or config.get("site") or "")
        areas[area] = label + (f" · {context}" if context else "")
        key = "integration:" + area
        nodes.setdefault(
            key,
            ProjectMapNode(
                key,
                label,
                "cloud",
                area,
                "Без адреса",
                details=(
                    "Подключение проекта",
                    "Ресурсы показаны внутри облачной области.",
                    "Сохранённые наблюдения могут относиться к разному времени.",
                ),
                scope=area,
            ),
        )
        return area

    for item in integrations:
        integration({**item["config"], "platform": item["provider"].removeprefix("cloud_ru_")})
    for item in devices:
        check_cancelled()
        if item.get("cloud_origin"):
            # The original cloud inventory node owns this policy; avoid a second device.
            continue
        try:
            revision = (revisions or {}).get(str(item["id"]))
            if revision is None:
                revision = DeviceRevision.model_validate(item.get("revision"))
        except (ValueError, TypeError):
            warnings.append(f"Нет пригодной ревизии: {item.get('source_name', item['id'])}")
            # Keep the inventory device even if its old payload cannot provide rules.
            key = "device:" + str(item.get("report", {}).get("device_id", item["id"]))
            nodes[key] = ProjectMapNode(
                key,
                str(item.get("source_name", key)),
                "router",
                CONTOUR,
                "Без адреса",
                details=(warnings[-1],),
            )
            continue
        device = revision.device
        key = "device:" + device.device_id
        # Device context strings (including "default") are device-local names,
        # not evidence of one shared address space across imported devices.
        scope = "local:" + identity(project_id, device.device_id, device.context)
        observations[key] = str(revision.revision_id)
        addresses = set()
        if device.management_ip:
            addresses.add(device.management_ip)
        for interface in revision.interfaces:
            for address in interface.addresses:
                addresses.add(str(ip_interface(address).ip))
        switch = revision.parse_result.switch_facts
        if switch is not None:
            for switch_interface in switch.interfaces:
                for switch_address in switch_interface.addresses:
                    if switch_address.status == "known" and switch_address.cidr:
                        with suppress(ValueError):
                            addresses.add(str(ip_interface(switch_address.cidr).ip))
        values = tuple(sorted(addresses))
        label = device.hostname or (switch.hostname if switch is not None else None)
        label = label or str(item.get("source_name") or device.device_id)
        nodes[key] = ProjectMapNode(
            key,
            label,
            "router",
            CONTOUR,
            subnet_zone(values[0]) if values else "Без адреса",
            values,
            (
                f"Устройство: {device.device_id}",
                f"Источник: {item.get('source_name', '')}",
                f"Ревизия: {revision.revision_id}",
                f"Контекст устройства: {device.context or 'не указан'}",
                "Общая адресная область с другими устройствами не подтверждена.",
                f"Правил ACL: {len(revision.parse_result.rules)}",
            ),
            scope,
        )
        for address in values:
            address_index.add(
                CatalogObservation(key, label, evidence_refs=(str(revision.revision_id),)),
                context=scope,
                snapshot_id=observations[key],
                address=address,
            )
        parsed.append((revision, key, label))
    cloud_records: list[tuple[dict[str, Any], str, str]] = []
    incomplete_cloud_records = 0
    cloud_platforms: dict[str, str] = {}
    for item in clouds:
        check_cancelled()
        record = item["record"]
        area = integration(item["scan"]["config"])
        values = resource_addresses(record)
        if record.get("type") in {"subnets", "networks", "vpcs"}:
            prefixes = set()
            for name in ("cidr", "cidr_block", "subnet_cidr", "ipv4_cidr", "ipv6_cidr"):
                value = record.get("inventory", {}).get(name)
                if isinstance(value, str):
                    with suppress(ValueError):
                        prefixes.add(str(ip_network(value, strict=False)))
            values = tuple(dict.fromkeys((*values, *sorted(prefixes))))
        kind = {
            "vms": "server",
            "edges": "router",
            "networks": "network",
            "vpcs": "network",
            "subnets": "network",
            "security_groups": "shield",
            "interfaces": "network",
        }.get(record.get("type"), "server")
        key = str(item["id"])
        cloud_platforms[key] = str(item.get("platform", "vmware"))
        inventory = record.get("inventory", {})
        vdc = vdc_reference(inventory)
        scope = (
            area + ":vdc:" + vdc[0] if vdc is not None else area + ":resource:" + identity(key)
        )
        if item.get("platform", "vmware") != "vmware":
            # A provider project can contain isolated networks with overlapping
            # addresses. Only an explicit network reference establishes sharing.
            network_ref = next(
                (
                    (field_name, inventory[field_name])
                    for field_name in ("network_id", "subnet_id", "vpc_id")
                    if isinstance(inventory.get(field_name), str) and inventory[field_name]
                ),
                None,
            )
            scope = (
                area + ":network:" + identity(network_ref)
                if network_ref else area + ":resource:" + identity(key)
            )
        scope_areas[scope] = area
        observations[key] = str(item["scan"]["id"])
        nodes[key] = ProjectMapNode(
            key,
            str(record.get("name") or record.get("id") or "Ресурс"),
            kind,
            area,
            subnet_zone(values[0]) if values else "Без адреса",
            values,
            (
                f"Ресурс: {record.get('id', '')}",
                f"Тип: {record.get('type', '')}",
                f"Сбор: {item['scan']['id']}",
                f"Наблюдение: {record.get('collected_at', '')}",
                f"Имена источника: {', '.join(resource_aliases(record)) or 'не указаны'}",
            ),
            scope,
        )
        if item.get("platform", "vmware") == "vmware" and vdc is not None:
            container = "vdc:" + identity(area, observations[key], vdc[0])
            nodes.setdefault(container, ProjectMapNode(
                container, "VDC · " + vdc[1], "network", area, "VDC",
                details=(f"Явная область VDC: {vdc[0]}", f"Сбор: {observations[key]}"),
                scope=scope,
            ))
            structural_edges.append(ProjectMapEdge(
                container, key, "membership",
                details=("Принадлежность VDC по ссылке API; не физическое соединение.", f"Сбор: {observations[key]}"),
            ))
        for address in values:
            # Prefix inventory belongs on the map, but is not a host binding.
            try:
                canonical = str(ip_address(address))
            except ValueError:
                continue
            address_index.add(
                CatalogObservation(
                    key,
                    nodes[key].label,
                    aliases=resource_aliases(record),
                    evidence_refs=(f"{item['scan']['id']}/{record.get('id', key)}",),
                ),
                context=scope,
                snapshot_id=observations[key],
                address=canonical,
            )
        if item.get("cloud_record_missing"):
            incomplete_cloud_records += 1
            continue
        cloud_records.append((record, area, key))
        if (
            item.get("platform", "vmware") == "vmware"
            and record.get("type") == "edges"
            and isinstance(record.get("data", {}).get("firewall"), dict)
        ):
            try:
                index = item.get("record_index")
                if index is None:
                    index = next(
                        i
                        for i, value in enumerate(item["scan"]["result"]["records"])
                        if isinstance(value, dict)
                        and value.get("id") == record.get("id") and value.get("type") == "edges"
                    )
                parsed.append((vmware_record_revision(item["scan"], index, record), key, nodes[key].label))
            except (ValueError, TypeError, KeyError, IndexError, StopIteration):
                warnings.append(
                    f"{nodes[key].label}: правила Firewall не нормализованы; "
                    "в карте нет разобранных правил этого Edge. Откройте диагностику сбора и анализа."
                )

    aggregated: dict[tuple[str, str, str, bool, str], list[RuleEvidence]] = defaultdict(list)

    def endpoint_nodes(endpoint: Endpoint, scope: str, owner: str) -> tuple[str, ...]:
        result = []
        values = list(endpoint.cidrs)
        values.extend(f"{item.start}–{item.end}" for item in endpoint.ip_ranges)
        if endpoint.fqdn:
            values.append(endpoint.fqdn)
        if not values:
            values.append("Любой адрес" if endpoint.kind == EndpointKind.ANY else endpoint.name)
        for value in values:
            area = EXTERNAL
            zone = "Условия ACL"
            address = None
            network_value = None
            try:
                network = ip_network(value, strict=False)
                network_value = str(network)
                if network.prefixlen == network.max_prefixlen:
                    address = str(network.network_address)
                area = CONTOUR if _private(value) else EXTERNAL
                if scope.startswith("cloud:") and area == CONTOUR:
                    area = scope_areas.get(scope, scope)
                zone = subnet_zone(value)
            except ValueError:
                pass
            if network_value is not None and endpoint.resolution_status == DataStatus.KNOWN:
                candidates = (
                    address_index.resolve(
                        context=scope, snapshot_id=observations[owner], address=address
                    )
                    if address and (resolve_cloud_rule_addresses or not scope.startswith("cloud:"))
                    else ()
                )
                if len(candidates) == 1:
                    result.append(candidates[0].resource_key)
                    continue
                if not candidates:
                    pass
                else:
                    # Overlapping local/cloud/VRF addresses need explicit association.
                    zone += " · адрес не сопоставлен"
            kind = "monitor" if address else "network"
            if endpoint.kind == EndpointKind.ANY:
                kind = "globe"
            discriminator = "" if endpoint.resolution_status == DataStatus.KNOWN else owner
            key = "endpoint:" + identity(
                scope, observations[owner], value, endpoint.resolution_status, discriminator
            )
            display = address or value
            nodes.setdefault(
                key,
                ProjectMapNode(
                    key,
                    display,
                    kind,
                    area,
                    zone,
                    (address,) if address else (),
                    (
                        f"Условие ACL: {endpoint.name}",
                        f"Значение: {value}",
                        f"Статус: {endpoint.resolution_status.value}",
                        "Адрес из правила не подтверждает наличие устройства.",
                    ),
                    scope,
                ),
            )
            result.append(key)
        return tuple(dict.fromkeys(result))

    for revision, owner, label in parsed:
        check_cancelled()
        scope = nodes[owner].scope
        endpoint_keys: dict[str, str] = {}
        for fact in (*revision.interfaces, *revision.network_segments):
            is_interface = isinstance(fact, Interface)
            fact_id = fact.interface_id if isinstance(fact, Interface) else fact.segment_id
            key = ("interface:" if is_interface else "segment:") + identity(owner, fact_id)
            endpoint_keys[fact_id] = key
            addresses = fact.addresses if isinstance(fact, Interface) else fact.cidrs
            location = fact.source_location
            details = (
                f"Владелец: {label} · {revision.device.device_id}",
                f"Ревизия: {revision.revision_id}",
                f"ID: {fact_id} · полнота: {fact.data_status.value}",
                f"Источник: {location.source_name}:{location.object_path or location.line_start}"
                if location else f"Ручной факт: {fact.manual_reason}",
                "Принадлежность устройству не означает физическую или доступную сквозную связь.",
            )
            nodes[key] = ProjectMapNode(
                key, fact.name, "network", nodes[owner].area,
                fact.zone or ("Интерфейсы" if is_interface else "Настроенные сегменты"),
                tuple(addresses), details, scope,
            )
            structural_edges.append(ProjectMapEdge(
                owner, key, "membership", status=fact.data_status.value,
                details=("Принадлежность устройству", *details),
            ))
        for link in revision.topology_links:
            left = endpoint_keys.get(link.left_endpoint_id)
            right = endpoint_keys.get(link.right_endpoint_id)
            if left is not None and right is not None:
                location = link.source_location
                structural_edges.append(ProjectMapEdge(
                    left, right, "topology", status=link.data_status.value,
                    details=(
                        f"Явный факт топологии: {link.link_id}",
                        f"Ревизия: {revision.revision_id}",
                        f"Источник: {location.source_name}:{location.object_path or location.line_start}"
                        if location else f"Ручной факт: {link.manual_reason}",
                        "Связь внутри одной ревизии; сквозная доступность не вычисляется.",
                    ),
                ))
        if include_switch_structure and (switch := revision.parse_result.switch_facts) is not None:
            for vlan in switch.vlans:
                check_cancelled()
                key = "segment:" + identity(owner, "vlan", vlan.vlan_id)
                nodes[key] = ProjectMapNode(
                    key, f"VLAN {vlan.vlan_id}" + (f" · {vlan.name}" if vlan.name else ""),
                    "network", nodes[owner].area, "Локальные VLAN",
                    details=(
                        f"Устройство: {label}", "VLAN объявлен в сохранённой конфигурации.",
                        *(f"Источник: {location.source_name}:{location.line_start}"
                          for location in vlan.source_locations),
                    ),
                    scope=scope,
                )
                structural_edges.append(ProjectMapEdge(
                    owner, key, "membership", details=("Локальный VLAN устройства.",),
                ))
            for interface in switch.interfaces:
                check_cancelled()
                key = "interface:" + identity(owner, "switch", interface.name)
                addresses = tuple(
                    address.cidr for address in interface.addresses
                    if address.status == "known" and address.cidr is not None
                )
                nodes[key] = ProjectMapNode(
                    key, interface.name, "network", nodes[owner].area, "Интерфейсы",
                    addresses, (
                        f"Устройство: {label}",
                        f"VRF: {interface.vrf or 'не указан'}",
                        f"Административное состояние: {interface.admin_state}",
                        *(f"Источник: {location.source_name}:{location.line_start}"
                          for location in interface.source_locations),
                    ), scope,
                )
                structural_edges.append(ProjectMapEdge(
                    owner, key, "membership", details=("Интерфейс в сохранённой конфигурации.",),
                ))

    for revision, owner, label in parsed:
        scope = nodes[owner].scope
        for rule in revision.parse_result.rules:
            check_cancelled()
            rule_inputs[owner, rule.rule_id] = rule
            sources = tuple(
                dict.fromkeys(
                    key
                    for endpoint in rule.sources
                    for key in endpoint_nodes(endpoint, scope, owner)
                )
            )
            destinations = tuple(
                dict.fromkeys(
                    key
                    for endpoint in rule.destinations
                    for key in endpoint_nodes(endpoint, scope, owner)
                )
            )
            status = (
                "known"
                if all(
                    value == DataStatus.KNOWN
                    for value in (
                        rule.match_status,
                        rule.source_status,
                        rule.destination_status,
                        rule.service_status,
                        *(
                            endpoint.resolution_status
                            for endpoint in (*rule.sources, *rule.destinations)
                        ),
                    )
                )
                else "unknown"
            )
            evidence = RuleEvidence(
                label,
                rule.rule_id,
                rule.name,
                rule.action.value,
                rule.enabled,
                tuple(service.name for service in rule.services),
                ", ".join(endpoint.name for endpoint in rule.sources) or "Неизвестно",
                ", ".join(endpoint.name for endpoint in rule.destinations) or "Неизвестно",
                status,
                f"{rule.source_location.source_name}:"
                f"{rule.source_location.object_path or rule.source_location.line_start}",
                owner,
                rule.policy_direction or "unknown",
                (
                    f"Политика: {rule.policy_id or 'не указана'}; порядок: {rule.sequence}",
                    f"Зоны: {rule.source_zone or 'не указана'} → {rule.destination_zone or 'не указана'}",
                    f"Снимок: {revision.parse_result.configuration.captured_at.isoformat()}",
                    f"SHA-256: {revision.parse_result.configuration.content_sha256}",
                    "Условия пользователя/AD и расписания не раскрываются в адреса без исходных данных.",
                ),
            )
            if not sources or not destinations:
                warnings.append(f"{label} / {rule.name}: неполные адресные условия")
                continue
            pair_count = len(sources) * len(destinations)
            if pair_count > (1 if group_rule_pairs else 400):
                grouped = []
                for dimension, values in (("Источники", sources), ("Назначения", destinations)):
                    key = "group:" + identity(owner, rule.rule_id, dimension)
                    nodes[key] = ProjectMapNode(
                        key,
                        f"{dimension}: {len(values)}",
                        "network",
                        nodes[owner].area,
                        "Группы ACL",
                        details=tuple(nodes[value].label for value in values),
                        scope=scope,
                    )
                    grouped.append(key)
                sources, destinations = (grouped[0],), (grouped[1],)
                if not group_rule_pairs:
                    warnings.append(f"{label} / {rule.name}: показана связь групп адресов")
            for source in sources:
                for destination in destinations:
                    aggregated[source, destination, rule.action.value, rule.enabled, status].append(
                        evidence,
                    )

    def cloud_endpoints(values: object, area: str, owner: str) -> tuple[str, ...]:
        if not isinstance(values, list):
            return ()
        keys: list[str] = []
        for index, value in enumerate(values):
            if not isinstance(value, str):
                return ()
            if value.lower() in {"any", "any_ipv4", "any_ipv6"}:
                endpoint = Endpoint(endpoint_id=str(index), name="any", kind=EndpointKind.ANY)
            else:
                try:
                    network = ip_network(value, strict=False)
                except ValueError:
                    return ()
                endpoint = Endpoint(
                    endpoint_id=str(index),
                    name=value,
                    kind=EndpointKind.SUBNET,
                    cidrs=(str(network),),
                )
            keys.extend(endpoint_nodes(endpoint, area, owner))
        return tuple(dict.fromkeys(keys))

    security_groups: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for record, area, key in cloud_records:
        if record.get("type") == "security_groups":
            security_groups[area, observations[key], canonical_cloud_reference(str(record.get("id", "")), "security_groups")].append(key)

    for record, area, owner in cloud_records:
        check_cancelled()
        data = record.get("data", {})
        rules = data.get("security_rules", [])
        if isinstance(rules, dict):
            rules = rules.get("items", rules.get("rules", []))
        if isinstance(rules, list):
            for index, rule_data in enumerate(rules):
                check_cancelled()
                if not isinstance(rule_data, dict):
                    continue
                remote = rule_data.get("remote_ip_prefix") or rule_data.get("remote_cidr")
                direction = rule_data.get("direction")
                if not isinstance(direction, str):
                    direction = None
                peers = cloud_endpoints([remote], nodes[owner].scope, owner) if remote else ()
                if not peers and isinstance(rule_data.get("remote_group_id"), str):
                    reference = canonical_cloud_reference(rule_data["remote_group_id"], "security_groups")
                    matches = security_groups.get((area, observations[owner], reference), [])
                    if len(matches) == 1:
                        peers = (matches[0],)
                remote_known = bool(peers)
                if not peers:
                    peers = endpoint_nodes(Endpoint(
                        endpoint_id=f"sg:{rule_data.get('id', index)}:remote",
                        name=str(rule_data.get("remote_group_id") or remote or "Удалённая сторона не указана API"),
                        kind=EndpointKind.OBJECT, resolution_status=DataStatus.UNKNOWN,
                    ), nodes[owner].scope, owner)
                protocol = rule_data.get("protocol")
                action = security_group_action(rule_data)
                enabled = rule_data.get("enabled") is not False
                status = (
                    "known" if remote_known and direction in {"ingress", "egress"}
                    and action != "unknown"
                    and type(protocol) in {str, int}
                    and protocol in {"tcp", "udp", "icmp", "6", "17", "1", 6, 17, 1}
                    else "unknown"
                )
                if status != "known":
                    warnings.append(f"{nodes[owner].label}: правило SG показано с неразрешёнными условиями")
                services = (
                    f"Протокол API: {protocol if protocol is not None else 'не указан'}; "
                    f"порты API: {rule_data.get('port_range_min')}–{rule_data.get('port_range_max')}",
                )
                evidence = RuleEvidence(
                    nodes[owner].label,
                    str(rule_data.get("id", index)),
                    str(rule_data.get("description") or "Правило SG"),
                    action,
                    enabled,
                    services,
                    str(remote or rule_data.get("remote_group_id") or "неизвестно")
                    if direction == "ingress" else nodes[owner].label,
                    nodes[owner].label if direction == "ingress"
                    else str(remote or rule_data.get("remote_group_id") or "неизвестно"),
                    status,
                    "Облачный сбор / security_rules",
                    owner,
                    str(direction or "unknown"),
                    (
                        f"Сбор: {observations[owner]}; наблюдение: {record.get('collected_at', 'не указано')}",
                        "Правило SG показано по данным API; нормализованный анализ SG не выполнялся.",
                    ),
                )
                for peer in peers:
                    if direction not in {"ingress", "egress"}:
                        structural_edges.append(ProjectMapEdge(
                            owner, peer, "condition", "unknown", enabled, "unknown", (evidence,),
                            ("Направление правила API неизвестно; линия не задаёт направление доступа.",),
                        ))
                        continue
                    source, target = (peer, owner) if direction == "ingress" else (owner, peer)
                    aggregated[source, target, action, enabled, status].append(evidence)
    edges = [*structural_edges, *(
        ProjectMapEdge(source, target, "acl", action, enabled, status, tuple(rules))
        for (source, target, action, enabled, status), rules in aggregated.items()
    )]
    # Ссылки одного сбора не связываются с устаревшими наблюдениями другого.
    cloud_ids: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for record, area, key in cloud_records:
        inventory = record.get("inventory", {})
        for raw_id in (record.get("id"), inventory.get("id"), inventory.get("href")):
            if isinstance(raw_id, str) and raw_id:
                kind = str(record.get("type", ""))
                cloud_ids[area, observations[key], kind, canonical_cloud_reference(raw_id, kind)].add(key)

    for record, area, key in cloud_records:
        vm_networks = record.get("data", {}).get("vm_networks", ())
        resource_refs = (
            (*cloud_references(record.get("inventory", {})), *cloud_references(vm_networks, "data.vm_networks"))
            if resolve_cloud_references else ()
        )
        for ref in resource_refs:
            matches = cloud_ids.get((area, observations[key], ref.kind, ref.identifier), set())
            if matches == {key}:
                continue
            details = (
                f"Явная ссылка API: {ref.kind} / {ref.identifier}",
                f"Поле: {ref.path}; сбор: {observations[key]}",
                "Принадлежность/подключение не подтверждает физический или разрешённый сквозной путь.",
            )
            if len(matches) == 1:
                target = next(iter(matches))
                status = "known"
            else:
                target = "cloud-reference:" + identity(area, observations[key], ref.kind, ref.identifier)
                status = "unknown"
                reason = "Объект не получен в этом сборе" if not matches else "Ссылка имеет несколько кандидатов"
                nodes.setdefault(target, ProjectMapNode(
                    target, ref.kind + " · " + ref.identifier, "network", area, "Неразрешённые ссылки API",
                    details=(reason, *details, *(nodes[value].label for value in sorted(matches))),
                    scope=area + ":reference:" + identity(observations[key], ref.kind, ref.identifier),
                ))
                warnings.append(f"{nodes[key].label}: {reason.lower()} ({ref.path})")
            edges.append(ProjectMapEdge(key, target, "attachment", status=status, details=details))
        if cloud_platforms[key] == "vmware" and record.get("type") == "vms" and isinstance(vm_networks, list):
            for index, connection in enumerate(vm_networks):
                if not isinstance(connection, dict) or not isinstance(connection.get("network"), str):
                    continue
                name = connection["network"].strip()
                if not name:
                    continue
                target = "vm-network:" + identity(key, connection.get("NetworkConnectionIndex", index), name)
                nodes[target] = ProjectMapNode(
                    target, name + " · сеть подключения ВМ", "network", area, "Сетевые подключения ВМ",
                    details=(
                        f"Владелец: {nodes[key].label}; сбор: {observations[key]}",
                        f"Поле: data.vm_networks[{index}].network",
                        "API передал локальное имя сети. Соответствие сети Org VDC по одному имени не установлено.",
                    ),
                    scope=nodes[key].scope,
                )
                edges.append(ProjectMapEdge(
                    key, target, "attachment", status="unknown",
                    details=nodes[target].details,
                ))
    if incomplete_cloud_records:
        warnings.append(f"Полные данные не отображены для ресурсов: {incomplete_cloud_records}.")
    if cloud_records:
        missing_networks = sum(
            record.get("type") == "vms" and "vm_networks" not in record.get("data", {})
            for record, _, _ in cloud_records
        )
        missing_firewalls = sum(
            record.get("type") == "edges" and not isinstance(record.get("data", {}).get("firewall"), dict)
            for record, _, _ in cloud_records
        )
        if missing_networks or missing_firewalls:
            warnings.append(
                f"Не собраны сетевые подключения ВМ: {missing_networks}; "
                f"Firewall Edge: {missing_firewalls}. Связи по этим данным восстановить невозможно."
            )
        warnings.append(
            "Облачные линии: принадлежность VDC, явные ссылки API и условия правил — разные виды связей. "
            "Локальные имена сетей ВМ не объединяются с Org VDC без стабильной ссылки."
        )
    return ProjectMap(
        project_id, tuple(nodes.values()), tuple(edges), areas, tuple(dict.fromkeys(warnings)), rule_inputs,
    )
