"""Project-wide inventory and declared ACL relationships, independent of Qt."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

from firewall_compliance.application.asset_catalog import CatalogObservation, SnapshotAddressIndex
from firewall_compliance.application.cloud_analysis import vmware_revision
from firewall_compliance.domain.enums import DataStatus, EndpointKind
from firewall_compliance.domain.network import Endpoint
from firewall_compliance.domain.revision import DeviceRevision

CONTOUR = "contour"
EXTERNAL = "external"


def identity(*parts: object) -> str:
    return sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:24]


def cloud_area(config: Mapping[str, Any]) -> str:
    return "cloud:" + identity(
        {
            key: config.get(key, "vmware" if key == "platform" else None)
            for key in ("platform", "site", "tenant", "project_id", "region")
        }
    )


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
) -> ProjectMap:
    """Combine latest device snapshots and cloud inventory without invented links."""
    nodes: dict[str, ProjectMapNode] = {}
    areas = {CONTOUR: "Внутренний контур", EXTERNAL: "Внешние адреса и условия ACL"}
    warnings: list[str] = []
    parsed: list[tuple[DeviceRevision, str, str]] = []
    address_index = SnapshotAddressIndex()
    observations: dict[str, str] = {}
    scope_areas: dict[str, str] = {}

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
        values = tuple(sorted(addresses))
        label = device.hostname or str(item.get("source_name") or device.device_id)
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
    for item in clouds:
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
        inventory = record.get("inventory", {})
        vdc = inventory.get("vdc")
        for field_name in ("orgVdc", "ownerRef"):
            reference = inventory.get(field_name)
            if not vdc:
                vdc = reference.get("id") if isinstance(reference, dict) else reference
        match = re.search(
            r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$", str(vdc or "").rstrip("/")
        )
        scope = (
            area + ":vdc:" + (match[0].lower() if match else str(vdc or record.get("id") or key))
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
                        if value.get("id") == record.get("id") and value.get("type") == "edges"
                    )
                parsed.append((vmware_revision(item["scan"], index), key, nodes[key].label))
            except (ValueError, KeyError, StopIteration):
                warnings.append(
                    f"{nodes[key].label}: правила Firewall не нормализованы; "
                    "проверьте ошибки сбора."
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
                    if address else ()
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
        scope = nodes[owner].scope
        for rule in revision.parse_result.rules:
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
            )
            if not sources or not destinations:
                warnings.append(f"{label} / {rule.name}: неполные адресные условия")
                continue
            if len(sources) * len(destinations) > 400:
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

    for record, area, owner in cloud_records:
        data = record.get("data", {})
        rules = data.get("security_rules", [])
        if isinstance(rules, dict):
            rules = rules.get("items", rules.get("rules", []))
        if isinstance(rules, list):
            for index, rule_data in enumerate(rules):
                if not isinstance(rule_data, dict):
                    continue
                remote = rule_data.get("remote_ip_prefix") or rule_data.get("remote_cidr")
                direction = rule_data.get("direction")
                peers = cloud_endpoints([remote], nodes[owner].scope, owner) if remote else ()
                if not peers or direction not in {"ingress", "egress"}:
                    warnings.append(f"{nodes[owner].label}: правило SG без явного CIDR/направления")
                    continue
                services = (
                    f"{rule_data.get('protocol', 'any')} "
                    f"{rule_data.get('port_range_min', '')}–"
                    f"{rule_data.get('port_range_max', '')}",
                )
                evidence = RuleEvidence(
                    nodes[owner].label,
                    str(rule_data.get("id", index)),
                    str(rule_data.get("description") or "Правило SG"),
                    "allow",
                    True,
                    services,
                    str(remote) if direction == "ingress" else nodes[owner].label,
                    nodes[owner].label if direction == "ingress" else str(remote),
                    "known",
                    "Облачный сбор / security_rules",
                    owner,
                )
                for peer in peers:
                    source, target = (peer, owner) if direction == "ingress" else (owner, peer)
                    aggregated[source, target, "allow", True, "known"].append(evidence)
    edges = [
        ProjectMapEdge(source, target, "acl", action, enabled, status, tuple(rules))
        for (source, target, action, enabled, status), rules in aggregated.items()
    ]
    # Cloud links are explicit references within one connection, never name/IP guesses.
    cloud_ids: dict[tuple[str, str], list[str]] = defaultdict(list)
    for record, area, key in cloud_records:
        cloud_ids[area, str(record.get("id", ""))].append(key)
    reference_fields = {
        "network_id",
        "subnet_id",
        "vpc_id",
        "server_id",
        "vm_id",
        "security_group_id",
    }

    def references(value: object) -> set[str]:
        result: set[str] = set()
        if isinstance(value, dict):
            for name, child in value.items():
                if name in reference_fields and isinstance(child, str):
                    result.add(child)
                elif name == "security_group_ids" and isinstance(child, list):
                    result.update(item for item in child if isinstance(item, str))
                elif name == "security_groups" and isinstance(child, list):
                    result.update(
                        str(item["id"])
                        for item in child
                        if isinstance(item, dict) and item.get("id")
                    )
                elif isinstance(child, (dict, list)):
                    result.update(references(child))
        elif isinstance(value, list):
            for child in value:
                result.update(references(child))
        return result

    seen_links = set()
    for record, area, key in cloud_records:
        resource_refs = references(record.get("inventory", {}))
        resource_refs.update(references(record.get("data", {}).get("vm_networks", {})))
        for value in sorted(resource_refs):
            matches = cloud_ids.get((area, value), [])
            if len(matches) == 1 and matches[0] != key:
                pair = tuple(sorted((key, matches[0])))
                if pair not in seen_links:
                    seen_links.add(pair)
                    edges.append(
                        ProjectMapEdge(
                            key,
                            matches[0],
                            "attachment",
                            details=(f"Явная ссылка облачного ресурса: {value}",),
                        )
                    )
    return ProjectMap(
        project_id, tuple(nodes.values()), tuple(edges), areas, tuple(dict.fromkeys(warnings))
    )
