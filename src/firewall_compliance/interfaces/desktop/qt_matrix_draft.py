"""Подготовка строк черновика из явно заданных разрешений выбранной политики."""

from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address, ip_network, summarize_address_range
from uuid import uuid4

from firewall_compliance.application.matrix_policy import (
    matrix_binding_zones, matrix_policy_supports_zones, matrix_transit_binding,
)
from firewall_compliance.domain.access_matrix import MatrixGroup, MatrixRequirement, MatrixService, MatrixZonePair
from firewall_compliance.domain.enums import DataStatus, RuleAction
from firewall_compliance.domain.policy_matching import AddressSet, Interval, merge_intervals, resolve_rule
from firewall_compliance.domain.revision import DeviceRevision


def _cidrs(addresses: AddressSet) -> tuple[str, ...]:
    return tuple(
        str(network)
        for version, ranges in enumerate(addresses)
        for start, end in ranges
        for network in summarize_address_range(
            IPv4Address(start) if version == 0 else IPv6Address(start),
            IPv4Address(end) if version == 0 else IPv6Address(end),
        )
    )


def _literal_addresses(group: MatrixGroup) -> AddressSet:
    ipv4: list[Interval] = []
    ipv6: list[Interval] = []
    for member in group.members:
        network = ip_network(member.value, strict=False)
        intervals = ipv4 if network.version == 4 else ipv6
        intervals.append((int(network.network_address), int(network.broadcast_address)))
    return merge_intervals(ipv4), merge_intervals(ipv6)


def _service_key(service: MatrixService) -> tuple[str, tuple[Interval, ...]]:
    if service.any_ports:
        return service.protocol, ((0, 65535),)
    return service.protocol, merge_intervals([(port.start, port.end) for port in service.ports])


def declared_draft(
    revision: DeviceRevision, scope_id: str, policy_id: str, existing: Sequence[MatrixGroup],
    existing_rows: Sequence[MatrixRequirement], *, zone_pair: MatrixZonePair | None = None,
    provenance: str = "",
) -> tuple[tuple[MatrixGroup, ...], tuple[MatrixRequirement, ...], dict[str, int]]:
    """Зоны и дополнительные условия не отбрасываются при переносе строки."""
    index: dict[AddressSet, str] = {}
    literal_groups: dict[str, AddressSet] = {}
    repeated_addresses: set[AddressSet] = set()
    for group in existing:
        if group.members and all(member.kind == "network" for member in group.members):
            addresses = _literal_addresses(group)
            literal_groups[group.group_id] = addresses
            if addresses in index:
                repeated_addresses.add(addresses)
            index.setdefault(addresses, group.group_id)
    for addresses in repeated_addresses:
        del index[addresses]
    groups = []
    rows = []
    skipped = {"non_allow": 0, "unresolved": 0, "duplicate": 0, "outside_zone": 0}
    zones_supported = matrix_policy_supports_zones(revision)
    binding = matrix_transit_binding(revision, policy_id)
    binding_direction = None
    binding_zones = None
    if binding is not None and binding.semantics == "first_match" and (
        revision.device.platform in {"aos-cx", "aos-switch"}
        or (
            revision.device.platform == "comware"
            and binding.configured_profile == "hpe-flexfabric-5944-5945-r6622"
            and binding.direction == "routed-in"
        )
    ):
        binding_direction = "in" if binding.direction in {"in", "routed-in"} else "out"
        binding_zones = matrix_binding_zones(binding)
    conditions = {
        (literal_groups[row.source_group], literal_groups[row.destination_group], _service_key(row.service), row.zone_pair)
        for row in existing_rows
        if row.scope_id == scope_id and row.policy_id == policy_id
        and row.identity is None and row.schedule is None and row.access_context is None
        and row.requirement in {"permit", "allow_optional"}
        and row.source_group in literal_groups and row.destination_group in literal_groups
    }

    def group_for(values: AddressSet) -> str:
        if values not in index:
            cidrs = _cidrs(values)
            identifier = "draft-" + uuid4().hex
            groups.append(MatrixGroup.model_validate({
                "group_id": identifier,
                "name": cidrs[0] if len(cidrs) == 1 else f"{cidrs[0]} и ещё {len(cidrs) - 1}",
                "members": [{"kind": "network", "value": cidr} for cidr in cidrs],
            }))
            index[values] = identifier
        return index[values]

    for rule in revision.parse_result.rules:
        if rule.policy_id != policy_id:
            continue
        if not rule.enabled or rule.action != RuleAction.ALLOW:
            skipped["non_allow"] += 1
            continue
        match = resolve_rule(rule)
        if (
            match is None or rule.zone_status != DataStatus.KNOWN
            or rule.policy_purpose in {"management", "unbound", "unknown"}
            or any(
                protocol not in {"ip", "tcp", "udp", "icmp"}
                or (protocol in {"tcp", "udp"} and len(ranges) > 128)
                for protocol, ranges in match.services
            )
        ):
            skipped["unresolved"] += 1
            continue
        draft_zones = zone_pair
        sources, destinations = match.sources, match.destinations
        if draft_zones is not None:
            if not zones_supported:
                skipped["unresolved"] += 1
                continue
            if (rule.source_zone not in (None, draft_zones.source_zone)
                    or rule.destination_zone not in (None, draft_zones.destination_zone)):
                skipped["outside_zone"] += 1
                continue
        elif binding_zones is not None:
            if (
                (rule.source_zone, rule.destination_zone) != binding_zones
                or rule.policy_direction != binding_direction or rule.policy_purpose != "transit"
                or rule.policy_semantics != "first_match" or not sources[0] or not destinations[0]
            ):
                skipped["unresolved"] += 1
                continue
            sources, destinations = (sources[0], ()), (destinations[0], ())
        elif rule.source_zone is not None or rule.destination_zone is not None:
            if not zones_supported or rule.source_zone is None or rule.destination_zone is None:
                skipped["unresolved"] += 1
                continue
            try:
                draft_zones = MatrixZonePair(source_zone=rule.source_zone, destination_zone=rule.destination_zone)
            except ValueError:
                skipped["unresolved"] += 1
                continue
        location = rule.source_location
        anchor = f"строка {location.line_start}" if location.line_start is not None else (
            location.object_path or location.object_id or ""
        )
        direction = {"in": "входящее", "out": "исходящее", "global": "общее"}.get(rule.policy_direction or "")
        reason = " · ".join(part for part in (
            f"Правило {rule.rule_id}", f"ревизия {revision.revision_id}", provenance, anchor, direction,
        ) if part)[:4096]
        for protocol, ranges in match.services:
            any_ports = protocol in {"tcp", "udp"} and ranges == ((0, 65535),)
            service = MatrixService.model_validate({
                "protocol": protocol,
                "ports": [
                    {"start": start, "end": end} for start, end in ranges
                    if protocol in {"tcp", "udp"} and not any_ports
                ],
                "any_ports": any_ports,
            })
            key = sources, destinations, _service_key(service), draft_zones
            if key in conditions:
                skipped["duplicate"] += 1
                continue
            conditions.add(key)
            rows.append(MatrixRequirement(
                requirement_id="draft-" + uuid4().hex,
                source_group=group_for(sources), destination_group=group_for(destinations),
                service=service, requirement="allow_optional", scope_id=scope_id, policy_id=policy_id,
                zone_pair=draft_zones,
                reason=reason,
            ))
    return tuple(groups), tuple(rows), skipped
