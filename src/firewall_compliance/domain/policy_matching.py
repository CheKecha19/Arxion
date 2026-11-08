"""Чистая доменная алгебра полностью разрешённых условий правил."""

from dataclasses import dataclass
from ipaddress import ip_address, ip_network

from firewall_compliance.domain import DataStatus, Endpoint, EndpointKind, Protocol, Rule, Service
from firewall_compliance.domain.reachability import ReachabilityQuery
from firewall_compliance.domain.switch_policy import is_transit_rule

type Interval = tuple[int, int]
type AddressSet = tuple[tuple[Interval, ...], tuple[Interval, ...]]
type ServiceSet = tuple[tuple[str, tuple[Interval, ...]], ...]
type ScopeKey = tuple[str, str, str | None, str | None]


def merge_intervals(values: list[Interval]) -> tuple[Interval, ...]:
    """Объединить пересекающиеся и соседние интервалы."""
    merged: list[Interval] = []
    for start, end in sorted(values):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return tuple(merged)


def intervals_cover(outer: tuple[Interval, ...], inner: tuple[Interval, ...]) -> bool:
    """Проверить включение уже нормализованного набора интервалов."""
    return all(any(a <= start and b >= end for a, b in outer) for start, end in inner)


def resolve_addresses(values: tuple[Endpoint, ...]) -> AddressSet | None:
    """Разрешить явные CIDR и диапазоны без догадок об FQDN или пустых группах."""
    if not values:
        return None
    ipv4: list[Interval] = []
    ipv6: list[Interval] = []
    for value in values:
        if value.resolution_status != DataStatus.KNOWN:
            return None
        if value.kind == EndpointKind.ANY:
            ipv4.append((0, 2**32 - 1))
            ipv6.append((0, 2**128 - 1))
        elif (
            value.fqdn
            or value.kind in {EndpointKind.FQDN, EndpointKind.ZONE}
            or not value.cidrs
            and not value.ip_ranges
        ):
            return None
        for cidr in value.cidrs:
            network = ip_network(cidr)
            target = ipv4 if network.version == 4 else ipv6
            target.append((int(network.network_address), int(network.broadcast_address)))
        for interval in value.ip_ranges:
            start, end = ip_address(interval.start), ip_address(interval.end)
            target = ipv4 if start.version == 4 else ipv6
            target.append((int(start), int(end)))
    return merge_intervals(ipv4), merge_intervals(ipv6)


def resolve_services(values: tuple[Service, ...]) -> ServiceSet | None:
    """Разрешить протокол и destination ports без расширения неизвестных сервисов."""
    if not values:
        return None
    intervals: dict[str, list[Interval]] = {}
    for value in values:
        if value.resolution_status != DataStatus.KNOWN or value.protocol == Protocol.OTHER:
            return None
        intervals.setdefault(value.protocol.value, []).extend(
            [(port.start, port.end) for port in value.port_ranges] or [(0, 65535)]
        )
    if "ip" in intervals:
        return (("ip", ((0, 65535),)),)
    return tuple(
        (protocol, merge_intervals(ports)) for protocol, ports in sorted(intervals.items())
    )


@dataclass(frozen=True)
class RuleMatch:
    """Полностью известные условия одного правила."""

    sources: AddressSet
    destinations: AddressSet
    services: ServiceSet

    def covers(self, other: "RuleMatch") -> bool:
        """Проверить полное включение условий другого правила."""
        service_map = dict(self.services)
        return (
            all(intervals_cover(a, b) for a, b in zip(self.sources, other.sources, strict=True))
            and all(
                intervals_cover(a, b)
                for a, b in zip(self.destinations, other.destinations, strict=True)
            )
            and all(
                intervals_cover(service_map.get(protocol, service_map.get("ip", ())), ports)
                for protocol, ports in other.services
            )
        )


def matches_query(match: RuleMatch, query: ReachabilityQuery) -> bool:
    """Сопоставить полностью разрешённые условия с конкретным IPv4 tuple."""
    source, destination = int(ip_address(query.source_ip)), int(ip_address(query.destination_ip))
    services = dict(match.services)
    ports = services.get(query.protocol.value, services.get("ip", ()))
    port = query.destination_port if query.destination_port is not None else 0
    return (
        any(start <= source <= end for start, end in match.sources[0])
        and any(start <= destination <= end for start, end in match.destinations[0])
        and any(start <= port <= end for start, end in ports)
    )


def resolve_rule(rule: Rule) -> RuleMatch | None:
    """Вернуть условия только при подтверждённом полном разборе правила."""
    if any(
        status != DataStatus.KNOWN
        for status in (
            rule.match_status,
            rule.source_status,
            rule.destination_status,
            rule.service_status,
        )
    ):
        return None
    sources = resolve_addresses(rule.sources)
    destinations = resolve_addresses(rule.destinations)
    services = resolve_services(rule.services)
    if sources is None or destinations is None or services is None:
        return None
    shared_sources: AddressSet = (
        sources[0] if destinations[0] else (),
        sources[1] if destinations[1] else (),
    )
    shared_destinations: AddressSet = (
        destinations[0] if sources[0] else (),
        destinations[1] if sources[1] else (),
    )
    if not any(shared_sources):
        return None
    return RuleMatch(shared_sources, shared_destinations, services)


def scope_key(rule: Rule) -> ScopeKey | None:
    """Определить явно подтверждённую область first-match policy."""
    if (
        not is_transit_rule(rule)
        or rule.policy_id is None
        or rule.policy_direction is None
        or rule.policy_semantics != "first_match"
        or rule.zone_status != DataStatus.KNOWN
    ):
        return None
    return rule.policy_id, rule.policy_direction, rule.source_zone, rule.destination_zone
