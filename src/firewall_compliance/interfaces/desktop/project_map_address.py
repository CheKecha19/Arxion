"""Карта адресных условий сохранённых политик для одного ресурса."""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_network
from typing import Literal

from firewall_compliance.application.matrix_policy import matrix_policy_contexts
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus, EndpointKind, RuleAction
from firewall_compliance.domain.network import Endpoint
from firewall_compliance.domain.policy_matching import (
    AddressSet,
    Interval,
    merge_intervals,
    resolve_addresses,
    resolve_services,
)
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.switch_policy import rule_purpose
from firewall_compliance.interfaces.desktop.object_presentation import endpoint_summary, service_summary
from firewall_compliance.interfaces.desktop.project_map import (
    CONTOUR,
    ProjectMap,
    ProjectMapEdge,
    ProjectMapNode,
    RuleEvidence,
    identity,
)

_IPV4_SWITCHES = {"aos-cx", "aos-switch", "comware"}
_POLICY_PURPOSES = {
    "transit": "транзит",
    "management": "управление устройством",
    "unbound": "привязка отсутствует",
    "unknown": "применение неизвестно",
}

type _Side = Literal["source", "destination"]
type _AddressTerms = list[tuple[Endpoint, AddressSet]]


@dataclass(frozen=True, slots=True)
class _Prefixes:
    ranges: tuple[Interval, ...]
    starts: tuple[int, ...]

    def compare(self, interval: Interval) -> tuple[bool, bool]:
        """Вернуть пересечение и полное включение условия в состав ресурса."""
        start, end = interval
        index = bisect_right(self.starts, end) - 1
        if index < 0:
            return False, False
        low, high = self.ranges[index]
        return start <= high, start >= low and end <= high


def _prefixes(addresses: tuple[str, ...]) -> tuple[_Prefixes, _Prefixes]:
    ranges: tuple[list[Interval], list[Interval]] = [], []
    for address in addresses:
        network = ip_network(address, strict=False)
        ranges[0 if network.version == 4 else 1].append(
            (int(network.network_address), int(network.broadcast_address))
        )
    ipv4, ipv6 = (merge_intervals(values) for values in ranges)
    return _Prefixes(ipv4, tuple(start for start, _ in ipv4)), _Prefixes(
        ipv6, tuple(start for start, _ in ipv6),
    )


def _known_addresses(endpoint: Endpoint, ipv4_only: bool) -> AddressSet | None:
    result = resolve_addresses((endpoint,))
    if result is None:
        return None
    if ipv4_only or (
        endpoint.kind == EndpointKind.ANY and endpoint.endpoint_id.casefold().endswith(":ipv4")
    ):
        return result[0], ()
    if endpoint.kind == EndpointKind.ANY and endpoint.endpoint_id.casefold().endswith(":ipv6"):
        return (), result[1]
    return result


def _addresses(
    endpoints: tuple[Endpoint, ...], status: DataStatus, ipv4_only: bool,
) -> tuple[_AddressTerms, bool]:
    values = [
        (endpoint, result)
        for endpoint in endpoints
        if (result := _known_addresses(endpoint, ipv4_only)) is not None
    ]
    complete = bool(endpoints) and status == DataStatus.KNOWN and len(values) == len(endpoints)
    return values, complete


def _matching_terms(
    terms: _AddressTerms,
    targets: tuple[_Prefixes, _Prefixes],
    families: tuple[bool, bool],
) -> tuple[tuple[str, ...], bool]:
    matches: dict[str, None] = {}
    wider = False
    for endpoint, addresses in terms:
        for ranges, target, applies, address in zip(
            addresses, targets, families, (IPv4Address, IPv6Address), strict=True,
        ):
            if not applies:
                continue
            for interval in ranges:
                intersects, contained = target.compare(interval)
                wider |= not contained
                if intersects:
                    start, end = interval
                    if endpoint.kind == EndpointKind.ANY:
                        label = "Любой адрес (ANY)"
                    else:
                        value = str(address(start)) if start == end else f"{address(start)}–{address(end)}"
                        label = value if endpoint.name == value else f"{endpoint.name} · {value}"
                    matches.setdefault(label)
                    wider |= endpoint.kind == EndpointKind.ANY
    return tuple(matches), wider


def _location(rule: Rule) -> str:
    source = rule.source_location
    if source.line_start is not None:
        line = str(source.line_start)
        if source.line_end is not None and source.line_end != source.line_start:
            line += f"–{source.line_end}"
    else:
        line = ""
    anchor = " · ".join(filter(None, (source.object_path, line, source.object_id)))
    return f"{source.source_name}:{anchor}"


@dataclass(frozen=True, slots=True)
class _AddressMatch:
    side: _Side
    terms: tuple[str, ...]
    wider: bool


def _evidence(
    revision: DeviceRevision,
    rule: Rule,
    peer: ProjectMapNode,
    match: _AddressMatch,
    status: str,
    policy_context: str,
) -> RuleEvidence:
    configuration = revision.parse_result.configuration
    address_side = "источник" if match.side == "source" else "назначение"
    source_ports = tuple(
        f"{service.name}: " + ", ".join(
            str(port.start) if port.start == port.end else f"{port.start}–{port.end}"
            for port in service.source_port_ranges
        )
        for service in rule.services if service.source_port_ranges
    )
    details = (
        f"Ресурс в адресном условии: {address_side}",
        f"Пересекающиеся адресные условия: {', '.join(match.terms)}",
        "Адресное условие шире состава ресурса." if match.wider else "",
        "Полное условие правила не установлено." if status == "unknown" else "",
        f"Политика: {rule.policy_id or 'не указана'} · строка порядка {rule.sequence} · "
        f"{_POLICY_PURPOSES[rule_purpose(rule)]}",
        f"VRF применения: {policy_context}",
        f"Зоны: {rule.source_zone or 'не указана'} → {rule.destination_zone or 'не указана'}",
        f"Порты источника: {', '.join(source_ports)}" if source_ports else "",
        f"Ревизия: {revision.revision_id}",
        f"Снимок: {configuration.captured_at.isoformat()} · SHA-256: {configuration.content_sha256}",
    )
    return RuleEvidence(
        device=revision.device.hostname or revision.device.device_id,
        rule_id=rule.rule_id,
        name=rule.name,
        action=rule.action.value,
        enabled=rule.enabled,
        services=(
            service_summary([service.model_dump(mode="json") for service in rule.services]),
        ),
        source=endpoint_summary([endpoint.model_dump(mode="json") for endpoint in rule.sources]),
        destination=endpoint_summary([endpoint.model_dump(mode="json") for endpoint in rule.destinations]),
        status=status,
        location=_location(rule),
        owner_id=peer.key,
        direction=rule.policy_direction or "unknown",
        details=tuple(value for value in details if value),
    )


def build_address_project_map(
    project_id: str,
    anchor: ProjectMapNode,
    revisions: Iterable[DeviceRevision],
    *,
    site_label: str,
    cancelled: Callable[[], bool] | None = None,
) -> ProjectMap:
    """Сопоставить подтверждённые адреса с видимыми условиями без расчёта пути."""
    areas = {anchor.area: site_label, CONTOUR: site_label}
    warning = (
        "Линии показывают место ресурса в адресном условии и владельца правила. "
        "Для выводов о доступности нужны привязка к сетевому контексту, "
        "порядок применения правил и данные о пути."
    )
    if not anchor.addresses:
        return ProjectMap(
            project_id, (anchor,), areas=areas,
            warnings=(warning, "Для ресурса нет подтверждённых адресов."),
        )
    targets = _prefixes(anchor.addresses)
    nodes = {anchor.key: anchor}
    related: dict[tuple[str, str, str, bool, str], list[tuple[bool, RuleEvidence]]] = defaultdict(list)
    rule_inputs: dict[tuple[str, str], Rule] = {}
    revision_count = rule_count = unresolved = partial_revisions = 0
    stopped = False
    for revision in revisions:
        if cancelled is not None and cancelled():
            stopped = True
            break
        device = revision.device
        parsed = revision.parse_result
        if parsed.errors or parsed.coverage.unsupported_constructs or (
            parsed.coverage.recognized_constructs < parsed.coverage.discovered_constructs
        ):
            partial_revisions += 1
        revision_count += 1
        contexts = matrix_policy_contexts(revision)
        switch = parsed.switch_facts
        name = device.hostname or (switch.hostname if switch is not None else None) or device.device_id
        context = device.context or "не указан"
        ipv4_only = device.platform in _IPV4_SWITCHES
        owner_keys = {
            "source": "address-policy:" + identity(revision.revision_id, "source"),
            "destination": "address-policy:" + identity(revision.revision_id, "destination"),
        }
        for rule in parsed.rules:
            if cancelled is not None and cancelled():
                stopped = True
                break
            rule_count += 1
            source, source_complete = _addresses(rule.sources, rule.source_status, ipv4_only)
            destination, destination_complete = _addresses(
                rule.destinations, rule.destination_status, ipv4_only,
            )
            applies = (True, not ipv4_only)
            rule_matches: list[_AddressMatch] = []
            sides: tuple[tuple[_Side, _AddressTerms, bool, _AddressTerms, bool], ...] = (
                ("source", source, source_complete, destination, destination_complete),
                ("destination", destination, destination_complete, source, source_complete),
            )
            for side, terms, complete, opposite, opposite_complete in sides:
                families = (
                    (
                        applies[0] and any(values[0] for _, values in opposite),
                        applies[1] and any(values[1] for _, values in opposite),
                    )
                    if opposite_complete and rule.match_status == DataStatus.KNOWN
                    else applies
                )
                matches, wider = _matching_terms(terms, targets, families)
                if not matches:
                    compatible_family = any(
                        allowed and target.ranges
                        for allowed, target in zip(families, targets, strict=True)
                    )
                    if compatible_family and (not complete or rule.match_status != DataStatus.KNOWN):
                        unresolved += 1
                    continue
                rule_matches.append(_AddressMatch(side, matches, wider))
            if not rule_matches:
                continue
            status = "known" if (
                rule.match_status == DataStatus.KNOWN
                and source_complete and destination_complete
                and rule.service_status == DataStatus.KNOWN
                and resolve_services(rule.services) is not None
                and rule.action != RuleAction.UNKNOWN
            ) else "unknown"
            for match in rule_matches:
                key = owner_keys[match.side]
                if key not in nodes:
                    peer = "Условия назначения" if match.side == "source" else "Условия источника"
                    nodes[key] = ProjectMapNode(
                        key, f"{peer} · {name}", "network", CONTOUR, "Политики",
                        details=(
                            f"Владелец политики: {device.device_id}",
                            f"Платформа: {device.platform}",
                            f"Контекст устройства: {context}",
                            f"Ревизия: {revision.revision_id}",
                            "Узел объединяет условия правил указанной ревизии.",
                        ),
                        scope="view:address-policy",
                    )
                evidence = _evidence(
                    revision, rule, nodes[key], match, status,
                    (contexts.get(rule.policy_id) if rule.policy_id else None) or "не подтверждён",
                )
                related[key, match.side, rule.action.value, rule.enabled, status].append(
                    (match.wider, evidence)
                )
                rule_inputs[key, rule.rule_id] = rule
        if stopped:
            break
    edges = []
    for (owner, side, action, enabled, status), matches in related.items():
        source_key, target_key = (anchor.key, owner) if side == "source" else (owner, anchor.key)
        edges.append(ProjectMapEdge(
            source_key, target_key, "acl", action, enabled, status,
            rules=tuple(evidence for _, evidence in sorted(matches, key=lambda item: item[0])),
            details=("Адресное пересечение с правилами сохранённой ревизии.",),
        ))
    warnings = [
        warning,
        f"Просмотрено правил: {rule_count} · сохранённых ревизий: {revision_count}.",
    ]
    if unresolved:
        warnings.append(
            f"Сторон правил без подтверждённого совпадения из-за неизвестных условий: {unresolved}."
        )
    if partial_revisions:
        warnings.append(f"Ревизий с неполным разбором: {partial_revisions}.")
    if stopped:
        warnings.append("Чтение условий отменено. Показана обработанная часть.")
    elif not edges:
        warnings.append("В просмотренных адресных условиях совпадений не найдено.")
    return ProjectMap(project_id, tuple(nodes.values()), tuple(edges), areas, tuple(warnings), rule_inputs)
