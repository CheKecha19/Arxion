"""Сборка карты настроек и свидетельств без моделирования forwarding."""

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from firewall_compliance.domain.enums import DataOrigin, DataStatus, SourceDocumentKind
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.domain.switch_topology import (
    SwitchLinkKind,
    SwitchNodeKind,
    SwitchTopology,
    SwitchTopologyGap,
    SwitchTopologyLink,
    SwitchTopologyNode,
    SwitchTopologyProvenance,
)


def _id(revision: DeviceRevision, kind: str, name: str) -> str:
    return f"{revision.revision_id}:{kind}:{name}"


def _basis(
    revision: DeviceRevision, locations: tuple[SourceLocation, ...] = ()
) -> SwitchTopologyProvenance:
    configuration = revision.parse_result.configuration
    source = next((
        item for item in revision.sources
        if item.source_name == configuration.source_name
        and item.content_sha256.lower() == configuration.content_sha256.lower()
        and item.captured_at == configuration.captured_at
    ), None)
    if source is None:
        raise ValueError("нет точного источника конфигурации для топологического свидетельства")
    return SwitchTopologyProvenance(
        revision_id=revision.revision_id,
        source_name=source.source_name,
        content_sha256=source.content_sha256,
        captured_at=source.captured_at,
        source_document_id=source.source_document_id,
        source_locations=locations,
        observed_at=source.observation.observed_at if source.observation is not None else None,
        reference=source.observation.reference if source.observation is not None else None,
    )


def _allowed(value: str | None, vlan: int) -> bool:
    if value is None:
        return False
    if value == "all":
        return True
    value = re.sub(r"(\d+)\s+to\s+(\d+)", r"\1-\2", value)
    for token in re.split(r"[,\s]+", value):
        if token.isdigit() and int(token) == vlan:
            return True
        match = re.fullmatch(r"(\d+)-(\d+)", token)
        if match and int(match[1]) <= vlan <= int(match[2]):
            return True
    return False


def _description_name(description: str) -> str:
    """Убрать только явное оформление description, не угадывая модель соседа."""
    value = re.sub(r"^to[_\s:-]+", "", description.strip(), flags=re.I)
    value = value.split()[0] if value.split() else value
    return re.sub(r"(?:\.untrusted)?\.port\d+$", "", value, flags=re.I)


def build_switch_topology(
    revisions: Sequence[DeviceRevision], *, built_at: datetime | None = None
) -> SwitchTopology:
    """Оставить каждую ревизию отдельным слоем, не объявляя историю актуальной сетью."""
    unique: dict[str, DeviceRevision] = {}
    for revision in revisions:
        identifier = str(revision.revision_id)
        if identifier in unique and unique[identifier] != revision:
            raise ValueError("один revision_id содержит разные снимки")
        unique[identifier] = revision
    values = tuple(unique.values())
    nodes: dict[str, SwitchTopologyNode] = {}
    links: list[SwitchTopologyLink] = []
    configured_edges: set[tuple[str, str, str]] = set()
    gaps: list[SwitchTopologyGap] = []
    hostnames: dict[str, list[DeviceRevision]] = {}

    def node(
        revision: DeviceRevision, kind: SwitchNodeKind, name: str, label: str,
        locations: tuple[SourceLocation, ...] = (), details: dict[str, Any] | None = None,
    ) -> str:
        identifier = _id(revision, kind, name)
        nodes[identifier] = SwitchTopologyNode(
            node_id=identifier, kind=kind, label=label, device_id=revision.device.device_id,
            revision_id=revision.revision_id, details=details or {},
            provenance=(_basis(revision, locations),),
        )
        return identifier

    def configured(
        revision: DeviceRevision, left: str, right: str, kind: SwitchLinkKind,
        locations: tuple[SourceLocation, ...] = (),
    ) -> None:
        edge = (left, right, kind)
        if edge in configured_edges:
            return
        configured_edges.add(edge)
        links.append(SwitchTopologyLink(
            link_id=f"{left}:{kind}:{right}", left=left, right=right, kind=kind,
            status="configured", evidence_kind="configuration",
            provenance=(_basis(revision, locations),),
        ))

    for revision in values:
        facts = revision.parse_result.switch_facts
        hostname = facts.hostname if facts is not None else revision.device.hostname
        root = node(revision, "device", "device", hostname or revision.device.device_id)
        if hostname:
            hostnames.setdefault(hostname.casefold(), []).append(revision)
        if facts is None:
            gaps.append(SwitchTopologyGap(
                code="SWITCH_FACTS_UNAVAILABLE", node_id=root,
                message="В ревизии нет конфигурационных фактов коммутатора.",
                next_source="Повторный импорт исходной конфигурации.",
                provenance=(_basis(revision),),
            ))
            continue
        for member in facts.stack:
            child = node(revision, "stack_member", member.member, f"{member.system} {member.member}",
                         member.source_locations, member.model_dump(mode="json"))
            configured(revision, root, child, "contains", member.source_locations)
        for vlan in facts.vlans:
            child = node(revision, "vlan", str(vlan.vlan_id),
                         f"VLAN {vlan.vlan_id} {vlan.name or ''}".strip(),
                         vlan.source_locations, vlan.model_dump(mode="json"))
            configured(revision, root, child, "contains", vlan.source_locations)
        for aggregate in facts.aggregates:
            child = node(revision, "aggregate", aggregate.name, aggregate.name,
                         aggregate.source_locations, aggregate.model_dump(mode="json"))
            configured(revision, root, child, "contains", aggregate.source_locations)
            for vlan in facts.vlans:
                if vlan.vlan_id == aggregate.native_vlan or _allowed(
                    aggregate.allowed_vlans, vlan.vlan_id
                ):
                    configured(revision, child, _id(revision, "vlan", str(vlan.vlan_id)),
                               "vlan_membership", aggregate.source_locations)
        for interface in facts.interfaces:
            child = node(revision, "interface", interface.name, interface.name,
                         interface.source_locations, interface.model_dump(mode="json"))
            configured(revision, root, child, "contains", interface.source_locations)
            if interface.aggregate:
                aggregate_id = _id(revision, "aggregate", interface.aggregate)
                if aggregate_id in nodes:
                    configured(revision, child, aggregate_id, "aggregate_member",
                               interface.source_locations)
            member_id = _id(revision, "stack_member", interface.stack_member or "")
            if member_id in nodes:
                configured(revision, child, member_id, "contains", interface.source_locations)
            for vlan in facts.vlans:
                if (
                    vlan.vlan_id in interface.tagged_vlans
                    or vlan.vlan_id in interface.untagged_vlans
                    or vlan.vlan_id in {interface.access_vlan, interface.native_vlan}
                    or interface.name in vlan.tagged_interfaces
                    or interface.name in vlan.untagged_interfaces
                    or _allowed(interface.allowed_vlans, vlan.vlan_id)
                ):
                    configured(revision, child, _id(revision, "vlan", str(vlan.vlan_id)),
                               "vlan_membership", interface.source_locations)
        for aggregate in facts.aggregates:
            for member in aggregate.members:
                interface_id = _id(revision, "interface", member)
                if interface_id not in nodes:
                    node(revision, "interface", member, member, aggregate.source_locations)
                configured(revision, interface_id, _id(revision, "aggregate", aggregate.name),
                           "aggregate_member", aggregate.source_locations)
        management_vrfs = dict.fromkeys(
            fact.vrf or "unknown" for fact in facts.management if fact.kind == "service"
        )
        for vrf in management_vrfs:
            services = [fact for fact in facts.management
                        if fact.kind == "service" and (fact.vrf or "unknown") == vrf]
            locations = tuple(location for fact in services for location in fact.source_locations)
            plane = node(revision, "management_plane", vrf, f"Management VRF {vrf}", locations,
                         {"vrf": vrf, "services": [fact.model_dump(mode="json") for fact in services]})
            configured(revision, root, plane, "contains", locations)
        if facts.vlans:
            gaps.append(SwitchTopologyGap(
                code="UNKNOWN_GATEWAY", node_id=root,
                message="Роль шлюза конечных узлов VLAN не установлена по этому файлу. "
                "Наличие IP-интерфейса VLAN само по себе её не доказывает.",
                next_source="Конфигурация L3-ядра и интерфейсов NGFW.",
                provenance=(_basis(revision),),
            ))
        gaps.extend((
            SwitchTopologyGap(
                code="NO_OPERATIONAL_STATE", node_id=root,
                message="Состояние портов, стека и LACP не наблюдалось в конфигурации.",
                next_source="Вывод состояния интерфейсов, стека и агрегации.",
                provenance=(_basis(revision),),
            ),
            SwitchTopologyGap(
                code="NO_RIB", node_id=root,
                message="Настроенные маршруты не подтверждают установленную таблицу маршрутизации.",
                next_source="Таблица маршрутизации соответствующего устройства и VRF.",
                provenance=(_basis(revision),),
            ),
            SwitchTopologyGap(
                code="UNKNOWN_EXTERNAL_POLICY", node_id=root,
                message="Политики внешних фильтрующих устройств не установлены по этому файлу.",
                next_source="Конфигурации ядра и межсетевых экранов на предполагаемом пути.",
                provenance=(_basis(revision),),
            ),
        ))

    # Все узлы устройств уже созданы: совпадение имени никогда не зависит от порядка импорта.
    for revision in values:
        _existing_links(revision, nodes, links, gaps)
        facts = revision.parse_result.switch_facts
        if facts is None:
            continue
        described: tuple[tuple[Any, SwitchNodeKind], ...] = (
            *((interface, "interface") for interface in facts.interfaces),
            *((aggregate, "aggregate") for aggregate in facts.aggregates),
        )
        for item, kind in described:
            if not item.description or item.description.casefold() in {"management", "irf-link"}:
                continue
            candidate = _description_name(item.description)
            matches = [value for value in hostnames.get(candidate.casefold(), ())
                       if value.device.device_id != revision.device.device_id]
            left = _id(revision, kind, item.name)
            alternatives = tuple(_id(value, "device", "device") for value in matches)
            conflicts: list[str] = []
            if len(matches) == 1:
                right = alternatives[0]
                if matches[0].parse_result.configuration.captured_at != facts.captured_at:
                    conflicts.append("Источники имеют разное время получения; одновременность не доказана.")
            else:
                right = node(revision, "neighbor", f"{kind}:{item.name}", candidate,
                             item.source_locations,
                             {"description": item.description, "identity_status": "inferred"})
                code = "AMBIGUOUS_NEIGHBOR" if matches else "MISSING_NEIGHBOR_CONFIG"
                if matches:
                    conflicts.append("Имя соответствует нескольким ревизиям; сосед не выбран.")
                gaps.append(SwitchTopologyGap(
                    code=code, node_id=right,
                    message="Сосед предполагается по description; конфигурация не сопоставлена однозначно.",
                    next_source=f"Конфигурация предполагаемого соседа {candidate} и данные LLDP.",
                    provenance=(_basis(revision, item.source_locations),),
                ))
            links.append(SwitchTopologyLink(
                link_id=f"{left}:neighbor:{right}", left=left, right=right, kind="neighbor",
                status="inferred", evidence_kind="configuration_description",
                alternatives=alternatives if len(matches) != 1 else (),
                conflicts=tuple(conflicts), provenance=(
                    _basis(revision, item.source_locations),
                    *(_basis(value) for value in matches),
                ),
            ))
    if len({value.parse_result.configuration.captured_at for value in values}) > 1:
        gaps.append(SwitchTopologyGap(
            code="DIFFERENT_CAPTURE_TIMES",
            message="Снимки получены в разное время; карта не является единым наблюдаемым состоянием.",
            next_source="Согласованные по времени конфигурации и операционные свидетельства.",
        ))
    return SwitchTopology(
        built_at=built_at or datetime.now(UTC), nodes=tuple(nodes.values()),
        links=tuple(links), gaps=tuple(gaps),
    )


def _existing_links(
    revision: DeviceRevision, nodes: dict[str, SwitchTopologyNode],
    links: list[SwitchTopologyLink], gaps: list[SwitchTopologyGap],
) -> None:
    """Не превращать конфигурационную ссылку в наблюдение без отдельного основания."""
    sources = {source.source_document_id: source for source in revision.sources}
    for link in revision.topology_links:
        source = sources.get(link.source_document_id) if link.source_document_id is not None else None
        observation = source.observation if source is not None else None
        manual = link.origin == DataOrigin.MANUAL and link.manual_reason and link.recorded_at
        observed = (
            source is not None and source.kind == SourceDocumentKind.TOPOLOGY
            and observation is not None and observation.method == "device_export"
        )
        if link.data_status != DataStatus.KNOWN or not (manual or observed):
            gaps.append(SwitchTopologyGap(
                code="TOPOLOGY_EVIDENCE_INSUFFICIENT", node_id=_id(revision, "device", "device"),
                message="Сохранённая топологическая связь не имеет достаточного основания наблюдения.",
                next_source="Отдельное свидетельство состояния или подтверждение оператора.",
                provenance=(_basis(revision),),
            ))
            continue
        provenance = SwitchTopologyProvenance(
            revision_id=revision.revision_id,
            source_name=source.source_name if source is not None else revision.parse_result.configuration.source_name,
            content_sha256=source.content_sha256 if source is not None else revision.parse_result.configuration.content_sha256,
            captured_at=source.captured_at if source is not None else revision.parse_result.configuration.captured_at,
            source_document_id=source.source_document_id if source is not None else None,
            source_locations=(link.source_location,) if link.source_location is not None else (),
            observed_at=observation.observed_at if observation is not None else None,
            recorded_at=link.recorded_at,
            reference=link.manual_reason if manual else observation.reference if observation else None,
        )
        for endpoint in (link.left_endpoint_id, link.right_endpoint_id):
            identifier = _id(revision, "interface", f"evidence:{endpoint}")
            interface = next((value for value in revision.interfaces if value.interface_id == endpoint), None)
            segment = next((value for value in revision.network_segments if value.segment_id == endpoint), None)
            nodes[identifier] = SwitchTopologyNode(
                node_id=identifier, kind="interface" if interface is not None else "segment",
                label=interface.name if interface is not None else segment.name if segment else endpoint,
                device_id=revision.device.device_id, revision_id=revision.revision_id,
                provenance=(provenance,),
            )
        links.append(SwitchTopologyLink(
            link_id=_id(revision, "topology", link.link_id),
            left=_id(revision, "interface", f"evidence:{link.left_endpoint_id}"),
            right=_id(revision, "interface", f"evidence:{link.right_endpoint_id}"), kind="topology",
            status="operator_confirmed" if manual else "observed",
            evidence_kind="operator_confirmation" if manual else "device_export",
            provenance=(provenance,),
        ))


def build_switch_topology_from_items(
    items: Sequence[Mapping[str, Any]], *, built_at: datetime | None = None
) -> SwitchTopology:
    """Читать полные сохранённые ревизии; не создавать идентичность из имени файла."""
    revisions: list[DeviceRevision] = []
    gaps: list[SwitchTopologyGap] = []
    for item in items:
        payload = item.get("revision")
        if payload is None:
            gaps.append(SwitchTopologyGap(
                code="REVISION_UNAVAILABLE",
                message="У сохранённого элемента нет полной ревизии; структура не восстановлена.",
                next_source="Повторный импорт конфигурации с сохранением ревизии.",
            ))
            continue
        try:
            revisions.append(DeviceRevision.model_validate(payload))
        except (ValueError, TypeError):
            gaps.append(SwitchTopologyGap(
                code="REVISION_INVALID",
                message="Сохранённая ревизия не прошла проверку контракта; структура не восстановлена.",
                next_source="Корректный сохранённый снимок или повторный импорт.",
            ))
    result = build_switch_topology(revisions, built_at=built_at)
    return SwitchTopology.model_validate({
        **result.model_dump(mode="python"), "gaps": (*result.gaps, *gaps),
    })
