"""Построение и выбор связей логической карты без зависимости от UI."""

from datetime import datetime
from ipaddress import ip_network

from pydantic import ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.acl_map import (
    AclMap,
    AclMapRelation,
    acl_map_limitations,
    derive_acl_map,
)
from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.enums import DataStatus, Protocol, RuleAction
from firewall_compliance.domain.policy_matching import resolve_addresses, resolve_services
from firewall_compliance.domain.revision import DeviceRevision


class AclMapFilter(DomainModel):
    """View-only conjunction; network filters mean overlap, never permission."""

    model_config = ConfigDict(frozen=True)

    policy_id: str | None = None
    rule_id: str | None = None
    action: RuleAction | None = None
    enabled: bool | None = None
    source_cidr: str | None = None
    destination_cidr: str | None = None
    protocol: Protocol | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    include_unknown: bool = True

    @field_validator("source_cidr", "destination_cidr")
    @classmethod
    def validate_cidr(cls, value: str | None) -> str | None:
        return str(ip_network(value, strict=False)) if value is not None else None

    @model_validator(mode="after")
    def validate_port(self) -> "AclMapFilter":
        if self.destination_port is not None and self.protocol not in {
            None,
            Protocol.TCP,
            Protocol.UDP,
            Protocol.IP,
        }:
            raise ValueError("destination_port requires TCP, UDP or an unspecified protocol")
        return self


def _network_overlap(relation: AclMapRelation, field: str, cidr: str) -> bool | None:
    rule = relation.rule
    status = rule.source_status if field == "sources" else rule.destination_status
    if rule.match_status != DataStatus.KNOWN or status != DataStatus.KNOWN:
        return None
    addresses = resolve_addresses(rule.sources if field == "sources" else rule.destinations)
    if addresses is None:
        return None
    network = ip_network(cidr)
    start, end = int(network.network_address), int(network.broadcast_address)
    return any(a <= end and b >= start for a, b in addresses[0 if network.version == 4 else 1])


def _service_overlap(relation: AclMapRelation, filters: AclMapFilter) -> bool | None:
    rule = relation.rule
    if rule.match_status != DataStatus.KNOWN or rule.service_status != DataStatus.KNOWN:
        return None
    services = resolve_services(rule.services)
    if services is None:
        return None
    for protocol, ports in services:
        if (
            filters.protocol is not None
            and filters.protocol != Protocol.IP
            and protocol
            not in {
                "ip",
                filters.protocol.value,
            }
        ):
            continue
        if filters.destination_port is None:
            return True
        if protocol in {"ip", "tcp", "udp"} and any(
            start <= filters.destination_port <= end for start, end in ports
        ):
            return True
    return False


def filter_acl_relations(graph: AclMap, filters: AclMapFilter) -> tuple[AclMapRelation, ...]:
    """Keep indeterminate matches visible by default; preserve source rule order."""
    validated = AclMap.model_validate(graph.model_dump(mode="python"))
    filters = AclMapFilter.model_validate(filters.model_dump(mode="python"))
    candidates = select_acl_relations(
        validated,
        policy_id=filters.policy_id,
        rule_id=filters.rule_id,
        action=filters.action,
        enabled=filters.enabled,
    )
    result: list[AclMapRelation] = []
    for relation in candidates:
        matches: list[bool | None] = []
        if filters.source_cidr is not None:
            matches.append(_network_overlap(relation, "sources", filters.source_cidr))
        if filters.destination_cidr is not None:
            matches.append(_network_overlap(relation, "destinations", filters.destination_cidr))
        if filters.protocol is not None or filters.destination_port is not None:
            matches.append(_service_overlap(relation, filters))
        if False not in matches and (filters.include_unknown or None not in matches):
            result.append(relation)
    return tuple(result)


def build_acl_map(revision: DeviceRevision, *, built_at: datetime) -> AclMap:
    """Проверить вход и вернуть отдельный неизменяемый снимок карты."""
    validated = DeviceRevision.model_validate(revision.model_dump(mode="python"))
    nodes, relations = derive_acl_map(validated)
    return AclMap(
        revision=validated,
        built_at=built_at,
        nodes=nodes,
        relations=relations,
        limitations=acl_map_limitations(validated, relations),
    )


def select_acl_relations(
    graph: AclMap,
    *,
    policy_id: str | None = None,
    rule_id: str | None = None,
    action: RuleAction | None = None,
    enabled: bool | None = None,
) -> tuple[AclMapRelation, ...]:
    """Отфильтровать представление, не меняя полноту исходного результата."""
    validated = AclMap.model_validate(graph.model_dump(mode="python"))
    return tuple(
        relation
        for relation in validated.relations
        if (policy_id is None or relation.rule.policy_id == policy_id)
        and (rule_id is None or relation.rule.rule_id == rule_id)
        and (action is None or relation.rule.action == action)
        and (enabled is None or relation.rule.enabled == enabled)
    )
