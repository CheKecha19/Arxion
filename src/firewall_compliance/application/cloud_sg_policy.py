"""Граница локального решения для подтверждённых политик SG Advanced."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import ip_network
from typing import Annotated, Literal, Self
from uuid import UUID, uuid5

from pydantic import AwareDatetime, Field, StringConstraints, field_validator, model_validator

from firewall_compliance.analysis.policy_coverage import PacketBox
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.controls import ControlModel
from firewall_compliance.domain.enums import DataStatus, RuleAction
from firewall_compliance.domain.policy_matching import merge_intervals
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.source import SourceLocation

ADVANCED_ORDERED_PROJECTION = "sg-1.1.0"
ADVANCED_MULTI_ORDERED_PROJECTION = "sg-1.2.0"
ADVANCED_MATCHING_REFERENCE = "https://cloud.ru/docs/en-ru/usermanual/vpc/en-us_topic_0073379079"
ADVANCED_GROUP_ORDER_REFERENCE = "https://cloud.ru/docs/en/usermanual/vpc/en-us_topic_0073379079"
_GROUP_STRIDE = 256

type _OrderIdentifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]


class CloudSGOrderEvidence(ControlModel):
    """Наблюдённая очередность назначенных групп одного интерфейса и сбора."""

    scan_id: _OrderIdentifier
    scope_id: _OrderIdentifier
    interface_id: _OrderIdentifier
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: AwareDatetime
    source_name: _OrderIdentifier
    source_reference: _OrderIdentifier
    group_ids: tuple[_OrderIdentifier, ...] = Field(min_length=2)

    @field_validator("observed_at")
    @classmethod
    def _utc_observation(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_group_ids(self) -> Self:
        if len(set(self.group_ids)) != len(self.group_ids):
            raise ValueError("В наблюдённом порядке группа должна встречаться один раз")
        return self

    @property
    def evidence_sha256(self) -> str:
        return sha256(self.model_dump_json().encode("utf-8")).hexdigest()


def advanced_multi_configuration_id(device_id: UUID, order: CloudSGOrderEvidence) -> UUID:
    return uuid5(
        device_id,
        f"{order.scan_id}/{order.snapshot_sha256}/{ADVANCED_MULTI_ORDERED_PROJECTION}/{order.evidence_sha256}",
    )


@dataclass(frozen=True, slots=True)
class AdvancedSGPolicy:
    interface_id: str
    direction: Literal["in", "out"]
    source_locations: tuple[SourceLocation, ...]
    domain: tuple[PacketBox, ...]
    order_evidence: CloudSGOrderEvidence | None = None
    locations_by_group: tuple[tuple[SourceLocation, ...], ...] = ()

    @property
    def matching_reference(self) -> str:
        return ADVANCED_GROUP_ORDER_REFERENCE if self.order_evidence is not None else ADVANCED_MATCHING_REFERENCE

    def rule_facts(self, rule: Rule) -> dict[str, str | int]:
        group_position, priority = _advanced_rule_rank(rule.sequence)
        facts: dict[str, str | int] = {"priority": priority, "reference": self.matching_reference}
        if self.order_evidence is not None:
            facts.update(
                security_group_id=self.order_evidence.group_ids[group_position],
                security_group_position=group_position + 1,
                order_observed_at=self.order_evidence.observed_at.isoformat(),
            )
        return facts

    def rule_locations(self, rule: Rule) -> tuple[SourceLocation, ...]:
        if self.order_evidence is None:
            return self.source_locations
        group_position, _ = _advanced_rule_rank(rule.sequence)
        return self.locations_by_group[group_position]


def advanced_rule_order(priority: int, action: RuleAction, *, group_position: int = 0) -> int:
    """Сначала группа, затем приоритет и запрещающее действие при равном приоритете."""
    return group_position * _GROUP_STRIDE + 2 * priority + int(action == RuleAction.ALLOW)


def _advanced_rule_rank(sequence: int) -> tuple[int, int]:
    group_position, rank = divmod(sequence, _GROUP_STRIDE)
    return group_position, rank // 2


def _saved_group_order(
    revision: DeviceRevision, interface_id: str, group_ids: set[str | None],
) -> tuple[CloudSGOrderEvidence, tuple[SourceLocation, ...]] | None:
    parsed = revision.parse_result
    configuration = parsed.configuration
    anchor = parsed.source_map.get("sg-order-observation")
    if anchor is None or anchor.object_id is None or anchor.object_path is None or revision.device.context is None:
        return None
    order_sources = [
        source for source in revision.sources
        if source.source_document_id == uuid5(configuration.configuration_id, "group-order")
    ]
    if len(order_sources) != 1:
        return None
    source = order_sources[0]
    observation = source.observation
    if (
        source.source_name != anchor.source_name or observation is None
        or observation.method != "operator_declared" or observation.reference != anchor.object_path
        or observation.observed_at != source.captured_at
        or observation.observed_at != configuration.captured_at
    ):
        return None
    order_by_index = {key: value for key, value in parsed.source_map.items() if key.startswith("sg-order:")}
    positions: list[SourceLocation] = []
    for index in range(len(order_by_index)):
        position = order_by_index.get(f"sg-order:{index}")
        if (
            position is None or position.object_id is None or position.source_name != source.source_name
            or position.object_path != f"/group_ids/{index}"
        ):
            return None
        positions.append(position)
    if {position.object_id for position in positions} != group_ids:
        return None
    try:
        order = CloudSGOrderEvidence.model_validate({
            "scan_id": anchor.object_id,
            "scope_id": revision.device.context,
            "interface_id": interface_id,
            "snapshot_sha256": configuration.content_sha256,
            "observed_at": observation.observed_at,
            "source_name": source.source_name,
            "source_reference": observation.reference,
            "group_ids": tuple(position.object_id for position in positions),
        })
        expected_configuration = advanced_multi_configuration_id(UUID(revision.device.device_id), order)
    except ValueError:
        return None
    if (
        source.content_sha256 != order.evidence_sha256 or configuration.configuration_id != expected_configuration
        or revision.revision_id != uuid5(expected_configuration, "revision")
    ):
        return None
    return order, (anchor, *positions)


def advanced_sg_policy(
    revision: DeviceRevision, policy_id: str, rules: tuple[Rule, ...],
) -> AdvancedSGPolicy | None:
    """Восстановить границы ранее нормализованного полного снимка привязки."""
    parsed = revision.parse_result
    parser_version = parsed.configuration.parser_version
    if (
        revision.device.platform != "cloud-ru-advanced-sg"
        or parser_version not in {ADVANCED_ORDERED_PROJECTION, ADVANCED_MULTI_ORDERED_PROJECTION}
        or parsed.errors or parsed.unsupported_constructs
        or parsed.coverage.recognized_constructs != parsed.coverage.discovered_constructs
        or not rules or not policy_id.startswith("sg:")
    ):
        return None
    parts = policy_id.split(":")
    if len(parts) != 4:
        return None
    _, _, policy_direction, policy_family = parts
    if policy_direction not in {"ingress", "egress"} or policy_family not in {"ipv4", "ipv6"}:
        return None
    multi = parser_version == ADVANCED_MULTI_ORDERED_PROJECTION
    if multi and policy_direction != "ingress":
        return None
    family: Literal[4, 6] = 4 if policy_family == "ipv4" else 6
    direction: Literal["in", "out"] = "in" if policy_direction == "ingress" else "out"
    endpoints = [endpoint for endpoint in parsed.endpoints if endpoint.endpoint_id.startswith("interface:")]
    if len(endpoints) != 1 or not endpoints[0].cidrs:
        return None
    local = endpoints[0]
    active_ids = {rule.rule_id for rule in parsed.rules if rule.enabled}
    if active_ids != {rule.rule_id for rule in rules} or len(active_ids) != len(rules):
        return None
    prefixes = ("sg-interface:", "sg-assignment:", "sg-group:")
    entries = sorted((key, loc) for key, loc in parsed.source_map.items() if key.startswith(prefixes))
    anchors = {prefix: [loc for key, loc in entries if key.startswith(prefix)] for prefix in prefixes}
    if any(not anchors[prefix] for prefix in prefixes):
        return None
    group_ids = {loc.object_id for loc in anchors["sg-group:"]}
    assignment_ids = {loc.object_id for loc in anchors["sg-assignment:"]}
    if group_ids != assignment_ids or None in group_ids:
        return None
    locations = tuple(loc for prefix in prefixes for loc in anchors[prefix])
    interface_id = local.endpoint_id.removeprefix("interface:")
    order = None
    locations_by_group: tuple[tuple[SourceLocation, ...], ...] = ()
    if multi:
        saved_order = _saved_group_order(revision, interface_id, group_ids)
        if saved_order is None:
            return None
        order, order_locations = saved_order
        locations = (*locations, *order_locations)
        related: dict[str, list[SourceLocation]] = defaultdict(list)
        for location in (*anchors["sg-assignment:"], *anchors["sg-group:"]):
            if location.object_id is not None:
                related[location.object_id].append(location)
        observation, *positions = order_locations
        locations_by_group = tuple(
            (*anchors["sg-interface:"], observation, position, *related[identifier])
            for identifier, position in zip(order.group_ids, positions, strict=True)
        )
    elif len(group_ids) != 1:
        return None
    group_records = {loc.object_path: loc.object_id for loc in anchors["sg-group:"]}
    for rule in rules:
        position, priority = _advanced_rule_rank(rule.sequence)
        if (
            rule.policy_id != policy_id or rule.policy_direction != direction or rule.policy_semantics != "first_match"
            or rule.match_status != DataStatus.KNOWN or not rule.enabled
            or rule.action not in {RuleAction.ALLOW, RuleAction.DENY}
            or not 1 <= priority <= 100
            or rule.sequence != advanced_rule_order(priority, rule.action, group_position=position)
            or (rule.destinations if direction == "in" else rule.sources) != (local,)
        ):
            return None
        if order is None:
            if position != 0:
                return None
        else:
            record, separator, index = (rule.source_location.object_path or "").rpartition("/data/security_rules/")
            if (
                position >= len(order.group_ids) or not separator or not index.isascii() or not index.isdecimal()
                or group_records.get(record) != order.group_ids[position]
                or rule.source_location.source_name != parsed.configuration.source_name
            ):
                return None
    addresses = tuple(ip_network(value) for value in local.cidrs)
    if any(address.version != family or address.num_addresses != 1 for address in addresses):
        return None
    # У SG вход/выход уже определён самой проекцией, а матрица строит область с общей осью направления.
    unrestricted = (0, (1 << (32 if family == 4 else 128)) - 1)
    known_hosts = merge_intervals([
        (int(value.network_address), int(value.network_address)) for value in addresses
    ])
    domain = tuple(
        PacketBox(
            family,
            (unrestricted, host, (0, 255), (0, 65535), (0, 1)) if direction == "in"
            else (host, unrestricted, (0, 255), (0, 65535), (0, 1)),
        )
        for host in known_hosts
    )
    return AdvancedSGPolicy(interface_id, direction, locations, domain, order, locations_by_group)
