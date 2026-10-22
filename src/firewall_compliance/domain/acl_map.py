"""Версионированная карта условий ACL, не являющаяся картой достижимости."""

import json
from datetime import datetime
from hashlib import sha256
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus, RuleAction
from firewall_compliance.domain.network import Endpoint, Service
from firewall_compliance.domain.policy_matching import resolve_rule
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.snapshot import freeze_snapshot_fields


class AclMapNode(DomainModel):
    """Объект внутри области одной ревизии и политики."""

    model_config = ConfigDict(frozen=True)

    node_id: str = Field(min_length=1)
    kind: Literal["endpoint", "service", "unknown"]
    endpoint: Endpoint | None = None
    service: Service | None = None
    unknown_dimension: Literal["source", "destination", "service"] | None = None

    @model_validator(mode="after")
    def validate_value(self) -> "AclMapNode":
        expected = {
            "endpoint": (True, False, False),
            "service": (False, True, False),
            "unknown": (False, False, True),
        }[self.kind]
        actual = (
            self.endpoint is not None,
            self.service is not None,
            self.unknown_dimension is not None,
        )
        if actual != expected:
            raise ValueError("узел карты должен содержать только значение своего типа")
        return self


class AclMapRelation(DomainModel):
    """Одно правило как связь наборов условий без декартова размножения."""

    model_config = ConfigDict(frozen=True)

    relation_id: str = Field(min_length=1)
    rule: Rule
    source_node_ids: tuple[str, ...]
    destination_node_ids: tuple[str, ...]
    service_node_ids: tuple[str, ...]
    condition_status: Literal["known", "unknown", "unsupported"]


def _identifier(prefix: str, values: list[object]) -> str:
    encoded = json.dumps(values, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return prefix + sha256(encoded.encode("utf-8")).hexdigest()


def _condition_status(rule: Rule) -> Literal["known", "unknown", "unsupported"]:
    statuses = (
        rule.match_status,
        rule.source_status,
        rule.destination_status,
        rule.service_status,
        *(value.resolution_status for value in rule.sources),
        *(value.resolution_status for value in rule.destinations),
        *(value.resolution_status for value in rule.services),
    )
    if DataStatus.UNSUPPORTED in statuses:
        return "unsupported"
    return "known" if resolve_rule(rule) is not None else "unknown"


def derive_acl_map(
    revision: DeviceRevision,
) -> tuple[tuple[AclMapNode, ...], tuple[AclMapRelation, ...]]:
    """Построить каноническую проекцию, сохранив порядок исходных правил."""
    nodes: dict[str, AclMapNode] = {}
    relations: list[AclMapRelation] = []
    rule_ids = [rule.rule_id for rule in revision.parse_result.rules]
    if len(set(rule_ids)) != len(rule_ids):
        raise ValueError("карта ACL требует уникальные rule_id внутри ревизии")
    for rule in revision.parse_result.rules:
        scope: list[object] = [
            str(revision.revision_id),
            rule.policy_id,
            rule.policy_direction,
            rule.source_zone,
            rule.destination_zone,
            rule.rule_id if rule.policy_id is None else None,
        ]
        dimensions: list[tuple[str, ...]] = []
        condition_values: tuple[
            tuple[Literal["source", "destination", "service"], tuple[Endpoint | Service, ...]], ...
        ] = (
            ("source", rule.sources),
            ("destination", rule.destinations),
            ("service", rule.services),
        )
        for dimension, values in condition_values:
            identifiers: list[str] = []
            for value in values:
                kind: Literal["endpoint", "service"] = (
                    "endpoint" if isinstance(value, Endpoint) else "service"
                )
                node_id = _identifier("node:", [*scope, kind, value.model_dump(mode="json")])
                nodes.setdefault(
                    node_id,
                    AclMapNode(
                        node_id=node_id,
                        kind=kind,
                        endpoint=value if isinstance(value, Endpoint) else None,
                        service=value if isinstance(value, Service) else None,
                    ),
                )
                identifiers.append(node_id)
            if not identifiers:
                node_id = _identifier("node:", [*scope, "unknown", rule.rule_id, dimension])
                nodes[node_id] = AclMapNode(
                    node_id=node_id,
                    kind="unknown",
                    unknown_dimension=dimension,
                )
                identifiers.append(node_id)
            dimensions.append(tuple(dict.fromkeys(identifiers)))
        relations.append(
            AclMapRelation(
                relation_id=_identifier("rule:", [str(revision.revision_id), rule.rule_id]),
                rule=rule,
                source_node_ids=dimensions[0],
                destination_node_ids=dimensions[1],
                service_node_ids=dimensions[2],
                condition_status=_condition_status(rule),
            )
        )
    return tuple(nodes.values()), tuple(relations)


def acl_map_limitations(
    revision: DeviceRevision, relations: tuple[AclMapRelation, ...]
) -> tuple[str, ...]:
    """Описать границы карты независимо от выбранного представления UI."""
    reasons = [
        "Карта показывает заданные условия правил, а не эффективные разрешения ACL.",
        "Привязки, порядок применения ACL, маршруты, NAT и сквозная достижимость не вычисляются.",
    ]
    parsed = revision.parse_result
    if (
        parsed.warnings
        or parsed.errors
        or parsed.unsupported_constructs
        or parsed.coverage.recognized_constructs != parsed.coverage.discovered_constructs
    ):
        reasons.append("Источник имеет диагностику или неполное покрытие; карта не полная.")
    if any(relation.condition_status != "known" for relation in relations):
        reasons.append("Условия части правил неизвестны или не поддержаны.")
    if any(relation.rule.action == RuleAction.UNKNOWN for relation in relations):
        reasons.append("Действие части правил неизвестно.")
    if not relations:
        reasons.append("Нет разобранных правил; это не доказывает отсутствие политики.")
    return tuple(reasons)


class AclMap(DomainModel):
    """Автономный нормализованный результат для UI, JSON и графовых экспортов."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    analyzer_version: Literal["0.1.0"] = "0.1.0"
    mode: Literal["declared_rules"] = "declared_rules"
    revision: DeviceRevision
    built_at: datetime
    nodes: tuple[AclMapNode, ...]
    relations: tuple[AclMapRelation, ...]
    limitations: tuple[str, ...]

    @field_validator("revision", mode="before")
    @classmethod
    def validate_revision(cls, value: object) -> DeviceRevision:
        if isinstance(value, DeviceRevision):
            value = value.model_dump(mode="python")
        return DeviceRevision.model_validate(value)

    @model_validator(mode="after")
    def validate_projection(self) -> "AclMap":
        if self.built_at.tzinfo is None or self.built_at < self.revision.imported_at:
            raise ValueError("built_at требует часовой пояс и не может быть раньше импорта")
        expected_nodes, expected_relations = derive_acl_map(self.revision)
        if self.nodes != expected_nodes or self.relations != expected_relations:
            raise ValueError("карта ACL должна точно соответствовать правилам своей ревизии")
        if self.limitations != acl_map_limitations(self.revision, expected_relations):
            raise ValueError("ограничения карты ACL должны соответствовать входным данным")
        freeze_snapshot_fields(self)
        return self
