"""Построение и выбор связей логической карты без зависимости от UI."""

from datetime import datetime

from firewall_compliance.domain.acl_map import (
    AclMap,
    AclMapRelation,
    acl_map_limitations,
    derive_acl_map,
)
from firewall_compliance.domain.enums import RuleAction
from firewall_compliance.domain.revision import DeviceRevision


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
