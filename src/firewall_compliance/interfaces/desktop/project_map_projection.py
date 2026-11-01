"""Bounded visual grouping; original nodes/rules remain the authoritative graph."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from math import ceil

from firewall_compliance.interfaces.desktop.project_map import (
    ProjectMap, ProjectMapEdge, ProjectMapNode, identity,
)


@dataclass(frozen=True, slots=True)
class ProjectMapProjection:
    graph: ProjectMap
    members: dict[str, tuple[str, ...]]
    source_nodes: int
    source_edges: int


def bounded_project_map(
    graph: ProjectMap, visible: set[str], edges: tuple[ProjectMapEdge, ...],
    *, node_budget: int = 100, detail: bool = False, anchor: str | None = None,
    detail_members: frozenset[str] | None = None,
) -> ProjectMapProjection:
    """Represent every selected node within the budget, with explicit drill-down.

    Groups describe a presentation slice, never a physical segment or effective
    permission. A detail slice uses balanced chunks so repeated drill-down always
    makes progress even if every host belongs to one original address group.
    """
    if type(node_budget) is not int or node_budget < 3:
        raise ValueError("Node budget must allow detail and boundary objects")
    selected = tuple(sorted(
        (node for node in graph.nodes if node.key in visible), key=lambda node: node.key
    ))
    selected_ids = {node.key for node in selected}
    selected_edges = tuple(
        edge for edge in edges if edge.source in selected_ids and edge.target in selected_ids
    )
    if len(selected) <= node_budget:
        return ProjectMapProjection(
            ProjectMap(graph.project_id, selected, selected_edges, graph.areas, graph.warnings, graph.rule_inputs),
            {node.key: (node.key,) for node in selected}, len(selected), len(selected_edges),
        )
    anchored = tuple(node for node in selected if node.key == anchor)
    candidates = tuple(node for node in selected if node.key != anchor)
    slots = node_budget - len(anchored)
    groups: list[tuple[str, tuple[ProjectMapNode, ...]]] = []
    boundary: tuple[ProjectMapNode, ...] = ()
    if detail and detail_members is not None:
        boundary = tuple(node for node in candidates if node.key not in detail_members)
        candidates = tuple(node for node in candidates if node.key in detail_members)
        slots -= bool(boundary)
    if not detail:
        zones: dict[tuple[str, str, str], list[ProjectMapNode]] = defaultdict(list)
        for node in candidates:
            zones[node.area, node.scope, node.zone].append(node)
        if len(zones) <= slots:
            groups = [(key[2], tuple(values)) for key, values in sorted(zones.items())]
        else:
            areas: dict[str, list[ProjectMapNode]] = defaultdict(list)
            for node in candidates:
                areas[node.area].append(node)
            if len(areas) <= slots:
                groups = [(graph.areas.get(key, key), tuple(values)) for key, values in sorted(areas.items())]
    if not groups:
        size = max(1, ceil(len(candidates) / slots))
        groups = [
            (f"Объекты {start + 1}–{min(start + size, len(candidates))}", candidates[start:start + size])
            for start in range(0, len(candidates), size)
        ]
    if boundary:
        groups.append(("Связанные объекты вне раскрываемой группы", boundary))
    nodes = list(anchored)
    members = {node.key: (node.key,) for node in anchored}
    representative = {node.key: node.key for node in anchored}
    areas = dict(graph.areas)
    for label, values in groups:
        if len(values) == 1:
            node = values[0]
        else:
            keys = tuple(value.key for value in values)
            key = "view-group:" + identity(keys)
            area_ids = {value.area for value in values}
            area = values[0].area if len(area_ids) == 1 else "view-overview"
            if area == "view-overview":
                areas[area] = "Сводные области"
            node = ProjectMapNode(
                key, f"{label} · {len(values)} объектов", "network", area, label,
                details=(
                    "Группа представления. Не является доказательством общей сети или доступа.",
                    "Выберите «Раскрыть группу» для подробностей.",
                    *(value.label for value in values[:20]),
                    f"Всего участников: {len(values)}; полный состав доступен при раскрытии.",
                ),
                scope="view:" + identity(keys),
            )
        nodes.append(node)
        members[node.key] = tuple(value.key for value in values)
        for value in values:
            representative[value.key] = node.key
    bundles: dict[tuple[str, str, str, str, bool, str], list[ProjectMapEdge]] = defaultdict(list)
    for edge in selected_edges:
        bundles[
            representative[edge.source], representative[edge.target],
            edge.kind, edge.action, edge.enabled, edge.status,
        ].append(edge)
    projected_edges = tuple(
        ProjectMapEdge(
            source, target, kind, action, enabled, status,
            tuple(dict.fromkeys(rule for edge in values for rule in edge.rules)),
            tuple(dict.fromkeys(value for edge in values for value in edge.details)),
        )
        for (source, target, kind, action, enabled, status), values in sorted(bundles.items())
    )
    return ProjectMapProjection(
        ProjectMap(graph.project_id, tuple(nodes), projected_edges, areas, graph.warnings, graph.rule_inputs),
        members, len(selected), len(selected_edges),
    )
