"""Project-scoped reads for the resource neighborhood in the desktop registry."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.project_map import (
    CONTOUR,
    ProjectMap,
    ProjectMapNode,
    build_project_map,
)
from firewall_compliance.interfaces.desktop.project_map_address import build_address_project_map
from firewall_compliance.interfaces.desktop.project_map_cloud_neighborhood import (
    cloud_resource_neighborhood,
)
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.resource_registry import (
    MATRIX_BINDING_FIELD,
    resource_address_binding,
)
from firewall_compliance.interfaces.desktop.workspace_models import cloud_resource_key


@dataclass(frozen=True, slots=True)
class ResourceNeighborhood:
    graph: ProjectMap
    anchor: str
    presentation: str
    scope: str


class ResourceNeighborhoodUnavailable(ValueError):
    """An actionable message for a selected saved resource."""


def read_resource_neighborhood(
    store: ProjectStore,
    project_id: str,
    resource: Mapping[str, Any],
    site_id: str | None,
    assignments: Mapping[str, str],
    sites: Sequence[Mapping[str, str]],
    *,
    cancelled: Callable[[], bool],
) -> ResourceNeighborhood:
    if cancelled():
        raise InterruptedError("Чтение окружения отменено.")
    if resource.get("project_id") != project_id:
        raise ResourceNeighborhoodUnavailable("Карточка относится к другому проекту.")
    label = str(resource.get("label") or resource.get("name") or resource["id"])
    source = resource.get("source") or {}
    site_names = {site["id"]: site["name"] for site in sites}
    aliases = set(resource.get("identities") or [resource.get("identity")])

    def site_label(value: str) -> str:
        return site_names.get(value, value) if value else "Без площадки"

    def check_site(value: str) -> None:
        if site_id is not None and site_id != value:
            raise ResourceNeighborhoodUnavailable(
                f"Ресурс относится к области «{site_label(value)}». Выберите её в проекте."
            )

    if source.get("kind") == "cloud" or source.get("scan_id"):
        scan_id, index = source.get("scan_id"), source.get("record_index")
        if not isinstance(scan_id, str) or type(index) is not int or index < 0:
            raise ResourceNeighborhoodUnavailable("У карточки отсутствует точная ссылка на облачный сбор.")
        scan = store.get_cloud_scan(project_id, scan_id)
        records = (scan.get("result") or {}).get("records", ()) if scan else ()
        if scan is None or index >= len(records) or not isinstance(records[index], dict):
            raise ResourceNeighborhoodUnavailable("Исходная запись облачного сбора недоступна.")
        anchor = "cloud:" + cloud_resource_key(scan, records[index], index)
        if anchor not in aliases or records[index].get("id") != source.get("resource_id"):
            raise ResourceNeighborhoodUnavailable("Исходная запись облачного сбора не совпадает с карточкой.")
        graph = cloud_resource_neighborhood(project_id, scan, index, cancelled=cancelled)
        return ResourceNeighborhood(
            graph, anchor, _initial_presentation(graph),
            f"Облачный сбор проекта · {scan['created_at']} · {scan_id}",
        )

    device_id = source.get("device_id")
    if source.get("kind") == "device" or device_id:
        if not device_id or "device:" + str(device_id) not in aliases:
            raise ResourceNeighborhoodUnavailable("Связь устройства с выбранной карточкой недоступна.")
        anchor = "device:" + str(device_id)
        assigned_site = assignments.get(str(device_id), "")
        check_site(assigned_site)
        run_id = source.get("observation_run_id") or source.get("run_id")
        item_id = source.get("observation_item_id") or source.get("item_id")
        item = store.get_run_item(project_id, run_id, item_id) if run_id and item_id else None
        if item is None or (item.get("report") or {}).get("device_id") != device_id:
            raise ResourceNeighborhoodUnavailable("Исходная сохранённая конфигурация устройства недоступна.")
        expected_digest = source.get("content_sha256")
        if expected_digest and item.get("content_sha256") != expected_digest:
            raise ResourceNeighborhoodUnavailable("Исходная конфигурация устройства не совпадает с карточкой.")
        graph = build_project_map(
            project_id, [item], (), group_rule_pairs=True, include_switch_structure=True,
            cancelled=cancelled,
        )
        graph = replace(
            graph, nodes=tuple(replace(node, label=label) if node.key == anchor else node for node in graph.nodes),
        )
        return ResourceNeighborhood(
            graph, anchor, _initial_presentation(graph), f"{site_label(assigned_site)} · запуск {run_id}",
        )

    raw_binding = (resource.get("metadata") or {}).get(MATRIX_BINDING_FIELD)
    anchor = "resource:" + str(resource["id"])
    if raw_binding is None:
        node = ProjectMapNode(anchor, label, "server", CONTOUR, "Реестр ресурсов")
        graph = ProjectMap(
            project_id, (node,), areas={CONTOUR: "Реестр ресурсов"},
            warnings=("Для карточки нет привязанного наблюдения и подтверждённых адресов. "
                      "Укажите адреса и площадку в карточке ресурса.",),
        )
        return ResourceNeighborhood(graph, anchor, "structure", "Карточка реестра")
    try:
        binding = resource_address_binding(raw_binding)
    except ValueError as error:
        raise ResourceNeighborhoodUnavailable("Уточните подтверждённые адреса и площадку в карточке.") from error
    bound_site = binding["site_id"]
    check_site(bound_site)
    area_label = site_label(bound_site)
    node = ProjectMapNode(
        anchor, label, "server", CONTOUR, "Подтверждённые адреса",
        tuple(binding["prefixes"]),
        ("Префиксы подтверждены в карточке.", "Сетевой контекст VRF карточки не установлен."),
    )
    archived = store.resource_registry.archived_device_ids(project_id)
    revisions: list[DeviceRevision] = []
    invalid = 0
    for _, _, raw in store.latest_matrix_revisions(project_id, bound_site, cancelled=cancelled):
        if cancelled():
            break
        try:
            revision = DeviceRevision.model_validate(raw)
        except ValueError:
            invalid += 1
            continue
        if (
            revision.device.device_id not in archived
            and not revision.device.platform.startswith("cloud-ru-")
        ):
            revisions.append(revision)
    graph = build_address_project_map(
        project_id, node, revisions, site_label=area_label, cancelled=cancelled,
    )
    if invalid:
        graph = replace(
            graph, warnings=(*graph.warnings, f"Сохранённых ревизий с недоступной нормализацией: {invalid}."),
        )
    return ResourceNeighborhood(graph, anchor, "access", f"{area_label} · адресные условия политик")


def _initial_presentation(graph: ProjectMap) -> str:
    if graph.edges and all(edge.kind in {"acl", "condition"} for edge in graph.edges):
        return "access"
    return "structure"
