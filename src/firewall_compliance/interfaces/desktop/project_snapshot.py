"""Reusable project read models built without Qt objects or repeated JSON parsing."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from firewall_compliance.application.source_health import build_source_health
from firewall_compliance.interfaces.desktop.workspace_models import cloud_inventory


@dataclass(frozen=True, slots=True)
class ProjectSnapshot:
    """One project load shared by desktop views until the backing store changes.

    Containers and their payloads are shared read models: consumers must not mutate
    them. A frozen envelope prevents replacing fields, not editing nested values.
    """

    project_id: str
    project: dict[str, Any]
    history: list[dict[str, Any]]
    runs: list[dict[str, Any]]
    devices: list[dict[str, Any]]
    scans: list[dict[str, Any]]
    run_by_id: dict[str, dict[str, Any]]
    site_assignments: dict[str, str] = field(default_factory=dict)
    sites: tuple[dict[str, str], ...] = ()
    source_health: tuple[dict[str, Any], ...] = ()
    compact_history: bool = False
    cloud_resources: list[dict[str, Any]] = field(default_factory=list)
    cloud_resource_history: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def scoped_project_snapshot(
    snapshot: ProjectSnapshot, assignments: Mapping[str, str], site_id: str | None
) -> ProjectSnapshot:
    """Project explicit device assignments without rewriting historical evidence.

    None selects all sites; an empty string selects devices without an assignment.
    Items lacking a usable report have unknown site and remain visible. Collection
    scans are not safely assignable here and remain project-wide. Run state and
    marks retain their original meaning; counts describe only the visible items.
    """
    if site_id is None:
        return snapshot

    def visible(item: dict[str, Any]) -> bool:
        report = item.get("report")
        if not isinstance(report, dict) or not report.get("device_id"):
            return True
        return assignments.get(str(report["device_id"]), "") == site_id

    history = []
    runs = []
    for run in snapshot.history:
        items = [item for item in run["items"] if visible(item)]
        if not items and run["items"]:
            continue
        projected = {**run, "items": items, "site_selection": site_id}
        history.append(projected)
        runs.append(
            {
                **{key: value for key, value in projected.items() if key not in {"items", "marks"}},
                "item_count": len(items),
                "source_item_count": len(run["items"]),
                "finding_count": sum(
                    len(check["findings"])
                    for item in items
                    for check in (item.get("report") or {}).get("checks", [])
                ),
            }
        )
    return ProjectSnapshot(
        snapshot.project_id,
        snapshot.project,
        history,
        runs,
        [item for item in snapshot.devices if visible(item)],
        snapshot.scans,
        {run["id"]: run for run in history},
        snapshot.site_assignments,
        snapshot.sites,
        snapshot.source_health,
        snapshot.compact_history,
        snapshot.cloud_resources,
        snapshot.cloud_resource_history,
    )


def read_project_snapshot(store: Any, project_id: str) -> ProjectSnapshot:
    """Load desktop projections without copying historical rule and network data.

    History supplies runs in descending creation/rowid order and each run's items
    in ascending rowid order. Reversing items therefore preserves the latest-device
    selection used by ``ProjectStore.list_project_devices``. Marks and original
    reports remain untouched. The store opens its own connections, so this function
    can run in a desktop worker without transferring a SQLite connection or Qt object.
    """
    project = store.get_project(project_id)
    workspace_reader = getattr(store, "project_workspace_history", None)
    workspace = workspace_reader(project_id) if callable(workspace_reader) else None
    compact = workspace is not None
    history, devices = workspace if workspace is not None else (store.project_history(project_id), [])
    cloud_reader = getattr(store, "project_cloud_scan_summaries", None)
    scans = cloud_reader(project_id) if callable(cloud_reader) else store.list_cloud_scans(project_id)
    cloud_resources, cloud_resource_history = cloud_inventory(scans)
    metadata = getattr(store, "workspace_metadata", None)
    assignments = metadata.device_sites(project_id) if metadata is not None else {}
    sites = tuple(metadata.list_sites()) if metadata is not None else ()
    source_sites = metadata.source_sites(project_id) if hasattr(metadata, "source_sites") else {}
    runs: list[dict[str, Any]] = []
    seen: set[str] = set()
    run_by_id: dict[str, dict[str, Any]] = {}
    for run in history:
        run_by_id[run["id"]] = run
        items = run["items"]
        finding_count = sum(
            len(check["findings"])
            for item in items
            if item["report"]
            for check in item["report"]["checks"]
        )
        runs.append(
            {
                **{key: value for key, value in run.items() if key not in {"items", "marks"}},
                "item_count": len(items),
                "finding_count": finding_count,
            }
        )
        if compact:
            continue
        for item in reversed(items):
            report = item.get("report")
            if not report:
                continue
            device_id = report["device_id"]
            if device_id in seen:
                continue
            seen.add(device_id)
            devices.append(
                {
                    **item,
                    "run_id": run["id"],
                    "run_created_at": run["created_at"],
                }
            )
    return ProjectSnapshot(
        project_id=project_id,
        project=project,
        history=history,
        runs=runs,
        devices=devices,
        scans=scans,
        run_by_id=run_by_id,
        site_assignments=assignments,
        sites=sites,
        source_health=build_source_health(
            store.list_source_connections(project_id), history, scans, site_memberships=source_sites,
        ) if hasattr(store, "list_source_connections") else (),
        compact_history=compact,
        cloud_resources=cloud_resources,
        cloud_resource_history=cloud_resource_history,
    )
