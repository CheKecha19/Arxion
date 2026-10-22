"""Read-only all-origin compatibility facade before organization activation."""

from __future__ import annotations

import json
from pathlib import Path

from firewall_compliance.interfaces.desktop.organization_inspection import (
    inspect_v1_snapshot,
    inspect_workspace,
    legacy_records,
)
from firewall_compliance.interfaces.desktop.organization_models import (
    LegacyDeviceRef,
    LegacyDeviceView,
    LegacyItemView,
    LegacyRunDetail,
    LegacyRunView,
    LegacyScanView,
    LegacyWorkspaceSnapshot,
    OriginRef,
    WorkspaceInspection,
)


class WorkspaceReadError(ValueError):
    """A store cannot be interpreted safely; preserve its inspection details."""

    def __init__(self, inspection: WorkspaceInspection) -> None:
        self.inspection = inspection
        super().__init__(f"Workspace unavailable: {inspection.phase}")


def _runs(snapshot: LegacyWorkspaceSnapshot) -> tuple[LegacyRunView, ...]:
    origins = {origin.project_id: origin for origin in snapshot.inspection.origins}
    runs = tuple(
        LegacyRunView(
            row["id"],
            origins[row["project_id"]],
            row["created_at"],
            row["finished_at"],
            row["state"],
            row["settings"],
            row["_rowid"],
        )
        for row in legacy_records(snapshot, "runs")
    )
    return tuple(sorted(runs, key=lambda r: (r.created_at, r.snapshot_rowid), reverse=True))


class LegacyOrganizationWorkspace:
    """Expose every legacy origin without initializing or changing its database.

    Each method reads a fresh consistent snapshot. Use get_run for a consistent
    run/items/marks bundle; separate method calls do not share a transaction.
    Unknown payloads remain opaque and are excluded from semantic projections.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def inspect(self) -> WorkspaceInspection:
        """Return exact readiness/issues without treating failed opens as empty."""
        return inspect_workspace(self.path)

    def _snapshot(self) -> LegacyWorkspaceSnapshot:
        snapshot = inspect_v1_snapshot(self.path)
        inspection = snapshot.inspection
        if inspection.phase == "legacy" or (
            inspection.phase == "unsupported" and inspection.schema_version == 1 and snapshot.tables
        ):
            return snapshot
        raise WorkspaceReadError(inspection)

    def list_origins(self) -> tuple[OriginRef, ...]:
        """Return original namespaces, including empty projects."""
        return self._snapshot().inspection.origins

    def list_runs(self) -> tuple[LegacyRunView, ...]:
        """Read all run metadata, even when some results require a future reader."""
        return _runs(self._snapshot())

    def list_cloud_scans(self) -> tuple[LegacyScanView, ...]:
        """Read every collection without collapsing providers or native IDs."""
        snapshot = self._snapshot()
        origins = {origin.project_id: origin for origin in snapshot.inspection.origins}
        scans = tuple(
            LegacyScanView(
                row["id"],
                origins[row["project_id"]],
                row["created_at"],
                row["finished_at"],
                row["state"],
                row["selection"],
                row["config"],
                row["result"],
                row["_rowid"],
            )
            for row in legacy_records(snapshot, "cloud_scans")
        )
        return tuple(sorted(scans, key=lambda s: (s.created_at, s.snapshot_rowid), reverse=True))

    def get_run(self, run_id: str) -> LegacyRunDetail:
        """Return exact original items and current decision texts from one snapshot."""
        snapshot = self._snapshot()
        run = next((r for r in _runs(snapshot) if r.run_id == run_id), None)
        if run is None:
            raise KeyError("Run not found")
        items = tuple(
            LegacyItemView(
                row["id"],
                run_id,
                row["payload"],
                "unsupported" if row["id"] in snapshot.unsupported_item_ids else "supported",
            )
            for row in legacy_records(snapshot, "items")
            if row["run_id"] == run_id
        )
        marks = tuple(
            (row["finding_id"], row["status"], row["comment"], row["updated_at"])
            for row in legacy_records(snapshot, "marks")
            if row["run_id"] == run_id
        )
        return LegacyRunDetail(run, items, marks)

    def list_devices(self) -> tuple[LegacyDeviceView, ...]:
        """Keep latest usable analyses per composite identity, never merge by name.

        Failed or future-version items remain in history but do not replace a
        supported device projection. This is not a four-clock v2 health view.
        """
        snapshot = self._snapshot()
        runs = {run.run_id: run for run in _runs(snapshot)}
        rows = sorted(
            legacy_records(snapshot, "items"),
            key=lambda row: (
                runs[row["run_id"]].created_at,
                runs[row["run_id"]].snapshot_rowid,
                row["_rowid"],
            ),
            reverse=True,
        )
        devices: dict[LegacyDeviceRef, LegacyDeviceView] = {}
        for row in rows:
            if row["id"] in snapshot.unsupported_item_ids:
                continue
            payload = json.loads(row["payload"])
            if not payload.get("report"):
                continue
            run = runs[row["run_id"]]
            identity = LegacyDeviceRef(run.origin.project_id, payload["report"]["device_id"])
            devices.setdefault(
                identity,
                LegacyDeviceView(
                    identity,
                    run.origin,
                    run.run_id,
                    row["id"],
                    row["payload"],
                    run.created_at,
                    (run.snapshot_rowid, row["_rowid"]),
                ),
            )
        return tuple(devices.values())
