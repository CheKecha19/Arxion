"""Immutable read contracts for organization migration preparation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

WorkspacePhase = Literal["absent", "legacy", "ready", "unsupported", "invalid", "busy", "access"]
SqlValue = str | int | float | bytes | None


@dataclass(frozen=True, slots=True)
class OriginRef:
    """Original project namespace, without inventing an organization identity."""

    project_id: str
    name: str
    created_at: str
    settings_json: str


@dataclass(frozen=True, slots=True)
class LegacyDeviceRef:
    """Injective legacy identity; equal hostnames across origins remain distinct."""

    origin_project_id: str
    raw_device_id: str


@dataclass(frozen=True, slots=True)
class TableCount:
    """Inventory count, never a substitute for a no-loss comparison."""

    table: str
    count: int


@dataclass(frozen=True, slots=True)
class InspectionIssue:
    """Safe scoped issue; raw payload and credential values are excluded."""

    code: str
    table: str = ""
    row_key: str = ""
    detail: str = ""
    severity: Literal["error", "unsupported", "warning"] = "error"


@dataclass(frozen=True, slots=True)
class WorkspaceInspection:
    """Read-only store state, separate from future schema migration execution."""

    schema_version: int | None
    phase: WorkspacePhase
    origins: tuple[OriginRef, ...] = ()
    counts: tuple[TableCount, ...] = ()
    logical_digest: str | None = None
    issues: tuple[InspectionIssue, ...] = ()
    organization_id: None = None
    chronology: Literal["sequence_unavailable"] = "sequence_unavailable"


@dataclass(frozen=True, slots=True)
class RawLegacyRow:
    """Exact SQLite values for internal preservation checks, hidden from repr."""

    rowid: int
    values: tuple[SqlValue, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class LegacyTable:
    """Captured table in one read transaction, including original SQLite types."""

    name: str
    columns: tuple[str, ...]
    rows: tuple[RawLegacyRow, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class LegacyWorkspaceSnapshot:
    """Internal immutable read transaction output; never dump into logs."""

    path: Path
    inspection: WorkspaceInspection
    tables: tuple[LegacyTable, ...] = field(default=(), repr=False)
    unsupported_item_ids: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class LegacyRunView:
    """Original operation and settings, retaining its legacy origin."""

    run_id: str
    origin: OriginRef
    created_at: str
    finished_at: str | None
    state: str
    settings_json: str
    snapshot_rowid: int


@dataclass(frozen=True, slots=True)
class LegacyScanView:
    """Collection with exact public JSON and an unresolved legacy namespace."""

    scan_id: str
    origin: OriginRef
    created_at: str
    finished_at: str | None
    state: str
    selection_json: str
    config_json: str
    result_json: str
    snapshot_rowid: int


@dataclass(frozen=True, slots=True)
class LegacyItemView:
    """Original opaque payload; semantic support is explicit."""

    item_id: str
    run_id: str
    payload_json: str
    semantic_support: Literal["supported", "unsupported"]


@dataclass(frozen=True, slots=True)
class LegacyRunDetail:
    """Run and exact item/decision texts without rewriting historical bytes."""

    run: LegacyRunView
    items: tuple[LegacyItemView, ...]
    marks: tuple[tuple[str, str, str, str], ...]


@dataclass(frozen=True, slots=True)
class LegacyDeviceView:
    """Latest usable historical analysis; ordering does not prove chronology."""

    identity: LegacyDeviceRef
    origin: OriginRef
    run_id: str
    item_id: str
    payload_json: str
    created_at: str
    snapshot_order: tuple[int, int]
    device_uid: None = None
    chronology: Literal["sequence_unavailable"] = "sequence_unavailable"
