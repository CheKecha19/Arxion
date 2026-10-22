"""SQLite-aware read-only inspection of supported legacy organization inputs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.enums import FindingStatus
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.organization_models import (
    InspectionIssue,
    LegacyTable,
    LegacyWorkspaceSnapshot,
    OriginRef,
    RawLegacyRow,
    SqlValue,
    TableCount,
    WorkspaceInspection,
    WorkspacePhase,
)

V1_COLUMNS = {
    "projects": ("id", "name", "created_at", "settings"),
    "runs": ("id", "project_id", "created_at", "finished_at", "state", "settings"),
    "items": ("id", "run_id", "payload"),
    "marks": ("run_id", "finding_id", "status", "comment", "updated_at"),
    "device_links": ("project_id", "source_key", "device_id"),
    "integrations": ("project_id", "provider", "config", "protected_secret"),
    "cloud_scans": (
        "id",
        "project_id",
        "created_at",
        "finished_at",
        "state",
        "selection",
        "config",
        "result",
    ),
}
_PRIMARY_KEYS = {
    "projects": ("id",),
    "runs": ("id",),
    "items": ("id",),
    "marks": ("run_id", "finding_id"),
    "device_links": ("project_id", "source_key"),
    "integrations": ("project_id", "provider"),
    "cloud_scans": ("id",),
}
_JSON_COLUMNS = {
    "projects": ("settings",),
    "runs": ("settings",),
    "items": ("payload",),
    "integrations": ("config",),
    "cloud_scans": ("selection", "config", "result"),
}


def _pairs(value: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = item
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _object(text: str) -> dict[str, Any]:
    value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def _typed_value(value: SqlValue) -> list[str]:
    if value is None:
        return ["null", ""]
    if isinstance(value, bytes):
        return ["blob", value.hex()]
    if isinstance(value, str):
        return ["text", value]
    if isinstance(value, int):
        return ["integer", str(value)]
    return ["real", value.hex()]


def _digest(tables: tuple[LegacyTable, ...]) -> str:
    digest = hashlib.sha256()
    for table in tables:
        digest.update(json.dumps([table.name, table.columns]).encode())
        # Multiset preserves exact values/types, not incidental rowid allocation.
        rows = sorted(
            json.dumps([_typed_value(value) for value in row.values], ensure_ascii=True)
            for row in table.rows
        )
        for row in rows:
            raw = row.encode("ascii")
            digest.update(len(raw).to_bytes(8, "big"))
            digest.update(raw)
    return digest.hexdigest()


def _issue(code: str, table: str, row: RawLegacyRow, detail: str = "") -> InspectionIssue:
    # Snapshot-local rowid avoids exposing a secret or attacker-controlled ID in diagnostics.
    return InspectionIssue(code, table, f"rowid:{row.rowid}", detail)


def _payload_issues(
    payload: dict[str, Any], row: RawLegacyRow
) -> tuple[list[InspectionIssue], bool]:
    issues: list[InspectionIssue] = []
    versions: list[tuple[str, Any, tuple[Any, ...]]] = []
    if "schema_version" in payload:
        versions.append(("envelope", payload["schema_version"], ()))
    report = payload.get("report")
    revision = payload.get("revision")
    parse_result = payload.get("parse_result")
    opaque_kinds: set[str] = set()
    if isinstance(report, dict):
        versions.append(("report", report.get("schema_version"), ("1.0.0",)))
    if isinstance(revision, dict):
        # DeviceRevision explicitly implements documented v1/unversioned legacy adaptation.
        versions.append(("revision", revision.get("schema_version"), (None, "1.0.0", "2.0.0")))
    if isinstance(parse_result, dict) and "schema_version" in parse_result:
        versions.append(("parse_result", parse_result["schema_version"], ()))
    for kind, version, supported in versions:
        if version not in supported:
            opaque_kinds.add(kind)
            issues.append(
                InspectionIssue(
                    "UNSUPPORTED_PAYLOAD_VERSION",
                    "items",
                    f"rowid:{row.rowid}",
                    kind,
                    "unsupported",
                )
            )
    if "envelope" in opaque_kinds:
        # A future envelope may assign different meanings to all child fields.
        # Preserve it whole; do not invoke current child readers under that schema.
        return issues, True
    status = payload.get("status")
    if not isinstance(status, str) or status not in {
        "complete",
        "partial",
        "unsupported",
        "error",
        "canceled",
    }:
        issues.append(_issue("INVALID_ITEM_STATUS", "items", row))
    parsed: FirewallAssuranceResult | None = None
    parse: ParseResult | None = None
    rev: DeviceRevision | None = None
    # A sibling's absence or unknown version cannot hide a malformed known
    # payload. Only the unsupported component itself is withheld from readers.
    if report is not None and "report" not in opaque_kinds:
        try:
            parsed = FirewallAssuranceResult.model_validate(report)
        except (ValidationError, ValueError, TypeError):
            issues.append(_issue("INVALID_DOMAIN_PAYLOAD", "items", row, "report"))
    if parse_result is not None and "parse_result" not in opaque_kinds:
        try:
            parse = ParseResult.model_validate(parse_result)
        except (ValidationError, ValueError, TypeError):
            issues.append(_issue("INVALID_DOMAIN_PAYLOAD", "items", row, "parse_result"))
    if revision is not None and "revision" not in opaque_kinds:
        try:
            rev = DeviceRevision.model_validate(revision)
        except (ValidationError, ValueError, TypeError):
            issues.append(_issue("INVALID_DOMAIN_PAYLOAD", "items", row, "revision"))
    if report is None and isinstance(status, str) and status in {"complete", "partial"}:
        issues.append(_issue("MISSING_RESULT", "items", row))

    if (
        parse is not None
        and rev is not None
        and parse.model_dump(mode="json") != rev.parse_result.model_dump(mode="json")
    ):
        issues.append(_issue("ITEM_PARSE_RESULT_MISMATCH", "items", row))
    for known_parse in (parse, rev.parse_result if rev is not None else None):
        if known_parse is None:
            continue
        config = known_parse.configuration
        if parsed is not None and (
            config.configuration_id != parsed.configuration_id
            or config.device_id != parsed.device_id
            or config.parser_version != parsed.parser_version
            or known_parse.warnings != parsed.parse_warnings
            or known_parse.errors != parsed.parse_errors
            or known_parse.unsupported_constructs != parsed.unsupported_constructs
            or known_parse.coverage != parsed.parse_coverage
            or parsed.analyzed_at < config.imported_at
        ):
            issues.append(_issue("ITEM_CONFIGURATION_MISMATCH", "items", row))
        for field, expected in (
            ("source_name", config.source_name),
            ("content_sha256", config.content_sha256),
        ):
            if field in payload and payload[field] != expected:
                issues.append(_issue("ITEM_SOURCE_MISMATCH", "items", row, field))
    if (
        parsed is not None
        and rev is not None
        and (
            rev.revision_id != parsed.revision_id
            or rev.device.device_id != parsed.device_id
            or rev.application_version != parsed.application_version
        )
    ):
        issues.append(_issue("ITEM_REVISION_MISMATCH", "items", row))
    return issues, bool(opaque_kinds)


def _validate(
    tables: tuple[LegacyTable, ...],
) -> tuple[tuple[InspectionIssue, ...], frozenset[str], tuple[OriginRef, ...]]:
    issues: list[InspectionIssue] = []
    unsupported: set[str] = set()
    origins: list[OriginRef] = []
    ids: dict[str, set[str]] = {"projects": set(), "runs": set()}
    decoded: dict[tuple[str, int, str], dict[str, Any]] = {}
    for table in tables:
        seen: set[tuple[SqlValue, ...]] = set()
        for row in table.rows:
            record = dict(zip(table.columns, row.values, strict=True))
            for column, value in record.items():
                if column == "finished_at" and value is None:
                    continue
                if not isinstance(value, str):
                    issues.append(_issue("INVALID_STORAGE_TYPE", table.name, row, column))
                elif (
                    column in {*_PRIMARY_KEYS[table.name], "device_id", "name", "created_at"}
                    and not value.strip()
                ):
                    issues.append(_issue("EMPTY_IDENTITY", table.name, row, column))
                if column in {"created_at", "finished_at", "updated_at"} and isinstance(value, str):
                    try:
                        if datetime.fromisoformat(value).tzinfo is None:
                            raise ValueError("timezone required")
                    except ValueError:
                        issues.append(_issue("INVALID_TIMESTAMP", table.name, row, column))
            key = tuple(record[column] for column in _PRIMARY_KEYS[table.name])
            if key in seen:
                issues.append(_issue("DUPLICATE_IDENTITY", table.name, row))
            seen.add(key)
            if table.name in ids and isinstance(record["id"], str):
                ids[table.name].add(record["id"])
            for column in _JSON_COLUMNS.get(table.name, ()):
                value = record[column]
                if isinstance(value, str):
                    try:
                        decoded[(table.name, row.rowid, column)] = _object(value)
                    except (ValueError, TypeError, RecursionError):
                        issues.append(_issue("INVALID_JSON_OBJECT", table.name, row, column))
            payload = decoded.get(("items", row.rowid, "payload"))
            if table.name == "items" and payload is not None:
                found, opaque = _payload_issues(payload, row)
                issues.extend(found)
                if opaque and isinstance(record["id"], str):
                    unsupported.add(record["id"])
            if table.name == "projects" and all(isinstance(v, str) for v in row.values):
                origins.append(OriginRef(*(str(record[c]) for c in table.columns)))
            if table.name == "runs" and record["state"] not in {
                "running",
                "completed",
                "cancelled",
                "interrupted",
            }:
                issues.append(_issue("INVALID_RUN_STATE", table.name, row))
            if table.name == "cloud_scans" and record["state"] not in {
                "running",
                "completed",
                "partial",
                "failed",
                "cancelled",
                "interrupted",
            }:
                issues.append(_issue("INVALID_SCAN_STATE", table.name, row))
            if table.name == "marks":
                try:
                    status = record["status"]
                    if not isinstance(status, str):
                        raise ValueError("mark status must be text")
                    FindingStatus(status)
                except (ValueError, TypeError):
                    issues.append(_issue("INVALID_MARK_STATUS", table.name, row))
    for table in tables:
        for row in table.rows:
            record = dict(zip(table.columns, row.values, strict=True))
            for column, target in (("project_id", "projects"), ("run_id", "runs")):
                if column in record and record[column] not in ids[target]:
                    issues.append(_issue("BROKEN_RELATION", table.name, row, column))
    # A mark references a finding in that exact run, unless an opaque result
    # prevents proving membership. Never interpret unknown-version findings.
    findings: dict[str, set[str]] = {}
    opaque_runs: set[str] = set()
    for table in tables:
        if table.name != "items":
            continue
        for row in table.rows:
            record = dict(zip(table.columns, row.values, strict=True))
            run_id = record["run_id"]
            if not isinstance(run_id, str):
                continue
            if record["id"] in unsupported:
                opaque_runs.add(run_id)
                continue
            payload = decoded.get(("items", row.rowid, "payload"), {})
            report = payload.get("report")
            if isinstance(report, dict):
                try:
                    result = FirewallAssuranceResult.model_validate(report)
                except (ValidationError, ValueError, TypeError):
                    continue
                findings.setdefault(run_id, set()).update(
                    str(f.finding_id) for check in result.checks for f in check.findings
                )
    for table in tables:
        if table.name == "marks":
            for row in table.rows:
                record = dict(zip(table.columns, row.values, strict=True))
                run_id = record["run_id"]
                if (
                    isinstance(run_id, str)
                    and run_id not in opaque_runs
                    and record["finding_id"] not in findings.get(run_id, set())
                ):
                    issues.append(_issue("FINDING_RELATION_MISSING", "marks", row))
    return tuple(issues), frozenset(unsupported), tuple(origins)


def _failure(path: Path, phase: WorkspacePhase, code: str) -> LegacyWorkspaceSnapshot:
    return LegacyWorkspaceSnapshot(
        path, WorkspaceInspection(None, phase, issues=(InspectionIssue(code),))
    )


def inspect_v1_snapshot(path: Path) -> LegacyWorkspaceSnapshot:
    """Read all v1 families in one snapshot without bootstrap or recovery writes.

    WAL sidecars follow SQLite's read-only runtime rules; this does not promise
    filesystem-wide immutability. Unknown payloads remain opaque exact strings.
    """
    path = path.absolute()
    try:
        path.stat()
    except FileNotFoundError:
        return LegacyWorkspaceSnapshot(path, WorkspaceInspection(None, "absent"))
    except OSError:
        return _failure(path, "access", "STORE_ACCESS_DENIED")
    db: sqlite3.Connection | None = None
    try:
        db = sqlite3.connect(
            path.as_uri() + "?mode=ro", uri=True, timeout=0.1, isolation_level=None
        )
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        version = int(db.execute("PRAGMA user_version").fetchone()[0])
        if version != 1:
            return LegacyWorkspaceSnapshot(
                path,
                WorkspaceInspection(
                    version, "unsupported", issues=(InspectionIssue("UNSUPPORTED_STORE_VERSION"),)
                ),
            )
        tables: list[LegacyTable] = []
        for name, columns in V1_COLUMNS.items():
            actual = tuple(row[1] for row in db.execute(f'PRAGMA table_info("{name}")'))
            kind = db.execute("SELECT type FROM sqlite_master WHERE name=?", (name,)).fetchone()
            if actual != columns or kind != ("table",):
                return LegacyWorkspaceSnapshot(
                    path,
                    WorkspaceInspection(
                        version, "invalid", issues=(InspectionIssue("INVALID_V1_SCHEMA", name),)
                    ),
                )
            rows = tuple(
                RawLegacyRow(row[0], tuple(row[1:]))
                for row in db.execute(f'SELECT rowid,* FROM "{name}" ORDER BY rowid')
            )
            tables.append(LegacyTable(name, columns, rows))
        raw = tuple(tables)
        issues, unsupported, origins = _validate(raw)
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            issues += (InspectionIssue("SQLITE_INTEGRITY_FAILURE"),)
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            issues += (InspectionIssue("SQLITE_FOREIGN_KEY_FAILURE"),)
        phase: WorkspacePhase = "legacy"
        if any(issue.severity == "error" for issue in issues):
            phase = "invalid"
        elif any(issue.severity == "unsupported" for issue in issues):
            phase = "unsupported"
        return LegacyWorkspaceSnapshot(
            path,
            WorkspaceInspection(
                version,
                phase,
                origins,
                tuple(TableCount(t.name, len(t.rows)) for t in raw),
                _digest(raw),
                issues,
            ),
            raw,
            unsupported,
        )
    except sqlite3.Error as error:
        code = getattr(error, "sqlite_errorcode", 0)
        if code in {sqlite3.SQLITE_READONLY_RECOVERY, sqlite3.SQLITE_READONLY_ROLLBACK}:
            return _failure(path, "access", "RECOVERY_REQUIRED")
        if code & 255 in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            return _failure(path, "busy", "STORE_BUSY")
        if code & 255 in {sqlite3.SQLITE_CANTOPEN, sqlite3.SQLITE_PERM, sqlite3.SQLITE_READONLY}:
            return _failure(path, "access", "STORE_ACCESS_DENIED")
        return _failure(path, "invalid", "SQLITE_READ_FAILURE")
    finally:
        if db is not None:
            db.close()


def inspect_workspace(path: Path) -> WorkspaceInspection:
    """Inspect an explicit path without touching the default user database."""
    return inspect_v1_snapshot(path).inspection


def legacy_records(snapshot: LegacyWorkspaceSnapshot, table: str) -> tuple[Mapping[str, Any], ...]:
    """Build detached adapters for internal facade reads, never mutate snapshots."""
    for family in snapshot.tables:
        if family.name == table:
            return tuple(
                {"_rowid": row.rowid, **dict(zip(family.columns, row.values, strict=True))}
                for row in family.rows
            )
    return ()
