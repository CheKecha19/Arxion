"""Optional append-only profile history for legacy origins, before org activation.

Initialization is explicit and backed up; construction never writes. Activation
must transfer this history to org_profiles before retiring the legacy writer.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from firewall_compliance.application.workspace_profile import ProfileVersion, analysis_settings
from firewall_compliance.interfaces.desktop.organization_backup import create_workspace_backup
from firewall_compliance.interfaces.desktop.organization_lock import workspace_lease


class LegacyProfileHistory:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=15)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _ready(db: sqlite3.Connection) -> bool:
        if db.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise ValueError("Profile history requires a supported legacy database")
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='org_context'").fetchone():
            raise ValueError("Transfer legacy profiles before organization activation")
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "workspace_profile_history_meta" not in tables:
            if "workspace_profile_history" in tables:
                raise ValueError("Incomplete profile history schema")
            return False
        rows = [
            tuple(row)
            for row in db.execute("SELECT singleton,version FROM workspace_profile_history_meta")
        ]
        if rows != [(1, 1)] or "workspace_profile_history" not in tables:
            raise ValueError("Unsupported profile history schema")
        return True

    @classmethod
    def is_initialized(cls, db: sqlite3.Connection) -> bool:
        """Inspect without writing; reject incompatible databases or partial schemas."""
        return cls._ready(db)

    def initialize(self) -> Path | None:
        """Create additive tables transactionally, preserving user_version and origins."""
        with workspace_lease(self.path):
            with self._connect() as db:
                if self._ready(db):
                    return None
            backup = self.path.with_name(f"{self.path.name}.before-profiles-{uuid4().hex}.sqlite3")
            create_workspace_backup(self.path, backup)
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                if self._ready(db):
                    return backup
                db.execute(
                    "CREATE TABLE workspace_profile_history_meta "
                    "(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL)"
                )
                db.execute("INSERT INTO workspace_profile_history_meta VALUES(1,1)")
                db.execute(
                    "CREATE TABLE workspace_profile_history ("
                    "project_id TEXT NOT NULL REFERENCES projects(id),"
                    "version INTEGER NOT NULL CHECK(version>0),settings_json TEXT NOT NULL,"
                    "fingerprint TEXT NOT NULL,created_at TEXT NOT NULL,"
                    "PRIMARY KEY(project_id,version))"
                )
                for operation in ("UPDATE", "DELETE"):
                    db.execute(
                        f"CREATE TRIGGER workspace_profiles_no_{operation.lower()} "
                        f"BEFORE {operation} ON workspace_profile_history "
                        "BEGIN SELECT RAISE(ABORT,'Profile history is immutable'); END"
                    )
            return backup

    def record(self, project_id: str, settings: Mapping[str, Any]) -> ProfileVersion:
        """Append a changed validated analysis profile; unchanged input reuses latest."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            return self.record_in_transaction(db, project_id, settings)

    @classmethod
    def record_in_transaction(
        cls, db: sqlite3.Connection, project_id: str, settings: Mapping[str, Any]
    ) -> ProfileVersion:
        """Append inside the caller's write transaction, without committing it.

        The owner must begin IMMEDIATE and keep settings/run writes in the same
        transaction. This helper does not initialize schemas or make backups.
        """
        if not db.in_transaction:
            raise ValueError("An active write transaction is required")
        if not cls._ready(db):
            raise ValueError("Initialize profile history explicitly before writing")
        previous = db.execute(
            "SELECT version,settings_json,fingerprint FROM "
            "workspace_profile_history WHERE project_id=? ORDER BY version DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        result = ProfileVersion.from_settings(
            project_id, previous[0] + 1 if previous else 1, analysis_settings(settings)
        )
        if previous:
            baseline = ProfileVersion(project_id, previous[0], previous[1])
            if baseline.fingerprint != previous[2]:
                raise ValueError("Profile history fingerprint mismatch")
            if baseline.settings_json == result.settings_json:
                return baseline
        db.execute(
            "INSERT INTO workspace_profile_history VALUES(?,?,?,?,?)",
            (
                project_id,
                result.version,
                result.settings_json,
                result.fingerprint,
                datetime.now(UTC).isoformat(),
            ),
        )
        return result

    record_on_connection = record_in_transaction

    def list_versions(self, project_id: str) -> tuple[ProfileVersion, ...]:
        with self._connect() as db:
            if not self._ready(db):
                return ()
            rows = db.execute(
                "SELECT version,settings_json,fingerprint FROM "
                "workspace_profile_history WHERE project_id=? ORDER BY version",
                (project_id,),
            ).fetchall()
        result = tuple(ProfileVersion(project_id, row[0], row[1]) for row in rows)
        if any(profile.fingerprint != row[2] for profile, row in zip(result, rows, strict=True)):
            raise ValueError("Profile history fingerprint mismatch")
        return result
