"""Append-only история сравнений с явной резервной копией перед DDL."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from firewall_compliance.application.run_comparison_artifact import RunComparisonArtifact
from firewall_compliance.interfaces.desktop.organization_backup import create_workspace_backup
from firewall_compliance.interfaces.desktop.organization_lock import workspace_lease


@dataclass(frozen=True, slots=True)
class RunComparisonSummary:
    comparison_id: str
    saved_at: str
    before_run_id: str
    after_run_id: str
    site_id: str | None


class RunComparisonStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=15)
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _ready(db: sqlite3.Connection) -> bool:
        if db.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise ValueError("Unsupported workspace version")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "org_context" in tables:
            raise ValueError("Transfer comparison history before organization activation")
        if "workspace_comparison_meta" not in tables:
            if "workspace_run_comparisons" in tables:
                raise ValueError("Incomplete comparison history schema")
            return False
        if (
            db.execute("SELECT singleton,version FROM workspace_comparison_meta").fetchall() != [(1, 1)]
            or "workspace_run_comparisons" not in tables
        ):
            raise ValueError("Unsupported comparison history schema")
        return True

    def initialize(self) -> Path | None:
        with workspace_lease(self.path):
            db = self._connect()
            try:
                if self._ready(db):
                    return None
                backup = self.path.with_name(
                    f"{self.path.name}.before-comparisons-{uuid4().hex}.sqlite3"
                )
                create_workspace_backup(self.path, backup)
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    if self._ready(db):
                        return backup
                    db.execute(
                        "CREATE TABLE workspace_comparison_meta "
                        "(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL)"
                    )
                    db.execute("INSERT INTO workspace_comparison_meta VALUES(1,1)")
                    db.execute(
                        "CREATE TABLE workspace_run_comparisons ("
                        "comparison_id TEXT PRIMARY KEY,project_id TEXT NOT NULL REFERENCES projects(id),"
                        "before_run_id TEXT NOT NULL REFERENCES runs(id),"
                        "after_run_id TEXT NOT NULL REFERENCES runs(id),saved_at TEXT NOT NULL,"
                        "site_id TEXT,payload TEXT NOT NULL,checksum TEXT NOT NULL)"
                    )
                    db.execute(
                        "CREATE INDEX workspace_comparisons_after "
                        "ON workspace_run_comparisons(project_id,after_run_id,saved_at)"
                    )
                    db.execute(
                        "CREATE TRIGGER workspace_comparisons_no_update BEFORE UPDATE ON "
                        "workspace_run_comparisons BEGIN SELECT RAISE(ABORT,'Comparison is immutable'); END"
                    )
                    db.execute(
                        "CREATE TRIGGER workspace_comparisons_no_delete BEFORE DELETE ON "
                        "workspace_run_comparisons BEGIN SELECT RAISE(ABORT,'Comparison is immutable'); END"
                    )
                return backup
            finally:
                db.close()

    def save(self, project_id: str, package: dict[str, Any]) -> RunComparisonArtifact:
        artifact = RunComparisonArtifact(
            project_id=project_id, before_run_id=package["before_run_id"],
            after_run_id=package["after_run_id"], package=package,
        )
        encoded = artifact.model_dump_json()
        checksum = sha256(encoded.encode("utf-8")).hexdigest()
        db = self._connect()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                if not self._ready(db):
                    raise ValueError("Initialize comparison history explicitly before saving")
                for key, run_id in (
                    ("before_created_at", artifact.before_run_id),
                    ("after_created_at", artifact.after_run_id),
                ):
                    row = db.execute(
                        "SELECT project_id,created_at FROM runs WHERE id=?", (run_id,),
                    ).fetchone()
                    if row is None or row[0] != project_id or row[1] != package.get(key):
                        raise ValueError("Comparison origin was not found in this project")
                site_id = package.get("site_selection")
                if site_id is not None and not isinstance(site_id, str):
                    raise ValueError("Invalid comparison site selection")
                db.execute(
                    "INSERT INTO workspace_run_comparisons VALUES(?,?,?,?,?,?,?,?)",
                    (
                        str(artifact.comparison_id), project_id, artifact.before_run_id,
                        artifact.after_run_id, artifact.saved_at.isoformat(), site_id,
                        encoded, checksum,
                    ),
                )
            return artifact
        finally:
            db.close()

    def ids_for_run(self, project_id: str, run_id: str) -> tuple[str, ...]:
        db = self._connect()
        try:
            if not self._ready(db):
                return ()
            return tuple(row[0] for row in db.execute(
                "SELECT comparison_id FROM workspace_run_comparisons "
                "WHERE project_id=? AND after_run_id=? ORDER BY saved_at,comparison_id",
                (project_id, run_id),
            ))
        finally:
            db.close()

    def history(
        self, project_id: str, *, site_id: str | None = None, limit: int = 100, offset: int = 0,
    ) -> tuple[tuple[RunComparisonSummary, ...], int]:
        if type(limit) is not int or not 1 <= limit <= 500 or type(offset) is not int or offset < 0:
            raise ValueError("Invalid comparison history page")
        db = self._connect()
        try:
            if not self._ready(db):
                return (), 0
            with db:
                db.execute("BEGIN")
                if site_id is None:
                    count = db.execute(
                        "SELECT count(*) FROM workspace_run_comparisons WHERE project_id=?",
                        (project_id,),
                    ).fetchone()[0]
                    rows = db.execute(
                        "SELECT comparison_id,saved_at,before_run_id,after_run_id,site_id "
                        "FROM workspace_run_comparisons WHERE project_id=? "
                        "ORDER BY saved_at DESC,comparison_id DESC LIMIT ? OFFSET ?",
                        (project_id, limit, offset),
                    ).fetchall()
                else:
                    count = db.execute(
                        "SELECT count(*) FROM workspace_run_comparisons WHERE project_id=? AND site_id=?",
                        (project_id, site_id),
                    ).fetchone()[0]
                    rows = db.execute(
                        "SELECT comparison_id,saved_at,before_run_id,after_run_id,site_id "
                        "FROM workspace_run_comparisons WHERE project_id=? AND site_id=? "
                        "ORDER BY saved_at DESC,comparison_id DESC LIMIT ? OFFSET ?",
                        (project_id, site_id, limit, offset),
                    ).fetchall()
            return tuple(RunComparisonSummary(*row) for row in rows), int(count)
        finally:
            db.close()

    def get(self, project_id: str, comparison_id: str) -> RunComparisonArtifact:
        db = self._connect()
        try:
            if not self._ready(db):
                raise ValueError("Comparison history has not been initialized")
            row = db.execute(
                "SELECT payload,checksum,before_run_id,after_run_id,saved_at,site_id "
                "FROM workspace_run_comparisons WHERE project_id=? AND comparison_id=?",
                (project_id, comparison_id),
            ).fetchone()
            if row is None:
                raise ValueError("Comparison was not found in this project")
            payload, checksum, before_id, after_id, saved_at, site_id = row
            if sha256(payload.encode("utf-8")).hexdigest() != checksum:
                raise ValueError("Comparison checksum mismatch")
            artifact = RunComparisonArtifact.model_validate_json(payload)
            if (
                str(artifact.comparison_id) != comparison_id or artifact.project_id != project_id
                or artifact.before_run_id != before_id or artifact.after_run_id != after_id
                or artifact.saved_at.isoformat() != saved_at
                or artifact.package.get("site_selection") != site_id
            ):
                raise ValueError("Comparison history metadata mismatch")
            return artifact
        finally:
            db.close()
