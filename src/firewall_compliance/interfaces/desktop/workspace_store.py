"""Explicit site assignments while legacy projects remain provenance namespaces.

This additive staging store is not an organization catalog. It never activates
org_context, duplicates devices/connections, or stores profiles or credentials.
Profiles belong to org_profiles during organization activation. A future
activation must explicitly transfer these site IDs and assignments before this
legacy writer can be used against an organization database.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from firewall_compliance.interfaces.desktop.organization_backup import create_workspace_backup
from firewall_compliance.interfaces.desktop.organization_lock import workspace_lease

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.project_store import ProjectStore


def _text(value: str, *, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > maximum:
        raise ValueError("Укажите непустой текст допустимой длины без нулевых символов")
    return value.strip()


class WorkspaceMetadataStore:
    """Optional, explicitly initialized site metadata using ProjectStore transactions.

    Construction performs no writes. initialize creates a unique backup before
    adding version-1 tables in one transaction. PRAGMA user_version and legacy
    project labels/settings/results are preserved. Site assignment does not
    establish that a device exists or has been successfully collected.
    """

    def __init__(self, store: ProjectStore) -> None:
        self._store = store

    @staticmethod
    def _legacy(db: sqlite3.Connection) -> None:
        if db.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise ValueError("Метаданные площадок требуют совместимого legacy-хранилища")
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='org_context'"
        ).fetchone():
            raise ValueError("Требуется явный перенос площадок в организационное хранилище")

    @classmethod
    def _version(cls, db: sqlite3.Connection) -> bool:
        cls._legacy(db)
        present = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='workspace_metadata'"
        ).fetchone()
        if not present:
            orphan = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name IN "
                "('workspace_sites','workspace_device_sites')"
            ).fetchone()
            if orphan:
                raise ValueError("Неполная схема метаданных площадок")
            return False
        rows = db.execute("SELECT singleton,schema_version FROM workspace_metadata").fetchall()
        if len(rows) != 1 or tuple(rows[0]) != (1, 1):
            raise ValueError("Неподдерживаемая версия метаданных площадок")
        return True

    def initialize(self) -> Path | None:
        """Add staging tables once; return the backup path, or None if already ready.

        Call from a worker: backup and SQLite writes may take time. Failures retain
        the backup and propagate; no partially created schema is committed.
        The workflow lease coordinates migration writers, not every legacy write.
        """
        with workspace_lease(self._store.path):
            with self._store._connect() as db:
                if self._version(db):
                    return None
            backup_path = self._store.path.with_name(
                f"{self._store.path.name}.before-sites-{uuid4().hex}.sqlite3"
            )
            create_workspace_backup(self._store.path, backup_path)
            with self._store._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                if self._version(db):
                    return backup_path
                db.execute(
                    "CREATE TABLE workspace_metadata ("
                    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                    "schema_version INTEGER NOT NULL CHECK(schema_version=1))"
                )
                db.execute(
                    "CREATE TABLE workspace_sites ("
                    "id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)"
                )
                db.execute(
                    "CREATE TABLE workspace_device_sites ("
                    "origin_project_id TEXT NOT NULL REFERENCES projects(id),"
                    "device_id TEXT NOT NULL, site_id TEXT NOT NULL REFERENCES workspace_sites(id),"
                    "updated_at TEXT NOT NULL, PRIMARY KEY(origin_project_id,device_id))"
                )
                db.execute(
                    "CREATE INDEX workspace_device_sites_site ON workspace_device_sites(site_id)"
                )
                db.execute("INSERT INTO workspace_metadata VALUES (1,1)")
            return backup_path

    @classmethod
    def _ready(cls, db: sqlite3.Connection) -> None:
        if not cls._version(db):
            raise ValueError("Сначала инициализируйте метаданные площадок с резервной копией")

    def list_sites(self) -> list[dict[str, str]]:
        """Read explicit sites; absent staging metadata means no assigned sites."""
        with self._store._connect() as db:
            if not self._version(db):
                return []
            return [
                dict(row)
                for row in db.execute(
                    "SELECT id,name,created_at FROM workspace_sites ORDER BY name,id"
                )
            ]

    def create_site(self, name: str) -> str:
        name = _text(name)
        site_id = str(uuid4())
        with self._store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._ready(db)
            db.execute(
                "INSERT INTO workspace_sites VALUES (?,?,?)",
                (site_id, name, datetime.now(UTC).isoformat()),
            )
        return site_id

    def rename_site(self, site_id: str, name: str) -> None:
        site_id, name = _text(site_id), _text(name)
        with self._store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._ready(db)
            if db.execute(
                "UPDATE workspace_sites SET name=? WHERE id=?", (name, site_id)
            ).rowcount != 1:
                raise ValueError("Площадка не найдена")

    def assign_device(self, project_id: str, device_id: str, site_id: str | None) -> None:
        """Assign a namespaced legacy device explicitly; None removes only metadata.

        No imported observation, historical revision, or decision is modified.
        The project must exist. Device IDs are opaque legacy identifiers and are
        scoped by project; equal names in different projects remain distinct.
        """
        self.assign_devices(project_id, (device_id,), site_id)

    def assign_devices(
        self, project_id: str, device_ids: tuple[str, ...], site_id: str | None
    ) -> None:
        """Assign the complete selection atomically; never partially move a batch."""
        project_id = _text(project_id)
        if isinstance(device_ids, (str, bytes)):
            raise TypeError("device_ids must be a collection")
        identifiers = tuple(dict.fromkeys(_text(value, maximum=2000) for value in device_ids))
        if not identifiers:
            raise ValueError("Выберите устройства для назначения")
        if site_id is not None:
            site_id = _text(site_id)
        with self._store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._ready(db)
            if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
                raise ValueError("Исходный проект не найден")
            if site_id is None:
                db.executemany(
                    "DELETE FROM workspace_device_sites WHERE origin_project_id=? AND device_id=?",
                    ((project_id, device_id) for device_id in identifiers),
                )
            else:
                if not db.execute("SELECT 1 FROM workspace_sites WHERE id=?", (site_id,)).fetchone():
                    raise ValueError("Площадка не найдена")
                db.executemany(
                    "INSERT INTO workspace_device_sites VALUES (?,?,?,?) "
                    "ON CONFLICT(origin_project_id,device_id) DO UPDATE SET "
                    "site_id=excluded.site_id,updated_at=excluded.updated_at",
                    (
                        (project_id, device_id, site_id, datetime.now(UTC).isoformat())
                        for device_id in identifiers
                    ),
                )

    def device_sites(self, project_id: str) -> dict[str, str]:
        project_id = _text(project_id)
        with self._store._connect() as db:
            if not self._version(db):
                return {}
            return {
                row["device_id"]: row["site_id"]
                for row in db.execute(
                    "SELECT device_id,site_id FROM workspace_device_sites WHERE origin_project_id=?",
                    (project_id,),
                )
            }
