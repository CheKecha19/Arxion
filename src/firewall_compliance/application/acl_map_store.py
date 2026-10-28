"""Additive ACL-map repository over an injected project SQLite connection.

No files or sources are opened here. The caller owns the connection and outer
transaction. Savepoints keep a failed write from committing unrelated work.
"""

import json
import sqlite3
from datetime import UTC, datetime
from hashlib import sha256
from typing import TypedDict
from uuid import UUID, uuid4

from firewall_compliance.domain.acl_map import AclMap
from firewall_compliance.domain.revision import DeviceRevision

_MAX_BYTES = 64 * 1024 * 1024


class AclMapRecord(TypedDict):
    map_id: str
    project_id: str
    run_id: str | None
    item_id: str | None
    revision_id: str
    created_at: str
    built_at: str
    rule_count: int
    content_sha256: str


def _canonical(graph: AclMap) -> str:
    return json.dumps(
        graph.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _digest(metadata: tuple[object, ...], payload: str) -> str:
    encoded = json.dumps([*metadata, payload], ensure_ascii=False, separators=(",", ":"))
    return sha256(encoded.encode("utf-8")).hexdigest()


class AclMapStore:
    """Immutable validated maps with explicit project and optional run provenance."""

    def __init__(self, connection: sqlite3.Connection, *, initialize: bool = True) -> None:
        self.connection = connection
        if connection.execute("PRAGMA user_version").fetchone()[0] > 1:
            raise ValueError("Unsupported project database version")
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if not {"projects", "runs", "items"}.issubset(tables):
            raise ValueError("An existing project database is required")
        if not initialize:
            if "acl_maps" not in tables:
                raise KeyError("No saved ACL maps")
            return
        connection.execute("""CREATE TABLE IF NOT EXISTS acl_maps (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id),
            run_id TEXT REFERENCES runs(id),
            item_id TEXT REFERENCES items(id),
            revision_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            built_at TEXT NOT NULL,
            rule_count INTEGER NOT NULL,
            content_sha256 TEXT NOT NULL,
            payload TEXT NOT NULL)""")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS acl_maps_project ON acl_maps(project_id,created_at)"
        )
        connection.execute("""CREATE TRIGGER IF NOT EXISTS acl_maps_immutable_update
            BEFORE UPDATE ON acl_maps BEGIN SELECT RAISE(ABORT,'ACL maps are immutable'); END""")
        connection.execute("""CREATE TRIGGER IF NOT EXISTS acl_maps_immutable_delete
            BEFORE DELETE ON acl_maps BEGIN SELECT RAISE(ABORT,'ACL maps are immutable'); END""")

    def _project(self, project_id: str) -> None:
        if (
            self.connection.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone()
            is None
        ):
            raise KeyError("Project not found")

    def _provenance(
        self, project_id: str, run_id: str | None, item_id: str | None, graph: AclMap
    ) -> None:
        self._project(project_id)
        if run_id is None:
            if item_id is not None:
                raise ValueError("An item requires its run")
            return
        row = self.connection.execute(
            "SELECT project_id FROM runs WHERE id=?", (run_id,)
        ).fetchone()
        if row is None or row[0] != project_id:
            raise ValueError("Run does not belong to project")
        query = "SELECT id,payload FROM items WHERE run_id=?"
        parameters: tuple[str, ...] = (run_id,)
        if item_id is not None:
            query += " AND id=?"
            parameters = (run_id, item_id)
        for _, payload in self.connection.execute(query, parameters):
            item = json.loads(payload)
            revision_payload = item.get("revision") if isinstance(item, dict) else None
            if revision_payload is not None:
                revision = DeviceRevision.model_validate(revision_payload)
                if revision == graph.revision:
                    return
        raise ValueError("Map revision is not an exact captured revision in this run/item")

    def save(
        self,
        project_id: str,
        graph: AclMap,
        *,
        run_id: str | None = None,
        item_id: str | None = None,
        map_id: str | None = None,
    ) -> str:
        validated = AclMap.model_validate(graph.model_dump(mode="python"))
        identifier = str(UUID(map_id)) if map_id is not None else str(uuid4())
        payload = _canonical(validated)
        if len(payload.encode("utf-8")) > _MAX_BYTES:
            raise ValueError("ACL map exceeds 64 MiB")
        db = self.connection
        db.execute("SAVEPOINT save_acl_map")
        try:
            self._provenance(project_id, run_id, item_id, validated)
            existing = db.execute(
                "SELECT project_id,run_id,item_id,payload FROM acl_maps WHERE id=?", (identifier,)
            ).fetchone()
            if existing is not None:
                self.get(project_id, identifier)
                if tuple(existing) != (project_id, run_id, item_id, payload):
                    raise ValueError("Map ID already names different content")
            else:
                metadata: tuple[object, ...] = (
                    identifier,
                    project_id,
                    run_id,
                    item_id,
                    str(validated.revision.revision_id),
                    datetime.now(UTC).isoformat(),
                    validated.built_at.isoformat(),
                    len(validated.relations),
                )
                db.execute(
                    "INSERT INTO acl_maps VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        *metadata,
                        _digest(metadata, payload),
                        payload,
                    ),
                )
            db.execute("RELEASE SAVEPOINT save_acl_map")
        except BaseException:
            db.execute("ROLLBACK TO SAVEPOINT save_acl_map")
            db.execute("RELEASE SAVEPOINT save_acl_map")
            raise
        return identifier

    def _read(self, row: tuple[object, ...]) -> AclMap:
        (
            identifier,
            project_id,
            run_id,
            item_id,
            revision_id,
            created_at,
            built_at,
            rule_count,
            digest,
            payload,
        ) = row
        if not all(
            isinstance(value, str)
            for value in (
                identifier,
                project_id,
                revision_id,
                created_at,
                built_at,
                digest,
                payload,
            )
        ):
            raise ValueError("Invalid ACL map row")
        if not isinstance(payload, str) or len(payload.encode("utf-8")) > _MAX_BYTES:
            raise ValueError("Invalid ACL map payload")
        if _digest(row[:8], payload) != digest:
            raise ValueError("ACL map checksum mismatch")
        graph = AclMap.model_validate_json(payload)
        if (str(graph.revision.revision_id), graph.built_at.isoformat(), len(graph.relations)) != (
            revision_id,
            built_at,
            rule_count,
        ):
            raise ValueError("ACL map metadata mismatch")
        UUID(str(identifier))
        timestamp = datetime.fromisoformat(str(created_at))
        if timestamp.tzinfo is None:
            raise ValueError("ACL map capture time requires timezone")
        if run_id is not None and not isinstance(run_id, str):
            raise ValueError("Invalid run reference")
        if item_id is not None and not isinstance(item_id, str):
            raise ValueError("Invalid item reference")
        self._provenance(str(project_id), run_id, item_id, graph)
        return graph

    def get(self, project_id: str, map_id: str) -> AclMap:
        self._project(project_id)
        row = self.connection.execute(
            "SELECT * FROM acl_maps WHERE project_id=? AND id=?", (project_id, map_id)
        ).fetchone()
        if row is None:
            raise KeyError("ACL map not found in project")
        return self._read(tuple(row))

    def list(self, project_id: str) -> list[AclMapRecord]:
        self._project(project_id)
        rows = self.connection.execute(
            "SELECT * FROM acl_maps WHERE project_id=? ORDER BY created_at DESC,rowid DESC",
            (project_id,),
        ).fetchall()
        records: list[AclMapRecord] = []
        for raw in rows:
            row = tuple(raw)
            graph = self._read(row)
            records.append(
                AclMapRecord(
                    map_id=str(row[0]),
                    project_id=project_id,
                    run_id=str(row[2]) if row[2] is not None else None,
                    item_id=str(row[3]) if row[3] is not None else None,
                    revision_id=str(graph.revision.revision_id),
                    created_at=str(row[5]),
                    built_at=graph.built_at.isoformat(),
                    rule_count=len(graph.relations),
                    content_sha256=str(row[8]),
                )
            )
        return records
