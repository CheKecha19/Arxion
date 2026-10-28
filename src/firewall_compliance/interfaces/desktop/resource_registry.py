"""Persistent resource registry; imported observations and user metadata stay separate."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

CATEGORIES = frozenset({"ngfw", "network", "cloud", "unclassified"})
LOCATION_FIELDS = (
    "country",
    "region",
    "province",
    "city",
    "site",
    "street",
    "house",
    "floor",
    "room",
    "rack",
    "rack_position",
)
METADATA_FIELDS = frozenset({"label", "description", "comments", "status", "vdc", *LOCATION_FIELDS})
MANUAL_FIELDS = frozenset({"name", "platform", "resource_type", "category"})
OBSERVED_FIELDS = frozenset(
    {"name", "platform", "resource_type", "category", "vdc", "region", "source"}
)
DATE_FIELDS = ("first_seen", "last_scan", "last_check")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
    except (TypeError, ValueError):
        raise ValueError("Поля ресурса должны содержать сериализуемые JSON-значения.") from None


def _date(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Дата ресурса должна быть строкой ISO с часовым поясом или None.")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError
        return timestamp.astimezone(UTC).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        raise ValueError(
            "Дата ресурса должна содержать корректный ISO timestamp с часовым поясом."
        ) from None


def _text(value: Any, *, maximum: int = 16000) -> str:
    if not isinstance(value, str) or "\x00" in value or len(value) > maximum:
        raise ValueError(
            "Поле ресурса должно содержать текст допустимой длины без нулевых символов."
        )
    return value.strip()


class ResourceRegistry:
    """Additive SQLite registry with explicit aliases and reversible archive lifecycle.

    The existing ProjectStore must initialize its projects table before use. This
    class creates only its own three tables and does not change user_version or
    mutate runs, items, integrations, cloud_scans or project settings.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS infrastructure_resources (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    identity TEXT NOT NULL,
                    origin TEXT NOT NULL CHECK(origin IN ('manual','discovered')),
                    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','archived')),
                    observed TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    first_seen TEXT,
                    last_scan TEXT,
                    last_check TEXT,
                    merged_into TEXT REFERENCES infrastructure_resources(id),
                    UNIQUE(project_id,identity)
                );
                CREATE TABLE IF NOT EXISTS infrastructure_resource_aliases (
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    identity TEXT NOT NULL,
                    resource_id TEXT NOT NULL REFERENCES infrastructure_resources(id),
                    PRIMARY KEY(project_id,identity)
                );
                CREATE TABLE IF NOT EXISTS infrastructure_resource_events (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    resource_id TEXT NOT NULL REFERENCES infrastructure_resources(id),
                    created_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    before_payload TEXT,
                    after_payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS infrastructure_resources_project
                    ON infrastructure_resources(project_id,lifecycle,merged_into);
                CREATE INDEX IF NOT EXISTS infrastructure_events_resource
                    ON infrastructure_resource_events(project_id,resource_id,created_at);
            """)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _project(db: sqlite3.Connection, project_id: str) -> None:
        if not isinstance(project_id, str) or not project_id:
            raise ValueError("Выберите проект.")
        if db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is None:
            raise ValueError("Проект не найден.")

    @staticmethod
    def _row(db: sqlite3.Connection, project_id: str, resource_id: str) -> sqlite3.Row:
        row = db.execute(
            "SELECT * FROM infrastructure_resources WHERE project_id=? AND id=? "
            "AND merged_into IS NULL",
            (project_id, resource_id),
        ).fetchone()
        if row is None:
            raise ValueError("Ресурс не найден в текущем проекте.")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _view(db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        observed = json.loads(row["observed"])
        metadata = json.loads(row["metadata"])
        identities = [
            alias["identity"]
            for alias in db.execute(
                "SELECT identity FROM infrastructure_resource_aliases "
                "WHERE project_id=? AND resource_id=? ORDER BY identity",
                (row["project_id"], row["id"]),
            )
        ]
        effective = {key: "" for key in (*METADATA_FIELDS, *MANUAL_FIELDS)}
        effective["category"] = "unclassified"
        effective.update(observed)
        effective.update(metadata)
        return {
            **effective,
            "id": row["id"],
            "project_id": row["project_id"],
            "identity": row["identity"],
            "identities": identities,
            "origin": row["origin"],
            "lifecycle": row["lifecycle"],
            "observed": observed,
            "metadata": metadata,
            "created_at": row["created_at"],
            "added_at": row["created_at"] if row["origin"] == "manual" else row["first_seen"],
            **{key: row[key] for key in DATE_FIELDS},
        }

    @classmethod
    def _event(
        cls, db: sqlite3.Connection, row: sqlite3.Row, action: str, before: dict[str, Any] | None
    ) -> None:
        db.execute(
            "INSERT INTO infrastructure_resource_events VALUES (?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                row["project_id"],
                row["id"],
                _now(),
                action,
                _json(before) if before is not None else None,
                _json(cls._view(db, row)),
            ),
        )

    @staticmethod
    def _fields(fields: Mapping[str, Any], *, manual: bool) -> dict[str, str | None]:
        allowed = METADATA_FIELDS | MANUAL_FIELDS if manual else METADATA_FIELDS
        if set(fields) - allowed:
            raise ValueError("Изменяются только пользовательские поля ресурса.")
        values: dict[str, str | None] = {}
        for key, raw in fields.items():
            if raw is None:
                values[key] = None
                continue
            value = _text(raw)
            if key == "category" and value not in CATEGORIES:
                raise ValueError("Неизвестная категория ресурса.")
            if key in {"name", "category"} and not value:
                raise ValueError("Имя и категория ручного ресурса не могут быть пустыми.")
            values[key] = value
        return values

    @staticmethod
    def _observation(
        observation: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any], dict[str, str | None]]:
        if set(observation) - (OBSERVED_FIELDS | set(DATE_FIELDS) | {"identity"}):
            raise ValueError("Наблюдение содержит неизвестные поля.")
        identity = _text(observation.get("identity"), maximum=8192)
        if not identity.startswith(("device:", "cloud:")) or identity in {"device:", "cloud:"}:
            raise ValueError("Наблюдение должно содержать устойчивый device:/cloud: identity.")
        observed: dict[str, Any] = {}
        for key in OBSERVED_FIELDS - {"source"}:
            raw = observation.get(key)
            if raw is not None:
                observed[key] = _text(raw)
        if observed.get("category") not in CATEGORIES:
            raise ValueError("Наблюдение должно содержать известную категорию ресурса.")
        source = observation.get("source")
        if source is not None:
            if not isinstance(source, dict):
                raise ValueError("Источник ресурса должен содержать JSON-объект.")
            observed["source"] = json.loads(_json(source))
        return identity, observed, {key: _date(observation.get(key)) for key in DATE_FIELDS}

    @staticmethod
    def _times(row: sqlite3.Row, incoming: Mapping[str, str | None]) -> dict[str, str | None]:
        values = {}
        for key in DATE_FIELDS:
            dates = [value for value in (row[key], incoming.get(key)) if value is not None]
            values[key] = (min(dates) if key == "first_seen" else max(dates)) if dates else None
        return values

    @staticmethod
    def _latest(values: Mapping[str, Any]) -> str | None:
        dates = [value for key in DATE_FIELDS if isinstance(value := values.get(key), str)]
        return max(dates) if dates else None

    def reconcile(
        self, project_id: str, observations: Sequence[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Accumulate observations; neither missing rows nor rediscovery remove archives."""
        parsed = [self._observation(observation) for observation in observations]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._project(db, project_id)
            for identity, observed, dates in parsed:
                alias = db.execute(
                    "SELECT resource_id FROM infrastructure_resource_aliases "
                    "WHERE project_id=? AND identity=?",
                    (project_id, identity),
                ).fetchone()
                if alias is None:
                    resource_id = str(uuid4())
                    db.execute(
                        "INSERT INTO infrastructure_resources VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            resource_id,
                            project_id,
                            identity,
                            "discovered",
                            "active",
                            _json(observed),
                            "{}",
                            _now(),
                            dates["first_seen"],
                            dates["last_scan"],
                            dates["last_check"],
                            None,
                        ),
                    )
                    db.execute(
                        "INSERT INTO infrastructure_resource_aliases VALUES (?,?,?)",
                        (project_id, identity, resource_id),
                    )
                    self._event(db, self._row(db, project_id, resource_id), "discover", None)
                    continue
                row = self._row(db, project_id, alias["resource_id"])
                before = self._view(db, row)
                times = self._times(row, dates)
                current_latest = self._latest({key: row[key] for key in DATE_FIELDS})
                incoming_latest = self._latest(dates)
                merged = json.loads(row["observed"])
                if (
                    current_latest is None
                    or incoming_latest is not None
                    and incoming_latest >= current_latest
                ):
                    merged.update(observed)
                if merged == before["observed"] and all(
                    times[key] == row[key] for key in DATE_FIELDS
                ):
                    continue
                db.execute(
                    "UPDATE infrastructure_resources "
                    "SET observed=?,first_seen=?,last_scan=?,last_check=? "
                    "WHERE project_id=? AND id=?",
                    (
                        _json(merged),
                        times["first_seen"],
                        times["last_scan"],
                        times["last_check"],
                        project_id,
                        row["id"],
                    ),
                )
                self._event(db, self._row(db, project_id, row["id"]), "observe", before)
        return self.list_resources(project_id, include_archived=True)

    def list_resources(
        self, project_id: str, include_archived: bool = False
    ) -> list[dict[str, Any]]:
        with self._connect() as db:
            self._project(db, project_id)
            rows = db.execute(
                "SELECT * FROM infrastructure_resources WHERE project_id=? AND merged_into IS NULL "
                "AND (? OR lifecycle='active') ORDER BY created_at,id",
                (project_id, include_archived),
            ).fetchall()
            return [self._view(db, row) for row in rows]

    def add_manual(self, project_id: str, fields: Mapping[str, Any]) -> str:
        values = self._fields(fields, manual=True)
        if not values.get("name"):
            raise ValueError("Введите имя ручного ресурса.")
        metadata = {key: value for key, value in values.items() if value is not None}
        resource_id = str(uuid4())
        identity = "manual:" + resource_id
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._project(db, project_id)
            db.execute(
                "INSERT INTO infrastructure_resources VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    resource_id,
                    project_id,
                    identity,
                    "manual",
                    "active",
                    "{}",
                    _json(metadata),
                    _now(),
                    None,
                    None,
                    None,
                    None,
                ),
            )
            db.execute(
                "INSERT INTO infrastructure_resource_aliases VALUES (?,?,?)",
                (project_id, identity, resource_id),
            )
            self._event(db, self._row(db, project_id, resource_id), "create_manual", None)
        return resource_id

    def update(self, project_id: str, resource_id: str, fields: Mapping[str, Any]) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._row(db, project_id, resource_id)
            values = self._fields(fields, manual=row["origin"] == "manual")
            before = self._view(db, row)
            metadata = dict(before["metadata"])
            for key, value in values.items():
                if value is None:
                    metadata.pop(key, None)
                else:
                    metadata[key] = value
            if metadata == before["metadata"]:
                return
            if (
                row["origin"] == "manual"
                and not metadata.get("name")
                and not before["observed"].get("name")
            ):
                raise ValueError("Имя ручного ресурса не может быть пустым.")
            db.execute(
                "UPDATE infrastructure_resources SET metadata=? WHERE project_id=? AND id=?",
                (_json(metadata), project_id, resource_id),
            )
            self._event(db, self._row(db, project_id, resource_id), "edit", before)

    def _lifecycle(self, project_id: str, resource_id: str, lifecycle: str) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._row(db, project_id, resource_id)
            if row["lifecycle"] == lifecycle:
                return
            before = self._view(db, row)
            db.execute(
                "UPDATE infrastructure_resources SET lifecycle=? WHERE project_id=? AND id=?",
                (lifecycle, project_id, resource_id),
            )
            self._event(
                db,
                self._row(db, project_id, resource_id),
                "archive" if lifecycle == "archived" else "restore",
                before,
            )

    def archive(self, project_id: str, resource_id: str) -> None:
        self._lifecycle(project_id, resource_id, "archived")

    def restore(self, project_id: str, resource_id: str) -> None:
        self._lifecycle(project_id, resource_id, "active")

    def link_manual(self, project_id: str, manual_id: str, discovered_id: str) -> None:
        """Explicitly associate discovery with a manual row, retaining both histories."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            manual = self._row(db, project_id, manual_id)
            discovered = self._row(db, project_id, discovered_id)
            if manual["origin"] != "manual" or discovered["origin"] != "discovered":
                raise ValueError("Сопоставьте ручную запись с отдельно обнаруженным ресурсом.")
            before = self._view(db, manual)
            discovered_before = self._view(db, discovered)
            times = self._times(manual, {key: discovered[key] for key in DATE_FIELDS})
            observed = dict(before["observed"])
            existing_date = self._latest({key: manual[key] for key in DATE_FIELDS})
            discovered_date = self._latest({key: discovered[key] for key in DATE_FIELDS})
            if (
                existing_date is None
                or discovered_date is not None
                and discovered_date >= existing_date
            ):
                observed.update(discovered_before["observed"])
            metadata = {**discovered_before["metadata"], **before["metadata"]}
            db.execute(
                "UPDATE infrastructure_resources "
                "SET observed=?,metadata=?,first_seen=?,last_scan=?,last_check=? "
                "WHERE project_id=? AND id=?",
                (
                    _json(observed),
                    _json(metadata),
                    times["first_seen"],
                    times["last_scan"],
                    times["last_check"],
                    project_id,
                    manual_id,
                ),
            )
            db.execute(
                "UPDATE infrastructure_resource_aliases SET resource_id=? "
                "WHERE project_id=? AND resource_id=?",
                (manual_id, project_id, discovered_id),
            )
            db.execute(
                "UPDATE infrastructure_resources SET lifecycle='archived',merged_into=? "
                "WHERE project_id=? AND id=?",
                (manual_id, project_id, discovered_id),
            )
            self._event(db, self._row(db, project_id, manual_id), "link", before)
            db.execute(
                "INSERT INTO infrastructure_resource_events VALUES (?,?,?,?,?,?,?)",
                (
                    str(uuid4()),
                    project_id,
                    discovered_id,
                    _now(),
                    "linked_into",
                    _json(discovered_before),
                    _json({"merged_into": manual_id}),
                ),
            )

    def history(self, project_id: str, resource_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            self._row(db, project_id, resource_id)
            rows = db.execute(
                "SELECT * FROM infrastructure_resource_events WHERE project_id=? AND "
                "(resource_id=? OR resource_id IN (SELECT id FROM infrastructure_resources "
                "WHERE project_id=? AND merged_into=?)) ORDER BY created_at,id",
                (project_id, resource_id, project_id, resource_id),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "resource_id": row["resource_id"],
                "created_at": row["created_at"],
                "action": row["action"],
                "before": json.loads(row["before_payload"]) if row["before_payload"] else None,
                "after": json.loads(row["after_payload"]),
            }
            for row in rows
        ]
