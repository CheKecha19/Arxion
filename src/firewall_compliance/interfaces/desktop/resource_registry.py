"""Persistent resource registry; imported observations and user metadata stay separate."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, NotRequired, TypedDict, cast
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
    {"name", "platform", "resource_type", "category", "vdc", "region", "source", "observed_addresses"}
)
DATE_FIELDS = ("first_seen", "last_scan", "last_check")
MATRIX_BINDING_FIELD = "matrix_address_binding"
MATRIX_SOURCE_BINDINGS_FIELD = "matrix_source_bindings"


class ResourceAddressBinding(TypedDict):
    site_id: str
    prefixes: list[str]


class ResourceSourceAddressBinding(ResourceAddressBinding):
    device_id: str
    platform: str
    device_context: str | None
    vrf: NotRequired[str]


type _MatrixSourceKey = tuple[str, str, str, str | None, str | None]
type _MatrixResource = tuple[str, str, ResourceAddressBinding | None, tuple[ResourceSourceAddressBinding, ...]]
type _ManualMetadata = dict[str, str | ResourceAddressBinding]
type _ManualAddressKey = tuple[str, str, tuple[str, ...]]


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


def resource_address_binding(value: Any) -> ResourceAddressBinding:
    """Разбирает явное назначение ресурса адресам в стандартном контексте площадки."""
    if not isinstance(value, dict) or set(value) != {"site_id", "prefixes"}:
        raise ValueError("Укажите площадку и подтверждённые адреса ресурса.")
    site_id = _text(value["site_id"], maximum=512)
    prefixes = value["prefixes"]
    if not isinstance(prefixes, (list, tuple)) or not prefixes:
        raise ValueError("Укажите хотя бы один подтверждённый IP-адрес или CIDR.")
    normalized: set[str] = set()
    try:
        for prefix in prefixes:
            prefix = _text(prefix, maximum=64)
            if "%" in prefix:
                raise ValueError
            normalized.add(str(ip_network(prefix)))
    except ValueError:
        raise ValueError("Укажите IP-адрес или адрес сети в CIDR для каждого элемента.") from None
    return {"site_id": site_id, "prefixes": sorted(normalized)}


def _matrix_source_key(
    site_id: Any, device_id: Any, platform: Any, device_context: Any, vrf: Any = None,
) -> _MatrixSourceKey:
    site = _text(site_id, maximum=512)
    device = _text(device_id)
    kind = _text(platform)
    context = _text(device_context) if device_context is not None else None
    scoped = _text(vrf) if vrf is not None else None
    if not device or not kind or context == "" or scoped == "":
        raise ValueError("Укажите точный идентификатор, платформу и контекст источника сверки.")
    return site, device, kind, context, scoped


def _binding_source_key(binding: ResourceSourceAddressBinding) -> _MatrixSourceKey:
    return binding["site_id"], binding["device_id"], binding["platform"], binding["device_context"], binding.get("vrf")


def resource_source_address_bindings(value: Any) -> tuple[ResourceSourceAddressBinding, ...]:
    """Проверяет подтверждённые адреса для точных источников сверки."""
    if not isinstance(value, (list, tuple)):
        raise ValueError("Привязки адресов к источникам должны быть списком.")
    bindings: dict[_MatrixSourceKey, ResourceSourceAddressBinding] = {}
    required = {"site_id", "prefixes", "device_id", "platform", "device_context"}
    for raw in value:
        if not isinstance(raw, dict) or set(raw) - {"vrf"} != required:
            raise ValueError("Привязка должна содержать площадку, адреса и точный источник сверки.")
        addresses = resource_address_binding({"site_id": raw["site_id"], "prefixes": raw["prefixes"]})
        key = _matrix_source_key(addresses["site_id"], raw["device_id"], raw["platform"], raw["device_context"], raw.get("vrf"))
        if key in bindings:
            raise ValueError("Для одного источника и площадки нужна одна привязка адресов.")
        binding: ResourceSourceAddressBinding = {
            **addresses, "device_id": key[1], "platform": key[2], "device_context": key[3],
        }
        if key[4] is not None:
            binding["vrf"] = key[4]
        bindings[key] = binding
    return tuple(bindings.values())


def _read_matrix_source_bindings(metadata: Mapping[str, Any]) -> tuple[ResourceSourceAddressBinding, ...]:
    try:
        return resource_source_address_bindings(metadata.get(MATRIX_SOURCE_BINDINGS_FIELD, ()))
    except ValueError:
        return ()


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
    def _view(
        db: sqlite3.Connection, row: sqlite3.Row, identities: list[str] | None = None,
    ) -> dict[str, Any]:
        observed = json.loads(row["observed"])
        metadata = json.loads(row["metadata"])
        if identities is None:
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
    def _fields(
        fields: Mapping[str, Any], *, manual: bool,
    ) -> dict[str, str | ResourceAddressBinding | None]:
        allowed = METADATA_FIELDS | MANUAL_FIELDS if manual else METADATA_FIELDS
        if set(fields) - allowed - {MATRIX_BINDING_FIELD}:
            raise ValueError("Изменяются только пользовательские поля ресурса.")
        values: dict[str, str | ResourceAddressBinding | None] = {}
        for key, raw in fields.items():
            if raw is None:
                values[key] = None
                continue
            if key == MATRIX_BINDING_FIELD:
                values[key] = resource_address_binding(raw)
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
        for key in OBSERVED_FIELDS - {"source", "observed_addresses"}:
            raw = observation.get(key)
            if raw is not None:
                observed[key] = _text(raw)
        if observed.get("category") not in CATEGORIES:
            raise ValueError("Наблюдение должно содержать известную категорию ресурса.")
        addresses = observation.get("observed_addresses")
        if addresses is not None:
            if not isinstance(addresses, (list, tuple)) or any(
                not isinstance(value, str) or "%" in value for value in addresses
            ):
                raise ValueError("Адреса наблюдения должны быть списком IP-адресов.")
            observed["observed_addresses"] = sorted({str(ip_address(value)) for value in addresses})
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
        self, project_id: str, observations: Sequence[dict[str, Any]], *, read_back: bool = True,
    ) -> list[dict[str, Any]]:
        """Accumulate observations; neither missing rows nor rediscovery remove archives."""
        parsed = [self._observation(observation) for observation in observations]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._project(db, project_id)
            aliases = {
                row["identity"]: row["resource_id"]
                for row in db.execute(
                    "SELECT identity,resource_id FROM infrastructure_resource_aliases WHERE project_id=?",
                    (project_id,),
                )
            }
            rows = {
                row["id"]: row
                for row in db.execute(
                    "SELECT * FROM infrastructure_resources WHERE project_id=? AND merged_into IS NULL",
                    (project_id,),
                )
            }
            for identity, observed, dates in parsed:
                resource_id = aliases.get(identity)
                if resource_id is None:
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
                    aliases[identity] = resource_id
                    rows[resource_id] = self._row(db, project_id, resource_id)
                    self._event(db, rows[resource_id], "discover", None)
                    continue
                row = rows.get(resource_id)
                if row is None:
                    raise ValueError("Псевдоним ресурса указывает на недоступную карточку.")
                times = self._times(row, dates)
                current_latest = self._latest({key: row[key] for key in DATE_FIELDS})
                incoming_latest = self._latest(dates)
                previous = json.loads(row["observed"])
                merged = dict(previous)
                if (
                    current_latest is None
                    or incoming_latest is not None
                    and incoming_latest >= current_latest
                ):
                    merged.update(observed)
                if merged == previous and all(
                    times[key] == row[key] for key in DATE_FIELDS
                ):
                    continue
                before = self._view(db, row)
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
                rows[resource_id] = self._row(db, project_id, resource_id)
                self._event(db, rows[resource_id], "observe", before)
        return self.list_resources(project_id, include_archived=True) if read_back else []

    def list_resources(
        self, project_id: str, include_archived: bool = False
    ) -> list[dict[str, Any]]:
        with self._connect() as db:
            db.execute("BEGIN")
            self._project(db, project_id)
            rows = db.execute(
                "SELECT * FROM infrastructure_resources WHERE project_id=? AND merged_into IS NULL "
                "AND (? OR lifecycle='active') ORDER BY created_at,id",
                (project_id, include_archived),
            ).fetchall()
            aliases: dict[str, list[str]] = {}
            for alias in db.execute(
                "SELECT resource_id,identity FROM infrastructure_resource_aliases "
                "WHERE project_id=? ORDER BY resource_id,identity",
                (project_id,),
            ):
                aliases.setdefault(alias["resource_id"], []).append(alias["identity"])
            return [self._view(db, row, aliases.get(row["id"], [])) for row in rows]

    def archived_device_ids(self, project_id: str) -> frozenset[str]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT a.identity FROM infrastructure_resource_aliases a
                   JOIN infrastructure_resources r ON r.id=a.resource_id AND r.project_id=a.project_id
                   WHERE a.project_id=? AND r.lifecycle='archived' AND r.merged_into IS NULL
                         AND a.identity GLOB 'device:*'""",
                (project_id,),
            )
            return frozenset(row["identity"].removeprefix("device:") for row in rows)

    def matrix_resources(
        self, project_id: str,
    ) -> list[tuple[str, str, ResourceAddressBinding | None]]:
        """Читает карточки без истории наблюдений и без запроса псевдонимов для каждой строки."""
        resources, _ = self.matrix_catalog_snapshot(project_id)
        return [(key, label, binding) for key, label, binding, _ in resources]

    def matrix_catalog_snapshot(self, project_id: str) -> tuple[list[_MatrixResource], dict[str, str]]:
        """Читать активные карточки, адреса и явные объединения одним снимком."""
        with self._connect() as db:
            db.execute("BEGIN")
            self._project(db, project_id)
            rows = db.execute(
                "SELECT id,observed,metadata FROM infrastructure_resources "
                "WHERE project_id=? AND merged_into IS NULL AND lifecycle='active' "
                "ORDER BY created_at,id",
                (project_id,),
            ).fetchall()
            redirects = dict(db.execute(
                "SELECT source.id, target.id FROM infrastructure_resources source "
                "JOIN infrastructure_resources target ON target.id=source.merged_into "
                "AND target.project_id=source.project_id "
                "WHERE source.project_id=? AND target.merged_into IS NULL AND target.lifecycle='active'",
                (project_id,),
            ).fetchall())
        result: list[_MatrixResource] = []
        for row in rows:
            metadata = json.loads(row["metadata"])
            label = (
                metadata.get("label") or metadata.get("name")
                or json.loads(row["observed"]).get("name")
            )
            raw = metadata.get(MATRIX_BINDING_FIELD)
            try:
                binding = resource_address_binding(raw) if raw is not None else None
            except ValueError:
                binding = None
            result.append((row["id"], str(label or row["id"]), binding, _read_matrix_source_bindings(metadata)))
        return result, redirects

    def set_matrix_source_binding(
        self, project_id: str, resource_id: str, *, site_id: str, device_id: str,
        platform: str, device_context: str | None, prefixes: Sequence[str], vrf: str | None = None,
    ) -> None:
        """Обновляет или удаляет адреса для одной пары источника и площадки."""
        if isinstance(prefixes, (str, bytes)) or not isinstance(prefixes, Sequence):
            raise ValueError("Укажите список подтверждённых IP-адресов или CIDR.")
        key = _matrix_source_key(site_id, device_id, platform, device_context, vrf)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._row(db, project_id, resource_id)
            if row["lifecycle"] != "active":
                raise ValueError("Привязку можно изменить в активной карточке ресурса.")
            if prefixes and key[0] and (
                db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='workspace_sites'").fetchone() is None
                or db.execute("SELECT 1 FROM workspace_sites WHERE id=?", (key[0],)).fetchone() is None
            ):
                raise ValueError("Площадка для сверки не найдена.")
            before = self._view(db, row)
            metadata = dict(before["metadata"])
            current = resource_source_address_bindings(metadata.get(MATRIX_SOURCE_BINDINGS_FIELD, ()))
            bindings = {_binding_source_key(binding): binding for binding in current}
            if prefixes:
                addresses = resource_address_binding({"site_id": key[0], "prefixes": list(prefixes)})
                binding: ResourceSourceAddressBinding = {
                    **addresses, "device_id": key[1], "platform": key[2], "device_context": key[3],
                }
                if key[4] is not None:
                    binding["vrf"] = key[4]
                bindings[key] = binding
            else:
                bindings.pop(key, None)
            updated = tuple(bindings.values())
            if updated == current:
                return
            if updated:
                metadata[MATRIX_SOURCE_BINDINGS_FIELD] = list(updated)
            else:
                metadata.pop(MATRIX_SOURCE_BINDINGS_FIELD, None)
            db.execute(
                "UPDATE infrastructure_resources SET metadata=? WHERE project_id=? AND id=?",
                (_json(metadata), project_id, resource_id),
            )
            self._event(db, self._row(db, project_id, resource_id), "edit", before)

    @classmethod
    def _manual_metadata(cls, fields: Mapping[str, Any]) -> _ManualMetadata:
        values = cls._fields(fields, manual=True)
        if not values.get("name"):
            raise ValueError("Введите имя ручного ресурса.")
        return {key: value for key, value in values.items() if value is not None}

    @classmethod
    def _insert_manual(cls, db: sqlite3.Connection, project_id: str, metadata: _ManualMetadata) -> str:
        resource_id = str(uuid4())
        identity = "manual:" + resource_id
        db.execute(
            "INSERT INTO infrastructure_resources VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (resource_id, project_id, identity, "manual", "active", "{}", _json(metadata), _now(),
             None, None, None, None),
        )
        db.execute(
            "INSERT INTO infrastructure_resource_aliases VALUES (?,?,?)",
            (project_id, identity, resource_id),
        )
        cls._event(db, cls._row(db, project_id, resource_id), "create_manual", None)
        return resource_id

    def add_manual(self, project_id: str, fields: Mapping[str, Any]) -> str:
        metadata = self._manual_metadata(fields)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._project(db, project_id)
            return self._insert_manual(db, project_id, metadata)

    def add_manual_batch(self, project_id: str, rows: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
        """Создать ручные карточки с подтверждёнными адресами одной транзакцией."""
        prepared: list[_ManualMetadata] = []
        positions: dict[_ManualAddressKey, int] = {}
        sites: dict[str, int] = {}
        for number, fields in enumerate(rows, start=1):
            try:
                if not isinstance(fields, Mapping):
                    raise ValueError("Ожидаются поля ручного ресурса.")
                metadata = self._manual_metadata(fields)
                binding = metadata.get(MATRIX_BINDING_FIELD)
                if not isinstance(binding, dict):
                    raise ValueError("Укажите площадку и подтверждённые адреса ресурса.")
                name = cast(str, metadata["name"])
            except ValueError as error:
                raise ValueError(f"Строка {number}. {error}") from None
            key = (name.casefold(), binding["site_id"], tuple(binding["prefixes"]))
            if key in positions:
                raise ValueError(f"Строка {number} повторяет имя, площадку и адреса строки {positions[key]}.")
            positions[key] = number
            if binding["site_id"]:
                sites.setdefault(binding["site_id"], number)
            prepared.append(metadata)
        if not prepared:
            return ()

        names = {name for name, _, _ in positions}
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._project(db, project_id)
            if sites:
                has_sites = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='workspace_sites'"
                ).fetchone()
                available = {row["id"] for row in db.execute("SELECT id FROM workspace_sites")} if has_sites else set()
                for site_id, number in sites.items():
                    if site_id not in available:
                        raise ValueError(f"Строка {number}. Площадка для сверки не найдена.")
            for row in db.execute(
                "SELECT metadata,lifecycle FROM infrastructure_resources "
                "WHERE project_id=? AND origin='manual' AND merged_into IS NULL",
                (project_id,),
            ):
                existing = json.loads(row["metadata"])
                existing_name = existing.get("name")
                if not isinstance(existing_name, str) or (name := existing_name.strip().casefold()) not in names:
                    continue
                try:
                    binding = resource_address_binding(existing.get(MATRIX_BINDING_FIELD))
                except ValueError:
                    continue
                key = name, binding["site_id"], tuple(binding["prefixes"])
                if key in positions:
                    state = "архивная " if row["lifecycle"] == "archived" else ""
                    raise ValueError(
                        f"Строка {positions[key]}. Уже существует {state}ручная карточка "
                        f"«{existing_name.strip()[:120]}» с этой площадкой и адресами."
                    )
            return tuple(self._insert_manual(db, project_id, metadata) for metadata in prepared)

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
            if MATRIX_SOURCE_BINDINGS_FIELD in metadata:
                source_bindings = {
                    _binding_source_key(binding): binding
                    for record in (discovered_before, before)
                    for binding in _read_matrix_source_bindings(record["metadata"])
                }
                if source_bindings:
                    metadata[MATRIX_SOURCE_BINDINGS_FIELD] = list(source_bindings.values())
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
