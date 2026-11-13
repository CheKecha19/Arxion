"""Saved local configuration sources, using the existing project source catalogue."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from os.path import normcase, normpath
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from firewall_compliance.application.source_health import configuration_fingerprint

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.project_store import ProjectStore


FILE_SOURCE_PREFIX = "files:"
CONFIG_EXTENSIONS = frozenset({".txt", ".cfg", ".conf", ".config", ".json"})


def file_path_key(path: Path) -> str:
    # normcase is platform-specific: Windows paths are case-insensitive.
    return normcase(normpath(str(path)))


def default_file_device_id(path: Path) -> str:
    # A path is stable across fresh exports. Identical basenames in different
    # directories must not merge without an explicit association.
    return f"file:{path.stem[:80]}:{sha256(file_path_key(path).encode()).hexdigest()[:24]}"


class FileSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    source_id: UUID = Field(default_factory=uuid4)
    label: str = Field(min_length=1, max_length=200)
    kind: Literal["files", "directory"]
    paths: tuple[str, ...]
    enabled: bool = True
    device_ids: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        if not self.label.strip() or not self.paths:
            raise ValueError("Укажите название и пути источника")
        if self.kind == "directory" and len(self.paths) != 1:
            raise ValueError("Для источника-папки укажите один путь")
        if any(not Path(path).is_absolute() for path in self.paths):
            raise ValueError("Укажите абсолютные пути к локальным конфигурациям")
        if any(not Path(path).is_absolute() or not name.strip()
               for path, name in self.device_ids.items()):
            raise ValueError("Некорректная привязка файла к устройству")
        if len({file_path_key(Path(path)) for path in self.device_ids}) != len(self.device_ids):
            raise ValueError("Несколько привязок для одного файла")
        return self

    @property
    def source_key(self) -> str:
        return FILE_SOURCE_PREFIX + str(self.source_id)

    def paths_for_run(self) -> tuple[Path, ...]:
        """Expand the selected directory once, in stable order, in a worker."""
        if self.kind == "directory":
            paths = sorted(
                (path for path in Path(self.paths[0]).iterdir()
                 if path.suffix.lower() in CONFIG_EXTENSIONS and path.is_file()),
                key=file_path_key,
            )
        else:
            # Keep missing explicit files so the cycle records their failures.
            paths = [Path(path) for path in self.paths]
        result: dict[str, Path] = {}
        for path in paths:
            result.setdefault(file_path_key(path), path)
        return tuple(result.values())


class SavedFileSources:
    def __init__(self, store: ProjectStore) -> None:
        self.store = store

    def list(self, project_id: str) -> tuple[FileSource, ...]:
        result = []
        for row in self.store.list_source_connections(project_id):
            if row["provider"].startswith(FILE_SOURCE_PREFIX):
                try:
                    result.append(self.from_config(row["provider"], row["config"]))
                except (ValueError, TypeError):
                    # Invalid rows remain visible in source health and are
                    # reported by the collection cycle independently.
                    continue
        return tuple(result)

    @staticmethod
    def from_config(source_key: str, config: Mapping[str, object] | None) -> FileSource:
        source = FileSource.model_validate(config)
        if source.source_key != source_key:
            raise ValueError("Ключ файлового источника не совпадает с настройками")
        return source

    def get(self, project_id: str, source_key: str) -> FileSource | None:
        with self.store._connect() as db:
            row = db.execute(
                "SELECT config FROM integrations WHERE project_id=? AND provider=?",
                (project_id, source_key),
            ).fetchone()
        return self.from_config(source_key, json.loads(row["config"])) if row else None

    def save(
        self, project_id: str, source: FileSource, *, previous: FileSource | None = None,
    ) -> None:
        """Update only the version selected in the editor."""
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT config FROM integrations WHERE project_id=? AND provider=?",
                (project_id, source.source_key),
            ).fetchone()
            current = (
                self.from_config(source.source_key, json.loads(row["config"])) if row else None
            )
            if current != previous:
                raise ValueError("Источник изменился. Обновите список перед сохранением")
            db.execute(
                "INSERT INTO integrations(project_id,provider,config,protected_secret) "
                "VALUES(?,?,?,'') ON CONFLICT(project_id,provider) DO UPDATE "
                "SET config=excluded.config",
                (project_id, source.source_key, source.model_dump_json()),
            )

    def previous_devices(self, project_id: str, source: FileSource) -> dict[str, str]:
        """Reuse staged assignments from the latest run with the same configuration."""
        fingerprint = configuration_fingerprint(source.model_dump(mode="json"))
        with self.store._connect() as db:
            rows = db.execute(
                "SELECT settings FROM runs WHERE project_id=? ORDER BY created_at DESC,rowid DESC",
                (project_id,),
            )
            bindings = {}
            for run in rows:
                settings = json.loads(run["settings"])
                if (
                    settings.get("source_id") == source.source_key
                    and settings.get("source_config_fingerprint") == fingerprint
                    and isinstance(settings.get("workspace_input_devices"), dict)
                ):
                    bindings = settings["workspace_input_devices"]
                    break
        return {
            file_path_key(Path(path)): name for path, name in bindings.items()
            if isinstance(name, str) and name.strip()
        }
