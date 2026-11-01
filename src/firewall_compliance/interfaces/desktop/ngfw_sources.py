"""Explicit saved NGFW sources using existing DPAPI-protected integrations rows."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from firewall_compliance.infrastructure.ideco import IdecoReader
from firewall_compliance.infrastructure.usergate import UserGateReader
from firewall_compliance.infrastructure.windows_secrets import protect_secret, unprotect_secret

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.project_store import ProjectStore


class NgfwSource(BaseModel):
    """Public connection metadata; passwords never enter this model or snapshots."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    source_id: str = Field(default_factory=lambda: str(uuid4()))
    provider: Literal["usergate", "ideco"]
    label: str = Field(min_length=1, max_length=200)
    host: str
    username: str = Field(min_length=1, max_length=200)
    family: Literal["6", "7"] = "7"
    transport: Literal["tcp", "https"] = "https"
    port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    ca_file: str | None = None
    timeout: float = Field(default=30, gt=0, le=300)

    @model_validator(mode="after")
    def validate_endpoint(self) -> Self:
        UUID(self.source_id)
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", self.host):
            raise ValueError("Укажите имя узла или IPv4 без URL и порта")
        if not self.label.strip() or not self.username.strip() or not math.isfinite(self.timeout):
            raise ValueError("Проверьте название, пользователя и таймаут")
        if self.provider == "ideco" and self.transport != "https":
            raise ValueError("Ideco требует проверяемый HTTPS")
        if self.provider == "usergate" and self.family == "6" and self.transport != "tcp":
            raise ValueError("UserGate 6 требует XML-RPC TCP/HTTP")
        return self

    @property
    def source_key(self) -> str:
        return f"ngfw:{self.provider}:{self.source_id}"

    def reader(self) -> UserGateReader | IdecoReader:
        """Reuse reader validation/TLS setup; construction performs no requests."""
        if self.provider == "usergate":
            return UserGateReader(
                self.host, family=self.family, transport=self.transport,
                port=self.port, ca_file=self.ca_file, timeout=self.timeout,
            )
        return IdecoReader(
            self.host, port=self.port or 8443, ca_file=self.ca_file, timeout=self.timeout
        )


class SavedNgfwSources:
    """Multiple vendor connections per legacy origin, no additional catalog tables.

    Future organization activation must explicitly transfer rows to org_connections.
    Creating this wrapper performs no writes; save is an explicit consent action.
    """

    def __init__(self, store: ProjectStore) -> None:
        self.store = store

    def list(self, project_id: str, provider: str | None = None) -> tuple[NgfwSource, ...]:
        with self.store._connect() as db:
            rows = db.execute(
                "SELECT provider,config FROM integrations WHERE project_id=? "
                "AND provider LIKE 'ngfw:%' ORDER BY provider", (project_id,),
            ).fetchall()
        values = []
        for row in rows:
            value = NgfwSource.model_validate_json(row["config"])
            if value.source_key != row["provider"]:
                raise ValueError("Идентификатор NGFW не соответствует сохранённому источнику")
            if provider is None or value.provider == provider:
                values.append(value)
        return tuple(values)

    def get(self, project_id: str, source_id: str) -> NgfwSource | None:
        keys = (source_id,) if source_id.startswith("ngfw:") else (
            f"ngfw:usergate:{source_id}", f"ngfw:ideco:{source_id}"
        )
        with self.store._connect() as db:
            rows = []
            for key in keys:
                row = db.execute(
                    "SELECT provider,config FROM integrations WHERE project_id=? AND provider=?",
                    (project_id, key),
                ).fetchone()
                if row is not None:
                    rows.append(row)
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError("Неоднозначный идентификатор источника NGFW")
        source = NgfwSource.model_validate_json(rows[0]["config"])
        if source.source_key != rows[0]["provider"]:
            raise ValueError("Источник NGFW не соответствует ключу подключения")
        return source

    def save(self, project_id: str, source: NgfwSource, password: str) -> None:
        source = NgfwSource.model_validate(source)
        source.reader()
        if not isinstance(password, str) or not password:
            raise ValueError("Для сохранения подключения введите пароль заново")
        protected = protect_secret(password)
        with self.store._connect() as db:
            db.execute(
                "INSERT INTO integrations VALUES(?,?,?,?) "
                "ON CONFLICT(project_id,provider) DO UPDATE SET "
                "config=excluded.config,protected_secret=excluded.protected_secret",
                (project_id, source.source_key, source.model_dump_json(), protected),
            )

    def password(self, project_id: str, source: NgfwSource) -> str:
        with self.store._connect() as db:
            row = db.execute(
                "SELECT config,protected_secret FROM integrations WHERE project_id=? AND provider=?",
                (project_id, source.source_key),
            ).fetchone()
        if row is None or NgfwSource.model_validate_json(row["config"]) != source:
            raise ValueError("Подключение изменилось; повторно выберите источник или введите пароль")
        return unprotect_secret(row["protected_secret"])


def collect_saved_ngfw(
    store: ProjectStore,
    project_id: str,
    source_id: str,
    output_dir: Path,
    cancel: Callable[[], bool],
) -> Path:
    """Collect a configured source in a worker; cancellation is between stages.

    Reader calls remain bounded but cannot be interrupted mid-request. No output
    is created after cancellation is observed. Each successful snapshot gets an
    exclusive UUID filename; source credentials are never included in it.
    """
    saved = SavedNgfwSources(store)
    source = saved.get(project_id, source_id)
    if source is None:
        raise ValueError("Сохранённый источник NGFW не найден")
    if cancel():
        raise InterruptedError("Сбор NGFW отменён")
    reader = source.reader()
    snapshot = reader.collect(source.username, saved.password(project_id, source))
    if cancel():
        raise InterruptedError("Сбор NGFW отменён")
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{source.provider}-{source.source_id}-{uuid4().hex}.json"
    with target.open("x", encoding="utf-8") as stream:
        json.dump(snapshot, stream, ensure_ascii=False, indent=2, allow_nan=False)
    return target
