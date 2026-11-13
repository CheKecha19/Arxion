"""Project-local network intent and explicit bindings to imported switch VLANs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from ipaddress import ip_network
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.logical_network_vlan_draft import LogicalNetworkVlanDraft
    from firewall_compliance.interfaces.desktop.project_store import ProjectStore

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS logical_networks (
        project_id TEXT NOT NULL REFERENCES projects(id),
        id TEXT NOT NULL, name TEXT NOT NULL, site_id TEXT NOT NULL,
        vlan_id INTEGER NOT NULL CHECK(vlan_id BETWEEN 1 AND 4094),
        subnets TEXT NOT NULL, vrf TEXT NOT NULL,
        PRIMARY KEY (project_id, id)
    )""",
    """CREATE TABLE IF NOT EXISTS logical_vlan_bindings (
        project_id TEXT NOT NULL, device_id TEXT NOT NULL,
        vlan_id INTEGER NOT NULL CHECK(vlan_id BETWEEN 1 AND 4094),
        network_id TEXT NOT NULL,
        PRIMARY KEY (project_id, device_id, vlan_id),
        FOREIGN KEY (project_id, network_id) REFERENCES logical_networks(project_id, id)
    )""",
    """CREATE TABLE IF NOT EXISTS logical_network_events (
        project_id TEXT NOT NULL REFERENCES projects(id),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        action TEXT NOT NULL, before_value TEXT NOT NULL, after_value TEXT NOT NULL
    )""",
)


def subnet_comparison(
    observed: set[str], expected: Sequence[str], *, incomplete: bool
) -> tuple[str, set[str]]:
    unexpected = observed.difference(expected) if expected else set()
    if unexpected:
        return "Расхождение", unexpected
    if not observed or not expected or incomplete:
        return "Нет данных для сравнения", set()
    return "Совпадает", set()


def _network_values(
    name: str, site_id: str, vlan_id: int, subnets: Sequence[str], vrf: str,
) -> tuple[str, str, int, str, str]:
    if not name.strip():
        raise ValueError("Укажите название логической сети.")
    try:
        if any("/" not in value for value in subnets):
            raise ValueError("Missing prefix")
        prefixes = sorted({str(ip_network(value)) for value in subnets})
    except ValueError:
        raise ValueError("Укажите подсети в CIDR, например 10.20.100.0/24.") from None
    return name.strip(), site_id, vlan_id, json.dumps(prefixes), vrf.strip()


class LogicalNetworkStore:
    def __init__(self, store: ProjectStore) -> None:
        self.store = store

    def read(
        self, project_id: str
    ) -> tuple[list[dict[str, Any]], dict[tuple[str, int], str]]:
        with self.store._connect() as db:
            db.execute("BEGIN")
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='logical_networks'"
            ).fetchone():
                return [], {}
            rows = db.execute(
                "SELECT * FROM logical_networks WHERE project_id=? ORDER BY name, id", (project_id,)
            )
            networks = [{**dict(row), "subnets": json.loads(row["subnets"])} for row in rows]
            bindings = {
                (row["device_id"], row["vlan_id"]): row["network_id"]
                for row in db.execute(
                    "SELECT * FROM logical_vlan_bindings WHERE project_id=?", (project_id,)
                )
            }
            return networks, bindings

    def history(self, project_id: str) -> list[dict[str, Any]]:
        with self.store._connect() as db:
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='logical_network_events'"
            ).fetchone():
                return []
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM logical_network_events WHERE project_id=? ORDER BY rowid DESC",
                    (project_id,),
                )
            ]

    def save(
        self, project_id: str, *, name: str, site_id: str, vlan_id: int,
        subnets: Sequence[str], vrf: str, network_id: str | None = None,
        binding: tuple[str, int] | None = None,
    ) -> str:
        identifier = network_id or str(uuid4())
        values = _network_values(name, site_id, vlan_id, subnets, vrf)
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for statement in _SCHEMA:
                db.execute(statement)
            before = db.execute(
                "SELECT * FROM logical_networks WHERE project_id=? AND id=?",
                (project_id, identifier),
            ).fetchone()
            if network_id and before is None:
                raise ValueError("Логическая сеть не найдена.")
            db.execute(
                """INSERT INTO logical_networks VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(project_id, id) DO UPDATE SET name=excluded.name,
                   site_id=excluded.site_id, vlan_id=excluded.vlan_id,
                   subnets=excluded.subnets, vrf=excluded.vrf""",
                (project_id, identifier, *values),
            )
            after = db.execute(
                "SELECT * FROM logical_networks WHERE project_id=? AND id=?",
                (project_id, identifier),
            ).fetchone()
            previous = dict(before) if before else None
            if previous != dict(after):
                self._event(db, project_id, "Сохранение сети", previous, dict(after))
            if binding is not None:
                self._bind(db, project_id, binding, identifier)
        return identifier

    def create_from_vlans(
        self, project_id: str, candidates: Sequence[LogicalNetworkVlanDraft],
    ) -> tuple[str, ...]:
        """Создать все выбранные сети, привязки и записи истории одной транзакцией."""
        prepared: list[tuple[str, tuple[str, int], tuple[str, str, int, str, str]]] = []
        keys: set[tuple[str, int]] = set()
        domains: set[tuple[str, int]] = set()
        device_sites: dict[str, str] = {}
        for candidate in candidates:
            key, site = candidate.binding_key, candidate.site_id
            if (
                candidate.reason is not None or key is None or not key[0].strip()
                or type(key[1]) is not int or not 1 <= key[1] <= 4094 or key[1] != candidate.vlan_id
                or not site or not candidate.subnets
            ):
                raise ValueError("Для создания сети выберите наблюдение VLAN с площадкой и подсетью.")
            domain = site, key[1]
            if key in keys or domain in domains:
                raise ValueError("В выборке повторяется устройство и VLAN или площадка и VLAN.")
            if device_sites.setdefault(key[0], site) != site:
                raise ValueError("Для одного устройства указаны разные площадки. Обновите выборку.")
            keys.add(key)
            domains.add(domain)
            values = _network_values(candidate.name, site, key[1], candidate.subnets, candidate.vrf)
            prepared.append((str(uuid4()), key, values))
        if not prepared:
            return ()

        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.store.workspace_metadata._ready(db)
            for device_id, site_id in device_sites.items():
                if db.execute(
                    """SELECT 1 FROM workspace_device_sites a JOIN workspace_sites s ON s.id=a.site_id
                       WHERE a.origin_project_id=? AND a.device_id=? AND a.site_id=?""",
                    (project_id, device_id, site_id),
                ).fetchone() is None:
                    raise ValueError("Площадка устройства изменилась или недоступна. Обновите выборку.")
            for statement in _SCHEMA:
                db.execute(statement)
            if any(
                (row["site_id"], row["vlan_id"]) in domains
                for row in db.execute("SELECT site_id, vlan_id FROM logical_networks WHERE project_id=?", (project_id,))
            ):
                raise ValueError("Для площадки и номера VLAN уже есть логическая сеть. Обновите выборку.")
            for identifier, key, values in prepared:
                row = (project_id, identifier, *values)
                db.execute("INSERT INTO logical_networks VALUES (?, ?, ?, ?, ?, ?, ?)", row)
                self._event(
                    db, project_id, "Сохранение сети", None,
                    dict(zip(("project_id", "id", "name", "site_id", "vlan_id", "subnets", "vrf"), row, strict=True)),
                )
                self._bind(db, project_id, key, identifier, unbound_only=True)
        return tuple(identifier for identifier, _, _ in prepared)

    def bind(self, project_id: str, key: tuple[str, int], network_id: str | None) -> None:
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='logical_vlan_bindings'"
            ).fetchone():
                if network_id is None:
                    return
                raise ValueError("Логическая сеть не найдена.")
            self._bind(db, project_id, key, network_id)

    def confirm_suggestions(
        self, project_id: str, network_id: str, site_id: str, vlan_id: int,
        keys: Sequence[tuple[str, int]],
    ) -> None:
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            network = db.execute(
                "SELECT site_id, vlan_id FROM logical_networks WHERE project_id=? AND id=?",
                (project_id, network_id),
            ).fetchone()
            if network is None or (network["site_id"], network["vlan_id"]) != (site_id, vlan_id):
                raise ValueError("Площадка или VLAN сети изменились. Обновите предложения.")
            for key in keys:
                if key[1] != vlan_id:
                    raise ValueError("VLAN не совпадает с номером в логической сети.")
                self._bind(db, project_id, key, network_id, unbound_only=True)

    @staticmethod
    def _event(
        db: sqlite3.Connection, project_id: str, action: str, before: Any, after: Any
    ) -> None:
        db.execute(
            """INSERT INTO logical_network_events (project_id, action, before_value, after_value)
               VALUES (?, ?, ?, ?)""",
            (project_id, action, json.dumps(before, ensure_ascii=False),
             json.dumps(after, ensure_ascii=False)),
        )

    def _bind(
        self, db: sqlite3.Connection, project_id: str, key: tuple[str, int],
        network_id: str | None, *, unbound_only: bool = False,
    ) -> None:
        if not key[0] or not 1 <= key[1] <= 4094:
            raise ValueError("У наблюдения нет устойчивого идентификатора VLAN.")
        scope = (project_id, *key)
        before = db.execute(
            """SELECT network_id FROM logical_vlan_bindings
               WHERE project_id=? AND device_id=? AND vlan_id=?""",
            scope,
        ).fetchone()
        previous = before["network_id"] if before else None
        if network_id == previous:
            return
        if unbound_only and previous is not None:
            raise ValueError("Один из VLAN уже привязан к другой сети. Обновите предложения.")
        if network_id is None:
            db.execute(
                "DELETE FROM logical_vlan_bindings WHERE project_id=? AND device_id=? AND vlan_id=?",
                scope,
            )
        else:
            db.execute(
                """INSERT INTO logical_vlan_bindings VALUES (?, ?, ?, ?)
                   ON CONFLICT(project_id, device_id, vlan_id)
                   DO UPDATE SET network_id=excluded.network_id""",
                (*scope, network_id),
            )
        device = {"device_id": key[0], "vlan_id": key[1]}
        self._event(
            db, project_id, "Привязка VLAN",
            {**device, "network_id": previous},
            {**device, "network_id": network_id},
        )
