"""Independent legacy SQL fixture and byte/type oracle; no production serializers."""

import json
import sqlite3
import struct
from collections import Counter
from pathlib import Path

SCHEMA = """
CREATE TABLE projects(id TEXT PRIMARY KEY,name TEXT,created_at TEXT,settings TEXT);
CREATE TABLE runs(id TEXT PRIMARY KEY,project_id TEXT REFERENCES projects(id),
 created_at TEXT,finished_at TEXT,state TEXT,settings TEXT);
CREATE TABLE items(id TEXT PRIMARY KEY,run_id TEXT REFERENCES runs(id),payload TEXT);
CREATE TABLE marks(run_id TEXT REFERENCES runs(id),finding_id TEXT,status TEXT,
 comment TEXT,updated_at TEXT,PRIMARY KEY(run_id,finding_id));
CREATE TABLE device_links(project_id TEXT REFERENCES projects(id),source_key TEXT,
 device_id TEXT,PRIMARY KEY(project_id,source_key));
CREATE TABLE integrations(project_id TEXT REFERENCES projects(id),provider TEXT,
 config TEXT,protected_secret TEXT,PRIMARY KEY(project_id,provider));
CREATE TABLE cloud_scans(id TEXT PRIMARY KEY,project_id TEXT REFERENCES projects(id),
 created_at TEXT,finished_at TEXT,state TEXT,selection TEXT,config TEXT,result TEXT);
PRAGMA user_version=1;
"""
TABLES = ("projects", "runs", "items", "marks", "device_links", "integrations", "cloud_scans")
STAMP = "2026-10-01T00:00:00+00:00"


def create_legacy_database(path: Path, origins: int = 3) -> None:
    """Create seven v1 families directly, without invoking ProjectStore bootstrap."""
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA)
        for index in range(origins):
            project = f"origin-{index}"
            settings = '{ "profile" : "одинаковый", "unknown": null }'
            db.execute(
                "INSERT INTO projects VALUES(?,?,?,?)", (project, "Одинаковое имя", STAMP, settings)
            )
            for run in range(3):
                run_id = f"{project}-run-{run}"
                db.execute(
                    "INSERT INTO runs VALUES(?,?,?,?,?,?)",
                    (
                        run_id,
                        project,
                        STAMP,
                        None if run == 2 else STAMP,
                        ("completed", "cancelled", "running")[run],
                        settings,
                    ),
                )
            for item in range(4):
                payload = {
                    "status": ("complete", "partial", "canceled", "error")[item],
                    "device_id": "EDGE",
                    "hostname": "EDGE",
                    "ip": "192.0.2.1",
                    "source_hash": "a" * 64,
                    "unknown": {"nullable": None},
                    "message": "Синтетический результат",
                }
                if item % 2:
                    payload["unknown"] = {}
                if item < 2:
                    # Fixed historical golden input, never a production serializer.
                    report_text = Path(__file__).parent / "golden/expected/firewall_assurance.json"
                    payload["report"] = json.loads(
                        report_text.read_text(encoding="utf-8").replace(
                            '"cisco-asa:ASA-ASSURANCE"', '"EDGE"'
                        )
                    )
                if item == 3:
                    payload["schema_version"] = "99.0.0"
                raw = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
                db.execute(
                    "INSERT INTO items VALUES(?,?,?)",
                    (f"{project}-item-{item}", f"{project}-run-{item % 3}", raw),
                )
            for mark in range(2):
                db.execute(
                    "INSERT INTO marks VALUES(?,?,?,?,?)",
                    (
                        f"{project}-run-{mark}",
                        "1565b4e4-d349-565a-ab20-641d8a81e9ad",
                        ("accepted_risk", "false_positive")[mark],
                        f"Комментарий {index}/{mark}\nвторая строка",
                        STAMP,
                    ),
                )
                db.execute(
                    "INSERT INTO device_links VALUES(?,?,?)", (project, f"source-{mark}", "EDGE")
                )
                db.execute(
                    "INSERT INTO integrations VALUES(?,?,?,?)",
                    (
                        project,
                        ("vmware", "advanced")[mark],
                        '{ "same": "config", "absentVsNull": null }',
                        f"OPAQUE-SYNTHETIC-PROTECTED-{index}-{mark}",
                    ),
                )
            for scan in range(3):
                db.execute(
                    "INSERT INTO cloud_scans VALUES(?,?,?,?,?,?,?,?)",
                    (
                        f"{project}-scan-{scan}",
                        project,
                        STAMP,
                        None if scan == 2 else STAMP,
                        ("completed", "failed", "partial")[scan],
                        '{"same":true}',
                        '{ "tenant": "same" }',
                        '{"native_id":"same-cloud-id"}',
                    ),
                )


def typed(value: object) -> tuple[str, bytes]:
    """Use exact storage class and bytes, independent of the production digest."""
    if value is None:
        return "null", b""
    if type(value) is bytes:
        return "blob", value
    if type(value) is str:
        return "text", value.encode("utf-8")
    if type(value) is int:
        return "integer", str(value).encode("ascii")
    if type(value) is float:
        return "real", struct.pack("!d", value)
    raise AssertionError(f"Unexpected SQLite value type: {type(value)}")


def direct_oracle(path: Path) -> dict[str, Counter]:
    """Capture multisets (with multiplicity) and explicit FK values in every row."""
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        return {
            table: Counter(
                tuple(typed(value) for value in row) for row in db.execute(f"SELECT * FROM {table}")
            )
            for table in TABLES
        }
