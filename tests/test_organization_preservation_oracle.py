"""R2 independent preservation oracle; synthetic explicit paths only."""

import hashlib
import sqlite3
from collections import Counter
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from firewall_compliance.interfaces.desktop.organization_inspection import (
    inspect_v1_snapshot,
    inspect_workspace,
)
from firewall_compliance.interfaces.desktop.organization_workspace import (
    LegacyOrganizationWorkspace,
    WorkspaceReadError,
)
from tests.organization_oracle_fixtures import create_legacy_database, direct_oracle, typed


@pytest.mark.parametrize("origins", [0, 1, 3])
def test_snapshot_preserves_exact_typed_multisets_and_relations(tmp_path: Path, origins: int):
    path = tmp_path / "legacy.sqlite3"
    create_legacy_database(path, origins)
    expected = direct_oracle(path)
    before = path.read_bytes()

    snapshot = inspect_v1_snapshot(path)

    actual = {
        table.name: Counter(tuple(typed(value) for value in row.values) for row in table.rows)
        for table in snapshot.tables
    }
    assert actual == expected
    assert path.read_bytes() == before
    assert len(snapshot.inspection.origins) == origins
    assert snapshot.inspection.organization_id is None
    assert snapshot.inspection.chronology == "sequence_unavailable"
    assert snapshot.unsupported_item_ids == frozenset(f"origin-{i}-item-3" for i in range(origins))


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE marks SET comment='replacement' WHERE rowid=1",
        "UPDATE items SET run_id='origin-1-run-0' WHERE rowid=1",
        "UPDATE projects SET settings='{}' WHERE rowid=1",
        "UPDATE integrations SET protected_secret='different' WHERE rowid=1",
        "UPDATE runs SET finished_at='' WHERE rowid=3",
        "UPDATE device_links SET device_id='merged' WHERE rowid=1",
    ],
)
def test_oracle_detects_count_preserving_data_or_relationship_mutation(
    tmp_path: Path, mutation: str
):
    path = tmp_path / "legacy.sqlite3"
    create_legacy_database(path)
    before = direct_oracle(path)
    with sqlite3.connect(path) as db:
        db.execute(mutation)

    after = direct_oracle(path)

    assert {name: sum(rows.values()) for name, rows in before.items()} == {
        name: sum(rows.values()) for name, rows in after.items()
    }
    assert after != before


def test_missing_database_is_absent_and_does_not_bootstrap(tmp_path: Path):
    path = tmp_path / "missing" / "projects.sqlite3"

    result = inspect_workspace(path)

    assert result.phase == "absent"
    assert not path.parent.exists()


@pytest.mark.parametrize(("content", "phase"), [(b"", "unsupported"), (b"not sqlite", "invalid")])
def test_unusable_database_remains_exact_and_never_becomes_empty_ready(
    tmp_path: Path,
    content: bytes,
    phase: str,
):
    path = tmp_path / "unusable.sqlite3"
    path.write_bytes(content)

    result = inspect_workspace(path)

    assert result.phase == phase
    assert result.phase != "ready"
    assert path.read_bytes() == content


@pytest.mark.parametrize(
    ("mutation", "phase"),
    [
        ("PRAGMA user_version=99", "unsupported"),
        ("DROP TABLE marks", "invalid"),
        ("UPDATE projects SET id=NULL WHERE rowid=1", "invalid"),
        ("UPDATE integrations SET protected_secret=X'00FF' WHERE rowid=1", "invalid"),
        ("UPDATE items SET run_id='missing' WHERE rowid=1", "invalid"),
    ],
)
def test_invalid_legacy_state_is_reported_without_recovery_writes(
    tmp_path: Path,
    mutation: str,
    phase: str,
):
    path = tmp_path / "invalid.sqlite3"
    create_legacy_database(path)
    with sqlite3.connect(path) as db:
        db.execute(mutation)
    before = hashlib.sha256(path.read_bytes()).digest()

    result = inspect_workspace(path)

    assert result.phase == phase
    assert result.issues
    assert hashlib.sha256(path.read_bytes()).digest() == before


def test_exclusive_writer_is_busy_without_fallback(tmp_path: Path):
    path = tmp_path / "busy.sqlite3"
    create_legacy_database(path)
    with sqlite3.connect(path) as writer:
        writer.execute("BEGIN EXCLUSIVE")
        try:
            result = inspect_workspace(path)
        finally:
            writer.rollback()

    assert result.phase == "busy"
    assert result.issues[0].code == "STORE_BUSY"


def test_permission_failure_is_access_error_without_fallback(tmp_path: Path, monkeypatch):
    path = tmp_path / "denied.sqlite3"
    create_legacy_database(path)
    before = path.read_bytes()

    def denied(*args, **kwargs):
        error = sqlite3.OperationalError("access denied")
        error.sqlite_errorcode = sqlite3.SQLITE_CANTOPEN
        raise error

    monkeypatch.setattr(sqlite3, "connect", denied)
    result = inspect_workspace(path)

    assert result.phase == "access"
    assert result.issues[0].code == "STORE_ACCESS_DENIED"
    assert path.read_bytes() == before


def test_empty_payload_is_invalid_instead_of_silently_supported(tmp_path: Path):
    path = tmp_path / "empty-payload.sqlite3"
    create_legacy_database(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE items SET payload='{}' WHERE rowid=1")

    result = inspect_workspace(path)

    assert result.phase == "invalid"
    assert any(issue.code == "INVALID_ITEM_STATUS" for issue in result.issues)


def test_facade_keeps_all_origins_exact_history_and_composite_device_identity(tmp_path: Path):
    path = tmp_path / "facade.sqlite3"
    create_legacy_database(path)
    expected = direct_oracle(path)
    workspace = LegacyOrganizationWorkspace(path)

    origins = workspace.list_origins()
    runs = workspace.list_runs()
    scans = workspace.list_cloud_scans()
    devices = workspace.list_devices()

    assert {origin.project_id for origin in origins} == {f"origin-{i}" for i in range(3)}
    assert len(runs) == 9
    assert len(scans) == 9
    assert {(d.identity.origin_project_id, d.identity.raw_device_id) for d in devices} == {
        (f"origin-{i}", "EDGE") for i in range(3)
    }
    assert all(d.device_uid is None and d.chronology == "sequence_unavailable" for d in devices)
    actual_items = Counter()
    actual_marks = Counter()
    for run in runs:
        detail = workspace.get_run(run.run_id)
        assert detail.run == run
        for item in detail.items:
            actual_items[
                tuple(typed(v) for v in (item.item_id, run.run_id, item.payload_json))
            ] += 1
            assert item.semantic_support == (
                "unsupported" if item.item_id.endswith("-item-3") else "supported"
            )
        for mark in detail.marks:
            actual_marks[tuple(typed(v) for v in (run.run_id, *mark))] += 1
    assert actual_items == expected["items"]
    assert actual_marks == expected["marks"]
    assert (
        Counter(
            tuple(
                typed(v)
                for v in (
                    scan.scan_id,
                    scan.origin.project_id,
                    scan.created_at,
                    scan.finished_at,
                    scan.state,
                    scan.selection_json,
                    scan.config_json,
                    scan.result_json,
                )
            )
            for scan in scans
        )
        == expected["cloud_scans"]
    )
    assert direct_oracle(path) == expected


def test_failed_newer_attempt_does_not_erase_previous_usable_device(tmp_path: Path):
    path = tmp_path / "temporal.sqlite3"
    create_legacy_database(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE runs SET created_at='2099-01-01T00:00:00Z' WHERE id LIKE '%-run-2'")

    devices = LegacyOrganizationWorkspace(path).list_devices()

    assert {d.item_id for d in devices} == {f"origin-{i}-item-1" for i in range(3)}
    assert all(d.chronology == "sequence_unavailable" for d in devices)


def test_read_only_snapshot_observes_committed_wal_not_uncommitted_writer(tmp_path: Path):
    path = tmp_path / "wal.sqlite3"
    create_legacy_database(path)
    writer = sqlite3.connect(path)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("UPDATE marks SET comment='committed WAL' WHERE rowid=1")
        writer.commit()
        expected = direct_oracle(path)
        writer.execute("UPDATE marks SET comment='uncommitted' WHERE rowid=1")

        snapshot = inspect_v1_snapshot(path)

        actual = {
            table.name: Counter(tuple(typed(v) for v in row.values) for row in table.rows)
            for table in snapshot.tables
        }
        assert actual == expected
    finally:
        writer.rollback()
        writer.close()


def test_facade_failed_open_raises_instead_of_returning_empty_origins(tmp_path: Path):
    path = tmp_path / "corrupt.sqlite3"
    path.write_bytes(b"synthetic-corruption")
    workspace = LegacyOrganizationWorkspace(path)

    with pytest.raises(WorkspaceReadError) as error:
        workspace.list_origins()

    assert error.value.inspection.phase == "invalid"
    assert path.read_bytes() == b"synthetic-corruption"


def test_snapshot_stays_coherent_when_writer_commits_between_family_queries(
    tmp_path: Path, monkeypatch
):
    path = tmp_path / "writer-skew.sqlite3"
    create_legacy_database(path)
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    expected = direct_oracle(path)
    real_connect = sqlite3.connect
    commits = []

    class ConcurrentReader(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            cursor = super().execute(sql, parameters)
            if sql.startswith('SELECT rowid,* FROM "projects"') and not commits:
                writer.execute("UPDATE runs SET settings='{\"new\":true}' WHERE rowid=1")
                writer.execute("UPDATE marks SET comment='new decision' WHERE rowid=1")
                writer.commit()
                commits.append(True)
            return cursor

    def connect(*args, **kwargs):
        return real_connect(*args, **kwargs, factory=ConcurrentReader)

    monkeypatch.setattr(sqlite3, "connect", connect)
    try:
        snapshot = inspect_v1_snapshot(path)
        actual = {
            table.name: Counter(tuple(typed(v) for v in row.values) for row in table.rows)
            for table in snapshot.tables
        }
        assert commits == [True]
        assert actual == expected
    finally:
        writer.close()
    assert direct_oracle(path) != expected


def test_snapshot_dtos_and_nested_sql_rows_are_immutable(tmp_path: Path):
    path = tmp_path / "immutable.sqlite3"
    create_legacy_database(path)
    snapshot = inspect_v1_snapshot(path)

    with pytest.raises(FrozenInstanceError):
        snapshot.inspection.phase = "ready"
    with pytest.raises(FrozenInstanceError):
        snapshot.inspection.origins[0].name = "changed"
    with pytest.raises(TypeError):
        snapshot.tables[0].rows[0].values[1] = "changed"

    assert "OPAQUE-SYNTHETIC-PROTECTED" not in repr(snapshot)
