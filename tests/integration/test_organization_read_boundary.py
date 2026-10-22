"""Real SQLite preservation and identity checks for the R2 read-only slice."""

import hashlib
import json
import sqlite3
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.organization_inspection import (
    inspect_v1_snapshot,
    inspect_workspace,
)
from firewall_compliance.interfaces.desktop.organization_workspace import (
    LegacyOrganizationWorkspace,
    WorkspaceReadError,
)
from firewall_compliance.interfaces.desktop.project_store import ProjectStore


def _store(tmp_path: Path) -> ProjectStore:
    return ProjectStore(tmp_path / "synthetic.sqlite3")


def _analysis(tmp_path: Path) -> AnalysisSession:
    path = tmp_path / "same.cfg"
    path.write_text(
        "hostname SAME\naccess-list INSIDE extended permit ip any any\n"
        "access-group INSIDE in interface inside\n",
        encoding="utf-8",
    )
    session = analyze_file(path, device_id="SAME")
    assert isinstance(session, AnalysisSession)
    return session


def _bytes_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_absent_is_not_bootstrapped(tmp_path: Path) -> None:
    path = tmp_path / "does-not-exist" / "store.sqlite3"
    assert inspect_workspace(path).phase == "absent"
    assert not path.parent.exists()
    with pytest.raises(WorkspaceReadError):
        LegacyOrganizationWorkspace(path).list_origins()
    assert not path.parent.exists()


def test_all_origins_same_name_hash_and_device_remain_separate(tmp_path: Path) -> None:
    store = _store(tmp_path)
    empty = store.create_project("Empty")
    session = _analysis(tmp_path)
    expected: set[tuple[str, str, str]] = set()
    for name in ("First", "Second"):
        project = store.create_project(name)
        run = store.create_run(project)
        item = store.record_session(run, session)
        expected.add((project, run, item))
        store.finish_run(run)
        with sqlite3.connect(store.path) as db:
            db.execute(
                "INSERT INTO integrations VALUES (?,?,?,?)",
                (project, "vmware", '{ "site": "same" }', "opaque encrypted bytes " + name),
            )
    before = _bytes_hash(store.path)
    facade = LegacyOrganizationWorkspace(store.path)
    assert facade.inspect().phase == "legacy"
    assert {o.project_id for o in facade.list_origins()} == {empty, *(x[0] for x in expected)}
    assert len(facade.list_runs()) == 2
    devices = facade.list_devices()
    assert {(d.identity.origin_project_id, d.run_id, d.item_id) for d in devices} == expected
    assert {d.identity.raw_device_id for d in devices} == {"SAME"}
    assert all(d.device_uid is None and d.chronology == "sequence_unavailable" for d in devices)
    with pytest.raises(FrozenInstanceError):
        devices[0].item_id = "changed"  # type: ignore[misc]
    assert before == _bytes_hash(store.path)
    assert "opaque encrypted bytes" not in repr(inspect_v1_snapshot(store.path))


def test_failed_newer_attempt_does_not_replace_configuration(tmp_path: Path) -> None:
    store = _store(tmp_path)
    project = store.create_project("One")
    first = store.create_run(project)
    item = store.record_session(first, _analysis(tmp_path))
    store.finish_run(first)
    second = store.create_run(project)
    store.record_error(second, tmp_path / "same.cfg", "Cannot read")
    store.finish_run(second, "interrupted")
    facade = LegacyOrganizationWorkspace(store.path)
    assert facade.list_devices()[0].item_id == item
    assert facade.list_runs()[0].run_id == second


@pytest.mark.parametrize("version_field", ["report", "revision", "envelope"])
def test_future_payload_opaque_before_domain_parse(tmp_path: Path, version_field: str) -> None:
    store = _store(tmp_path)
    project = store.create_project("One")
    run = store.create_run(project)
    item = store.record_session(run, _analysis(tmp_path))
    with sqlite3.connect(store.path) as db:
        payload = json.loads(db.execute("SELECT payload FROM items").fetchone()[0])
        target = payload if version_field == "envelope" else payload[version_field]
        target["schema_version"] = "99.0.0"
        exact = json.dumps(payload, ensure_ascii=False, indent=3)
        db.execute("UPDATE items SET payload=?", (exact,))
    before = _bytes_hash(store.path)
    facade = LegacyOrganizationWorkspace(store.path)
    assert facade.inspect().phase == "unsupported"
    assert facade.list_devices() == ()
    saved = facade.get_run(run).items[0]
    assert saved.item_id == item and saved.payload_json == exact
    assert saved.semantic_support == "unsupported"
    assert before == _bytes_hash(store.path)


@pytest.mark.parametrize("bad_payload", ['{"status":[]}', "{}", '{"a":1,"a":2}', "[]", "{"])
def test_malformed_payload_is_not_dropped(tmp_path: Path, bad_payload: str) -> None:
    store = _store(tmp_path)
    project = store.create_project("One")
    run = store.create_run(project)
    with sqlite3.connect(store.path) as db:
        db.execute("INSERT INTO items VALUES (?,?,?)", ("item", run, bad_payload))
    before = _bytes_hash(store.path)
    snapshot = inspect_v1_snapshot(store.path)
    assert snapshot.inspection.phase == "invalid"
    assert snapshot.inspection.issues
    assert next(t for t in snapshot.tables if t.name == "items").rows[0].values[2] == bad_payload
    with pytest.raises(WorkspaceReadError):
        LegacyOrganizationWorkspace(store.path).list_devices()
    assert before == _bytes_hash(store.path)


@pytest.mark.parametrize(
    "mutation,code",
    [
        (
            "INSERT INTO projects VALUES(NULL,'n','2026-01-01T00:00:00+00:00','{}')",
            "INVALID_STORAGE_TYPE",
        ),
        ("INSERT INTO integrations VALUES('ghost','p','{}',X'80FF')", "INVALID_STORAGE_TYPE"),
        (
            "INSERT INTO runs VALUES('r','ghost','2026-01-01T00:00:00+00:00',NULL,'running','{}')",
            "BROKEN_RELATION",
        ),
    ],
)
def test_sqlite_weak_typing_and_relations_rejected(
    tmp_path: Path, mutation: str, code: str
) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.path) as db:
        db.execute(mutation)
    before = _bytes_hash(store.path)
    result = inspect_workspace(store.path)
    assert result.phase == "invalid"
    assert code in {issue.code for issue in result.issues}
    assert before == _bytes_hash(store.path)


def test_wal_committed_frames_are_visible_without_checkpoint(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.path) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "INSERT INTO projects VALUES(?,?,?,?)",
            ("committed-wal", "WAL", "2026-01-01T00:00:00+00:00", "{}"),
        )
        writer.commit()
        assert Path(str(store.path) + "-wal").stat().st_size > 0
        before = _bytes_hash(store.path)
        assert inspect_workspace(store.path).origins[0].project_id == "committed-wal"
        assert before == _bytes_hash(store.path)


def test_newer_corrupt_and_empty_unversioned_are_distinct(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.path) as db:
        db.execute("PRAGMA user_version=999")
    before = _bytes_hash(store.path)
    assert inspect_workspace(store.path).phase == "unsupported"
    assert before == _bytes_hash(store.path)
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not sqlite")
    assert inspect_workspace(corrupt).phase == "invalid"
    zero = tmp_path / "zero.db"
    zero.touch()
    assert inspect_workspace(zero).phase == "unsupported"
    assert zero.stat().st_size == 0


def test_busy_is_not_misreported_as_invalid(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.path) as writer:
        writer.execute("BEGIN EXCLUSIVE")
        assert inspect_workspace(store.path).phase == "busy"
        writer.rollback()


@pytest.mark.parametrize("component", ["parse_result", "revision"])
def test_known_present_component_validates_without_report(tmp_path: Path, component: str) -> None:
    store = _store(tmp_path)
    project = store.create_project("One")
    run = store.create_run(project)
    payload = {"status": "error", "report": None, component: {}}
    if component == "revision":
        payload[component] = {"schema_version": "2.0.0"}
    exact = json.dumps(payload, indent=2)
    with sqlite3.connect(store.path) as db:
        db.execute("INSERT INTO items VALUES(?,?,?)", ("malformed", run, exact))
    before = _bytes_hash(store.path)
    result = inspect_workspace(store.path)
    assert result.phase == "invalid"
    assert any(i.code == "INVALID_DOMAIN_PAYLOAD" and i.detail == component for i in result.issues)
    assert before == _bytes_hash(store.path)


@pytest.mark.parametrize("fact", ["device_id", "content_sha256", "source_name", "parser_version"])
def test_same_configuration_uuid_does_not_prove_same_snapshot(tmp_path: Path, fact: str) -> None:
    store = _store(tmp_path)
    project = store.create_project("One")
    run = store.create_run(project)
    store.record_session(run, _analysis(tmp_path))
    with sqlite3.connect(store.path) as db:
        payload = json.loads(db.execute("SELECT payload FROM items").fetchone()[0])
        original_uuid = payload["parse_result"]["configuration"]["configuration_id"]
        payload["parse_result"]["configuration"][fact] = (
            "b" * 64 if fact == "content_sha256" else "OTHER"
        )
        assert payload["parse_result"]["configuration"]["configuration_id"] == original_uuid
        db.execute("UPDATE items SET payload=?", (json.dumps(payload),))
    before = _bytes_hash(store.path)
    result = inspect_workspace(store.path)
    assert result.phase == "invalid"
    assert "ITEM_PARSE_RESULT_MISMATCH" in {i.code for i in result.issues}
    assert before == _bytes_hash(store.path)


def test_parse_fact_mismatch_without_report_is_still_invalid(tmp_path: Path) -> None:
    store = _store(tmp_path)
    project = store.create_project("One")
    run = store.create_run(project)
    store.record_session(run, _analysis(tmp_path))
    with sqlite3.connect(store.path) as db:
        payload = json.loads(db.execute("SELECT payload FROM items").fetchone()[0])
        payload["report"] = None
        payload["status"] = "error"
        payload["parse_result"]["configuration"]["device_id"] = "OTHER"
        db.execute("UPDATE items SET payload=?", (json.dumps(payload),))
    assert inspect_workspace(store.path).phase == "invalid"


def test_unknown_sibling_does_not_hide_known_malformed_component(tmp_path: Path) -> None:
    store = _store(tmp_path)
    project = store.create_project("One")
    run = store.create_run(project)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "INSERT INTO items VALUES(?,?,?)",
            (
                "mixed",
                run,
                json.dumps(
                    {
                        "status": "error",
                        "report": None,
                        "parse_result": {},
                        "revision": {"schema_version": "99.0.0"},
                    }
                ),
            ),
        )
    result = inspect_workspace(store.path)
    assert result.phase == "invalid"
    assert {"UNSUPPORTED_PAYLOAD_VERSION", "INVALID_DOMAIN_PAYLOAD"} <= {
        issue.code for issue in result.issues
    }


def test_future_envelope_is_not_interpreted_with_current_child_semantics(tmp_path: Path) -> None:
    store = _store(tmp_path)
    project = store.create_project("One")
    run = store.create_run(project)
    raw = '{"schema_version":"99.0.0","parse_result":{},"report":null}'
    with sqlite3.connect(store.path) as db:
        db.execute("INSERT INTO items VALUES(?,?,?)", ("future-envelope", run, raw))
    result = inspect_workspace(store.path)
    assert result.phase == "unsupported"
    assert not any(issue.code == "INVALID_DOMAIN_PAYLOAD" for issue in result.issues)
    assert LegacyOrganizationWorkspace(store.path).get_run(run).items[0].payload_json == raw
