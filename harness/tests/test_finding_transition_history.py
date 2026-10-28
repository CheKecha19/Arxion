"""Synthetic SQLite status/comment history, rollback and immutable report contracts."""

import json
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from firewall_compliance.interfaces.desktop import project_store
from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.organization_backup import create_workspace_backup
from firewall_compliance.interfaces.desktop.project_store import ProjectStore


@pytest.fixture
def finding_store():
    directory = Path("artifacts/finding-transition-tests") / str(uuid4())
    directory.mkdir(parents=True)
    source = directory / "synthetic.cfg"
    source.write_text(
        "hostname SYNTHETIC-HISTORY\naccess-list OUTSIDE extended permit ip any any\n"
        "access-group OUTSIDE in interface outside\n",
        encoding="utf-8",
    )
    session = analyze_file(source)
    assert isinstance(session, AnalysisSession)
    store = ProjectStore(directory / "projects.sqlite3")
    project = store.create_project("Synthetic transitions")
    run = store.create_run(project)
    store.record_session(run, session)
    finding = next(f for check in session.report.checks for f in check.findings)
    return store, project, run, str(finding.finding_id)


def test_initial_timeline_does_not_manufacture_decisions(finding_store):
    store, project, run, finding = finding_store
    original = store.get_run(run)
    timeline = store.finding_mark_timeline(project, run, finding)
    assert timeline["baseline"]["kind"] == "original_report"
    assert timeline["baseline"]["history_started_at"] is None
    assert timeline["history_complete"] is True
    assert timeline["current"] == {"status": "new", "comment": "", "updated_at": None}
    assert timeline["events"] == []
    store.set_finding_mark(run, finding, "new")
    assert store.get_run(run) == original
    assert store.list_finding_transitions(project) == []


def test_status_and_comment_edits_are_ordered_and_repeated_save_is_noop(finding_store, monkeypatch):
    store, project, run, finding = finding_store
    monkeypatch.setattr(project_store, "_now", lambda: "2026-10-27T00:00:00+00:00")
    original_items = store.get_run(run)["items"]
    store.set_finding_mark(run, finding, "confirmed", "First comment")
    first_mark = store.get_run(run)["marks"][finding]
    store.set_finding_mark(run, finding, "confirmed", "First comment")
    assert store.get_run(run)["marks"][finding] == first_mark
    store.set_finding_mark(run, finding, "confirmed", "Edited comment")
    store.set_finding_mark(run, finding, "resolved", "Edited comment")
    events = store.list_finding_transitions(project, run, finding)
    assert len(events) == 3
    assert [event["sequence"] for event in events] == sorted(event["sequence"] for event in events)
    assert len({event["changed_at"] for event in events}) == 1
    assert [(e["previous_status"], e["new_status"]) for e in events] == [
        ("new", "confirmed"),
        ("confirmed", "confirmed"),
        ("confirmed", "resolved"),
    ]
    assert events[1]["previous_comment"] == "First comment"
    assert events[1]["new_comment"] == "Edited comment"
    assert all(
        (e["project_id"], e["run_id"], e["finding_id"]) == (project, run, finding) for e in events
    )
    assert store.get_run(run)["items"] == original_items
    reopened = ProjectStore(store.path)
    assert reopened.list_finding_transitions(project, run, finding) == events


def test_replay_reads_baseline_and_intermediate_states_without_changing_reports(finding_store):
    store, project, run, finding = finding_store
    store.set_finding_mark(run, finding, "confirmed", "First")
    store.set_finding_mark(run, finding, "resolved", "Second")
    saved = store.get_run(run)
    first_event = store.list_finding_transitions(project)[0]
    assert store.replay_finding_mark(project, run, finding, 0) == {
        "status": "new",
        "comment": "",
        "updated_at": None,
    }
    assert store.replay_finding_mark(project, run, finding, first_event["sequence"]) == {
        "status": "confirmed",
        "comment": "First",
        "updated_at": first_event["changed_at"],
    }
    assert store.replay_finding_mark(project, run, finding) == saved["marks"][finding]
    assert store.get_run(run) == saved
    assert all(
        f["status"] == "new"
        for item in saved["items"]
        for check in item["report"]["checks"]
        for f in check["findings"]
    )


def test_existing_marks_get_explicit_baseline_without_invented_prior_events(finding_store):
    store, project, run, finding = finding_store
    old_timestamp = "2026-01-01T00:00:00+00:00"
    with sqlite3.connect(store.path) as db:
        db.execute(
            "INSERT INTO marks VALUES (?,?,?,?,?)",
            (run, finding, "accepted_risk", "Legacy comment", old_timestamp),
        )
    saved = store.get_run(run)
    reopened = ProjectStore(store.path)
    timeline = reopened.finding_mark_timeline(project, run, finding)
    assert timeline["baseline"]["kind"] == "legacy_mark"
    assert timeline["baseline"]["updated_at"] == old_timestamp
    assert timeline["baseline"]["history_started_at"] > old_timestamp
    assert timeline["events"] == [] and timeline["history_complete"] is False
    assert reopened.get_run(run) == saved
    reopened.set_finding_mark(run, finding, "resolved", "New decision")
    event = reopened.list_finding_transitions(project)[0]
    assert (event["previous_status"], event["previous_comment"]) == (
        "accepted_risk",
        "Legacy comment",
    )
    assert reopened.replay_finding_mark(project, run, finding, 0) == saved["marks"][finding]
    assert (
        ProjectStore(store.path).finding_mark_timeline(project, run, finding)["baseline"]
        == (timeline["baseline"])
    )


@pytest.mark.parametrize("failing_table", ["marks", "finding_mark_transitions"])
def test_failed_write_rolls_back_mark_baseline_and_event_together(finding_store, failing_table):
    store, project, run, finding = finding_store
    before = store.get_run(run)
    with sqlite3.connect(store.path) as db:
        db.execute(
            f"CREATE TRIGGER synthetic_fail BEFORE INSERT ON {failing_table} "
            "BEGIN SELECT RAISE(ABORT, 'Synthetic failed write'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="Synthetic failed write"):
        store.set_finding_mark(run, finding, "confirmed", "Must roll back")
    assert store.get_run(run) == before
    assert store.list_finding_transitions(project) == []
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM finding_mark_baselines").fetchone()[0] == 0


@pytest.mark.parametrize("table", ["finding_mark_baselines", "finding_mark_transitions"])
@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_history_cannot_be_rewritten_or_deleted(finding_store, table, operation):
    store, _, run, finding = finding_store
    store.set_finding_mark(run, finding, "confirmed")
    query = (
        f"UPDATE {table} SET finding_id='changed'"
        if operation == "UPDATE"
        else f"DELETE FROM {table}"
    )
    with (
        sqlite3.connect(store.path) as db,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        db.execute(query)


def test_failed_transition_keeps_previous_saved_decision_and_history(finding_store):
    store, project, run, finding = finding_store
    store.set_finding_mark(run, finding, "confirmed", "First decision")
    before = store.get_run(run)
    timeline = store.finding_mark_timeline(project, run, finding)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "CREATE TRIGGER synthetic_fail BEFORE INSERT ON finding_mark_transitions "
            "BEGIN SELECT RAISE(ABORT, 'Synthetic failed write'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="Synthetic failed write"):
        store.set_finding_mark(run, finding, "resolved", "Must roll back")
    assert store.get_run(run) == before
    assert store.finding_mark_timeline(project, run, finding) == timeline


def test_history_reads_enforce_project_and_run_isolation(finding_store):
    store, project, run, finding = finding_store
    other = store.create_project("Other synthetic project")
    other_run = store.create_run(other)
    with sqlite3.connect(store.path) as db:
        payload = db.execute("SELECT payload FROM items WHERE run_id=?", (run,)).fetchone()[0]
        db.execute("INSERT INTO items VALUES (?,?,?)", (str(uuid4()), other_run, payload))
    store.set_finding_mark(run, finding, "confirmed", "Project one")
    store.set_finding_mark(other_run, finding, "resolved", "Project two")
    assert [
        e["new_comment"] for e in store.list_finding_transitions(other, finding_id=finding)
    ] == ["Project two"]
    with pytest.raises(KeyError):
        store.list_finding_transitions(other, run)
    with pytest.raises(KeyError):
        store.finding_mark_timeline(other, run, finding)
    with pytest.raises(KeyError):
        store.replay_finding_mark(other, run, finding)
    assert len(store.list_finding_transitions(project)) == 1


def test_invalid_decisions_do_not_change_history(finding_store):
    store, project, run, finding = finding_store
    with pytest.raises(ValueError):
        store.set_finding_mark(run, finding, "not-a-status")
    with pytest.raises(KeyError):
        store.set_finding_mark(run, "another-finding", "confirmed")
    with pytest.raises(ValueError):
        store.set_finding_mark(run, finding, "confirmed", "Invalid\0comment")
    with pytest.raises(ValueError):
        store.replay_finding_mark(project, run, finding, -1)
    assert store.list_finding_transitions(project) == []


def test_backup_and_registry_preserve_append_only_history_and_original_results(finding_store):
    store, project, run, finding = finding_store
    resource = store.resource_registry.add_manual(project, {"name": "Synthetic device"})
    store.set_finding_mark(run, finding, "confirmed", "Saved decision")
    before = store.finding_mark_timeline(project, run, finding)
    original = json.dumps(store.get_run(run), sort_keys=True)
    backup_path = store.path.with_name("backup.sqlite3")
    create_workspace_backup(store.path, backup_path)
    restored = ProjectStore(backup_path)
    assert restored.finding_mark_timeline(project, run, finding) == before
    assert json.dumps(restored.get_run(run), sort_keys=True) == original
    assert restored.resource_registry.list_resources(project)[0]["id"] == resource
    with sqlite3.connect(backup_path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
