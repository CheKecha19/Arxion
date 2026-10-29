"""SQLite preservation and project boundaries for immutable mixed analysis envelopes."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest

from firewall_compliance.analysis.route_selection import select_route
from firewall_compliance.application.analysis_result import (
    AnalysisResult,
    AttemptComponent,
    ComponentLimitation,
    PolicyAnalysisOptions,
    PolicyComponent,
    RouteComponent,
    replay_policy,
    source_manifest,
)
from firewall_compliance.domain.reachability import ReachabilityQuery
from firewall_compliance.interfaces.desktop.organization_backup import create_workspace_backup
from firewall_compliance.interfaces.desktop.organization_restore import _copy_forensic_file
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from tests.regression.test_policy_exposure import AT, context, rule


def mixed_result(**changes):
    revision = context(rule()).revision
    options = PolicyAnalysisOptions(check_ids=("FW-ANY-ANY",))
    policy = PolicyComponent(
        component_id="policy",
        revision=revision,
        options=options,
        result=replay_policy(revision, options, AT),
    )
    query = ReachabilityQuery(
        revision_id=revision.revision_id,
        device_id=revision.device.device_id,
        ingress_interface_id="inside",
        source_ip="198.51.100.1",
        destination_ip="192.0.2.1",
        protocol="tcp",
        destination_port=23,
    )
    route = RouteComponent(
        component_id="route", revision=revision, query=query, result=select_route(revision, query)
    )
    payload = {
        "application_version": "0.3.0",
        "started_at": AT,
        "finished_at": AT + timedelta(seconds=1),
        "sources": source_manifest((revision,)),
        "components": (policy, route),
    }
    payload.update(changes)
    return AnalysisResult(**payload)


@pytest.fixture
def store():
    root = Path("artifacts/analysis-result-storage-tests") / str(uuid4())
    root.mkdir(parents=True)
    return ProjectStore(root / "projects.sqlite3")


def all_saved_rows(store):
    with store._connect() as db:
        return db.execute("SELECT * FROM analysis_results ORDER BY rowid").fetchall()


def test_mixed_snapshot_reopens_with_compact_metadata_without_creating_run(store):
    project = store.create_project("Synthetic mixed result")
    value = mixed_result(project_reference=project)
    original = value.model_dump(mode="json")
    identifier = store.save_analysis_result(project, value)
    reopened = ProjectStore(store.path)
    assert reopened.get_analysis_result(project, identifier).model_dump(mode="json") == original
    assert not reopened.list_runs(project)
    metadata = reopened.list_analysis_results(project)
    assert len(metadata) == 1
    assert metadata[0]["component_kinds"] == ["policy", "route"]
    assert metadata[0]["state"] == value.state
    assert metadata[0]["summary"] == value.summary.model_dump(mode="json")
    assert "sources" not in metadata[0] and "components" not in metadata[0]
    assert metadata[0]["project_id"] == project and metadata[0]["analysis_id"] == identifier
    with reopened._connect() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1


def test_identical_save_is_noop_and_conflicting_payload_never_overwrites(store):
    project = store.create_project("Synthetic idempotence")
    value = mixed_result()
    identifier = store.save_analysis_result(project, value)
    before = tuple(all_saved_rows(store)[0])
    assert store.save_analysis_result(project, value) == identifier
    assert tuple(all_saved_rows(store)[0]) == before
    changed = value.model_copy(update={"application_version": "different"})
    with pytest.raises(ValueError, match="different saved envelope"):
        store.save_analysis_result(project, changed)
    assert tuple(all_saved_rows(store)[0]) == before


def test_concurrent_identical_saves_are_idempotent(store):
    project = store.create_project("Synthetic concurrent save")
    value = mixed_result()
    with ThreadPoolExecutor(max_workers=4) as workers:
        saved = list(workers.map(lambda _: store.save_analysis_result(project, value), range(8)))
    assert saved == [str(value.analysis_id)] * 8
    assert len(all_saved_rows(store)) == 1
    assert store.get_analysis_result(project, saved[0]) == value


def test_scoped_read_and_global_identity_reject_cross_project_reuse(store):
    first, second = store.create_project("First"), store.create_project("Second")
    value = mixed_result()
    identifier = store.save_analysis_result(first, value)
    with pytest.raises(KeyError, match="this project"):
        store.get_analysis_result(second, identifier)
    assert store.list_analysis_results(second) == []
    with pytest.raises(ValueError, match="different saved envelope"):
        store.save_analysis_result(second, value)
    assert store.get_analysis_result(first, identifier) == value


def test_project_and_run_references_must_match_without_changing_existing_runs(store):
    first, second = store.create_project("First"), store.create_project("Second")
    run = store.create_run(first)
    before = store.get_run(run)
    for value in (
        mixed_result(project_reference=second),
        mixed_result(run_reference=run, project_reference=second),
        mixed_result(run_reference=str(uuid4())),
    ):
        with pytest.raises(ValueError):
            store.save_analysis_result(first, value)
    with pytest.raises(ValueError, match="this project"):
        store.save_analysis_result(second, mixed_result(run_reference=run))
    saved = mixed_result(project_reference=first, run_reference=run)
    identifier = store.save_analysis_result(first, saved)
    assert store.get_analysis_result(first, identifier) == saved
    assert store.get_run(run) == before


def test_unknown_project_is_rejected_without_orphan_envelope(store):
    with pytest.raises(KeyError, match="Unknown project"):
        store.save_analysis_result(str(uuid4()), mixed_result())
    assert not all_saved_rows(store)


def test_save_revalidates_constructed_summary_before_writing(store):
    project = store.create_project("Synthetic untrusted instance")
    value = mixed_result()
    invalid = AnalysisResult.model_construct(**{**value.__dict__, "state": "complete"})
    with pytest.raises(ValueError):
        store.save_analysis_result(project, invalid)
    assert not all_saved_rows(store)


def test_failed_and_cancelled_attempts_remain_explicit_not_policy_runs(store):
    project = store.create_project("Synthetic unsuccessful operations")
    attempts = tuple(
        AttemptComponent(
            component_id=state,
            family="network",
            operation="synthetic route query",
            state=state,
            diagnostic=ComponentLimitation(code="SYNTHETIC_STOP", message="Synthetic failure"),
        )
        for state in ("failed", "cancelled", "not_executed")
    )
    value = mixed_result(components=attempts, sources=())
    identifier = store.save_analysis_result(project, value)
    loaded = store.get_analysis_result(project, identifier)
    assert loaded.state != "complete"
    assert [component.state for component in loaded.components] == [
        "failed",
        "cancelled",
        "not_executed",
    ]
    assert not store.list_runs(project)


@pytest.mark.parametrize(
    "kind", ["result", "source", "query", "options", "identity", "project", "version", "summary"]
)
def test_reads_revalidate_tampered_payload_even_if_checksum_is_recomputed(store, kind):
    project = store.create_project("Synthetic tamper")
    value = mixed_result()
    identifier = store.save_analysis_result(project, value)
    raw = value.model_dump(mode="json")
    if kind == "result":
        raw["components"][0]["result"]["device_id"] = "another-device"
    elif kind == "source":
        raw["sources"][0]["content_sha256"] = "f" * 64
    elif kind == "query":
        raw["components"][1]["query"]["device_id"] = "another-device"
    elif kind == "options":
        raw["components"][0]["options"]["require_logging"] = False
    elif kind == "identity":
        raw["analysis_id"] = str(uuid4())
    elif kind == "version":
        raw["schema_version"] = "99.0.0"
    elif kind == "summary":
        raw["summary"]["findings"] += 1
    else:
        raw["project_reference"] = str(uuid4())
    payload = json.dumps(raw, ensure_ascii=False)
    with store._connect() as db:
        db.execute("DROP TRIGGER analysis_results_no_update")
        db.execute(
            "UPDATE analysis_results SET payload=?,payload_sha256=? WHERE analysis_id=?",
            (payload, sha256(payload.encode("utf-8")).hexdigest(), identifier),
        )
    with pytest.raises(ValueError):
        store.get_analysis_result(project, identifier)
    with pytest.raises(ValueError):
        store.list_analysis_results(project)


def test_bad_checksum_is_not_accepted_as_an_unchanged_result(store):
    project = store.create_project("Synthetic checksum")
    value = mixed_result()
    identifier = store.save_analysis_result(project, value)
    with store._connect() as db:
        db.execute("DROP TRIGGER analysis_results_no_update")
        db.execute(
            "UPDATE analysis_results SET payload_sha256='corrupt' WHERE analysis_id=?",
            (identifier,),
        )
    with pytest.raises(ValueError, match="checksum"):
        store.get_analysis_result(project, identifier)
    with pytest.raises(ValueError, match="checksum"):
        store.save_analysis_result(project, value)


def test_appended_envelopes_cannot_be_updated_or_deleted_by_normal_connection(store):
    project = store.create_project("Synthetic immutability")
    identifier = store.save_analysis_result(project, mixed_result())
    with pytest.raises(sqlite3.IntegrityError, match="immutable"), store._connect() as db:
        db.execute(
            "UPDATE analysis_results SET created_at='changed' WHERE analysis_id=?", (identifier,)
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"), store._connect() as db:
        db.execute("DELETE FROM analysis_results WHERE analysis_id=?", (identifier,))
    assert len(all_saved_rows(store)) == 1


def test_failed_insert_rolls_back_without_changing_other_project_tables(store):
    project = store.create_project("Synthetic rollback")
    run = store.create_run(project)
    before = store.get_run(run)
    with store._connect() as db:
        db.execute(
            "CREATE TRIGGER synthetic_refusal BEFORE INSERT ON analysis_results "
            "BEGIN SELECT RAISE(ABORT, 'synthetic refusal'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="synthetic refusal"):
        store.save_analysis_result(project, mixed_result(run_reference=run))
    assert store.get_run(run) == before
    assert store.list_analysis_results(project) == []


def test_public_backup_and_forensic_restore_preserve_full_envelopes(store):
    project = store.create_project("Synthetic backup")
    value = mixed_result(project_reference=project)
    identifier = store.save_analysis_result(project, value)
    baseline = [tuple(row) for row in all_saved_rows(store)]
    backup_path = store.path.with_name("backup.sqlite3")
    create_workspace_backup(store.path, backup_path)
    restored_path = store.path.with_name("restored.sqlite3")
    _copy_forensic_file(backup_path, restored_path)
    reopened = ProjectStore(restored_path)
    assert [tuple(row) for row in all_saved_rows(reopened)] == baseline
    assert reopened.get_analysis_result(project, identifier) == value
    assert reopened.list_analysis_results(project) == store.list_analysis_results(project)
