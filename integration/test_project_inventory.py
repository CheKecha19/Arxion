"""Инвентарь всего проекта сохраняет устройства вне последнего запуска."""

import sqlite3
from pathlib import Path

import pytest

from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.parsers import ParseFailure


def _session(tmp_path: Path, name: str, device_id: str) -> AnalysisSession:
    path = tmp_path / name
    path.write_text(
        "hostname INVENTORY\n"
        "access-list INSIDE extended permit ip any any\n"
        "access-group INSIDE in interface inside\n",
        encoding="utf-8",
    )
    session = analyze_file(path, device_id=device_id)
    assert isinstance(session, AnalysisSession)
    return session


def test_inventory_keeps_latest_device_snapshot_and_older_devices(tmp_path: Path) -> None:
    store = ProjectStore(tmp_path / "inventory.db")
    project = store.create_project("Сеть")
    first = store.create_run(project)
    original_a = store.record_session(first, _session(tmp_path, "first-a.cfg", "A"))
    original_b = store.record_session(first, _session(tmp_path, "first-b.cfg", "B"))
    store.finish_run(first)
    second = store.create_run(project)
    latest_a = store.record_session(second, _session(tmp_path, "latest-a.cfg", "A"))
    # Repeated imports within one run resolve to the last stored snapshot.
    latest_a = store.record_session(second, _session(tmp_path, "last-a.cfg", "A"))
    store.finish_run(second)
    third = store.create_run(project)
    store.record_error(third, tmp_path / "last-a.cfg", "Не удалось прочитать")
    unknown = tmp_path / "unsupported.txt"
    unknown.write_text("not a supported configuration", encoding="utf-8")
    failure = analyze_file(unknown)
    assert isinstance(failure, ParseFailure)
    store.record_failure(third, unknown, failure)
    store.record_cancelled(third, tmp_path / "cancelled.cfg")
    store.finish_run(third, "cancelled")

    restored = ProjectStore(store.path)
    devices = restored.list_project_devices(project)
    assert [item["report"]["device_id"] for item in devices] == ["A", "B"]
    assert [item["id"] for item in devices] == [latest_a, original_b]
    assert [item["run_id"] for item in devices] == [second, first]
    assert devices[0]["run_created_at"] == restored.get_run(second)["created_at"]
    assert devices[0]["revision"] == restored.get_run(second)["items"][-1]["revision"]
    assert devices[0]["diagnostics"] == restored.get_run(second)["items"][-1]["diagnostics"]
    assert restored.get_run(first)["items"][0]["id"] == original_a
    with sqlite3.connect(store.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1


def test_inventory_is_scoped_to_project_and_keeps_partial_snapshots(tmp_path: Path) -> None:
    store = ProjectStore(tmp_path / "inventory.db")
    project = store.create_project("Первая сеть")
    other = store.create_project("Другая сеть")
    assert store.list_project_devices(project) == []
    run = store.create_run(project)
    session = _session(tmp_path, "partial.cfg", "SAME-ID")
    coverage = session.report.parse_coverage.model_copy(
        update={"discovered_constructs": 2, "recognized_constructs": 1}
    )
    partial = session.report.model_copy(update={"parse_coverage": coverage})
    store.record_session(
        run,
        AnalysisSession(
            session.job_id,
            session.path,
            session.source,
            session.parse_result,
            session.revision,
            partial,
        ),
    )
    other_run = store.create_run(other)
    store.record_session(other_run, _session(tmp_path, "other.cfg", "SAME-ID"))
    devices = store.list_project_devices(project)
    assert len(devices) == 1
    assert devices[0]["status"] == "partial"
    assert devices[0]["run_id"] == run
    assert devices[0]["source_name"] == "partial.cfg"
    assert store.list_project_devices(other)[0]["source_name"] == "other.cfg"
    with pytest.raises(KeyError, match="Проект не найден"):
        store.list_project_devices("missing")
