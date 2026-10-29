"""Перезапуск проекта, проверка источника и автономный экспорт общего отчёта."""

import json
import sqlite3
from pathlib import Path

import pytest

from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.batch_reports import (
    build_batch_report,
    compare_run_findings,
    export_batch_html,
    export_batch_json,
)
from firewall_compliance.interfaces.desktop.project_store import ProjectStore, SourceMismatchError
from firewall_compliance.parsers import ParseFailure


@pytest.fixture
def analyzed(tmp_path: Path) -> AnalysisSession:
    path = tmp_path / "device.cfg"
    path.write_text(
        "hostname TEST-DEVICE\n"
        "! private configuration line must not persist\n"
        "access-list OUTSIDE extended permit ip any any\n"
        "access-group OUTSIDE in interface outside\n",
        encoding="utf-8",
    )
    session = analyze_file(path)
    assert isinstance(session, AnalysisSession)
    assert any(check.findings for check in session.report.checks)
    return session


def test_durable_original_results_marks_and_no_full_source(
    tmp_path: Path, analyzed: AnalysisSession
) -> None:
    store = ProjectStore(tmp_path / "projects.db")
    project_id = store.create_project("Демо")
    run_id = store.create_run(project_id)
    item_id = store.record_session(run_id, analyzed)
    finding = next(f for c in analyzed.report.checks for f in c.findings)
    store.set_finding_mark(run_id, str(finding.finding_id), "accepted_risk", "Согласовано")
    store.finish_run(run_id)
    restored = ProjectStore(store.path).get_run(run_id)
    assert restored["state"] == "completed"
    assert restored["items"][0]["id"] == item_id
    assert FirewallAssuranceResult.model_validate(restored["items"][0]["report"]) == analyzed.report
    assert restored["marks"][str(finding.finding_id)]["status"] == "accepted_risk"
    assert str(finding.status) == "new"
    assert b"private configuration line" not in store.path.read_bytes()
    assert b'"content"' not in store.path.read_bytes()
    assert restored["items"][0]["excerpts"]


def test_attach_original_hash_and_reject_changed_source(
    tmp_path: Path, analyzed: AnalysisSession
) -> None:
    store = ProjectStore(tmp_path / "projects.db")
    run_id = store.create_run(store.create_project("Проект"))
    item_id = store.record_session(run_id, analyzed)
    renamed = tmp_path / "renamed.cfg"
    renamed.write_bytes(analyzed.source.content)
    session = store.attach_source(item_id, renamed)
    assert session.report == analyzed.report
    assert session.revision == analyzed.revision
    assert session.source.source_name == analyzed.source.source_name
    renamed.write_bytes(analyzed.source.content + b"changed")
    with pytest.raises(SourceMismatchError, match="SHA-256"):
        store.attach_source(item_id, renamed)
    with pytest.raises(FileNotFoundError):
        store.attach_source(item_id, tmp_path / "missing.cfg")
    assert store.list_runs(store.get_run(run_id)["project_id"])[0]["item_count"] == 1
    assert store.list_runs(store.get_run(run_id)["project_id"])[0]["finding_count"] > 0


def test_batch_json_contract_html_escape_and_fragment_toggle(
    tmp_path: Path, analyzed: AnalysisSession
) -> None:
    store = ProjectStore(tmp_path / "projects.db")
    run_id = store.create_run(store.create_project("<script>alert('x')</script>"))
    store.record_session(run_id, analyzed)
    finding = next(f for c in analyzed.report.checks for f in c.findings)
    store.set_finding_mark(run_id, str(finding.finding_id), "confirmed", "<img src=x>")
    store.finish_run(run_id)
    json_path, html_path = tmp_path / "report.json", tmp_path / "report.html"
    export_batch_json(store, run_id, json_path)
    export_batch_html(store, run_id, html_path)
    package = json.loads(json_path.read_text(encoding="utf-8"))
    assert package["schema_version"] == "1.0.0"
    assert FirewallAssuranceResult.model_validate(package["items"][0]["result"]) == analyzed.report
    rendered = html_path.read_text(encoding="utf-8")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "&lt;img src=x&gt;" in rendered
    assert "@media print" in rendered
    assert 'src="http' not in rendered
    assert "path" not in package["items"][0]
    assert not build_batch_report(store, run_id, include_fragments=False)["items"][0]["excerpts"]


def test_failures_errors_and_history_do_not_transfer_marks(
    tmp_path: Path, analyzed: AnalysisSession
) -> None:
    store = ProjectStore(tmp_path / "projects.db")
    project_id = store.create_project("Демо")
    first = store.create_run(project_id)
    store.record_session(first, analyzed)
    finding = next(f for c in analyzed.report.checks for f in c.findings)
    store.set_finding_mark(first, str(finding.finding_id), "resolved")
    store.finish_run(first)
    store.update_settings(project_id, {"require_logging": False})
    second = store.create_run(project_id)
    bad_path = tmp_path / "unsupported.txt"
    bad_path.write_text("unsupported format", encoding="utf-8")
    failure = analyze_file(bad_path)
    assert isinstance(failure, ParseFailure)
    store.record_failure(second, bad_path, failure)
    store.record_error(second, tmp_path / "missing.cfg", "Файл недоступен")
    store.finish_run(second, "cancelled")
    package = build_batch_report(store, second)
    assert package["summary"]["imports"] == {"unsupported": 1, "error": 1}
    assert not package["user_decisions"]
    comparison = compare_run_findings(store, first, second)
    assert comparison["not_observed"]
    assert "resolved" not in comparison
    assert store.get_run(first)["settings"]["require_logging"] is True
    assert store.get_run(second)["settings"]["require_logging"] is False


def test_confirmed_device_mapping_and_invalid_mark(
    tmp_path: Path, analyzed: AnalysisSession
) -> None:
    store = ProjectStore(tmp_path / "projects.db")
    project_id = store.create_project("Демо")
    store.confirm_device(project_id, "Switch.CFG", "switch-01")
    assert store.suggest_device(project_id, "switch.cfg") == "switch-01"
    assert store.suggest_device(project_id, "other.cfg") is None
    run_id = store.create_run(project_id)
    store.record_session(run_id, analyzed)
    with pytest.raises(KeyError):
        store.set_finding_mark(run_id, "not-a-finding", "confirmed")
    with pytest.raises(ValueError):
        store.set_finding_mark(run_id, "not-a-finding", "bad-status")


def test_cancelled_inventory_and_newer_database_guard(tmp_path: Path) -> None:
    store = ProjectStore(tmp_path / "projects.db")
    run_id = store.create_run(store.create_project("Демо"))
    store.record_cancelled(run_id, tmp_path / "pending.cfg")
    store.finish_run(run_id, "cancelled")
    assert build_batch_report(store, run_id)["summary"]["imports"] == {"canceled": 1}
    with sqlite3.connect(store.path) as db:
        db.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="новой версией"):
        ProjectStore(store.path)
    with sqlite3.connect(store.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 99
