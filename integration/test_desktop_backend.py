"""Проверки согласованности desktop orchestration на синтетических документах."""

import json
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.interfaces.desktop.backend import (
    AnalysisSession,
    analyze_file,
    compare_sessions,
    diagnostic_lines,
    export_report,
    reanalyze_session,
    source_preview,
    view_workspace,
)
from firewall_compliance.parsers import ParseFailure

FIXTURE = Path("tests/fixtures/assurance/policy_quality.cfg")


def _session() -> AnalysisSession:
    result = analyze_file(FIXTURE)
    assert isinstance(result, AnalysisSession)
    return result


def test_real_analysis_preserves_all_linked_results() -> None:
    job_id = uuid4()
    result = analyze_file(FIXTURE, job_id=job_id)
    assert isinstance(result, AnalysisSession)
    assert result.job_id == job_id
    assert result.report.schema_version == "1.0.0"
    assert result.report.parser_version == "0.2.0"
    assert len(result.report.checks) == 7
    findings = [f for c in result.report.checks for f in c.findings]
    assert len(findings) == 14
    assert result.report.configuration_id == result.parse_result.configuration.configuration_id
    assert result.report.revision_id == result.revision.revision_id
    assert result.report.device_id == result.revision.device.device_id
    assert all(f.revision_id == result.revision.revision_id for f in findings)
    assert all(
        r.configuration_id == result.report.configuration_id for r in result.parse_result.rules
    )
    assert result.revision.interfaces_status == DataStatus.UNKNOWN
    assert result.revision.routes_status == DataStatus.UNKNOWN
    assert result.revision.observed_at is None
    workspace = view_workspace((result,))
    assert len(workspace.rules) == len(result.parse_result.rules)
    assert len(workspace.findings) == len(findings)
    for view, finding in zip(workspace.findings, findings, strict=True):
        evidence = json.loads(view.evidence)
        assert evidence["evidence"] == finding.evidence.model_dump(mode="json")
        assert evidence["confidence"] == finding.confidence
        assert evidence["status"] == finding.status.value
    assert "Ноль находок" in diagnostic_lines(result)[-1]


def test_export_roundtrip_preserves_backend_contract(tmp_path: Path) -> None:
    session = _session()
    output = tmp_path / "report.json"
    export_report(session, output)
    reloaded = FirewallAssuranceResult.model_validate_json(output.read_text(encoding="utf-8"))
    assert reloaded == session.report
    assert '"content"' not in output.read_text(encoding="utf-8")


def test_unsupported_and_read_failure_have_no_demo_results(tmp_path: Path) -> None:
    source = tmp_path / "juniper.conf"
    source.write_text("set system host-name test\nset interfaces ge-0/0/0 unit 0\n")
    result = analyze_file(source)
    assert isinstance(result, ParseFailure)
    assert result.errors[0].code == "PARSER_NOT_FOUND"
    assert view_workspace(()).findings == ()
    with pytest.raises(OSError):
        analyze_file(tmp_path / "missing.cfg")


def test_preview_uses_captured_bytes_and_validates_identity(tmp_path: Path) -> None:
    source = tmp_path / "policy.cfg"
    source.write_bytes(FIXTURE.read_bytes())
    session = analyze_file(source)
    assert isinstance(session, AnalysisSession)
    location = session.parse_result.rules[0].source_location
    preview = source_preview(session, location)
    assert "access-list" in preview
    source.write_text("changed after analysis")
    assert source_preview(session, location) == preview
    with pytest.raises(ValueError):
        source_preview(session, SourceLocation(source_name="other.cfg", line_start=1))
    with pytest.raises(ValueError):
        source_preview(session, SourceLocation(source_name=source.name, line_start=100000))
    with pytest.raises(ValueError):
        source_preview(session, SourceLocation(source_name=source.name, object_id="test"))
    corrupted = replace(session, source=session.source.model_copy(update={"content": b"wrong"}))
    with pytest.raises(ValueError):
        source_preview(corrupted, location)


def test_explicit_device_identity_allows_revision_comparison() -> None:
    before = analyze_file(FIXTURE, device_id="firewall-hq")
    after = analyze_file(FIXTURE, device_id="firewall-hq")
    assert isinstance(before, AnalysisSession)
    assert isinstance(after, AnalysisSession)
    assert before.report.device_id == before.parse_result.configuration.device_id == "firewall-hq"
    assert before.revision.revision_id != after.revision.revision_id
    result = compare_sessions(before, after)
    assert result.device_id == "firewall-hq"
    other = analyze_file(FIXTURE, device_id="other-device")
    assert isinstance(other, AnalysisSession)
    with pytest.raises(ValueError):
        compare_sessions(before, other)


def test_zero_findings_still_displays_check_statuses(tmp_path: Path) -> None:
    source = tmp_path / "empty.cfg"
    source.write_text(
        "hostname ASA-EMPTY\naccess-list OUTSIDE remark Explicit default guard\n"
        "access-list OUTSIDE extended deny ip any any log\n"
        "access-group OUTSIDE in interface outside\n",
        encoding="utf-8",
    )
    result = analyze_file(source)
    assert isinstance(result, AnalysisSession)
    assert all(not c.findings for c in result.report.checks)
    assert view_workspace((result,)).findings == ()
    assert len([line for line in diagnostic_lines(result) if "находок 0" in line]) == 7


def test_reanalysis_preserves_snapshot_without_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session()

    def forbid_read(*args: object, **kwargs: object) -> None:
        pytest.fail("Повторные проверки не должны читать файл")

    monkeypatch.setattr(
        "firewall_compliance.interfaces.desktop.backend.FileSourceReader.read", forbid_read
    )
    repeated = reanalyze_session(session, require_logging=False, require_comments=False)
    assert repeated.source is session.source
    assert repeated.parse_result is session.parse_result
    assert repeated.revision is session.revision
    assert repeated.job_id == session.job_id
    assert repeated.report.revision_id == session.report.revision_id
    assert repeated.report.configuration_id == session.report.configuration_id
    assert not repeated.report.require_logging
    assert not repeated.report.require_comments
