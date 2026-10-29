"""Saved revision governance stages preserve historical reports and need no configuration."""

import os
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from firewall_compliance.application.analysis_reports import (
    export_analysis_csv,
    export_analysis_html,
    export_analysis_json,
)
from firewall_compliance.application.analysis_result import (
    AnalysisResult,
    FindingDecision,
    PolicyComponent,
)
from firewall_compliance.application.governance_workflow import (
    GOVERNANCE_CHECK_IDS,
    assess_governance,
)
from firewall_compliance.domain.enums import FindingStatus
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from tests.regression.test_analysis_result import AT, bundle, network_components, policy
from tests.regression.test_analysis_workflow_cli import cli
from tests.regression.test_policy_governance import inputs, metadata, profile, stats

ROOT = Path(__file__).resolve().parents[2]
ASSESSED = AT + timedelta(hours=1)


@pytest.fixture
def directory():
    location = ROOT / "artifacts" / "governance-workflow-tests" / uuid4().hex
    location.mkdir(parents=True)
    return location


def source_with_decision():
    previous = policy()
    finding = previous.result.checks[0].findings[0]
    return bundle(
        previous,
        *network_components(previous.revision),
        decisions=(
            FindingDecision(
                component_id=previous.component_id,
                finding_id=finding.finding_id,
                status=FindingStatus.ACCEPTED_RISK,
                comment="Preserve historical synthetic decision and its exact date",
                decided_at=AT + timedelta(seconds=1),
                actor_reference="synthetic-operator",
            ),
        ),
    )


def evidence():
    return inputs(
        meta=metadata(
            owner="",
            observed_at=ASSESSED,
            expires_at=ASSESSED,
            review_at=ASSESSED,
        ),
        observation=stats(
            evidence_id="synthetic-statistics",
            observed_at=ASSESSED,
            window_start=ASSESSED - timedelta(hours=1),
            window_end=ASSESSED,
        ),
    )


def test_new_stage_preserves_all_historical_components_decisions_and_exact_revision():
    original = source_with_decision()
    encoded = original.model_dump_json()
    result = assess_governance(original, "policy", profile(), evidence(), assessed_at=ASSESSED)
    assert original.model_dump_json() == encoded
    assert result.analysis_id != original.analysis_id
    assert result.sources == original.sources
    assert result.components[:-1] == original.components
    assert result.decisions == original.decisions
    assert result.decisions[0].decided_at == AT + timedelta(seconds=1)
    assert result.started_at == original.started_at and result.finished_at == ASSESSED
    stage = result.components[-1]
    assert isinstance(stage, PolicyComponent)
    assert stage.component_id.startswith("governance:")
    assert stage.revision == original.components[0].revision
    assert stage.options.check_ids == GOVERNANCE_CHECK_IDS
    assert tuple(check.check_id for check in stage.result.checks) == GOVERNANCE_CHECK_IDS
    assert stage.result.check_catalog_version == "1.4.0"
    assert all(check.findings for check in stage.result.checks)
    previous_findings = [
        item.finding_id for check in original.components[0].result.checks for item in check.findings
    ]
    all_policy_findings = [
        item.finding_id
        for component in result.components
        if isinstance(component, PolicyComponent)
        for check in component.result.checks
        for item in check.findings
    ]
    assert all(all_policy_findings.count(identifier) == 1 for identifier in previous_findings)
    assert AnalysisResult.model_validate_json(result.model_dump_json()) == result


def test_optional_evidence_stays_unknown_and_does_not_reuse_earlier_governance_inputs():
    original = source_with_decision()
    first = assess_governance(original, "policy", profile(), evidence(), assessed_at=ASSESSED)
    second = assess_governance(
        first,
        first.components[-1].component_id,
        profile(),
        assessed_at=ASSESSED + timedelta(seconds=1),
    )
    latest = second.components[-1]
    assert latest.options.governance_inputs is None
    assert all(
        check.status.value == "partial" and not check.findings for check in latest.result.checks
    )
    assert all(
        "GOVERNANCE_INPUTS_UNKNOWN" in {item.code for item in check.limitations}
        for check in latest.result.checks
    )
    assert second.components[:-1] == first.components


@pytest.mark.parametrize("component_id", ["missing", "route"])
def test_component_must_be_an_explicit_existing_policy_component(component_id):
    with pytest.raises(ValueError, match="component"):
        assess_governance(source_with_decision(), component_id, profile(), assessed_at=ASSESSED)


@pytest.mark.parametrize("date", [AT, ASSESSED.replace(tzinfo=None)])
def test_assessment_time_must_be_aware_and_not_precede_source_completion(date):
    with pytest.raises(ValueError, match="assessment time"):
        assess_governance(source_with_decision(), "policy", profile(), assessed_at=date)


def test_wrong_revision_and_invalid_budget_are_rejected_without_rebinding():
    foreign = uuid4()
    wrong = inputs(meta=metadata(revision_id=foreign), revision_id=foreign)
    with pytest.raises(ValueError, match="exact revision"):
        assess_governance(source_with_decision(), "policy", profile(), wrong, assessed_at=ASSESSED)
    for maximum in (0, True, 10000001):
        with pytest.raises(ValidationError):
            assess_governance(
                source_with_decision(),
                "policy",
                profile(),
                evidence(),
                assessed_at=ASSESSED,
                max_operations=maximum,
            )


def test_legacy_options_json_shape_does_not_gain_null_governance_fields():
    original = source_with_decision()
    encoded = original.model_dump_json()
    assert '"governance_' not in encoded
    assert AnalysisResult.model_validate_json(encoded).model_dump_json() == encoded
    result = assess_governance(original, "policy", profile(), evidence(), assessed_at=ASSESSED)
    assert "governance_profile" not in result.components[0].options.model_dump(mode="json")
    assert "governance_profile" in result.components[-1].options.model_dump(mode="json")


def test_pure_assessment_and_exports_do_not_open_files_or_network(monkeypatch):
    original = source_with_decision()
    selected = profile()
    records = evidence()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Pure governance assessment/export attempted I/O")

    with monkeypatch.context() as scope:
        scope.setattr("builtins.open", forbidden)
        scope.setattr(Path, "open", forbidden)
        scope.setattr("socket.socket", forbidden)
        result = assess_governance(original, "policy", selected, records, assessed_at=ASSESSED)
        assert export_analysis_json(result)
        assert "FW-RULE-GOVERNANCE" in export_analysis_csv(result)
        assert "FW-UNUSED-CANDIDATE" in export_analysis_html(result)


def test_store_keeps_original_and_new_stage_as_two_immutable_history_entries(directory):
    store = ProjectStore(directory / "projects.sqlite3")
    project = store.create_project("Synthetic governance")
    original = source_with_decision().model_copy(update={"project_reference": project})
    assessed = assess_governance(original, "policy", profile(), evidence(), assessed_at=ASSESSED)
    store.save_analysis_result(project, original)
    store.save_analysis_result(project, assessed)
    assert len(store.list_analysis_results(project)) == 2
    assert store.get_analysis_result(project, str(original.analysis_id)) == original
    assert store.get_analysis_result(project, str(assessed.analysis_id)) == assessed


def write_cli_inputs(directory):
    saved = directory / "saved-bundle.json"
    selected = directory / "profile.json"
    records = directory / "evidence.json"
    saved.write_text(source_with_decision().model_dump_json(), encoding="utf-8")
    selected.write_text(profile().model_dump_json(), encoding="utf-8-sig")
    records.write_text(evidence().model_dump_json(), encoding="utf-8")
    return saved, selected, records


def test_real_cli_assessment_and_existing_exports_need_only_saved_bundle(directory):
    saved, selected, records = write_cli_inputs(directory)
    before = {path: path.read_bytes() for path in (saved, selected, records)}
    output = directory / "new-bundle.json"
    process = cli(
        "governance",
        "assess",
        saved,
        "--component",
        "policy",
        "--profile",
        selected,
        "--inputs",
        records,
        "--assessed-at",
        ASSESSED.isoformat(),
        "--output",
        output,
    )
    assert process.returncode == 0, process.stderr.decode("utf-8")
    result = AnalysisResult.model_validate_json(output.read_text(encoding="utf-8"))
    assert process.stdout.decode("utf-8").strip() == str(result.analysis_id)
    assert all(path.read_bytes() == content for path, content in before.items())
    for format_name in ("json", "csv", "html"):
        exported = directory / f"export.{format_name}"
        response = cli("analysis-export", output, "--format", format_name, "--output", exported)
        assert response.returncode == 0, response.stderr.decode("utf-8")
        assert "FW-UNUSED-CANDIDATE" in exported.read_text(encoding="utf-8")


@pytest.mark.parametrize("target", ["bundle", "profile", "evidence"])
def test_cli_prevents_overwriting_each_input_including_hardlink_aliases(directory, target):
    saved, selected, records = write_cli_inputs(directory)
    protected = {"bundle": saved, "profile": selected, "evidence": records}[target]
    original = protected.read_bytes()
    alias = directory / "hardlink-output.json"
    os.link(protected, alias)
    process = cli(
        "governance",
        "assess",
        saved,
        "--component",
        "policy",
        "--profile",
        selected,
        "--inputs",
        records,
        "--output",
        alias,
    )
    assert process.returncode == 2
    assert protected.read_bytes() == alias.read_bytes() == original


def test_cli_safe_error_does_not_echo_input_payload_or_model_errors(directory):
    saved, selected, records = write_cli_inputs(directory)
    records.write_text('{"private_configuration_marker":"DO-NOT-ECHO-SYNTHETIC"}', encoding="utf-8")
    output = directory / "not-written.json"
    process = cli(
        "governance",
        "assess",
        saved,
        "--component",
        "policy",
        "--profile",
        selected,
        "--inputs",
        records,
        "--output",
        output,
    )
    assert process.returncode == 2 and not output.exists()
    assert b"DO-NOT-ECHO-SYNTHETIC" not in process.stderr + process.stdout
    assert b"Traceback" not in process.stderr


def test_cli_without_evidence_writes_truthful_partial_stage(directory):
    saved, selected, _records = write_cli_inputs(directory)
    output = directory / "partial-stage.json"
    process = cli(
        "governance",
        "assess",
        saved,
        "--component",
        "policy",
        "--profile",
        selected,
        "--assessed-at",
        ASSESSED.isoformat(),
        "--output",
        output,
    )
    assert process.returncode == 0, process.stderr.decode("utf-8")
    result = AnalysisResult.model_validate_json(output.read_text(encoding="utf-8"))
    assert all(check.status.value == "partial" for check in result.components[-1].result.checks)
    assert all(not check.findings for check in result.components[-1].result.checks)


@pytest.mark.parametrize("timestamp", ["2026-10-27T01:00:00", "invalid-date"])
def test_cli_rejects_naive_or_invalid_assessment_dates_without_output(directory, timestamp):
    saved, selected, records = write_cli_inputs(directory)
    output = directory / "invalid-date-result.json"
    process = cli(
        "governance",
        "assess",
        saved,
        "--component",
        "policy",
        "--profile",
        selected,
        "--inputs",
        records,
        "--assessed-at",
        timestamp,
        "--output",
        output,
    )
    assert process.returncode == 2 and not output.exists()


def test_cli_bounds_profile_read_before_decoding_or_writing(directory):
    saved, selected, records = write_cli_inputs(directory)
    with selected.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    output = directory / "oversized-result.json"
    process = cli(
        "governance",
        "assess",
        saved,
        "--component",
        "policy",
        "--profile",
        selected,
        "--inputs",
        records,
        "--output",
        output,
    )
    assert process.returncode == 2 and not output.exists()


def test_cli_rejects_invalid_utf8_without_exposing_decoding_exception(directory):
    saved, selected, records = write_cli_inputs(directory)
    selected.write_bytes(b"\xff\xfe\x00not-utf8")
    output = directory / "invalid-encoding-result.json"
    process = cli(
        "governance",
        "assess",
        saved,
        "--component",
        "policy",
        "--profile",
        selected,
        "--inputs",
        records,
        "--output",
        output,
    )
    assert process.returncode == 2 and not output.exists()
    assert b"UnicodeDecodeError" not in process.stderr
