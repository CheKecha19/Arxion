"""Real Typer command boundary for versioned local technical controls."""

import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from firewall_compliance.application.control_assessment import ControlAssessment
from firewall_compliance.domain.controls import ControlCatalogue, OrganizationControlProfile
from firewall_compliance.interfaces.cli.control_commands import app
from tests.regression.test_control_assessment import AT, assess, profile, source_result

ROOT = Path(__file__).resolve().parents[2]
runner = CliRunner()


@pytest.fixture
def directory():
    path = ROOT / "artifacts" / "control-cli-tests" / uuid4().hex
    path.mkdir(parents=True)
    return path


@pytest.fixture
def inputs(directory):
    source = directory / "analysis.json"
    selected = directory / "profile.json"
    source.write_text(source_result().model_dump_json(), encoding="utf-8-sig")
    selected.write_text(profile().model_dump_json(), encoding="utf-8-sig")
    return source, selected


def invoke(*arguments):
    return runner.invoke(app, list(map(str, arguments)))


def test_cli_catalogue_and_explicit_profile_template(directory):
    catalogue = directory / "catalogue.json"
    selected = directory / "profile.json"
    assert invoke("catalogue", "--output", catalogue).exit_code == 0
    assert (
        len(ControlCatalogue.model_validate_json(catalogue.read_text(encoding="utf-8")).controls)
        == 5
    )
    result = invoke(
        "profile-template",
        "--output",
        selected,
        "--organization",
        "Synthetic",
        "--scope-reference",
        "Authored test bundle",
        "--profile-id",
        "synthetic",
        "--version",
        "2",
        "--control",
        "TECH-BROAD-ALLOW",
        "--control",
        "TECH-POLICY-LOGGING",
        "--justification",
        "Explicit caller policy",
        "--not-applicable",
    )
    assert result.exit_code == 0, result.output
    value = OrganizationControlProfile.model_validate_json(selected.read_text(encoding="utf-8"))
    assert value.version == "2" and len(value.requirements) == 2
    assert all(not requirement.applicable for requirement in value.requirements)
    assert value.exceptions == ()


def test_profile_template_unknown_controls_and_missing_justification_fail(directory):
    destination = directory / "profile.json"
    base = [
        "profile-template",
        "--output",
        destination,
        "--organization",
        "Synthetic",
        "--scope-reference",
        "Test",
        "--profile-id",
        "test",
        "--control",
        "NIST-CERTIFIED",
    ]
    assert invoke(*base, "--justification", "Synthetic").exit_code == 2
    assert not destination.exists()
    assert invoke(*base).exit_code == 2


def test_cli_assessment_captures_exact_source_profile_and_mapping(inputs, directory):
    source, selected = inputs
    output = directory / "assessment.json"
    result = invoke(
        "assess", source, "--profile", selected, "--output", output, "--assessed-at", AT.isoformat()
    )
    assert result.exit_code == 0, result.output
    value = ControlAssessment.model_validate_json(output.read_text(encoding="utf-8"))
    assert value.source.model_dump_json() == source.read_text(encoding="utf-8-sig")
    assert value.evaluations[0].state == "technical_violation"
    assert str(value.assessment_id) in result.output
    assert value.profile.version == "1"


@pytest.mark.parametrize("format_name", ["json", "csv", "html"])
def test_cli_export_needs_only_captured_assessment(directory, format_name):
    source = directory / "assessment.json"
    original = assess()
    source.write_text(original.model_dump_json(), encoding="utf-8")
    output = directory / f"export.{format_name}"
    result = invoke("export", source, "--format", format_name, "--output", output)
    assert result.exit_code == 0, result.output
    text = output.read_text(encoding="utf-8")
    assert "technical_violation" in text
    if format_name == "json":
        assert ControlAssessment.model_validate_json(text) == original
    assert "NIST/CIS" in text


@pytest.mark.parametrize("input_index", [0, 1, 2])
def test_assess_refuses_output_hardlink_to_any_selected_input(inputs, directory, input_index):
    source, selected = inputs
    catalogue = directory / "catalogue.json"
    invoke("catalogue", "--output", catalogue)
    target = (source, selected, catalogue)[input_index]
    original = target.read_bytes()
    output = directory / "hardlink.json"
    os.link(target, output)
    result = invoke(
        "assess",
        source,
        "--profile",
        selected,
        "--catalogue",
        catalogue,
        "--output",
        output,
        "--assessed-at",
        AT.isoformat(),
    )
    assert result.exit_code == 2
    assert target.read_bytes() == original


def test_export_refuses_same_file_and_hardlink(directory):
    source = directory / "assessment.json"
    source.write_text(assess().model_dump_json(), encoding="utf-8")
    alias = directory / "alias.json"
    os.link(source, alias)
    original = source.read_bytes()
    assert invoke("export", source, "--output", source).exit_code == 2
    assert invoke("export", source, "--output", alias).exit_code == 2
    assert source.read_bytes() == original


@pytest.mark.parametrize("kind", ["invalid", "tampered", "oversized"])
def test_invalid_input_does_not_overwrite_output_or_disclose_payload(directory, kind):
    source = directory / "assessment.json"
    if kind == "invalid":
        source.write_text("SYNTHETIC-SENSITIVE-MARKER", encoding="utf-8")
    elif kind == "tampered":
        data = assess().model_dump(mode="json")
        data["coverage"]["violations"] = 100
        import json

        source.write_text(json.dumps(data), encoding="utf-8")
    else:
        with source.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
    output = directory / "preserved.html"
    output.write_text("PRESERVE", encoding="utf-8")
    result = invoke("export", source, "--output", output)
    assert result.exit_code == 2
    assert "SYNTHETIC-SENSITIVE-MARKER" not in result.output
    assert output.read_text() == "PRESERVE"


def test_explicit_custom_catalogue_is_retained(inputs, directory):
    source, selected = inputs
    catalogue = directory / "catalogue.json"
    invoke("catalogue", "--output", catalogue)
    value = ControlCatalogue.model_validate_json(catalogue.read_text(encoding="utf-8")).model_copy(
        update={"version": "synthetic-custom-version"}
    )
    catalogue.write_text(value.model_dump_json(), encoding="utf-8")
    output = directory / "assessment.json"
    result = invoke(
        "assess",
        source,
        "--profile",
        selected,
        "--catalogue",
        catalogue,
        "--output",
        output,
        "--assessed-at",
        AT.isoformat(),
    )
    assert result.exit_code == 0, result.output
    assert (
        ControlAssessment.model_validate_json(output.read_text(encoding="utf-8")).catalogue == value
    )


def test_control_cli_does_not_import_qt_or_open_configuration_files():
    code = (
        "import sys; import firewall_compliance.interfaces.cli.control_commands; "
        "assert not any(name.startswith(('PySide6', 'tkinter')) for name in sys.modules)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr


def test_real_registered_cli_entrypoint_assessment_and_export(inputs, directory):
    source, selected = inputs
    output = directory / "registered-assessment.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "firewall_compliance",
            "controls",
            "assess",
            str(source),
            "--profile",
            str(selected),
            "--output",
            str(output),
            "--assessed-at",
            AT.isoformat(),
        ],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    captured = ControlAssessment.model_validate_json(output.read_text(encoding="utf-8"))
    assert captured.evaluations[0].state == "technical_violation"
    destination = directory / "registered-assessment.html"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "firewall_compliance",
            "controls",
            "export",
            str(output),
            "--output",
            str(destination),
            "--format",
            "html",
        ],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "technical_violation" in destination.read_text(encoding="utf-8")
