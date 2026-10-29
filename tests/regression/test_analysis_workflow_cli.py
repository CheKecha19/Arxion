"""Real bundle CLI/workflow interoperability and immutable-source error boundaries."""

import csv
import io
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from firewall_compliance.analysis.revision_diff import compare_device_revisions
from firewall_compliance.application.analysis_result import AnalysisResult, RevisionDiffComponent
from firewall_compliance.application.analysis_workflow import analyze_source_result
from firewall_compliance.application.firewall_assurance import analyze_source
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.parsers import SourceDocument
from firewall_compliance.parsers.catalog import create_default_registry
from tests.regression.test_analysis_result import bundle, network_components, policy

ROOT = Path(__file__).resolve().parents[2]
AT = datetime(2026, 10, 27, 16, 0, tzinfo=UTC)
CONTENT = (
    "hostname SYNTHETIC-WORKFLOW\n"
    "access-list AUDIT extended permit tcp any host 192.0.2.10 eq 22\n"
    "access-group AUDIT in interface outside\n"
    "! SYNTHETIC-RAW-ONLY-MARKER\n"
)


@pytest.fixture
def directory():
    result = (ROOT / "artifacts" / "analysis-workflow-tests" / uuid4().hex).resolve()
    assert result.is_relative_to(ROOT)
    result.mkdir(parents=True)
    return result


@pytest.fixture
def source(directory):
    path = directory / "синтетический.txt"
    path.write_text(CONTENT, encoding="utf-8")
    return path


def cli(*arguments):
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "firewall_compliance", *map(str, arguments)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )


def create_bundle(source, directory, *options):
    output = directory / "bundle.json"
    process = cli("analyze-bundle", source, "--output", output, *options)
    assert process.returncode == 0, process.stderr.decode("utf-8")
    result = AnalysisResult.model_validate_json(output.read_text(encoding="utf-8"))
    assert process.stdout.decode("utf-8").strip() == str(result.analysis_id)
    return output, result


@pytest.mark.parametrize("requirements", [(True, True), (False, False)])
def test_workflow_preserves_exact_legacy_report_with_fixed_revision_and_time(requirements):
    source = SourceDocument(
        source_name="синтетический.txt",
        content=CONTENT.encode(),
        captured_at=AT,
        file_modified_at=AT - timedelta(minutes=1),
    )
    arguments = {
        "imported_at": AT + timedelta(seconds=1),
        "revision_id": UUID("10000000-0000-0000-0000-000000000002"),
        "require_logging": requirements[0],
        "require_comments": requirements[1],
    }
    legacy = analyze_source(source, create_default_registry(), **arguments)
    result = analyze_source_result(source, create_default_registry(), **arguments)

    assert isinstance(legacy, FirewallAssuranceResult)
    assert len(result.components) == 1 and result.components[0].kind == "policy"
    assert result.components[0].result == legacy
    assert (
        result.components[0].revision.parse_result.configuration.content_sha256
        == sha256(source.content).hexdigest()
    )
    assert result.sources[0].hash_basis == "raw_file"
    assert result.sources[0].file_modified_at == source.file_modified_at
    assert "SYNTHETIC-RAW-ONLY-MARKER" not in result.model_dump_json()
    assert source.content == CONTENT.encode()


def test_bundle_workflow_parses_the_captured_document_once(monkeypatch):
    source = SourceDocument(source_name="synthetic.txt", content=CONTENT.encode(), captured_at=AT)
    registry = create_default_registry()
    original_parse = registry.parse
    captured = []

    def parse(request):
        captured.append(request.source)
        return original_parse(request)

    monkeypatch.setattr(registry, "parse", parse)
    result = analyze_source_result(source, registry, imported_at=AT)

    assert captured == [source]
    assert result.components[0].revision.parse_result.rules


def test_source_workflow_imports_no_qt_or_desktop_module():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import firewall_compliance.application.analysis_workflow; "
            "assert not any(name.startswith(('PySide6', 'firewall_compliance.interfaces.desktop')) "
            "for name in sys.modules)",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("format_name", ["json", "csv", "html"])
def test_cli_exports_saved_bundle_after_original_source_is_deleted(source, directory, format_name):
    saved, bundle_result = create_bundle(source, directory)
    original_digest = sha256(source.read_bytes()).hexdigest()
    assert source.name.encode("utf-8") in saved.read_bytes()
    assert bundle_result.sources[0].content_sha256 == original_digest
    assert source.resolve().is_relative_to(directory)
    source.unlink()

    output = directory / ("экспорт." + format_name)
    process = cli("analysis-export", saved, "--output", output, "--format", format_name)

    assert process.returncode == 0, process.stderr.decode("utf-8")
    assert process.stdout.decode("utf-8").strip() == str(bundle_result.analysis_id)
    document = output.read_text(encoding="utf-8")
    if format_name == "json":
        assert AnalysisResult.model_validate_json(document) == bundle_result
    elif format_name == "csv":
        rows = list(csv.DictReader(io.StringIO(document)))
        assert any(row["row_type"] == "component" and row["family"] == "policy" for row in rows)
    else:
        assert "не означает безопасность или доказанную достижимость" in document
        assert "policy" in document and "синтетический.txt" in document


@pytest.mark.parametrize("format_name", ["json", "csv", "html"])
def test_cli_exports_utf8_bom_mixed_network_and_diff_bundle(directory, format_name):
    component = policy()
    revision = component.revision
    later = revision.model_copy(update={"revision_id": uuid4()})
    diff = RevisionDiffComponent(
        component_id="diff",
        before=revision,
        after=later,
        result=compare_device_revisions(revision, later),
    )
    original = bundle(component, *network_components(revision), diff)
    saved = directory / "mixed.json"
    saved.write_text(original.model_dump_json(), encoding="utf-8-sig")
    output = directory / ("mixed-export." + format_name)

    process = cli("analysis-export", saved, "--output", output, "--format", format_name)

    assert process.returncode == 0, process.stderr.decode("utf-8")
    document = output.read_text(encoding="utf-8")
    assert original.state == "partial"
    if format_name == "json":
        reopened = AnalysisResult.model_validate_json(document)
        assert reopened == original
        assert reopened.summary.network_results == 5
        assert reopened.summary.semantic_changes == 0
    elif format_name == "csv":
        rows = list(csv.DictReader(io.StringIO(document)))
        components = [row for row in rows if row["row_type"] == "component"]
        assert len(components) == 7
        assert {row["family"] for row in components} == {"policy", "network", "revision_diff"}
        assert any(row["state"] != "complete" for row in components)
    else:
        assert "не означает безопасность или доказанную достижимость" in document
        assert "revision_diff" in document and "reachability" in document


def test_cli_failure_still_writes_an_explicit_failed_bundle_with_raw_source_digest(directory):
    source = directory / "unsupported.txt"
    content = b"SYNTHETIC-RAW-FAILURE-MARKER unsupported format\n"
    source.write_bytes(content)
    saved = directory / "failed.json"

    process = cli("analyze-bundle", source, "--output", saved)

    assert process.returncode == 2
    result = AnalysisResult.model_validate_json(saved.read_text(encoding="utf-8"))
    assert result.state == "failed" and result.summary.checks_executed == 0
    assert result.components[0].kind == "attempt"
    assert result.components[0].diagnostic.code == "PARSER_NOT_FOUND"
    assert result.sources[0].content_sha256 == sha256(content).hexdigest()
    assert result.components[0].source_ids == (result.sources[0].source_document_id,)
    assert b"Traceback" not in process.stderr
    assert (
        b"SYNTHETIC-RAW-FAILURE-MARKER" not in process.stderr + process.stdout + saved.read_bytes()
    )


@pytest.mark.parametrize("tamper", ["version", "findings", "digest", "query"])
def test_cli_rejects_tampered_saved_results_without_disclosing_payload_or_overwriting_output(
    directory, tamper
):
    component = policy()
    original = bundle(component, *network_components(component.revision))
    payload = original.model_dump(mode="json")
    if tamper == "version":
        payload["schema_version"] = "SYNTHETIC-PRIVATE-BAD-VERSION"
    elif tamper == "findings":
        payload["components"][0]["result"]["checks"][0]["findings"] = []
    elif tamper == "digest":
        payload["sources"][0]["content_sha256"] = "b" * 64
    else:
        payload["components"][1]["query"]["destination_ip"] = "203.0.113.200"
    saved = directory / "tampered.json"
    saved.write_text(json.dumps(payload), encoding="utf-8")
    output = directory / "previous-report.html"
    output.write_text("Previous valid artifact", encoding="utf-8")

    process = cli("analysis-export", saved, "--output", output)

    assert process.returncode == 2
    assert output.read_text(encoding="utf-8") == "Previous valid artifact"
    assert b"Traceback" not in process.stderr
    assert b"SYNTHETIC-PRIVATE-BAD-VERSION" not in process.stderr
    assert b"203.0.113.200" not in process.stderr


@pytest.mark.parametrize("command", ["analyze-bundle", "analysis-export"])
def test_cli_refuses_to_overwrite_its_exact_input(source, directory, command):
    path = source if command == "analyze-bundle" else create_bundle(source, directory)[0]
    original = path.read_bytes()

    process = cli(command, path, "--output", path)

    assert process.returncode == 2
    assert path.read_bytes() == original
    assert b"Traceback" not in process.stderr


@pytest.mark.parametrize("command", ["analyze-bundle", "analysis-export"])
def test_cli_refuses_to_overwrite_an_input_hardlink(source, directory, command):
    path = source if command == "analyze-bundle" else create_bundle(source, directory)[0]
    original = path.read_bytes()
    alias = directory / "output-alias.txt"
    os.link(path, alias)

    process = cli(command, path, "--output", alias)

    assert process.returncode == 2
    assert path.read_bytes() == original
    assert alias.read_bytes() == original


@pytest.mark.parametrize("payload", [b"\xffnot UTF8", b"{broken JSON", b"{}"])
def test_cli_bad_bundle_errors_do_not_create_an_output(directory, payload):
    saved, output = directory / "invalid.json", directory / "new-report.html"
    saved.write_bytes(payload)

    process = cli("analysis-export", saved, "--output", output)

    assert process.returncode == 2
    assert not output.exists()
    assert b"Traceback" not in process.stderr


def test_cli_rejects_bundle_over_64_mib_without_rendering(directory):
    saved, output = directory / "oversized.json", directory / "report.html"
    with saved.open("wb") as stream:
        stream.seek(64 * 1024 * 1024)
        stream.write(b"x")

    process = cli("analysis-export", saved, "--output", output)

    assert process.returncode == 2
    assert not output.exists()
    assert b"Traceback" not in process.stderr


def test_cli_persists_explicit_profiles_and_complete_config_in_replayable_bundle(source, directory):
    management = directory / "management.json"
    management_payload = {
        "profile_id": "synthetic-management",
        "version": "9",
        "approved_admin_networks": ["10.0.0.0/8"],
        "max_idle_seconds": 120,
    }
    management.write_text(json.dumps(management_payload), encoding="utf-8-sig")
    exposure = directory / "exposure.json"
    exposure_payload = {
        "profile_id": "synthetic-service-policy",
        "version": "7",
        "dangerous_services": [
            {
                "selector_id": "organization-ssh",
                "name": "Explicit SSH",
                "protocol": "tcp",
                "port_ranges": [{"start": 22, "end": 22}],
            }
        ],
        "administrative_services": [],
        "administrative_targets": [],
        "trusted_admin_networks": [],
    }
    exposure.write_text(json.dumps(exposure_payload), encoding="utf-8-sig")

    _, result = create_bundle(
        source,
        directory,
        "--management-profile",
        management,
        "--policy-exposure-profile",
        exposure,
        "--complete-config",
        "--no-require-logging",
        "--no-require-comments",
    )

    component = result.components[0]
    assert component.kind == "policy"
    assert component.options.management_profile.profile_id == "synthetic-management"
    assert component.options.management_profile.max_idle_seconds == 120
    assert component.options.exposure_profile.profile_id == "synthetic-service-policy"
    assert component.options.exposure_profile.administrative_services == ()
    assert (
        component.options.exposure_profile.dangerous_services[0].selector_id == "organization-ssh"
    )
    assert component.options.require_logging is False
    assert component.options.require_comments is False
    checks = {check.check_id: check for check in component.result.checks}
    assert checks["FW-DANGEROUS-SERVICES"].findings
    assert {"FW-PARTIAL-SHADOWED", "FW-UNION-SHADOWED", "FW-ADMIN-UNTRUSTED"} <= checks.keys()
    assert AnalysisResult.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("complete", [False, True])
def test_cli_complete_config_flag_preserves_explicit_management_inventory(directory, complete):
    source = directory / "aruba.cfg"
    source.write_text("; ArubaOS-Switch 16.10\nhostname SYNTHETIC-SWITCH\n", encoding="utf-8")

    _, result = create_bundle(source, directory, *(("--complete-config",) if complete else ()))

    component = result.components[0]
    assert component.kind == "policy"
    assert component.revision.parse_result.management.complete_export is complete
    assert component.options.management_profile.profile_id == "baseline"


@pytest.mark.parametrize("option", ["--management-profile", "--policy-exposure-profile"])
def test_cli_refuses_output_hardlink_to_a_selected_profile(source, directory, option):
    profile_path = directory / "profile.json"
    profile_path.write_text("{}", encoding="utf-8")
    alias = directory / "profile-output-alias.json"
    os.link(profile_path, alias)
    original = source.read_bytes()

    process = cli("analyze-bundle", source, "--output", alias, option, profile_path)

    assert process.returncode == 2
    assert profile_path.read_text(encoding="utf-8") == "{}"
    assert alias.read_text(encoding="utf-8") == "{}"
    assert source.read_bytes() == original
    assert b"Traceback" not in process.stderr


@pytest.mark.parametrize("option", ["--management-profile", "--policy-exposure-profile"])
def test_invalid_explicit_profile_preserves_existing_output_and_configuration(
    source, directory, option
):
    profile_path = directory / "invalid-profile.json"
    profile_path.write_text('{"unknown": "SYNTHETIC-PRIVATE-PROFILE"}', encoding="utf-8")
    output = directory / "existing-bundle.json"
    output.write_text("previous valid artifact", encoding="utf-8")
    original = source.read_bytes()

    process = cli("analyze-bundle", source, "--output", output, option, profile_path)

    assert process.returncode == 2
    assert output.read_text(encoding="utf-8") == "previous valid artifact"
    assert source.read_bytes() == original
    assert b"SYNTHETIC-PRIVATE-PROFILE" not in process.stderr + process.stdout
    assert b"Traceback" not in process.stderr
