"""Сквозной анализ synthetic Cisco ASA export и сохранение диагностики."""

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from uuid import UUID

from typer.testing import CliRunner

from firewall_compliance.application.firewall_assurance import analyze_source
from firewall_compliance.domain.assurance import CheckStatus, FirewallAssuranceResult
from firewall_compliance.interfaces.cli.main import app
from firewall_compliance.parsers import CiscoAsaParser, ParseFailure, ParserRegistry, SourceDocument

FIXTURES = Path(__file__).parents[1] / "fixtures" / "assurance"
CAPTURED_AT = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
IMPORTED_AT = datetime(2026, 10, 9, 12, 1, tzinfo=UTC)
REVISION_ID = UUID("70000000-0000-0000-0000-000000000001")


def analyze_fixture(content: bytes | None = None) -> FirewallAssuranceResult:
    """Выполнить воспроизводимый сквозной анализ входного файла."""
    result = analyze_source(
        SourceDocument(
            source_name="policy_quality.cfg",
            content=content
            if content is not None
            else (FIXTURES / "policy_quality.cfg").read_bytes(),
            captured_at=CAPTURED_AT,
        ),
        ParserRegistry([CiscoAsaParser()]),
        imported_at=IMPORTED_AT,
        revision_id=REVISION_ID,
    )
    assert isinstance(result, FirewallAssuranceResult)
    return result


def test_cisco_asa_pipeline_returns_all_seven_check_results() -> None:
    result = analyze_fixture()
    assert not result.parse_warnings
    assert len(result.checks) == 7
    assert all(check.status == CheckStatus.COMPLETE for check in result.checks)
    assert all(check.findings for check in result.checks)
    assert all(
        finding.revision_id == result.revision_id
        for check in result.checks
        for finding in check.findings
    )


def test_unknown_acl_keeps_diagnostics_and_prevents_pair_claims() -> None:
    result = analyze_fixture(
        (FIXTURES / "policy_quality.cfg").read_bytes()
        + b"access-list AUDIT extended permit tcp any any eq 443 time-range WORK\n"
    )
    assert result.parse_warnings
    for check in result.checks:
        assert check.status == CheckStatus.PARTIAL
        if check.check_id in {"FW-DUPLICATE", "FW-SHADOWED", "FW-MERGE-CANDIDATE"}:
            assert not check.findings


def test_fixture_manifest_matches_synthetic_export() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    assert sha256((FIXTURES / manifest["name"]).read_bytes()).hexdigest() == manifest["sha256"]


def test_cli_outputs_json_and_honors_check_preferences() -> None:
    result = CliRunner().invoke(
        app,
        [
            "analyze",
            str(FIXTURES / "policy_quality.cfg"),
            "--no-require-logging",
            "--no-require-comments",
        ],
    )
    assert result.exit_code == 0, result.output
    values = json.loads(result.stdout)
    assert values["schema_version"] == "1.0.0"
    assert all(
        check["status"] == "not_applicable"
        for check in values["checks"]
        if check["check_id"] in {"FW-LOGGING", "FW-COMMENTS"}
    )


def test_cli_unknown_format_returns_structured_failure() -> None:
    result = CliRunner().invoke(app, ["analyze", str(FIXTURES / "README.md")])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["errors"][0]["code"] == "PARSER_NOT_FOUND"


def test_invalid_encoding_is_rejected_by_registry_before_parser_selection() -> None:
    result = analyze_source(
        SourceDocument(source_name="binary.cfg", content=b"\xff", captured_at=CAPTURED_AT),
        ParserRegistry([CiscoAsaParser()]),
        imported_at=IMPORTED_AT,
    )
    assert isinstance(result, ParseFailure)
    assert result.errors[0].code == "PARSER_NOT_FOUND"
