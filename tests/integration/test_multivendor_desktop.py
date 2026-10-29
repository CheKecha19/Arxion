"""Новые форматы проходят тот же реальный desktop pipeline, что и ASA."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from firewall_compliance.domain import DataStatus
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.interfaces.cli.main import app
from firewall_compliance.interfaces.desktop.backend import (
    AnalysisSession,
    analyze_file,
    reanalyze_session,
    source_preview,
    view_workspace,
)
from firewall_compliance.parsers.contracts import ParseFailure

ROOT = Path(__file__).resolve().parents[1] / "fixtures/hp_aruba"


def test_cli_uses_same_catalog_as_desktop() -> None:
    result = CliRunner().invoke(app, ["analyze", str(ROOT / "aos_switch.cfg")])
    assert result.exit_code == 0
    report = FirewallAssuranceResult.model_validate_json(result.stdout)
    assert len(report.checks) == 19
    assert report.parser_version == "0.2.0"


@pytest.mark.parametrize(
    "filename,platform", [("aos_switch.cfg", "aos-switch"), ("aos_cx.cfg", "aos-cx")]
)
def test_real_pipeline_models_and_original_export(filename: str, platform: str) -> None:
    session = analyze_file(ROOT / filename, device_id="SYNTHETIC-MULTIVENDOR")
    assert isinstance(session, AnalysisSession)
    assert session.parse_result.configuration.platform == platform
    assert session.report.device_id == "SYNTHETIC-MULTIVENDOR"
    assert session.report.configuration_id == session.parse_result.configuration.configuration_id
    assert session.report.revision_id == session.revision.revision_id
    assert len(session.report.checks) == 19
    assert session.parse_result.rules
    workspace = view_workspace((session,))
    assert len(workspace.rules) == len(session.parse_result.rules)
    assert (
        FirewallAssuranceResult.model_validate_json(session.report.model_dump_json())
        == session.report
    )
    assert source_preview(session, session.parse_result.rules[0].source_location)
    assert session.revision.interfaces_status == DataStatus.UNKNOWN
    repeated = reanalyze_session(session, require_logging=False, require_comments=False)
    assert repeated.revision.revision_id == session.revision.revision_id
    assert repeated.parse_result == session.parse_result


def test_comware_pipeline_and_management_scope(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-comware.txt"
    path.write_text(
        "version 7.1.045\nsysname LAB\nacl number 2000\n"
        " rule 0 permit source 192.0.2.10 0\n#\n"
        "snmp-agent community read SYNTHETIC acl 2000",
        encoding="utf-8",
    )
    session = analyze_file(path)
    assert isinstance(session, AnalysisSession)
    assert session.parse_result.rules[0].policy_id == "management:snmp:acl:2000"
    assert session.parse_result.rules[0].policy_direction is None
    assert session.report.device_id == "LAB"


def test_controller_is_explicit_failure_not_fake_inventory(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-controller.txt"
    path.write_text(
        "ip access-list session LAB\n any any svc-https permit\nuser-role LAB\n"
        " access-list session LAB\nwlan ssid-profile LAB\n",
        encoding="utf-8",
    )
    result = analyze_file(path)
    assert isinstance(result, ParseFailure)
    assert result.errors[0].code == "ARUBAOS_CONTROLLER_UNSUPPORTED"


def test_no_juniper_registered(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-junos.txt"
    path.write_text(
        "set system host-name LAB\nset firewall family inet filter LAB term FIRST then accept\n",
        encoding="utf-8",
    )
    result = analyze_file(path)
    assert isinstance(result, ParseFailure)
    assert result.errors[0].code == "PARSER_NOT_FOUND"
