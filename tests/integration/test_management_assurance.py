"""Management checks: findings, clean cases, unknowns, provenance and user entry points."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from firewall_compliance.application.firewall_assurance import analyze_source
from firewall_compliance.checks.management.rules import MANAGEMENT_CHECKS, outside_networks
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.interfaces.cli.main import app
from firewall_compliance.interfaces.desktop.backend import analyze_file, reanalyze_session
from firewall_compliance.interfaces.desktop.project_store import _excerpts
from firewall_compliance.parsers import SourceDocument
from firewall_compliance.parsers.catalog import create_default_registry

NOW = datetime(2026, 10, 19, tzinfo=UTC)
PROFILE = ManagementProfile(
    approved_admin_networks=("192.0.2.0/24",),
    approved_snmp_networks=("192.0.2.0/24",),
    approved_syslog_servers=("192.0.2.1",),
    approved_ntp_servers=("192.0.2.2",),
)


def report(
    text: str,
    *,
    complete: bool = True,
    platform: str = "aos-switch",
    profile: ManagementProfile = PROFILE,
) -> FirewallAssuranceResult:
    header = {
        "aos-switch": "; ArubaOS-Switch 16.10\nhostname test\n",
        "aos-cx": "! AOS-CX 10.13\nhostname test\n",
        "comware": "version 7.1.045\nsysname test\n",
    }[platform]
    source = SourceDocument(
        source_name="synthetic.cfg",
        content=(header + text).encode(),
        captured_at=NOW,
        configuration_complete=complete,
    )
    result = analyze_source(
        source, create_default_registry(), imported_at=NOW, management_profile=profile
    )
    assert isinstance(result, FirewallAssuranceResult)
    assert len([c for c in result.checks if c.check_id.startswith("MGMT-")]) == 12
    return result


CASES = [
    ("MGMT-TELNET", "telnet-server", "no telnet-server"),
    ("MGMT-HTTP", "web-management plaintext", "no web-management plaintext"),
    (
        "MGMT-ADMIN-SOURCES",
        "ip authorized-managers 198.51.100.1 255.255.255.255 access manager access-method ssh",
        "ip authorized-managers 192.0.2.1 255.255.255.255 access manager access-method ssh",
    ),
    ("MGMT-SNMP-LEGACY", 'snmp-server community "SENSITIVE" operator restricted', "snmpv3 only"),
    (
        "MGMT-SNMP-WRITE",
        'snmp-server community "SENSITIVE" manager unrestricted',
        'snmp-server community "SENSITIVE" operator restricted',
    ),
    (
        "MGMT-SNMP-SOURCES",
        "ip authorized-managers 198.51.100.1 255.255.255.255 access manager access-method snmp",
        "ip authorized-managers 192.0.2.1 255.255.255.255 access manager access-method snmp",
    ),
    ("MGMT-SYSLOG-MISSING", "", "logging 192.0.2.1"),
    ("MGMT-SYSLOG-UNAPPROVED", "logging 198.51.100.1", "logging 192.0.2.1"),
    ("MGMT-NTP-MISSING", "", "ntp server 192.0.2.2"),
    ("MGMT-NTP-UNAPPROVED", "ntp server 198.51.100.2", "ntp server 192.0.2.2"),
    ("MGMT-IDLE-TIMEOUT", "console idle-timeout 0", "console idle-timeout 900"),
    ("MGMT-BANNER", "", 'banner motd "Authorized access only"'),
]


@pytest.mark.parametrize("check_id,bad,good", CASES)
def test_each_check_has_positive_and_clean_case(check_id: str, bad: str, good: str) -> None:
    for content, expected in ((bad, 1), (good, 0)):
        result = report(content)
        check = next(c for c in result.checks if c.check_id == check_id)
        assert check.status == "complete"
        assert len(check.findings) == expected
        for finding in check.findings:
            assert finding.evidence.source_locations
            assert finding.evidence.facts["profile"] == PROFILE.model_dump(mode="json")
        assert "SENSITIVE" not in result.model_dump_json()


@pytest.mark.parametrize("check_id", MANAGEMENT_CHECKS)
def test_excerpt_never_claims_clean_or_missing(check_id: str) -> None:
    check = next(c for c in report("", complete=False).checks if c.check_id == check_id)
    assert check.status == "partial"
    assert not check.findings


@pytest.mark.parametrize(
    "check_id",
    ["MGMT-ADMIN-SOURCES", "MGMT-SNMP-SOURCES", "MGMT-SYSLOG-UNAPPROVED", "MGMT-NTP-UNAPPROVED"],
)
def test_unset_allowlist_requires_profile(check_id: str) -> None:
    check = next(
        c for c in report("", profile=ManagementProfile()).checks if c.check_id == check_id
    )
    assert any(x.code == "MANAGEMENT_PROFILE_REQUIRED" for x in check.limitations)


def test_partial_positive_and_conflicting_commands() -> None:
    result = report("telnet-server", complete=False)
    check = next(c for c in result.checks if c.check_id == "MGMT-TELNET")
    assert check.status == "partial" and len(check.findings) == 1
    result = report("telnet-server\nno telnet-server")
    check = next(c for c in result.checks if c.check_id == "MGMT-TELNET")
    assert check.status == "partial" and not check.findings


@pytest.mark.parametrize(
    "text,check_id",
    [
        ("logging ip#13", "MGMT-SYSLOG-MISSING"),
        ("ntp server 192.0.2.2 unsupported-option", "MGMT-NTP-MISSING"),
        ("undo ntp-service unicast-server 192.0.2.2", "MGMT-NTP-MISSING"),
        ('banner motd "unterminated\nntp server 192.0.2.2', "MGMT-BANNER"),
        ("ip authorized-managers ip12 ip13", "MGMT-ADMIN-SOURCES"),
    ],
)
def test_unsupported_syntax_never_implies_absence(text: str, check_id: str) -> None:
    check = next(c for c in report(text).checks if c.check_id == check_id)
    assert check.status == "partial" and not check.findings


def test_banner_body_is_not_executed_and_content_is_not_retained() -> None:
    result = report('banner motd "\ntelnet-server\nweb-management plaintext\nSENSITIVE\n"')
    assert not any(
        f.check_id in {"MGMT-TELNET", "MGMT-HTTP"} for c in result.checks for f in c.findings
    )
    assert "SENSITIVE" not in result.model_dump_json()
    malformed = report('banner motd "unterminated\nlogging 192.0.2.1')
    for check in malformed.checks:
        if check.check_id.startswith("MGMT-"):
            assert check.status == "partial" and not check.findings


def test_comware_acl_order_wildcards_and_bindings() -> None:
    text = """acl number 2000
 rule 0 deny source 192.0.2.0 0.0.0.127
 rule 5 permit source 192.0.2.0 0.0.0.255
 rule 10 deny
#
user-interface vty 0 4
 acl 2000 inbound
 idle-timeout 15 0
#
snmp-agent community write SENSITIVE acl 2000
snmp-agent sys-info version v2c v3
telnet server enable
ip http enable
info-center loghost 192.0.2.1
ntp-service unicast-server 192.0.2.2
header login %Authorized access only%
"""
    result = report(text, platform="comware")
    checks = {c.check_id: c for c in result.checks}
    for key in ("MGMT-ADMIN-SOURCES", "MGMT-SNMP-SOURCES", "MGMT-IDLE-TIMEOUT"):
        assert checks[key].status == "complete"
        assert not checks[key].findings
    for key in ("MGMT-TELNET", "MGMT-HTTP", "MGMT-SNMP-WRITE", "MGMT-SNMP-LEGACY"):
        assert len(checks[key].findings) == 1
    assert "SENSITIVE" not in result.model_dump_json()


def test_acl_incomplete_or_unmatched_tail_is_unknown() -> None:
    for complete in (True, False):
        result = report(
            "acl number 2000\n rule 0 permit source 192.0.2.1 0\n#\n"
            "user-interface vty 0 4\n acl 2000 inbound\n",
            platform="comware",
            complete=complete,
        )
        check = next(c for c in result.checks if c.check_id == "MGMT-ADMIN-SOURCES")
        assert check.status == "partial" and not check.findings


def test_only_v3_overrides_community_legacy_in_both_orders() -> None:
    community = 'snmp-server community "SENSITIVE" operator restricted'
    for text in (f"{community}\nsnmpv3 only", f"snmpv3 only\n{community}"):
        check = next(c for c in report(text).checks if c.check_id == "MGMT-SNMP-LEGACY")
        assert check.status == "complete" and not check.findings


def test_profile_normalization_validation_and_union() -> None:
    assert outside_networks("192.0.2.0/24", ("192.0.2.0/25", "192.0.2.128/25")) is None
    assert outside_networks("192.0.2.0/24", ("192.0.2.0/25",)) == "192.0.2.128"
    assert outside_networks("::/0", ("0.0.0.0/0",)) == "::"
    assert ManagementProfile(approved_ntp_servers=("NTP.EXAMPLE.",)).approved_ntp_servers == (
        "ntp.example",
    )
    with pytest.raises(ValueError):
        ManagementProfile(approved_admin_networks=("192.0.2.1/24",))
    with pytest.raises(ValueError):
        ManagementProfile.model_validate_json('{"allow_snmp_write": "false"}')


@given(st.sets(st.integers(min_value=0, max_value=15)))
def test_network_union_against_small_exhaustive_oracle(allowed: set[int]) -> None:
    approved = tuple(f"192.0.2.{n}/32" for n in allowed)
    witness = outside_networks("192.0.2.0/28", approved)
    missing = set(range(16)) - allowed
    assert (witness is None) == (not missing)
    if witness:
        assert int(witness.rsplit(".", 1)[1]) in missing


def test_cli_and_desktop_persist_profile_without_raw_community(tmp_path: Path) -> None:
    source = tmp_path / "switch.cfg"
    source.write_text(
        '; ArubaOS-Switch 16.10\nsnmp-server community "SENSITIVE" manager unrestricted\n'
    )
    profile = tmp_path / "profile.json"
    profile.write_text(PROFILE.model_dump_json(), encoding="utf-8")
    cli = CliRunner().invoke(
        app, ["analyze", str(source), "--complete-config", "--management-profile", str(profile)]
    )
    assert cli.exit_code == 0, cli.output
    assert json.loads(cli.stdout)["management_profile"]["approved_ntp_servers"] == ["192.0.2.2"]
    session = analyze_file(source, management_profile=PROFILE, configuration_complete=True)
    assert not hasattr(session, "errors")
    assert "SENSITIVE" not in json.dumps(_excerpts(session))
    changed = reanalyze_session(
        session, management_profile=ManagementProfile(allow_snmp_write=True)
    )
    assert not next(c for c in changed.report.checks if c.check_id == "MGMT-SNMP-WRITE").findings
    assert next(c for c in session.report.checks if c.check_id == "MGMT-SNMP-WRITE").findings
    assert (
        FirewallAssuranceResult.model_validate_json(session.report.model_dump_json())
        == session.report
    )


def test_cli_rejects_invalid_profile_without_echoing_input(tmp_path: Path) -> None:
    source = tmp_path / "switch.cfg"
    source.write_text("; ArubaOS-Switch 16.10\n")
    profile = tmp_path / "profile.json"
    profile.write_text('{"approved_ntp_servers": ["SENSITIVE:bad"]}')
    result = CliRunner().invoke(app, ["analyze", str(source), "--management-profile", str(profile)])
    assert result.exit_code == 2
    assert "SENSITIVE" not in result.output


def test_empty_banner_and_cx_supported_subset() -> None:
    check = next(c for c in report('banner motd ""').checks if c.check_id == "MGMT-BANNER")
    assert len(check.findings) == 1
    cx = report(
        "snmp-server snmpv3-only\nsession-timeout 16\nntp server 192.0.2.2 iburst\n",
        platform="aos-cx",
    )
    checks = {c.check_id: c for c in cx.checks}
    assert not checks["MGMT-SNMP-LEGACY"].findings
    assert len(checks["MGMT-IDLE-TIMEOUT"].findings) == 1
    assert not checks["MGMT-NTP-MISSING"].findings
    assert checks["MGMT-TELNET"].status == "partial"


def test_nested_commands_and_banner_acl_are_not_management_facts() -> None:
    result = report("interface 1\n telnet-server\n logging 192.0.2.1\n exit\n")
    assert not next(c for c in result.checks if c.check_id == "MGMT-TELNET").findings
    text = (
        "header login %\nacl number 2000\n rule 0 permit\n%\n"
        "user-interface vty 0 4\n acl 2000 inbound\n"
    )
    result = report(text, platform="comware")
    assert next(c for c in result.checks if c.check_id == "MGMT-ADMIN-SOURCES").status == "partial"


def test_all_ones_acl_wildcard_is_all_ipv4() -> None:
    result = report(
        "acl number 2000\n rule 0 permit source 0.0.0.0 255.255.255.255\n#\n"
        "user-interface vty 0 4\n acl 2000 inbound\n",
        platform="comware",
    )
    check = next(c for c in result.checks if c.check_id == "MGMT-ADMIN-SOURCES")
    assert check.status == "complete" and len(check.findings) == 1


def test_persisted_management_snapshot_roundtrip(tmp_path: Path) -> None:
    from firewall_compliance.interfaces.desktop.backend import AnalysisSession
    from firewall_compliance.interfaces.desktop.project_store import ProjectStore

    source = tmp_path / "switch.cfg"
    source.write_text(
        '; ArubaOS-Switch 16.10\nsnmp-server community "SENSITIVE" manager unrestricted\n'
    )
    session = analyze_file(source, management_profile=PROFILE, configuration_complete=True)
    assert isinstance(session, AnalysisSession)
    store = ProjectStore(tmp_path / "project.sqlite3")
    run = store.create_run(store.create_project("Test"))
    item = store.record_session(run, session)
    restored = store.attach_source(item, source)
    assert restored.revision == session.revision
    assert (
        reanalyze_session(restored).report.management_profile == session.report.management_profile
    )
    assert b"SENSITIVE" not in store.path.read_bytes()
