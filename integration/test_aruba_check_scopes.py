"""Полнота отдельных ACL не подменяется общим предупреждением о платформе."""

from pathlib import Path

from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file


def session(tmp_path: Path, body: str) -> AnalysisSession:
    path = tmp_path / "scope.cfg"
    path.write_text("!Version ArubaOS-CX FL.10.13.1000\nhostname SCOPE\n" + body, encoding="utf-8")
    result = analyze_file(path)
    assert isinstance(result, AnalysisSession)
    return result


GOOD = """access-list ip GOOD
 10 permit tcp any any eq 443
 20 permit tcp any any eq 443
!
interface 1/1/1
 apply access-list ip GOOD in
!
"""


def test_scope_warning_does_not_disable_known_acl(tmp_path: Path) -> None:
    result = session(tmp_path, GOOD)
    checks = {check.check_id: check for check in result.report.checks}
    assert result.parse_result.coverage.coverage_ratio == 1
    assert any(w.code == "HP_ARUBA_SCOPE_LIMITED" for w in result.report.parse_warnings)
    assert checks["FW-DUPLICATE"].status.value == "complete"
    assert len(checks["FW-DUPLICATE"].findings) == 1
    assert checks["FW-SHADOWED"].status.value == "complete"
    assert result.report.check_catalog_version == "1.2.0"
    assert checks["FW-DUPLICATE"].check_version == "1.1.0"


def test_unrelated_bad_acl_does_not_hide_valid_duplicates(tmp_path: Path) -> None:
    result = session(
        tmp_path,
        GOOD
        + """access-list ip BAD
 10 permit tcp ip#1 any eq 443
 20 unsupported-ace
!
interface 1/1/2
 apply access-list ip BAD in
!
""",
    )
    check = next(c for c in result.report.checks if c.check_id == "FW-DUPLICATE")
    assert check.status.value == "partial"
    assert len(check.findings) == 1
    assert any(limitation.code == "INCOMPLETE_ACL" for limitation in check.limitations)
    assert not any(limitation.code == "CHECK_NOT_EXECUTED" for limitation in check.limitations)


def test_unknown_ace_blocks_its_entire_acl(tmp_path: Path) -> None:
    result = session(tmp_path, GOOD.replace(" 20 permit", " 15 unsupported-ace\n 20 permit"))
    check = next(c for c in result.report.checks if c.check_id == "FW-DUPLICATE")
    assert not check.findings
    assert any(limitation.code == "CHECK_NOT_EXECUTED" for limitation in check.limitations)


def test_unbound_acl_is_not_claimed_as_checked(tmp_path: Path) -> None:
    result = session(tmp_path, GOOD.split("interface")[0])
    check = next(c for c in result.report.checks if c.check_id == "FW-DUPLICATE")
    assert check.status.value == "partial"
    assert any(limitation.code == "UNKNOWN_SCOPE" for limitation in check.limitations)
    assert any(limitation.code == "CHECK_NOT_EXECUTED" for limitation in check.limitations)


def test_missing_binding_target_does_not_prove_other_acls_complete(tmp_path: Path) -> None:
    result = session(tmp_path, GOOD + "interface 1/1/3\n apply access-list ip MISSING in\n")
    check = next(c for c in result.report.checks if c.check_id == "FW-DUPLICATE")
    assert check.status.value == "partial"
    assert not check.findings
    assert any(limitation.code == "CHECK_NOT_EXECUTED" for limitation in check.limitations)


def test_comment_and_logging_do_not_invalidate_packet_matches(tmp_path: Path) -> None:
    result = session(
        tmp_path,
        GOOD.replace(" 10 permit", " 10 comment HTTPS\n 10 permit").replace("eq 443", "eq 443 log"),
    )
    checks = {check.check_id: check for check in result.report.checks}
    assert checks["FW-ANY-ANY"].status.value == "complete"
    assert checks["FW-LOGGING"].status.value == "complete"
    assert not checks["FW-LOGGING"].findings
    assert len(checks["FW-COMMENTS"].findings) == 1
    assert len(checks["FW-DUPLICATE"].findings) == 1


def test_unknown_logging_version_only_limits_metadata(tmp_path: Path) -> None:
    result = session(tmp_path, GOOD.replace("eq 443", "eq 443 log"))
    path = tmp_path / "scope.cfg"
    path.write_text(path.read_text().replace("10.13", "synthetic"))
    result = analyze_file(path)
    assert isinstance(result, AnalysisSession)
    checks = {check.check_id: check for check in result.report.checks}
    assert checks["FW-ANY-ANY"].status.value == "complete"
    assert checks["FW-LOGGING"].status.value == "partial"
    assert any(limit.code == "CHECK_NOT_EXECUTED" for limit in checks["FW-LOGGING"].limitations)
    assert not any(
        limit.code == "CHECK_NOT_EXECUTED" for limit in checks["FW-DUPLICATE"].limitations
    )


def test_supported_descriptions_enable_merge_and_are_evidence(tmp_path: Path) -> None:
    result = session(
        tmp_path,
        GOOD.replace(
            " 10 permit tcp any any eq 443\n 20 permit tcp any any eq 443",
            " 10 comment Web\n 10 permit tcp 192.0.2.0/24 any eq 443\n"
            " 20 comment Web\n 20 permit tcp 198.51.100.0/24 any eq 443",
        ),
    )
    checks = {check.check_id: check for check in result.report.checks}
    assert not checks["FW-COMMENTS"].findings
    merge = checks["FW-MERGE-CANDIDATE"]
    assert merge.status.value == "complete"
    assert len(merge.findings) == 1
    locations = merge.findings[0].evidence.source_locations
    for rule in result.parse_result.rules:
        assert result.parse_result.source_map[f"description:{rule.rule_id}"] in locations
        assert result.parse_result.source_map[f"binding:{rule.rule_id}"] in locations


def test_earlier_deny_can_shadow_later_permit(tmp_path: Path) -> None:
    result = session(tmp_path, GOOD.replace("10 permit tcp any any eq 443", "10 deny any any any"))
    check = next(c for c in result.report.checks if c.check_id == "FW-SHADOWED")
    assert check.status.value == "complete"
    assert len(check.findings) == 1
