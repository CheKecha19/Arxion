"""Регрессии Comware: управление, маски и ограничения нормализации."""

from datetime import UTC, datetime

import pytest

from firewall_compliance.devices.network.hpe_h3c.comware.policy import ComwareParser
from firewall_compliance.domain import DataStatus, EndpointKind, ParseResult, RuleAction
from firewall_compliance.parsers.contracts import ParseFailure, ParseRequest, SourceDocument


def parse(text: str) -> ParseResult:
    if not text.startswith("version "):
        text = "version 7.1.045\n" + text
    now = datetime.now(UTC)
    outcome = ComwareParser().parse(
        ParseRequest(
            source=SourceDocument(
                source_name="synthetic-comware.txt", content=text.encode(), captured_at=now
            ),
            imported_at=now,
        )
    )
    assert isinstance(outcome, ParseResult)
    return outcome


def test_management_acl_and_source_mapping() -> None:
    result = parse(
        "version 7.1.045\nsysname LAB\nacl number 2000\n"
        " rule 5 permit source 192.0.2.10 0\n rule 10 deny source any\n#\n"
        "snmp-agent community read SYNTHETIC acl 2000\n"
    )
    assert len(result.rules) == 2
    assert result.rules[0].sources[0].cidrs == ("192.0.2.10/32",)
    assert result.rules[1].action == RuleAction.DENY
    assert result.rules[0].policy_id == "management:snmp:acl:2000"
    assert result.rules[0].source_zone == "management:snmp"
    assert result.rules[0].policy_semantics is None
    assert result.rules[0].destinations[0].kind == EndpointKind.ZONE
    assert result.rules[0].match_status == DataStatus.UNKNOWN
    assert result.rules[0].source_location.line_start == 4
    assert result.source_map[result.rules[0].rule_id] == result.rules[0].source_location
    assert "SYNTHETIC" not in result.model_dump_json()


@pytest.mark.parametrize(
    "address,mask,expected",
    [
        ("192.0.2.42", "0.0.0.255", "192.0.2.0/24"),
        ("192.0.2.42", "0", "192.0.2.42/32"),
    ],
)
def test_wildcard_is_inverse_mask(address: str, mask: str, expected: str) -> None:
    result = parse(f"sysname LAB\nacl number 2000\n rule 0 permit source {address} {mask}\n#")
    assert result.rules[0].sources[0].cidrs == (expected,)


@pytest.mark.parametrize(
    "address,mask", [("ip17", "0"), ("ip#17", "0"), ("192.0.2.1", "0.255.0.255")]
)
def test_masked_and_discontiguous_values_stay_unknown(address: str, mask: str) -> None:
    result = parse(f"sysname LAB\nacl number 2000\n rule 0 permit source {address} {mask}\n#")
    rule = result.rules[0]
    assert rule.sources[0].kind == EndpointKind.OBJECT
    assert rule.sources[0].resolution_status == DataStatus.UNKNOWN
    assert rule.match_status == DataStatus.UNKNOWN
    assert result.coverage.recognized_constructs == 0
    assert result.unsupported_constructs


def test_advanced_ports_and_logging() -> None:
    result = parse(
        "sysname LAB\nacl number 3000\n rule 10 permit tcp source any "
        "destination 198.51.100.10 0 destination-port eq 443 logging\n#"
    )
    rule = result.rules[0]
    assert rule.match_status == DataStatus.KNOWN
    assert rule.services[0].port_ranges[0].start == 443
    assert rule.logging_enabled is True


def test_unsupported_condition_is_not_dropped() -> None:
    result = parse(
        "sysname LAB\nacl number 3000\n rule 0 deny tcp source any destination any "
        "source-port eq 22\n rule 10 permit ip source any destination any\n#"
    )
    assert len(result.rules) == 2
    assert result.rules[0].action == RuleAction.DENY
    assert result.rules[0].match_status == DataStatus.UNSUPPORTED
    assert result.rules[1].match_status == DataStatus.KNOWN
    assert result.coverage.discovered_constructs == 2
    assert result.coverage.unsupported_constructs == 1


def test_invalid_ports_do_not_crash() -> None:
    result = parse("sysname LAB\nacl number 3000\n rule 0 permit tcp destination-port eq 70000\n#")
    assert result.rules[0].match_status == DataStatus.UNSUPPORTED


def test_masked_acl_number_does_not_hide_rules() -> None:
    result = parse(
        "sysname LAB\nacl number phone001\n rule 0 permit source ip1 0\n#\n"
        "snmp-agent community read SYNTHETIC acl phone001"
    )
    assert len(result.rules) == 1
    assert result.rules[0].policy_id == "management:snmp:acl:phone001"
    assert result.rules[0].match_status == DataStatus.UNKNOWN
    assert any(issue.code == "UNKNOWN_ACL_IDENTIFIER" for issue in result.warnings)


def test_huawei_marker_prevents_comware_detection() -> None:
    now = datetime.now(UTC)
    source = SourceDocument(
        source_name="synthetic.txt",
        captured_at=now,
        content=b"Huawei VRP\nversion 7.1.045\nacl number 2000",
    )
    assert not ComwareParser().detect(source).is_match


def test_does_not_claim_generic_or_junos_acl() -> None:
    now = datetime.now(UTC)
    for content in (
        b"acl number 2000\n rule 0 permit source any",
        b"set firewall family inet filter X",
    ):
        source = SourceDocument(source_name="unknown.txt", content=content, captured_at=now)
        assert not ComwareParser().detect(source).is_match
        assert isinstance(
            ComwareParser().parse(ParseRequest(source=source, imported_at=now)), ParseFailure
        )
