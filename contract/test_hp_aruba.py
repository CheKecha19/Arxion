"""Контракт HP/Aruba: management отдельно, маски и suffix без расширения условий."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from firewall_compliance.analysis.policy_matching import resolve_rule
from firewall_compliance.domain import DataStatus, EndpointKind, ParseResult, Protocol
from firewall_compliance.parsers.contracts import ParseFailure, ParseRequest, SourceDocument
from firewall_compliance.parsers.hp_aruba import HpArubaParser

ROOT = Path(__file__).parents[1] / "fixtures" / "hp_aruba"
TIME = datetime(2026, 1, 1, tzinfo=UTC)


def request(content: str | bytes, name: str = "synthetic.txt") -> ParseRequest:
    return ParseRequest(
        source=SourceDocument(
            source_name=name,
            content=content.encode() if isinstance(content, str) else content,
            captured_at=TIME,
        ),
        imported_at=TIME,
    )


def parse(content: str | bytes, name: str = "synthetic.txt") -> ParseResult:
    result = HpArubaParser().parse(request(content, name))
    assert isinstance(result, ParseResult)
    return result


@pytest.mark.parametrize(
    "content,platform",
    [
        ("; J0000A Configuration Editor; synthetic\nhostname demo\n", "aos-switch"),
        ("ip authorized-managers 192.0.2.10 255.255.255.255 access manager\n", "aos-switch"),
        (
            "!Version ArubaOS-CX synthetic\naccess-list ip EXAMPLE\n 10 permit any any any\n",
            "aos-cx",
        ),
        (
            "access-list ip EXAMPLE\n 10 permit any any any\n!\n"
            "interface 1/1/1\n apply access-list ip EXAMPLE in\n",
            "aos-cx",
        ),
    ],
)
def test_detection_uses_positive_content_not_extension(content: str, platform: str) -> None:
    parser = HpArubaParser()
    assert parser.detect(request(content, "not-an-aruba-file.bin").source).is_match
    assert parse(content).configuration.platform == platform


@pytest.mark.parametrize(
    "content",
    [
        "hostname my-aos-cx\ninterface 1\n",
        "ip access-list extended WEB\n 10 permit ip any any\n",
        "ASA Version 9.16\naccess-list X extended permit ip any any\n"
        "access-group X in interface outside\n",
        "set version 22.4R1\nset firewall family inet filter F term T then accept\n",
    ],
)
def test_generic_cisco_or_juniper_syntax_does_not_claim_aruba(content: str) -> None:
    parser = HpArubaParser()
    assert not parser.detect(request(content, "aruba.cfg").source).is_match
    assert isinstance(parser.parse(request(content)), ParseFailure)


def test_aos_switch_fixture_preserves_wildcard_rules_and_each_binding_scope() -> None:
    result = parse((ROOT / "aos_switch.cfg").read_bytes(), "aos_switch.cfg")
    assert result.configuration.vendor == "hp-aruba"
    assert len(result.rules) == 13
    web = [rule for rule in result.rules if rule.name == "WEB sequence 10"]
    assert len(web) == 2
    assert web[0].sources[0].cidrs == ("198.51.100.0/24",)
    assert web[0].destinations[0].cidrs == ("203.0.113.10/32",)
    assert web[0].services[0].port_ranges[0].start == 443
    assert {rule.policy_direction for rule in web} == {"in", "out"}
    assert len({rule.policy_id for rule in web}) == 2
    assert any(rule.source_zone == "vlan:20:routed-in" for rule in web)
    assert any(rule.destination_zone == "vlan:30:out" for rule in web)
    assert all(resolve_rule(rule) is not None for rule in web)
    assert all(result.source_map[rule.rule_id] == rule.source_location for rule in result.rules)
    assert any(key.startswith("binding:") for key in result.source_map)
    assert ParseResult.model_validate_json(result.model_dump_json()) == result


def test_authorized_managers_are_not_transit_or_any_any() -> None:
    result = parse((ROOT / "aos_switch.cfg").read_bytes())
    managers = [rule for rule in result.rules if (rule.policy_id or "").startswith("management:")]
    assert len(managers) == 2
    assert all(rule.destination_zone == "management-plane" for rule in managers)
    assert all(rule.destinations[0].kind == EndpointKind.ZONE for rule in managers)
    assert all(rule.match_status == DataStatus.UNKNOWN for rule in managers)
    assert all(rule.policy_semantics is None for rule in managers)
    assert all(resolve_rule(rule) is None for rule in managers)
    masked = managers[1].sources[0]
    assert masked.name == "ip17"
    assert masked.kind == EndpointKind.OBJECT
    assert masked.resolution_status == DataStatus.UNKNOWN
    assert masked.cidrs == ()
    assert not any(w.code == "HP_ARUBA_MANAGER_SUFFIX_UNSUPPORTED" for w in result.warnings)


def test_masked_manager_netmask_never_defaults_to_a_known_host() -> None:
    result = parse("ip authorized-managers 192.0.2.5 ip#8 access manager access-method ssh\n")
    assert result.rules[0].sources[0].name == "192.0.2.5"
    assert result.rules[0].source_status == DataStatus.UNKNOWN
    assert result.rules[0].sources[0].cidrs == ()


def test_unknown_manager_suffix_is_reported_and_never_becomes_transit() -> None:
    result = parse(
        "ip authorized-managers 192.0.2.5 255.255.255.255 access manager invalid-option\n"
    )
    assert result.rules[0].match_status == DataStatus.UNKNOWN
    assert result.rules[0].destination_zone == "management-plane"
    assert any(w.code == "HP_ARUBA_MANAGER_SUFFIX_UNSUPPORTED" for w in result.warnings)


def test_cx_cidr_bindings_and_control_plane_do_not_mix() -> None:
    result = parse((ROOT / "aos_cx.cfg").read_bytes())
    assert result.configuration.platform == "aos-cx"
    assert len(result.rules) == 10
    known = [rule for rule in result.rules if rule.name == "EDGE sequence 10"]
    assert all(rule.match_status == DataStatus.KNOWN for rule in known)
    assert known[0].sources[0].cidrs == ("198.51.100.0/24",)
    assert known[0].services[0].protocol == Protocol.TCP
    assert known[0].services[0].port_ranges[0].start == 443
    assert {rule.policy_direction for rule in known} == {"in", "out"}
    controls = [rule for rule in result.rules if (rule.policy_id or "").startswith("management:")]
    assert len(controls) == 2
    assert all(rule.destination_zone == "management-plane:vrf:default" for rule in controls)
    assert all(resolve_rule(rule) is None for rule in controls)


@pytest.mark.parametrize(
    "tail", ["established", "dscp 46", "fragment", "log garbage", "count count"]
)
def test_unknown_suffix_never_becomes_unrestricted_known_match(tail: str) -> None:
    result = parse(
        "!Version ArubaOS-CX synthetic\naccess-list ip EDGE\n"
        f" 10 permit tcp any any eq 443 {tail}\n"
    )
    assert len(result.rules) == 1
    assert result.rules[0].match_status == DataStatus.UNKNOWN
    assert resolve_rule(result.rules[0]) is None
    assert result.unsupported_constructs


@pytest.mark.parametrize("address", ["ip9", "ip#9", "ip#17/24"])
def test_masked_endpoint_preserves_original_name_without_any_or_random_ip(address: str) -> None:
    result = parse(
        f"!Version ArubaOS-CX synthetic\naccess-list ip EDGE\n 10 permit udp {address} any eq 53\n"
    )
    rule = result.rules[0]
    assert rule.sources[0].name == address
    assert rule.sources[0].kind == EndpointKind.OBJECT
    assert not rule.sources[0].cidrs
    assert rule.source_status == DataStatus.UNKNOWN
    assert rule.match_status == DataStatus.UNKNOWN


def test_source_port_and_non_contiguous_wildcard_remain_unknown() -> None:
    cx = parse(
        "!Version ArubaOS-CX synthetic\naccess-list ip EDGE\n"
        " 10 permit tcp any eq 1024 any eq 443\n"
    )
    assert cx.rules[0].service_status == DataStatus.UNKNOWN
    assert resolve_rule(cx.rules[0]) is None
    switch = parse(
        "; J0000A Configuration Editor\nip access-list extended EDGE\n"
        " 10 permit ip 192.0.2.0 0.255.0.255 any\n"
    )
    assert switch.rules[0].source_status == DataStatus.UNKNOWN
    assert switch.rules[0].sources[0].kind == EndpointKind.OBJECT


def test_duplicate_sequence_does_not_claim_first_match_order() -> None:
    result = parse(
        "!Version ArubaOS-CX synthetic\naccess-list ip EDGE\n"
        " 10 deny any any any\n 10 permit any any any\n"
    )
    assert len(result.rules) == 2
    assert all(rule.policy_semantics is None for rule in result.rules)
    assert all(rule.match_status == DataStatus.UNKNOWN for rule in result.rules)


def test_invalid_or_missing_ace_and_binding_have_diagnostics_without_fake_rules() -> None:
    result = parse(
        "!Version ArubaOS-CX synthetic\naccess-list ip EDGE\n"
        " 10 permit tcp any\n!\napply access-list ip EDGE in\n"
    )
    assert result.rules == ()
    assert result.unsupported_constructs
    assert any(w.code == "HP_ARUBA_ACE_INVALID" for w in result.warnings)
    assert any(w.code == "HP_ARUBA_BINDING_UNSUPPORTED" for w in result.warnings)
    assert result.coverage.recognized_constructs <= result.coverage.discovered_constructs


def test_controller_is_recognized_but_explicitly_unsupported() -> None:
    content = (
        "ip access-list session EXAMPLE\n any any svc-https permit\n"
        "user-role EXAMPLE\n access-list session EXAMPLE\n"
    )
    parser = HpArubaParser()
    assert parser.detect(request(content).source).is_match
    result = parser.parse(request(content))
    assert isinstance(result, ParseFailure)
    assert result.errors[0].code == "ARUBAOS_CONTROLLER_UNSUPPORTED"


def test_invalid_encoding_returns_typed_failure() -> None:
    result = HpArubaParser().parse(request(b"\xff\xfe"))
    assert isinstance(result, ParseFailure)
    assert result.errors[0].code == "HP_ARUBA_ENCODING"


@pytest.mark.parametrize("style", ["block", "inline", "numbered"])
def test_switch_remark_binds_next_ace_without_consuming_sequence(style: str) -> None:
    body = {
        "block": 'ip access-list extended EDGE\n remark "Allow web"\n permit tcp any any eq 443\n',
        "inline": 'ip access-list extended EDGE remark "Allow web"\n'
        "ip access-list extended EDGE permit tcp any any eq 443\n",
        "numbered": 'access-list 100 remark "Allow web"\n'
        "access-list 100 permit tcp any any eq 443\n",
    }[style]
    result = parse("; Configuration Editor\n" + body)
    rule = result.rules[0]
    assert rule.sequence == 10
    assert rule.description == "Allow web"
    assert rule.description_status == DataStatus.KNOWN
    remark_line = 3 if style == "block" else 2
    assert result.source_map[f"description:{rule.rule_id}"].line_start == remark_line
    assert rule.source_location.line_start == (4 if style == "block" else 3)
    assert not any(w.code == "HP_ARUBA_COMMENT_LIMITED" for w in result.warnings)


def test_cx_comment_sequence_can_follow_ace_and_does_not_leak_to_other_acl() -> None:
    result = parse(
        "!Version ArubaOS-CX FL.10.13.1000\naccess-list ip EDGE\n"
        " 10 permit tcp any any eq 443 log\n 10 comment Allow web\n!\n"
        "access-list ip OTHER\n 10 deny any any any\n"
    )
    first, second = result.rules
    assert first.description == "Allow web"
    assert first.description_status == DataStatus.KNOWN
    assert first.logging_enabled is True
    assert second.description is None
    assert second.description_status == DataStatus.ABSENT
    assert result.source_map[f"description:{first.rule_id}"].line_start == 4


@pytest.mark.parametrize(
    "header,known",
    [
        ("; Configuration Editor; Created on release #WC.16.10.0001", True),
        ("; Configuration Editor; Created on release #WC.16.05.0001", False),
        ("; Configuration Editor", False),
        ("!Version ArubaOS-CX FL.10.13.1000", True),
        ("!Version ArubaOS-CX FL.10.07.1000", False),
        ("!Version ArubaOS-CX synthetic", False),
    ],
)
def test_permit_logging_is_release_aware_without_losing_packet_matches(
    header: str, known: bool
) -> None:
    acl = "access-list ip EDGE" if "CX" in header else "ip access-list extended EDGE"
    result = parse(f"{header}\n{acl}\n 10 permit tcp any any eq 443 log\n")
    rule = result.rules[0]
    assert rule.match_status == DataStatus.KNOWN
    assert rule.logging_status == (DataStatus.KNOWN if known else DataStatus.UNKNOWN)
    assert rule.logging_enabled == (True if known else None)


def test_orphan_conflicting_and_unnumbered_cx_comments_remain_diagnostic() -> None:
    result = parse(
        "!Version ArubaOS-CX synthetic\naccess-list ip EDGE\n"
        " 10 deny any any any\n 10 comment one\n 10 comment two\n"
        " 20 comment no matching ace\n comment no explicit sequence\n"
    )
    assert result.rules[0].description_status == DataStatus.UNKNOWN
    assert any(w.code == "HP_ARUBA_COMMENT_LIMITED" for w in result.warnings)


def test_acl_issue_ranges_include_unparsed_children_and_unsupported_binding() -> None:
    result = parse(
        "!Version ArubaOS-CX synthetic\naccess-list ip EDGE\n"
        " 10 permit tcp any\n unsupported-condition\n!\n"
        "interface 1/1/1\n apply access-list ip EDGE impossible\n"
    )
    assert result.source_map["acl-range:EDGE:3"].line_start == 3
    assert result.source_map["acl-range:EDGE:4"].line_start == 4
    assert result.source_map["acl-binding:EDGE:7"].line_start == 7


def test_broken_comment_quote_cannot_become_proven_absence() -> None:
    result = parse(
        '!Version ArubaOS-CX synthetic\naccess-list ip EDGE\n 10 comment "unterminated\n'
        " 10 deny any any any\n"
    )
    assert result.rules[0].description_status == DataStatus.UNKNOWN
    assert result.rules[0].match_status == DataStatus.KNOWN
    assert result.unsupported_constructs[0].construct_type == "comment"
