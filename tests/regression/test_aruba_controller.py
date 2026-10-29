"""Authored controller declarations; no real device exports or golden updates."""

from datetime import UTC, datetime

import pytest

from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.application.firewall_assurance import build_source_revision
from firewall_compliance.devices.network.hpe_aruba.arubaos_controller.policy import (
    ArubaControllerParser,
)
from firewall_compliance.domain import DataStatus, EndpointKind, ParseResult, Protocol, RuleAction
from firewall_compliance.domain.policy_matching import resolve_rule
from firewall_compliance.parsers.contracts import ParseFailure, ParseRequest, SourceDocument
from firewall_compliance.parsers.registry import ParserRegistry

AT = datetime(2026, 10, 28, tzinfo=UTC)
HEADER = "version 8.10.0.15\nhostname SYNTHETIC-CONTROLLER\n"


def document(rules="any any any permit", *, objects="", role="access-list session TEST position 1"):
    return SourceDocument(
        source_name="synthetic-controller.cfg",
        captured_at=AT,
        content=(
            HEADER
            + objects
            + f"ip access-list session TEST\n {rules}\n!\nuser-role employee\n {role}\n!\n"
        ).encode(),
    )


def parse(source=None, **kwargs):
    return ArubaControllerParser(**kwargs).parse(
        ParseRequest(source=source or document(), imported_at=AT)
    )


def success(source=None):
    result = parse(source)
    assert isinstance(result, ParseResult)
    return result


def test_metadata_detection_and_explicit_role_binding_survive_json():
    parser = ArubaControllerParser()
    assert parser.metadata.parser_id == "aruba-aos-controller"
    assert parser.metadata.version == "0.1.0"
    assert parser.detect(document()).confidence == 0.99
    result = success()
    assert result.configuration.platform == "arubaos-controller-8.10"
    assert result.configuration.content_sha256 == document().content_sha256
    assert result.configuration.device_id == "SYNTHETIC-CONTROLLER"
    assert result.rules[0].action == RuleAction.ALLOW
    assert result.rules[0].match_status == DataStatus.KNOWN
    assert result.rules[0].policy_direction is None
    assert result.rules[0].policy_semantics is None
    assert result.rules[0].source_zone is None
    (attachment,) = result.policy_attachments
    assert attachment.subject_id == "employee"
    assert attachment.subject_kind == "user_role"
    assert attachment.policy_id == result.rules[0].policy_id
    assert attachment.declaration_position == 1
    assert result.source_map[attachment.attachment_id] == attachment.source_location
    assert ParseResult.model_validate_json(result.model_dump_json()) == result
    assert "controller-role-binding:" not in result.model_dump_json()


@pytest.mark.parametrize("version", ["8.9.0.0", "8.11.0.0", "10.10.1000", "8.100.0", "8.10.future"])
def test_other_or_ambiguous_versions_are_rejected(version):
    source = document().model_copy(
        update={"content": document().content.replace(b"8.10.0.15", version.encode())}
    )
    assert not ArubaControllerParser().detect(source).is_match
    assert isinstance(parse(source), ParseFailure)


@pytest.mark.parametrize(
    "addition",
    [
        "ArubaOS-CX",
        "Aruba Instant",
        "Comware Software",
        "access-list ip MIX",
        "acl number 3000",
        "version 8.9.0.0",
    ],
)
def test_mixed_platform_headers_are_not_accepted(addition):
    source = document().model_copy(
        update={"content": document().content + addition.encode() + b"\n"}
    )
    assert not ArubaControllerParser().detect(source).is_match
    assert isinstance(parse(source), ParseFailure)


@pytest.mark.parametrize(
    "missing", [b"version 8.10.0.15\n", b"user-role employee", b"ip access-list session TEST"]
)
def test_detection_requires_all_format_evidence(missing):
    source = document().model_copy(update={"content": document().content.replace(missing, b"")})
    assert not ArubaControllerParser().detect(source).is_match


def test_aliases_explicit_services_and_provenance_are_preserved():
    objects = (
        "netdestination OPS\n host 192.0.2.10\n network 192.0.3.0 255.255.255.0\n!\n"
        "netdestination WEB\n range 198.51.100.1 198.51.100.16\n!\n"
        "netservice SECURE tcp 443\n"
    )
    result = success(document("alias OPS alias WEB SECURE permit log", objects=objects))
    (rule,) = result.rules
    assert rule.sources[0].cidrs == ("192.0.2.10/32", "192.0.3.0/24")
    assert rule.destinations[0].ip_ranges[0].end == "198.51.100.16"
    assert rule.services[0].protocol == Protocol.TCP
    assert rule.services[0].port_ranges[0].start == 443
    assert rule.logging_enabled is True
    assert result.source_map[rule.sources[0].endpoint_id].line_start == 3
    assert (
        result.source_map[rule.services[0].service_id].source_name
        == result.configuration.source_name
    )
    assert result.source_map[rule.rule_id] == rule.source_location


@pytest.mark.parametrize(
    "condition",
    [
        "host 192.0.2.1 any tcp 443",
        "network 192.0.2.0/24 any udp 53",
        "network 192.0.2.0 255.255.255.0 host 198.51.100.1 icmp",
    ],
)
def test_explicit_host_network_and_services(condition):
    result = success(document(condition + " deny"))
    assert result.rules[0].match_status == DataStatus.KNOWN
    assert result.rules[0].action == RuleAction.DENY


@pytest.mark.parametrize(
    "service,ports", [("tcp 20 22", (20, 22)), ("udp list 53,123,161", (53, 161))]
)
def test_netservice_range_and_list(service, ports):
    result = success(
        document("any any SELECTED permit", objects=f"netservice SELECTED {service}\n")
    )
    chosen = result.rules[0].services[0]
    assert chosen.port_ranges[0].start == ports[0]
    assert chosen.port_ranges[-1].end == ports[-1]


@pytest.mark.parametrize(
    "entry",
    [
        "user any tcp 443 permit",
        "localip any any permit",
        "userrole admin any any permit",
        "ipv6 any any any permit",
        "any any app web permit",
        "any any tcp source 22 permit",
        "any any tcp 443 permit time-range WORK",
        "any any tcp 443 src-nat",
        "any any tcp 0 permit",
        "any any svc-implicit permit",
        "any any 47 permit",
        "any any any permit position 1",
        "host invalid any any permit",
    ],
)
def test_unsupported_entry_is_retained_and_never_becomes_known_any(entry):
    result = success(document(entry))
    (rule,) = result.rules
    assert rule.match_status != DataStatus.KNOWN
    assert result.unsupported_constructs
    assert result.coverage.unsupported_constructs >= 1
    assert rule.source_location == result.source_map[rule.rule_id]
    revision = build_source_revision(
        document(entry), ParserRegistry([ArubaControllerParser()]), imported_at=AT
    )
    assert not isinstance(revision, ParseFailure)
    report = analyze_firewall(revision)
    any_check = next(check for check in report.checks if check.check_id == "FW-ANY-ANY")
    assert not any_check.findings


@pytest.mark.parametrize(
    "member",
    [
        "invert",
        "name *.example.invalid",
        "host vlan 2 offset 1",
        "alias OTHER",
        "range 192.0.2.1 192.0.2.17",
        "host not-ip",
        "network 192.0.2.0 255.0.255.0",
    ],
)
def test_any_unknown_alias_member_poison_entire_group(member):
    result = success(
        document(
            "alias A any any permit", objects=f"netdestination A\n host 192.0.2.1\n {member}\n!\n"
        )
    )
    assert result.rules[0].sources[0].resolution_status == DataStatus.UNSUPPORTED
    assert result.rules[0].sources[0].kind != EndpointKind.ANY
    assert result.rules[0].sources[0].cidrs == ()


def test_alias_cycle_and_empty_alias_remain_unknown_without_recursive_resolution():
    objects = (
        "netdestination A\n alias B\n!\nnetdestination B\n alias A\n!\nnetdestination EMPTY\n!\n"
    )
    result = success(document("alias A any any permit\n alias EMPTY any any deny", objects=objects))
    assert all(rule.match_status == DataStatus.UNSUPPORTED for rule in result.rules)
    assert any(issue.code == "CONTROLLER_ALIAS_UNSUPPORTED" for issue in result.warnings)


@pytest.mark.parametrize(
    "definition", ["tcp 0", "tcp 10 1", "tcp 443 ALG ftp", "17", "tcp", "udp list 1,2,3,4,5,6,7"]
)
def test_invalid_or_unrepresentable_netservice_not_promoted_to_any(definition):
    result = success(document("any any BAD permit", objects=f"netservice BAD {definition}\n"))
    assert result.rules[0].services[0].resolution_status == DataStatus.UNSUPPORTED


def test_duplicate_alias_service_and_acl_definitions_do_not_gain_known_conditions():
    objects = (
        "netdestination A\n host 192.0.2.1\n!\n"
        "netdestination A\n host 198.51.100.1\n!\n"
        "netservice S tcp 443\nnetservice S tcp 22\n"
    )
    result = success(document("alias A any S permit", objects=objects))
    assert result.rules[0].match_status == DataStatus.UNSUPPORTED
    source = document().model_copy(
        update={
            "content": document().content + b"ip access-list session TEST\n any any any deny\n!\n"
        }
    )
    result = success(source)
    assert len(result.rules) == 2
    assert all(rule.match_status == DataStatus.UNSUPPORTED for rule in result.rules)


def test_role_qualifiers_unresolved_acl_and_repeated_attachments_are_explicit():
    result = success(
        document(role="access-list session MISSING ap-group SITE position 2\n session-acl TEST")
    )
    assert len(result.policy_attachments) == 2
    assert result.policy_attachments[0].scope_reference == "ap-group:SITE"
    assert result.policy_attachments[1].declaration_position is None
    assert any(issue.code == "CONTROLLER_BINDING_WITHOUT_ACL" for issue in result.warnings)
    duplicate = success(document(role="session-acl TEST\n session-acl TEST"))
    assert len({item.attachment_id for item in duplicate.policy_attachments}) == 2


@pytest.mark.parametrize(
    "role",
    [
        "access-list session TEST position 0",
        "access-list eth TEST",
        "access-list session TEST strange flag",
        "vlan 10",
    ],
)
def test_unknown_role_options_are_not_implicit_transit_bindings(role):
    result = success(document(role=role))
    assert not result.policy_attachments
    assert any(issue.code == "CONTROLLER_ROLE_UNSUPPORTED" for issue in result.warnings)


def test_byte_line_object_rule_budgets_fail_explicitly():
    for values in ({"max_bytes": 5}, {"max_lines": 1}, {"max_objects": 1}, {"max_rules": 1}):
        source = document("any any any permit\n any any any deny", objects="netdestination A\n!\n")
        assert isinstance(parse(source, **values), ParseFailure)


@pytest.mark.parametrize("value", [False, 0, -1, 1.5])
def test_invalid_budget_is_rejected(value):
    with pytest.raises(ValueError):
        ArubaControllerParser(max_rules=value)


def test_invalid_utf8_is_failure_and_detection_false():
    source = document().model_copy(update={"content": b"\xff"})
    assert not ArubaControllerParser().detect(source).is_match
    assert isinstance(parse(source), ParseFailure)


def test_quotes_and_rule_source_mapping_are_not_lost_on_parse_failure():
    result = success(document('any any "broken permit'))
    assert len(result.rules) == 1
    assert result.rules[0].match_status == DataStatus.UNSUPPORTED
    assert result.coverage.unsupported_constructs


def test_unprefixed_any_is_ipv4_only_and_any_any_check_still_detects_wide_ipv4_allow():
    result = success()
    match = resolve_rule(result.rules[0])
    assert match is not None and match.sources[0] == ((0, 2**32 - 1),)
    assert match.sources[1] == match.destinations[1] == ()
    revision = build_source_revision(
        document(), ParserRegistry([ArubaControllerParser()]), imported_at=AT
    )
    report = analyze_firewall(revision)
    assert (
        len(next(check for check in report.checks if check.check_id == "FW-ANY-ANY").findings) == 1
    )


@pytest.mark.parametrize("inline", ["tcp 20 22", "tcp list 22,443", "udp", "tcp source 22"])
def test_inline_service_does_not_inherit_netservice_range_or_list_grammar(inline):
    result = success(document(f"any any {inline} permit"))
    assert result.rules[0].match_status == DataStatus.UNSUPPORTED


def test_netservice_protocol_one_is_icmp_without_port_guessing():
    result = success(document("any any PING permit", objects="netservice PING 1\n"))
    assert result.rules[0].services[0].protocol == Protocol.ICMP
    assert result.rules[0].services[0].port_ranges == ()
