"""Проверки первого ограниченного parser adapter Cisco ASA."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from firewall_compliance.domain import DataStatus, ParseResult, Protocol, RuleAction
from firewall_compliance.parsers import CiscoAsaParser, ParseFailure, ParseRequest, SourceDocument

FIXTURES_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "candidates" / "cisco-asa"
CAPTURED_AT = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
IMPORTED_AT = datetime(2026, 10, 9, 12, 1, tzinfo=UTC)


def parse_fixture(name: str) -> ParseResult:
    """Разобрать fixture с фиксированным временем для воспроизводимых проверок."""
    source_path = FIXTURES_DIRECTORY / name
    outcome = CiscoAsaParser().parse(
        ParseRequest(
            source=SourceDocument(
                source_name=name,
                content=source_path.read_bytes(),
                captured_at=CAPTURED_AT,
            ),
            imported_at=IMPORTED_AT,
        )
    )
    assert isinstance(outcome, ParseResult)
    return outcome


def test_manifest_preserves_fixture_hashes_and_gate_coverage() -> None:
    """Quality gate допускает только неизменённые обезличенные сценарии."""
    manifest = json.loads((FIXTURES_DIRECTORY / "manifest.json").read_text(encoding="utf-8"))

    assert len(manifest["fixtures"]) == 3
    for fixture in manifest["fixtures"]:
        content = (FIXTURES_DIRECTORY / fixture["name"]).read_bytes()
        assert sha256(content).hexdigest() == fixture["sha256"]


def test_detection_requires_asa_acl_and_context() -> None:
    """Один access-list не создаёт ложного положительного распознавания ASA."""
    parser = CiscoAsaParser()
    recognized = SourceDocument(
        source_name="asa.cfg",
        content=(FIXTURES_DIRECTORY / "asa_basic_access.cfg").read_bytes(),
        captured_at=CAPTURED_AT,
    )
    unrelated = SourceDocument(
        source_name="acl.txt",
        content=b"access-list TEST extended permit ip any any\n",
        captured_at=CAPTURED_AT,
    )

    assert parser.detect(recognized).is_match is True
    assert parser.detect(unrelated).is_match is False


def test_basic_acl_preserves_blocking_rule_logging_and_source_mapping() -> None:
    """Permit и deny остаются отдельными правилами со ссылками на строки источника."""
    result = parse_fixture("asa_basic_access.cfg")

    assert tuple(rule.action for rule in result.rules) == (RuleAction.ALLOW, RuleAction.DENY)
    assert all(rule.logging_enabled is True for rule in result.rules)
    assert all(rule.source_zone == "outside" for rule in result.rules)
    assert tuple(location.line_start for location in result.source_map.values()) == (3, 4)
    assert result.rules[0].services[0].port_ranges[0].start == 443


def test_objects_and_groups_are_resolved_into_canonical_rules() -> None:
    """Группы и сервисные объекты дают канонические адреса и TCP-порт."""
    result = parse_fixture("asa_objects_and_groups.cfg")

    first_rule = result.rules[0]
    assert first_rule.sources[0].cidrs == ("198.51.100.0/24",)
    assert first_rule.destinations[0].cidrs == ("192.0.2.20/32",)
    assert first_rule.services[0].port_ranges[0].start == 443
    assert first_rule.services[0].port_ranges[0].end == 443


def test_nat_is_reported_as_unsupported_without_hiding_acl_rules() -> None:
    """Неподдержанный NAT не удаляет доступные для анализа правила ACL."""
    result = parse_fixture("asa_nat_unsupported.cfg")

    assert len(result.rules) == 2
    assert result.unsupported_constructs[0].construct_type == "nat"
    assert result.warnings[0].code == "UNSUPPORTED_NAT"
    assert result.coverage.unsupported_constructs == 1


@pytest.mark.parametrize(
    "name",
    ["asa_basic_access.cfg", "asa_objects_and_groups.cfg", "asa_nat_unsupported.cfg"],
)
def test_all_fixture_rules_have_source_mapping(name: str) -> None:
    """Каждый policy result остаётся трассируемым до строки конфигурации."""
    result = parse_fixture(name)

    assert all(result.source_map[rule.rule_id] == rule.source_location for rule in result.rules)


def parse_config(content: str) -> ParseResult:
    """Разобрать synthetic config без файлов и изменений golden results."""
    result = CiscoAsaParser().parse(
        ParseRequest(
            source=SourceDocument(
                source_name="synthetic.cfg", content=content.encode(), captured_at=CAPTURED_AT
            ),
            imported_at=IMPORTED_AT,
        )
    )
    assert isinstance(result, ParseResult)
    return result


@pytest.mark.parametrize(
    "name",
    ["asa_basic_access.cfg", "asa_objects_and_groups.cfg", "asa_nat_unsupported.cfg"],
)
def test_supported_fixtures_have_explicit_policy_semantics(name: str) -> None:
    result = parse_fixture(name)

    assert result.configuration.parser_version == "0.2.0"
    for rule in result.rules:
        assert rule.policy_id == rule.name.split()[0]
        assert rule.policy_direction == "in"
        assert rule.policy_semantics == "first_match"
        assert rule.match_status == DataStatus.KNOWN
        assert rule.description_status == DataStatus.ABSENT


@pytest.mark.parametrize(
    ("suffix", "enabled", "logging"),
    [
        ("", True, False),
        ("log", True, True),
        ("log disable", True, False),
        ("inactive", False, False),
        ("log inactive", False, True),
        ("inactive log disable", False, False),
        ("log disable inactive", False, False),
    ],
)
def test_suffixes_are_consumed_completely(suffix: str, enabled: bool, logging: bool) -> None:
    result = parse_config(
        f"access-list A extended permit ip any any {suffix}\naccess-group A in interface inside\n"
    )

    assert len(result.rules) == 1
    rule = result.rules[0]
    assert rule.enabled is enabled
    assert rule.logging_enabled is logging
    assert rule.logging_status == DataStatus.KNOWN
    assert rule.match_status == DataStatus.KNOWN
    assert not result.warnings
    assert result.coverage.coverage_ratio == 1


@pytest.mark.parametrize(
    "ace",
    [
        "permit ip any any time-range OFFICE",
        "permit icmp any any echo",
        "permit tcp any eq 1024 any eq 443",
        "permit tcp any any neq 80",
        "permit tcp any any lt 1024",
        "permit tcp any any gt 1024",
        "permit tcp any any established",
        "permit ip any any log informational",
        "permit ip any any log interval 60",
        "permit ip any any log log",
        "permit ip any any inactive inactive",
        "permit ip any any disable",
        "permit ip any any log disable extra",
        "permit gre any any",
        "permit 6 any any",
        "permit ip any4 any4",
        "permit ip any6 any6",
        "permit ip any host 2001:db8::1",
        "permit tcp any any eq https extra",
        "permit ip any any eq 80",
        "permit udp any any range 1000 2000 extra",
    ],
)
def test_unknown_match_conditions_omit_ace_with_location(ace: str) -> None:
    result = parse_config(
        f"access-list A extended {ace}\n"
        "access-list A extended deny ip any any\n"
        "access-group A in interface inside\n"
    )

    assert len(result.rules) == 1
    assert result.rules[0].action == RuleAction.DENY
    assert result.rules[0].sequence == 2
    assert len(result.warnings) == 1
    issue = result.warnings[0]
    assert issue.code == "UNSUPPORTED_ACCESS_LIST"
    assert issue.source_location is not None
    assert issue.source_location.line_start == 1
    assert issue.source_location.source_name == "synthetic.cfg"
    assert result.coverage.coverage_ratio == 0.5
    assert result.unsupported_constructs[0].source_location == issue.source_location


@pytest.mark.parametrize(
    "ace",
    [
        "permit",
        "permit tcp",
        "permit ip any",
        "permit ip any host invalid",
        "permit tcp any any eq",
        "permit tcp any any range 443",
        "permit tcp any any eq nonsense",
        "permit tcp any any eq -1",
        "permit tcp any any eq 0",
        "permit tcp any any eq 65536",
        "permit tcp any any range 443 80",
        "permit tcp any any range x y",
        "permit ip 192.0.2.0 255.0.255.0 any",
        "permit ip 192.0.2.0 0.0.0.255 any",
    ],
)
def test_malformed_aces_do_not_abort_independent_rules(ace: str) -> None:
    result = parse_config(
        f"access-list A extended {ace}\n"
        "access-list A extended permit ip any any\n"
        "access-group A in interface inside\n"
    )

    assert len(result.rules) == 1
    assert result.rules[0].sequence == 2
    assert result.warnings[0].code == "UNSUPPORTED_ACCESS_LIST"


def test_remarks_are_scoped_to_next_ace_in_same_acl() -> None:
    result = parse_config(
        "access-list A remark First line\n"
        "access-list B remark Other policy\n"
        "access-list A remark Second line\n"
        "access-list A extended permit ip any any\n"
        "access-list A extended deny ip any any\n"
        "access-list B extended deny ip any any\n"
        "access-group A in interface inside\n"
    )

    assert tuple(rule.description for rule in result.rules) == (
        "First line\nSecond line",
        None,
        "Other policy",
    )
    assert tuple(rule.description_status for rule in result.rules) == (
        DataStatus.KNOWN,
        DataStatus.ABSENT,
        DataStatus.KNOWN,
    )
    assert tuple(rule.sequence for rule in result.rules) == (4, 5, 6)
    assert not result.warnings
    assert result.coverage.coverage_ratio == 1


def test_remark_is_consumed_by_unsupported_ace() -> None:
    result = parse_config(
        "access-list A remark Limited schedule\n"
        "access-list A extended permit ip any any time-range OFFICE\n"
        "access-list A extended deny ip any any\n"
        "access-group A in interface inside\n"
    )

    assert len(result.rules) == 1
    assert result.rules[0].description is None
    assert result.rules[0].description_status == DataStatus.ABSENT


def test_empty_remark_is_unknown_and_reported() -> None:
    result = parse_config(
        "access-list A remark\n"
        "access-list A extended permit ip any any\n"
        "access-group A in interface inside\n"
    )

    assert result.rules[0].description_status == DataStatus.UNKNOWN
    assert result.warnings[0].source_location is not None
    assert result.warnings[0].source_location.line_start == 1


@pytest.mark.parametrize(
    ("bindings", "direction", "source_zone", "destination_zone"),
    [
        ("access-group A in interface inside", "in", "inside", None),
        ("access-group A out interface outside", "out", None, "outside"),
        ("access-group A global", None, None, None),
        ("access-group B in interface inside", None, None, None),
        (
            "access-group A in interface inside\naccess-group A out interface inside",
            None,
            None,
            None,
        ),
        (
            "access-group A in interface inside\naccess-group A in interface outside",
            None,
            None,
            None,
        ),
        ("access-group A in interface inside\naccess-group A global", None, None, None),
        ("access-group A in interface", None, None, None),
    ],
)
def test_binding_direction_and_ambiguity(
    bindings: str, direction: str | None, source_zone: str | None, destination_zone: str | None
) -> None:
    result = parse_config(f"access-list A extended permit ip any any\n{bindings}\n")

    rule = result.rules[0]
    assert rule.policy_id == "A"
    assert rule.policy_direction == direction
    assert rule.source_zone == source_zone
    assert rule.destination_zone == destination_zone
    assert rule.zone_status == (DataStatus.KNOWN if direction else DataStatus.UNKNOWN)
    assert rule.match_status == DataStatus.KNOWN


@pytest.mark.parametrize(
    "definition",
    [
        "object-group network G\n network-object host 192.0.2.1\n group-object NESTED",
        "object-group network G\n network-object object MISSING",
        "object-group network G\n network-object host 192.0.2.1\n network-object bad bad",
        "object-group network G\n description No members",
        "object-group network G\n network-object host 2001:db8::1",
        "object network BAD\n fqdn example.test\nobject-group network G\n"
        " network-object object BAD",
        "object network G\n range 192.0.2.1 192.0.2.5",
        "object network G\n description First\n host malformed",
        "object network G\n host 192.0.2.1\n host 192.0.2.2",
        "object network G\n host 192.0.2.1\n unknown-condition x",
        "object network G\n host 192.0.2.1\nobject network G\n host 192.0.2.2",
    ],
)
def test_unresolved_network_objects_cannot_become_known_matches(definition: str) -> None:
    reference = "object-group" if definition.startswith("object-group") else "object"
    if "object-group network G" in definition:
        reference = "object-group"
    result = parse_config(
        f"{definition}\naccess-list A extended permit ip {reference} G any\n"
        "access-list A extended deny ip any any\naccess-group A in interface inside\n"
    )

    assert len(result.rules) == 1
    assert result.rules[0].action == RuleAction.DENY
    assert any(issue.code == "UNSUPPORTED_OBJECT" for issue in result.warnings)
    assert any(issue.code == "UNSUPPORTED_ACCESS_LIST" for issue in result.warnings)
    assert all(issue.source_location is not None for issue in result.warnings)
    assert result.coverage.coverage_ratio < 1


@pytest.mark.parametrize(
    "definition",
    [
        "object-group service G tcp\n service-object tcp destination eq 443\n group-object NESTED",
        "object-group service G tcp\n service-object object MISSING",
        "object-group service G tcp\n service-object tcp destination eq 443\n"
        " service-object udp destination eq 53",
        "object-group service G\n service-object tcp destination eq 443",
        "object-group service G tcp-udp\n port-object eq 53",
        "object-group service G tcp\n service-object tcp source eq 1024 destination eq 443",
        "object-group service G tcp\n service-object tcp destination eq 443 extra",
        "object-group service G tcp\n service-object tcp destination eq bad",
        "object-group service G tcp\n service-object tcp destination eq 0",
        "object-group service G tcp\n description No members",
        "object service G\n service tcp source eq 1024 destination eq 443",
        "object service G\n service tcp destination range 443 80",
        "object service G\n service icmp echo",
        "object service G\n description Missing declaration",
        "object service BAD\n service tcp source eq 1024\nobject-group service G tcp\n"
        " service-object object BAD",
        "object service G\n service tcp destination eq 443\nobject service G\n"
        " service udp destination eq 53",
    ],
)
def test_unresolved_service_objects_cannot_broaden_access(definition: str) -> None:
    reference = "object-group" if "object-group service G" in definition else "object"
    result = parse_config(
        f"{definition}\naccess-list A extended permit {reference} G any any\n"
        "access-list A extended deny ip any any\naccess-group A in interface inside\n"
    )

    assert len(result.rules) == 1
    assert result.rules[0].action == RuleAction.DENY
    assert any(issue.code == "UNSUPPORTED_OBJECT" for issue in result.warnings)
    assert all(issue.source_location is not None for issue in result.warnings)
    assert result.coverage.coverage_ratio < 1


def test_forward_references_and_descriptions_preserve_complete_groups() -> None:
    result = parse_config(
        "object-group network G\n description Trusted\n network-object object HOST\n"
        "object-group service S tcp\n description Web\n service-object object HTTPS\n"
        "object network HOST\n description Server\n host 192.0.2.1\n"
        "object service HTTPS\n description TLS\n service tcp destination eq https\n"
        "access-list A extended permit object-group S object-group G any\n"
        "access-group A in interface inside\n"
    )

    assert len(result.rules) == 1
    rule = result.rules[0]
    assert rule.sources[0].cidrs == ("192.0.2.1/32",)
    assert rule.services[0].port_ranges[0].start == 443
    assert rule.services[0].resolution_status == DataStatus.KNOWN
    assert not result.warnings


def test_all_ports_member_preserves_service_group_union() -> None:
    result = parse_config(
        "object-group service S tcp\n service-object tcp\n service-object tcp destination eq 443\n"
        "access-list A extended permit object-group S any any\n"
        "access-group A in interface inside\n"
    )

    assert result.rules[0].services[0].protocol == Protocol.TCP
    assert result.rules[0].services[0].port_ranges == ()
    assert not result.warnings


def test_invalid_encoding_is_a_parse_failure() -> None:
    source = SourceDocument(source_name="bad.cfg", content=b"\xff", captured_at=CAPTURED_AT)
    parser = CiscoAsaParser()

    assert parser.detect(source).is_match is False
    outcome = parser.parse(ParseRequest(source=source, imported_at=IMPORTED_AT))
    assert isinstance(outcome, ParseFailure)
    assert outcome.errors[0].code == "INVALID_ENCODING"


@pytest.mark.parametrize("directive", ["access-list", "access-list A", "access-list A extended"])
def test_truncated_directives_are_reported(directive: str) -> None:
    result = parse_config(
        f"{directive}\naccess-list A extended deny ip any any\naccess-group A in interface inside\n"
    )

    assert len(result.rules) == 1
    assert result.warnings[0].code == "UNSUPPORTED_ACCESS_LIST"
    assert result.coverage.discovered_constructs == 2
    assert result.coverage.recognized_constructs == 1


def test_tab_separated_directives_do_not_escape_parsing() -> None:
    result = parse_config(
        "access-list\tA\textended\tpermit\ttcp\tany\tany\teq\t443\tinactive\n"
        "access-group\tA\tout\tinterface\toutside\n"
    )

    assert len(result.rules) == 1
    assert result.rules[0].enabled is False
    assert result.rules[0].policy_direction == "out"
    assert result.rules[0].services[0].port_ranges[0].start == 443


@pytest.mark.parametrize(
    "definition",
    [
        "object",
        "object network",
        "object service",
        "object network G",
        "object service G",
        "object-group",
        "object-group network",
        "object-group service",
        "object-group network G",
        "object-group service G tcp",
        "object-group service G unknown",
        "object-group unsupported G",
    ],
)
def test_truncated_objects_report_incomplete_coverage(definition: str) -> None:
    result = parse_config(
        f"{definition}\naccess-list A extended deny ip any any\n"
        "access-group A in interface inside\n"
    )

    assert len(result.rules) == 1
    assert result.warnings[0].code == "UNSUPPORTED_OBJECT"
    assert result.warnings[0].source_location is not None
    assert result.warnings[0].source_location.line_start == 1
    assert result.coverage.coverage_ratio == 0.5


def test_duplicate_binding_does_not_create_ambiguity() -> None:
    result = parse_config(
        "access-list A extended permit ip any any\n"
        "access-group A in interface inside\naccess-group A in interface inside\n"
    )

    assert result.rules[0].policy_direction == "in"
    assert result.rules[0].zone_status == DataStatus.KNOWN


@pytest.mark.parametrize("operator", ["eq 443", "range 80 443"])
def test_supported_destination_ports_in_service_groups(operator: str) -> None:
    result = parse_config(
        f"object-group service G tcp\n port-object {operator}\n"
        "access-list A extended permit object-group G any any\n"
        "access-group A in interface inside\n"
    )

    assert result.rules[0].services[0].port_ranges[0].end == 443
    assert not result.warnings
