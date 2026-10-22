"""Импорт синтетических выдержек ASA не доказывает полноту."""

import json
from hashlib import sha256
from pathlib import Path

import pytest
from tests.asa_forwarding_fixtures import forwarding_request
from tests.forwarding_fixtures import CONFIGURATION_ID

from firewall_compliance.domain.enums import DataStatus, RuleAction
from firewall_compliance.domain.forwarding import FEATURE_SCOPES
from firewall_compliance.parsers.cisco_asa_forwarding import CiscoAsaForwardingParser
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseResult

ROOT = Path(__file__).parents[1] / "fixtures" / "forwarding_asa"
MANIFEST = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("scenario", MANIFEST["scenarios"], ids=lambda item: item["id"])
def test_existing_excerpt_preserves_facts_without_claiming_absence(scenario: dict) -> None:
    entry = scenario["sources"][0]
    content = (ROOT / entry["path"]).read_bytes()
    assert sha256(content).hexdigest() == entry["sha256"]
    request = forwarding_request(scenario["id"])
    parser = CiscoAsaForwardingParser()
    assert parser.detect(request.source, request.metadata).is_match
    result = parser.parse(request)
    assert isinstance(result, ForwardingParseResult), result
    assert result.schema_version == "0.1.0"
    assert result.parser_id == parser.metadata.parser_id
    assert result.parser_version == parser.metadata.version
    context = result.context
    assert context.revision_id == request.revision_id
    assert context.configuration_id == request.configuration_id
    assert context.device_id == scenario["device_id"]
    assert context.observed_at is None and context.flow is None
    assert len(context.sources) == 1
    assert context.sources[0] == request.metadata
    assert context.sources[0].observation is None
    assert context.sources[0].complete_scopes == ()
    inventories = {item.feature: item for item in context.inventories}
    assert set(inventories) == set(FEATURE_SCOPES)
    unsupported_feature = {
        "object_and_global_nat_unsupported": "configured_nat",
        "policy_route_route_map_unsupported": "pbr",
    }.get(scenario["id"])
    for feature, inventory in inventories.items():
        expected = DataStatus.UNSUPPORTED if feature == unsupported_feature else DataStatus.UNKNOWN
        assert inventory.status == expected
        assert not inventory.complete and not inventory.enumeration_complete
    assert inventories["effective_nat"].status == DataStatus.UNKNOWN

    interfaces = {item.label: item for item in context.interfaces}
    assert set(interfaces) == {"inside", "outside"}
    equal_security = scenario["id"].startswith("equal_security")
    assert interfaces["inside"].security_level == (50 if equal_security else 100)
    assert interfaces["outside"].security_level == (50 if equal_security else 0)
    assert all(item.security_status == DataStatus.KNOWN for item in interfaces.values())
    expected_bindings = {("INSIDE_IN", "in", interfaces["inside"].interface_id)}
    global_policy = (
        "GLOBAL_MISSING" if scenario["id"] == "truncated_missing_global_chain" else "GLOBAL_IN"
    )
    expected_bindings.add((global_policy, "global", None))
    if scenario["id"] == "ingress_permit_outbound_deny":
        expected_bindings.add(("OUTSIDE_OUT", "out", interfaces["outside"].interface_id))
    actual_bindings = {(b.policy_id, b.direction, b.interface_id) for b in context.bindings}
    assert actual_bindings == expected_bindings

    acls = {acl.policy_id: acl for acl in context.acls}
    assert {policy for policy, _, _ in expected_bindings} <= set(acls)
    assert all(acl.configuration_id == CONFIGURATION_ID for acl in context.acls)
    assert all(acl.status == DataStatus.UNKNOWN and not acl.complete for acl in context.acls)
    inside_rule = acls["INSIDE_IN"].rules[0]
    assert inside_rule.action == (
        RuleAction.DENY if scenario["id"] == "ingress_deny_before_global" else RuleAction.ALLOW
    )
    if global_policy == "GLOBAL_MISSING":
        assert acls[global_policy].rules == ()
        assert result.warnings or result.errors
    else:
        assert acls[global_policy].rules[0].action == RuleAction.ALLOW
    if "OUTSIDE_OUT" in acls:
        assert acls["OUTSIDE_OUT"].rules[0].action == RuleAction.DENY
    if "PBR_CLASS" in acls:
        assert [r.action for r in acls["PBR_CLASS"].rules] == [RuleAction.DENY, RuleAction.ALLOW]

    lines = content.decode("ascii").splitlines()
    assert sum(len(acl.rules) for acl in context.acls) == sum(
        line.startswith("access-list ") for line in lines
    )
    for acl in context.acls:
        for rule in acl.rules:
            assert rule.configuration_id == CONFIGURATION_ID
            assert rule.policy_id == acl.policy_id
            assert rule.policy_semantics == "first_match"
            assert rule.match_status == DataStatus.KNOWN
            position = rule.source_location
            assert position.source_name == entry["path"]
            assert position.line_start is not None
            assert lines[position.line_start - 1].startswith(f"access-list {acl.policy_id} ")
            assert result.source_map[rule.rule_id] == position
    for fact in (*context.interfaces, *context.bindings, *context.acls):
        assert fact.location.source_document_id == request.metadata.source_document_id
        position = fact.location.location
        assert position.source_name == entry["path"]
        assert position.line_start is not None and 1 <= position.line_start <= len(lines)
    for binding in context.bindings:
        assert lines[binding.location.location.line_start - 1].startswith(
            f"access-group {binding.policy_id} "
        )

    toggles = {item.name: item for item in context.toggles}
    assert set(toggles) == {"inter_interface", "intra_interface", "permit_vpn"}
    explicit = scenario["id"] == "equal_security_explicit_inter_interface"
    assert toggles["inter_interface"].value is (True if explicit else None)
    expected_toggle_status = DataStatus.KNOWN if explicit else DataStatus.UNKNOWN
    assert toggles["inter_interface"].status == expected_toggle_status
    for name in ("intra_interface", "permit_vpn"):
        assert toggles[name].status == DataStatus.UNKNOWN and toggles[name].value is None
    assert result.coverage.recognized_constructs > 0
    assert result.coverage.discovered_constructs >= result.coverage.recognized_constructs
    if unsupported_feature:
        assert result.unsupported_constructs
        assert result.coverage.unsupported_constructs > 0
        for construct in result.unsupported_constructs:
            assert construct.source_location.source_name == entry["path"]
            assert construct.source_location.line_start is not None
        unsupported_lines = {
            construct.source_location.line_start for construct in result.unsupported_constructs
        }
        if unsupported_feature == "configured_nat":
            nat_lines = {
                number for number, line in enumerate(lines, 1) if line.strip().startswith("nat ")
            }
            assert len(nat_lines) == 2
            assert nat_lines <= unsupported_lines
        else:
            pbr_lines = {
                number
                for number, line in enumerate(lines, 1)
                if line.strip().startswith(("policy-route ", "route-map "))
            }
            assert pbr_lines <= unsupported_lines


def test_fixture_manifest_has_exactly_eight_unchanged_sources() -> None:
    sources = [entry for scenario in MANIFEST["scenarios"] for entry in scenario["sources"]]
    assert len(sources) == 8
    for entry in sources:
        content = (ROOT / entry["path"]).read_bytes()
        assert len(content) == entry["byte_length"]
        assert sha256(content).hexdigest() == entry["sha256"]
