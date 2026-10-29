"""Локальные решения и консервативные границы ACL."""

from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.policy_fixtures import endpoint, policy_revision, rule
from tests.reachability_fixtures import make_query
from tests.revision_fixtures import CONFIGURATION_SOURCE_ID, OBSERVATION

from firewall_compliance.analysis.policy_decision import evaluate_policy
from firewall_compliance.domain import (
    DataStatus,
    DeviceRevision,
    ParseCoverage,
    ParseIssue,
    ParseIssueLevel,
    Protocol,
    RevisionSource,
    RuleAction,
    Service,
    SourceDocumentKind,
    SourceLocation,
    UnsupportedConstruct,
)
from firewall_compliance.domain.policy_decision import PolicyBindingEvidence


def acl_rule(sequence: int = 1, **changes: Any):
    return rule(
        sequence,
        **{
            "sources": (endpoint(),),
            "destinations": (endpoint(),),
            "source_zone": "inside",
            **changes,
        },
    )


def binding(**changes: Any) -> PolicyBindingEvidence:
    return PolicyBindingEvidence.model_validate(
        {
            "policy_id": "ACL",
            "direction": "in",
            "interface_id": "interface:inside",
            "interface_label": "inside",
            "interface_mapping_reference": "Synthetic mapping.",
            "source_document_id": CONFIGURATION_SOURCE_ID,
            "binding_location": SourceLocation(source_name="fixture.config", line_start=20),
            "complete": True,
            "completeness_reference": "Synthetic complete ACL.",
            "declaration_origin": "synthetic",
            "coordinate_space": "acl_input",
            **changes,
        }
    )


@pytest.mark.parametrize(
    "action", [RuleAction.ALLOW, RuleAction.DENY, RuleAction.DROP, RuleAction.REJECT]
)
def test_first_match_sorted_local_actions(action) -> None:
    revision = policy_revision(acl_rule(2), acl_rule(1, action=action))
    result = evaluate_policy(revision, make_query(), binding())
    assert result.status == action.value
    assert result.matched_rule_id == "rule-1"
    assert [(item.rule_id, item.outcome) for item in result.trace] == [("rule-1", "match")]


@pytest.mark.parametrize(
    "terminal,implicit,expected",
    [
        (False, "deny", "no_match"),
        (False, "unknown", "no_match"),
        (True, "unknown", "no_match"),
        (True, "deny", "implicit_deny"),
    ],
)
def test_nonterminal_inbound_deny_claim_yields_no_match(terminal, implicit, expected) -> None:
    revision = policy_revision(acl_rule(sources=(endpoint("192.0.2.0/24"),)))
    result = evaluate_policy(
        revision,
        make_query(),
        binding(
            implicit_action=implicit,
            terminal=terminal,
            terminal_reference="Synthetic chain end." if terminal else None,
        ),
    )
    assert result.status == expected
    assert result.trace[0].outcome == "no_match"
    assert result.matched_rule_id is None


def test_disabled_unknown_match_is_skipped() -> None:
    result = evaluate_policy(
        policy_revision(
            acl_rule(1, enabled=False, match_status=DataStatus.UNKNOWN, action=RuleAction.UNKNOWN),
            acl_rule(2),
        ),
        make_query(),
        binding(),
    )
    assert result.status == "allow"
    assert [item.outcome for item in result.trace] == ["disabled", "match"]


@pytest.mark.parametrize("action", [RuleAction.ALLOW, RuleAction.DENY])
def test_unknown_predecessor_stops_before_later_decision(action) -> None:
    result = evaluate_policy(
        policy_revision(
            acl_rule(1, match_status=DataStatus.UNKNOWN),
            acl_rule(2, action=action),
        ),
        make_query(),
        binding(),
    )
    assert result.status == "unknown"
    assert len(result.trace) == 1
    assert result.trace[0].outcome == "unknown"


@pytest.mark.parametrize("action", [RuleAction.LOG, RuleAction.UNKNOWN])
@pytest.mark.parametrize("matches", [True, False])
def test_unknown_action_only_blocks_on_match(action, matches) -> None:
    result = evaluate_policy(
        policy_revision(
            acl_rule(
                1, action=action, sources=(endpoint() if matches else endpoint("192.0.2.0/24"),)
            ),
            acl_rule(2),
        ),
        make_query(),
        binding(),
    )
    assert result.status == ("unknown" if matches else "allow")


@pytest.mark.parametrize(
    "protocol,port", [(Protocol.TCP, 443), (Protocol.UDP, 53), (Protocol.ICMP, None)]
)
def test_ip_service_wildcard(protocol, port) -> None:
    revision = policy_revision(
        acl_rule(services=(Service(service_id="ip", name="ip", protocol=Protocol.IP),))
    )
    assert (
        evaluate_policy(
            revision, make_query(protocol=protocol, destination_port=port), binding()
        ).status
        == "allow"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"source_ip": "192.0.2.5"},
        {"destination_ip": "203.0.113.2"},
        {"destination_port": 80},
        {"protocol": Protocol.UDP},
    ],
)
def test_address_protocol_and_port_mismatch(changes) -> None:
    revision = policy_revision(
        acl_rule(sources=(endpoint("10.0.0.0/24"),), destinations=(endpoint("198.51.100.0/24"),))
    )
    assert evaluate_policy(revision, make_query(**changes), binding()).status == "no_match"


@pytest.mark.parametrize(
    "changes",
    [
        {"revision_id": uuid4()},
        {"device_id": "other"},
        {"device_context": "other"},
        {"table_id": "vrf"},
        {"source_ip": "2001:db8::1", "destination_ip": "2001:db8::2"},
    ],
)
def test_query_context_and_supported_scope(changes) -> None:
    assert (
        evaluate_policy(policy_revision(acl_rule()), make_query(**changes), binding()).status
        == "unknown"
    )


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({"complete": False}, "not_enough_evidence"),
        ({"policy_id": "unbound"}, "not_enough_evidence"),
        ({"interface_id": "missing"}, "unknown"),
        ({"source_document_id": uuid4()}, "not_enough_evidence"),
        ({"binding_location": SourceLocation(source_name="other", line_start=1)}, "unknown"),
        (
            {"binding_location": SourceLocation(source_name="fixture.config", object_path=" ")},
            "unknown",
        ),
    ],
)
def test_binding_evidence(changes, expected) -> None:
    assert (
        evaluate_policy(policy_revision(acl_rule()), make_query(), binding(**changes)).status
        == expected
    )


def test_empty_acl_never_implies_deny() -> None:
    assert (
        evaluate_policy(
            policy_revision(),
            make_query(),
            binding(
                implicit_action="deny",
                terminal=True,
                terminal_reference="Chain end.",
            ),
        ).status
        == "not_enough_evidence"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"policy_direction": "out"},
        {"policy_semantics": None},
        {"zone_status": DataStatus.UNKNOWN},
        {"source_zone": None},
        {"source_zone": "other"},
    ],
)
def test_rule_scope_requires_known_binding(changes) -> None:
    assert (
        evaluate_policy(policy_revision(acl_rule(**changes)), make_query(), binding()).status
        == "unknown"
    )


def test_only_bound_policy_and_casefold_label() -> None:
    revision = policy_revision(
        acl_rule(2, policy_id="other", match_status=DataStatus.UNKNOWN),
        acl_rule(1, source_zone="INSIDE"),
    )
    result = evaluate_policy(revision, make_query(), binding())
    assert result.status == "allow"
    assert result.evidence.related_rule_ids == ("rule-1",)


def test_duplicate_sequence_blocks_early_allow() -> None:
    result = evaluate_policy(
        policy_revision(acl_rule(), acl_rule(rule_id="second")), make_query(), binding()
    )
    assert result.status == "unknown"
    assert not result.trace


@pytest.mark.parametrize("field", ["warnings", "errors", "unsupported_constructs", "coverage"])
def test_entire_parse_diagnostics_block_decision(field) -> None:
    values = {
        "warnings": (ParseIssue(code="warn", level=ParseIssueLevel.WARNING, message="Warning"),),
        "errors": (ParseIssue(code="err", level=ParseIssueLevel.ERROR, message="Error"),),
        "unsupported_constructs": (
            UnsupportedConstruct(
                construct_type="other",
                message="Unsupported",
                source_location=SourceLocation(source_name="fixture.config", line_start=99),
            ),
        ),
        "coverage": ParseCoverage(
            discovered_constructs=2, recognized_constructs=1, unsupported_constructs=0
        ),
    }
    result = evaluate_policy(
        policy_revision(acl_rule(), **{field: values[field]}), make_query(), binding()
    )
    assert result.status == "unknown"
    assert not result.trace
    assert result.evidence.facts[field]


def test_known_interfaces_collection_and_trusted_mapping() -> None:
    revision = policy_revision(acl_rule())
    payload = revision.model_dump(mode="python")
    payload["interfaces"][0].update(name="GigabitEthernet0/1", zone=None)
    assert (
        evaluate_policy(DeviceRevision.model_validate(payload), make_query(), binding()).status
        == "allow"
    )
    payload["interfaces_status"] = DataStatus.UNKNOWN
    assert (
        evaluate_policy(DeviceRevision.model_validate(payload), make_query(), binding()).status
        == "not_enough_evidence"
    )


def test_outbound_only_checks_interface_exists_not_selected_egress() -> None:
    revision = policy_revision(
        acl_rule(policy_direction="out", source_zone=None, destination_zone="inside")
    )
    assert evaluate_policy(revision, make_query(), binding(direction="out")).status == "allow"


@pytest.mark.parametrize("change", ["kind", "hash", "observation"])
def test_configuration_source_and_observation_must_cohere(change) -> None:
    payload = policy_revision(acl_rule()).model_dump(mode="python")
    payload.update(
        interfaces_status=DataStatus.UNKNOWN,
        routes_status=DataStatus.UNKNOWN,
        network_segments_status=DataStatus.UNKNOWN,
        topology_status=DataStatus.UNKNOWN,
    )
    source = payload["sources"][0]
    if change == "kind":
        source["kind"] = SourceDocumentKind.ROUTING_TABLE
    elif change == "hash":
        source["content_sha256"] = "c" * 64
    else:
        source["observation"] = OBSERVATION.model_copy(
            update={
                "observed_at": OBSERVATION.observed_at - timedelta(days=1),
            }
        ).model_dump(mode="python")
    corrupted = policy_revision(acl_rule()).model_copy(
        update={
            "sources": tuple(RevisionSource.model_validate(item) for item in payload["sources"]),
        }
    )
    with pytest.raises(ValidationError):
        evaluate_policy(corrupted, make_query(), binding())


@pytest.mark.parametrize("target", ["revision", "query", "binding"])
def test_revalidates_constructed_or_copied_inputs(target) -> None:
    revision, query, bound = policy_revision(acl_rule()), make_query(), binding()
    if target == "revision":
        revision = revision.model_copy(update={"application_version": ""})
    elif target == "query":
        query = query.model_copy(update={"destination_port": None})
    else:
        bound = bound.model_copy(update={"interface_mapping_reference": ""})
    with pytest.raises(ValidationError):
        evaluate_policy(revision, query, bound)


def test_evidence_is_complete_frozen_snapshot() -> None:
    revision = policy_revision(acl_rule())
    result = evaluate_policy(revision, make_query(), binding())
    facts = result.evidence.facts
    assert facts["revision_id"] == str(revision.revision_id)
    assert facts["configuration_id"] == str(revision.parse_result.configuration.configuration_id)
    assert facts["content_sha256"] == revision.parse_result.configuration.content_sha256
    assert facts["parser_version"] == revision.parse_result.configuration.parser_version
    assert facts["application_version"] == revision.application_version
    assert facts["observed_at"] == revision.observed_at.isoformat()
    assert facts["rules"][0]["sources"][0]["kind"] == "any"
    assert len(facts["sources"]) == len(result.sources) == len(revision.sources)
    with pytest.raises(TypeError):
        facts["rules"][0]["action"] = "deny"
    with pytest.raises(TypeError):
        result.status = "deny"
    assert type(result).model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize(
    "field", ["completeness_reference", "interface_mapping_reference", "terminal_reference"]
)
def test_blank_references_are_revalidated(field) -> None:
    bound = binding(terminal=True, terminal_reference="Chain end.").model_copy(update={field: " "})
    with pytest.raises(ValidationError):
        evaluate_policy(policy_revision(acl_rule()), make_query(), bound)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_name", "other.config"),
        ("content_sha256", "d" * 64),
        ("kind", SourceDocumentKind.TOPOLOGY),
    ],
)
def test_binding_uuid_must_identify_the_actual_configuration(field, value) -> None:
    payload = policy_revision(acl_rule()).model_dump(mode="python")
    alternate = {**payload["sources"][0], "source_document_id": uuid4(), field: value}
    payload["sources"] = (*payload["sources"], alternate)
    result = evaluate_policy(
        DeviceRevision.model_validate(payload),
        make_query(),
        binding(
            source_document_id=alternate["source_document_id"],
            binding_location=SourceLocation(source_name=alternate["source_name"], line_start=20),
        ),
    )
    assert result.status == "unknown"
    assert "binding_source_mismatch" in {item.code for item in result.reasons}
