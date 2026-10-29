"""Concrete overlap witnesses and versioned evidence; synthetic policies only."""

from ipaddress import ip_address

import pytest

from firewall_compliance.checks.access.exposure import (
    DangerousServicesCheck,
    UntrustedAdministrativeAccessCheck,
)
from firewall_compliance.checks.policy_quality.rules import (
    PartialShadowedRulesCheck,
    UnionShadowedRulesCheck,
)
from firewall_compliance.domain import DataStatus, RuleAction
from firewall_compliance.domain.assurance import CheckStatus
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from tests.regression.test_policy_exposure import context as exposure_context
from tests.regression.test_policy_exposure import profile, selector
from tests.regression.test_policy_exposure import rule as exposure_rule
from tests.regression.test_policy_union_shadowing import evaluate, rule, target_findings


@pytest.mark.parametrize("check_type", [DangerousServicesCheck, UntrustedAdministrativeAccessCheck])
@pytest.mark.parametrize("family", [4, 6])
def test_exposure_witness_is_a_real_member_with_exact_rule_and_profile(check_type, family):
    values = profile().model_dump(mode="python")
    src = "198.51.100.0/24" if family == 4 else "2001:db8:1::/120"
    target = "192.0.2.7/32" if family == 4 else "2001:db8:2::7/128"
    trusted = "198.51.100.0/25" if family == 4 else "2001:db8:1::/121"
    values.update(administrative_targets=(target,), trusted_admin_networks=(trusted,))
    policy = PolicyExposureProfile.model_validate(values)
    current = exposure_context(exposure_rule(source=src, destination=target))
    result = check_type(policy).evaluate(current)
    finding = result.findings[0]
    facts = finding.evidence.facts
    witness = facts["witness_flow"]
    assert result.check_version == "1.1.0"
    assert witness["family"] == family
    assert ip_address(witness["source_ip"]).version == family
    assert ip_address(witness["destination_ip"]).version == family
    assert witness["protocol"] == "tcp" and witness["protocol_number"] == 6
    assert witness["destination_port"] == (23 if check_type is DangerousServicesCheck else 22)
    assert witness["rule_id"] == current.revision.parse_result.rules[0].rule_id
    assert witness["profile_id"] == policy.profile_id
    assert witness["profile_version"] == policy.version
    assert witness["profile_sha256"] == facts["profile_sha256"]
    for axis, key in (("source_ranges", "source_ip"), ("destination_ranges", "destination_ip")):
        assert any(
            ip_address(interval["start"]) <= ip_address(witness[key]) <= ip_address(interval["end"])
            for group in facts[axis]
            if group["ip_version"] == family
            for interval in group["ranges"]
        )
    assert check_type(policy).evaluate(current).model_dump_json() == result.model_dump_json()


@pytest.mark.parametrize(
    ("earlier_action", "later_action", "classification", "dependent"),
    [
        (RuleAction.DENY, RuleAction.ALLOW, "opposite_decision", True),
        (RuleAction.ALLOW, RuleAction.DROP, "opposite_decision", True),
        (RuleAction.ALLOW, RuleAction.ALLOW, "same_action_redundancy", False),
        (RuleAction.DENY, RuleAction.REJECT, "different_denial_actions", False),
    ],
)
def test_partial_classification_uses_semantic_decisions_and_actual_covered_packet(
    earlier_action, later_action, classification, dependent
):
    result = evaluate(
        PartialShadowedRulesCheck(),
        rule("first", 10, ports=(2, 4), action=earlier_action),
        rule("target", 20, ports=(1, 8), action=later_action),
    )
    facts = target_findings(result)[0].evidence.facts
    overlap = facts["ordered_overlaps"][0]
    assert facts["overlap_classification"] == classification
    assert facts["decision_order_dependent"] is dependent
    assert overlap["classification"] == classification
    assert overlap["decision_order_dependent"] is dependent
    assert overlap["action_order_dependent"] is (earlier_action != later_action)
    assert overlap["earlier_rule_id"] == "first" and overlap["target_rule_id"] == "target"
    assert overlap["earlier_sequence"] == 10 and overlap["target_sequence"] == 20
    assert overlap["earlier_action"] == earlier_action.value
    assert overlap["target_action"] == later_action.value
    assert overlap["overlap_witness"]["destination_port"] == 2
    assert overlap["first_match_owner_known"]


def test_union_evidence_keeps_each_contributors_own_overlap_not_the_first_witness():
    result = evaluate(
        UnionShadowedRulesCheck(),
        rule("low", 1, ports=(1, 4), action=RuleAction.DENY),
        rule("high", 2, ports=(5, 8), action=RuleAction.ALLOW),
        rule("target", 3, action=RuleAction.ALLOW),
    )
    facts = target_findings(result)[0].evidence.facts
    assert facts["overlap_classification"] == "mixed_decisions"
    assert facts["decision_order_dependent"] is True
    assert [item["earlier_rule_id"] for item in facts["ordered_overlaps"]] == ["low", "high"]
    assert [item["overlap_witness"]["destination_port"] for item in facts["ordered_overlaps"]] == [
        1,
        5,
    ]
    assert [item["classification"] for item in facts["ordered_overlaps"]] == [
        "opposite_decision",
        "same_action_redundancy",
    ]


def test_unknown_first_owner_never_claims_a_known_effective_order_decision():
    result = evaluate(
        UnionShadowedRulesCheck(),
        rule("unknown", 1, match_status=DataStatus.UNKNOWN),
        rule("low", 2, ports=(1, 4), action=RuleAction.DENY),
        rule("high", 3, ports=(5, 8), action=RuleAction.DENY),
        rule("target", 4, action=RuleAction.ALLOW),
    )
    facts = target_findings(result)[0].evidence.facts
    assert result.status == CheckStatus.PARTIAL
    assert facts["overlap_classification"] == "opposite_decision"
    assert facts["decision_order_dependent"] is None
    assert all(item["decision_order_dependent"] is None for item in facts["ordered_overlaps"])
    assert not any(item["first_match_owner_known"] for item in facts["ordered_overlaps"])


def test_ambiguous_icmpv6_never_generates_a_protocol_one_witness():
    values = profile().model_dump(mode="python")
    values.update(
        dangerous_services=(selector(protocol="icmp"),),
        administrative_services=(selector(protocol="icmp"),),
        administrative_targets=("2001:db8:2::/64",),
        trusted_admin_networks=(),
    )
    policy = PolicyExposureProfile.model_validate(values)
    from firewall_compliance.domain import Protocol

    current = exposure_context(
        exposure_rule(
            source="2001:db8:1::/64", destination="2001:db8:2::/64", protocol=Protocol.ICMP
        )
    )
    for check_type in (DangerousServicesCheck, UntrustedAdministrativeAccessCheck):
        result = check_type(policy).evaluate(current)
        assert result.status == CheckStatus.PARTIAL and not result.findings
        assert "UNSUPPORTED_ICMPV6" in {item.code for item in result.limitations}
        legacy = check_type(policy, evidence_version="1.0.0").evaluate(current)
        assert legacy.findings and "witness_flow" not in legacy.findings[0].evidence.facts


@pytest.mark.parametrize(
    "check_type",
    [
        DangerousServicesCheck,
        UntrustedAdministrativeAccessCheck,
        PartialShadowedRulesCheck,
        UnionShadowedRulesCheck,
    ],
)
def test_unsupported_evidence_version_is_rejected(check_type):
    with pytest.raises(ValueError, match="evidence version"):
        check_type(evidence_version="future-version")
