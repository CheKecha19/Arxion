"""Acceptance boundaries from CHECKS-001/002/004 passports; synthetic models only."""

import json
from hashlib import sha256

import pytest
from test_policy_exposure import context as exposure_context
from test_policy_exposure import profile as exposure_profile
from test_policy_exposure import rule as exposure_rule
from test_policy_exposure import selector
from test_policy_union_shadowing import evaluate, revision, rule, target_findings

from firewall_compliance.analysis.policy_checks import (
    PartialShadowedRulesCheck,
    PolicyCheckContext,
    UnionShadowedRulesCheck,
)
from firewall_compliance.analysis.policy_exposure import UntrustedAdministrativeAccessCheck
from firewall_compliance.domain import DataStatus, DeviceRevision, RuleAction
from firewall_compliance.domain.assurance import CheckStatus
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile


def codes(result):
    return {item.code for item in result.limitations}


@pytest.mark.parametrize("port", [22, 3389])
def test_admin_catalogue_has_exact_provenance_and_profile_evidence(port):
    profile = exposure_profile().model_dump(mode="python")
    profile.update(
        profile_id="synthetic-approved",
        version="17",
        administrative_services=(selector("ssh-or-rdp", start=port, end=port),),
        administrative_targets=("192.0.2.20/32",),
        trusted_admin_networks=("198.51.100.0/25",),
    )
    profile = PolicyExposureProfile.model_validate(profile)
    current = exposure_context(
        exposure_rule(
            source="198.51.100.0/24",
            destination="192.0.2.0/24",
            start=port,
            end=port,
        )
    )
    result = UntrustedAdministrativeAccessCheck(profile).evaluate(current)
    finding = result.findings[0]
    facts = finding.evidence.facts
    assert result.status == CheckStatus.COMPLETE
    assert result.check_version == "1.1.0"
    assert finding.severity.value == "high"
    assert finding.revision_id == current.revision.revision_id
    assert finding.configuration_id == current.revision.parse_result.configuration.configuration_id
    assert finding.evidence.source_locations == (
        current.revision.parse_result.rules[0].source_location,
    )
    assert facts["rule"] == current.revision.parse_result.rules[0].model_dump(mode="json")
    assert facts["basis"] == "declared_allow_condition"
    assert facts["profile_id"] == profile.profile_id and facts["profile_version"] == "17"
    assert facts["profile_sha256"] == sha256(profile.model_dump_json().encode()).hexdigest()
    assert facts["source_ranges"][0]["ranges"] == [
        {"start": "198.51.100.128", "end": "198.51.100.255"}
    ]
    assert facts["destination_ranges"][0]["ranges"] == [
        {"start": "192.0.2.20", "end": "192.0.2.20"}
    ]
    assert facts["destination_port_ranges"] == [[port, port]]
    assert any("first-match" in item for item in finding.evidence.limitations)
    assert finding.recommendation


def test_approved_admin_exceptions_are_unioned_and_service_boundaries_remain_exact():
    values = exposure_profile().model_dump(mode="python")
    values["trusted_admin_networks"] = ("198.51.100.0/25", "198.51.100.128/25")
    check = UntrustedAdministrativeAccessCheck(PolicyExposureProfile.model_validate(values))
    accepted = check.evaluate(
        exposure_context(
            exposure_rule(source="198.51.100.0/24", destination="192.0.2.3/32", start=22, end=22)
        )
    )
    other_port = check.evaluate(
        exposure_context(exposure_rule(destination="192.0.2.3/32", start=21, end=21))
    )
    other_target = check.evaluate(
        exposure_context(exposure_rule(destination="203.0.113.3/32", start=22, end=22))
    )
    assert all(
        result.status == CheckStatus.COMPLETE for result in (accepted, other_port, other_target)
    )
    assert not any(result.findings for result in (accepted, other_port, other_target))


def test_missing_disabled_unknown_and_budget_are_distinct_from_safe_admin_configuration():
    current = exposure_context(exposure_rule(destination="192.0.2.3/32"))
    unknown_profile = UntrustedAdministrativeAccessCheck().evaluate(current)
    values = exposure_profile().model_dump(mode="python")
    values["administrative_targets"] = ()
    disabled = UntrustedAdministrativeAccessCheck(
        PolicyExposureProfile.model_validate(values)
    ).evaluate(current)
    unknown_match = UntrustedAdministrativeAccessCheck(exposure_profile()).evaluate(
        exposure_context(exposure_rule(match_status=DataStatus.UNKNOWN))
    )
    budget = UntrustedAdministrativeAccessCheck(exposure_profile(), max_operations=1).evaluate(
        current
    )
    assert unknown_profile.status == CheckStatus.PARTIAL
    assert codes(unknown_profile) >= {"EXPOSURE_POLICY_UNKNOWN", "CHECK_NOT_EXECUTED"}
    assert disabled.status == CheckStatus.NOT_APPLICABLE and not disabled.limitations
    assert unknown_match.status == CheckStatus.PARTIAL and "UNKNOWN_MATCH" in codes(unknown_match)
    assert budget.status == CheckStatus.PARTIAL and "EXPOSURE_LIMIT_REACHED" in codes(budget)
    assert not any(result.findings for result in (unknown_profile, disabled, unknown_match, budget))


def test_admin_saved_revision_and_profile_replay_preserve_identity_and_new_profile_is_distinct():
    current = exposure_context(exposure_rule(destination="192.0.2.3/32"))
    profile = exposure_profile()
    original = UntrustedAdministrativeAccessCheck(profile).evaluate(current)
    saved_revision = DeviceRevision.model_validate_json(current.revision.model_dump_json())
    saved_profile = PolicyExposureProfile.model_validate_json(profile.model_dump_json())
    replay = UntrustedAdministrativeAccessCheck(saved_profile).evaluate(
        PolicyCheckContext(saved_revision, current.analyzed_at)
    )
    assert replay.model_dump_json() == original.model_dump_json()
    changed = profile.model_dump(mode="python")
    changed["version"] = "organization-policy-next"
    updated = UntrustedAdministrativeAccessCheck(
        PolicyExposureProfile.model_validate(changed)
    ).evaluate(current)
    assert updated.findings[0].finding_id != original.findings[0].finding_id


def test_opposite_actions_preserve_ordered_rules_and_both_flow_witnesses():
    earlier = rule("denied-prefix", 10, ports=(1, 4), action=RuleAction.DENY)
    later = rule("target", 20, action=RuleAction.ALLOW)
    result = evaluate(PartialShadowedRulesCheck(), earlier, later)
    finding = target_findings(result)[0]
    facts = finding.evidence.facts
    assert result.status == CheckStatus.COMPLETE
    assert result.check_version == "1.1.0"
    assert facts["covering_rule_ids"] == ["denied-prefix"]
    assert facts["target_rule_id"] == "target" and facts["first_match_owners_known"]
    assert [item["action"] for item in facts["rules"]] == ["deny", "allow"]
    assert [item["sequence"] for item in facts["rules"]] == [10, 20]
    assert facts["covered_witness"]["destination_port"] == 1
    assert facts["residual_witness"]["destination_port"] == 5
    assert finding.evidence.source_locations == (earlier.source_location, later.source_location)
    reversed_order = evaluate(
        PartialShadowedRulesCheck(),
        earlier.model_copy(update={"sequence": 20}),
        later.model_copy(update={"sequence": 10}),
    )
    assert not target_findings(reversed_order)


def test_mixed_action_union_retains_first_match_owners_and_does_not_invent_allow_access():
    first = rule("deny-lower", 1, ports=(1, 4), action=RuleAction.DENY)
    second = rule("permit-upper", 2, ports=(5, 8), action=RuleAction.ALLOW)
    target = rule("target", 3, action=RuleAction.DENY)
    result = evaluate(UnionShadowedRulesCheck(), first, second, target)
    finding = target_findings(result)[0]
    facts = finding.evidence.facts
    assert facts["coverage_kind"] == "full_union"
    assert facts["covering_rule_ids"] == ["deny-lower", "permit-upper"]
    assert facts["residual_witness"] is None and facts["residual_fragments"] == 0
    assert [item["action"] for item in facts["rules"]] == ["deny", "allow", "deny"]
    assert "достижимость" in " ".join(finding.evidence.limitations)
    saved = DeviceRevision.model_validate_json(revision(first, second, target).model_dump_json())
    replay = UnionShadowedRulesCheck().evaluate(
        PolicyCheckContext(saved, result.findings[0].first_seen)
    )
    assert json.loads(result.model_dump_json()) == json.loads(replay.model_dump_json())


@pytest.mark.parametrize("check", [PartialShadowedRulesCheck(), UnionShadowedRulesCheck()])
def test_ordered_acl_guarantee_does_not_apply_to_unknown_or_unordered_group_semantics(check):
    source = rule("source", 1, ports=(1, 4))
    target = rule("target", 2)
    result = evaluate(
        check,
        source.model_copy(update={"policy_semantics": None}),
        target.model_copy(update={"policy_semantics": None}),
    )
    assert result.status == CheckStatus.PARTIAL and not result.findings
    assert "CHECK_NOT_EXECUTED" in codes(result)


def test_unknown_predecessor_and_budget_keep_coverage_uncertainty_visible():
    unknown = rule("unresolved", 1, match_status=DataStatus.UNKNOWN)
    low = rule("lower", 2, ports=(1, 4))
    high = rule("upper", 3, ports=(5, 8))
    target = rule("target", 4)
    partial = evaluate(PartialShadowedRulesCheck(), unknown, low, target)
    assert partial.status == CheckStatus.PARTIAL and not target_findings(partial)
    assert "UNKNOWN_EARLIER_MATCH" in codes(partial)
    full = evaluate(UnionShadowedRulesCheck(), unknown, low, high, target)
    finding = target_findings(full)[0]
    assert full.status == CheckStatus.PARTIAL
    assert finding.evidence.facts["first_match_owners_known"] is False
    assert finding.evidence.facts["uncertain_predecessor_ids"] == ["unresolved"]
    exhausted = evaluate(UnionShadowedRulesCheck(max_operations=1), low, high, target)
    assert exhausted.status == CheckStatus.PARTIAL and not exhausted.findings
    assert "COVERAGE_LIMIT" in codes(exhausted)
