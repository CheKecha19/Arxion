"""Позитивные и отрицательные сценарии независимых проверок политик."""

from datetime import datetime
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.policy_fixtures import endpoint, policy_revision, rule

from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.analysis.policy_checks import (
    AnyAnyCheck,
    CommentsCheck,
    DisabledRulesCheck,
    DuplicateRulesCheck,
    LoggingCheck,
    MergeCandidateCheck,
    PolicyCheckContext,
    ShadowedRulesCheck,
)
from firewall_compliance.domain import (
    DataStatus,
    Endpoint,
    EndpointKind,
    ParseIssue,
    ParseIssueLevel,
    Protocol,
    RuleAction,
    Service,
)
from firewall_compliance.domain.assurance import CheckResult, CheckStatus


def test_any_any_is_scoped_service_risk_not_reachability_claim() -> None:
    revision = policy_revision(rule(1, sources=(endpoint(),), destinations=(endpoint(),)))
    result = AnyAnyCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.revision_id == revision.revision_id
    assert finding.evidence.source_locations
    assert finding.evidence.limitations


@pytest.mark.parametrize(
    "changes",
    [
        {"action": RuleAction.DENY},
        {"enabled": False},
        {"match_status": DataStatus.UNKNOWN},
        {"sources": (endpoint("192.0.2.0/24"),)},
        {"sources": (Endpoint(endpoint_id="missing", name="missing", kind=EndpointKind.GROUP),)},
        {"services": (Service(service_id="other", name="other", protocol=Protocol.OTHER),)},
    ],
)
def test_any_any_does_not_guess_unknown_matches_or_flag_deny(changes: dict) -> None:
    revision = policy_revision(
        rule(
            1,
            **{
                "sources": (endpoint(),),
                "destinations": (endpoint(),),
                **changes,
            },
        )
    )
    result = AnyAnyCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert not result.findings


def test_unknown_match_is_reported_as_partial_not_empty_success() -> None:
    revision = policy_revision(rule(1, match_status=DataStatus.UNSUPPORTED))
    result = AnyAnyCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert result.status == CheckStatus.PARTIAL
    assert result.limitations[0].rule_ids == ("rule-1",)


def test_any_any_requires_a_shared_address_family() -> None:
    revision = policy_revision(
        rule(
            1,
            sources=(endpoint("0.0.0.0/0"),),
            destinations=(endpoint("::/0"),),
        )
    )
    result = AnyAnyCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert not result.findings


def test_unknown_action_is_not_silently_assumed_to_be_non_applicable() -> None:
    revision = policy_revision(rule(1, action=RuleAction.UNKNOWN))
    context = PolicyCheckContext(revision, revision.imported_at)
    assert AnyAnyCheck().evaluate(context).status == CheckStatus.PARTIAL
    assert LoggingCheck().evaluate(context).status == CheckStatus.PARTIAL


def test_unknown_duplicate_effect_is_explicitly_partial() -> None:
    revision = policy_revision(rule(1), rule(2, logging_status=DataStatus.UNKNOWN))
    result = DuplicateRulesCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert not result.findings
    assert result.status == CheckStatus.PARTIAL


@pytest.mark.parametrize(
    "network,host",
    [
        ("0.0.0.0/0", "203.0.113.10/32"),
        ("::/0", "2001:db8::1/128"),
    ],
)
def test_any_and_single_family_universe_are_semantic_duplicates(network: str, host: str) -> None:
    revision = policy_revision(
        rule(1, sources=(endpoint(),), destinations=(endpoint(host),)),
        rule(2, sources=(endpoint(network),), destinations=(endpoint(host),)),
    )
    context = PolicyCheckContext(revision, revision.imported_at)
    assert len(DuplicateRulesCheck().evaluate(context).findings) == 1
    assert not ShadowedRulesCheck().evaluate(context).findings


def test_non_applicable_check_cannot_contain_findings() -> None:
    revision = policy_revision(rule(1, enabled=False))
    finding = (
        DisabledRulesCheck()
        .evaluate(PolicyCheckContext(revision, revision.imported_at))
        .findings[0]
    )
    with pytest.raises(ValidationError, match="not_applicable"):
        CheckResult(
            check_id="FW-DISABLED",
            check_version="1.0.0",
            status=CheckStatus.NOT_APPLICABLE,
            findings=(finding,),
        )


def test_structural_duplicates_can_also_be_shadowed_by_earlier_blocker() -> None:
    revision = policy_revision(rule(1, action=RuleAction.DENY), rule(2), rule(3))
    context = PolicyCheckContext(revision, revision.imported_at)
    assert DuplicateRulesCheck().evaluate(context).findings[0].affected_rule_ids == (
        "rule-2",
        "rule-3",
    )
    assert {f.affected_rule_ids for f in ShadowedRulesCheck().evaluate(context).findings} == {
        ("rule-1", "rule-2"),
        ("rule-1", "rule-3"),
    }


def test_merge_candidates_exclude_shadowed_neighbors() -> None:
    revision = policy_revision(
        rule(1, action=RuleAction.DENY, destinations=(endpoint(),)),
        rule(2),
        rule(3, destinations=(endpoint("203.0.113.20/32"),)),
    )
    result = MergeCandidateCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert not result.findings


def test_duplicate_conditions_ignore_object_names_and_input_order() -> None:
    revision = policy_revision(rule(2), rule(1))
    result = DuplicateRulesCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert [finding.affected_rule_ids for finding in result.findings] == [("rule-1", "rule-2")]


@pytest.mark.parametrize(
    "changes",
    [
        {"policy_id": "OTHER"},
        {"policy_direction": "out"},
        {"source_zone": "inside"},
        {"policy_id": None},
        {"zone_status": DataStatus.UNKNOWN},
        {"match_status": DataStatus.UNKNOWN},
        {"logging_enabled": False},
        {"enabled": False},
    ],
)
def test_duplicate_never_crosses_scope_or_effect(changes: dict) -> None:
    revision = policy_revision(rule(1), rule(2, **changes))
    result = DuplicateRulesCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert not result.findings


def test_shadowing_preserves_blocking_action_and_cidr_inclusion() -> None:
    revision = policy_revision(
        rule(1, action=RuleAction.DENY, sources=(endpoint("192.0.2.0/24"),)),
        rule(2, sources=(endpoint("192.0.2.20/32"),)),
    )
    result = ShadowedRulesCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert result.findings[0].affected_rule_ids == ("rule-1", "rule-2")
    assert result.findings[0].evidence.facts["rules"][0]["action"] == "deny"


def test_broader_later_rule_is_not_fully_shadowed() -> None:
    revision = policy_revision(rule(1, sources=(endpoint("192.0.2.20/32"),)), rule(2))
    result = ShadowedRulesCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert not result.findings


def test_duplicate_is_not_reported_again_as_shadowing() -> None:
    revision = policy_revision(rule(1), rule(2))
    result = ShadowedRulesCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert not result.findings


def test_merge_candidate_requires_one_axis_and_adjacency() -> None:
    revision = policy_revision(rule(1), rule(2, destinations=(endpoint("203.0.113.20/32"),)))
    result = MergeCandidateCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert result.findings[0].affected_rule_ids == ("rule-1", "rule-2")
    interrupted = policy_revision(
        rule(1),
        rule(2, action=RuleAction.DENY),
        rule(3, destinations=(endpoint("203.0.113.20/32"),)),
    )
    assert (
        not MergeCandidateCheck()
        .evaluate(PolicyCheckContext(interrupted, interrupted.imported_at))
        .findings
    )


def test_merge_candidate_does_not_create_cross_product_access() -> None:
    revision = policy_revision(
        rule(1),
        rule(
            2,
            sources=(endpoint("198.51.100.0/24"),),
            destinations=(endpoint("203.0.113.20/32"),),
        ),
    )
    result = MergeCandidateCheck().evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert not result.findings


def test_unknown_logging_and_description_are_diagnostics() -> None:
    revision = policy_revision(
        rule(1, logging_status=DataStatus.UNKNOWN, description_status=DataStatus.UNKNOWN)
    )
    context = PolicyCheckContext(revision, revision.imported_at)
    for check in (LoggingCheck(), CommentsCheck()):
        result = check.evaluate(context)
        assert not result.findings
        assert result.status == CheckStatus.PARTIAL


def test_policy_preferences_are_explicit_and_disabled_is_inventory() -> None:
    revision = policy_revision(rule(1, enabled=False))
    context = PolicyCheckContext(revision, revision.imported_at, False, False)
    assert LoggingCheck().evaluate(context).status == CheckStatus.NOT_APPLICABLE
    assert CommentsCheck().evaluate(context).status == CheckStatus.NOT_APPLICABLE
    assert DisabledRulesCheck().evaluate(context).findings[0].severity.value == "info"


@pytest.mark.parametrize(
    "check", [DuplicateRulesCheck(), ShadowedRulesCheck(), MergeCandidateCheck()]
)
def test_incomplete_parse_blocks_pair_claims(check) -> None:
    revision = policy_revision(
        rule(1),
        rule(2),
        warnings=(
            ParseIssue(
                code="UNSUPPORTED_ACCESS_LIST",
                level=ParseIssueLevel.WARNING,
                message="Неполная ACL.",
            ),
        ),
    )
    result = check.evaluate(PolicyCheckContext(revision, revision.imported_at))
    assert not result.findings
    assert result.status == CheckStatus.PARTIAL


def test_pair_limit_and_ambiguous_order_are_explained() -> None:
    revision = policy_revision(rule(1), rule(2))
    result = DuplicateRulesCheck().evaluate(
        PolicyCheckContext(revision, revision.imported_at, max_pair_rules=1)
    )
    assert result.limitations[0].code == "PAIR_LIMIT"
    ambiguous = policy_revision(rule(1), rule(1, rule_id="another"))
    result = DuplicateRulesCheck().evaluate(PolicyCheckContext(ambiguous, ambiguous.imported_at))
    assert result.limitations[0].code == "AMBIGUOUS_ORDER"


def test_catalog_is_deterministic_and_does_not_mutate_revision() -> None:
    revision = policy_revision(rule(1, logging_enabled=False), rule(2))
    before = revision.model_dump_json()
    result = analyze_firewall(revision)
    assert len(result.checks) == 7
    assert result.model_dump_json() == analyze_firewall(revision).model_dump_json()
    assert revision.model_dump_json() == before
    assert all(
        finding.revision_id == revision.revision_id
        for check in result.checks
        for finding in check.findings
    )


def test_analysis_rejects_naive_time_and_duplicate_check_ids() -> None:
    revision = policy_revision(rule(1))
    with pytest.raises(ValueError, match="время анализа"):
        analyze_firewall(revision, analyzed_at=datetime(2026, 10, 9))
    with pytest.raises(ValueError, match="уникальными"):
        analyze_firewall(revision, checks=(AnyAnyCheck(), AnyAnyCheck()))


def test_findings_are_distinct_for_repeated_imports() -> None:
    revision = policy_revision(rule(1, sources=(endpoint(),), destinations=(endpoint(),)))
    after = revision.model_copy(
        update={"revision_id": UUID("10000000-0000-0000-0000-000000000099")}
    )
    before_result, after_result = analyze_firewall(revision), analyze_firewall(after)
    assert (
        before_result.checks[0].findings[0].finding_id
        != after_result.checks[0].findings[0].finding_id
    )
