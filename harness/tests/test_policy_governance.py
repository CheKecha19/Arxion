"""Synthetic lifecycle and statistics evidence gates; no comments or zero-counter guesses."""

from datetime import timedelta, timezone
from uuid import uuid4

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError
from test_policy_exposure import AT, REVISION_ID, context, rule

from firewall_compliance.analysis.policy_governance import (
    RuleGovernanceCheck,
    UnusedRuleCandidatesCheck,
)
from firewall_compliance.domain import SourceLocation
from firewall_compliance.domain.enums import ParseIssueLevel
from firewall_compliance.domain.parse_result import ParseIssue
from firewall_compliance.domain.policy_governance import (
    PolicyGovernanceInputs,
    PolicyGovernanceProfile,
    RuleGovernanceMetadata,
    RuleObservationStatistics,
)


def profile(**changes):
    fields = dict(
        profile_id="synthetic-requirements",
        version="3",
        lifecycle_enabled=True,
        require_owner=True,
        require_justification=True,
        require_temporary_expiry=True,
        require_review_date=True,
        unused_enabled=True,
        unused_min_observation_seconds=3600,
        unused_max_age_seconds=60,
    )
    fields.update(changes)
    return PolicyGovernanceProfile(**fields)


def base_record(**changes):
    fields = dict(
        evidence_id="synthetic-record",
        revision_id=REVISION_ID,
        rule_id="r1",
        observed_at=AT,
        reference="Synthetic explicit organizational evidence",
        source_location=SourceLocation(source_name="synthetic.csv", object_path="$.rules.r1"),
    )
    fields.update(changes)
    return fields


def metadata(**changes):
    fields = dict(
        owner="Synthetic owner",
        justification="Approved synthetic test use",
        temporary=True,
        expiry_status="known",
        expires_at=AT + timedelta(seconds=1),
        review_status="known",
        review_at=AT + timedelta(seconds=1),
    )
    fields.update(changes)
    return RuleGovernanceMetadata(**base_record(**fields))


def stats(**changes):
    fields = dict(
        window_start=AT - timedelta(hours=1),
        window_end=AT,
        hits=0,
        count_kind="window_delta",
        coverage="complete",
        counter_resets=0,
        revision_stable=True,
    )
    fields.update(changes)
    return RuleObservationStatistics(**base_record(**fields))


def inputs(*, meta=None, observation=None, **changes):
    return PolicyGovernanceInputs(
        input_id="synthetic-inputs",
        revision_id=changes.pop("revision_id", REVISION_ID),
        metadata=(meta,) if meta is not None else (),
        statistics=(observation,) if observation is not None else (),
        **changes,
    )


def codes(result):
    return {item.code for item in result.limitations}


def test_lifecycle_known_absence_and_expiry_have_exact_evidence_and_evaluation_date():
    record = metadata(owner="", justification="", expires_at=AT, review_at=AT)
    document = inputs(meta=record)
    current = context(rule())
    check = RuleGovernanceCheck(profile(), document)
    result = check.evaluate(current)
    assert result.status.value == "complete" and len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity.value == "medium"
    assert finding.evidence.facts["violations"] == [
        "MISSING_OWNER",
        "MISSING_JUSTIFICATION",
        "TEMPORARY_PERMISSION_EXPIRED",
        "REVIEW_OVERDUE",
    ]
    assert finding.revision_id == REVISION_ID
    assert finding.evidence.facts["record"] == record.model_dump(mode="json")
    assert finding.evidence.facts["input_id"] == document.input_id
    assert finding.evidence.facts["profile_sha256"] == check.profile_sha256
    assert finding.evidence.facts["input_sha256"] == check.inputs_sha256
    assert finding.evidence.facts["evaluated_at"] == AT.isoformat()
    assert finding.evidence.source_locations == (
        current.revision.parse_result.rules[0].source_location,
        record.source_location,
    )
    assert "Не удалять" in finding.recommendation


def test_approved_metadata_and_positive_hit_window_produce_no_candidate():
    lifecycle = RuleGovernanceCheck(profile(), inputs(meta=metadata())).evaluate(context(rule()))
    usage = UnusedRuleCandidatesCheck(profile(), inputs(observation=stats(hits=1))).evaluate(
        context(rule())
    )
    assert lifecycle.status.value == usage.status.value == "complete"
    assert not lifecycle.findings and not usage.findings


def test_zero_hits_require_explicit_sufficient_stable_complete_window_and_are_only_a_candidate():
    record = stats()
    check = UnusedRuleCandidatesCheck(profile(), inputs(observation=record))
    result = check.evaluate(context(rule()))
    assert result.status.value == "complete" and len(result.findings) == 1
    finding = result.findings[0]
    assert finding.check_id == "FW-UNUSED-CANDIDATE" and finding.severity.value == "low"
    assert finding.evidence.facts["record"] == record.model_dump(mode="json")
    assert finding.evidence.facts["basis"] == "observed_usage_candidate"
    assert "Кандидат" in finding.title
    assert any(
        "не доказывает безопасность удаления" in value for value in finding.evidence.limitations
    )


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"hits": None}, "UNPROVEN_WINDOW_COUNTER"),
        ({"count_kind": "cumulative_sample"}, "UNPROVEN_WINDOW_COUNTER"),
        ({"coverage": "partial"}, "INCOMPLETE_OBSERVATION"),
        ({"coverage": "unknown"}, "INCOMPLETE_OBSERVATION"),
        ({"counter_resets": 1}, "COUNTER_RESET_UNKNOWN_OR_PRESENT"),
        ({"counter_resets": None}, "COUNTER_RESET_UNKNOWN_OR_PRESENT"),
        ({"revision_stable": False}, "UNSTABLE_POLICY_WINDOW"),
        ({"revision_stable": None}, "UNSTABLE_POLICY_WINDOW"),
        ({"window_start": None, "window_end": None}, "OBSERVATION_WINDOW_UNKNOWN"),
        ({"window_start": AT - timedelta(seconds=3599)}, "OBSERVATION_WINDOW_TOO_SHORT"),
        (
            {"window_start": AT - timedelta(hours=2), "window_end": AT - timedelta(seconds=61)},
            "OBSERVATION_TOO_OLD",
        ),
        ({"observed_at": AT + timedelta(seconds=1)}, "FUTURE_EVIDENCE"),
    ],
)
def test_zero_counter_without_each_evidence_gate_is_partial_not_a_finding(changes, code):
    result = UnusedRuleCandidatesCheck(profile(), inputs(observation=stats(**changes))).evaluate(
        context(rule())
    )
    assert result.status.value == "partial" and not result.findings
    assert {code, "CHECK_NOT_EXECUTED"} <= codes(result)


@pytest.mark.parametrize("check_type", [RuleGovernanceCheck, UnusedRuleCandidatesCheck])
def test_unknown_profile_inputs_and_explicit_disabled_requirement_are_distinct(check_type):
    current = context(rule(description="owner=guessed; hits=0; expires=2000-01-01"))
    unknown_profile = check_type().evaluate(current)
    unknown_data = check_type(profile()).evaluate(current)
    disabled = check_type(profile(lifecycle_enabled=False, unused_enabled=False)).evaluate(current)
    assert unknown_profile.status.value == unknown_data.status.value == "partial"
    assert "CHECK_NOT_EXECUTED" in codes(unknown_profile)
    assert "GOVERNANCE_INPUTS_UNKNOWN" in codes(unknown_data)
    assert disabled.status.value == "not_applicable" and not disabled.findings


def test_none_metadata_is_unknown_but_empty_string_is_known_absence():
    current = context(rule())
    missing = RuleGovernanceCheck(profile(), inputs(meta=metadata(owner=None))).evaluate(current)
    absent = RuleGovernanceCheck(profile(), inputs(meta=metadata(owner="   "))).evaluate(current)
    assert missing.status.value == "partial" and not missing.findings
    assert "RULE_METADATA_UNKNOWN" in codes(missing)
    assert absent.status.value == "complete"
    assert absent.findings[0].evidence.facts["violations"] == ["MISSING_OWNER"]


def test_unknown_requirements_keep_known_violations_in_partial_result():
    result = RuleGovernanceCheck(
        profile(require_justification=None), inputs(meta=metadata(owner=""))
    ).evaluate(context(rule()))
    assert result.status.value == "partial" and result.findings
    assert "GOVERNANCE_POLICY_UNKNOWN" in codes(result)
    assert "CHECK_NOT_EXECUTED" not in codes(result)


def test_absent_dates_and_unknown_temporary_flag_are_not_guessed_from_comments():
    record = metadata(
        expiry_status="absent", expires_at=None, review_status="absent", review_at=None
    )
    result = RuleGovernanceCheck(profile(), inputs(meta=record)).evaluate(context(rule()))
    assert result.findings[0].evidence.facts["violations"] == [
        "MISSING_TEMPORARY_EXPIRY",
        "MISSING_REVIEW_DATE",
    ]
    unknown = RuleGovernanceCheck(profile(), inputs(meta=metadata(temporary=None))).evaluate(
        context(rule())
    )
    assert unknown.status.value == "partial" and not unknown.findings
    permanent = RuleGovernanceCheck(
        profile(), inputs(meta=metadata(temporary=False, expiry_status="absent", expires_at=None))
    ).evaluate(context(rule()))
    assert permanent.status.value == "complete" and not permanent.findings


@pytest.mark.parametrize("check_type", [RuleGovernanceCheck, UnusedRuleCandidatesCheck])
def test_wrong_revision_or_unknown_rule_id_never_rebinds_by_name(check_type):
    foreign = uuid4()
    source = inputs(
        meta=metadata(revision_id=foreign),
        observation=stats(revision_id=foreign, evidence_id="statistics"),
        revision_id=foreign,
    )
    result = check_type(profile(), source).evaluate(context(rule()))
    assert result.status.value == "partial" and not result.findings
    assert "GOVERNANCE_REVISION_MISMATCH" in codes(result)
    orphaned = inputs(
        meta=metadata(rule_id="another"),
        observation=stats(rule_id="another", evidence_id="statistics"),
    )
    result = check_type(profile(), orphaned).evaluate(context(rule()))
    assert result.status.value == "partial" and not result.findings
    assert "ORPHAN_RULE_EVIDENCE" in codes(result)


@pytest.mark.parametrize("check_type", [RuleGovernanceCheck, UnusedRuleCandidatesCheck])
def test_disabled_rule_scope_is_an_explicit_profile_choice(check_type):
    source = inputs(meta=metadata(owner=""), observation=stats(evidence_id="statistics"))
    assert not check_type(profile(), source).evaluate(context(rule(enabled=False))).findings
    assert (
        check_type(profile(include_disabled_rules=True), source)
        .evaluate(context(rule(enabled=False)))
        .findings
    )


@pytest.mark.parametrize("check_type", [RuleGovernanceCheck, UnusedRuleCandidatesCheck])
def test_operation_limit_does_not_look_like_a_successful_empty_check(check_type):
    source = inputs(meta=metadata(owner=""), observation=stats(evidence_id="statistics"))
    result = check_type(profile(), source, max_operations=1).evaluate(context(rule()))
    assert result.status.value == "partial" and not result.findings
    assert {"GOVERNANCE_LIMIT_REACHED", "CHECK_NOT_EXECUTED"} <= codes(result)
    for invalid in (0, True, 10000001):
        with pytest.raises(ValueError):
            check_type(max_operations=invalid)


def test_inputs_and_profile_are_deep_snapshots_and_json_replay_is_stable():
    original_profile = profile()
    record = metadata(owner="")
    source = inputs(meta=record)
    check = RuleGovernanceCheck(original_profile, source)
    before = check.evaluate(context(rule()))
    record.source_location.source_name = "changed after constructor"
    assert check.evaluate(context(rule())).model_dump_json() == before.model_dump_json()
    with pytest.raises((TypeError, ValidationError)):
        check.inputs.metadata[0].source_location.source_name = "tampered"
    replay = RuleGovernanceCheck(
        PolicyGovernanceProfile.model_validate_json(original_profile.model_dump_json()),
        PolicyGovernanceInputs.model_validate_json(check.inputs.model_dump_json()),
    ).evaluate(context(rule()))
    assert replay.model_dump_json() == before.model_dump_json()
    changed = RuleGovernanceCheck(profile(version="next"), check.inputs).evaluate(context(rule()))
    assert changed.findings[0].finding_id != before.findings[0].finding_id


@pytest.mark.parametrize(
    "changes",
    [
        {"hits": True},
        {"hits": -1},
        {"counter_resets": True},
        {"window_end": AT - timedelta(hours=2)},
        {"window_start": None},
        {"observed_at": AT.replace(tzinfo=None)},
    ],
)
def test_statistics_reject_ambiguous_counts_times_or_invalid_window(changes):
    with pytest.raises(ValidationError):
        stats(**changes)


def test_input_record_uniqueness_and_revision_links_are_validated():
    with pytest.raises(ValidationError):
        inputs(meta=metadata(revision_id=uuid4()))
    with pytest.raises(ValidationError):
        inputs(meta=metadata(), observation=stats())
    with pytest.raises(ValidationError):
        PolicyGovernanceInputs(
            input_id="duplicate",
            revision_id=REVISION_ID,
            metadata=(metadata(), metadata(evidence_id="different")),
        )
    with pytest.raises(ValidationError):
        metadata(expiry_status="absent")
    with pytest.raises(ValidationError):
        PolicyGovernanceProfile.model_validate({"unused_enabled": "true"})


def test_equal_instants_with_different_offsets_have_same_expiry_decision():
    expiry = AT.astimezone(timezone(timedelta(hours=3)))
    result = RuleGovernanceCheck(profile(), inputs(meta=metadata(expires_at=expiry))).evaluate(
        context(rule())
    )
    assert result.findings[0].evidence.facts["violations"] == ["TEMPORARY_PERMISSION_EXPIRED"]


def test_future_metadata_cannot_be_used_to_claim_a_historical_violation():
    result = RuleGovernanceCheck(
        profile(), inputs(meta=metadata(owner="", observed_at=AT + timedelta(seconds=1)))
    ).evaluate(context(rule()))
    assert result.status.value == "partial" and not result.findings
    assert {"FUTURE_EVIDENCE", "CHECK_NOT_EXECUTED"} <= codes(result)


@pytest.mark.parametrize("check_type", [RuleGovernanceCheck, UnusedRuleCandidatesCheck])
def test_incomplete_parse_preserves_independently_proven_record_with_partial_status(check_type):
    source = inputs(meta=metadata(owner=""), observation=stats(evidence_id="statistics"))
    current = context(
        rule(),
        warnings=(
            ParseIssue(
                code="SYNTHETIC_LIMIT",
                level=ParseIssueLevel.WARNING,
                message="Synthetic limitation",
            ),
        ),
    )
    result = check_type(profile(), source).evaluate(current)
    assert result.findings and result.status.value == "partial"
    assert "INCOMPLETE_PARSE" in codes(result) and "CHECK_NOT_EXECUTED" not in codes(result)


def test_explicitly_empty_lifecycle_requirements_are_not_applicable_without_metadata():
    result = RuleGovernanceCheck(
        profile(
            require_owner=False,
            require_justification=False,
            require_temporary_expiry=False,
            require_review_date=False,
        )
    ).evaluate(context(rule()))
    assert result.status.value == "not_applicable"


@given(st.integers(min_value=-10, max_value=10))
@settings(max_examples=21)
def test_expiry_boundary_matches_explicit_time_comparison(offset):
    result = RuleGovernanceCheck(
        profile(), inputs(meta=metadata(expires_at=AT + timedelta(seconds=offset)))
    ).evaluate(context(rule()))
    assert bool(result.findings) is (offset <= 0)


@given(st.integers(min_value=3598, max_value=3602), st.integers(min_value=59, max_value=62))
@settings(max_examples=20)
def test_usage_period_and_freshness_boundaries(duration, age):
    end = AT - timedelta(seconds=age)
    record = stats(window_start=end - timedelta(seconds=duration), window_end=end)
    result = UnusedRuleCandidatesCheck(profile(), inputs(observation=record)).evaluate(
        context(rule())
    )
    assert bool(result.findings) is (duration >= 3600 and age <= 60)
