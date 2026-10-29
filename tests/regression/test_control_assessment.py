"""Synthetic control assessment retains exact evidence, coverage and exceptions."""

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from firewall_compliance.application.analysis_result import (
    AnalysisResult,
    ComponentLimitation,
    FindingDecision,
)
from firewall_compliance.application.analysis_workflow import analyze_source_result
from firewall_compliance.application.control_assessment import (
    DISCLAIMER,
    ControlAssessment,
    assess_controls,
    export_control_assessment_csv,
    export_control_assessment_html,
    export_control_assessment_json,
    internal_control_catalogue,
)
from firewall_compliance.domain.controls import (
    ControlException,
    ControlRequirement,
    OrganizationControlProfile,
)
from firewall_compliance.domain.enums import FindingStatus
from firewall_compliance.domain.network import PortRange
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile, PolicyServiceSelector
from firewall_compliance.parsers import SourceDocument
from firewall_compliance.parsers.catalog import create_default_registry

AT = datetime(2026, 10, 28, 5, tzinfo=UTC)


def source_result(*, content=None, **options):
    return analyze_source_result(
        SourceDocument(
            source_name="SYNTHETIC-controls.cfg",
            captured_at=AT,
            content=content
            or (
                b"hostname SYNTHETIC\n"
                b"access-list TEST extended permit ip any any log\n"
                b"access-group TEST in interface outside\n"
            ),
        ),
        create_default_registry(),
        imported_at=AT,
        **options,
    )


def profile(*controls, **values):
    return OrganizationControlProfile(
        profile_id="synthetic-organization-policy",
        version="1",
        organization="Synthetic organization",
        scope_reference="Selected authored policy bundle only",
        requirements=tuple(
            ControlRequirement(control_id=value, applicable=True, justification="Explicit policy")
            for value in controls or ("TECH-BROAD-ALLOW",)
        ),
        **values,
    )


def assess(source=None, selected=None, catalogue=None, **values):
    return assess_controls(
        source or source_result(),
        selected or profile(),
        catalogue or internal_control_catalogue(),
        assessed_at=values.pop("assessed_at", AT + timedelta(hours=1)),
        **values,
    )


def test_internal_catalogue_only_maps_bounded_internal_claims():
    catalogue = internal_control_catalogue()
    assert len(catalogue.controls) == len(catalogue.mappings) == 5
    assert all("internal" in value.source for value in catalogue.mappings)
    assert all(
        value.edition and value.covered_part and value.limits for value in catalogue.mappings
    )
    assert "NIST" not in catalogue.model_dump_json()
    assert "CIS" not in catalogue.model_dump_json()


def test_violation_and_no_violation_are_distinct_and_coverage_counts_real_checks():
    result = assess(selected=profile("TECH-BROAD-ALLOW", "TECH-POLICY-LOGGING"))
    assert [row.state for row in result.evaluations] == [
        "technical_violation",
        "no_violation_in_examined_scope",
    ]
    assert result.coverage.executed_check_evaluations == 2
    assert result.coverage.fully_examined_evaluations == 2
    assert result.coverage.violations == 1
    assert result.source.components[0].result.checks[0].findings[0].finding_id in (
        result.evaluations[0].evidence[0].finding_ids
    )


def test_missing_check_does_not_count_as_safe_or_executed():
    result = assess(selected=profile("TECH-ADMIN-SOURCES"))
    assert result.evaluations[0].state == "insufficient_evidence"
    assert result.evaluations[0].evidence[0].execution == "missing"
    assert result.coverage.executed_check_evaluations == 0


def test_executed_partial_scope_is_separate_from_unexecuted_unknown_profile():
    exposure = PolicyExposureProfile(
        administrative_services=(
            PolicyServiceSelector(
                selector_id="ssh",
                name="Authored SSH",
                protocol="tcp",
                port_ranges=(PortRange(start=22, end=22),),
            ),
        ),
        administrative_targets=("192.0.2.1/32",),
        trusted_admin_networks=("198.51.100.0/24",),
    )
    source = source_result(
        content=(
            b"hostname SYNTHETIC\n"
            b"access-list TEST extended permit tcp host 198.51.100.1 host 192.0.2.1 eq 22\n"
            b"access-list TEST extended permit tcp object UNKNOWN host 192.0.2.1 eq 22\n"
            b"access-group TEST in interface outside\n"
        ),
        extended_policy_checks=True,
        policy_exposure_profile=exposure,
    )
    result = assess(source, profile("TECH-ADMIN-SOURCES"))
    assert result.evaluations[0].state == "insufficient_evidence"
    assert result.evaluations[0].evidence[0].execution == "partial"
    assert result.coverage.executed_check_evaluations == 1
    assert result.coverage.sufficient_check_evaluations == 0


def test_invalid_parameter_boolean_does_not_match_python_integer_equality():
    with pytest.raises(ValueError, match="booleans"):
        ControlRequirement(
            control_id="TECH-BROAD-ALLOW",
            applicable=True,
            justification="Synthetic",
            parameters={"require_logging": 1},
        )


def test_exception_cannot_waive_unrelated_control_finding():
    source = source_result()
    wrong = exception_for(source, control_id="TECH-POLICY-LOGGING")
    with pytest.raises(ValueError, match="mapping"):
        assess(source, profile("TECH-POLICY-LOGGING", exceptions=(wrong,)))


def test_not_executed_unknown_profile_is_insufficient_with_no_findings():
    source = source_result(extended_policy_checks=True)
    result = assess(source, profile("TECH-ADMIN-SOURCES"))
    assert result.evaluations[0].state == "insufficient_evidence"
    assert result.evaluations[0].evidence[0].execution == "not_executed"
    assert result.coverage.executed_check_evaluations == 0
    assert result.coverage.sufficient_check_evaluations == 0


@pytest.mark.parametrize("kind", ["empty", "failed", "missing_component"])
def test_absent_or_failed_policy_never_becomes_no_violation(kind):
    source = source_result()
    selected = profile()
    if kind == "empty":
        source = AnalysisResult(application_version="synthetic", started_at=AT, finished_at=AT)
    elif kind == "failed":
        source = source_result(content=b"Unrecognized synthetic text\n")
    else:
        selected = profile(component_ids=("not-retained",))
    result = assess(source, selected)
    assert result.evaluations[0].state == "insufficient_evidence"
    assert result.coverage.executed_check_evaluations == 0
    assert result.coverage.insufficient_evidence == 1


def test_explicit_not_applicable_requires_justification_and_is_separate_from_coverage():
    selected = profile().model_copy(
        update={
            "requirements": (
                ControlRequirement(
                    control_id="TECH-BROAD-ALLOW",
                    applicable=False,
                    justification="Excluded by approved scope",
                ),
            )
        }
    )
    result = assess(selected=selected)
    assert result.evaluations[0].state == "not_applicable"
    assert result.coverage.not_applicable == 1
    assert result.coverage.applicable_evaluations == 0
    assert result.coverage.executed_check_evaluations == 0
    with pytest.raises(ValidationError):
        ControlRequirement(control_id="X", applicable=False, justification=" ")


@pytest.mark.parametrize(
    "option,control",
    [
        ("require_logging", "TECH-POLICY-LOGGING"),
        ("require_comments", "TECH-POLICY-COMMENTS"),
    ],
)
def test_disabled_requirement_is_not_successful_control_evidence(option, control):
    result = assess(source_result(**{option: False}), profile(control))
    assert result.evaluations[0].state == "insufficient_evidence"
    assert not result.evaluations[0].evidence[0].sufficient


def test_exact_profile_parameters_must_match_retained_analysis_options():
    selected = profile().model_copy(
        update={
            "requirements": (
                ControlRequirement(
                    control_id="TECH-BROAD-ALLOW",
                    applicable=True,
                    justification="Explicit mismatched policy",
                    parameters={"require_logging": False},
                ),
            )
        }
    )
    result = assess(selected=selected)
    assert result.evaluations[0].evidence[0].finding_ids
    assert result.evaluations[0].state == "insufficient_evidence"
    assert "PARAMETER_MISMATCH:require_logging" in result.evaluations[0].evidence[0].limitations


def test_unknown_check_version_preserves_finding_but_cannot_establish_violation():
    catalogue = internal_control_catalogue()
    mapping = catalogue.mappings[0].model_copy(update={"check_versions": ("99.0.0",)})
    catalogue = catalogue.model_copy(update={"mappings": (mapping, *catalogue.mappings[1:])})
    result = assess(catalogue=catalogue)
    assert result.evaluations[0].state == "insufficient_evidence"
    assert result.evaluations[0].evidence[0].finding_ids
    assert "CHECK_VERSION_UNMAPPED" in result.evaluations[0].evidence[0].limitations


def test_no_mapping_remains_insufficient_not_an_empty_pass():
    result = assess(catalogue=internal_control_catalogue().model_copy(update={"mappings": ()}))
    assert result.evaluations[0].state == "insufficient_evidence"
    assert result.evaluations[0].limitations == ("NO_TECHNICAL_MAPPING",)


def test_many_to_many_mapping_requires_each_check_for_complete_coverage():
    catalogue = internal_control_catalogue()
    first = catalogue.mappings[0]
    extra = catalogue.mappings[-1].model_copy(
        update={
            "mapping_id": "second-required-check",
            "control_id": first.control_id,
        }
    )
    catalogue = catalogue.model_copy(update={"mappings": (*catalogue.mappings, extra)})
    result = assess(catalogue=catalogue)
    assert result.evaluations[0].state == "technical_violation"
    assert len(result.evaluations[0].evidence) == 2
    assert result.coverage.expected_check_evaluations == 2
    assert result.coverage.fully_examined_evaluations == 0


def test_component_and_bundle_limitations_prevent_empty_success():
    source = source_result()
    source = source.model_copy(
        update={
            "limitations": (
                ComponentLimitation(
                    code="AUTHOR_SCOPE_UNKNOWN", message="Synthetic unavailable scope"
                ),
            )
        }
    )
    result = assess(source, profile("TECH-POLICY-LOGGING"))
    assert result.evaluations[0].state == "insufficient_evidence"
    assert result.evaluations[0].evidence[0].execution == "complete"
    assert result.coverage.sufficient_check_evaluations == 0


def exception_for(source, **updates):
    return ControlException(
        exception_id="approved-synthetic-exception",
        control_id="TECH-BROAD-ALLOW",
        component_id="policy",
        finding_id=source.components[0].result.checks[0].findings[0].finding_id,
        reason="Authored acceptance case",
        approved_by="Synthetic policy owner",
        approved_at=AT,
        expires_at=AT + timedelta(days=1),
    ).model_copy(update=updates)


@pytest.mark.parametrize("offset,active", [(1, True), (24, False), (25, False)])
def test_exception_is_time_bounded_and_does_not_erase_technical_finding(offset, active):
    source = source_result()
    selected = profile(exceptions=(exception_for(source),))
    result = assess(source, selected, assessed_at=AT + timedelta(hours=offset))
    evidence = result.evaluations[0].evidence[0]
    assert result.evaluations[0].state == "technical_violation"
    assert evidence.finding_ids
    assert bool(evidence.active_exception_ids) is active
    assert result.profile.exceptions[0].approved_by == "Synthetic policy owner"


def test_unapproved_future_exception_does_not_apply():
    source = source_result()
    exception = exception_for(source, approved_at=AT + timedelta(hours=2))
    result = assess(source, profile(exceptions=(exception,)))
    assert not result.evaluations[0].evidence[0].active_exception_ids


def test_exception_must_reference_existing_finding_and_selected_component():
    source = source_result()
    with pytest.raises(ValueError, match="exception"):
        assess(source, profile(exceptions=(exception_for(source, finding_id=uuid4()),)))
    with pytest.raises(ValueError, match="scope"):
        profile(component_ids=("other",), exceptions=(exception_for(source),))


def test_finding_status_is_retained_separately_and_does_not_change_technical_conclusion():
    source = source_result()
    finding = source.components[0].result.checks[0].findings[0]
    source = source.model_copy(
        update={
            "decisions": (
                FindingDecision(
                    component_id="policy",
                    finding_id=finding.finding_id,
                    status=FindingStatus.ACCEPTED_RISK,
                    comment="Synthetic accepted risk",
                    decided_at=AT + timedelta(minutes=2),
                ),
            )
        }
    )
    result = assess(source)
    assert result.evaluations[0].state == "technical_violation"
    assert result.source.decisions[0].status == FindingStatus.ACCEPTED_RISK
    assert not result.evaluations[0].evidence[0].active_exception_ids


def test_immutable_historical_profile_and_result_replay_without_current_settings():
    original = profile().model_dump(mode="python")
    selected = OrganizationControlProfile.model_validate(original)
    result = assess(selected=selected)
    original["requirements"][0]["parameters"]["require_logging"] = False
    assert result.profile.requirements[0].parameters == {}
    with pytest.raises(TypeError):
        result.profile.requirements[0].parameters["require_logging"] = False
    saved = result.model_dump_json()
    assert ControlAssessment.model_validate_json(saved) == result
    new_profile = selected.model_copy(update={"version": "2"})
    assert new_profile.version == "2" and result.profile.version == "1"


@pytest.mark.parametrize("change", ["state", "coverage", "profile", "mapping", "disclaimer"])
def test_tampered_assessment_claims_rejected(change):
    data = assess().model_dump(mode="json")
    if change == "state":
        data["evaluations"][0]["state"] = "no_violation_in_examined_scope"
    elif change == "coverage":
        data["coverage"]["violations"] = 0
    elif change == "profile":
        data["profile"]["requirements"][0]["applicable"] = False
    elif change == "mapping":
        data["catalogue"]["mappings"][0]["check_versions"] = ["99"]
    else:
        data["disclaimer"] = "Certified NIST compliant"
    with pytest.raises(ValueError):
        ControlAssessment.model_validate(data)


@pytest.mark.parametrize("date", [AT - timedelta(seconds=1), AT.replace(tzinfo=None)])
def test_assessment_date_requires_real_time_order_and_timezone(date):
    with pytest.raises(ValueError):
        assess(assessed_at=date)


@pytest.mark.parametrize("change", ["duplicate", "empty_scope", "unsupported_parameter"])
def test_invalid_profiles_do_not_silently_drop_requirements(change):
    selected = profile()
    values = {
        "duplicate": {"requirements": (selected.requirements[0], selected.requirements[0])},
        "empty_scope": {"component_ids": ()},
        "unsupported_parameter": {
            "requirements": (
                {
                    "control_id": "TECH-BROAD-ALLOW",
                    "applicable": True,
                    "justification": "Synthetic",
                    "parameters": {"unknown": True},
                },
            )
        },
    }
    with pytest.raises(ValueError):
        selected.model_copy(update=values[change])


def test_exports_preserve_states_and_escape_html_and_csv_formulas():
    source = source_result()
    component = source.components[0].model_copy(update={"component_id": "=SYNTHETIC<script>"})
    source = source.model_copy(update={"components": (component,)})
    selected = profile().model_copy(update={"organization": "<script>synthetic</script>"})
    result = assess(source, selected)
    assert ControlAssessment.model_validate_json(export_control_assessment_json(result)) == result
    html = export_control_assessment_html(result)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "NIST/CIS" in html and "technical_violation" in html
    rows = list(csv.DictReader(io.StringIO(export_control_assessment_csv(result))))
    assert rows[0]["component"].startswith("'=SYNTHETIC")
    assert json.loads(rows[0]["evidence"])["finding_ids"]


def test_assessment_scope_does_not_merge_or_hide_distinct_component_results():
    source = source_result()
    other = source.components[0].model_copy(update={"component_id": "same-source-second-capture"})
    source = source.model_copy(update={"components": (*source.components, other)})
    result = assess(source)
    assert result.coverage.evaluations == 2
    assert result.coverage.executed_check_evaluations == 2
    assert {row.component_id for row in result.evaluations} == {"policy", other.component_id}
    subset = assess(source, profile(component_ids=(other.component_id,)))
    assert subset.coverage.evaluations == 1


def test_unknown_catalogue_control_and_future_schema_rejected():
    with pytest.raises(ValueError, match="unknown"):
        assess(selected=profile("NOT-IN-CATALOGUE"))
    data = assess().model_dump(mode="json")
    data["schema_version"] = "99.0.0"
    with pytest.raises(ValueError):
        ControlAssessment.model_validate(data)


def test_copy_validates_not_enough_evidence_instead_of_reusing_old_claims():
    result = assess()
    with pytest.raises(ValueError):
        result.model_copy(update={"profile": profile("TECH-ADMIN-SOURCES")})
    changed = result.model_copy(
        update={
            "profile": profile("TECH-ADMIN-SOURCES"),
            "evaluations": None,
            "coverage": None,
        }
    )
    assert changed.evaluations[0].state == "insufficient_evidence"
    assert changed.disclaimer == DISCLAIMER


@pytest.mark.parametrize("kind", ["control_scope", "mapping_scope"])
def test_assessment_work_budget_refuses_oversized_scope_before_returning_claims(kind):
    catalogue = internal_control_catalogue()
    selected = profile(component_ids=tuple(f"not-retained-{index}" for index in range(1000)))
    if kind == "control_scope":
        extras = tuple(
            catalogue.controls[0].model_copy(update={"control_id": f"synthetic-{index}"})
            for index in range(10)
        )
        catalogue = catalogue.model_copy(update={"controls": (*catalogue.controls, *extras)})
        selected = selected.model_copy(
            update={
                "requirements": (
                    selected.requirements[0],
                    *(
                        ControlRequirement(
                            control_id=value.control_id,
                            applicable=True,
                            justification="Explicit synthetic budget case",
                        )
                        for value in extras
                    ),
                )
            }
        )
        message = "10000"
    else:
        extras = tuple(
            catalogue.mappings[0].model_copy(
                update={
                    "mapping_id": f"synthetic-map-{index}",
                    "check_id": f"SYNTHETIC-CHECK-{index}",
                }
            )
            for index in range(101)
        )
        catalogue = catalogue.model_copy(update={"mappings": extras})
        message = "100000"
    with pytest.raises(ValueError, match=message):
        assess(selected=selected, catalogue=catalogue)
