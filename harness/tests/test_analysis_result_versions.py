"""Saved policy reports replay their exact evidence version, without migration."""

import json

import pytest
from pydantic import ValidationError
from test_analysis_result import bundle
from test_policy_exposure import profile
from test_policy_union_shadowing import NOW, revision, rule

from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.analysis.policy_checks import (
    PartialShadowedRulesCheck,
    UnionShadowedRulesCheck,
)
from firewall_compliance.analysis.policy_exposure import (
    DangerousServicesCheck,
    UntrustedAdministrativeAccessCheck,
)
from firewall_compliance.application.analysis_result import (
    AnalysisResult,
    PolicyAnalysisOptions,
    PolicyComponent,
    replay_policy,
)
from firewall_compliance.domain import RuleAction
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile


def example(version):
    current = revision(
        rule("low", 1, ports=(1, 4), action=RuleAction.DENY),
        rule("high", 2, ports=(5, 8), action=RuleAction.DENY),
        rule("target", 3, action=RuleAction.ALLOW),
        rule("partial", 4, ports=(1, 9), action=RuleAction.ALLOW),
    )
    values = profile().model_dump(mode="python")
    values["administrative_targets"] = ("0.0.0.0/24",)
    values["trusted_admin_networks"] = ()
    for key in ("dangerous_services", "administrative_services"):
        values[key] = (
            {
                "selector_id": key,
                "name": "Synthetic organization selector",
                "protocol": "tcp",
                "port_ranges": ({"start": 1, "end": 9},),
            },
        )
    policy = PolicyExposureProfile.model_validate(values)
    checks = (
        DangerousServicesCheck(policy, evidence_version=version),
        UntrustedAdministrativeAccessCheck(policy, evidence_version=version),
        PartialShadowedRulesCheck(evidence_version=version),
        UnionShadowedRulesCheck(evidence_version=version),
    )
    report = analyze_firewall(current, analyzed_at=NOW, checks=checks)
    options = PolicyAnalysisOptions(
        check_ids=tuple(check.check_id for check in checks), exposure_profile=policy
    )
    return current, options, report


@pytest.mark.parametrize("version", ["1.0.0", "1.1.0"])
def test_saved_report_and_common_bundle_replay_exact_recorded_evidence_version(version):
    current, options, report = example(version)
    assert all(check.check_version == version for check in report.checks)
    assert all(check.findings for check in report.checks)
    replay = replay_policy(
        current,
        options,
        NOW,
        check_versions={check.check_id: check.check_version for check in report.checks},
    )
    assert replay.model_dump_json() == report.model_dump_json()
    component = PolicyComponent(
        component_id="recorded-policy", revision=current, options=options, result=report
    )
    saved = bundle(component)
    encoded = saved.model_dump_json()
    assert AnalysisResult.model_validate_json(encoded).model_dump_json() == encoded


def test_new_evidence_keeps_old_finding_identity_without_mutating_legacy_fact_shape():
    _, _, old = example("1.0.0")
    _, _, new = example("1.1.0")
    old_snapshot = old.model_dump_json()
    for before, after in zip(old.checks, new.checks, strict=True):
        assert [item.finding_id for item in before.findings] == [
            item.finding_id for item in after.findings
        ]
        for old_finding, new_finding in zip(before.findings, after.findings, strict=True):
            previous = old_finding.evidence.facts
            next_facts = new_finding.evidence.facts
            if before.check_id in {"FW-DANGEROUS-SERVICES", "FW-ADMIN-UNTRUSTED"}:
                assert "witness_flow" not in previous
                assert {
                    key: value for key, value in next_facts.items() if key != "witness_flow"
                } == previous
            else:
                assert "ordered_overlaps" not in previous
                old_shape = {
                    key: value
                    for key, value in next_facts.items()
                    if key
                    not in {
                        "ordered_overlaps",
                        "overlap_classification",
                        "decision_order_dependent",
                        "action_order_dependent",
                    }
                }
                old_shape["check_version"] = "1.0.0"
                assert old_shape == previous
    assert old.model_dump_json() == old_snapshot


def test_unsupported_or_falsely_labelled_saved_evidence_version_is_rejected():
    current, options, report = example("1.0.0")
    component = PolicyComponent(
        component_id="recorded-policy", revision=current, options=options, result=report
    )
    saved = bundle(component).model_dump(mode="json")
    for version in ("2.0.0", "1.1.0"):
        changed = json.loads(json.dumps(saved))
        changed["components"][0]["result"]["checks"][0]["check_version"] = version
        with pytest.raises(ValidationError):
            AnalysisResult.model_validate(changed)


def test_json_key_order_is_irrelevant_but_boolean_numeric_tampering_is_rejected():
    current, options, report = example("1.1.0")
    component = PolicyComponent(
        component_id="recorded-policy", revision=current, options=options, result=report
    )
    saved = bundle(component).model_dump(mode="json")
    facts = saved["components"][0]["result"]["checks"][2]["findings"][0]["evidence"]["facts"]
    assert facts["first_match_owners_known"] is True
    reversed_facts = dict(reversed(tuple(facts.items())))
    saved["components"][0]["result"]["checks"][2]["findings"][0]["evidence"]["facts"] = (
        reversed_facts
    )
    assert AnalysisResult.model_validate_json(json.dumps(saved))
    reversed_facts["first_match_owners_known"] = 1
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate_json(json.dumps(saved))
