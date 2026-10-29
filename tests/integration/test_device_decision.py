"""Проверка локальных этапов без ложного конечного вердикта."""

import pytest
from tests.device_decision_fixtures import device_scenario
from tests.network_import_fixtures import import_scenario

from firewall_compliance.analysis.device_decision import (
    analyze_device_decisions,
    evaluate_interface,
)
from firewall_compliance.application.device_decision import analyze_imported_device
from firewall_compliance.domain.policy_decision import SingleDeviceDecisionResult


@pytest.mark.parametrize(
    ("scenario", "policy_status"),
    [
        ("allow", "allow"),
        ("no_match", "no_match"),
        ("implicit_deny", "implicit_deny"),
        ("incomplete", "not_enough_evidence"),
    ],
)
def test_imported_pipeline_local_only(scenario: str, policy_status: str) -> None:
    result = device_scenario(scenario)
    assert result.policy.status == policy_status
    assert result.route_selection.status == "selected"
    assert result.status in {"unknown", "not_enough_evidence"}
    assert any(reason.code == "forward_chain_pending" for reason in result.reasons)
    assert result.interfaces[0].status == "unknown"
    assert result.interfaces[1].status == "administratively_enabled"
    assert SingleDeviceDecisionResult.model_validate_json(result.model_dump_json()) == result


def test_mapping_cannot_substitute_other_physical_interface() -> None:
    imported = import_scenario()
    result = device_scenario()
    binding = result.policy.binding.model_copy(
        update={"interface_id": "interface:GigabitEthernet0/0"}
    )
    with pytest.raises(ValueError, match="label ACL"):
        analyze_imported_device(imported, result.policy.query, binding)


def test_mapping_rejects_disagreement_with_revision_fact() -> None:
    imported = import_scenario()
    result = device_scenario()
    payload = imported.model_dump(mode="python")
    payload["revision"]["interfaces"][1]["name"] = "OtherPhysicalInterface"
    changed = type(imported).model_validate(payload)
    with pytest.raises(ValueError, match="не совпадает с ревизией"):
        analyze_imported_device(changed, result.policy.query, result.policy.binding)


def test_mapping_evidence_is_preserved() -> None:
    result = device_scenario()
    mapping = result.policy.evidence.facts["interface_mapping"]
    assert mapping["settings"]["label"] == "inside"
    assert mapping["settings"]["source_locations"]
    assert len(mapping["content_sha256"]) == 64


def test_missing_interface_has_no_invented_state() -> None:
    result = evaluate_interface(import_scenario().revision, "missing")
    assert result.status == "unknown"
    assert result.interface is None


def test_input_import_is_unchanged() -> None:
    imported = import_scenario()
    before = imported.model_dump_json()
    result = device_scenario()
    analyze_imported_device(imported, result.policy.query, result.policy.binding)
    assert imported.model_dump_json() == before


def test_nested_result_is_immutable() -> None:
    result = device_scenario()
    with pytest.raises(TypeError):
        result.policy.evidence.facts["changed"] = True


@pytest.mark.parametrize("enabled", [True, False, None])
def test_administrative_state_is_not_operational(enabled: bool | None) -> None:
    revision = import_scenario().revision
    payload = revision.model_dump(mode="python")
    payload["interfaces"][0]["enabled"] = enabled
    updated = type(revision).model_validate(payload)
    result = evaluate_interface(updated, updated.interfaces[0].interface_id)
    expected = (
        "unknown"
        if enabled is None
        else "administratively_enabled"
        if enabled
        else "administratively_disabled"
    )
    assert result.status == expected
    assert result.evidence.limitations


def test_outbound_binding_not_on_route_does_not_claim_path() -> None:
    imported = import_scenario()
    result = device_scenario()
    binding = result.policy.binding.model_copy(update={"direction": "out"})
    analyzed = analyze_device_decisions(imported.revision, result.policy.query, binding)
    assert analyzed.status == "unknown"
    assert any(reason.code == "egress_binding_not_selected" for reason in analyzed.reasons)
