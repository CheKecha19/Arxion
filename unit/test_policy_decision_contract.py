"""Контракты локальных решений без запуска evaluator."""

from copy import copy, deepcopy
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.reachability_fixtures import make_query
from tests.revision_fixtures import CONFIGURATION_SOURCE_ID, make_revision

from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.policy_decision import (
    InterfaceDecisionResult,
    PolicyBindingEvidence,
    PolicyDecisionResult,
    PolicyTraceEntry,
    SingleDeviceDecisionResult,
)
from firewall_compliance.domain.reachability import AnalysisReason, RouteSelectionResult
from firewall_compliance.domain.revision import Interface
from firewall_compliance.domain.source import SourceLocation

EXPLICIT = ("allow", "deny", "drop", "reject")
UNCERTAIN = ("unknown", "not_enough_evidence")
RESOLVED = (*EXPLICIT, "no_match", "implicit_deny")


def _reason() -> AnalysisReason:
    return AnalysisReason(code="policy_pending", category="pending", message="Не хватает фактов.")


def _evidence() -> Evidence:
    return Evidence(summary="Локальное основание.", facts={"trace": [{"rule_id": "rule-1"}]})


def _binding(**changes: Any) -> PolicyBindingEvidence:
    return PolicyBindingEvidence.model_validate(
        {
            "policy_id": "ACL",
            "direction": "in",
            "interface_id": "interface:inside",
            "interface_label": "asa-ingress-label",
            "interface_mapping_reference": "synthetic:label-to-physical-id",
            "source_document_id": CONFIGURATION_SOURCE_ID,
            "binding_location": SourceLocation(source_name="fixture.config", line_start=10),
            "complete": True,
            "completeness_reference": "synthetic:complete-acl",
            "declaration_origin": "synthetic",
            "coordinate_space": "acl_input",
            **changes,
        }
    )


def _trace(outcome: str = "match", **changes: Any) -> PolicyTraceEntry:
    return PolicyTraceEntry.model_validate(
        {
            "rule_id": "rule-1",
            "sequence": 1,
            "outcome": outcome,
            "source_location": SourceLocation(source_name="fixture.config", line_start=1),
            **changes,
        }
    )


def _policy(status: str = "allow", **changes: Any) -> PolicyDecisionResult:
    explicit = status in EXPLICIT
    binding = _binding()
    if status == "implicit_deny":
        binding = _binding(implicit_action="deny", terminal=True, terminal_reference="end-of-acl")
    return PolicyDecisionResult.model_validate(
        {
            "query": make_query(),
            "binding": binding,
            "status": status,
            "matched_rule_id": "rule-1" if explicit else None,
            "trace": (
                (_trace(),)
                if explicit
                else (_trace("no_match"),)
                if status in {"no_match", "implicit_deny"}
                else ()
            ),
            "reasons": (_reason(),) if status in UNCERTAIN else (),
            "sources": make_revision().sources,
            "evidence": _evidence(),
            **changes,
        }
    )


def _interface(status: str = "administratively_enabled", **changes: Any) -> InterfaceDecisionResult:
    payload = make_revision().interfaces[0].model_dump(mode="python")
    payload["enabled"] = status == "administratively_enabled"
    return InterfaceDecisionResult.model_validate(
        {
            "interface_id": "interface:inside",
            "status": status,
            "interface": Interface.model_validate(payload) if status != "unknown" else None,
            "reasons": (_reason(),) if status == "unknown" else (),
            "evidence": _evidence(),
            **changes,
        }
    )


def _composite(**changes: Any) -> SingleDeviceDecisionResult:
    route = RouteSelectionResult(
        query=make_query(),
        status="no_route",
        sources=make_revision().sources,
        revision_schema_version="0.1.0",
        application_version="0.1.0a0",
        evidence=_evidence(),
    )
    return SingleDeviceDecisionResult.model_validate(
        {
            "status": "unknown",
            "route_selection": route,
            "interfaces": (_interface(),),
            "policy": _policy(),
            "reasons": (_reason(),),
            **changes,
        }
    )


@pytest.mark.parametrize(
    "flag,reference",
    [
        ("complete", "completeness_reference"),
        ("terminal", "terminal_reference"),
    ],
)
@pytest.mark.parametrize("value", [None, "", "   "])
def test_binding_requires_reference_for_asserted_flag(
    flag: str, reference: str, value: Any
) -> None:
    with pytest.raises(ValidationError):
        _binding(**{flag: True, reference: value})


@pytest.mark.parametrize("flag", ["complete", "terminal"])
@pytest.mark.parametrize("value", [0, 1, "true", "false", 1.0, None])
def test_binding_flags_are_strict_bool(flag: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        _binding(**{flag: value})


def test_binding_defaults_do_not_assert_completeness_or_terminal() -> None:
    payload = _binding().model_dump()
    for key in ("complete", "completeness_reference", "terminal", "terminal_reference"):
        payload.pop(key)
    result = PolicyBindingEvidence.model_validate(payload)
    assert result.complete is False
    assert result.terminal is False
    assert result.implicit_action == "unknown"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_binding_requires_explicit_interface_mapping_reference(value: Any) -> None:
    with pytest.raises(ValidationError):
        _binding(interface_mapping_reference=value)


def test_binding_mapping_reference_cannot_be_omitted() -> None:
    payload = _binding().model_dump()
    del payload["interface_mapping_reference"]
    with pytest.raises(ValidationError):
        PolicyBindingEvidence.model_validate(payload)


def test_binding_label_is_independent_of_interface_name_and_zone() -> None:
    binding = _binding()
    interface = make_revision().interfaces[0]
    assert binding.interface_id == interface.interface_id
    assert binding.interface_label not in {interface.name, interface.zone, interface.interface_id}


@pytest.mark.parametrize("status", (*RESOLVED, *UNCERTAIN))
def test_policy_accepts_consistent_status(status: str) -> None:
    result = _policy(status)
    assert result.status == status
    assert (result.matched_rule_id is not None) == (status in EXPLICIT)


def test_no_match_does_not_require_terminal_declaration() -> None:
    result = _policy("no_match", binding=_binding(implicit_action="deny"))
    assert result.binding.terminal is False
    assert result.matched_rule_id is None


@pytest.mark.parametrize(
    "changes",
    [
        {"terminal": False, "implicit_action": "deny"},
        {"terminal": True, "terminal_reference": "end-of-acl", "implicit_action": "unknown"},
    ],
)
def test_implicit_deny_requires_terminal_and_deny_default(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _policy("implicit_deny", binding=_binding(**changes))


@pytest.mark.parametrize("status", RESOLVED)
def test_resolved_policy_requires_complete_binding_and_no_reasons(status: str) -> None:
    with pytest.raises(ValidationError):
        _policy(status, binding=_binding(complete=False))
    with pytest.raises(ValidationError):
        _policy(status, reasons=(_reason(),))


@pytest.mark.parametrize("status", UNCERTAIN)
def test_uncertain_policy_requires_reason_and_forbids_matched_id(status: str) -> None:
    with pytest.raises(ValidationError):
        _policy(status, reasons=())
    with pytest.raises(ValidationError):
        _policy(status, matched_rule_id="rule-1")
    result = _policy(status, binding=_binding(complete=False), trace=(_trace("unknown"),))
    assert result.trace[0].outcome == "unknown"


@pytest.mark.parametrize("status", EXPLICIT)
@pytest.mark.parametrize("outcome", ["disabled", "no_match", "unknown"])
def test_explicit_policy_requires_matching_final_entry(status: str, outcome: str) -> None:
    with pytest.raises(ValidationError):
        _policy(status, trace=(_trace(outcome),))


@pytest.mark.parametrize(
    "changes",
    [
        {"trace": ()},
        {"matched_rule_id": None},
        {"matched_rule_id": "another-rule"},
    ],
)
def test_explicit_policy_requires_trace_and_exact_matched_id(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _policy(**changes)


@pytest.mark.parametrize("status", RESOLVED)
def test_unknown_predecessor_forbids_resolved_policy(status: str) -> None:
    trace = (_trace("unknown", rule_id="earlier", sequence=0),)
    if status in EXPLICIT:
        trace += (_trace(),)
    with pytest.raises(ValidationError):
        _policy(status, trace=trace)


def test_disabled_and_nonmatching_predecessors_allow_explicit_decision() -> None:
    result = _policy(
        trace=(
            _trace("disabled", rule_id="disabled", sequence=0),
            _trace("no_match", rule_id="different", sequence=1),
            _trace(sequence=2),
        )
    )
    assert result.matched_rule_id == result.trace[-1].rule_id


def test_trace_rejects_duplicate_rule_ids() -> None:
    with pytest.raises(ValidationError):
        _policy(trace=(_trace("no_match"), _trace(sequence=2)))


@pytest.mark.parametrize("value", [-1, True, "1", 1.0])
def test_trace_sequence_is_strict_nonnegative_integer(value: Any) -> None:
    with pytest.raises(ValidationError):
        _trace(sequence=value)


@pytest.mark.parametrize("status", ["no_match", "implicit_deny"])
def test_nonmatching_decision_rejects_match_in_trace(status: str) -> None:
    with pytest.raises(ValidationError):
        _policy(status, trace=(_trace(),))


@pytest.mark.parametrize("status", ["no_match", "implicit_deny"])
def test_nonmatching_decision_requires_checked_rules(status: str) -> None:
    with pytest.raises(ValidationError):
        _policy(status, trace=())
    assert _policy(status, trace=(_trace("disabled"),)).status == status


def test_explicit_first_match_rejects_earlier_match() -> None:
    with pytest.raises(ValidationError):
        _policy(trace=(_trace(rule_id="earlier", sequence=0), _trace()))


@pytest.mark.parametrize(
    "status,enabled",
    [
        ("administratively_enabled", True),
        ("administratively_disabled", False),
    ],
)
def test_interface_status_requires_matching_snapshot(status: str, enabled: bool) -> None:
    result = _interface(status)
    assert result.interface.enabled is enabled
    for changes in (
        {"interface": None},
        {"reasons": (_reason(),)},
        {"interface_id": "different-interface"},
    ):
        with pytest.raises(ValidationError):
            _interface(status, **changes)
    payload = result.interface.model_dump()
    payload["enabled"] = not enabled
    with pytest.raises(ValidationError):
        _interface(status, interface=Interface.model_validate(payload))


def test_unknown_interface_requires_reason() -> None:
    assert _interface("unknown").interface is None
    with pytest.raises(ValidationError):
        _interface("unknown", reasons=())


@pytest.mark.parametrize("status", ["administratively_enabled", "administratively_disabled"])
@pytest.mark.parametrize("data_status", [DataStatus.UNKNOWN, DataStatus.UNSUPPORTED])
def test_known_interface_decision_requires_known_fact(status: str, data_status: DataStatus) -> None:
    payload = _interface(status).interface.model_dump()
    payload["data_status"] = data_status
    with pytest.raises(ValidationError):
        _interface(status, interface=Interface.model_validate(payload))


@pytest.mark.parametrize(
    "field,value",
    [
        ("destination_port", 80),
        ("source_ip", "10.0.0.11"),
        ("destination_ip", "198.51.100.26"),
        ("ingress_interface_id", "interface:other"),
        ("table_id", "other"),
        ("device_id", "other"),
        ("device_context", "tenant"),
        ("revision_id", UUID("10000000-0000-0000-0000-000000000002")),
    ],
)
def test_composite_rejects_mismatched_query(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        _composite(policy=_policy(query=make_query(**{field: value})))


def test_composite_requires_reasons_and_unique_interfaces() -> None:
    with pytest.raises(ValidationError):
        _composite(reasons=())
    with pytest.raises(ValidationError):
        _composite(interfaces=(_interface(), _interface()))
    assert _composite(status="not_enough_evidence").status == "not_enough_evidence"


@pytest.mark.parametrize("factory", [_policy, _interface, _composite])
@pytest.mark.parametrize("status", ["reachable", "blocked"])
def test_local_contracts_forbid_final_reachability_status(factory: Any, status: str) -> None:
    with pytest.raises(ValidationError):
        factory(status=status)


@pytest.mark.parametrize("field", ["binding", "query", "trace", "reasons", "sources", "evidence"])
def test_policy_revalidates_nested_model_copy_bypass(field: str) -> None:
    result = _policy("unknown")
    invalid = {
        "binding": result.binding.model_copy(
            update={"complete": True, "completeness_reference": None}
        ),
        "query": result.query.model_copy(update={"destination_port": True}),
        "trace": (_trace().model_copy(update={"sequence": True}),),
        "reasons": (_reason().model_copy(update={"category": "invalid"}),),
        "sources": (result.sources[0].model_copy(update={"content_sha256": "bad"}),),
        "evidence": result.evidence.model_copy(update={"summary": ""}),
    }
    with pytest.raises(ValidationError):
        _policy("unknown", **{field: invalid[field]})


def test_interface_revalidates_nested_snapshot_invariants() -> None:
    invalid = _interface().interface.model_copy(update={"addresses": ()})
    with pytest.raises(ValidationError):
        _interface(interface=invalid)


@pytest.mark.parametrize("field", ["policy", "interfaces", "route_selection"])
def test_composite_revalidates_nested_model_copy_bypass(field: str) -> None:
    result = _composite()
    invalid = {
        "policy": result.policy.model_copy(update={"matched_rule_id": "missing"}),
        "interfaces": (result.interfaces[0].model_copy(update={"interface": None}),),
        "route_selection": result.route_selection.model_copy(
            update={"candidate_route_ids": ("x",)}
        ),
    }
    with pytest.raises(ValidationError):
        _composite(**{field: invalid[field]})


def test_snapshot_detaches_mutable_inputs_and_freezes_nested_facts() -> None:
    evidence = _evidence()
    location = SourceLocation(source_name="fixture.config", line_start=10)
    interface = Interface.model_validate(make_revision().interfaces[0].model_dump())
    result = _policy(evidence=evidence, binding=_binding(binding_location=location))
    interface_result = _interface(interface=interface)
    evidence.facts["trace"][0]["rule_id"] = "changed"
    location.source_name = "changed"
    assert interface_result.interface is not interface
    assert result.evidence.facts["trace"][0]["rule_id"] == "rule-1"
    assert result.binding.binding_location.source_name == "fixture.config"
    assert interface_result.interface.enabled is True
    with pytest.raises(TypeError):
        result.evidence.facts["trace"][0]["rule_id"] = "changed"
    with pytest.raises(TypeError):
        result.evidence.facts["trace"].append({})


@pytest.mark.parametrize("factory", [_binding, _trace, _policy, _interface, _composite])
@pytest.mark.parametrize("copier", [copy, deepcopy, lambda value: value.model_copy(deep=True)])
def test_copy_and_json_roundtrip_preserve_frozen_contract(factory: Any, copier: Any) -> None:
    original = factory()
    copied = copier(original)
    restored = type(original).model_validate_json(original.model_dump_json())
    for value in (original, copied, restored):
        assert value.model_dump(mode="json") == original.model_dump(mode="json")
        field = "rule_id" if isinstance(value, PolicyTraceEntry) else "schema_version"
        with pytest.raises((ValidationError, TypeError)):
            setattr(value, field, "changed")
        with pytest.raises((ValidationError, TypeError)):
            delattr(value, field)
        if hasattr(value, "evidence"):
            with pytest.raises(TypeError):
                value.evidence.facts.clear()
        if isinstance(value, SingleDeviceDecisionResult):
            with pytest.raises(TypeError):
                value.interfaces[0].interface.enabled = False
        if isinstance(value, InterfaceDecisionResult):
            with pytest.raises(TypeError):
                value.interface.enabled = False
        if isinstance(value, PolicyBindingEvidence):
            with pytest.raises(TypeError):
                value.binding_location.source_name = "changed"
        if isinstance(value, PolicyTraceEntry):
            with pytest.raises(TypeError):
                value.source_location.source_name = "changed"
