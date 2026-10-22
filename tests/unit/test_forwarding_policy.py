"""Консервативные ворота и first-match цепочка без утверждения достижимости."""

from copy import copy, deepcopy
from datetime import timedelta
from json import dumps
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.forwarding_fixtures import forwarding_location, forwarding_rule
from tests.forwarding_policy_fixtures import (
    EGRESS_ID,
    INGRESS_ID,
    feature,
    incomplete_feature,
    policy_context,
    policy_payload,
)

from firewall_compliance.analysis.forwarding_policy import evaluate_forwarding_policy
from firewall_compliance.domain.forwarding_policy import ForwardingPolicyResult


def evaluate(values: dict[str, Any] | None = None, **ids: str) -> ForwardingPolicyResult:
    result = evaluate_forwarding_policy(
        policy_context(values),
        ingress_interface_id=ids.get("ingress", INGRESS_ID),
        egress_interface_id=ids.get("egress", EGRESS_ID),
    )
    assert result.status == (
        "not_enough_evidence" if result.policy_status == "not_enough_evidence" else "unknown"
    )
    assert result.egress_basis == "caller_supplied_conditional"
    assert any(reason.code == "runtime_pending" for reason in result.reasons)
    assert tuple(entry.stage for entry in result.trace) == (
        "applicability",
        "coordinates",
        "same_security",
        "ingress_acl",
        "global_acl",
        "inbound_default",
        "egress_acl",
        "runtime",
    )
    return result


def acl_trace(result: ForwardingPolicyResult) -> list[Any]:
    return [entry for entry in result.trace if entry.policy_id is not None]


def set_rules(values: dict[str, Any], policy_id: str, *rules: Any) -> None:
    acl = next(item for item in values["acls"] if item["policy_id"] == policy_id)
    acl["rules"] = [rule.model_dump(mode="python") for rule in rules]


def global_rule(sequence: int = 20, **changes: Any) -> Any:
    return forwarding_rule(sequence, policy_id="GLOBAL", **changes)


def outbound(values: dict[str, Any], *rules: Any) -> None:
    set_rules(values, "GLOBAL", *rules)
    values["bindings"] = [
        values["bindings"][0],
        {
            "policy_id": "GLOBAL",
            "direction": "out",
            "interface_id": EGRESS_ID,
            "location": forwarding_location(30).model_dump(mode="python"),
        },
    ]


def assert_gated(result: ForwardingPolicyResult, expected: str) -> None:
    assert result.policy_status == expected
    assert not acl_trace(result)
    assert all(entry.matched_rule_id is None for entry in result.trace)


def test_should_allow_complete_ingress_without_claiming_reachability() -> None:
    result = evaluate()

    assert result.policy_status == "allow"
    assert result.status in {"unknown", "not_enough_evidence"}
    assert result.schema_version == result.engine_version == "0.1.0"
    assert result.ingress_interface_id == INGRESS_ID
    assert result.egress_interface_id == EGRESS_ID
    assert any(reason.code == "runtime_pending" for reason in result.reasons)
    assert isinstance(result.trace, tuple)
    assert [(entry.policy_id, entry.matched_rule_id) for entry in acl_trace(result)] == [
        ("INSIDE", "ace-10")
    ]
    assert acl_trace(result)[0].locations
    assert acl_trace(result)[0].rule_trace[0].outcome == "match"


@pytest.mark.parametrize(
    "field", ["context_mode", "firewall_mode", "address_family", "table_role", "table_id"]
)
def test_should_gate_when_profile_fact_is_missing(field: str) -> None:
    values = policy_payload()
    values[field] = None

    assert_gated(evaluate(values), "not_enough_evidence")


@pytest.mark.parametrize(
    "field,value",
    [("firewall_mode", "transparent"), ("table_role", "management")],
)
def test_should_report_unknown_when_profile_is_unsupported(field: str, value: str) -> None:
    values = policy_payload()
    values[field] = value

    assert_gated(evaluate(values), "unknown")


@pytest.mark.parametrize(
    "name",
    [
        "interfaces",
        "acl_definitions",
        "acl_bindings",
        "configured_nat",
        "effective_nat",
        "pbr",
        "exceptions",
    ],
)
@pytest.mark.parametrize(
    "status,expected", [("unknown", "not_enough_evidence"), ("unsupported", "unknown")]
)
def test_should_gate_before_acl_when_inventory_is_unproven(
    name: str, status: str, expected: str
) -> None:
    values = policy_payload()
    incomplete_feature(values, name, status)

    assert_gated(evaluate(values), expected)


@pytest.mark.parametrize("name", ["configured_nat", "effective_nat", "pbr", "exceptions"])
def test_should_gate_when_nat_or_exception_is_explicitly_present(name: str) -> None:
    values = policy_payload()
    inventory = feature(values, name)
    source = values["sources"][1 if name == "effective_nat" else 0]
    location = {
        "source_document_id": source["source_document_id"],
        "location": {
            "source_name": source["source_name"],
            "line_start": 40,
        },
    }
    inventory.update(status="known", item_count=1, locations=[location])

    assert_gated(evaluate(values), "unknown")


@pytest.mark.parametrize("field", ["new_connection", "transit", "non_vpn", "non_fragment"])
@pytest.mark.parametrize("value,expected", [(None, "not_enough_evidence"), (False, "unknown")])
def test_should_gate_when_flow_applicability_is_missing_or_false(
    field: str, value: bool | None, expected: str
) -> None:
    values = policy_payload()
    values["flow"][field] = value

    assert_gated(evaluate(values), expected)


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("tcp_syn", None, "not_enough_evidence"),
        ("tcp_syn", False, "unknown"),
        ("tcp_ack", None, "not_enough_evidence"),
        ("tcp_ack", True, "unknown"),
        ("tcp_payload_length", None, "not_enough_evidence"),
        ("tcp_payload_length", 1, "unknown"),
    ],
)
def test_should_require_initial_tcp_syn(field: str, value: Any, expected: str) -> None:
    values = policy_payload()
    values["flow"][field] = value

    assert_gated(evaluate(values), expected)


@pytest.mark.parametrize("protocol", ["udp", "icmp"])
def test_should_accept_udp_and_icmp_echo_without_tcp_fields(protocol: str) -> None:
    values = policy_payload()
    flow = values["flow"]
    flow.update(tcp_syn=None, tcp_ack=None, tcp_payload_length=None)
    flow["query"].update(protocol=protocol, destination_port=443 if protocol == "udp" else None)
    if protocol == "icmp":
        flow.update(icmp_type=8, icmp_code=0)
    values["acls"][0]["rules"][0]["services"][0].update(protocol=protocol, port_ranges=[])

    assert evaluate(values).policy_status == "allow"


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("icmp_type", None, "not_enough_evidence"),
        ("icmp_code", None, "not_enough_evidence"),
        ("icmp_type", 0, "unknown"),
        ("icmp_code", 1, "unknown"),
    ],
)
def test_should_gate_icmp_without_explicit_echo_request(
    field: str, value: Any, expected: str
) -> None:
    values = policy_payload()
    values["flow"].update(
        tcp_syn=None, tcp_ack=None, tcp_payload_length=None, icmp_type=8, icmp_code=0
    )
    values["flow"]["query"].update(protocol="icmp", destination_port=None)
    values["flow"][field] = value

    assert_gated(evaluate(values), expected)


def test_should_gate_when_flow_is_missing() -> None:
    values = policy_payload()
    values["flow"] = None

    assert_gated(evaluate(values), "not_enough_evidence")


def test_should_reject_network_interface_id_in_physical_coordinates() -> None:
    values = policy_payload()
    values["flow"]["query"]["ingress_interface_id"] = "network-interface-1"

    assert_gated(evaluate(values), "unknown")


@pytest.mark.parametrize(
    "ids", [{"ingress": "missing"}, {"egress": "missing"}, {"egress": INGRESS_ID}]
)
def test_should_gate_absent_or_identical_interfaces(ids: dict[str, str]) -> None:
    result = evaluate(**ids)

    assert result.policy_status in {"unknown", "not_enough_evidence"}
    assert not acl_trace(result)


def test_should_reject_nonphysical_interface() -> None:
    values = policy_payload()
    values["interfaces"][1]["physical_l3"] = False

    assert_gated(evaluate(values), "unknown")


@pytest.mark.parametrize(
    "value,expected", [(False, "deny"), (True, "allow"), (None, "not_enough_evidence")]
)
def test_should_apply_equal_security_gate_before_ingress_acl(
    value: bool | None, expected: str
) -> None:
    values = policy_payload()
    values["interfaces"][1]["security_level"] = 100
    toggle = values["toggles"][0]
    toggle["value"] = value
    if value is None:
        toggle["status"] = "unknown"
        incomplete_feature(values, "same_security")

    result = evaluate(values)

    assert result.policy_status == expected
    if value is not True:
        assert not acl_trace(result)


def test_should_not_require_same_security_toggle_for_unequal_levels() -> None:
    values = policy_payload()
    incomplete_feature(values, "same_security")
    values["toggles"] = [item for item in values["toggles"] if item["name"] == "permit_vpn"]

    assert evaluate(values).policy_status == "allow"


@pytest.mark.parametrize("action", ["deny", "drop", "reject"])
def test_should_stop_on_ingress_terminal_action_before_global(action: str) -> None:
    values = policy_payload()
    set_rules(values, "INSIDE", forwarding_rule(action=action))
    set_rules(values, "GLOBAL", global_rule())

    result = evaluate(values)

    assert result.policy_status == action
    assert [entry.policy_id for entry in acl_trace(result)] == ["INSIDE"]


def test_should_bypass_global_deny_after_ingress_allow() -> None:
    values = policy_payload()
    set_rules(values, "GLOBAL", global_rule(action="deny"))

    assert evaluate(values).policy_status == "allow"


@pytest.mark.parametrize("empty", [False, True])
def test_should_continue_to_global_after_ingress_no_match_including_known_empty_acl(
    empty: bool,
) -> None:
    values = policy_payload()
    rules = (
        ()
        if empty
        else (
            forwarding_rule(
                services=(
                    {
                        "service_id": "ssh",
                        "name": "ssh",
                        "protocol": "tcp",
                        "port_ranges": [{"start": 22, "end": 22}],
                    },
                )
            ),
        )
    )
    set_rules(values, "INSIDE", *rules)
    set_rules(values, "GLOBAL", global_rule())

    result = evaluate(values)

    assert result.policy_status == "allow"
    entries = acl_trace(result)
    assert [entry.policy_id for entry in entries] == ["INSIDE", "GLOBAL"]
    assert entries[0].outcome == "no_match"
    assert entries[1].matched_rule_id == "ace-20"


def test_should_implicitly_deny_at_end_of_applicable_empty_inbound_chain() -> None:
    values = policy_payload()
    set_rules(values, "INSIDE")

    assert evaluate(values).policy_status == "implicit_deny"


@pytest.mark.parametrize(
    "levels,expected", [((100, 0), "allow"), ((0, 100), "deny"), ((50, 50), "allow")]
)
def test_should_use_security_defaults_only_without_applicable_inbound_bindings(
    levels: tuple[int, int], expected: str
) -> None:
    values = policy_payload()
    values["bindings"] = []
    for interface, level in zip(values["interfaces"], levels, strict=True):
        interface["security_level"] = level

    assert evaluate(values).policy_status == expected


@pytest.mark.parametrize("action", ["allow", "deny", "drop", "reject"])
def test_should_evaluate_outbound_after_inbound_allow(action: str) -> None:
    values = policy_payload()
    outbound(values, global_rule(action=action))

    result = evaluate(values)

    assert result.policy_status == action
    assert [entry.policy_id for entry in acl_trace(result)] == ["INSIDE", "GLOBAL"]


def test_should_implicitly_deny_empty_outbound_acl_after_inbound_allow() -> None:
    values = policy_payload()
    outbound(values)

    assert evaluate(values).policy_status == "implicit_deny"


def test_should_not_evaluate_outbound_after_inbound_deny() -> None:
    values = policy_payload()
    set_rules(values, "INSIDE", forwarding_rule(action="deny"))
    outbound(values, global_rule())

    assert [entry.policy_id for entry in acl_trace(evaluate(values))] == ["INSIDE"]


def test_should_stop_on_first_matching_rule_in_order() -> None:
    values = policy_payload()
    set_rules(values, "INSIDE", forwarding_rule(10, action="deny"), forwarding_rule(20))

    entry = acl_trace(evaluate(values))[0]

    assert entry.outcome == "deny"
    assert entry.matched_rule_id == "ace-10"
    assert [item.rule_id for item in entry.rule_trace] == ["ace-10"]


def test_should_skip_disabled_unknown_rule() -> None:
    values = policy_payload()
    set_rules(
        values,
        "INSIDE",
        forwarding_rule(10, enabled=False, match_status="unknown"),
        forwarding_rule(20),
    )

    result = evaluate(values)

    assert result.policy_status == "allow"
    assert [item.outcome for item in acl_trace(result)[0].rule_trace] == ["disabled", "match"]


def test_should_never_fall_through_unknown_active_condition_to_global_allow() -> None:
    values = policy_payload()
    acl = values["acls"][0]
    acl.update(status="unknown", complete=False)
    incomplete_feature(values, "acl_definitions")
    set_rules(values, "INSIDE", forwarding_rule(10, match_status="unknown"), forwarding_rule(20))
    set_rules(values, "GLOBAL", global_rule())

    result = evaluate(values)

    assert result.policy_status in {"unknown", "not_enough_evidence"}
    assert all(entry.matched_rule_id is None for entry in result.trace)


def test_should_reuse_acl_for_inbound_and_outbound_without_rule_scope_mutation() -> None:
    values = policy_payload()
    values["bindings"] = [
        values["bindings"][0],
        {
            "policy_id": "INSIDE",
            "direction": "out",
            "interface_id": EGRESS_ID,
            "location": forwarding_location(30).model_dump(mode="python"),
        },
    ]
    context = policy_context(values)
    before = context.model_dump_json()

    result = evaluate_forwarding_policy(
        context, ingress_interface_id=INGRESS_ID, egress_interface_id=EGRESS_ID
    )

    assert result.policy_status == "allow"
    assert [entry.matched_rule_id for entry in acl_trace(result)] == ["ace-10", "ace-10"]
    assert context.model_dump_json() == before


@pytest.mark.parametrize(
    "copier",
    [copy, deepcopy, lambda item: item.model_copy(), lambda item: item.model_copy(deep=True)],
)
def test_should_preserve_frozen_result_snapshot_through_copy_and_json(copier: Any) -> None:
    context = policy_context()
    result = evaluate_forwarding_policy(
        context, ingress_interface_id=INGRESS_ID, egress_interface_id=EGRESS_ID
    )
    cloned = copier(ForwardingPolicyResult.model_validate_json(result.model_dump_json()))

    assert cloned == result
    assert cloned.context == context
    assert cloned.context is not context
    with pytest.raises((TypeError, ValidationError)):
        cloned.context.acls[0].rules[0].name = "Изменение"
    with pytest.raises((TypeError, ValidationError)):
        cloned.trace[0].outcome = "allow"


@pytest.mark.parametrize("status", ["reachable", "blocked"])
def test_should_reject_final_reachability_status_in_result(status: str) -> None:
    result = evaluate()

    with pytest.raises(ValueError):
        result.model_copy(update={"status": status})


@pytest.mark.parametrize(
    "field,value",
    [
        ("revision_id", UUID("00000000-0000-4000-8000-000000000099")),
        ("device_id", "other-device"),
        ("device_context", "other-context"),
        ("table_id", "other-table"),
    ],
)
def test_should_reject_flow_from_another_snapshot_at_context_boundary(
    field: str, value: Any
) -> None:
    values = policy_payload()
    values["flow"]["query"][field] = value

    with pytest.raises(ValueError):
        policy_context(values)


def test_should_gate_unobserved_context_without_publishing_acl_decision() -> None:
    values = policy_payload()
    values["observed_at"] = None
    for inventory in values["inventories"]:
        incomplete_feature(values, inventory["feature"])

    assert_gated(evaluate(values), "not_enough_evidence")


def test_should_reject_complete_inventory_from_another_observation_time() -> None:
    values = policy_payload()
    values["sources"][0]["observation"]["observed_at"] -= timedelta(seconds=1)

    with pytest.raises(ValueError):
        policy_context(values)


@pytest.mark.parametrize("field", ["physical_l3", "security_level"])
def test_should_gate_unknown_interface_properties(field: str) -> None:
    values = policy_payload()
    values["interfaces"][1][field] = None
    if field == "security_level":
        values["interfaces"][1]["security_status"] = "unknown"
    incomplete_feature(values, "interfaces")

    assert_gated(evaluate(values), "not_enough_evidence")


def test_should_gate_equal_security_without_explicit_inter_interface_toggle() -> None:
    values = policy_payload()
    values["interfaces"][1]["security_level"] = 100
    values["toggles"] = [item for item in values["toggles"] if item["name"] != "inter_interface"]
    incomplete_feature(values, "same_security")

    assert_gated(evaluate(values), "not_enough_evidence")


def test_should_require_complete_same_security_inventory_despite_known_true_toggle() -> None:
    values = policy_payload()
    values["interfaces"][1]["security_level"] = 100
    incomplete_feature(values, "same_security")

    assert_gated(evaluate(values), "not_enough_evidence")


def test_should_ignore_inbound_binding_on_another_interface() -> None:
    values = policy_payload()
    values["bindings"] = [values["bindings"][0]]
    values["bindings"][0]["interface_id"] = EGRESS_ID
    set_rules(values, "INSIDE", forwarding_rule(action="deny"))

    result = evaluate(values)

    assert result.policy_status == "allow"
    assert not acl_trace(result)


def test_should_preserve_global_evaluation_with_no_ingress_binding() -> None:
    values = policy_payload()
    values["bindings"] = [values["bindings"][1]]
    set_rules(values, "GLOBAL", global_rule(action="deny"))

    result = evaluate(values)

    assert result.policy_status == "deny"
    assert [entry.policy_id for entry in acl_trace(result)] == ["GLOBAL"]


def test_should_preserve_all_input_inventories_and_detach_builder() -> None:
    values = policy_payload()
    context = policy_context(values)
    before = context.model_dump_json()

    result = evaluate_forwarding_policy(
        context, ingress_interface_id=INGRESS_ID, egress_interface_id=EGRESS_ID
    )
    values["inventories"][0]["reference"] = "Изменённый builder"
    values["acls"][0]["rules"][0]["action"] = "deny"

    assert context.model_dump_json() == before
    assert result.context.model_dump_json() == before
    assert result.context.inventories == context.inventories


@pytest.mark.parametrize("profile", ["multiple", "ipv6", "nondefault"])
def test_should_gate_unsupported_context_or_query_profile(profile: str) -> None:
    values = policy_payload()
    if profile == "multiple":
        values["context_mode"] = "multiple"
    elif profile == "ipv6":
        values["address_family"] = "ipv6"
        values["flow"]["query"].update(source_ip="2001:db8::1", destination_ip="2001:db8::2")
    else:
        values["table_id"] = values["flow"]["query"]["table_id"] = "custom"

    assert_gated(evaluate(values), "unknown")


@pytest.mark.parametrize("loader", ["copy", "json"])
def test_should_reject_stale_allow_when_effective_nat_becomes_unknown(loader: str) -> None:
    result = evaluate()
    values = result.context.model_dump(mode="python")
    incomplete_feature(values, "effective_nat")
    changed_context = policy_context(values)
    assert (
        evaluate_forwarding_policy(
            changed_context, ingress_interface_id=INGRESS_ID, egress_interface_id=EGRESS_ID
        ).policy_status
        == "not_enough_evidence"
    )

    with pytest.raises(ValueError, match="повторному расчёту"):
        if loader == "copy":
            result.model_copy(update={"context": changed_context})
        else:
            payload = result.model_dump(mode="json")
            payload["context"] = changed_context.model_dump(mode="json")
            ForwardingPolicyResult.model_validate_json(dumps(payload))


@pytest.mark.parametrize("change", ["ingress_id", "egress_id", "query", "acl"])
def test_should_reject_stale_allow_when_coordinates_query_or_acl_change(change: str) -> None:
    result = evaluate()
    update: dict[str, Any] = {}
    if change in {"ingress_id", "egress_id"}:
        field = "ingress_interface_id" if change == "ingress_id" else "egress_interface_id"
        update[field] = EGRESS_ID if change == "ingress_id" else INGRESS_ID
    else:
        values = result.context.model_dump(mode="python")
        if change == "query":
            values["flow"]["query"]["destination_port"] = 22
        else:
            values["acls"][0]["rules"][0]["action"] = "deny"
        update["context"] = policy_context(values)

    with pytest.raises(ValueError, match="повторному расчёту"):
        result.model_copy(update=update)


def test_should_reject_forged_egress_allow_after_terminal_same_security_deny() -> None:
    values = policy_payload()
    values["interfaces"][1]["security_level"] = 100
    outbound(values, global_rule())
    allowed = evaluate(values)
    valid_egress = next(entry for entry in allowed.trace if entry.stage == "egress_acl")
    assert valid_egress.outcome == "allow"
    assert valid_egress.matched_rule_id == "ace-20"
    values["toggles"][0]["value"] = False
    denied = evaluate(values)
    assert denied.policy_status == "deny"
    assert next(entry for entry in denied.trace if entry.stage == "same_security").outcome == "deny"
    forged_trace = tuple(
        valid_egress if entry.stage == "egress_acl" else entry for entry in denied.trace
    )

    with pytest.raises(ValueError, match="повторному расчёту"):
        denied.model_copy(update={"policy_status": "allow", "trace": forged_trace})


@pytest.mark.parametrize("removed", ["matched_rule_id", "rule_trace", "both"])
def test_should_reject_explicit_acl_allow_without_matching_rule_evidence(removed: str) -> None:
    payload = evaluate().model_dump(mode="python")
    stage = next(entry for entry in payload["trace"] if entry["stage"] == "ingress_acl")
    if removed in {"matched_rule_id", "both"}:
        stage["matched_rule_id"] = None
    if removed in {"rule_trace", "both"}:
        stage["rule_trace"] = ()

    with pytest.raises(ValueError):
        ForwardingPolicyResult.model_validate(payload)


@pytest.mark.parametrize("version", ["9.16(4)57", "9.16.4"])
def test_should_accept_supported_916_versions_with_build_or_dotted_patch(version: str) -> None:
    values = policy_payload()
    for source in values["sources"]:
        source["declared_version"] = version

    result = evaluate(values)

    assert result.policy_status == "allow"
    assert all(source.declared_version == version for source in result.context.sources)
