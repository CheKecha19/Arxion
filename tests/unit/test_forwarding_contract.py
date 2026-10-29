"""Контракт фактов и доказательств, без решений о пересылке."""

from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError
from tests.forwarding_fixtures import (
    CONFIG_SOURCE_ID,
    IMPORTED_AT,
    NAT_SOURCE_ID,
    OBSERVED_AT,
    empty_forwarding_context,
    forwarding_flow,
    forwarding_location,
    forwarding_rule,
    make_forwarding_context,
)

from firewall_compliance.domain.enums import DataStatus, Protocol
from firewall_compliance.domain.forwarding import (
    FeatureInventory,
    ForwardingContext,
    ForwardingInterface,
    ForwardingSource,
    ForwardingToggle,
)


def payload() -> dict[str, Any]:
    return make_forwarding_context().model_dump(mode="python")


def inventory(values: dict[str, Any], feature: str) -> dict[str, Any]:
    return next(item for item in values["inventories"] if item["feature"] == feature)


def test_empty_context_has_no_implicit_defaults() -> None:
    context = empty_forwarding_context()
    assert context.sources == context.inventories == context.interfaces == ()
    assert context.acls == context.bindings == context.toggles == ()
    assert context.observed_at is context.flow is None
    interface = ForwardingInterface(
        interface_id="inside", label="inside", location=forwarding_location(1)
    )
    assert interface.security_level is interface.physical_l3 is None
    assert interface.security_status == DataStatus.UNKNOWN
    toggle = ForwardingToggle(name="inter_interface", status=DataStatus.UNKNOWN)
    assert toggle.value is toggle.location is None


def test_full_fixture_is_deterministic_and_roundtrips() -> None:
    context = make_forwarding_context()
    assert context == make_forwarding_context()
    assert ForwardingContext.model_validate_json(context.model_dump_json()) == context
    assert all(item.enumeration_complete and item.complete for item in context.inventories)
    assert context.sources[0].origin == context.sources[1].origin == "synthetic"
    assert context.sources[0].source_document_id != context.sources[1].source_document_id
    assert context.sources[1].complete_scopes == ("effective_nat",)


def test_snapshot_detaches_and_freezes_nested_builders() -> None:
    values = payload()
    rule = forwarding_rule()
    values["acls"][0]["rules"] = [rule]
    context = ForwardingContext.model_validate(values)
    rule.name = "changed builder"
    values["sources"][0]["source_name"] = "changed input"
    assert context.acls[0].rules[0].name == "ace-10"
    assert context.sources[0].source_name == "synthetic.config"
    with pytest.raises((TypeError, ValidationError)):
        context.acls[0].rules[0].name = "mutation"
    with pytest.raises((TypeError, ValidationError)):
        context.interfaces[0].location.location.line_start = 42


@pytest.mark.parametrize(
    "field,value",
    [
        ("selection", "authored_excerpt"),
        ("extent", "truncated"),
        ("capture_success", False),
        ("observation", None),
        ("completeness_reference", None),
        ("content_sha256", "z" * 64),
        ("source_document_id", "bad-uuid"),
        ("captured_at", "2026-10-10T09:01:00"),
        ("version_provenance", "synthetic"),
    ],
)
def test_source_rejects_invalid_metadata_or_completeness(field: str, value: Any) -> None:
    values = payload()["sources"][0]
    values[field] = value
    with pytest.raises(ValidationError):
        ForwardingSource.model_validate(values)


def test_version_provenance_is_mandatory() -> None:
    values = payload()["sources"][0]
    del values["version_provenance"]
    with pytest.raises(ValidationError):
        ForwardingSource.model_validate(values)


@pytest.mark.parametrize(
    "purpose,scopes",
    [
        ("configuration", ("effective_nat",)),
        ("effective_nat", ("object_nat",)),
        ("pbr_state", ("pbr_definitions",)),
    ],
)
def test_source_roles_do_not_prove_other_scopes(purpose: str, scopes: tuple[str, ...]) -> None:
    values = payload()["sources"][0]
    values.update(purpose=purpose, complete_scopes=scopes)
    with pytest.raises(ValidationError):
        ForwardingSource.model_validate(values)


@pytest.mark.parametrize("scope", ["object_nat", "manual_nat", "pbr_bindings", "pbr_definitions"])
def test_absence_requires_every_relevant_scope(scope: str) -> None:
    values = payload()
    values["sources"][0]["complete_scopes"] = tuple(
        item for item in values["sources"][0]["complete_scopes"] if item != scope
    )
    with pytest.raises(ValidationError, match="scopes"):
        ForwardingContext.model_validate(values)


def test_configured_nat_absence_does_not_prove_effective_nat_absence() -> None:
    values = payload()
    nat = inventory(values, "effective_nat")
    nat["source_document_ids"] = (CONFIG_SOURCE_ID,)
    with pytest.raises(ValidationError, match="scopes"):
        ForwardingContext.model_validate(values)
    nat.update(
        status=DataStatus.UNKNOWN,
        complete=False,
        enumeration_complete=False,
        reference=None,
        source_document_ids=(),
    )
    values["sources"] = values["sources"][:1]
    context = ForwardingContext.model_validate(values)
    assert next(i for i in context.inventories if i.feature == "effective_nat").status == "unknown"


def test_excerpt_preserves_unknown_without_claiming_absence() -> None:
    source = payload()["sources"][0]
    source.update(
        selection="authored_excerpt",
        extent="excerpt",
        complete_scopes=(),
        completeness_reference=None,
        observation=None,
    )
    context = empty_forwarding_context(
        sources=(source,),
        inventories=(FeatureInventory(feature="configured_nat", status=DataStatus.UNKNOWN),),
    )
    assert context.inventories[0].complete is False
    values = context.model_dump()
    values["inventories"][0].update(
        status=DataStatus.ABSENT,
        complete=True,
        enumeration_complete=True,
        reference="Claim",
        source_document_ids=(CONFIG_SOURCE_ID,),
    )
    with pytest.raises(ValidationError):
        ForwardingContext.model_validate(values)


@pytest.mark.parametrize(
    "field,value",
    [
        ("enumeration_complete", False),
        ("complete", False),
        ("reference", None),
        ("diagnostics", ("unrecognized command",)),
        ("source_document_ids", ()),
        ("item_count", 3),
        ("item_count", True),
        ("locations", ()),
    ],
)
def test_known_inventory_requires_coherent_evidence(field: str, value: Any) -> None:
    values = payload()["inventories"][0]
    values[field] = value
    with pytest.raises(ValidationError):
        FeatureInventory.model_validate(values)


def test_duplicate_inventory_anchors_are_rejected() -> None:
    values = payload()["inventories"][0]
    values["locations"] = (values["locations"][0],) * 2
    with pytest.raises(ValidationError, match="повторяться"):
        FeatureInventory.model_validate(values)


def test_complete_enumeration_can_have_unknown_semantics() -> None:
    values = payload()
    inventory(values, "interfaces").update(
        status=DataStatus.UNKNOWN, complete=False, diagnostics=("unknown security-level",)
    )
    values["interfaces"][0].update(security_status=DataStatus.UNKNOWN, security_level=None)
    context = ForwardingContext.model_validate(values)
    assert context.inventories[0].enumeration_complete
    assert not context.inventories[0].complete
    values["sources"][0]["complete_scopes"] = ()
    with pytest.raises(ValidationError):
        ForwardingContext.model_validate(values)


@pytest.mark.parametrize(
    "case",
    [
        "duplicate_source_id",
        "duplicate_source_name",
        "wrong_device",
        "wrong_context",
        "future_capture",
        "future_observation",
        "naive_import",
        "missing_observation",
        "wrong_observation",
        "missing_source",
        "wrong_location",
        "missing_anchor",
        "duplicate_inventory",
        "missing_inventory",
        "wrong_count",
        "wrong_configuration",
        "wrong_flow_revision",
        "wrong_flow_device",
        "wrong_flow_context",
    ],
)
def test_context_rejects_incoherent_identity_time_and_mapping(case: str) -> None:
    values = payload()
    match case:
        case "duplicate_source_id":
            values["sources"][1]["source_document_id"] = CONFIG_SOURCE_ID
        case "duplicate_source_name":
            values["sources"][1]["source_name"] = values["sources"][0]["source_name"]
        case "wrong_device" | "wrong_context":
            field = "device_id" if case == "wrong_device" else "device_context"
            values["sources"][0][field] = "other"
        case "future_capture":
            values["sources"][0]["captured_at"] = IMPORTED_AT + timedelta(seconds=1)
        case "future_observation":
            values["observed_at"] = IMPORTED_AT + timedelta(seconds=1)
        case "naive_import":
            values["imported_at"] = IMPORTED_AT.replace(tzinfo=None)
        case "missing_observation":
            values["observed_at"] = None
        case "wrong_observation":
            values["sources"][0]["observation"]["observed_at"] = OBSERVED_AT - timedelta(seconds=1)
        case "missing_source":
            values["sources"] = values["sources"][:1]
        case "wrong_location":
            values["interfaces"][0]["location"]["location"]["source_name"] = "other"
        case "missing_anchor":
            values["interfaces"][0]["location"] = forwarding_location(99)
        case "duplicate_inventory":
            values["inventories"] += (values["inventories"][0],)
        case "missing_inventory":
            values["inventories"] = values["inventories"][1:]
        case "wrong_count":
            values["inventories"][0]["item_count"] = 1
        case "wrong_configuration":
            values["acls"][1]["configuration_id"] = NAT_SOURCE_ID
        case "wrong_flow_revision" | "wrong_flow_device" | "wrong_flow_context":
            field = {
                "wrong_flow_revision": "revision_id",
                "wrong_flow_device": "device_id",
                "wrong_flow_context": "device_context",
            }[case]
            values["flow"]["query"][field] = NAT_SOURCE_ID if field == "revision_id" else "other"
    with pytest.raises(ValidationError):
        ForwardingContext.model_validate(values)


@pytest.mark.parametrize(
    "case",
    [
        "duplicate_binding",
        "global_interface",
        "missing_interface",
        "duplicate_interface",
        "duplicate_label",
        "missing_definition",
    ],
)
def test_bindings_and_interfaces_are_unambiguous(case: str) -> None:
    values = payload()
    match case:
        case "duplicate_binding":
            values["bindings"][1].update(direction="in", interface_id="inside")
        case "global_interface":
            values["bindings"][1]["interface_id"] = "inside"
        case "missing_interface":
            values["bindings"][0]["interface_id"] = "missing"
        case "duplicate_interface":
            values["interfaces"][1]["interface_id"] = "inside"
        case "duplicate_label":
            values["interfaces"][1]["label"] = "INSIDE"
        case "missing_definition":
            values["bindings"][1]["policy_id"] = "MISSING"
    with pytest.raises(ValidationError):
        ForwardingContext.model_validate(values)


def test_explicit_empty_acl_is_a_definition_and_global_is_a_separate_slot() -> None:
    context = make_forwarding_context()
    assert context.acls[1].complete and context.acls[1].rules == ()
    assert context.bindings[1].direction == "global"
    assert context.bindings[1].interface_id is None
    outgoing = context.bindings[0].model_copy(update={"direction": "out"})
    assert outgoing.interface_id == "inside"


@pytest.mark.parametrize("feature", ["same_security", "vpn_bypass"])
def test_settings_absence_never_means_default_off(feature: str) -> None:
    values = payload()
    names = {"inter_interface", "intra_interface"} if feature == "same_security" else {"permit_vpn"}
    values["toggles"] = tuple(t for t in values["toggles"] if t["name"] not in names)
    inventory(values, feature).update(status=DataStatus.ABSENT, item_count=0, locations=())
    with pytest.raises(ValidationError, match="defaults"):
        ForwardingContext.model_validate(values)


@pytest.mark.parametrize("field", ["match_status", "policy_semantics", "source_name"])
def test_complete_acl_rejects_unknown_active_ace(field: str) -> None:
    values = payload()
    rule = values["acls"][0]["rules"][0]
    if field == "source_name":
        rule["source_location"]["source_name"] = "other"
    else:
        rule[field] = DataStatus.UNKNOWN if field == "match_status" else None
    with pytest.raises(ValidationError):
        ForwardingContext.model_validate(values)


def test_disabled_unknown_ace_is_preserved_without_claiming_known_match() -> None:
    values = payload()
    values["acls"][0]["rules"][0].update(enabled=False, match_status=DataStatus.UNKNOWN)
    context = ForwardingContext.model_validate(values)
    assert context.acls[0].rules[0].match_status == DataStatus.UNKNOWN


@pytest.mark.parametrize("protocol", [Protocol.TCP, Protocol.UDP, Protocol.ICMP])
def test_flow_details_remain_explicit_unknown(protocol: Protocol) -> None:
    flow = forwarding_flow(protocol)
    assert flow.new_connection is flow.transit is flow.non_vpn is flow.non_fragment is None
    assert flow.tcp_syn is flow.tcp_ack is flow.tcp_payload_length is None
    assert flow.icmp_type is flow.icmp_code is None
    if protocol == Protocol.ICMP:
        assert forwarding_flow(protocol, icmp_type=8, icmp_code=0).icmp_type == 8


@pytest.mark.parametrize(
    "protocol,details",
    [
        (Protocol.UDP, {"tcp_syn": False}),
        (Protocol.ICMP, {"tcp_payload_length": 0}),
        (Protocol.TCP, {"icmp_type": 8}),
        (Protocol.TCP, {"tcp_syn": 1}),
        (Protocol.ICMP, {"icmp_code": 256}),
    ],
)
def test_flow_rejects_inapplicable_or_coerced_details(protocol: Protocol, details: dict) -> None:
    with pytest.raises(ValidationError):
        forwarding_flow(protocol, **details)


def test_invalid_forwarding_copy_is_rejected_immediately() -> None:
    context = make_forwarding_context()
    with pytest.raises(ValidationError):
        context.interfaces[0].model_copy(update={"security_level": None})
    with pytest.raises(ValidationError):
        context.model_copy(update={"device_id": "other"})
    copied = context.model_copy(deep=True)
    assert copied == context and copied.acls[0].rules[0] is not context.acls[0].rules[0]


@pytest.mark.parametrize("nested", ["rule", "location"])
def test_corrupt_legacy_nested_copy_is_revalidated(nested: str) -> None:
    values = payload()
    if nested == "rule":
        values["acls"][0]["rules"] = (forwarding_rule().model_copy(update={"sources": ()}),)
    else:
        location = forwarding_location(1).location.model_copy(update={"line_start": 0})
        values["interfaces"][0]["location"]["location"] = location
    with pytest.raises(ValidationError):
        ForwardingContext.model_validate(values)


def test_observation_window_allows_coherent_separate_captures() -> None:
    values = payload()
    start = OBSERVED_AT - timedelta(seconds=10)
    values["sources"][1]["observation"]["observed_at"] = start
    values["observation_window"] = {
        "start": start,
        "end": OBSERVED_AT,
        "reason": "Synthetic capture interval",
    }
    assert ForwardingContext.model_validate(values).observation_window.start == start
    values["observation_window"]["end"] = IMPORTED_AT + timedelta(seconds=1)
    with pytest.raises(ValidationError):
        ForwardingContext.model_validate(values)


def test_known_same_security_requires_both_explicit_values() -> None:
    values = payload()
    values["toggles"] = values["toggles"][:1] + values["toggles"][2:]
    item = inventory(values, "same_security")
    item.update(item_count=1, locations=item["locations"][:1])
    with pytest.raises(ValidationError, match="effective"):
        ForwardingContext.model_validate(values)


def test_profile_defaults_are_unknown_and_declarations_need_evidence() -> None:
    context = make_forwarding_context()
    assert all(
        getattr(context, field) is None
        for field in (
            "context_mode",
            "firewall_mode",
            "address_family",
            "table_role",
            "table_id",
            "profile_reference",
        )
    )
    with pytest.raises(ValidationError):
        context.model_copy(update={"firewall_mode": "routed"})
    declared = context.model_copy(
        update={
            "context_mode": "multiple",
            "firewall_mode": "routed",
            "address_family": "ipv4",
            "table_role": "data",
            "table_id": "default",
            "profile_reference": "Synthetic profile",
        }
    )
    assert declared.address_family == "ipv4"


@pytest.mark.parametrize(
    "changes",
    [
        {"context_mode": "single"},
        {"address_family": "ipv6"},
        {"table_id": "management"},
    ],
)
def test_declared_profile_must_match_context_and_flow(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_forwarding_context(**changes, profile_reference="Synthetic profile")


@pytest.mark.parametrize("semantic_complete", [True, False], ids=["complete", "enumerated"])
@pytest.mark.parametrize(
    "defect", ["effective_nat_role", "empty_scopes", "truncated", "failed_capture"]
)
def test_each_interface_fact_requires_its_own_source_proof(
    semantic_complete: bool, defect: str
) -> None:
    values = payload()
    second_source = values["sources"][1]
    second_source.update(purpose="configuration", complete_scopes=("interfaces",))
    effective_nat = inventory(values, "effective_nat")
    effective_nat.update(
        status=DataStatus.UNKNOWN,
        complete=False,
        enumeration_complete=False,
        source_document_ids=(),
        reference=None,
    )
    interfaces = inventory(values, "interfaces")
    interfaces["source_document_ids"] = (CONFIG_SOURCE_ID, NAT_SOURCE_ID)
    anchor = {
        "source_document_id": NAT_SOURCE_ID,
        "location": {"source_name": second_source["source_name"], "line_start": 1},
    }
    values["interfaces"][1]["location"] = anchor
    interfaces["locations"] = (interfaces["locations"][0], anchor)
    if not semantic_complete:
        interfaces.update(
            status=DataStatus.UNKNOWN, complete=False, diagnostics=("Interface semantics pending",)
        )
    assert ForwardingContext.model_validate(values)

    second_source["complete_scopes"] = ()
    if defect == "effective_nat_role":
        second_source["purpose"] = "effective_nat"
    elif defect == "truncated":
        second_source["extent"] = "truncated"
    elif defect == "failed_capture":
        second_source["capture_success"] = False
    assert ForwardingSource.model_validate(second_source)
    assert "interfaces" in values["sources"][0]["complete_scopes"]
    with pytest.raises(ValidationError):
        ForwardingContext.model_validate(values)


def test_ace_requires_nonempty_source_anchor() -> None:
    values = payload()
    values["acls"][0]["rules"][0]["source_location"].update(
        line_start=None,
        line_end=None,
        object_path="",
        object_id="",
    )
    with pytest.raises(ValidationError):
        ForwardingContext.model_validate(values)
