"""Привязка доказывает связь снимков, но не полноту или достижимость."""

from copy import copy, deepcopy
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.forwarding_binding_fixtures import make_binding_inputs, unsafe_copy
from tests.network_import_fixtures import INTERFACES, RIB, make_document
from tests.revision_fixtures import CONFIGURATION_SOURCE_ID, OBSERVED_AT

from firewall_compliance.application.forwarding_binding import (
    ForwardingBindingResult,
    bind_forwarding_context,
)
from firewall_compliance.application.network_import import (
    NetworkImportResult,
    import_network_documents,
)
from firewall_compliance.domain import DataStatus, RuleAction, SourceDocumentKind
from firewall_compliance.domain.forwarding import ForwardingLocation
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseResult

OTHER_UUID = UUID("99999999-0000-0000-0000-000000000001")


def test_matching_real_parser_snapshots_bind_without_promoting_inventories() -> None:
    imported, parsed = make_binding_inputs()
    imported_before = imported.model_dump_json()
    parsed_before = parsed.model_dump_json()

    result = bind_forwarding_context(imported, parsed)

    assert result.schema_version == "0.1.0"
    assert result.status == "consistent"
    assert result.reasons == ()
    assert result.imported == imported
    assert result.forwarding == parsed
    assert result.imported is not imported
    assert result.forwarding is not parsed
    assert imported.model_dump_json() == imported_before
    assert parsed.model_dump_json() == parsed_before
    assert result.forwarding.context == parsed.context
    assert result.forwarding.context.flow is None
    assert all(not inventory.complete for inventory in result.forwarding.context.inventories)
    assert any(i.status == DataStatus.UNKNOWN for i in result.forwarding.context.inventories)
    assert result.imported.revision.routes_status == DataStatus.UNKNOWN
    assert isinstance(result.interfaces, tuple)
    assert {item.interface_id for item in result.interfaces} == {
        item.interface_id for item in parsed.context.interfaces
    }
    document = imported.documents[0]
    for mapping in result.interfaces:
        interface = next(
            i for i in parsed.context.interfaces if i.interface_id == mapping.interface_id
        )
        assert mapping.status == DataStatus.KNOWN
        assert mapping.interface_label == interface.label
        assert mapping.network_source_document_id == document.source.source_document_id
        assert mapping.forwarding_source_document_id == CONFIGURATION_SOURCE_ID
        assert interface.location in mapping.source_locations
        assert all(
            isinstance(location, ForwardingLocation) for location in mapping.source_locations
        )
        assert {location.source_document_id for location in mapping.source_locations} == {
            document.source.source_document_id,
            CONFIGURATION_SOURCE_ID,
        }
        assert all(
            location.location.line_start is not None for location in mapping.source_locations
        )


def test_binding_and_nested_snapshots_roundtrip_without_losing_provenance() -> None:
    imported, parsed = make_binding_inputs()
    result = bind_forwarding_context(imported, parsed)

    restored = ForwardingBindingResult.model_validate_json(result.model_dump_json())

    assert restored == result
    assert restored.imported == NetworkImportResult.model_validate_json(imported.model_dump_json())
    assert restored.forwarding == ForwardingParseResult.model_validate_json(
        parsed.model_dump_json()
    )
    assert restored.interfaces[0].source_locations == result.interfaces[0].source_locations


@pytest.mark.parametrize(
    "field,value",
    [
        ("revision_id", OTHER_UUID),
        ("configuration_id", OTHER_UUID),
        ("device_id", "different-device"),
        ("device_context", "different-context"),
        ("imported_at", OBSERVED_AT + timedelta(minutes=2)),
    ],
)
def test_binding_rejects_conflicting_snapshot_identity(field: str, value: Any) -> None:
    imported, parsed = make_binding_inputs()
    tampered = unsafe_copy(parsed, context=unsafe_copy(parsed.context, **{field: value}))

    with pytest.raises(ValueError):
        bind_forwarding_context(imported, tampered)


@pytest.mark.parametrize("field,value", [("vendor", "other"), ("platform", "asa-9.12")])
def test_binding_requires_asa_916_baseline(field: str, value: str) -> None:
    imported, parsed = make_binding_inputs()
    revision = imported.revision
    tampered = unsafe_copy(
        imported,
        revision=unsafe_copy(revision, device=unsafe_copy(revision.device, **{field: value})),
    )

    with pytest.raises(ValueError):
        bind_forwarding_context(tampered, parsed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_document_id", OTHER_UUID),
        ("source_name", "different.cfg"),
        ("content_sha256", "f" * 64),
        ("captured_at", OBSERVED_AT + timedelta(seconds=1)),
        ("device_id", "different-device"),
        ("device_context", "different-context"),
        ("observation", None),
    ],
)
def test_binding_rejects_configuration_source_provenance_conflicts(field: str, value: Any) -> None:
    imported, parsed = make_binding_inputs()
    source = unsafe_copy(parsed.context.sources[0], **{field: value})
    tampered = unsafe_copy(parsed, context=unsafe_copy(parsed.context, sources=(source,)))

    with pytest.raises(ValueError):
        bind_forwarding_context(imported, tampered)


@pytest.mark.parametrize(
    "field,value", [("source_name", "different.cfg"), ("content_sha256", "f" * 64)]
)
def test_binding_rejects_configuration_header_mismatch(field: str, value: str) -> None:
    imported, parsed = make_binding_inputs()
    revision = imported.revision
    baseline = revision.parse_result
    tampered = unsafe_copy(
        imported,
        revision=unsafe_copy(
            revision,
            parse_result=unsafe_copy(
                baseline, configuration=unsafe_copy(baseline.configuration, **{field: value})
            ),
        ),
    )

    with pytest.raises(ValueError):
        bind_forwarding_context(tampered, parsed)


def test_binding_rejects_wrong_configuration_revision_source_kind() -> None:
    imported, parsed = make_binding_inputs()
    revision = imported.revision
    source = unsafe_copy(revision.sources[0], kind=SourceDocumentKind.ROUTING_TABLE)
    tampered = unsafe_copy(
        imported, revision=unsafe_copy(revision, sources=(source, *revision.sources[1:]))
    )

    with pytest.raises(ValueError):
        bind_forwarding_context(tampered, parsed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("context_mode", "multiple"),
        ("firewall_mode", "transparent"),
        ("address_family", "ipv6"),
        ("table_role", "management"),
        ("table_id", "other-table"),
    ],
)
def test_binding_rejects_known_profile_contradictions(field: str, value: str) -> None:
    imported, parsed = make_binding_inputs()
    tampered = unsafe_copy(parsed, context=unsafe_copy(parsed.context, **{field: value}))

    with pytest.raises(ValueError):
        bind_forwarding_context(imported, tampered)


@pytest.mark.parametrize(
    "field", ["context_mode", "firewall_mode", "address_family", "table_role", "table_id"]
)
def test_unknown_profile_is_partial_without_erasing_known_interface_links(field: str) -> None:
    imported, parsed = make_binding_inputs()
    partial = parsed.model_copy(update={"context": parsed.context.model_copy(update={field: None})})

    result = bind_forwarding_context(imported, partial)

    assert result.status == "not_enough_evidence"
    assert result.reasons
    assert all(mapping.status == DataStatus.KNOWN for mapping in result.interfaces)
    assert result.forwarding == partial


def test_missing_interface_document_returns_partial_mappings_without_guessed_source_uuid() -> None:
    imported, parsed = make_binding_inputs(include_document=False)

    result = bind_forwarding_context(imported, parsed)

    assert result.status == "not_enough_evidence"
    assert result.reasons
    assert len(result.interfaces) == len(parsed.context.interfaces)
    assert all(mapping.status == DataStatus.UNKNOWN for mapping in result.interfaces)
    assert all(mapping.network_source_document_id is None for mapping in result.interfaces)
    assert result.forwarding == parsed


def test_absent_observation_returns_partial_without_inventing_observation() -> None:
    imported, parsed = make_binding_inputs(observed=False)

    result = bind_forwarding_context(imported, parsed)

    assert result.status == "not_enough_evidence"
    assert result.reasons
    assert all(mapping.status == DataStatus.UNKNOWN for mapping in result.interfaces)
    assert result.forwarding.context.observed_at is None
    assert result.imported.revision.observed_at is None


@pytest.mark.parametrize("field", ["label", "security_level"])
def test_binding_rejects_explicit_interface_setting_contradictions(field: str) -> None:
    imported, parsed = make_binding_inputs()
    document = imported.documents[0]
    first = document.interface_settings[0]
    changed = unsafe_copy(first, **{field: "renamed" if field == "label" else 42})
    tampered = unsafe_copy(
        imported,
        documents=(
            unsafe_copy(document, interface_settings=(changed, *document.interface_settings[1:])),
        ),
    )

    with pytest.raises(ValueError):
        bind_forwarding_context(tampered, parsed)


@pytest.mark.parametrize("missing", ["setting", "label", "security_level"])
def test_missing_settings_are_partial_without_guessed_defaults(missing: str) -> None:
    imported, parsed = make_binding_inputs()
    payload = imported.model_dump(mode="python")
    settings = payload["documents"][0]["interface_settings"]
    target = settings[0]["label"]
    if missing == "setting":
        payload["documents"][0]["interface_settings"] = settings[1:]
    else:
        settings[0][missing] = None
    partial = NetworkImportResult.model_validate(payload)

    result = bind_forwarding_context(partial, parsed)

    assert result.status == "not_enough_evidence"
    assert result.reasons
    statuses = {mapping.interface_label: mapping.status for mapping in result.interfaces}
    assert statuses[target] == DataStatus.UNKNOWN
    assert set(statuses.values()) == {DataStatus.KNOWN, DataStatus.UNKNOWN}


def test_missing_forwarding_security_is_partial_without_using_network_default() -> None:
    imported, parsed = make_binding_inputs()
    interface = parsed.context.interfaces[0].model_copy(
        update={"security_level": None, "security_status": DataStatus.UNKNOWN}
    )
    partial = parsed.model_copy(
        update={
            "context": parsed.context.model_copy(
                update={"interfaces": (interface, *parsed.context.interfaces[1:])}
            )
        }
    )

    result = bind_forwarding_context(imported, partial)

    assert result.status == "not_enough_evidence"
    assert (
        next(m for m in result.interfaces if m.interface_id == interface.interface_id).status
        == DataStatus.UNKNOWN
    )
    assert result.forwarding.context.interfaces[0].security_level is None


def test_missing_network_interface_keeps_other_mapping_known() -> None:
    outside_only = INTERFACES.split("interface GigabitEthernet0/1", 1)[0]
    imported, parsed = make_binding_inputs(interface_text=outside_only)

    result = bind_forwarding_context(imported, parsed)

    assert result.status == "not_enough_evidence"
    assert result.reasons
    assert {m.interface_label: m.status for m in result.interfaces} == {
        "outside": DataStatus.KNOWN,
        "inside": DataStatus.UNKNOWN,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "different-name"),
        ("addresses", ("192.0.2.99/24",)),
        ("source_document_id", CONFIGURATION_SOURCE_ID),
    ],
)
def test_binding_rejects_network_document_fact_disagreeing_with_revision(
    field: str, value: Any
) -> None:
    imported, parsed = make_binding_inputs()
    revision = imported.revision
    changed = unsafe_copy(revision.interfaces[0], **{field: value})
    tampered = unsafe_copy(
        imported, revision=unsafe_copy(revision, interfaces=(changed, *revision.interfaces[1:]))
    )

    with pytest.raises(ValueError):
        bind_forwarding_context(tampered, parsed)


def test_binding_rejects_different_known_forwarding_observation_time() -> None:
    imported, parsed = make_binding_inputs()
    different = OBSERVED_AT - timedelta(seconds=1)
    source = parsed.context.sources[0]
    assert source.observation is not None
    changed_source = source.model_copy(
        update={"observation": source.observation.model_copy(update={"observed_at": different})}
    )
    tampered = parsed.model_copy(
        update={
            "context": parsed.context.model_copy(
                update={"sources": (changed_source,), "observed_at": different}
            )
        }
    )

    with pytest.raises(ValueError):
        bind_forwarding_context(imported, tampered)


def test_binding_rejects_duplicate_interface_document_even_after_copy_bypass() -> None:
    imported, parsed = make_binding_inputs()
    tampered = unsafe_copy(imported, documents=(imported.documents[0], imported.documents[0]))

    with pytest.raises(ValueError):
        bind_forwarding_context(tampered, parsed)


def test_binding_rejects_duplicate_interface_settings_even_after_copy_bypass() -> None:
    imported, parsed = make_binding_inputs()
    document = imported.documents[0]
    tampered = unsafe_copy(
        imported,
        documents=(
            unsafe_copy(
                document,
                interface_settings=(*document.interface_settings, document.interface_settings[0]),
            ),
        ),
    )

    with pytest.raises(ValueError):
        bind_forwarding_context(tampered, parsed)


def test_binding_rejects_tampered_acl_packet_fields_despite_matching_source_hash() -> None:
    imported, parsed = make_binding_inputs()
    acl = parsed.context.acls[0]
    changed_rule = unsafe_copy(acl.rules[0], action=RuleAction.DENY)
    tampered = unsafe_copy(
        parsed, context=unsafe_copy(parsed.context, acls=(unsafe_copy(acl, rules=(changed_rule,)),))
    )

    with pytest.raises(ValueError):
        bind_forwarding_context(imported, tampered)


@pytest.mark.parametrize("field", ["status", "interfaces", "reasons"])
def test_result_validation_recomputes_and_rejects_tampered_link_evidence(field: str) -> None:
    imported, parsed = make_binding_inputs(observed=False)
    result = bind_forwarding_context(imported, parsed)
    payload = result.model_dump(mode="python")
    if field == "status":
        payload[field] = "consistent"
    elif field == "interfaces":
        payload[field][0]["status"] = "known"
    else:
        payload[field] = ()

    with pytest.raises(ValueError):
        ForwardingBindingResult.model_validate(payload)
    with pytest.raises(ValueError):
        result.model_copy(update={field: payload[field]})


def test_result_revalidates_nested_inputs_after_copy_bypass() -> None:
    imported, parsed = make_binding_inputs()
    result = bind_forwarding_context(imported, parsed)
    tampered = unsafe_copy(parsed, context=unsafe_copy(parsed.context, revision_id=OTHER_UUID))

    with pytest.raises(ValueError):
        result.model_copy(update={"forwarding": tampered})
    with pytest.raises(ValueError):
        ForwardingBindingResult.model_validate(
            {**result.model_dump(mode="python"), "forwarding": tampered}
        )


@pytest.mark.parametrize(
    "copier",
    [
        copy,
        deepcopy,
        lambda result: result.model_copy(),
        lambda result: result.model_copy(deep=True),
    ],
)
def test_binding_copies_preserve_frozen_nested_snapshots(copier: Any) -> None:
    imported, parsed = make_binding_inputs()
    result = copier(bind_forwarding_context(imported, parsed))

    with pytest.raises((TypeError, ValidationError)):
        result.forwarding.context.acls[0].rules[0].name = "mutation"
    with pytest.raises((TypeError, ValidationError)):
        result.interfaces[0].source_locations[0].location.line_start = 999
    with pytest.raises((TypeError, ValidationError)):
        result.imported.revision.interfaces[0].name = "mutation"
    with pytest.raises(TypeError):
        result.imported.documents[0].interface_labels["fake"] = "fake-interface"
    with pytest.raises((TypeError, ValidationError)):
        result.status = "not_enough_evidence"


@pytest.mark.parametrize("remove_settings", [False, True])
def test_swapped_labels_are_rejected_even_without_settings(remove_settings: bool) -> None:
    imported, parsed = make_binding_inputs()
    payload = imported.model_dump(mode="python")
    doc = payload["documents"][0]
    labels = doc["interface_labels"]
    labels["inside"], labels["outside"] = labels["outside"], labels["inside"]
    if remove_settings:
        doc["interface_settings"] = ()
    with pytest.raises(ValueError, match="карта labels"):
        bind_forwarding_context(NetworkImportResult.model_validate(payload), parsed)


def test_setting_anchors_must_belong_to_their_interface_block() -> None:
    imported, parsed = make_binding_inputs()
    payload = imported.model_dump(mode="python")
    settings = payload["documents"][0]["interface_settings"]
    settings[0]["source_locations"] = settings[1]["source_locations"]
    with pytest.raises(ValueError, match="source mapping"):
        bind_forwarding_context(NetworkImportResult.model_validate(payload), parsed)


def test_duplicate_baseline_rule_id_cannot_hide_a_conflicting_action() -> None:
    imported, parsed = make_binding_inputs()
    payload = imported.model_dump(mode="python")
    rules = payload["revision"]["parse_result"]["rules"]
    payload["revision"]["parse_result"]["rules"] = [{**rules[0], "action": "deny"}, *rules]
    with pytest.raises(ValueError, match="идентификаторы ACE"):
        bind_forwarding_context(NetworkImportResult.model_validate(payload), parsed)


@pytest.mark.parametrize("field,value", [("declared_version", "9.12"), ("command", "show nat")])
def test_forwarding_source_profile_is_rechecked(field: str, value: str) -> None:
    imported, parsed = make_binding_inputs()
    payload = parsed.model_dump(mode="python")
    payload["context"]["sources"][0][field] = value
    with pytest.raises(ValueError):
        bind_forwarding_context(imported, ForwardingParseResult.model_validate(payload))


def test_unknown_context_cannot_hide_an_unsupported_network_profile() -> None:
    imported, parsed = make_binding_inputs()
    payload = imported.model_dump(mode="python")
    payload["documents"][0]["metadata"]["address_family"] = "ipv6"
    partial = parsed.model_copy(
        update={"context": parsed.context.model_copy(update={"address_family": None})}
    )
    with pytest.raises(ValueError, match="профиль сетевого документа"):
        bind_forwarding_context(NetworkImportResult.model_validate(payload), partial)


def test_revision_fact_outside_forwarding_subset_is_still_checked() -> None:
    imported, parsed = make_binding_inputs()
    forwarding_payload = parsed.model_dump(mode="python")
    context = forwarding_payload["context"]
    context["interfaces"] = context["interfaces"][:1]
    context["bindings"] = ()
    for inventory in context["inventories"]:
        if inventory["feature"] == "interfaces":
            inventory["item_count"] = 1
        elif inventory["feature"] == "acl_bindings":
            inventory["item_count"] = 0
    partial = ForwardingParseResult.model_validate(forwarding_payload)
    payload = imported.model_dump(mode="python")
    payload["revision"]["interfaces"][1]["addresses"] = ("10.99.0.1/24",)
    with pytest.raises(ValueError, match="набор сетевых интерфейсов"):
        bind_forwarding_context(NetworkImportResult.model_validate(payload), partial)


def _with_rib(*, coherent: bool) -> tuple[NetworkImportResult, ForwardingParseResult]:
    imported, parsed = make_binding_inputs(include_document=False)
    base = imported.revision
    requests = (
        make_document(base, INTERFACES, "asa_running_config_interfaces"),
        make_document(base, RIB, "asa_ipv4_rib", observed=coherent),
    )
    outcome = import_network_documents(base, requests, revision_id=OTHER_UUID)
    assert isinstance(outcome, NetworkImportResult)
    return outcome, parsed.model_copy(
        update={"context": parsed.context.model_copy(update={"revision_id": OTHER_UUID})}
    )


def test_selected_rib_without_observation_is_partial() -> None:
    imported, parsed = _with_rib(coherent=False)
    result = bind_forwarding_context(imported, parsed)
    assert result.status == "not_enough_evidence"
    assert any(reason.code == "binding_network_observation_unknown" for reason in result.reasons)


def test_selected_rib_facts_must_equal_revision_routes() -> None:
    imported, parsed = _with_rib(coherent=True)
    assert bind_forwarding_context(imported, parsed).status == "consistent"
    payload = imported.model_dump(mode="python")
    payload["revision"]["routes"][0]["metric"] = 42
    with pytest.raises(ValueError, match="набор маршрутов"):
        bind_forwarding_context(NetworkImportResult.model_validate(payload), parsed)


@pytest.mark.parametrize("source_kind", ["configuration", "network"])
def test_failed_capture_does_not_produce_consistent_binding(source_kind: str) -> None:
    imported, parsed = make_binding_inputs()
    if source_kind == "configuration":
        payload = parsed.model_dump(mode="python")
        payload["context"]["sources"][0]["capture_success"] = False
        parsed = ForwardingParseResult.model_validate(payload)
    else:
        payload = imported.model_dump(mode="python")
        payload["documents"][0]["metadata"]["capture_success"] = False
        payload["documents"][0]["metadata"]["complete"] = False
        payload["documents"][0]["status"] = "unknown"
        payload["documents"][0]["collection_evidence"]["complete"] = False
        imported = NetworkImportResult.model_validate(payload)
    result = bind_forwarding_context(imported, parsed)
    assert result.status == "not_enough_evidence"
    assert any(reason.code == "binding_capture_failed" for reason in result.reasons)
