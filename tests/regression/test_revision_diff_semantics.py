"""Synthetic evidence-aware revision comparisons, including legacy JSON compatibility."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from firewall_compliance.analysis.revision_diff import compare_device_revisions
from firewall_compliance.domain.enums import RevisionChangeKind, RevisionEntityKind
from firewall_compliance.domain.revision import DeviceRevision, DeviceRevisionDiff

COLLECTIONS = ("interfaces", "routes", "network_segments", "topology_links")


def revision(seed=1, *, parser="1.0.0", complete=True, empty=False):
    date = (datetime(2026, 10, 20, tzinfo=UTC) + timedelta(days=seed)).isoformat()
    source_id = str(UUID(int=seed))
    observation = {"observed_at": date, "method": "synthetic", "reference": "Synthetic capture"}
    anchor = {"source_name": "synthetic.cfg", "line_start": 1}
    common = {
        "device_id": "synthetic-device",
        "origin": "imported",
        "data_status": "known",
        "source_document_id": source_id,
        "source_location": anchor,
    }
    payload = {
        "schema_version": "2.0.0",
        "revision_id": str(UUID(int=1000 + seed)),
        "device": {"device_id": "synthetic-device", "vendor": "synthetic", "platform": "test"},
        "parse_result": {
            "configuration": {
                "configuration_id": str(UUID(int=100 + seed)),
                "source_name": "synthetic.cfg",
                "device_id": "synthetic-device",
                "vendor": "synthetic",
                "platform": "test",
                "parser_version": parser,
                "content_sha256": "a" * 64,
                "captured_at": date,
                "imported_at": date,
            },
            "coverage": {
                "discovered_constructs": 0,
                "recognized_constructs": 0,
                "unsupported_constructs": 0,
            },
        },
        "sources": [
            {
                "source_document_id": source_id,
                "source_name": "synthetic.cfg",
                "content_sha256": "a" * 64,
                "kind": "configuration",
                "captured_at": date,
                "observation": observation,
            }
        ],
        "application_version": "0.3.0",
        "imported_at": date,
        "observed_at": date,
        "interfaces": [
            {
                **common,
                "interface_id": name,
                "name": name,
                "addresses": [address],
                "addresses_status": "known",
                "enabled": True,
            }
            for name, address in (("if-a", "192.0.2.1/24"), ("if-b", "198.51.100.1/24"))
        ],
        "routes": [
            {
                **common,
                "route_id": "route-a",
                "destination": "203.0.113.0/24",
                "next_hop": "192.0.2.2",
                "outgoing_interface_id": "if-a",
                "metric": 10,
                "administrative_distance": 1,
                "route_kind": "static",
            }
        ],
        "network_segments": [
            {
                **common,
                "segment_id": "segment-a",
                "name": "Synthetic segment",
                "cidrs": ["203.0.113.0/24"],
            }
        ],
        "topology_links": [
            {
                **common,
                "link_id": "link-a",
                "left_endpoint_id": "if-a",
                "right_endpoint_id": "segment-a",
            }
        ],
    }
    scopes = {
        "interfaces": "interfaces",
        "routes": "configured_routes",
        "network_segments": "segments",
        "topology_links": "topology",
    }
    for collection, scope in scopes.items():
        prefix = "topology" if collection == "topology_links" else collection
        payload[prefix + "_status"] = (
            "absent" if empty and complete else ("known" if complete else "unknown")
        )
        payload[prefix + "_evidence"] = {
            "scope": scope,
            "complete": complete,
            "source_document_ids": [source_id],
        }
        if empty:
            payload[collection] = []
    return DeviceRevision.model_validate(payload)


def changed(source, collection, index=0, **values):
    payload = source.model_dump(mode="python")
    payload[collection][index].update(values)
    return DeviceRevision.model_validate(payload)


def test_reimport_source_ids_locations_and_times_are_only_provenance():
    before, after = revision(1), revision(2)
    after = changed(
        after, "interfaces", source_location={"source_name": "synthetic.cfg", "line_start": 9}
    )
    result = compare_device_revisions(before, after)
    assert not result.changes and not result.normalization_changes
    assert not result.completeness_changes
    assert len(result.provenance_changes) == 6
    assert "source_document_id" in result.provenance_changes[1].changed_fields
    assert "source_location" in result.provenance_changes[1].changed_fields


def test_incomplete_disappearance_does_not_become_deletion():
    result = compare_device_revisions(revision(), revision(2, complete=False, empty=True))
    assert not result.changes
    missing = [detail for detail in result.completeness_changes if detail.code == "not_observed"]
    assert len(missing) == 5
    assert all(detail.evidence.facts["before"] for detail in missing)
    assert all(not detail.evidence.facts["after_inventory"]["complete"] for detail in missing)


def test_complete_observed_absence_allows_removal_in_comparable_scope():
    result = compare_device_revisions(revision(), revision(2, empty=True))
    assert len(result.changes) == 5
    assert all(change.change_kind == RevisionChangeKind.REMOVED for change in result.changes)
    assert not any(detail.code == "not_observed" for detail in result.completeness_changes)
    assert all(change.evidence.facts["after_inventory"]["complete"] for change in result.changes)


def test_addition_requires_comparable_observed_absence_before():
    proven = compare_device_revisions(revision(empty=True), revision(2))
    assert len(proven.changes) == 5
    assert all(change.change_kind == RevisionChangeKind.ADDED for change in proven.changes)
    first_seen = compare_device_revisions(revision(empty=True, complete=False), revision(2))
    assert not first_seen.changes
    assert sum(detail.code == "first_observed" for detail in first_seen.completeness_changes) == 5


@pytest.mark.parametrize(
    ("collection", "values", "kind", "field"),
    [
        ("interfaces", {"enabled": False}, RevisionEntityKind.INTERFACE, "enabled"),
        ("routes", {"metric": 20}, RevisionEntityKind.ROUTE, "metric"),
        (
            "network_segments",
            {"cidrs": ["203.0.114.0/24"]},
            RevisionEntityKind.NETWORK_SEGMENT,
            "cidrs",
        ),
        (
            "topology_links",
            {"right_endpoint_id": "if-b"},
            RevisionEntityKind.TOPOLOGY_LINK,
            "right_endpoint_id",
        ),
    ],
)
def test_known_value_modification_is_separate_from_source_changes(collection, values, kind, field):
    result = compare_device_revisions(revision(), changed(revision(2), collection, **values))
    assert len(result.changes) == 1
    assert result.changes[0].entity_kind == kind
    assert result.changes[0].change_kind == RevisionChangeKind.MODIFIED
    assert result.changes[0].evidence.facts["changed_fields"] == (field,)


def test_unknown_field_becoming_known_is_availability_not_network_modification():
    before = changed(revision(), "interfaces", enabled=None)
    result = compare_device_revisions(before, revision(2))
    assert not result.changes
    assert any(
        detail.entity_id == "if-a" and detail.changed_fields == ("enabled",)
        for detail in result.completeness_changes
    )


def test_unknown_addresses_and_changed_inventory_status_are_not_silent():
    after = changed(
        revision(2), "interfaces", addresses_status="unknown", addresses=["192.0.2.8/24"]
    )
    result = compare_device_revisions(revision(), after)
    assert not result.changes
    assert {"addresses", "addresses_status"} <= set(result.completeness_changes[0].changed_fields)


def test_parser_change_is_explicit_and_value_differences_remain_normalization_dependent():
    after = changed(revision(2, parser="2.0.0"), "routes", metric=20)
    result = compare_device_revisions(revision(), after)
    assert result.normalization_changed and not result.changes
    assert [detail.code for detail in result.normalization_changes] == [
        "normalization_changed",
        "normalization_dependent",
    ]
    assert result.normalization_changes[1].changed_fields == ("metric",)
    assert result.normalization_changes[1].evidence.facts["before"]["metric"] == 10


def test_configuration_byte_change_is_recorded_without_claiming_network_modification():
    payload = revision(2).model_dump(mode="python")
    payload["sources"][0]["content_sha256"] = "b" * 64
    payload["parse_result"]["configuration"]["content_sha256"] = "b" * 64
    result = compare_device_revisions(revision(), DeviceRevision.model_validate(payload))
    assert not result.changes
    assert (
        result.provenance_changes[0].evidence.facts["after"]["configuration"]["content_sha256"]
        == "b" * 64
    )


def test_route_source_derived_ids_are_reconciled_with_multiplicity_preserved():
    before, after = revision(), changed(revision(2), "routes", route_id="new-source:line-9")
    result = compare_device_revisions(before, after)
    assert not result.changes
    assert any("route_id" in detail.changed_fields for detail in result.provenance_changes)
    payload = after.model_dump(mode="python")
    payload["routes"] = [
        *payload["routes"],
        {**payload["routes"][0], "route_id": "duplicate-route"},
    ]
    result = compare_device_revisions(before, DeviceRevision.model_validate(payload))
    assert len(result.changes) == 1 and result.changes[0].change_kind == RevisionChangeKind.ADDED


def test_nondefault_route_scope_does_not_prove_removal():
    before = changed(revision(), "routes", table_id="other")
    result = compare_device_revisions(before, revision(2, empty=True))
    route_changes = [
        change for change in result.changes if change.entity_kind == RevisionEntityKind.ROUTE
    ]
    assert not route_changes
    assert any(
        detail.entity_kind == RevisionEntityKind.ROUTE and detail.code == "scope_incomparable"
        for detail in result.completeness_changes
    )


def test_configured_routes_and_rib_are_different_absence_scopes():
    payload = revision(2).model_dump(mode="python")
    routing_source = {
        **payload["sources"][0],
        "source_document_id": UUID(int=9999),
        "source_name": "routes.txt",
        "kind": "routing_table",
    }
    payload["sources"] = [*payload["sources"], routing_source]
    payload["routes"] = []
    payload["routes_status"] = "absent"
    payload["routes_evidence"].update(
        scope="routing_table", source_document_ids=[routing_source["source_document_id"]]
    )
    result = compare_device_revisions(revision(), DeviceRevision.model_validate(payload))
    assert not result.changes
    assert any(
        detail.entity_id == "route-a" and detail.code == "not_observed"
        for detail in result.completeness_changes
    )


def test_revision_observation_does_not_invent_an_unobserved_fact_time():
    payload = revision().model_dump(mode="python")
    secondary = {
        **payload["sources"][0],
        "source_document_id": UUID(int=9998),
        "source_name": "secondary.cfg",
        "observation": None,
    }
    payload["sources"] = [*payload["sources"], secondary]
    for collection in COLLECTIONS:
        prefix = "topology" if collection == "topology_links" else collection
        payload[prefix + "_status"] = "unknown"
        for fact in payload[collection]:
            fact["source_document_id"] = secondary["source_document_id"]
            fact["source_location"]["source_name"] = "secondary.cfg"
    result = compare_device_revisions(
        DeviceRevision.model_validate(payload), revision(2, empty=True)
    )
    assert not result.changes
    assert sum(detail.code == "not_observed" for detail in result.completeness_changes) == 5


def test_non_applicable_inventory_does_not_claim_removed_devices():
    payload = revision(2, empty=True).model_dump(mode="python")
    for collection in COLLECTIONS:
        prefix = "topology" if collection == "topology_links" else collection
        payload[prefix + "_status"] = "not_applicable"
    result = compare_device_revisions(revision(), DeviceRevision.model_validate(payload))
    assert not result.changes
    assert sum(detail.code == "not_observed" for detail in result.completeness_changes) == 5


def test_unknown_fact_status_prevents_network_modification():
    payload = revision().model_dump(mode="python")
    payload["interfaces_status"] = "unknown"
    payload["interfaces"][0]["data_status"] = "unknown"
    before = DeviceRevision.model_validate(payload)
    result = compare_device_revisions(before, changed(revision(2), "interfaces", enabled=False))
    assert not result.changes
    assert any("data_status" in detail.changed_fields for detail in result.completeness_changes)


def test_context_mismatch_is_rejected_even_for_same_device_id():
    payload = revision(2).model_dump(mode="python")
    payload["device"]["context"] = "other-context"
    with pytest.raises(ValueError, match="контекст"):
        compare_device_revisions(revision(), DeviceRevision.model_validate(payload))


def test_old_unversioned_diff_is_not_reclassified_or_expanded():
    payload = {
        "before_revision_id": str(UUID(int=1)),
        "after_revision_id": str(UUID(int=2)),
        "device_id": "synthetic-device",
        "normalization_changed": True,
        "limitations": ["Legacy structural comparison"],
        "changes": [
            {
                "entity_kind": "interface",
                "change_kind": "removed",
                "entity_id": "if-a",
                "evidence": {"summary": "Legacy absence", "facts": {"before": {"name": "if-a"}}},
            }
        ],
    }
    # Canonicalize existing Evidence defaults, not a golden-file update.
    old = DeviceRevisionDiff.model_validate(payload)
    dumped = old.model_dump(mode="json")
    assert old.schema_version is None
    assert "schema_version" not in dumped and "completeness_changes" not in dumped
    assert old.changes[0].change_kind == RevisionChangeKind.REMOVED
    assert old.normalization_changed and not old.normalization_changes
    with pytest.raises(ValueError, match="classified changes"):
        old.model_copy(
            update={
                "completeness_changes": [
                    {
                        "entity_kind": "interface",
                        "entity_id": "if-a",
                        "code": "not_observed",
                        "evidence": {"summary": "Cannot reclassify an old comparison"},
                    }
                ]
            }
        )
    assert (
        DeviceRevisionDiff.model_validate_json(old.model_dump_json()).model_dump(mode="json")
        == dumped
    )


def test_new_diff_serialization_is_deterministic_roundtrippable_and_frozen():
    before, after = revision(), changed(revision(2), "interfaces", enabled=False)
    original = deepcopy(after.model_dump(mode="json"))
    first = compare_device_revisions(before, after)
    second = compare_device_revisions(before, after)
    assert first.model_dump_json() == second.model_dump_json()
    assert json.loads(first.model_dump_json())["schema_version"] == "2.0.0"
    reread = DeviceRevisionDiff.model_validate_json(first.model_dump_json())
    assert reread.model_dump_json() == first.model_dump_json()
    assert after.model_dump(mode="json") == original
    with pytest.raises(TypeError):
        first.changes[0].evidence.facts["after"]["enabled"] = True
    with pytest.raises(ValueError):
        DeviceRevisionDiff.model_validate(
            {**first.model_dump(mode="json"), "schema_version": "future"}
        )
    with pytest.raises(ValueError):
        first.model_copy(update={"schema_version": "future"})
