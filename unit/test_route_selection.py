"""Выбор маршрута без скрытых предположений о полноте и сетевой передаче."""

from itertools import permutations
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.reachability_fixtures import make_query, make_rib_revision, make_route
from tests.revision_fixtures import OBSERVATION, OBSERVED_AT, make_revision

from firewall_compliance.analysis import analyze_reachability, select_route
from firewall_compliance.domain import (
    CollectionEvidence,
    DataOrigin,
    DataStatus,
    DeviceRevision,
    Route,
    RouteSelectionResult,
)


def codes(result: RouteSelectionResult) -> set[str]:
    return {reason.code for reason in result.reasons}


@pytest.mark.parametrize("kind", ["connected", "static"])
def test_single_supported_route_needs_no_invented_priority(kind: str) -> None:
    revision = make_rib_revision(
        (make_route(route_kind=kind, administrative_distance=None, metric=None),)
    )
    result = select_route(revision, make_query())
    assert result.status == "selected"
    assert result.hops[0].route_id == "default"
    assert result.hops[0].evidence.facts["administrative_distance"] is None


def test_longest_prefix_precedes_distance_and_metric() -> None:
    routes = (
        make_route("default", administrative_distance=0),
        make_route("wide", "198.51.100.0/24", administrative_distance=1),
        make_route("narrow", "198.51.100.0/26", administrative_distance=200, metric=999),
        make_route("elsewhere", "203.0.113.0/24"),
    )
    result = select_route(make_rib_revision(routes), make_query())
    assert result.candidate_route_ids == ("narrow",)
    assert result.matched_route_ids == ("default", "narrow", "wide")
    assert result.evidence.facts["selection_trace"] == {"longest_prefix_length": 26}


def test_host_route_wins_and_default_matches_another_destination() -> None:
    revision = make_rib_revision((make_route(), make_route("host", "198.51.100.25/32")))
    assert select_route(revision, make_query()).candidate_route_ids == ("host",)
    assert select_route(
        revision, make_query(destination_ip="203.0.113.10")
    ).candidate_route_ids == ("default",)


def test_distance_precedes_metric() -> None:
    result = select_route(
        make_rib_revision(
            (
                make_route("a", administrative_distance=10, metric=0),
                make_route("b", administrative_distance=1, metric=100),
            )
        ),
        make_query(),
    )
    assert result.candidate_route_ids == ("b",)


@pytest.mark.parametrize("kind", ["connected", "static"])
def test_explicit_metric_breaks_equal_distance(kind: str) -> None:
    result = select_route(
        make_rib_revision(
            (
                make_route("a", route_kind=kind, metric=1),
                make_route("b", route_kind=kind, metric=10),
            )
        ),
        make_query(),
    )
    assert result.candidate_route_ids == ("a",)
    assert result.evidence.facts["selection_trace"]["metric"] == 1


@pytest.mark.parametrize(
    "field,reason",
    [
        ("administrative_distance", "distance_missing"),
        ("metric", "metric_missing"),
    ],
)
def test_missing_competitor_priority_never_becomes_zero(field: str, reason: str) -> None:
    result = select_route(
        make_rib_revision((make_route("a"), make_route("b", **{field: None}))), make_query()
    )
    assert result.status == "not_enough_evidence"
    assert reason in codes(result)
    assert result.hops == ()
    assert result.candidate_route_ids == ("a", "b")


def test_equal_preferences_preserve_all_candidates_without_ecmp_hash() -> None:
    revision = make_rib_revision(
        (make_route("b", next_hop="192.0.2.2"), make_route("a", next_hop="192.0.2.1"))
    )
    result = select_route(revision, make_query())
    assert result.status == "equal_cost"
    assert result.candidate_route_ids == ("a", "b")
    assert tuple(hop.next_hop for hop in result.hops) == ("192.0.2.1", "192.0.2.2")
    assert analyze_reachability(revision, make_query()).status == "unknown"


def test_duplicate_next_hops_stay_equal_records_not_proven_paths() -> None:
    result = select_route(make_rib_revision((make_route("a"), make_route("b"))), make_query())
    assert result.status == "equal_cost"
    assert any("ECMP" in limit for limit in result.evidence.limitations)


def test_competitor_with_other_kind_has_no_comparable_metric() -> None:
    result = select_route(
        make_rib_revision((make_route("a", route_kind="connected"), make_route("b"))), make_query()
    )
    assert result.status == "unknown"
    assert "metric_not_comparable" in codes(result)


@pytest.mark.parametrize("kind", ["dynamic", "unknown"])
def test_unsupported_longer_prefix_cannot_fall_back_to_default(kind: str) -> None:
    result = select_route(
        make_rib_revision(
            (make_route(), make_route("specific", "198.51.100.0/24", route_kind=kind))
        ),
        make_query(),
    )
    assert result.status == "unknown"
    assert result.candidate_route_ids == ("specific",)
    assert "route_kind_unsupported" in codes(result)


def test_dynamic_less_specific_route_does_not_overrule_lpm() -> None:
    result = select_route(
        make_rib_revision(
            (make_route(route_kind="dynamic"), make_route("specific", "198.51.100.0/24"))
        ),
        make_query(),
    )
    assert result.status == "selected"
    assert result.candidate_route_ids == ("specific",)


def test_ad_255_never_becomes_usable_route() -> None:
    result = select_route(
        make_rib_revision((make_route(administrative_distance=255),)), make_query()
    )
    assert result.status == "unknown"
    assert "route_priority_unsupported" in codes(result)


@pytest.mark.parametrize("kind,distance", [("dynamic", 100), ("unknown", 100), ("static", 255)])
def test_proven_losing_distance_does_not_block_supported_winner(kind: str, distance: int) -> None:
    result = select_route(
        make_rib_revision(
            (
                make_route("winner"),
                make_route("loser", route_kind=kind, administrative_distance=distance),
            )
        ),
        make_query(),
    )
    assert result.status == "selected"
    assert result.candidate_route_ids == ("winner",)
    assert len(result.evidence.facts["matched_routes"]) == 2


def test_missing_priority_and_unsupported_kind_preserve_both_reasons() -> None:
    result = select_route(
        make_rib_revision(
            (make_route("a"), make_route("b", route_kind="dynamic", administrative_distance=None))
        ),
        make_query(),
    )
    assert result.status == "unknown"
    assert {"distance_missing", "route_kind_unsupported"} <= codes(result)


def test_blackhole_has_discard_hop_not_global_blocked() -> None:
    revision = make_rib_revision(
        (
            make_route("discard", "198.51.100.0/24", is_blackhole=True, outgoing_interface_id=None),
            make_route(),
        )
    )
    result = select_route(revision, make_query())
    assert result.status == "blackhole"
    assert result.hops[0].disposition == "discard"
    assert result.hops[0].outgoing_interface_id is None
    assert analyze_reachability(revision, make_query()).status == "unknown"


@pytest.mark.parametrize("all_discard", [False, True])
def test_equal_discard_preferences_do_not_choose_first(all_discard: bool) -> None:
    revision = make_rib_revision(
        (
            make_route("a", is_blackhole=True, outgoing_interface_id=None),
            make_route(
                "b",
                is_blackhole=all_discard,
                outgoing_interface_id=None if all_discard else "interface:inside",
            ),
        )
    )
    result = select_route(revision, make_query())
    assert result.status == "unknown"
    assert "discard_tie" in codes(result)
    assert result.hops == ()


@pytest.mark.parametrize("status", [DataStatus.KNOWN, DataStatus.ABSENT])
def test_proven_empty_rib_is_no_route_with_collection_evidence(status: DataStatus) -> None:
    revision = make_rib_revision((), status=status)
    result = select_route(revision, make_query())
    assert result.status == "no_route"
    assert result.evidence.facts["collection_evidence"]["complete"] is True
    assert result.sources[1].content_sha256
    assert analyze_reachability(revision, make_query()).status == "unknown"


def test_full_rib_with_no_match_is_no_route() -> None:
    result = select_route(
        make_rib_revision((make_route(destination="203.0.113.0/24"),)), make_query()
    )
    assert result.status == "no_route"
    assert result.matched_route_ids == ()


@pytest.mark.parametrize("has_match", [False, True])
def test_partial_rib_cannot_select_or_prove_no_route(has_match: bool) -> None:
    result = select_route(
        make_rib_revision(
            (make_route(),) if has_match else (), complete=False, status=DataStatus.UNKNOWN
        ),
        make_query(),
    )
    assert result.status == "not_enough_evidence"
    assert "rib_incomplete" in codes(result)
    assert result.hops == ()


def test_complete_evidence_with_unknown_status_is_not_a_known_rib() -> None:
    result = select_route(make_rib_revision(status=DataStatus.UNKNOWN), make_query())
    assert result.status == "not_enough_evidence"
    assert "rib_status_unresolved" in codes(result)


@pytest.mark.parametrize("empty", [False, True])
def test_configured_routes_never_substitute_for_rib(empty: bool) -> None:
    result = select_route(make_revision(routes=() if empty else None), make_query())
    assert result.status == "not_enough_evidence"
    assert "rib_missing" in codes(result)


def test_mixed_missing_and_unsupported_reasons_are_retained() -> None:
    result = select_route(
        make_rib_revision(status=DataStatus.UNSUPPORTED, complete=False), make_query()
    )
    assert result.status == "unknown"
    assert {"rib_incomplete", "rib_status_unresolved"} <= codes(result)


@pytest.mark.parametrize(
    "changes",
    [
        {"route_kind": "dynamic"},
        {"route_kind": "unknown"},
        {"data_status": DataStatus.UNSUPPORTED},
    ],
)
def test_partial_table_does_not_hide_unsupported_matching_facts(changes: dict) -> None:
    result = select_route(
        make_rib_revision(
            (make_route(**changes),),
            complete=False,
            status=DataStatus.UNKNOWN,
        ),
        make_query(),
    )
    assert result.status == "unknown"
    assert {"rib_incomplete", "route_kind_unsupported"} <= codes(result)


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"revision_id": UUID("10000000-0000-0000-0000-000000000099")}, "revision_mismatch"),
        ({"device_id": "another"}, "revision_mismatch"),
        ({"device_context": "another"}, "context_mismatch"),
        ({"ingress_interface_id": "another"}, "ingress_missing"),
        ({"table_id": "management"}, "table_scope_unsupported"),
        (
            {"source_ip": "2001:db8::1", "destination_ip": "2001:db8::2"},
            "address_family_unsupported",
        ),
    ],
)
def test_query_scope_mismatch_never_selects(changes: dict, code: str) -> None:
    result = select_route(make_rib_revision(), make_query(**changes))
    assert result.status == "unknown"
    assert code in codes(result)
    assert result.hops == ()


def test_other_table_in_revision_cannot_prove_default_completeness() -> None:
    result = select_route(make_rib_revision((make_route(table_id="management"),)), make_query())
    assert result.status == "unknown"
    assert "table_scope_unsupported" in codes(result)


def test_ipv6_rib_cannot_prove_no_route_in_ipv4() -> None:
    result = select_route(make_rib_revision((make_route(destination="::/0"),)), make_query())
    assert result.status == "unknown"
    assert "rib_family_unsupported" in codes(result)


def test_unresolved_interfaces_cannot_lend_unverified_observation_to_ingress() -> None:
    payload = make_rib_revision().model_dump(mode="python")
    payload["interfaces_status"] = DataStatus.UNKNOWN
    result = select_route(DeviceRevision.model_validate(payload), make_query())
    assert result.status == "not_enough_evidence"
    assert "interfaces_unresolved" in codes(result)


def test_missing_unknown_ingress_is_missing_evidence() -> None:
    payload = make_rib_revision().model_dump(mode="python")
    payload["interfaces_status"] = DataStatus.UNKNOWN
    result = select_route(
        DeviceRevision.model_validate(payload), make_query(ingress_interface_id="missing")
    )
    assert result.status == "not_enough_evidence"


def test_missing_observation_is_not_inferred_from_file_or_capture_time() -> None:
    payload = make_rib_revision().model_dump(mode="python")
    payload["observed_at"] = None
    for field in (
        "routes_status",
        "interfaces_status",
        "network_segments_status",
        "topology_status",
    ):
        payload[field] = DataStatus.UNKNOWN
    result = select_route(DeviceRevision.model_validate(payload), make_query())
    assert "observation_missing" in codes(result)
    assert result.status == "not_enough_evidence"


@pytest.mark.parametrize("enabled", [None, False])
def test_selected_rib_does_not_imply_enabled_interface(enabled: bool | None) -> None:
    payload = make_rib_revision().model_dump(mode="python")
    payload["interfaces"][0]["enabled"] = enabled
    result = analyze_reachability(DeviceRevision.model_validate(payload), make_query())
    assert result.route_selection.status == "selected"
    assert result.status == "unknown"
    assert result.route_selection.evidence.facts["ingress_interface"]["enabled"] is enabled


def test_recursive_next_hop_without_interface_is_not_fabricated() -> None:
    revision = make_rib_revision((make_route(next_hop="192.0.2.1", outgoing_interface_id=None),))
    result = select_route(revision, make_query())
    assert result.status == "selected"
    assert result.hops[0].outgoing_interface_id is None
    assert analyze_reachability(revision, make_query()).status == "unknown"


def test_device_local_destination_is_not_forwarded_using_default() -> None:
    result = select_route(make_rib_revision(), make_query(destination_ip="10.0.0.1"))
    assert result.status == "unknown"
    assert "local_delivery_unsupported" in codes(result)


def test_route_order_does_not_change_serialized_decision_or_source_hash() -> None:
    routes = (make_route("a"), make_route("b", metric=10), make_route("c", "198.51.100.0/24"))
    results = [
        select_route(make_rib_revision(order), make_query()).model_dump(mode="json")
        for order in permutations(routes)
    ]
    assert all(result == results[0] for result in results)


def test_input_snapshot_does_not_change() -> None:
    revision, query = make_rib_revision(), make_query()
    before = revision.model_dump_json(), query.model_dump_json()
    select_route(revision, query)
    assert before == (revision.model_dump_json(), query.model_dump_json())


def test_unvalidated_copy_cannot_bypass_revision_integrity() -> None:
    revision = make_rib_revision().model_copy(
        update={"routes_status": DataStatus.KNOWN, "routes_evidence": None}
    )
    with pytest.raises(ValidationError):
        select_route(revision, make_query())


def test_unvalidated_query_copy_cannot_bypass_port_validation() -> None:
    with pytest.raises(ValidationError):
        select_route(
            make_rib_revision(), make_query().model_copy(update={"destination_port": None})
        )


def test_manual_rib_retains_manual_basis_without_fake_source_mapping() -> None:
    payload = make_revision().model_dump(mode="python")
    payload["routes"] = (
        Route(
            route_id="manual",
            device_id="fixture-device",
            origin=DataOrigin.MANUAL,
            destination="0.0.0.0/0",
            outgoing_interface_id="interface:inside",
            route_kind="static",
            manual_reason="Собственный synthetic сценарий ручной фиксации RIB.",
            recorded_at=OBSERVED_AT,
            observation=OBSERVATION,
        ),
    )
    payload["routes_evidence"] = CollectionEvidence(
        scope="routing_table",
        complete=True,
        manual_reason="Полная synthetic IPv4 таблица default.",
        recorded_at=OBSERVED_AT,
        observation=OBSERVATION,
    )
    result = select_route(DeviceRevision.model_validate(payload), make_query())
    assert result.status == "selected"
    assert result.hops[0].evidence.source_locations == ()
    assert result.hops[0].evidence.facts["manual_reason"]
    assert result.evidence.facts["collection_evidence"]["observation"]["method"] == "synthetic"
