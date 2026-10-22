"""Контракты запроса и неизменяемых результатов без запуска сетевого движка."""

from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.revision_fixtures import REVISION_ID, make_revision

from firewall_compliance.domain.enums import Protocol
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.reachability import (
    AnalysisReason,
    PathHop,
    ReachabilityQuery,
    ReachabilityResult,
    RouteSelectionResult,
    RouteSelectionStatus,
)
from firewall_compliance.domain.source import SourceLocation


def _make_query(**changes: Any) -> ReachabilityQuery:
    return ReachabilityQuery(
        **(
            {
                "revision_id": REVISION_ID,
                "device_id": "fixture-device",
                "ingress_interface_id": "interface:inside",
                "source_ip": "10.0.0.10",
                "destination_ip": "192.0.2.20",
                "protocol": Protocol.TCP,
                "destination_port": 443,
            }
            | changes
        )
    )


def _make_evidence() -> Evidence:
    return Evidence(
        summary="Основание выбора маршрута.",
        source_locations=(SourceLocation(source_name="fixture.config", object_path="$.routes"),),
        facts={"routes": [{"route_id": "route:default", "metrics": [1, 10]}]},
    )


def _make_hop(**changes: Any) -> PathHop:
    return PathHop(
        **(
            {
                "device_id": "fixture-device",
                "revision_id": REVISION_ID,
                "table_id": "default",
                "route_id": "route:default",
                "destination": "0.0.0.0/0",
                "outgoing_interface_id": (
                    None if changes.get("disposition") == "discard" else "interface:inside"
                ),
                "disposition": "forward_candidate",
                "evidence": _make_evidence(),
            }
            | changes
        )
    )


def _make_reason() -> AnalysisReason:
    return AnalysisReason(
        code="policy_pending",
        category="pending",
        message="Проверка политики ещё не выполнена.",
        related_route_ids=("route:default",),
    )


def _make_selection(
    status: RouteSelectionStatus = "selected", **changes: Any
) -> RouteSelectionResult:
    candidates = ("route:default",)
    hops = (_make_hop(),)
    reasons: tuple[AnalysisReason, ...] = ()
    if status == "blackhole":
        hops = (_make_hop(disposition="discard", outgoing_interface_id=None),)
    elif status == "equal_cost":
        candidates += ("route:alternative",)
        hops += (_make_hop(route_id="route:alternative"),)
    elif status in {"unknown", "not_enough_evidence", "no_route"}:
        candidates = ()
        hops = ()
        if status != "no_route":
            reasons = (_make_reason(),)
    return RouteSelectionResult(
        **(
            {
                "query": _make_query(),
                "status": status,
                "matched_route_ids": candidates,
                "candidate_route_ids": candidates,
                "hops": hops,
                "reasons": reasons,
                "sources": make_revision().sources,
                "revision_schema_version": "0.1.0",
                "application_version": "0.1.0a0",
                "evidence": _make_evidence(),
            }
            | changes
        )
    )


@pytest.mark.parametrize("protocol", [Protocol.TCP, Protocol.UDP])
@pytest.mark.parametrize("port", [1, 443, 65535])
def test_query_accepts_transport_port_bounds(protocol: Protocol, port: int) -> None:
    query = _make_query(protocol=protocol, destination_port=port)
    assert query.protocol == protocol
    assert query.destination_port == port


@pytest.mark.parametrize("protocol", [Protocol.TCP, Protocol.UDP])
@pytest.mark.parametrize("port", [None, 0, -1, 65536, "443", 443.0, True, False])
def test_query_requires_strict_transport_port(protocol: Protocol, port: Any) -> None:
    with pytest.raises(ValidationError):
        _make_query(protocol=protocol, destination_port=port)


@pytest.mark.parametrize("protocol", [Protocol.TCP, Protocol.UDP])
def test_query_rejects_omitted_transport_port(protocol: Protocol) -> None:
    payload = _make_query().model_dump()
    payload["protocol"] = protocol
    del payload["destination_port"]
    with pytest.raises(ValidationError, match="destination_port"):
        ReachabilityQuery.model_validate(payload)


def test_query_accepts_icmp_without_port() -> None:
    payload = _make_query().model_dump()
    payload["protocol"] = Protocol.ICMP
    del payload["destination_port"]
    assert ReachabilityQuery.model_validate(payload).destination_port is None
    assert _make_query(protocol=Protocol.ICMP, destination_port=None).destination_port is None


@pytest.mark.parametrize("port", [1, 443, 65535])
def test_query_rejects_icmp_port(port: int) -> None:
    with pytest.raises(ValidationError, match="ICMP"):
        _make_query(protocol=Protocol.ICMP, destination_port=port)


@pytest.mark.parametrize("protocol", [Protocol.IP, Protocol.OTHER, "gre", "TCP"])
def test_query_rejects_unsupported_protocol(protocol: Any) -> None:
    with pytest.raises(ValidationError):
        _make_query(protocol=protocol)


@pytest.mark.parametrize("field", ["source_ip", "destination_ip"])
def test_query_rejects_mixed_address_families(field: str) -> None:
    with pytest.raises(ValidationError, match="семейство IP"):
        _make_query(**{field: "2001:db8::1"})


@pytest.mark.parametrize("field", ["source_ip", "destination_ip"])
@pytest.mark.parametrize(
    "address",
    [
        "",
        "not-an-ip",
        "999.0.0.1",
        "10.0.0.1/24",
        "2001:db8::1/64",
        "224.0.0.1",
        "239.255.255.255",
        "ff02::1",
        "0.0.0.0",
        "::",
        "fe80::1%eth0",
        "fe80::1%1",
        "255.255.255.255",
    ],
)
def test_query_rejects_invalid_or_non_unicast_address(field: str, address: str) -> None:
    peer = "2001:db8::2" if ":" in address else "192.0.2.2"
    payload = {"source_ip": peer, "destination_ip": peer, field: address}
    with pytest.raises(ValidationError) as exc:
        _make_query(**payload)
    assert any(error["loc"] == (field,) for error in exc.value.errors())


def test_query_normalizes_ipv6() -> None:
    query = _make_query(
        source_ip="2001:0DB8:0000:0000:0000:0000:0000:0001",
        destination_ip="2001:0DB8:0000:0000:0000:0000:0000:0002",
    )
    assert query.source_ip == "2001:db8::1"
    assert query.destination_ip == "2001:db8::2"


@pytest.mark.parametrize(
    "field", ["device_id", "device_context", "ingress_interface_id", "table_id"]
)
@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_query_rejects_empty_identifiers(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc:
        _make_query(**{field: value})
    assert exc.value.errors()[0]["loc"] == (field,)


def test_query_defaults_and_explicit_context() -> None:
    query = _make_query()
    assert query.device_context is None
    assert query.table_id == "default"
    contextual = _make_query(device_context=" tenant-a ", table_id=" vrf-a ")
    assert contextual.device_context == "tenant-a"
    assert contextual.table_id == "vrf-a"


@pytest.mark.parametrize("operation", ["assign", "delete"])
def test_query_is_immutable(operation: str) -> None:
    query = _make_query()
    with pytest.raises(ValidationError) as exc:
        if operation == "assign":
            query.destination_port = 80
        else:
            del query.destination_port
    assert exc.value.errors()[0]["type"] == "frozen_instance"
    assert query.destination_port == 443


@pytest.mark.parametrize(
    "status", ["selected", "equal_cost", "blackhole", "no_route", "unknown", "not_enough_evidence"]
)
def test_selection_accepts_consistent_status(status: RouteSelectionStatus) -> None:
    result = _make_selection(status)
    assert result.status == status
    assert result.query.revision_id == REVISION_ID
    assert result.sources == make_revision().sources


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("device_id", "another-device"),
        ("revision_id", UUID("10000000-0000-0000-0000-000000000002")),
        ("table_id", "another-table"),
    ],
)
def test_selection_rejects_wrong_hop_context(field: str, value: Any) -> None:
    with pytest.raises(ValidationError, match="контексту запроса"):
        _make_selection(hops=(_make_hop(**{field: value}),))


@pytest.mark.parametrize("field", ["matched_route_ids", "candidate_route_ids"])
def test_selection_rejects_duplicate_route_ids(field: str) -> None:
    with pytest.raises(ValidationError, match="повторяться"):
        _make_selection(**{field: ("route:default", "route:default")})


def test_selection_rejects_candidate_outside_matched_routes() -> None:
    with pytest.raises(ValidationError, match="совпавшие маршруты"):
        _make_selection(matched_route_ids=("route:another",))


@pytest.mark.parametrize(
    "changes",
    [
        {"matched_route_ids": ("route:default",)},
        {"matched_route_ids": ("route:default",), "candidate_route_ids": ("route:default",)},
    ],
)
def test_selection_rejects_no_route_with_routes(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="no_route"):
        _make_selection("no_route", **changes)


@pytest.mark.parametrize("status", ["unknown", "not_enough_evidence"])
def test_selection_requires_uncertainty_reasons(status: RouteSelectionStatus) -> None:
    with pytest.raises(ValidationError, match="требует причины"):
        _make_selection(status, reasons=())


@pytest.mark.parametrize("status", ["no_route", "unknown", "not_enough_evidence"])
def test_selection_rejects_unresolved_hops(status: RouteSelectionStatus) -> None:
    with pytest.raises(ValidationError, match="не публикует PathHop"):
        _make_selection(status, hops=(_make_hop(),))


@pytest.mark.parametrize("status", ["selected", "blackhole", "equal_cost"])
def test_selection_requires_hop_for_every_candidate(status: RouteSelectionStatus) -> None:
    with pytest.raises(ValidationError, match="один PathHop"):
        _make_selection(status, hops=())


@pytest.mark.parametrize("status", ["selected", "blackhole", "equal_cost"])
def test_selection_rejects_resolved_empty_candidates(status: RouteSelectionStatus) -> None:
    with pytest.raises(ValidationError, match="число PathHop"):
        _make_selection(status, matched_route_ids=(), candidate_route_ids=(), hops=())


@pytest.mark.parametrize("status", ["selected", "blackhole", "equal_cost"])
def test_selection_rejects_wrong_hop_disposition(status: RouteSelectionStatus) -> None:
    disposition = "forward_candidate" if status == "blackhole" else "discard"
    hops = (_make_hop(disposition=disposition),)
    if status == "equal_cost":
        hops += (_make_hop(route_id="route:alternative", disposition="forward_candidate"),)
    with pytest.raises(ValidationError, match="действие PathHop"):
        _make_selection(status, hops=hops)


@pytest.mark.parametrize("status", ["selected", "blackhole", "equal_cost"])
def test_selection_enforces_status_hop_count(status: RouteSelectionStatus) -> None:
    ids = ("route:default",) if status == "equal_cost" else ("route:default", "route:alternative")
    disposition = "discard" if status == "blackhole" else "forward_candidate"
    hops = tuple(_make_hop(route_id=route_id, disposition=disposition) for route_id in ids)
    with pytest.raises(ValidationError, match="число PathHop"):
        _make_selection(status, matched_route_ids=ids, candidate_route_ids=ids, hops=hops)


@pytest.mark.parametrize("operation", ["wrong_id", "reverse", "duplicate", "missing"])
def test_selection_enforces_candidate_hop_correspondence(operation: str) -> None:
    hops = (_make_hop(), _make_hop(route_id="route:alternative"))
    if operation == "wrong_id":
        hops = (_make_hop(route_id="route:another"), hops[1])
    elif operation == "reverse":
        hops = hops[::-1]
    elif operation == "duplicate":
        hops = (hops[0], hops[0])
    else:
        hops = hops[:1]
    with pytest.raises(ValidationError, match="один PathHop"):
        _make_selection("equal_cost", hops=hops)


@pytest.mark.parametrize("roundtrip", [False, True])
@pytest.mark.parametrize(
    "path",
    [
        ("status",),
        ("query", "source_ip"),
        ("hops", 0, "route_id"),
        ("hops", 0, "evidence", "summary"),
        ("hops", 0, "evidence", "source_locations", 0, "source_name"),
        ("evidence", "summary"),
        ("evidence", "source_locations", 0, "source_name"),
        ("sources", 0, "source_name"),
        ("sources", 0, "observation", "reference"),
        ("reasons", 0, "message"),
    ],
)
def test_selection_nested_models_are_immutable(path: tuple[Any, ...], roundtrip: bool) -> None:
    result = _make_selection(reasons=(_make_reason(),))
    if roundtrip:
        result = RouteSelectionResult.model_validate_json(result.model_dump_json())
    value: Any = result
    for key in path[:-1]:
        value = value[key] if isinstance(key, int) else getattr(value, key)
    before = result.model_dump(mode="json")
    with pytest.raises(TypeError, match="неизменяем"):
        setattr(value, path[-1], "changed")
    assert result.model_dump(mode="json") == before


@pytest.mark.parametrize("roundtrip", [False, True])
@pytest.mark.parametrize("target", ["result", "hop"])
@pytest.mark.parametrize("operation", ["mapping", "nested_mapping", "list", "nested_list"])
def test_selection_evidence_facts_are_deeply_immutable(
    target: str, operation: str, roundtrip: bool
) -> None:
    result = _make_selection()
    if roundtrip:
        result = RouteSelectionResult.model_validate_json(result.model_dump_json())
    evidence = result.evidence if target == "result" else result.hops[0].evidence
    before = result.model_dump(mode="json")
    with pytest.raises(TypeError, match="неизменяем"):
        if operation == "mapping":
            evidence.facts["added"] = 1
        elif operation == "nested_mapping":
            evidence.facts["routes"][0]["route_id"] = "changed"
        elif operation == "list":
            evidence.facts["routes"].append({"route_id": "changed"})
        else:
            evidence.facts["routes"][0]["metrics"].append(100)
    assert result.model_dump(mode="json") == before


def test_selection_detaches_original_evidence_and_containers() -> None:
    evidence = _make_evidence()
    hop_evidence = _make_evidence()
    hop = _make_hop(evidence=hop_evidence)
    hops = [hop]
    sources = list(make_revision().sources)
    result = _make_selection(evidence=evidence, hops=hops, sources=sources)
    before = result.model_dump(mode="json")
    evidence.summary = "Изменённое основание."
    evidence.source_locations[0].source_name = "changed.config"
    evidence.facts["routes"][0]["metrics"].append(100)
    hop_evidence.facts["routes"][0]["route_id"] = "changed"
    hops.clear()
    sources.clear()
    assert result.model_dump(mode="json") == before
    assert isinstance(result.hops, tuple)
    assert isinstance(result.sources, tuple)
    assert result.evidence is not evidence
    assert result.hops[0] is not hop


@pytest.mark.parametrize(
    "status", ["selected", "equal_cost", "blackhole", "no_route", "unknown", "not_enough_evidence"]
)
def test_selection_json_roundtrip(status: RouteSelectionStatus) -> None:
    result = _make_selection(status)
    restored = RouteSelectionResult.model_validate_json(result.model_dump_json())
    assert restored.model_dump(mode="json") == result.model_dump(mode="json")
    assert restored.query == result.query
    assert restored.sources == result.sources
    assert restored.hops == result.hops


@pytest.mark.parametrize("status", ["reachable", "blocked"])
def test_reachability_rejects_final_verdict_during_pending_stage(status: str) -> None:
    with pytest.raises(ValidationError) as exc:
        ReachabilityResult(
            status=status, route_selection=_make_selection(), reasons=(_make_reason(),)
        )
    assert exc.value.errors()[0]["loc"] == ("status",)


@pytest.mark.parametrize("status", ["unknown", "not_enough_evidence"])
def test_reachability_pending_result_roundtrip_and_immutability(status: str) -> None:
    result = ReachabilityResult(
        status=status, route_selection=_make_selection(), reasons=(_make_reason(),)
    )
    assert result.direction == "forward"
    assert result.schema_version == "0.1.0"
    restored = ReachabilityResult.model_validate_json(result.model_dump_json())
    assert restored.model_dump(mode="json") == result.model_dump(mode="json")
    for candidate in (result, restored):
        with pytest.raises(TypeError, match="неизменяем"):
            candidate.status = "unknown"
        with pytest.raises(TypeError, match="неизменяем"):
            candidate.reasons[0].message = "changed"
        with pytest.raises(TypeError, match="неизменяем"):
            candidate.route_selection.hops[0].evidence.facts.clear()


def test_reachability_requires_pending_reason_and_forward_direction() -> None:
    payload = {
        "status": "unknown",
        "route_selection": _make_selection(),
        "reasons": (_make_reason(),),
    }
    with pytest.raises(ValidationError):
        ReachabilityResult(**(payload | {"reasons": ()}))
    with pytest.raises(ValidationError):
        ReachabilityResult(**(payload | {"direction": "reverse"}))


@pytest.mark.parametrize("field", ["schema_version", "engine_version"])
@pytest.mark.parametrize("version", ["0.2.0", "", None])
def test_selection_versions_are_fixed(field: str, version: Any) -> None:
    result = _make_selection()
    assert result.schema_version == "0.1.0"
    assert result.engine_version == "0.1.0"
    with pytest.raises(ValidationError) as exc:
        _make_selection(**{field: version})
    assert exc.value.errors()[0]["loc"] == (field,)


@pytest.mark.parametrize("version", ["0.2.0", "", None])
def test_reachability_schema_version_is_fixed(version: Any) -> None:
    with pytest.raises(ValidationError) as exc:
        ReachabilityResult(
            schema_version=version,
            status="unknown",
            route_selection=_make_selection(),
            reasons=(_make_reason(),),
        )
    assert exc.value.errors()[0]["loc"] == ("schema_version",)


@pytest.mark.parametrize(
    "changes",
    [
        {"destination": "198.51.100.25/24"},
        {"destination": "not-a-network"},
        {"next_hop": "2001:db8::1"},
        {"disposition": "discard", "outgoing_interface_id": "interface:inside"},
        {"disposition": "discard", "outgoing_interface_id": None, "next_hop": "192.0.2.1"},
        {"outgoing_interface_id": None},
    ],
)
def test_path_hop_rejects_inconsistent_forwarding_target(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _make_hop(**changes)


def test_standalone_path_hop_evidence_is_deeply_immutable() -> None:
    hop = _make_hop()
    with pytest.raises(TypeError, match="неизменяем"):
        hop.evidence.facts["routes"].clear()
