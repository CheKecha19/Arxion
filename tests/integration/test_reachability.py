"""Сквозной нейтральный запрос на валидированной synthetic ревизии."""

import json

import pytest
from tests.reachability_fixtures import make_query, make_rib_revision, make_route

from firewall_compliance.analysis import analyze_reachability
from firewall_compliance.domain import (
    DataStatus,
    DeviceRevision,
    ReachabilityQuery,
    ReachabilityResult,
)


@pytest.mark.parametrize(
    "scenario,expected_route_status,expected_status",
    [
        ("default", "selected", "unknown"),
        ("empty", "no_route", "unknown"),
        ("discard", "blackhole", "unknown"),
        ("equal", "equal_cost", "unknown"),
        ("partial", "not_enough_evidence", "not_enough_evidence"),
    ],
)
def test_query_revision_result_json_pipeline(
    scenario: str, expected_route_status: str, expected_status: str
) -> None:
    routes = {
        "default": (make_route(),),
        "empty": (),
        "discard": (make_route(is_blackhole=True, outgoing_interface_id=None),),
        "equal": (make_route("a"), make_route("b")),
        "partial": (make_route(),),
    }[scenario]
    revision = make_rib_revision(
        routes,
        complete=scenario != "partial",
        status=DataStatus.UNKNOWN if scenario == "partial" else DataStatus.KNOWN,
    )
    restored_revision = DeviceRevision.model_validate_json(revision.model_dump_json())
    query = ReachabilityQuery.model_validate_json(make_query().model_dump_json())
    result = analyze_reachability(restored_revision, query)
    assert result.status == expected_status
    assert result.route_selection.status == expected_route_status
    assert "forward_chain_pending" in {reason.code for reason in result.reasons}
    assert ReachabilityResult.model_validate_json(result.model_dump_json()) == result
    serialized = json.loads(result.model_dump_json())
    assert (
        serialized["route_selection"]["sources"][1]["content_sha256"]
        == revision.sources[1].content_sha256
    )
    assert serialized["route_selection"]["query"]["revision_id"] == str(revision.revision_id)
