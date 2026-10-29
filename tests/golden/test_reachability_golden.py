"""Эталоны первого сетевого среза не расширяют статус поддержки ASA."""

from pathlib import Path

import pytest
from tests.golden.assertions import assert_matches_golden
from tests.reachability_fixtures import make_query, make_rib_revision, make_route

from firewall_compliance.analysis import analyze_reachability
from firewall_compliance.domain import DataStatus, ReachabilityResult

SCENARIOS = ("selected", "equal_cost", "blackhole", "no_route", "incomplete")


def analyze_scenario(scenario: str) -> ReachabilityResult:
    routes = {
        "selected": (make_route(), make_route("specific", "198.51.100.0/24")),
        "equal_cost": (
            make_route("a", next_hop="192.0.2.1"),
            make_route("b", next_hop="192.0.2.2"),
        ),
        "blackhole": (make_route(is_blackhole=True, outgoing_interface_id=None),),
        "no_route": (),
        "incomplete": (make_route(),),
    }[scenario]
    return analyze_reachability(
        make_rib_revision(
            routes,
            complete=scenario != "incomplete",
            status=DataStatus.UNKNOWN if scenario == "incomplete" else DataStatus.KNOWN,
        ),
        make_query(),
    )


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_reachability_golden(scenario: str) -> None:
    assert_matches_golden(
        analyze_scenario(scenario),
        Path(__file__).parent / "expected" / f"reachability_{scenario}.json",
    )
