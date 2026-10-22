"""Эталоны локальной цепочки, не аппаратного packet-processing и не достижимости."""

from pathlib import Path

import pytest
from tests.forwarding_policy_scenarios import POLICY_SCENARIOS, policy_scenario
from tests.golden.assertions import assert_matches_golden


@pytest.mark.parametrize("scenario", POLICY_SCENARIOS)
def test_forwarding_policy_golden(scenario: str) -> None:
    assert_matches_golden(
        policy_scenario(scenario),
        Path(__file__).parent / "expected" / f"forwarding_policy_{scenario}.json",
    )
