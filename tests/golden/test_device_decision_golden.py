"""Эталоны одной ACL не доказывают итоговую достижимость."""

from pathlib import Path

import pytest
from tests.device_decision_fixtures import DEVICE_SCENARIOS, device_scenario
from tests.golden.assertions import assert_matches_golden


@pytest.mark.parametrize("scenario", DEVICE_SCENARIOS)
def test_device_decision_golden(scenario: str) -> None:
    assert_matches_golden(
        device_scenario(scenario),
        Path(__file__).parent / "expected" / f"device_decision_{scenario}.json",
    )
