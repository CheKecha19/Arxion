"""Эталоны импорта authored документов не являются аппаратными захватами."""

from pathlib import Path

import pytest
from tests.golden.assertions import assert_matches_golden
from tests.network_import_fixtures import import_scenario

NETWORK_SCENARIOS = ("complete", "configured_only", "unsupported")


@pytest.mark.parametrize("scenario", NETWORK_SCENARIOS)
def test_network_import_golden(scenario: str) -> None:
    assert_matches_golden(
        import_scenario(scenario),
        Path(__file__).parent / "expected" / f"network_import_{scenario}.json",
    )
