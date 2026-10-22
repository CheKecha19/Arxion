"""Эталоны разбора контекста не являются эталонами достижимости."""

from pathlib import Path

import pytest
from tests.asa_forwarding_fixtures import SCENARIOS, forwarding_request
from tests.golden.assertions import assert_matches_golden

from firewall_compliance.parsers.cisco_asa_forwarding import CiscoAsaForwardingParser
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseResult


def parse_forwarding_scenario(scenario: str) -> ForwardingParseResult:
    outcome = CiscoAsaForwardingParser().parse(forwarding_request(scenario))
    assert isinstance(outcome, ForwardingParseResult)
    return outcome


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_forwarding_parse_golden(scenario: str) -> None:
    assert_matches_golden(
        parse_forwarding_scenario(scenario),
        Path(__file__).parent / "expected" / f"asa_forwarding_{scenario}.json",
    )
