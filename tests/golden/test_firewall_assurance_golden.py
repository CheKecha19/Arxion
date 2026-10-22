"""Эталонный результат каталога Firewall Assurance."""

from pathlib import Path

from tests.golden.assertions import assert_matches_golden
from tests.integration.test_firewall_assurance import FIXTURES, analyze_fixture


def test_firewall_assurance_matches_golden() -> None:
    assert_matches_golden(
        analyze_fixture(), Path(__file__).parent / "expected" / "firewall_assurance.json"
    )


def test_incomplete_firewall_assurance_matches_golden() -> None:
    content = (
        FIXTURES / "policy_quality.cfg"
    ).read_bytes() + b"access-list AUDIT extended permit tcp any any eq 443 time-range WORK\n"
    assert_matches_golden(
        analyze_fixture(content),
        Path(__file__).parent / "expected" / "firewall_assurance_incomplete.json",
    )
