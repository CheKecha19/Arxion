"""Golden-проверки стабильного формата ParseResult."""

from pathlib import Path

from tests.fakes import FixtureParser, make_fixture_request
from tests.golden.assertions import assert_matches_golden

from firewall_compliance.domain import ParseResult


def test_neutral_parse_result_matches_golden_file() -> None:
    """Нейтральный parser adapter создаёт ожидаемый JSON без автозаписи эталона."""
    outcome = FixtureParser().parse(make_fixture_request())

    assert isinstance(outcome, ParseResult)
    golden_path = Path(__file__).parent / "expected" / "neutral_parse_result.json"
    assert_matches_golden(outcome, golden_path)
