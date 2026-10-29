"""Golden-проверки ограниченного результата Cisco ASA parser adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.golden.assertions import assert_matches_golden

from firewall_compliance.domain import ParseResult
from firewall_compliance.parsers import CiscoAsaParser, ParseRequest, ParserRegistry, SourceDocument

FIXTURES_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "candidates" / "cisco-asa"
EXPECTED_DIRECTORY = Path(__file__).parent / "expected"
CAPTURED_AT = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
IMPORTED_AT = datetime(2026, 10, 9, 12, 1, tzinfo=UTC)


def parse_fixture(name: str) -> ParseResult:
    """Получить детерминированный результат Cisco ASA для golden-проверки."""
    path = FIXTURES_DIRECTORY / name
    outcome = ParserRegistry([CiscoAsaParser()]).parse(
        ParseRequest(
            source=SourceDocument(
                source_name=name,
                content=path.read_bytes(),
                captured_at=CAPTURED_AT,
            ),
            imported_at=IMPORTED_AT,
        )
    )
    assert isinstance(outcome, ParseResult)
    return outcome


@pytest.mark.parametrize(
    ("fixture_name", "golden_name"),
    [
        ("asa_basic_access.cfg", "cisco_asa_basic_access.json"),
        ("asa_objects_and_groups.cfg", "cisco_asa_objects_and_groups.json"),
        ("asa_nat_unsupported.cfg", "cisco_asa_nat_unsupported.json"),
    ],
)
def test_cisco_asa_parse_result_matches_golden_file(fixture_name: str, golden_name: str) -> None:
    """Поддерживаемые сценарии не меняют нормализованный результат неявно."""
    assert_matches_golden(parse_fixture(fixture_name), EXPECTED_DIRECTORY / golden_name)
