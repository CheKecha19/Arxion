"""Контрактные тесты независимых от производителя parser adapters."""

import pytest
from tests.fakes import FixtureParser, make_fixture_request

from firewall_compliance.domain import DataStatus, ParseResult, RuleAction
from firewall_compliance.parsers import (
    AmbiguousParserError,
    DetectionResult,
    ParserMetadata,
    ParserRegistry,
    SourceDocument,
)


def test_detection_does_not_change_source_document() -> None:
    """Detection работает только на чтение и не меняет входной документ."""
    request = make_fixture_request()
    parser = FixtureParser()
    original_hash = request.source.content_sha256
    original_content = request.source.content

    result = parser.detect(request.source)

    assert result.is_match is True
    assert request.source.content_sha256 == original_hash
    assert request.source.content == original_content


def test_successful_parse_preserves_source_mapping_and_data_status() -> None:
    """Успешный parse возвращает трассируемое правило без маскировки статуса."""
    request = make_fixture_request()
    outcome = FixtureParser().parse(request)

    assert isinstance(outcome, ParseResult)
    rule = outcome.rules[0]
    assert outcome.source_map[rule.rule_id] == rule.source_location
    assert rule.source_status is DataStatus.UNSUPPORTED
    assert rule.zone_status is DataStatus.UNKNOWN
    assert rule.action is RuleAction.DROP


def test_registry_returns_failure_when_no_parser_matches() -> None:
    """Нераспознанный формат возвращает ParseFailure, а не исключение."""
    outcome = ParserRegistry([FixtureParser()]).parse(make_fixture_request(b"unknown"))

    assert outcome.parser_id == "registry"
    assert outcome.errors[0].code == "PARSER_NOT_FOUND"


class EquallyConfidentParser(FixtureParser):
    """Тестовый парсер с тем же уровнем уверенности для проверки неоднозначности."""

    @property
    def metadata(self) -> ParserMetadata:
        """Вернуть отличающийся идентификатор."""
        return ParserMetadata(parser_id="second-fixture", version="1.0.0", vendor="test")

    def detect(self, source: SourceDocument) -> DetectionResult:
        """Вернуть такой же положительный результат detection."""
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=True,
            confidence=1.0,
            reasons=("Тестовая неоднозначность.",),
        )


def test_registry_rejects_ambiguous_best_match() -> None:
    """Registry не должен угадывать выбор при равной уверенности."""
    registry = ParserRegistry([FixtureParser(), EquallyConfidentParser()])

    with pytest.raises(AmbiguousParserError):
        registry.select(make_fixture_request().source)
