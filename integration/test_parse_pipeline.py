"""Сквозная проверка нейтрального конвейера парсинга."""

from tests.fakes import FixtureParser, make_fixture_request

from firewall_compliance.domain import ParseResult
from firewall_compliance.parsers import ParserRegistry


def test_source_document_registry_parser_and_outcome_pipeline() -> None:
    """SourceDocument проходит registry и создаёт нормализованный ParseResult."""
    request = make_fixture_request()

    outcome = ParserRegistry([FixtureParser()]).parse(request)

    assert isinstance(outcome, ParseResult)
    assert outcome.configuration.content_sha256 == request.source.content_sha256
    assert outcome.rules[0].action == "drop"
