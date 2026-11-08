"""Регистрация и выбор адаптеров парсинга."""

from collections.abc import Iterable

from firewall_compliance.domain.enums import ParseIssueLevel
from firewall_compliance.domain.parse_result import ParseIssue
from firewall_compliance.parsers.contracts import (
    ConfigurationParser,
    DetectionResult,
    ParseFailure,
    ParseOutcome,
    ParseRequest,
    SourceDocument,
)
from firewall_compliance.parsers.platform_detection import detect_switch_platform


class ParserContractError(ValueError):
    """Нарушение обязательного контракта адаптера."""


class AmbiguousParserError(ValueError):
    """Два или более парсера имеют одинаковый максимальный результат detection."""


class ParserRegistry:
    """Выбирает единственный наиболее подходящий parser adapter."""

    def __init__(self, parsers: Iterable[ConfigurationParser]) -> None:
        parser_list = tuple(parsers)
        parser_ids = tuple(parser.metadata.parser_id for parser in parser_list)
        if len(parser_ids) != len(set(parser_ids)):
            raise ParserContractError("идентификаторы парсеров должны быть уникальными")
        self._parsers = parser_list

    def detect_all(self, source: SourceDocument) -> tuple[DetectionResult, ...]:
        """Получить результаты detection всех зарегистрированных парсеров."""
        results: list[DetectionResult] = []
        for parser in self._parsers:
            result = parser.detect(source)
            if result.parser_id != parser.metadata.parser_id:
                raise ParserContractError("parser_id результата detection не совпадает с metadata")
            results.append(result)
        return tuple(results)

    def select(self, source: SourceDocument) -> ConfigurationParser | None:
        """Выбрать один подходящий парсер либо вернуть None."""
        try:
            platform = detect_switch_platform(source.content.decode("utf-8-sig"))
        except UnicodeDecodeError:
            platform = None
        if platform is not None and platform.ambiguous:
            raise AmbiguousParserError(" ".join(platform.reasons))
        detections = self.detect_all(source)
        candidates = [
            (parser, result)
            for parser, result in zip(self._parsers, detections, strict=True)
            if result.is_match
        ]
        if not candidates:
            return None

        maximum_confidence = max(result.confidence for _, result in candidates)
        best = [parser for parser, result in candidates if result.confidence == maximum_confidence]
        if len(best) != 1:
            raise AmbiguousParserError("не удалось однозначно выбрать парсер")
        return best[0]

    def parse(self, request: ParseRequest) -> ParseOutcome:
        """Выбрать парсер и выполнить parse либо вернуть диагностический failure."""
        try:
            parser = self.select(request.source)
        except AmbiguousParserError as error:
            return ParseFailure(
                parser_id="registry",
                source_name=request.source.source_name,
                content_sha256=request.source.content_sha256,
                errors=(ParseIssue(
                    code="PLATFORM_AMBIGUOUS", level=ParseIssueLevel.ERROR,
                    message=str(error),
                ),),
            )
        if parser is None:
            return ParseFailure(
                parser_id="registry",
                source_name=request.source.source_name,
                content_sha256=request.source.content_sha256,
                errors=(
                    ParseIssue(
                        code="PARSER_NOT_FOUND",
                        level=ParseIssueLevel.ERROR,
                        message="Для входного документа не найден подходящий парсер.",
                    ),
                ),
            )
        return parser.parse(request)
