"""Детерминированные адаптеры для contract, golden и integration tests."""

from datetime import UTC, datetime
from uuid import UUID

from firewall_compliance.domain import (
    Configuration,
    DataStatus,
    Endpoint,
    EndpointKind,
    ParseCoverage,
    ParseResult,
    Protocol,
    Rule,
    RuleAction,
    Service,
    SourceLocation,
)
from firewall_compliance.parsers import (
    DetectionResult,
    ParseOutcome,
    ParseRequest,
    ParserMetadata,
    SourceDocument,
)

FIXED_CAPTURED_AT = datetime(2026, 10, 9, 10, 0, tzinfo=UTC)
FIXED_IMPORTED_AT = datetime(2026, 10, 9, 10, 1, tzinfo=UTC)
FIXED_CONFIGURATION_ID = UUID("00000000-0000-0000-0000-000000000001")


class FixtureParser:
    """Нейтральный детерминированный адаптер без вендорской логики."""

    @property
    def metadata(self) -> ParserMetadata:
        """Вернуть идентичность тестового парсера."""
        return ParserMetadata(parser_id="fixture", version="1.0.0", vendor="test")

    def detect(self, source: SourceDocument) -> DetectionResult:
        """Распознать только заранее определённый тестовый документ."""
        is_match = source.content == b"fixture"
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=is_match,
            confidence=1.0 if is_match else 0.0,
            reasons=("Совпадение с нейтральным тестовым документом.",) if is_match else (),
        )

    def parse(self, request: ParseRequest) -> ParseOutcome:
        """Вернуть стабильный ParseResult для тестов контракта."""
        configuration = Configuration(
            configuration_id=FIXED_CONFIGURATION_ID,
            source_name=request.source.source_name,
            device_id="fixture-device",
            vendor=self.metadata.vendor,
            platform="fixture-platform",
            parser_version=self.metadata.version,
            content_sha256=request.source.content_sha256,
            captured_at=request.source.captured_at,
            imported_at=request.imported_at,
        )
        destination = Endpoint(endpoint_id="any", name="any", kind=EndpointKind.ANY)
        service = Service(service_id="ip", name="ip", protocol=Protocol.IP)
        source_location = SourceLocation(
            source_name=request.source.source_name, object_path="$.rules[0]"
        )
        rule = Rule(
            rule_id="fixture-rule-1",
            configuration_id=configuration.configuration_id,
            name="Блокирующее тестовое правило",
            sequence=1,
            action=RuleAction.DROP,
            enabled=True,
            destinations=(destination,),
            services=(service,),
            source_location=source_location,
            source_status=DataStatus.UNSUPPORTED,
        )
        return ParseResult(
            configuration=configuration,
            rules=(rule,),
            endpoints=(destination,),
            services=(service,),
            source_map={rule.rule_id: source_location},
            coverage=ParseCoverage(
                discovered_constructs=3,
                recognized_constructs=2,
                unsupported_constructs=1,
            ),
        )


def make_fixture_request(content: bytes = b"fixture") -> ParseRequest:
    """Создать воспроизводимый запрос к нейтральному тестовому парсеру."""
    return ParseRequest(
        source=SourceDocument(
            source_name="fixture.config",
            content=content,
            captured_at=FIXED_CAPTURED_AT,
        ),
        imported_at=FIXED_IMPORTED_AT,
    )
