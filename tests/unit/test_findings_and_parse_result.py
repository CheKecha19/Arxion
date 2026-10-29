"""Проверки findings, evidence и результата парсинга."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from firewall_compliance.domain import (
    Configuration,
    Evidence,
    Finding,
    FindingCategory,
    ParseCoverage,
    ParseResult,
    Severity,
    SourceLocation,
)


def make_configuration() -> Configuration:
    """Создать валидный снимок для тестов результатов."""
    timestamp = datetime(2026, 10, 9, tzinfo=UTC)
    return Configuration(
        source_name="edge.json",
        device_id="edge-01",
        vendor="usergate",
        platform="ngfw",
        parser_version="0.1.0",
        content_sha256="b" * 64,
        captured_at=timestamp,
        imported_at=timestamp,
    )


def test_finding_rejects_reversed_lifecycle_timestamps() -> None:
    """Последнее обнаружение не может предшествовать первому."""
    configuration = make_configuration()
    timestamp = datetime(2026, 10, 9, tzinfo=UTC)
    with pytest.raises(ValidationError, match="last_seen"):
        Finding(
            check_id="SEC-001",
            category=FindingCategory.SECURITY,
            severity=Severity.HIGH,
            title="Открытый SSH",
            description="SSH доступен из недоверенной сети.",
            configuration_id=configuration.configuration_id,
            device_id="edge-01",
            evidence=Evidence(summary="Правило разрешает TCP/22."),
            recommendation="Ограничить источник.",
            confidence=0.9,
            first_seen=timestamp,
            last_seen=timestamp - timedelta(seconds=1),
        )


def test_parse_coverage_rejects_inconsistent_counts() -> None:
    """Покрытие не может содержать больше результатов, чем конструкций."""
    with pytest.raises(ValidationError, match="превышают"):
        ParseCoverage(discovered_constructs=2, recognized_constructs=2, unsupported_constructs=1)


def test_parse_result_serializes_with_coverage() -> None:
    """Пустой корректный результат парсинга сериализуется в JSON."""
    configuration = make_configuration()
    result = ParseResult(
        configuration=configuration,
        coverage=ParseCoverage(
            discovered_constructs=10,
            recognized_constructs=8,
            unsupported_constructs=2,
        ),
        source_map={"device": SourceLocation(source_name="edge.json", object_path="$.device")},
    )

    restored = ParseResult.model_validate_json(result.model_dump_json())

    assert restored.coverage.coverage_ratio == 0.8
    assert restored.configuration.configuration_id == configuration.configuration_id
