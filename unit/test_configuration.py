"""Проверки снимка конфигурации и firewall-правила."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from firewall_compliance.domain import (
    Configuration,
    DataStatus,
    Endpoint,
    EndpointKind,
    Protocol,
    Rule,
    RuleAction,
    Service,
    SourceLocation,
)


def make_configuration() -> Configuration:
    """Создать валидный снимок для unit-тестов."""
    timestamp = datetime(2026, 10, 9, tzinfo=UTC)
    return Configuration(
        source_name="edge.json",
        device_id="edge-01",
        vendor="usergate",
        platform="ngfw",
        parser_version="0.1.0",
        content_sha256="a" * 64,
        captured_at=timestamp,
        imported_at=timestamp,
    )


def test_configuration_round_trips_as_json() -> None:
    """Снимок восстанавливается из JSON без потери идентичности."""
    configuration = make_configuration()

    restored = Configuration.model_validate_json(configuration.model_dump_json())

    assert restored == configuration


def test_configuration_rejects_naive_timestamp() -> None:
    """Временные метки без часового пояса недопустимы."""
    timestamp = datetime(2026, 10, 9)
    with pytest.raises(ValidationError, match="часовой пояс"):
        Configuration(
            source_name="edge.json",
            device_id="edge-01",
            vendor="usergate",
            platform="ngfw",
            parser_version="0.1.0",
            content_sha256="a" * 64,
            captured_at=timestamp,
            imported_at=timestamp,
        )


def test_rule_requires_values_for_known_match_fields() -> None:
    """Пустые известные источники не считаются корректным правилом."""
    configuration = make_configuration()
    destination = Endpoint(
        endpoint_id="dst",
        name="server",
        kind=EndpointKind.HOST,
        cidrs=("10.0.0.10/32",),
    )
    service = Service(service_id="https", name="https", protocol=Protocol.TCP)

    with pytest.raises(ValidationError, match="источники"):
        Rule(
            rule_id="1",
            configuration_id=configuration.configuration_id,
            name="allow-web",
            sequence=1,
            action=RuleAction.ALLOW,
            enabled=True,
            destinations=(destination,),
            services=(service,),
            source_location=SourceLocation(source_name="edge.json", object_path="$.rules[0]"),
        )


def test_rule_accepts_unknown_match_field() -> None:
    """Неизвестное поле отделяется от известного пустого значения."""
    configuration = make_configuration()
    destination = Endpoint(
        endpoint_id="dst",
        name="server",
        kind=EndpointKind.HOST,
        cidrs=("10.0.0.10/32",),
    )
    service = Service(service_id="https", name="https", protocol=Protocol.TCP)
    rule = Rule(
        rule_id="1",
        configuration_id=configuration.configuration_id,
        name="allow-web",
        sequence=1,
        action=RuleAction.ALLOW,
        enabled=True,
        destinations=(destination,),
        services=(service,),
        source_location=SourceLocation(source_name="edge.json", object_path="$.rules[0]"),
        source_status=DataStatus.UNSUPPORTED,
    )

    assert rule.source_status == DataStatus.UNSUPPORTED


def test_configuration_rejects_import_before_capture() -> None:
    """Снимок не может быть импортирован до времени его создания."""
    timestamp = datetime(2026, 10, 9, tzinfo=UTC)
    with pytest.raises(ValidationError, match="imported_at"):
        Configuration(
            source_name="edge.json",
            device_id="edge-01",
            vendor="usergate",
            platform="ngfw",
            parser_version="0.1.0",
            content_sha256="a" * 64,
            captured_at=timestamp,
            imported_at=timestamp - timedelta(seconds=1),
        )
