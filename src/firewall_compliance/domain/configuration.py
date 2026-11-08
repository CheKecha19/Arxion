"""Модели устройства, снимка конфигурации и firewall-правила."""

from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.enums import DataStatus, RuleAction
from firewall_compliance.domain.network import Endpoint, Service
from firewall_compliance.domain.source import SourceLocation


class Device(DomainModel):
    """Устройство, которому принадлежит конфигурация."""

    device_id: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    hostname: str | None = None
    management_ip: str | None = None
    context: str | None = None

    @field_validator("management_ip")
    @classmethod
    def normalize_management_ip(cls, value: str | None) -> str | None:
        """Проверить и нормализовать адрес управления."""
        return str(ip_address(value)) if value is not None else None


class Configuration(DomainModel):
    """Неизменяемый снимок конфигурации устройства."""

    configuration_id: UUID = Field(default_factory=uuid4)
    source_name: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    parser_version: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    captured_at: datetime
    imported_at: datetime

    @model_validator(mode="after")
    def validate_timestamps(self) -> "Configuration":
        """Проверить часовой пояс и порядок временных отметок."""
        if self.captured_at.tzinfo is None or self.imported_at.tzinfo is None:
            raise ValueError("временные отметки Configuration должны содержать часовой пояс")
        if self.imported_at < self.captured_at:
            raise ValueError("imported_at не может быть раньше captured_at")
        return self


class Rule(DomainModel):
    """Нормализованное упорядоченное firewall-правило."""

    rule_id: str = Field(min_length=1)
    configuration_id: UUID
    name: str = Field(min_length=1)
    sequence: int = Field(ge=0)
    action: RuleAction
    enabled: bool
    sources: tuple[Endpoint, ...] = ()
    destinations: tuple[Endpoint, ...] = ()
    services: tuple[Service, ...] = ()
    source_zone: str | None = None
    destination_zone: str | None = None
    logging_enabled: bool | None = None
    description: str | None = None
    owner: str | None = None
    policy_id: str | None = Field(default=None, min_length=1)
    policy_direction: Literal["in", "out", "global"] | None = None
    policy_semantics: Literal["first_match"] | None = None
    policy_purpose: Literal["transit", "management", "unbound", "unknown"] | None = None
    match_status: DataStatus = DataStatus.UNKNOWN
    description_status: DataStatus = DataStatus.UNKNOWN
    source_location: SourceLocation
    source_status: DataStatus = DataStatus.KNOWN
    destination_status: DataStatus = DataStatus.KNOWN
    service_status: DataStatus = DataStatus.KNOWN
    zone_status: DataStatus = DataStatus.UNKNOWN
    logging_status: DataStatus = DataStatus.UNKNOWN

    @model_serializer(mode="wrap")
    def serialize_purpose(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.policy_purpose is None:
            payload.pop("policy_purpose", None)
        return payload

    @model_validator(mode="after")
    def validate_known_matches(self) -> "Rule":
        """Не допустить пустое известное условие правила."""
        checks = (
            (self.sources, self.source_status, "источники"),
            (self.destinations, self.destination_status, "назначения"),
            (self.services, self.service_status, "сервисы"),
        )
        for values, status, field_name in checks:
            if status == DataStatus.KNOWN and not values:
                raise ValueError(f"известное поле '{field_name}' не может быть пустым")
        return self
