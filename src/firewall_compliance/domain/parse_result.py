"""Модели результата парсинга и диагностики покрытия."""

from typing import Any

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.configuration import Configuration, Rule
from firewall_compliance.domain.enums import ParseIssueLevel
from firewall_compliance.domain.management import ManagementInventory
from firewall_compliance.domain.network import Endpoint, Service
from firewall_compliance.domain.source import SourceLocation


class ParseIssue(DomainModel):
    """Предупреждение или ошибка, возникшие при парсинге."""

    code: str = Field(min_length=1)
    level: ParseIssueLevel
    message: str = Field(min_length=1)
    source_location: SourceLocation | None = None


class UnsupportedConstruct(DomainModel):
    """Конструкция источника, распознанная, но не поддержанная парсером."""

    construct_type: str = Field(min_length=1)
    message: str = Field(min_length=1)
    source_location: SourceLocation


class ParseCoverage(DomainModel):
    """Измеримые сведения о полноте разбора конфигурации."""

    discovered_constructs: int = Field(ge=0)
    recognized_constructs: int = Field(ge=0)
    unsupported_constructs: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counts(self) -> "ParseCoverage":
        """Проверить согласованность счётчиков покрытия."""
        if self.recognized_constructs + self.unsupported_constructs > self.discovered_constructs:
            raise ValueError(
                "распознанные и неподдержанные конструкции превышают число обнаруженных"
            )
        return self

    @property
    def coverage_ratio(self) -> float:
        """Вернуть долю распознанных конструкций."""
        if self.discovered_constructs == 0:
            return 1.0
        return self.recognized_constructs / self.discovered_constructs


class ParseResult(DomainModel):
    """Нормализованный результат работы одного парсера."""

    configuration: Configuration
    management: ManagementInventory | None = None
    rules: tuple[Rule, ...] = ()
    endpoints: tuple[Endpoint, ...] = ()
    services: tuple[Service, ...] = ()
    warnings: tuple[ParseIssue, ...] = ()
    errors: tuple[ParseIssue, ...] = ()
    unsupported_constructs: tuple[UnsupportedConstruct, ...] = ()
    source_map: dict[str, SourceLocation] = Field(default_factory=dict)
    coverage: ParseCoverage

    @model_serializer(mode="wrap")
    def serialize_management(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.management is None:
            payload.pop("management", None)
        return payload

    @model_validator(mode="after")
    def validate_configuration_links(self) -> "ParseResult":
        """Проверить, что правила принадлежат снимку результата."""
        configuration_id = self.configuration.configuration_id
        if self.management is not None:
            inventory = self.management
            locations = [inventory.source_location]
            locations.extend(loc for fact in inventory.facts for loc in fact.source_locations)
            locations.extend(issue.source_location for issue in inventory.issues)
            if inventory.platform != self.configuration.platform or any(
                loc.source_name != self.configuration.source_name for loc in locations
            ):
                raise ValueError("management inventory must belong to this source and platform")
        if any(rule.configuration_id != configuration_id for rule in self.rules):
            raise ValueError("все правила ParseResult должны ссылаться на его Configuration")
        missing_source_map = [
            rule.rule_id for rule in self.rules if rule.rule_id not in self.source_map
        ]
        if missing_source_map:
            raise ValueError("каждое правило ParseResult должно иметь запись source_map")
        invalid_source_map = [
            rule.rule_id
            for rule in self.rules
            if self.source_map[rule.rule_id] != rule.source_location
        ]
        if invalid_source_map:
            raise ValueError("source_map правила должен совпадать с source_location")
        return self
