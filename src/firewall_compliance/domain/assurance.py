"""Контракт результатов независимых проверок firewall-политик."""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.finding import Finding
from firewall_compliance.domain.parse_result import ParseCoverage, ParseIssue, UnsupportedConstruct


class CheckStatus(StrEnum):
    """Полнота выполнения проверки, независимая от числа findings."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"


class CheckLimitation(DomainModel):
    """Причина, по которой проверка не может сделать достоверный вывод."""

    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    rule_ids: tuple[str, ...] = ()


class CheckResult(DomainModel):
    """Findings одной проверки вместе с непроверенными условиями."""

    check_id: str = Field(min_length=1)
    check_version: str = Field(min_length=1)
    status: CheckStatus
    findings: tuple[Finding, ...] = ()
    limitations: tuple[CheckLimitation, ...] = ()

    @model_validator(mode="after")
    def validate_result(self) -> "CheckResult":
        """Проверить согласованность полноты и идентичности проверки."""
        if any(finding.check_id != self.check_id for finding in self.findings):
            raise ValueError("findings должны принадлежать своей проверке")
        if self.status == CheckStatus.PARTIAL and not self.limitations:
            raise ValueError("partial требует объяснения ограничений")
        if self.status == CheckStatus.COMPLETE and self.limitations:
            raise ValueError("complete не может содержать непроверенные условия")
        if self.status == CheckStatus.NOT_APPLICABLE and (self.findings or self.limitations):
            raise ValueError("not_applicable не может содержать findings или непроверенные условия")
        return self


class FirewallAssuranceResult(DomainModel):
    """Воспроизводимый результат каталога проверок одной ревизии."""

    schema_version: str = "1.0.0"
    revision_id: UUID
    configuration_id: UUID
    device_id: str = Field(min_length=1)
    application_version: str = Field(min_length=1)
    parser_version: str = Field(min_length=1)
    check_catalog_version: str = Field(min_length=1)
    require_logging: bool
    require_comments: bool
    max_pair_rules: int = Field(ge=1)
    analyzed_at: datetime
    checks: tuple[CheckResult, ...]
    management_profile: dict[str, Any] | None = None
    parse_warnings: tuple[ParseIssue, ...] = ()
    parse_errors: tuple[ParseIssue, ...] = ()
    unsupported_constructs: tuple[UnsupportedConstruct, ...] = ()
    parse_coverage: ParseCoverage

    @model_serializer(mode="wrap")
    def serialize_management_profile(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.management_profile is None:
            payload.pop("management_profile", None)
        return payload

    @model_validator(mode="after")
    def validate_links(self) -> "FirewallAssuranceResult":
        """Проверить время и принадлежность findings анализируемой ревизии."""
        if self.analyzed_at.tzinfo is None:
            raise ValueError("analyzed_at должен содержать часовой пояс")
        if len({check.check_id for check in self.checks}) != len(self.checks):
            raise ValueError("идентификаторы проверок должны быть уникальными")
        for check in self.checks:
            for finding in check.findings:
                if (
                    finding.revision_id != self.revision_id
                    or finding.configuration_id != self.configuration_id
                    or finding.device_id != self.device_id
                ):
                    raise ValueError("finding должен принадлежать анализируемой ревизии")
        return self
