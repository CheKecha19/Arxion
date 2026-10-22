"""Модели findings и их доказательной базы."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.enums import FindingCategory, FindingStatus, Severity
from firewall_compliance.domain.source import SourceLocation


class Evidence(DomainModel):
    """Фактическое обоснование результата проверки."""

    summary: str = Field(min_length=1)
    source_locations: tuple[SourceLocation, ...] = ()
    related_rule_ids: tuple[str, ...] = ()
    facts: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()


class Finding(DomainModel):
    """Единый результат security-, policy- или compliance-проверки."""

    finding_id: UUID = Field(default_factory=uuid4)
    check_id: str = Field(min_length=1)
    category: FindingCategory
    severity: Severity
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    configuration_id: UUID
    revision_id: UUID | None = None
    device_id: str = Field(min_length=1)
    affected_rule_ids: tuple[str, ...] = ()
    evidence: Evidence
    recommendation: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    status: FindingStatus = FindingStatus.NEW
    first_seen: datetime
    last_seen: datetime

    @model_validator(mode="after")
    def validate_timestamps(self) -> "Finding":
        """Проверить временные отметки жизненного цикла finding."""
        if self.first_seen.tzinfo is None or self.last_seen.tzinfo is None:
            raise ValueError("временные отметки Finding должны содержать часовой пояс")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen не может быть раньше first_seen")
        return self
