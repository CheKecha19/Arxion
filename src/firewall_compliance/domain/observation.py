"""Явное происхождение времени наблюдения устройства."""

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from firewall_compliance.domain.base import DomainModel


class ObservationEvidence(DomainModel):
    """Основание времени состояния, а не времени файла или импорта."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    observed_at: datetime
    method: Literal["operator_declared", "device_export", "synthetic"]
    reference: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_time(self) -> "ObservationEvidence":
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at должен содержать часовой пояс")
        return self


class ObservationWindow(DomainModel):
    """Явно согласованный интервал для раздельных экспортов."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    start: datetime
    end: datetime
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_window(self) -> "ObservationWindow":
        if self.start.tzinfo is None or self.end.tzinfo is None or self.end < self.start:
            raise ValueError("интервал наблюдения должен иметь часовой пояс и верный порядок")
        return self
