"""Модели трассировки до исходной конфигурации."""

from pydantic import Field, model_validator

from firewall_compliance.domain.base import DomainModel


class SourceLocation(DomainModel):
    """Позиция сущности в файле или структуре исходной конфигурации."""

    source_name: str = Field(min_length=1)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    object_path: str | None = None
    object_id: str | None = None

    @model_validator(mode="after")
    def validate_anchor(self) -> "SourceLocation":
        """Проверить, что указан способ найти объект в источнике."""
        if self.line_start is None and self.object_path is None and self.object_id is None:
            raise ValueError(
                "source location должен содержать строку, путь или идентификатор объекта"
            )
        if self.line_end is not None and self.line_start is None:
            raise ValueError("line_end нельзя указать без line_start")
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("line_end не может быть меньше line_start")
        return self
