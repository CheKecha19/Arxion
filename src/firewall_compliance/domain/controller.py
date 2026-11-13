"""Версионированный каталог ArubaOS Controller без утверждения runtime-доступности."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.source import SourceLocation


class ControllerObject(DomainModel):
    """Объявленный объект и безопасные параметры, отдельно от его применения."""

    object_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    state: Literal["declared", "partial", "unsupported"] = "declared"
    source_locations: tuple[SourceLocation, ...] = Field(min_length=1)


class ControllerReference(DomainModel):
    """Ссылка с сохранённым порядком и неизвестными зависимостями."""

    reference_id: str = Field(min_length=1)
    source_id: str
    target_kind: str
    target_name: str
    target_id: str | None = None
    relation: str
    status: Literal["known", "missing", "dynamic"] = "missing"
    position: int | None = Field(default=None, ge=0)
    source_locations: tuple[SourceLocation, ...] = Field(min_length=1)


class ControllerIssue(DomainModel):
    """Ограничение конкретного объекта/области без секретного raw content."""

    code: str
    message: str
    object_id: str | None = None
    source_location: SourceLocation


class ControllerCoverage(DomainModel):
    """Наличие разобранных объявлений не доказывает полноту экспорта."""

    area: str
    state: Literal["partial", "not_observed", "unknown"] = "partial"
    recognized: int = Field(default=0, ge=0)
    unsupported: int = Field(default=0, ge=0)


class ControllerInventory(DomainModel):
    """Сохранённый граф конфигурационных объектов ArubaOS 8.6/8.10."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    source_name: str
    content_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    captured_at: datetime
    declared_version: str | None = None
    configuration_complete: bool = False
    configuration_view: Literal["local", "effective", "effective_detail", "pending", "unknown"] = "unknown"
    node_path: str | None = None
    objects: tuple[ControllerObject, ...] = ()
    references: tuple[ControllerReference, ...] = ()
    issues: tuple[ControllerIssue, ...] = ()
    coverage: tuple[ControllerCoverage, ...] = ()
    limitations: tuple[str, ...] = (
        "Извлечены объявления; активные клиенты, роли и каналы не наблюдались.",
        "Вид экспорта и наследование неизвестны без отдельного основания.",
        "DNS, динамические адреса и приложения не заменяются статическими ANY.",
        "NAT/PBR/AppRF сохранены отдельно; полная трансляция и путь не вычисляются.",
    )

    @model_validator(mode="after")
    def validate_links(self) -> "ControllerInventory":
        """Проверить локальную идентичность и происхождение после JSON roundtrip."""
        if self.captured_at.tzinfo is None:
            raise ValueError("controller inventory captured_at requires timezone")
        objects = {item.object_id: item for item in self.objects}
        if len(objects) != len(self.objects):
            raise ValueError("controller object IDs must be unique")
        if len({item.reference_id for item in self.references}) != len(self.references):
            raise ValueError("controller reference IDs must be unique")
        locations = [location for item in self.objects for location in item.source_locations]
        for reference in self.references:
            if reference.source_id not in objects:
                raise ValueError("controller reference source is absent")
            if reference.status == "known" and reference.target_id not in objects:
                raise ValueError("known controller reference target is absent")
            if reference.target_id is not None:
                target = objects.get(reference.target_id)
                if target is None or target.kind != reference.target_kind or target.name != reference.target_name:
                    raise ValueError("controller reference target identity differs")
            locations.extend(reference.source_locations)
        locations.extend(issue.source_location for issue in self.issues)
        if any(location.source_name != self.source_name for location in locations):
            raise ValueError("controller inventory locations must belong to the same source")
        return self
