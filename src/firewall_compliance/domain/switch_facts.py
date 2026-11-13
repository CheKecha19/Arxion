"""Конфигурационные факты коммутаторов, отдельно от ACL и runtime forwarding."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.observation import ObservationEvidence
from firewall_compliance.domain.source import SourceLocation


class SwitchFactIssue(DomainModel):
    """Ограничение конкретного факта без копирования секретной команды."""

    code: str
    area: str
    message: str
    source_location: SourceLocation


class SwitchAreaCoverage(DomainModel):
    """Область распознана частично; полнота файла не доказывает полноту грамматики."""

    area: str
    status: Literal["partial", "not_observed", "unknown"] = "partial"
    recognized: int = Field(default=0, ge=0)
    issues: int = Field(default=0, ge=0)


class SwitchHardware(DomainModel):
    """Аппаратный type из команды либо отдельное предположение по имени."""

    model: str
    origin: Literal["hardware_type", "hostname_hint"]
    member: str | None = None
    source_locations: tuple[SourceLocation, ...]


class SwitchAddress(DomainModel):
    """Нормализованный адрес либо повреждённая адресная запись."""

    raw: str
    cidr: str | None = None
    status: Literal["known", "unknown"] = "known"
    source_locations: tuple[SourceLocation, ...]


class SwitchInterface(DomainModel):
    """Настроенный интерфейс; administrative state не является link state."""

    name: str
    kind: str = "physical"
    description: str | None = None
    admin_state: Literal["enabled", "disabled", "unknown"] = "unknown"
    operational_state: Literal["unknown"] = "unknown"
    mode: Literal["l2", "l3", "unknown"] = "unknown"
    link_type: Literal["access", "trunk", "hybrid", "unknown"] = "unknown"
    vrf: str | None = None
    addresses: tuple[SwitchAddress, ...] = ()
    address_method: Literal["static", "dhcp", "dhcp-bootp", "unknown"] = "unknown"
    access_vlan: int | None = None
    native_vlan: int | None = None
    allowed_vlans: str | None = None
    tagged_vlans: tuple[int, ...] = ()
    untagged_vlans: tuple[int, ...] = ()
    aggregate: str | None = None
    stack_member: str | None = None
    source_locations: tuple[SourceLocation, ...]
    vrf_source_location: SourceLocation | None = None

    @model_validator(mode="after")
    def validate_vrf_source_location(self) -> "SwitchInterface":
        location = self.vrf_source_location
        if location is not None and (
            not self.vrf or location.line_start is None or location not in self.source_locations
        ):
            raise ValueError("Привязка VRF должна ссылаться на строку конфигурации интерфейса.")
        return self

    @model_serializer(mode="wrap")
    def serialize_vrf_source_location(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.vrf_source_location is None:
            payload.pop("vrf_source_location", None)
        return payload


class SwitchVlan(DomainModel):
    """Локальный VLAN; одинаковый ID не доказывает общую сеть на другом устройстве."""

    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = None
    description: str | None = None
    tagged_interfaces: tuple[str, ...] = ()
    untagged_interfaces: tuple[str, ...] = ()
    source_locations: tuple[SourceLocation, ...]


class SwitchAggregate(DomainModel):
    """Настроенная агрегация и её участники, без утверждения об активном LACP."""

    name: str
    description: str | None = None
    members: tuple[str, ...] = ()
    member_devices: tuple[str, ...] = ()
    lacp: Literal["active", "dynamic", "lacp", "unknown"] = "unknown"
    allowed_vlans: str | None = None
    native_vlan: int | None = None
    source_locations: tuple[SourceLocation, ...]


class SwitchStackMember(DomainModel):
    """Участник stacking/IRF/VSF и настроенные межсоединения."""

    member: str
    system: Literal["stacking", "irf", "vsf"]
    hardware_type: str | None = None
    priority: int | None = None
    links: tuple[str, ...] = ()
    source_locations: tuple[SourceLocation, ...]


class SwitchRoute(DomainModel):
    """Настроенный маршрут или management gateway; это не запись наблюдаемого RIB."""

    kind: Literal["static", "management_gateway"]
    prefix: str | None = None
    next_hop: str | None = None
    raw_prefix: str | None = None
    raw_next_hop: str
    vrf: str | None = None
    status: Literal["known", "unknown"] = "known"
    parameters: tuple[str, ...] = ()
    installed: Literal["unknown"] = "unknown"
    source_locations: tuple[SourceLocation, ...]


class SwitchManagementFact(DomainModel):
    """Безопасные параметры управления; значения паролей/community не сохраняются."""

    kind: str
    service: str
    subject: str | None = None
    vrf: str | None = None
    enabled: bool | None = None
    address: str | None = None
    raw_address: str | None = None
    value: str | None = None
    status: Literal["known", "unknown"] = "known"
    source_locations: tuple[SourceLocation, ...]


class SwitchFeature(DomainModel):
    """Наличие настройки протокола, без проверки его работоспособности."""

    name: str
    scope: str = "global"
    enabled: bool | None = None
    value: str | None = None
    source_locations: tuple[SourceLocation, ...]


class SwitchFacts(DomainModel):
    """Версионированный конфигурационный срез, не вход ASA forwarding-контракта."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    source_name: str
    content_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    captured_at: datetime
    observation: ObservationEvidence | None = None
    configuration_complete: bool = False
    evidence_kind: Literal["configuration"] = "configuration"
    platform: str
    platform_family: str | None = None
    identification_reasons: tuple[str, ...] = ()
    hostname: str | None = None
    os_version: str | None = None
    role_hint: str | None = None
    identification_locations: tuple[SourceLocation, ...] = ()
    hardware: tuple[SwitchHardware, ...] = ()
    interfaces: tuple[SwitchInterface, ...] = ()
    vlans: tuple[SwitchVlan, ...] = ()
    aggregates: tuple[SwitchAggregate, ...] = ()
    stack: tuple[SwitchStackMember, ...] = ()
    routes: tuple[SwitchRoute, ...] = ()
    management: tuple[SwitchManagementFact, ...] = ()
    features: tuple[SwitchFeature, ...] = ()
    issues: tuple[SwitchFactIssue, ...] = ()
    coverage: tuple[SwitchAreaCoverage, ...] = ()
    limitations: tuple[str, ...] = (
        "Извлечены настройки; состояние портов, LACP, RIB и доступность не наблюдались.",
        "Описание порта и совпадение VLAN/подсетей не доказывают межустройственную связь.",
        "Ограниченный синтаксис; полнота конфигурации и внешних политик не доказана.",
    )

    @model_validator(mode="after")
    def validate_provenance(self) -> "SwitchFacts":
        """Проверить происхождение и локальную идентичность при чтении JSON/SQLite."""
        if self.captured_at.tzinfo is None:
            raise ValueError("switch facts captured_at должен содержать часовой пояс")
        if self.observation is not None and self.observation.observed_at > self.captured_at:
            raise ValueError("наблюдение не может быть позже получения документа")
        for identifiers in (
            [item.name for item in self.interfaces],
            [item.vlan_id for item in self.vlans],
            [item.name for item in self.aggregates],
            [item.member for item in self.stack],
        ):
            if len(identifiers) != len(set(identifiers)):
                raise ValueError("идентификаторы фактов должны быть уникальны внутри устройства")
        locations = list(self.identification_locations)
        for collection in (
            self.hardware, self.interfaces, self.vlans, self.aggregates,
            self.stack, self.routes, self.management, self.features,
        ):
            for item in collection:
                locations.extend(item.source_locations)
        locations.extend(issue.source_location for issue in self.issues)
        for interface in self.interfaces:
            for address in interface.addresses:
                locations.extend(address.source_locations)
        if any(location.source_name != self.source_name for location in locations):
            raise ValueError("все факты коммутатора должны относиться к одному источнику")
        return self
