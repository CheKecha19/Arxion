"""Неизменяемые ревизии устройства, сетевые факты и результаты их сравнения."""

from datetime import datetime
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.configuration import Device
from firewall_compliance.domain.enums import (
    DataOrigin,
    DataStatus,
    RevisionChangeKind,
    RevisionEntityKind,
    SourceDocumentKind,
)
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.observation import ObservationEvidence, ObservationWindow
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.snapshot import freeze_snapshot_fields
from firewall_compliance.domain.source import SourceLocation


class RevisionModel(DomainModel):
    """Строгая неизменяемая модель, принадлежащая ревизии устройства."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, str_strip_whitespace=True, validate_assignment=True
    )


class RevisionSource(RevisionModel):
    """Метаданные одного исходного документа без хранения его содержимого."""

    source_document_id: UUID = Field(default_factory=uuid4)
    source_name: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    kind: SourceDocumentKind
    captured_at: datetime
    file_modified_at: datetime | None = None
    observation: ObservationEvidence | None = None

    @model_validator(mode="after")
    def validate_captured_at(self) -> "RevisionSource":
        """Проверить наличие часового пояса у времени получения документа."""
        if self.captured_at.tzinfo is None:
            raise ValueError("captured_at RevisionSource должен содержать часовой пояс")
        if self.file_modified_at is not None and self.file_modified_at.tzinfo is None:
            raise ValueError("file_modified_at должен содержать часовой пояс")
        if self.observation is not None and self.observation.observed_at > self.captured_at:
            raise ValueError("наблюдение не может быть позже получения документа")
        return self


class NetworkFact(RevisionModel):
    """Общие требования к происхождению сетевого факта."""

    device_id: str = Field(min_length=1)
    origin: DataOrigin
    data_status: DataStatus = DataStatus.KNOWN
    source_document_id: UUID | None = None
    source_location: SourceLocation | None = None
    manual_reason: str | None = None
    recorded_at: datetime | None = None
    observation: ObservationEvidence | None = None

    @model_validator(mode="after")
    def validate_provenance(self) -> "NetworkFact":
        """Не допустить подмену импортированных данных ручными и наоборот."""
        if self.origin == DataOrigin.IMPORTED:
            if self.source_document_id is None or self.source_location is None:
                raise ValueError("импортированный сетевой факт должен иметь source mapping")
            if (
                self.manual_reason is not None
                or self.recorded_at is not None
                or self.observation is not None
            ):
                raise ValueError("импортированный факт не может содержать реквизиты ручного ввода")
        else:
            if self.source_document_id is not None or self.source_location is not None:
                raise ValueError("ручной факт не может ссылаться на импортированный источник")
            if not self.manual_reason or self.recorded_at is None:
                raise ValueError("ручной факт должен содержать причину и время фиксации")
            if self.recorded_at.tzinfo is None:
                raise ValueError("recorded_at ручного факта должен содержать часовой пояс")
            if self.observation is not None and self.observation.observed_at > self.recorded_at:
                raise ValueError("наблюдение не может быть позже ручной фиксации")
        return self


class Interface(NetworkFact):
    """Интерфейс устройства в рамках одной ревизии."""

    interface_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    addresses: tuple[str, ...] = ()
    addresses_status: DataStatus = DataStatus.UNKNOWN
    zone: str | None = None
    enabled: bool | None = None

    @field_validator("addresses")
    @classmethod
    def normalize_addresses(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Нормализовать адреса интерфейса и удалить повторы."""
        return tuple(dict.fromkeys(str(ip_interface(value)) for value in values))

    @property
    def networks(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(str(ip_interface(value).network) for value in self.addresses))

    @model_validator(mode="after")
    def validate_addresses_status(self) -> "Interface":
        if self.addresses_status == DataStatus.KNOWN and not self.addresses:
            raise ValueError("известные адреса интерфейса не могут быть пустыми")
        if (
            self.addresses_status in {DataStatus.ABSENT, DataStatus.NOT_APPLICABLE}
            and self.addresses
        ):
            raise ValueError("отсутствующие адреса интерфейса не могут содержать значения")
        return self


class Route(NetworkFact):
    """Маршрут устройства без интерпретации достижимости."""

    route_id: str = Field(min_length=1)
    destination: str
    next_hop: str | None = None
    outgoing_interface_id: str | None = None
    metric: int | None = Field(default=None, ge=0)
    administrative_distance: int | None = Field(default=None, ge=0, le=255)
    route_kind: Literal["connected", "static", "dynamic", "unknown"] = "unknown"
    table_id: str = Field(default="default", min_length=1)
    is_blackhole: bool = False

    @field_validator("destination")
    @classmethod
    def normalize_destination(cls, value: str) -> str:
        """Проверить и нормализовать сеть назначения."""
        return str(ip_network(value, strict=False))

    @field_validator("next_hop")
    @classmethod
    def normalize_next_hop(cls, value: str | None) -> str | None:
        """Проверить и нормализовать адрес следующего перехода."""
        return str(ip_address(value)) if value is not None else None

    @model_validator(mode="after")
    def validate_route_target(self) -> "Route":
        """Потребовать цель для известного неблокирующего маршрута."""
        if self.next_hop is not None and (
            ip_network(self.destination).version != ip_address(self.next_hop).version
        ):
            raise ValueError("destination и next_hop должны иметь одно семейство адресов")
        if self.is_blackhole and (
            self.next_hop is not None or self.outgoing_interface_id is not None
        ):
            raise ValueError("blackhole не может содержать next_hop или интерфейс")
        if (
            self.data_status == DataStatus.KNOWN
            and not self.is_blackhole
            and self.next_hop is None
            and self.outgoing_interface_id is None
        ):
            raise ValueError("известный маршрут должен иметь next_hop или outgoing_interface_id")
        return self


class NetworkSegment(NetworkFact):
    """Логический или адресный сегмент сети."""

    segment_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    cidrs: tuple[str, ...] = ()
    zone: str | None = None

    @field_validator("cidrs")
    @classmethod
    def normalize_cidrs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Нормализовать сети сегмента и удалить повторы."""
        return tuple(dict.fromkeys(str(ip_network(value, strict=False)) for value in values))


class TopologyLink(NetworkFact):
    """Связь между двумя интерфейсами или сегментами одной ревизии."""

    link_id: str = Field(min_length=1)
    left_endpoint_id: str = Field(min_length=1)
    right_endpoint_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_distinct_endpoints(self) -> "TopologyLink":
        """Запретить топологическую связь сущности с самой собой."""
        if self.left_endpoint_id == self.right_endpoint_id:
            raise ValueError("TopologyLink не может соединять сущность саму с собой")
        return self


class RevisionChange(RevisionModel):
    """Одно объяснимое изменение сущности между ревизиями."""

    entity_kind: RevisionEntityKind
    change_kind: RevisionChangeKind
    entity_id: str = Field(min_length=1)
    evidence: Evidence


class DeviceRevisionDiff(RevisionModel):
    """Результат сравнения двух ревизий одного устройства."""

    before_revision_id: UUID
    after_revision_id: UUID
    device_id: str = Field(min_length=1)
    changes: tuple[RevisionChange, ...] = ()
    normalization_changed: bool = False
    limitations: tuple[str, ...] = ()


class CollectionEvidence(RevisionModel):
    """Явная область и основание полноты набора сетевых фактов."""

    scope: Literal["interfaces", "configured_routes", "routing_table", "segments", "topology"]
    complete: bool = False
    source_document_ids: tuple[UUID, ...] = ()
    manual_reason: str | None = Field(default=None, min_length=1)
    recorded_at: datetime | None = None
    observation: ObservationEvidence | None = None

    @model_validator(mode="after")
    def validate_basis(self) -> "CollectionEvidence":
        if len(set(self.source_document_ids)) != len(self.source_document_ids):
            raise ValueError("источники полноты не должны повторяться")
        if not self.source_document_ids and self.manual_reason is None:
            raise ValueError("полнота требует источники либо основание ручной фиксации")
        if self.manual_reason is None:
            if self.recorded_at is not None or self.observation is not None:
                raise ValueError("ручные реквизиты требуют manual_reason")
        elif self.recorded_at is None or self.recorded_at.tzinfo is None:
            raise ValueError("ручное основание полноты требует recorded_at с часовым поясом")
        elif self.observation is not None and self.observation.observed_at > self.recorded_at:
            raise ValueError("наблюдение полноты не может быть позже ручной фиксации")
        return self


class DeviceRevision(RevisionModel):
    """Согласованный снимок устройства и доступных сетевых фактов."""

    model_config = ConfigDict(revalidate_instances="always")

    revision_id: UUID = Field(default_factory=uuid4)
    schema_version: Literal["2.0.0"] = "2.0.0"
    device: Device
    parse_result: ParseResult
    sources: tuple[RevisionSource, ...]
    application_version: str = Field(min_length=1)
    observed_at: datetime | None = None
    observation_window: ObservationWindow | None = None
    legacy_observed_at: datetime | None = None
    migration_limitations: tuple[str, ...] = ()
    imported_at: datetime
    interfaces: tuple[Interface, ...] = ()
    routes: tuple[Route, ...] = ()
    network_segments: tuple[NetworkSegment, ...] = ()
    topology_links: tuple[TopologyLink, ...] = ()
    interfaces_status: DataStatus = DataStatus.UNKNOWN
    routes_status: DataStatus = DataStatus.UNKNOWN
    network_segments_status: DataStatus = DataStatus.UNKNOWN
    topology_status: DataStatus = DataStatus.UNKNOWN
    interfaces_evidence: CollectionEvidence | None = None
    routes_evidence: CollectionEvidence | None = None
    network_segments_evidence: CollectionEvidence | None = None
    topology_evidence: CollectionEvidence | None = None

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        legacy = value.get("schema_version") == "1.0.0" or (
            "schema_version" not in value and isinstance(value.get("parse_result"), dict)
        )
        if not legacy:
            return value
        migrated = dict(value)
        migrated.update(
            schema_version="2.0.0",
            legacy_observed_at=value.get("observed_at"),
            observed_at=None,
            observation_window=None,
            migration_limitations=(
                "Старая схема не доказывает время наблюдения, полноту или IP интерфейса; "
                "нужен повторный импорт источников.",
            ),
        )
        for collection, status, evidence in (
            ("interfaces", "interfaces_status", "interfaces_evidence"),
            ("routes", "routes_status", "routes_evidence"),
            ("network_segments", "network_segments_status", "network_segments_evidence"),
            ("topology_links", "topology_status", "topology_evidence"),
        ):
            migrated[status] = DataStatus.UNKNOWN
            migrated[evidence] = None
            migrated[collection] = [
                {**fact, "data_status": DataStatus.UNKNOWN} for fact in value.get(collection, ())
            ]
            if collection == "interfaces":
                for fact in migrated[collection]:
                    fact["addresses_status"] = DataStatus.UNKNOWN
        return migrated

    @field_validator(
        "device",
        "parse_result",
        "sources",
        "interfaces",
        "routes",
        "network_segments",
        "topology_links",
        "interfaces_evidence",
        "routes_evidence",
        "network_segments_evidence",
        "topology_evidence",
        "observation_window",
        mode="before",
    )
    @classmethod
    def revalidate_nested(cls, value: Any) -> Any:
        if isinstance(value, DomainModel):
            return value.model_dump(mode="python")
        if isinstance(value, (tuple, list)):
            return [cls.revalidate_nested(item) for item in value]
        return value

    @model_validator(mode="after")
    def validate_revision(self) -> "DeviceRevision":
        """Проверить целостность состава, времени и происхождения ревизии."""
        if self.imported_at.tzinfo is None or (
            self.observed_at is not None and self.observed_at.tzinfo is None
        ):
            raise ValueError("временные отметки DeviceRevision должны содержать часовой пояс")
        if self.observed_at is not None and self.imported_at < self.observed_at:
            raise ValueError("imported_at ревизии не может быть раньше observed_at")
        if self.legacy_observed_at is not None and self.legacy_observed_at.tzinfo is None:
            raise ValueError("legacy_observed_at должен содержать часовой пояс")
        if self.observation_window is not None and (
            self.observed_at is None
            or not self.observation_window.start <= self.observed_at <= self.observation_window.end
            or self.observation_window.end > self.imported_at
        ):
            raise ValueError("интервал должен содержать observed_at и завершаться до импорта")

        configuration = self.parse_result.configuration
        if configuration.device_id != self.device.device_id:
            raise ValueError("Configuration должна принадлежать устройству ревизии")
        if (
            configuration.vendor != self.device.vendor
            or configuration.platform != self.device.platform
        ):
            raise ValueError("производитель и платформа Configuration должны совпадать с Device")
        if configuration.imported_at != self.imported_at:
            raise ValueError("Configuration и DeviceRevision должны иметь общее время импорта")

        source_ids = {source.source_document_id for source in self.sources}
        if len(source_ids) != len(self.sources):
            raise ValueError("идентификаторы исходных документов должны быть уникальными")
        configuration_sources = [
            source
            for source in self.sources
            if source.kind == SourceDocumentKind.CONFIGURATION
            and source.source_name == configuration.source_name
            and source.content_sha256.lower() == configuration.content_sha256.lower()
            and source.captured_at == configuration.captured_at
        ]
        if len(configuration_sources) != 1:
            raise ValueError("ревизия должна содержать ровно один источник Configuration")
        if any(source.captured_at > self.imported_at for source in self.sources):
            raise ValueError("получение документа не может быть позже импорта")
        if self.observed_at is not None:
            self._validate_observation(configuration_sources[0].observation, "Configuration")

        sources_by_id = {source.source_document_id: source for source in self.sources}
        self._validate_facts(self.interfaces, "interface_id", "Interface", sources_by_id)
        self._validate_facts(self.routes, "route_id", "Route", sources_by_id)
        self._validate_facts(self.network_segments, "segment_id", "NetworkSegment", sources_by_id)
        self._validate_facts(self.topology_links, "link_id", "TopologyLink", sources_by_id)
        self._validate_status(
            self.interfaces_status,
            self.interfaces,
            "интерфейсы",
            sources_by_id,
            self.interfaces_evidence,
            ("interfaces",),
        )
        self._validate_status(
            self.routes_status,
            self.routes,
            "маршруты",
            sources_by_id,
            self.routes_evidence,
            ("configured_routes", "routing_table"),
        )
        self._validate_status(
            self.network_segments_status,
            self.network_segments,
            "сетевые сегменты",
            sources_by_id,
            self.network_segments_evidence,
            ("segments",),
        )
        self._validate_status(
            self.topology_status,
            self.topology_links,
            "топологические связи",
            sources_by_id,
            self.topology_evidence,
            ("topology",),
        )

        interface_ids = {interface.interface_id for interface in self.interfaces}
        segment_ids = {segment.segment_id for segment in self.network_segments}
        if interface_ids & segment_ids:
            raise ValueError("идентификаторы интерфейсов и сегментов не должны пересекаться")
        endpoint_ids = {
            *interface_ids,
            *(segment.segment_id for segment in self.network_segments),
        }
        if any(
            route.outgoing_interface_id not in interface_ids
            for route in self.routes
            if route.outgoing_interface_id is not None
        ):
            raise ValueError("маршрут должен ссылаться на интерфейс ревизии")
        for link in self.topology_links:
            if (
                link.left_endpoint_id not in endpoint_ids
                or link.right_endpoint_id not in endpoint_ids
            ):
                raise ValueError("TopologyLink должен ссылаться на интерфейсы или сегменты ревизии")
        freeze_snapshot_fields(self)
        return self

    def _validate_facts(
        self,
        facts: tuple[NetworkFact, ...],
        identifier: str,
        label: str,
        sources_by_id: dict[UUID, RevisionSource],
    ) -> None:
        """Проверить устройство, уникальность и происхождение набора сетевых фактов."""
        identifiers = [getattr(fact, identifier) for fact in facts]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError(f"идентификаторы {label} должны быть уникальными")
        for fact in facts:
            if fact.device_id != self.device.device_id:
                raise ValueError(f"{label} должен принадлежать устройству ревизии")
            if fact.origin == DataOrigin.IMPORTED:
                if fact.source_document_id is None or fact.source_document_id not in sources_by_id:
                    raise ValueError(f"источник {label} должен входить в состав ревизии")
                source = sources_by_id[fact.source_document_id]
                if (
                    fact.source_location is None
                    or fact.source_location.source_name != source.source_name
                ):
                    raise ValueError(f"source mapping {label} не совпадает с документом")
            elif fact.recorded_at is not None and fact.recorded_at > self.imported_at:
                raise ValueError(f"ручная фиксация {label} не может быть позже импорта")

    def _validate_status(
        self,
        status: DataStatus,
        facts: tuple[NetworkFact, ...],
        label: str,
        sources_by_id: dict[UUID, RevisionSource],
        evidence: CollectionEvidence | None,
        scopes: tuple[str, ...],
    ) -> None:
        """Проверить область, полноту и согласованность известного набора."""
        if status in {DataStatus.ABSENT, DataStatus.NOT_APPLICABLE} and facts:
            raise ValueError(f"отсутствующие или неприменимые {label} не могут содержать факты")
        if evidence is not None:
            if evidence.scope not in scopes:
                raise ValueError(f"область полноты не соответствует набору: {label}")
            if any(source_id not in sources_by_id for source_id in evidence.source_document_ids):
                raise ValueError("источник полноты должен входить в ревизию")
            if evidence.scope == "routing_table" and any(
                sources_by_id[source_id].kind != SourceDocumentKind.ROUTING_TABLE
                for source_id in evidence.source_document_ids
            ):
                raise ValueError("полнота routing_table требует источник таблицы маршрутизации")
            if evidence.recorded_at is not None and evidence.recorded_at > self.imported_at:
                raise ValueError("ручное основание полноты не может быть позже импорта")
        if status not in {DataStatus.KNOWN, DataStatus.ABSENT, DataStatus.NOT_APPLICABLE}:
            return
        if evidence is None or not evidence.complete:
            raise ValueError(f"известные {label} требуют доказательства полноты")
        if self.observed_at is None:
            raise ValueError(f"известные {label} требуют observed_at")
        for source_id in evidence.source_document_ids:
            self._validate_observation(sources_by_id[source_id].observation, label)
        if evidence.manual_reason is not None:
            self._validate_observation(evidence.observation, label)
        for fact in facts:
            if fact.data_status != DataStatus.KNOWN:
                raise ValueError(f"известные {label} требуют известных фактов")
            if fact.origin == DataOrigin.IMPORTED:
                source_document_id = fact.source_document_id
                if source_document_id is None:
                    raise ValueError("импортированный факт должен иметь идентификатор источника")
                source = sources_by_id[source_document_id]
                if source_document_id not in evidence.source_document_ids:
                    raise ValueError("источник факта должен входить в основание полноты")
                self._validate_observation(source.observation, label)
            else:
                if evidence.manual_reason is None:
                    raise ValueError("ручной факт требует ручное основание полноты")
                self._validate_observation(fact.observation, label)

    def _validate_observation(self, observation: ObservationEvidence | None, label: str) -> None:
        if observation is None or self.observed_at is None:
            raise ValueError(f"{label} требует явного observed_at")
        if self.observation_window is None:
            if observation.observed_at != self.observed_at:
                raise ValueError(f"{label} должен относиться к observed_at ревизии")
        elif (
            not self.observation_window.start
            <= observation.observed_at
            <= self.observation_window.end
        ):
            raise ValueError(f"{label} вне интервала observed_at ревизии")
