"""Явные метаданные сетевого документа и отдельный контракт импорта фактов."""

from datetime import datetime
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.enums import DataStatus, SourceDocumentKind
from firewall_compliance.domain.parse_result import ParseCoverage, ParseIssue, UnsupportedConstruct
from firewall_compliance.domain.revision import CollectionEvidence, Interface, RevisionSource, Route
from firewall_compliance.domain.snapshot import freeze_snapshot_fields
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.parsers.contracts import DetectionResult, ParseFailure, SourceDocument

type NetworkSourceKind = Literal[
    "asa_running_config_interfaces", "asa_running_config_static_routes", "asa_ipv4_rib"
]


class NetworkDocumentMetadata(DomainModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    schema_version: Literal["0.1.0"] = "0.1.0"
    source_document_id: UUID
    source_kind: NetworkSourceKind
    device_id: str = Field(min_length=1)
    context_mode: Literal["single", "multiple"]
    context: str | None = Field(default=None, min_length=1)
    firewall_mode: Literal["routed", "transparent"]
    declared_version: str = Field(min_length=1)
    version_provenance: Literal["documentation", "operator_declared", "device_export"]
    version_reference: str = Field(min_length=1)
    origin: Literal["synthetic", "operator_declared", "device_export"]
    origin_reference: str = Field(min_length=1)
    address_family: Literal["ipv4", "ipv6"]
    table_role: Literal["data", "management"]
    table_id: str = Field(min_length=1)
    command: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    encoding: Literal["ascii", "utf-8"]
    selection: Literal["all", "authored_excerpt", "partial", "filtered", "single_interface"]
    extent: Literal["full", "excerpt", "truncated"]
    capture_success: bool = Field(strict=True)
    complete: bool = Field(default=False, strict=True)
    completeness_reference: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_claim(self) -> "NetworkDocumentMetadata":
        if self.complete and (
            self.selection != "all"
            or self.extent != "full"
            or not self.capture_success
            or self.completeness_reference is None
        ):
            raise ValueError("полнота требует полный успешный захват всей области и основание")
        if self.context_mode == "single" and self.context is not None:
            raise ValueError("single context не содержит имя multiple-context")
        freeze_snapshot_fields(self)
        return self


class InterfaceSettings(DomainModel):
    model_config = ConfigDict(frozen=True)

    interface_id: str = Field(min_length=1)
    label: str | None = Field(default=None, min_length=1)
    security_level: int | None = Field(default=None, ge=0, le=100)
    source_locations: tuple[SourceLocation, ...]


class NetworkInterfaceBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    label: str = Field(min_length=1, max_length=48)
    interface_id: str = Field(min_length=1)


class NetworkParseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    source: SourceDocument
    metadata: NetworkDocumentMetadata
    imported_at: datetime
    interfaces: tuple[Interface, ...] = ()
    bindings: tuple[NetworkInterfaceBinding, ...] = ()

    @property
    def interface_labels(self) -> dict[str, str]:
        return {binding.label.casefold(): binding.interface_id for binding in self.bindings}

    @model_validator(mode="after")
    def validate_context(self) -> "NetworkParseRequest":
        if self.imported_at.tzinfo is None or self.imported_at < self.source.captured_at:
            raise ValueError("импорт требует часовой пояс и время не раньше получения документа")
        if self.metadata.content_sha256.lower() != self.source.content_sha256:
            raise ValueError("SHA-256 метаданных не совпадает с байтами документа")
        if len({binding.label.casefold() for binding in self.bindings}) != len(self.bindings):
            raise ValueError("labels интерфейсов не должны повторяться")
        if len({binding.interface_id for binding in self.bindings}) != len(self.bindings):
            raise ValueError("интерфейс не может иметь несколько labels")
        interfaces = tuple(
            Interface.model_validate(item.model_dump(mode="python")) for item in self.interfaces
        )
        by_id = {interface.interface_id: interface for interface in interfaces}
        if len(by_id) != len(interfaces) or any(
            interface.device_id != self.metadata.device_id for interface in interfaces
        ):
            raise ValueError("интерфейсы должны быть уникальны и принадлежать устройству документа")
        if any(
            binding.interface_id not in by_id
            or by_id[binding.interface_id].data_status != DataStatus.KNOWN
            for binding in self.bindings
        ):
            raise ValueError("binding требует известный интерфейс того же устройства")
        object.__setattr__(
            self, "interfaces", tuple(interface.as_snapshot() for interface in interfaces)
        )
        return self


class NetworkParseResult(DomainModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    schema_version: Literal["0.1.0"] = "0.1.0"
    parser_id: Literal["cisco-asa-network-9.16"] = "cisco-asa-network-9.16"
    parser_version: Literal["0.1.0"] = "0.1.0"
    metadata: NetworkDocumentMetadata
    source: RevisionSource
    scope: Literal["interfaces", "configured_routes", "routing_table"]
    status: DataStatus
    interfaces: tuple[Interface, ...] = ()
    routes: tuple[Route, ...] = ()
    interface_labels: dict[str, str] = Field(default_factory=dict)
    interface_settings: tuple[InterfaceSettings, ...] = ()
    collection_evidence: CollectionEvidence
    warnings: tuple[ParseIssue, ...] = ()
    errors: tuple[ParseIssue, ...] = ()
    unsupported_constructs: tuple[UnsupportedConstruct, ...] = ()
    source_map: dict[str, SourceLocation] = Field(default_factory=dict)
    coverage: ParseCoverage
    limitations: tuple[str, ...] = ()

    @field_validator(
        "metadata",
        "source",
        "interfaces",
        "routes",
        "interface_settings",
        "collection_evidence",
        "warnings",
        "errors",
        "unsupported_constructs",
        "source_map",
        "coverage",
        mode="before",
    )
    @classmethod
    def revalidate_nested(cls, value: Any) -> Any:
        if isinstance(value, DomainModel):
            return value.model_dump(mode="python")
        if isinstance(value, (tuple, list)):
            return [cls.revalidate_nested(item) for item in value]
        if isinstance(value, dict):
            return {key: cls.revalidate_nested(item) for key, item in value.items()}
        return value

    @model_validator(mode="after")
    def validate_facts(self) -> "NetworkParseResult":
        if (
            self.source.source_document_id != self.metadata.source_document_id
            or self.source.content_sha256.lower() != self.metadata.content_sha256.lower()
        ):
            raise ValueError("результат должен сохранять идентичность и хеш документа")
        if (
            self.collection_evidence.scope != self.scope
            or self.collection_evidence.source_document_ids != (self.source.source_document_id,)
        ):
            raise ValueError("основание полноты должно относиться к области и источнику результата")
        if (self.scope == "interfaces" and self.routes) or (
            self.scope != "interfaces"
            and (self.interfaces or self.interface_labels or self.interface_settings)
        ):
            raise ValueError("области интерфейсов и маршрутов не смешиваются")
        facts = (*self.interfaces, *self.routes)
        identifiers = tuple(interface.interface_id for interface in self.interfaces) + tuple(
            route.route_id for route in self.routes
        )
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("идентификаторы сетевых фактов должны быть уникальны")
        for identifier, fact in zip(identifiers, facts, strict=True):
            if (
                fact.device_id != self.metadata.device_id
                or fact.source_document_id != self.source.source_document_id
                or fact.source_location is None
                or fact.source_location.source_name != self.source.source_name
                or self.source_map.get(identifier) != fact.source_location
            ):
                raise ValueError("каждый сетевой факт требует согласованный source mapping")
        if set(self.interface_labels.values()) - set(identifiers):
            raise ValueError("label должен ссылаться на интерфейс результата")
        if self.status in {DataStatus.KNOWN, DataStatus.ABSENT} and (
            not self.collection_evidence.complete
            or not self.metadata.complete
            or self.source.observation is None
            or self.errors
            or self.unsupported_constructs
            or self.warnings
            or any(fact.data_status != DataStatus.KNOWN for fact in facts)
            or self.coverage.discovered_constructs != self.coverage.recognized_constructs
        ):
            raise ValueError("известный набор требует полного поддержанного разбора и наблюдения")
        expected_scope = {
            "asa_running_config_interfaces": "interfaces",
            "asa_running_config_static_routes": "configured_routes",
            "asa_ipv4_rib": "routing_table",
        }[self.metadata.source_kind]
        if expected_scope != self.scope:
            raise ValueError("роль метаданных должна соответствовать области результата")
        expected_kind = (
            SourceDocumentKind.ROUTING_TABLE
            if self.scope == "routing_table"
            else SourceDocumentKind.CONFIGURATION
        )
        if self.source.kind != expected_kind:
            raise ValueError("тип источника должен соответствовать роли документа")
        if len({label.casefold() for label in self.interface_labels}) != len(self.interface_labels):
            raise ValueError("привязки nameif должны быть однозначны без учёта регистра")
        if len(set(self.interface_labels.values())) != len(self.interface_labels):
            raise ValueError("интерфейс не может иметь несколько labels результата")
        if self.status == DataStatus.KNOWN and not facts:
            raise ValueError("доказанно пустой результат имеет статус absent")
        if len({setting.interface_id for setting in self.interface_settings}) != len(
            self.interface_settings
        ) or any(setting.interface_id not in identifiers for setting in self.interface_settings):
            raise ValueError("interface_settings должны быть уникальны и ссылаться на интерфейсы")
        if self.status == DataStatus.ABSENT and facts:
            raise ValueError("absent не содержит фактов")
        if self.collection_evidence.complete != (
            self.status in {DataStatus.KNOWN, DataStatus.ABSENT}
        ):
            raise ValueError("полнота результата должна соответствовать статусу набора")
        freeze_snapshot_fields(self)
        return self


type NetworkParseOutcome = NetworkParseResult | ParseFailure


class NetworkFactsParser(Protocol):
    def detect(
        self, source: SourceDocument, metadata: NetworkDocumentMetadata | None = None
    ) -> DetectionResult: ...

    def parse(self, request: NetworkParseRequest) -> NetworkParseOutcome: ...
