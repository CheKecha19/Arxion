"""Отдельный вход ASA forwarding без расширения реестра ACL-парсеров."""

from datetime import datetime
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.forwarding import (
    ForwardingContext,
    ForwardingModel,
    ForwardingSource,
)
from firewall_compliance.domain.parse_result import ParseCoverage, ParseIssue, UnsupportedConstruct
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.parsers.contracts import (
    DetectionResult,
    ParseFailure,
    ParserMetadata,
    SourceDocument,
)


class ForwardingParseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    source: SourceDocument
    metadata: ForwardingSource
    revision_id: UUID
    configuration_id: UUID
    imported_at: datetime
    context_mode: Literal["single", "multiple"] | None = None
    firewall_mode: Literal["routed", "transparent"] | None = None
    address_family: Literal["ipv4", "ipv6", "mixed"] | None = None
    table_role: Literal["data", "management"] | None = None
    table_id: str | None = Field(default=None, min_length=1)
    profile_reference: str | None = Field(default=None, min_length=1)

    @field_validator("source", "metadata", mode="before")
    @classmethod
    def revalidate_input(cls, value: Any) -> Any:
        return value.model_dump(mode="python") if isinstance(value, BaseModel) else value

    @model_validator(mode="after")
    def validate_input(self) -> "ForwardingParseRequest":
        if self.imported_at.tzinfo is None or self.imported_at < self.source.captured_at:
            raise ValueError("импорт требует часовой пояс и время не раньше получения")
        if self.metadata.content_sha256.lower() != self.source.content_sha256:
            raise ValueError("SHA-256 метаданных не совпадает с байтами документа")
        if (
            self.metadata.source_name != self.source.source_name
            or self.metadata.captured_at != self.source.captured_at
            or self.metadata.observation != self.source.observation
        ):
            raise ValueError("имя, получение и наблюдение должны совпадать с документом")
        if (
            any(
                value is not None
                for value in (
                    self.context_mode,
                    self.firewall_mode,
                    self.address_family,
                    self.table_role,
                    self.table_id,
                )
            )
            and not self.profile_reference
        ):
            raise ValueError("заявленный профиль требует отдельного основания")
        if self.context_mode == "single" and self.metadata.device_context is not None:
            raise ValueError("single context не содержит имени отдельного контекста")
        return self


class ForwardingParseResult(ForwardingModel):
    schema_version: Literal["0.1.0"] = "0.1.0"
    parser_id: Literal["cisco-asa-forwarding-9.16"] = "cisco-asa-forwarding-9.16"
    parser_version: Literal["0.1.0"] = "0.1.0"
    context: ForwardingContext
    coverage: ParseCoverage
    warnings: tuple[ParseIssue, ...] = ()
    errors: tuple[ParseIssue, ...] = ()
    unsupported_constructs: tuple[UnsupportedConstruct, ...] = ()
    source_map: dict[str, SourceLocation] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_mapping(self) -> "ForwardingParseResult":
        sources = {item.source_name for item in self.context.sources}
        anchors = (
            *(item.location.location for item in self.context.interfaces),
            *(item.location.location for item in self.context.acls),
            *(item.location.location for item in self.context.bindings),
            *(item.location.location for item in self.context.toggles if item.location is not None),
            *(item.location for inv in self.context.inventories for item in inv.locations),
        )
        if any(anchor not in self.source_map.values() for anchor in anchors):
            raise ValueError("каждый факт и элемент inventory требует запись source_map")
        for location in (
            *self.source_map.values(),
            *(item.source_location for item in self.unsupported_constructs),
            *(item.source_location for item in (*self.warnings, *self.errors)),
        ):
            if location is not None and (
                location.source_name not in sources
                or (
                    location.line_start is None and not (location.object_path or location.object_id)
                )
            ):
                raise ValueError("диагностика и source map требуют непустую позицию источника")
        for acl in self.context.acls:
            for rule in acl.rules:
                if self.source_map.get(rule.rule_id) != rule.source_location:
                    raise ValueError("каждый ACE требует совпадающую запись source_map")
        return self


type ForwardingParseOutcome = ForwardingParseResult | ParseFailure


class ForwardingFactsParser(Protocol):
    @property
    def metadata(self) -> ParserMetadata: ...

    def detect(
        self, source: SourceDocument, metadata: ForwardingSource | None = None
    ) -> DetectionResult: ...

    def parse(self, request: ForwardingParseRequest) -> ForwardingParseOutcome: ...
