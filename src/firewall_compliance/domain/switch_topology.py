"""Доказательная карта настроенной структуры, отдельно от достижимости."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.source import SourceLocation

type SwitchNodeKind = Literal[
    "device", "stack_member", "interface", "aggregate", "vlan", "neighbor", "segment",
    "management_plane",
]
type SwitchLinkKind = Literal[
    "contains", "aggregate_member", "vlan_membership", "neighbor", "topology"
]


class SwitchTopologyProvenance(DomainModel):
    """Ревизия и время источника не подменяются временем построения карты."""

    revision_id: UUID
    source_name: str
    content_sha256: str
    captured_at: datetime
    source_document_id: UUID | None = None
    source_locations: tuple[SourceLocation, ...] = ()
    observed_at: datetime | None = None
    recorded_at: datetime | None = None
    reference: str | None = None

    @model_validator(mode="after")
    def validate_times(self) -> "SwitchTopologyProvenance":
        for value in (self.captured_at, self.observed_at, self.recorded_at):
            if value is not None and value.tzinfo is None:
                raise ValueError("время происхождения карты должно содержать часовой пояс")
        return self


class SwitchTopologyNode(DomainModel):
    """Идентичность локальной сущности включает ревизию устройства."""

    node_id: str
    kind: SwitchNodeKind
    label: str
    device_id: str
    revision_id: UUID
    details: dict[str, Any] = Field(default_factory=dict)
    provenance: tuple[SwitchTopologyProvenance, ...] = ()


class SwitchTopologyLink(DomainModel):
    """Настройка, предположение и внешнее свидетельство — разные состояния."""

    link_id: str
    left: str
    right: str
    kind: SwitchLinkKind
    status: Literal["configured", "inferred", "observed", "operator_confirmed"]
    evidence_kind: Literal[
        "configuration", "configuration_description", "device_export", "operator_confirmation"
    ]
    alternatives: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    provenance: tuple[SwitchTopologyProvenance, ...]


class SwitchTopologyGap(DomainModel):
    """Пробел данных и следующий полезный источник, без вывода о блокировке."""

    code: str
    node_id: str | None = None
    message: str
    next_source: str | None = None
    provenance: tuple[SwitchTopologyProvenance, ...] = ()


class SwitchTopology(DomainModel):
    """Версионированная read model; не является NetworkSnapshot или ACL-картой."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    built_at: datetime
    nodes: tuple[SwitchTopologyNode, ...] = ()
    links: tuple[SwitchTopologyLink, ...] = ()
    gaps: tuple[SwitchTopologyGap, ...] = ()
    limitations: tuple[str, ...] = (
        "Карта настроенной структуры не доказывает IP-доступность или рабочее состояние.",
        "Одинаковые VLAN и подсети разных устройств не объединены автоматически.",
        "Связи по description остаются предположениями даже при совпадении hostname.",
        "Исторические ревизии представлены раздельно и не считаются текущей сетью.",
    )

    @model_validator(mode="after")
    def validate_graph(self) -> "SwitchTopology":
        if self.built_at.tzinfo is None:
            raise ValueError("built_at должен содержать часовой пояс")
        identifiers = {node.node_id for node in self.nodes}
        if len(identifiers) != len(self.nodes):
            raise ValueError("идентификаторы узлов карты должны быть уникальны")
        if len({link.link_id for link in self.links}) != len(self.links):
            raise ValueError("идентификаторы связей карты должны быть уникальны")
        if any(link.left not in identifiers or link.right not in identifiers for link in self.links):
            raise ValueError("связь должна ссылаться на узлы этой карты")
        return self
