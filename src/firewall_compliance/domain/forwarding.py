"""Нейтральный контекст пересылки с отдельными доказательствами inventories."""

from collections.abc import Mapping
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus, Protocol, RuleAction
from firewall_compliance.domain.observation import ObservationEvidence, ObservationWindow
from firewall_compliance.domain.reachability import ReachabilityQuery
from firewall_compliance.domain.snapshot import freeze_snapshot_fields
from firewall_compliance.domain.source import SourceLocation

type ForwardingFeature = Literal[
    "interfaces",
    "acl_definitions",
    "acl_bindings",
    "same_security",
    "vpn_bypass",
    "configured_nat",
    "effective_nat",
    "pbr",
    "exceptions",
]
type ForwardingScope = Literal[
    "interfaces",
    "acl_definitions",
    "acl_bindings",
    "same_security",
    "vpn_bypass",
    "object_nat",
    "manual_nat",
    "effective_nat",
    "pbr_bindings",
    "pbr_definitions",
    "exceptions",
]
FEATURE_SCOPES: dict[ForwardingFeature, frozenset[ForwardingScope]] = {
    "interfaces": frozenset({"interfaces"}),
    "acl_definitions": frozenset({"acl_definitions"}),
    "acl_bindings": frozenset({"acl_bindings"}),
    "same_security": frozenset({"same_security"}),
    "vpn_bypass": frozenset({"vpn_bypass"}),
    "configured_nat": frozenset({"object_nat", "manual_nat"}),
    "effective_nat": frozenset({"effective_nat"}),
    "pbr": frozenset({"pbr_bindings", "pbr_definitions"}),
    "exceptions": frozenset({"exceptions"}),
}


class ForwardingModel(DomainModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    @field_validator("*", mode="before")
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
    def freeze(self) -> "ForwardingModel":
        freeze_snapshot_fields(self)
        return self

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Копия нового контракта повторно валидируется и всегда отделена глубоко."""
        payload = self.model_dump(mode="python")
        payload.update(update or {})
        return type(self).model_validate(payload)


class ForwardingLocation(ForwardingModel):
    source_document_id: UUID
    location: SourceLocation

    @model_validator(mode="after")
    def validate_anchor(self) -> "ForwardingLocation":
        if self.location.line_start is None and not (
            self.location.object_path or self.location.object_id
        ):
            raise ValueError("source mapping требует непустой позиции")
        return self


class ForwardingSource(ForwardingModel):
    source_document_id: UUID
    source_name: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    purpose: Literal["configuration", "effective_nat", "pbr_state"]
    device_id: str = Field(min_length=1)
    device_context: str | None = Field(default=None, min_length=1)
    command: str = Field(min_length=1)
    declared_version: str = Field(min_length=1)
    version_provenance: Literal["documentation", "operator_declared", "device_export"]
    version_reference: str = Field(min_length=1)
    origin: Literal["synthetic", "operator_declared", "device_export"]
    origin_reference: str = Field(min_length=1)
    captured_at: datetime
    observation: ObservationEvidence | None = None
    selection: Literal["all", "authored_excerpt", "partial", "filtered"]
    extent: Literal["full", "excerpt", "truncated"]
    encoding: Literal["ascii", "utf-8"]
    capture_success: bool = Field(strict=True)
    complete_scopes: tuple[ForwardingScope, ...] = ()
    completeness_reference: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_capture(self) -> "ForwardingSource":
        if self.captured_at.tzinfo is None:
            raise ValueError("captured_at требует часовой пояс")
        if self.observation and self.observation.observed_at > self.captured_at:
            raise ValueError("наблюдение не может быть позже получения")
        if len(set(self.complete_scopes)) != len(self.complete_scopes):
            raise ValueError("области полноты источника не должны повторяться")
        if self.complete_scopes and (
            self.selection != "all"
            or self.extent != "full"
            or not self.capture_success
            or not self.completeness_reference
            or self.observation is None
        ):
            raise ValueError("полнота источника требует полного захвата, основания и наблюдения")
        if "effective_nat" in self.complete_scopes and self.purpose != "effective_nat":
            raise ValueError("конфигурационный источник не доказывает effective NAT")
        if self.purpose == "effective_nat" and any(
            scope != "effective_nat" for scope in self.complete_scopes
        ):
            raise ValueError("эффективный NAT не доказывает конфигурационные области")
        if self.purpose == "pbr_state" and any(
            scope != "pbr_bindings" for scope in self.complete_scopes
        ):
            raise ValueError("PBR state не доказывает определения route-map")
        return self


class FeatureInventory(ForwardingModel):
    feature: ForwardingFeature
    status: Literal[DataStatus.KNOWN, DataStatus.ABSENT, DataStatus.UNKNOWN, DataStatus.UNSUPPORTED]
    item_count: int = Field(default=0, ge=0, strict=True)
    complete: bool = Field(default=False, strict=True)
    enumeration_complete: bool = Field(default=False, strict=True)
    source_document_ids: tuple[UUID, ...] = ()
    locations: tuple[ForwardingLocation, ...] = ()
    reference: str | None = Field(default=None, min_length=1)
    diagnostics: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_inventory(self) -> "FeatureInventory":
        if len(set(self.source_document_ids)) != len(self.source_document_ids):
            raise ValueError("источники inventory не должны повторяться")
        proven = self.status in {DataStatus.KNOWN, DataStatus.ABSENT}
        if proven != self.complete:
            raise ValueError("только known/absent inventory имеет доказанную полноту")
        if self.complete and not self.enumeration_complete:
            raise ValueError("семантическая полнота требует полного перечня")
        if self.enumeration_complete and (not self.reference or not self.source_document_ids):
            raise ValueError("полный перечень требует источники и основание")
        if proven and (not self.reference or not self.source_document_ids or self.diagnostics):
            raise ValueError("полный inventory требует источники, основание и чистую диагностику")
        if self.status == DataStatus.ABSENT and (self.item_count or self.locations):
            raise ValueError("absent inventory не содержит обнаруженных конструкций")
        if self.status == DataStatus.KNOWN and (not self.item_count or not self.locations):
            raise ValueError("known inventory требует непустые факты с source mapping")
        if any(item.source_document_id not in self.source_document_ids for item in self.locations):
            raise ValueError("позиция inventory должна ссылаться на его источник")
        anchors = [
            (item.source_document_id, item.location.model_dump_json()) for item in self.locations
        ]
        if len(set(anchors)) != len(anchors):
            raise ValueError("позиции inventory не должны повторяться")
        if (self.status == DataStatus.KNOWN or self.enumeration_complete) and len(
            self.locations
        ) < self.item_count:
            raise ValueError("каждый обнаруженный элемент требует позиции")
        return self


class ForwardingInterface(ForwardingModel):
    interface_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    physical_l3: bool | None = Field(default=None, strict=True)
    security_level: int | None = Field(default=None, ge=0, le=100, strict=True)
    security_status: Literal[DataStatus.KNOWN, DataStatus.UNKNOWN] = DataStatus.UNKNOWN
    location: ForwardingLocation

    @model_validator(mode="after")
    def validate_security(self) -> "ForwardingInterface":
        if (self.security_status == DataStatus.KNOWN) != (self.security_level is not None):
            raise ValueError("security-level не получает неявный default")
        return self


class ForwardingAcl(ForwardingModel):
    policy_id: str = Field(min_length=1)
    configuration_id: UUID
    semantics: Literal["first_match"] = "first_match"
    status: Literal[DataStatus.KNOWN, DataStatus.UNKNOWN, DataStatus.UNSUPPORTED]
    complete: bool = Field(default=False, strict=True)
    rules: tuple[Rule, ...] = ()
    location: ForwardingLocation
    reference: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_rules(self) -> "ForwardingAcl":
        if (self.status == DataStatus.KNOWN) != self.complete:
            raise ValueError("известный список ACL требует полноты")
        if self.complete and not self.reference:
            raise ValueError("полнота ACL требует явного основания")
        if any(
            rule.configuration_id != self.configuration_id or rule.policy_id != self.policy_id
            for rule in self.rules
        ):
            raise ValueError("ACE должен принадлежать своей ACL и конфигурации")
        sequences = [rule.sequence for rule in self.rules]
        if len(set(sequences)) != len(sequences) or len({r.rule_id for r in self.rules}) != len(
            self.rules
        ):
            raise ValueError("порядок и идентичность ACE должны быть однозначны")
        if sequences != sorted(sequences):
            raise ValueError("ACE сохраняются в возрастающем порядке")
        if any(
            rule.source_location.source_name != self.location.location.source_name
            for rule in self.rules
        ):
            raise ValueError("ACE source mapping должен относиться к документу своей ACL")
        for rule in self.rules:
            ForwardingLocation(
                source_document_id=self.location.source_document_id,
                location=rule.source_location,
            )
        if self.complete and any(
            rule.enabled
            and (
                rule.action
                not in {RuleAction.ALLOW, RuleAction.DENY, RuleAction.DROP, RuleAction.REJECT}
                or rule.policy_semantics != self.semantics
                or any(
                    status != DataStatus.KNOWN
                    for status in (
                        rule.match_status,
                        rule.source_status,
                        rule.destination_status,
                        rule.service_status,
                    )
                )
                or any(
                    endpoint.resolution_status != DataStatus.KNOWN
                    for endpoint in (*rule.sources, *rule.destinations)
                )
                or any(service.resolution_status != DataStatus.KNOWN for service in rule.services)
            )
            for rule in self.rules
        ):
            raise ValueError("полная известная ACL не скрывает неизвестные активные ACE")
        return self


class ForwardingBinding(ForwardingModel):
    policy_id: str = Field(min_length=1)
    direction: Literal["in", "out", "global"]
    interface_id: str | None = Field(default=None, min_length=1)
    location: ForwardingLocation

    @model_validator(mode="after")
    def validate_direction(self) -> "ForwardingBinding":
        if (self.direction == "global") != (self.interface_id is None):
            raise ValueError("global binding не имеет интерфейса; in/out требуют interface_id")
        return self


class ForwardingToggle(ForwardingModel):
    name: Literal["inter_interface", "intra_interface", "permit_vpn"]
    status: Literal[DataStatus.KNOWN, DataStatus.UNKNOWN, DataStatus.UNSUPPORTED]
    value: bool | None = Field(default=None, strict=True)
    location: ForwardingLocation | None = None

    @model_validator(mode="after")
    def validate_value(self) -> "ForwardingToggle":
        if self.status == DataStatus.KNOWN:
            if self.value is None or self.location is None:
                raise ValueError("известная настройка требует значения и source mapping")
        elif self.value is not None:
            raise ValueError("неизвестная настройка не содержит эффективного значения")
        return self


class FlowApplicability(ForwardingModel):
    query: ReachabilityQuery
    origin: Literal["synthetic", "operator_declared"]
    reference: str = Field(min_length=1)
    new_connection: bool | None = Field(default=None, strict=True)
    transit: bool | None = Field(default=None, strict=True)
    non_vpn: bool | None = Field(default=None, strict=True)
    non_fragment: bool | None = Field(default=None, strict=True)
    tcp_syn: bool | None = Field(default=None, strict=True)
    tcp_ack: bool | None = Field(default=None, strict=True)
    tcp_payload_length: int | None = Field(default=None, ge=0, strict=True)
    icmp_type: int | None = Field(default=None, ge=0, le=255, strict=True)
    icmp_code: int | None = Field(default=None, ge=0, le=255, strict=True)

    @model_validator(mode="after")
    def validate_protocol_details(self) -> "FlowApplicability":
        if self.query.protocol != Protocol.TCP and any(
            value is not None for value in (self.tcp_syn, self.tcp_ack, self.tcp_payload_length)
        ):
            raise ValueError("TCP признаки неприменимы к другому протоколу")
        if self.query.protocol != Protocol.ICMP and (
            self.icmp_type is not None or self.icmp_code is not None
        ):
            raise ValueError("ICMP type/code неприменимы к другому протоколу")
        return self


class ForwardingContext(ForwardingModel):
    schema_version: Literal["0.1.0"] = "0.1.0"
    revision_id: UUID
    configuration_id: UUID
    device_id: str = Field(min_length=1)
    device_context: str | None = Field(default=None, min_length=1)
    context_mode: Literal["single", "multiple"] | None = None
    firewall_mode: Literal["routed", "transparent"] | None = None
    address_family: Literal["ipv4", "ipv6", "mixed"] | None = None
    table_role: Literal["data", "management"] | None = None
    table_id: str | None = Field(default=None, min_length=1)
    profile_reference: str | None = Field(default=None, min_length=1)
    imported_at: datetime
    observed_at: datetime | None = None
    observation_window: ObservationWindow | None = None
    sources: tuple[ForwardingSource, ...] = ()
    inventories: tuple[FeatureInventory, ...] = ()
    interfaces: tuple[ForwardingInterface, ...] = ()
    acls: tuple[ForwardingAcl, ...] = ()
    bindings: tuple[ForwardingBinding, ...] = ()
    toggles: tuple[ForwardingToggle, ...] = ()
    flow: FlowApplicability | None = None

    @model_validator(mode="after")
    def validate_context(self) -> "ForwardingContext":
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
            raise ValueError("известные признаки профиля требуют отдельного основания")
        if self.context_mode == "single" and self.device_context is not None:
            raise ValueError("single context не содержит имени отдельного контекста")
        if self.imported_at.tzinfo is None or (
            self.observed_at is not None and self.observed_at.tzinfo is None
        ):
            raise ValueError("времена контекста требуют часовой пояс")
        if self.observed_at is not None and self.observed_at > self.imported_at:
            raise ValueError("наблюдение не может быть позже импорта")
        if self.observation_window and (
            self.observed_at is None
            or not self.observation_window.start <= self.observed_at <= self.observation_window.end
            or self.observation_window.end > self.imported_at
        ):
            raise ValueError("окно должно включать наблюдение и завершаться до импорта")
        sources = {source.source_document_id: source for source in self.sources}
        if len(sources) != len(self.sources) or len({s.source_name for s in self.sources}) != len(
            self.sources
        ):
            raise ValueError("UUID и имена источников контекста должны быть уникальны")
        for source in self.sources:
            if source.device_id != self.device_id or source.device_context != self.device_context:
                raise ValueError("источник относится к другому устройству/контексту")
            if source.captured_at > self.imported_at:
                raise ValueError("источник получен позже импорта")
        features = {inventory.feature: inventory for inventory in self.inventories}
        if len(features) != len(self.inventories):
            raise ValueError("inventory одной feature не должен повторяться")
        for inventory in self.inventories:
            if any(identifier not in sources for identifier in inventory.source_document_ids):
                raise ValueError("inventory ссылается на отсутствующий источник")
            for anchor in inventory.locations:
                source = sources[anchor.source_document_id]
                roles = {"configuration"}
                if inventory.feature == "effective_nat":
                    roles = {"effective_nat"}
                elif inventory.feature == "pbr":
                    roles.add("pbr_state")
                if source.purpose not in roles:
                    raise ValueError("роль источника позиции не соответствует feature")
                if inventory.enumeration_complete and not (
                    FEATURE_SCOPES[inventory.feature] & set(source.complete_scopes)
                ):
                    raise ValueError("источник позиции не доказывает релевантную полноту")
            if inventory.complete or inventory.enumeration_complete:
                coverage: set[ForwardingScope] = set()
                for identifier in inventory.source_document_ids:
                    source = sources[identifier]
                    observation = source.observation
                    if (
                        self.observed_at is None
                        or observation is None
                        or (
                            observation.observed_at != self.observed_at
                            if self.observation_window is None
                            else not self.observation_window.start
                            <= observation.observed_at
                            <= self.observation_window.end
                        )
                    ):
                        raise ValueError("полный inventory требует согласованного наблюдения")
                    coverage.update(source.complete_scopes)
                if not FEATURE_SCOPES[inventory.feature] <= coverage:
                    raise ValueError("источники не доказывают полноту требуемых feature scopes")
        locations = [item for inventory in self.inventories for item in inventory.locations]
        locations.extend(interface.location for interface in self.interfaces)
        locations.extend(acl.location for acl in self.acls)
        locations.extend(binding.location for binding in self.bindings)
        locations.extend(toggle.location for toggle in self.toggles if toggle.location is not None)
        for item in locations:
            mapped_source = sources.get(item.source_document_id)
            if mapped_source is None or item.location.source_name != mapped_source.source_name:
                raise ValueError("source mapping не соответствует документу контекста")
        interface_ids = {interface.interface_id for interface in self.interfaces}
        policy_ids = {acl.policy_id for acl in self.acls}
        if len(interface_ids) != len(self.interfaces) or len(policy_ids) != len(self.acls):
            raise ValueError("идентичности интерфейсов и ACL не должны повторяться")
        if len({interface.label.casefold() for interface in self.interfaces}) != len(
            self.interfaces
        ):
            raise ValueError("label интерфейсов должен быть однозначным")
        if any(acl.configuration_id != self.configuration_id for acl in self.acls):
            raise ValueError("ACL относится к другой конфигурации")
        if any(binding.policy_id not in policy_ids for binding in self.bindings):
            raise ValueError("binding требует существующий ACL inventory, включая пустой ACL")
        slots = [(binding.direction, binding.interface_id) for binding in self.bindings]
        if len(set(slots)) != len(slots):
            raise ValueError("конфликтующие bindings не разрешаются последней записью")
        if any(
            binding.interface_id is not None and binding.interface_id not in interface_ids
            for binding in self.bindings
        ):
            raise ValueError("binding требует существующий интерфейс")
        if len({toggle.name for toggle in self.toggles}) != len(self.toggles):
            raise ValueError("настройки не должны повторяться")
        fact_counts: tuple[tuple[ForwardingFeature, int], ...] = (
            ("interfaces", len(self.interfaces)),
            ("acl_definitions", len(self.acls)),
            ("acl_bindings", len(self.bindings)),
            ("same_security", len([t for t in self.toggles if t.name != "permit_vpn"])),
            ("vpn_bypass", len([t for t in self.toggles if t.name == "permit_vpn"])),
        )
        for feature, count in fact_counts:
            fact_inventory = features.get(feature)
            if fact_inventory is None and count:
                raise ValueError("факты требуют inventory своей области")
            if fact_inventory is not None and fact_inventory.item_count != count:
                raise ValueError("число фактов не совпадает с inventory")
        fact_locations: dict[ForwardingFeature, tuple[ForwardingLocation, ...]] = {
            "interfaces": tuple(item.location for item in self.interfaces),
            "acl_definitions": tuple(item.location for item in self.acls),
            "acl_bindings": tuple(item.location for item in self.bindings),
            "same_security": tuple(
                item.location
                for item in self.toggles
                if item.name != "permit_vpn" and item.location is not None
            ),
            "vpn_bypass": tuple(
                item.location
                for item in self.toggles
                if item.name == "permit_vpn" and item.location is not None
            ),
        }
        for feature, anchors in fact_locations.items():
            fact_inventory = features.get(feature)
            if fact_inventory is not None and any(
                anchor.source_document_id not in fact_inventory.source_document_ids
                or anchor not in fact_inventory.locations
                for anchor in anchors
            ):
                raise ValueError("факт не входит в source mapping inventory своей области")
        if (
            features.get("acl_definitions")
            and features["acl_definitions"].complete
            and any(not acl.complete for acl in self.acls)
        ):
            raise ValueError("known ACL inventory не скрывает неизвестные определения")
        if (
            features.get("interfaces")
            and features["interfaces"].complete
            and any(
                interface.physical_l3 is None or interface.security_status != DataStatus.KNOWN
                for interface in self.interfaces
            )
        ):
            raise ValueError("known interfaces не скрывает неизвестные свойства")
        for feature, names in (
            ("same_security", {"inter_interface", "intra_interface"}),
            ("vpn_bypass", {"permit_vpn"}),
        ):
            toggle_inventory = next(
                (item for item in self.inventories if item.feature == feature), None
            )
            if toggle_inventory is not None and toggle_inventory.complete:
                group = [toggle for toggle in self.toggles if toggle.name in names]
                if toggle_inventory.status == DataStatus.ABSENT or (
                    {toggle.name for toggle in group} != names
                    or any(toggle.status != DataStatus.KNOWN for toggle in group)
                ):
                    raise ValueError(
                        "настройки требуют явных effective значений, не absent defaults"
                    )
        if self.flow and (
            self.flow.query.revision_id != self.revision_id
            or self.flow.query.device_id != self.device_id
            or self.flow.query.device_context != self.device_context
        ):
            raise ValueError("поток относится к другому снимку/устройству/контексту")
        if self.flow and self.table_id is not None and self.flow.query.table_id != self.table_id:
            raise ValueError("поток относится к другой таблице")
        if self.flow and self.address_family in {"ipv4", "ipv6"}:
            family = "ipv4" if ip_address(self.flow.query.source_ip).version == 4 else "ipv6"
            if family != self.address_family:
                raise ValueError("семейство потока не совпадает с профилем")
        return self
