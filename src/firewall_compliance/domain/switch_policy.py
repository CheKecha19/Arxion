"""Объявления и применения политик коммутаторов без догадок о пути пакета."""

import re
from typing import Any, Literal, Self

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.network import Endpoint, Service
from firewall_compliance.domain.source import SourceLocation

type PolicyPurpose = Literal["transit", "management", "unbound", "unknown"]
type AclMatchOrder = Literal["config", "auto"]
type ConfiguredAclProfile = Literal["hpe-flexfabric-5944-5945-r6622"]


def rule_purpose(rule: Rule) -> PolicyPurpose:
    """Старая management-маркировка остаётся значимой без миграции по имени ACL."""
    if rule.policy_purpose is not None:
        return rule.policy_purpose
    if (rule.policy_id or "").startswith("management:"):
        return "management"
    if rule.policy_semantics == "first_match" and rule.policy_direction is not None:
        return "transit"
    return "unknown"


def is_transit_rule(rule: Rule) -> bool:
    """Явные категории обязательны для новых импортов; legacy сохраняет прежнюю область."""
    if rule.policy_purpose is not None:
        return rule.policy_purpose == "transit"
    return not (rule.policy_id or "").startswith("management:")


class PolicyImportIssue(DomainModel):
    code: str
    message: str
    source_location: SourceLocation


class AceDeclaration(DomainModel):
    entry_id: str
    sequence: int
    action: str
    source_locations: tuple[SourceLocation, ...]
    raw_source: str | None = None
    raw_destination: str | None = None
    protocol: str | None = None
    raw_source_ports: str | None = None
    raw_destination_ports: str | None = None
    sources: tuple[Endpoint, ...] = ()
    destinations: tuple[Endpoint, ...] = ()
    services: tuple[Service, ...] = ()
    rule_ids: tuple[str, ...] = ()
    valid: bool = False


class AclDeclaration(DomainModel):
    acl_id: str
    name: str
    address_family: Literal["ipv4"] = "ipv4"
    acl_type: Literal["standard", "extended"] | None = None
    entries: tuple[AceDeclaration, ...] = ()
    source_locations: tuple[SourceLocation, ...]
    match_order: AclMatchOrder | None = None

    @model_serializer(mode="wrap")
    def serialize_match_order(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.match_order is None:
            payload.pop("match_order", None)
        return payload


class AclBinding(DomainModel):
    binding_id: str
    acl_id: str
    purpose: PolicyPurpose
    subject: str
    service: str | None = None
    vrf: str | None = None
    direction: str | None = None
    source_locations: tuple[SourceLocation, ...]
    implicit_action: Literal["allow", "deny", "unknown"] = "unknown"
    semantics: str | None = None
    implicit_action_reference: str | None = None
    configured_profile: ConfiguredAclProfile | None = None

    @model_validator(mode="after")
    def validate_configured_profile(self) -> Self:
        if self.configured_profile is None:
            return self
        vlan = re.fullmatch(r"interface:vlan:([1-9][0-9]{0,3})", self.subject)
        if (
            self.purpose != "transit" or self.direction != "routed-in" or self.semantics != "first_match"
            or vlan is None or int(vlan[1]) > 4094 or not re.fullmatch(r"ipv4:3[0-9]{3}", self.acl_id)
            or not self.vrf or not self.source_locations or any(loc.line_start is None for loc in self.source_locations)
            or self.implicit_action != "unknown" or self.implicit_action_reference is not None
        ):
            raise ValueError("Подтверждённый профиль Comware требует входящего маршрутизируемого VLAN ACL")
        return self

    @model_serializer(mode="wrap")
    def serialize_configured_profile(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.configured_profile is None:
            payload.pop("configured_profile", None)
        return payload


class ManagerAccess(DomainModel):
    manager_id: str
    source_raw: str
    source_cidr: str | None = None
    method: str
    privilege: str
    valid: bool = False
    source_locations: tuple[SourceLocation, ...]


class SwitchPolicySummary(DomainModel):
    acl_count: int = 0
    ace_count: int = 0
    binding_count: int = 0
    manager_count: int = 0
    transit_bindings: int = 0
    management_bindings: int = 0
    unbound_acls: int = 0
    unknown_bindings: int = 0
    invalid_entries: int = 0
    invalid_managers: int = 0


class PolicyAreaCoverage(DomainModel):
    """Покрытие ограниченного среза, а не гарантия полного running-config."""

    area: Literal["acl", "bindings", "managers"]
    state: Literal["partial", "not_observed", "unknown"]
    recognized_constructs: int = Field(default=0, ge=0)
    unsupported_constructs: int = Field(default=0, ge=0)
    source_locations: tuple[SourceLocation, ...] = ()


class SwitchPolicies(DomainModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    declarations: tuple[AclDeclaration, ...] = ()
    bindings: tuple[AclBinding, ...] = ()
    managers: tuple[ManagerAccess, ...] = ()
    detection_reasons: tuple[str, ...] = ()
    issues: tuple[PolicyImportIssue, ...] = ()
    coverage: tuple[PolicyAreaCoverage, ...] = ()
    source_name: str
    content_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    summary: SwitchPolicySummary = Field(default_factory=SwitchPolicySummary)

    @model_validator(mode="after")
    def refresh_summary(self) -> "SwitchPolicies":
        """Сохранять счётчики в JSON, пересчитывая их по данным при чтении."""
        entities = [
            *(acl.acl_id for acl in self.declarations),
            *(entry.entry_id for acl in self.declarations for entry in acl.entries),
            *(binding.binding_id for binding in self.bindings),
            *(manager.manager_id for manager in self.managers),
        ]
        if len(entities) != len(set(entities)):
            raise ValueError("идентификаторы объявлений и применений политик должны быть уникальны")
        if len({item.area for item in self.coverage}) != len(self.coverage):
            raise ValueError("область покрытия политик не должна повторяться")
        locations = [
            *(loc for acl in self.declarations for loc in acl.source_locations),
            *(loc for acl in self.declarations for entry in acl.entries for loc in entry.source_locations),
            *(loc for binding in self.bindings for loc in binding.source_locations),
            *(loc for manager in self.managers for loc in manager.source_locations),
            *(issue.source_location for issue in self.issues),
            *(loc for area in self.coverage for loc in area.source_locations),
        ]
        if any(loc.source_name != self.source_name for loc in locations):
            raise ValueError("ссылки политик должны принадлежать исходному документу")
        linked = {binding.acl_id for binding in self.bindings}
        summary = SwitchPolicySummary(
            acl_count=len(self.declarations),
            ace_count=sum(len(acl.entries) for acl in self.declarations),
            binding_count=len(self.bindings),
            manager_count=len(self.managers),
            transit_bindings=sum(b.purpose == "transit" for b in self.bindings),
            management_bindings=sum(b.purpose == "management" for b in self.bindings),
            unbound_acls=sum(acl.acl_id not in linked for acl in self.declarations),
            unknown_bindings=sum(b.purpose == "unknown" for b in self.bindings),
            invalid_entries=sum(not entry.valid for acl in self.declarations for entry in acl.entries),
            invalid_managers=sum(not manager.valid for manager in self.managers),
        )
        # validate_assignment не должен повторно вызывать этот же валидатор.
        object.__setattr__(self, "summary", summary)
        return self
