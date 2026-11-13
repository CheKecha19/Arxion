"""Объявления SG и ссылки интерфейсов в одном сохранённом сборе Cloud.ru."""

from typing import Literal

from pydantic import AwareDatetime, Field

from firewall_compliance.domain.controls import ControlModel
from firewall_compliance.domain.network import PortRange
from firewall_compliance.domain.source import SourceLocation

type CloudSGPlatform = Literal["advanced", "evolution"]
type SGDirection = Literal["ingress", "egress"]
type SGResolution = Literal["present", "missing", "ambiguous", "outside_scope"]
type SGStatus = Literal["present", "partial", "missing", "ambiguous", "outside_scope"]


class CloudSGPeer(ControlModel):
    kind: Literal["network", "security_group", "address_group", "unknown"]
    cidr: str | None = None
    reference_id: str | None = None
    reference_state: SGResolution | None = None


class CloudSGService(ControlModel):
    protocol: Literal["any", "tcp", "udp", "icmp", "icmpv6", "number"]
    protocol_number: int | None = Field(default=None, ge=0, le=255)
    ports: tuple[PortRange, ...] = ()
    any_ports: bool = False
    icmp_type: int | None = Field(default=None, ge=0, le=255)
    icmp_code: int | None = Field(default=None, ge=0, le=255)


class CloudSGRule(ControlModel):
    rule_id: str | None = None
    direction: SGDirection | None = None
    family: Literal[4, 6] | None = None
    action: Literal["allow", "deny", "unknown"]
    priority: int | None = Field(default=None, ge=1, le=100)
    enabled: bool | None = None
    provider_status: str | None = None
    service: CloudSGService | None = None
    peer: CloudSGPeer
    location: SourceLocation
    limitations: tuple[str, ...] = ()


class CloudSGDeclaration(ControlModel):
    group_id: str
    name: str
    scope_id: str
    project_id: str | None = None
    zone_id: str | None = None
    network_id: str | None = None
    locations: tuple[SourceLocation, ...]
    rules: tuple[CloudSGRule, ...] = ()
    rules_status: SGStatus


class CloudSGAssignment(ControlModel):
    group_id: str
    state: SGResolution
    locations: tuple[SourceLocation, ...] = ()


class CloudSGInterface(ControlModel):
    interface_id: str
    name: str
    scope_id: str
    project_id: str | None = None
    vm_id: str | None = None
    subnet_id: str | None = None
    zone_id: str | None = None
    network_id: str | None = None
    addresses: tuple[str, ...] = ()
    security_enabled: bool | None = None
    assignments: tuple[CloudSGAssignment, ...] = ()
    assignments_status: SGStatus
    locations: tuple[SourceLocation, ...]


class CloudSGDiagnostic(ControlModel):
    code: str
    message: str
    location: SourceLocation


class CloudSecurityGroupSnapshot(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    platform: CloudSGPlatform
    scan_id: str = Field(min_length=1)
    scan_status: Literal["completed", "partial", "failed", "cancelled", "interrupted", "unknown"]
    scope_id: str = Field(min_length=1)
    captured_at: AwareDatetime
    project_id: str | None = None
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_site_ids: tuple[str, ...] = ()
    record_indices: tuple[int, ...] = ()
    rule_semantics: Literal["advanced_priority", "evolution_allow_union"]
    groups: tuple[CloudSGDeclaration, ...] = ()
    interfaces: tuple[CloudSGInterface, ...] = ()
    diagnostics: tuple[CloudSGDiagnostic, ...] = ()
    limitations: tuple[str, ...] = (
        "Оцениваются объявления и подтверждённые ссылки одного сбора.",
        "Применение правил, порядок нескольких SG и доступность сети не рассчитаны.",
        "Отсутствие правил или назначений не доказывает запрет.",
    )


CloudSecurityGroupIndex = CloudSecurityGroupSnapshot
