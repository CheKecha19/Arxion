"""Versioned access requirements, separate from technical controls and reachability."""

from datetime import date
from ipaddress import ip_network
from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from firewall_compliance.domain.controls import ControlModel
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.network import PortRange

MatrixState = Literal[
    "declared_match", "declared_conflict", "insufficient_evidence",
    "unregulated", "requirement_conflict", "not_applicable",
]


class MatrixMember(ControlModel):
    kind: Literal["network", "object", "group"]
    value: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_network(self) -> "MatrixMember":
        if self.kind == "network":
            ip_network(self.value, strict=False)
        return self


class MatrixGroup(ControlModel):
    group_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    members: tuple[MatrixMember, ...] = Field(default=(), max_length=4096)


class MatrixService(ControlModel):
    protocol: Literal["ip", "tcp", "udp", "icmp"]
    ports: tuple[PortRange, ...] = Field(default=(), max_length=128)
    any_ports: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def validate_ports(self) -> "MatrixService":
        if self.protocol in {"tcp", "udp"}:
            if bool(self.ports) == self.any_ports:
                raise ValueError("specify explicit port ranges or any_ports, exclusively")
        elif self.ports or self.any_ports:
            raise ValueError("ports apply only to TCP/UDP")
        return self


class MatrixRequirement(ControlModel):
    requirement_id: str = Field(min_length=1, max_length=128)
    source_group: str = Field(min_length=1, max_length=128)
    destination_group: str = Field(min_length=1, max_length=128)
    service: MatrixService
    requirement: Literal["permit", "deny", "unregulated"] = "unregulated"
    scope_id: str = Field(min_length=1, max_length=256)
    policy_id: str | None = Field(default=None, min_length=1, max_length=256)
    owner: str | None = Field(default=None, min_length=1, max_length=256)
    review_date: date | None = None
    reason: str | None = Field(default=None, min_length=1, max_length=4096)
    identity: str | None = Field(default=None, min_length=1, max_length=512)
    schedule: str | None = Field(default=None, min_length=1, max_length=512)


class AccessMatrix(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    matrix_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    default_requirement: Literal["unregulated"] = "unregulated"
    groups: tuple[MatrixGroup, ...] = Field(default=(), max_length=256)
    requirements: tuple[MatrixRequirement, ...] = Field(default=(), max_length=512)


class MatrixDiagnostic(ControlModel):
    code: str
    message: str
    group_ids: tuple[str, ...] = ()
    requirement_ids: tuple[str, ...] = ()


class MatrixRequirementAssessment(ControlModel):
    requirement_id: str
    state: MatrixState
    evidence: tuple[Evidence, ...] = ()
    reasons: tuple[str, ...] = ()


class MatrixAssessment(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    mode: Literal["declared_rules"] = "declared_rules"
    matrix_id: str
    matrix_version: str
    revision_id: UUID
    profile_id: str = Field(min_length=1)
    profile_version: str = Field(min_length=1)
    scope_id: str = Field(min_length=1)
    diagnostics: tuple[MatrixDiagnostic, ...] = ()
    requirements: tuple[MatrixRequirementAssessment, ...] = ()
    limitations: tuple[str, ...] = (
        "Оцениваются заданные условия правил; порядок, NAT, маршрутизация и сквозная доступность не вычисляются.",
        "Отсутствие строки матрицы означает: не регламентировано.",
    )
