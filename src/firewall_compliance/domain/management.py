"""Configuration-only management facts and explicit organizational requirements."""

import re
from ipaddress import ip_address, ip_network
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.source import SourceLocation

ManagementKind = Literal[
    "telnet",
    "http",
    "admin_sources",
    "snmp_legacy",
    "snmp_write",
    "snmp_sources",
    "syslog",
    "ntp",
    "timeout",
    "banner",
]

AllowedValues = Annotated[tuple[str, ...], Field(strict=False)] | None


def normalize_server(value: str) -> str:
    """Normalize literal IP or DNS name without DNS/network access."""
    try:
        return str(ip_address(value))
    except ValueError:
        name = value.lower().rstrip(".")
        if (
            re.fullmatch(r"ip#?\d+", name)
            or len(name) > 253
            or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in name.split(".")
            )
        ):
            raise ValueError("expected IP address or DNS name") from None
        if re.fullmatch(r"[\d.]+", name):
            raise ValueError("invalid IP address") from None
        return name


class ManagementFact(DomainModel):
    """No raw lines, passwords, banner contents or SNMP communities are retained."""

    kind: ManagementKind
    scope: str
    value: str
    source_locations: tuple[SourceLocation, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_value(self) -> "ManagementFact":
        if self.kind in {"telnet", "http", "snmp_legacy", "snmp_write", "banner"}:
            if self.value not in {"true", "false"}:
                raise ValueError("expected explicit boolean management fact")
        elif self.kind == "timeout":
            if not self.value.isascii() or not self.value.isdecimal():
                raise ValueError("expected timeout in seconds")
        elif self.kind in {"admin_sources", "snmp_sources"}:
            for network in filter(None, self.value.split(",")):
                ip_network(network)
        else:
            normalize_server(self.value)
        return self


class ManagementIssue(DomainModel):
    kind: ManagementKind
    source_location: SourceLocation
    message: str = "Конструкция управления не поддержана или неоднозначна."


class ManagementInventory(DomainModel):
    parser_version: str = "1.0.0"
    platform: str
    complete_export: bool = Field(default=False, strict=True)
    source_location: SourceLocation
    facts: tuple[ManagementFact, ...] = ()
    issues: tuple[ManagementIssue, ...] = ()


class ManagementProfile(DomainModel):
    """None means an organizational allowlist has not been provided; () denies all."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    profile_id: str = Field(default="baseline", min_length=1)
    version: str = Field(default="1", min_length=1)
    approved_admin_networks: AllowedValues = None
    approved_snmp_networks: AllowedValues = None
    approved_syslog_servers: AllowedValues = None
    approved_ntp_servers: AllowedValues = None
    allow_snmp_write: bool = False
    require_syslog: bool = True
    require_ntp: bool = True
    require_banner: bool = True
    max_idle_seconds: int = Field(default=900, ge=1, le=86400)

    @field_validator("approved_admin_networks", "approved_snmp_networks")
    @classmethod
    def networks(cls, values: tuple[str, ...] | None) -> tuple[str, ...] | None:
        return None if values is None else tuple(str(ip_network(v, strict=True)) for v in values)

    @field_validator("approved_syslog_servers", "approved_ntp_servers")
    @classmethod
    def servers(cls, values: tuple[str, ...] | None) -> tuple[str, ...] | None:
        return None if values is None else tuple(normalize_server(v) for v in values)
