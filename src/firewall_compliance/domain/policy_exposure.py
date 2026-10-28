"""Explicit organizational policy for declared service exposure reviews."""

from ipaddress import ip_network
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.network import PortRange


class PolicyServiceSelector(DomainModel):
    """A named organizational service requirement, never guessed from a port."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    selector_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    protocol: Literal["tcp", "udp", "icmp"]
    port_ranges: tuple[PortRange, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_protocol_ports(self) -> "PolicyServiceSelector":
        if self.protocol in {"tcp", "udp"} and not self.port_ranges:
            raise ValueError("TCP/UDP selector requires explicit destination port ranges")
        if self.protocol == "icmp" and self.port_ranges:
            raise ValueError("ICMP selector cannot contain destination ports")
        return self


class PolicyExposureProfile(DomainModel):
    """None means unknown policy; an empty tuple is an explicit empty requirement."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    schema_version: Literal["1.0.0"] = "1.0.0"
    profile_id: str = Field(default="policy-exposure", min_length=1, max_length=128)
    version: str = Field(default="1", min_length=1, max_length=64)
    dangerous_services: tuple[PolicyServiceSelector, ...] | None = Field(
        default=None, max_length=256
    )
    administrative_services: tuple[PolicyServiceSelector, ...] | None = Field(
        default=None, max_length=256
    )
    administrative_targets: tuple[str, ...] | None = Field(default=None, max_length=4096)
    trusted_admin_networks: tuple[str, ...] | None = Field(default=None, max_length=4096)

    @field_validator("administrative_targets", "trusted_admin_networks")
    @classmethod
    def normalize_networks(cls, values: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if values is None:
            return None
        return tuple(dict.fromkeys(str(ip_network(value, strict=False)) for value in values))

    @field_validator("dangerous_services", "administrative_services")
    @classmethod
    def validate_selector_ids(
        cls, values: tuple[PolicyServiceSelector, ...] | None
    ) -> tuple[PolicyServiceSelector, ...] | None:
        if values is not None and len({value.selector_id for value in values}) != len(values):
            raise ValueError("selector IDs must be unique within a catalogue")
        return values
