"""Explicit organization inputs for excessive-access and ACL-attachment checks."""

from ipaddress import ip_network
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.policy_exposure import PolicyServiceSelector
from firewall_compliance.domain.snapshot import freeze_snapshot_fields


def _networks(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(ip_network(value, strict=False)) for value in values))


class RoleAccessRequirement(DomainModel):
    requirement_id: str = Field(min_length=1, max_length=128)
    role_id: str = Field(min_length=1, max_length=128)
    destination_networks: tuple[str, ...] = Field(min_length=1, max_length=256)
    approved_source_networks: tuple[str, ...] = Field(max_length=256)
    approved_services: tuple[PolicyServiceSelector, ...] = Field(max_length=256)

    _normalize_destinations = field_validator("destination_networks", mode="before")(
        lambda value: _networks(tuple(value))
    )
    _normalize_sources = field_validator("approved_source_networks", mode="before")(
        lambda value: _networks(tuple(value))
    )

    @model_validator(mode="after")
    def unique_services(self) -> "RoleAccessRequirement":
        identifiers = [value.selector_id for value in self.approved_services]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("approved service selector IDs must be unique per role requirement")
        return self


class RequiredPolicyAttachment(DomainModel):
    requirement_id: str = Field(min_length=1, max_length=128)
    subject_kind: Literal["user_role", "interface"]
    subject_id: str = Field(min_length=1, max_length=256)
    direction: Literal["in", "out"] | None = None
    allowed_policy_ids: tuple[str, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def validate_direction(self) -> "RequiredPolicyAttachment":
        if (self.subject_kind == "interface") != (self.direction is not None):
            raise ValueError("interface requirements need in/out; user roles do not have direction")
        if len(set(self.allowed_policy_ids)) != len(self.allowed_policy_ids):
            raise ValueError("allowed policy IDs must be unique")
        return self


class PolicyScopeProfile(DomainModel):
    """Versioned, immutable organization policy; None means an unknown requirement."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    profile_id: str = Field(default="policy-scope", min_length=1, max_length=128)
    version: str = Field(default="1", min_length=1, max_length=64)
    excessive_access_enabled: bool | None = None
    max_source_addresses: int | None = Field(default=None, ge=1, strict=True)
    max_destination_addresses: int | None = Field(default=None, ge=1, strict=True)
    max_destination_ports: int | None = Field(default=None, ge=1, le=65536, strict=True)
    role_requirements: tuple[RoleAccessRequirement, ...] | None = Field(
        default=None, max_length=256
    )
    exception_rule_ids: tuple[str, ...] = Field(default=(), max_length=4096)
    attachment_inventory_complete: bool | None = None
    required_attachments: tuple[RequiredPolicyAttachment, ...] | None = Field(
        default=None, max_length=1024
    )

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        if self.excessive_access_enabled is False and any(
            value is not None
            for value in (
                self.max_source_addresses,
                self.max_destination_addresses,
                self.max_destination_ports,
            )
        ):
            raise ValueError("disabled excessive-access thresholds must be omitted")
        if self.excessive_access_enabled is True and all(
            value is None
            for value in (
                self.max_source_addresses,
                self.max_destination_addresses,
                self.max_destination_ports,
            )
        ):
            raise ValueError("enabled excessive-access policy requires at least one threshold")
        identifiers = [
            value.requirement_id
            for collection in (self.role_requirements or (), self.required_attachments or ())
            for value in collection
        ]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("requirement IDs must be unique across the profile")
        if len(self.exception_rule_ids) != len(set(self.exception_rule_ids)):
            raise ValueError("exception rule IDs must be unique")
        freeze_snapshot_fields(self)
        return self

    def as_snapshot(self) -> "PolicyScopeProfile":
        return PolicyScopeProfile.model_validate(self.model_dump(mode="python"))
