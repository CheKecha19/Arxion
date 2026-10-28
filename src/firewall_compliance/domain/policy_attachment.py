"""Declared policy associations, independent of effective application semantics."""

from typing import Literal

from pydantic import Field

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.source import SourceLocation


class PolicyAttachment(DomainModel):
    """One source declaration attaching an ACL to a role within one revision.

    A position is the declared position only. This record does not establish
    effective order, active user membership, direction or packet processing.
    """

    attachment_id: str = Field(min_length=1, max_length=256)
    policy_id: str = Field(min_length=1, max_length=256)
    subject_kind: Literal["user_role"] = "user_role"
    subject_id: str = Field(min_length=1, max_length=256)
    declaration_position: int | None = Field(default=None, ge=0, strict=True)
    scope_reference: str | None = Field(default=None, min_length=1, max_length=1024)
    source_location: SourceLocation
