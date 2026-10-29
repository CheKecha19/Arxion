"""Declared policy associations, independent of effective application semantics."""

from typing import Any, Literal

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.source import SourceLocation


class PolicyAttachment(DomainModel):
    """One source declaration attaching an ACL to a role within one revision.

    A position is the declared position only. This record does not establish
    effective order, active user membership, direction or packet processing.
    """

    attachment_id: str = Field(min_length=1, max_length=256)
    policy_id: str = Field(min_length=1, max_length=256)
    subject_kind: Literal["user_role", "interface"] = "user_role"
    subject_id: str = Field(min_length=1, max_length=256)
    direction: Literal["in", "out"] | None = None
    declaration_position: int | None = Field(default=None, ge=0, strict=True)
    scope_reference: str | None = Field(default=None, min_length=1, max_length=1024)
    source_location: SourceLocation

    @model_validator(mode="after")
    def validate_subject(self) -> "PolicyAttachment":
        if (self.subject_kind == "interface") != (self.direction is not None):
            raise ValueError(
                "interface attachments require in/out; user roles do not have direction"
            )
        return self

    @model_serializer(mode="wrap")
    def omit_legacy_direction(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.direction is None:
            payload.pop("direction", None)
        return payload
