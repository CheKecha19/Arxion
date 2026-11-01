"""Validated immutable workspace selections, independent of Qt and persistence."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


def workspace_uuid(value: UUID | str) -> UUID:
    """Normalize workspace keys without accepting arbitrary object's repr."""
    if not isinstance(value, (UUID, str)):
        raise TypeError("workspace identifiers must be UUID values")
    return UUID(str(value))


@dataclass(frozen=True, slots=True)
class WorkspaceScope:
    """Empty site_ids selects an organization, including unassigned resources.

    Site IDs are explicit assignments, never inferred from legacy project IDs.
    Membership is a selection only; it does not establish permission to access data.
    """

    organization_id: UUID
    site_ids: frozenset[UUID] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "organization_id", workspace_uuid(self.organization_id))
        if isinstance(self.site_ids, (str, bytes)):
            raise TypeError("site_ids must be a collection of UUID values")
        object.__setattr__(
            self, "site_ids", frozenset(workspace_uuid(site) for site in self.site_ids)
        )

    @property
    def whole_organization(self) -> bool:
        return not self.site_ids

    def includes(self, organization_id: UUID, site_id: UUID | None) -> bool:
        """Check explicit membership without promoting unassigned assets to a site."""
        organization = workspace_uuid(organization_id)
        site = workspace_uuid(site_id) if site_id is not None else None
        return organization == self.organization_id and (
            self.whole_organization or site in self.site_ids
        )
