"""Context-aware immutable asset read models; no implicit address-based merging."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Literal
from uuid import UUID

from firewall_compliance.application.workspace_scope import WorkspaceScope, workspace_uuid


def _text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


@dataclass(frozen=True, slots=True)
class AddressContext:
    """Explicit isolated address-space identity, independent of physical location.

    The collector or an explicit binding must establish this context. Matching
    names, IPs or VLAN numbers alone must not create a shared context.
    """

    organization_id: UUID
    namespace: str
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "organization_id", workspace_uuid(self.organization_id))
        _text(self.namespace, "namespace")
        _text(self.value, "value")


@dataclass(frozen=True, slots=True)
class AssetIdentity:
    """Stable resource identity; display names and addresses are not its key."""

    organization_id: UUID
    asset_id: UUID

    def __post_init__(self) -> None:
        object.__setattr__(self, "organization_id", workspace_uuid(self.organization_id))
        object.__setattr__(self, "asset_id", workspace_uuid(self.asset_id))


@dataclass(frozen=True, slots=True)
class AssetAddressBinding:
    """An observed address assignment with explicit context and snapshot evidence."""

    context: AddressContext
    address: str
    source_id: str
    snapshot_id: str
    evidence_refs: tuple[str, ...]
    interface_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.context, AddressContext):
            raise TypeError("context must be AddressContext")
        object.__setattr__(self, "address", str(ip_address(self.address)))
        _text(self.source_id, "source_id")
        _text(self.snapshot_id, "snapshot_id")
        if isinstance(self.evidence_refs, (str, bytes)):
            raise TypeError("evidence_refs must be a collection")
        refs = tuple(_text(ref, "evidence reference") for ref in self.evidence_refs)
        if not refs:
            raise ValueError("an address binding requires evidence")
        object.__setattr__(self, "evidence_refs", refs)
        if self.interface_id is not None:
            _text(self.interface_id, "interface_id")


@dataclass(frozen=True, slots=True)
class AssetReadModel:
    """Immutable projection of one resource, separate from its source snapshots."""

    identity: AssetIdentity
    display_name: str
    site_id: UUID | None = None
    aliases: tuple[str, ...] = ()
    addresses: tuple[AssetAddressBinding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.identity, AssetIdentity):
            raise TypeError("identity must be AssetIdentity")
        _text(self.display_name, "display_name")
        if self.site_id is not None:
            object.__setattr__(self, "site_id", workspace_uuid(self.site_id))
        if isinstance(self.aliases, (str, bytes)):
            raise TypeError("aliases must be a collection")
        object.__setattr__(self, "aliases", tuple(_text(a, "alias") for a in self.aliases))
        bindings = tuple(self.addresses)
        for binding in bindings:
            if not isinstance(binding, AssetAddressBinding):
                raise TypeError("addresses must contain AssetAddressBinding values")
            if binding.context.organization_id != self.identity.organization_id:
                raise ValueError("address binding belongs to another organization")
        object.__setattr__(self, "addresses", bindings)


@dataclass(frozen=True, slots=True)
class AddressResolution:
    """Candidates within one explicit context and snapshot, not reachability."""

    candidates: tuple[AssetReadModel, ...]

    def __post_init__(self) -> None:
        values = tuple(self.candidates)
        if any(not isinstance(value, AssetReadModel) for value in values):
            raise TypeError("candidates must contain AssetReadModel values")
        if len({value.identity for value in values}) != len(values):
            raise ValueError("duplicate asset identities in resolution")
        object.__setattr__(self, "candidates", values)

    @property
    def status(self) -> Literal["not_found", "unique", "ambiguous"]:
        if not self.candidates:
            return "not_found"
        return "unique" if len(self.candidates) == 1 else "ambiguous"


def select_assets(
    assets: tuple[AssetReadModel, ...], scope: WorkspaceScope
) -> tuple[AssetReadModel, ...]:
    """Select a scope without guessing site assignments for legacy origins."""
    return tuple(
        asset
        for asset in assets
        if scope.includes(asset.identity.organization_id, asset.site_id)
    )


def resolve_address(
    assets: tuple[AssetReadModel, ...],
    *,
    context: AddressContext,
    address: str,
    snapshot_id: str,
) -> AddressResolution:
    """Resolve only co-observed bindings; historical addresses never match silently.

    Different source snapshots must first be explicitly reconciled by their
    caller; this function does not infer time equivalence or NAT mappings.
    """
    _text(snapshot_id, "snapshot_id")
    canonical = str(ip_address(address))
    selected: dict[AssetIdentity, AssetReadModel] = {}
    for asset in assets:
        if any(
            binding.context == context
            and binding.address == canonical
            and binding.snapshot_id == snapshot_id
            for binding in asset.addresses
        ):
            previous = selected.get(asset.identity)
            if previous is not None and previous != asset:
                raise ValueError("conflicting read models for one asset identity")
            selected[asset.identity] = asset
    return AddressResolution(tuple(selected.values()))
