"""Address lookups require both an explicit context and an observation snapshot.

The legacy map has no authoritative organization UUID. Its opaque local scopes
must remain opaque, rather than manufacturing AddressContext organization IDs.
Organization callers may index validated AssetAddressBinding values directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address

from firewall_compliance.application.asset_identity import AddressContext, AssetAddressBinding


@dataclass(frozen=True, slots=True)
class CatalogObservation:
    """A resource label/aliases with evidence, not a new persistent identity."""

    resource_key: str
    display_name: str
    aliases: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value in (self.resource_key, self.display_name):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Catalog observation keys and names must be nonempty")
        for field in ("aliases", "evidence_refs"):
            values = getattr(self, field)
            if isinstance(values, (str, bytes)):
                raise TypeError("Catalog observation collections must not be strings")
            values = tuple(values)
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError("Catalog observation references must be nonempty strings")
            object.__setattr__(self, field, tuple(dict.fromkeys(values)))


class SnapshotAddressIndex:
    """Deduplicated candidates; ambiguous addresses never select an arbitrary name."""

    def __init__(self) -> None:
        self._values: dict[
            tuple[str | AddressContext, str, str], dict[str, CatalogObservation]
        ] = {}

    @staticmethod
    def _key(
        context: str | AddressContext, snapshot_id: str, address: str
    ) -> tuple[str | AddressContext, str, str]:
        if isinstance(context, str):
            if not context.strip():
                raise ValueError("An explicit address context is required")
        elif not isinstance(context, AddressContext):
            raise TypeError("Address context must be an explicit scope or AddressContext")
        if not isinstance(snapshot_id, str) or not snapshot_id.strip():
            raise ValueError("An observation snapshot is required")
        return context, snapshot_id, str(ip_address(address))

    def add(
        self,
        observation: CatalogObservation,
        *,
        context: str | AddressContext,
        snapshot_id: str,
        address: str,
    ) -> None:
        key = self._key(context, snapshot_id, address)
        values = self._values.setdefault(key, {})
        previous = values.get(observation.resource_key)
        if previous is not None and previous != observation:
            raise ValueError("Conflicting observations for one resource within a snapshot")
        values[observation.resource_key] = observation

    def add_binding(self, observation: CatalogObservation, binding: AssetAddressBinding) -> None:
        """Use authoritative organization context only when supplied by its owner."""
        observed = CatalogObservation(
            observation.resource_key,
            observation.display_name,
            observation.aliases,
            tuple(dict.fromkeys((*observation.evidence_refs, *binding.evidence_refs))),
        )
        self.add(
            observed,
            context=binding.context,
            snapshot_id=binding.snapshot_id,
            address=binding.address,
        )

    def resolve(
        self, *, context: str | AddressContext, snapshot_id: str, address: str
    ) -> tuple[CatalogObservation, ...]:
        return tuple(self._values.get(self._key(context, snapshot_id, address), {}).values())
