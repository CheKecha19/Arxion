"""Versioned pure codec for complete saved network-map input snapshots."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.forwarding import ForwardingContext
from firewall_compliance.domain.revision import DeviceRevision


class MapNetworkFactsError(ValueError):
    """A map-facts envelope is malformed or its identities do not agree."""


class UnsupportedMapNetworkFactsError(MapNetworkFactsError):
    """A version or value cannot be represented by this fixed codec."""


class MapFactsOwner(BaseModel):
    """Exact analysis owner, separate from the imported network revision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0.0"] = "1.0.0"
    project_id: str = Field(strict=True, min_length=1)
    run_id: str = Field(strict=True, min_length=1)
    item_id: str = Field(strict=True, min_length=1)
    analysis_revision_id: UUID
    source_document_ids: tuple[UUID, ...]
    association: Literal["exact_same_revision", "explicit_attachment"]

    @field_validator("project_id", "run_id", "item_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        """Preserve opaque IDs exactly while rejecting blank boundaries."""
        if not value.strip():
            raise ValueError("Owner ID must not be blank")
        return value

    @model_validator(mode="after")
    def validate_sources(self) -> Self:
        """Require explicit, unique original source identifiers."""
        if not self.source_document_ids or len(set(self.source_document_ids)) != len(
            self.source_document_ids
        ):
            raise ValueError("Owner requires nonempty unique source document IDs")
        return self


@dataclass(frozen=True, slots=True)
class MapNetworkFacts:
    """Full network documents and a separate optional bound forwarding context."""

    network_import: NetworkImportResult
    forwarding: ForwardingContext | None = None
    owner: MapFactsOwner | None = None

    def __post_init__(self) -> None:
        imported = self.network_import.as_snapshot()
        context = self.forwarding.as_snapshot() if self.forwarding is not None else None
        owner = (
            MapFactsOwner.model_validate(self.owner.model_dump(mode="python"))
            if self.owner
            else None
        )
        if (
            owner is not None
            and owner.association == "exact_same_revision"
            and (
                owner.analysis_revision_id != imported.revision.revision_id
                or set(owner.source_document_ids)
                != {source.source_document_id for source in imported.revision.sources}
            )
        ):
            raise MapNetworkFactsError("owner: exact revision/source anchors do not match")
        if context is not None:
            revision = imported.revision
            if (
                context.revision_id != revision.revision_id
                or context.configuration_id != revision.parse_result.configuration.configuration_id
                or context.device_id != revision.device.device_id
                or context.device_context != revision.device.context
                or context.imported_at != revision.imported_at
                or context.observed_at != revision.observed_at
                or context.observation_window != revision.observation_window
            ):
                raise MapNetworkFactsError("forwarding: revision/context boundary mismatch")
            sources = {source.source_document_id: source for source in revision.sources}
            for source in context.sources:
                original = sources.get(source.source_document_id)
                if original is None or (
                    original.source_name,
                    original.content_sha256.lower(),
                    original.captured_at,
                    original.observation,
                ) != (
                    source.source_name,
                    source.content_sha256.lower(),
                    source.captured_at,
                    source.observation,
                ):
                    raise MapNetworkFactsError("forwarding.sources: original anchor mismatch")
        object.__setattr__(self, "network_import", imported)
        object.__setattr__(self, "forwarding", context)
        object.__setattr__(self, "owner", owner)


def bind_map_facts_owner(
    record: MapNetworkFacts,
    owner: MapFactsOwner,
    *,
    explicit_attachment: bool = False,
) -> MapNetworkFacts:
    """Return an associated record without changing any network/source identity.

    The attachment flag represents an explicit caller action; the codec cannot
    prove human consent. Attachment establishes ownership only, not identity or
    equivalence of different revisions. Existing owners cannot be reassigned.
    """
    if owner.association == "explicit_attachment" and explicit_attachment is not True:
        raise MapNetworkFactsError("owner: attachment requires explicit caller action")
    if record.owner is not None and record.owner != owner:
        raise MapNetworkFactsError("owner: existing association cannot be replaced")
    return MapNetworkFacts(record.network_import, record.forwarding, owner)


def map_facts_owner_matches(
    record: MapNetworkFacts,
    *,
    project_id: str,
    run_id: str,
    item_id: str,
    analysis_revision_id: UUID,
    source_document_ids: tuple[UUID, ...],
) -> bool:
    """Match all selected owner anchors; standalone records never auto-mount."""
    owner = record.owner
    return (
        owner is not None
        and (owner.project_id, owner.run_id, owner.item_id, owner.analysis_revision_id)
        == (project_id, run_id, item_id, analysis_revision_id)
        and len(source_document_ids) == len(set(source_document_ids))
        and set(owner.source_document_ids) == set(source_document_ids)
    )


def owner_reference(
    project_id: str,
    run_id: str,
    item_id: str,
    revision: DeviceRevision,
    *,
    association: Literal["exact_same_revision", "explicit_attachment"] = "exact_same_revision",
) -> MapFactsOwner:
    """Capture existing selected-analysis anchors; never generate identity."""
    return MapFactsOwner(
        project_id=project_id,
        run_id=run_id,
        item_id=item_id,
        analysis_revision_id=revision.revision_id,
        source_document_ids=tuple(source.source_document_id for source in revision.sources),
        association=association,
    )


def owner_matches(
    record: MapNetworkFacts,
    project_id: str,
    run_id: str,
    item_id: str,
    revision: DeviceRevision,
) -> bool:
    """Compare a selected analysis directly, without duplicating ID extraction."""
    return map_facts_owner_matches(
        record,
        project_id=project_id,
        run_id=run_id,
        item_id=item_id,
        analysis_revision_id=revision.revision_id,
        source_document_ids=tuple(source.source_document_id for source in revision.sources),
    )


def _canonical(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MapNetworkFactsError(f"{label}: expected an object")
    return value


def _version(payload: dict[str, Any], version: str, label: str) -> None:
    if payload.get("schema_version") != version:
        raise UnsupportedMapNetworkFactsError(f"{label}: unsupported or missing schema_version")


def _identity(payload: dict[str, Any], field: str, label: str) -> None:
    if not isinstance(payload.get(field), str) or not payload[field]:
        raise MapNetworkFactsError(f"{label}: missing explicit {field}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MapNetworkFactsError("envelope: duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise MapNetworkFactsError("envelope: non-finite JSON number")


def decode_map_network_facts(encoded: str) -> MapNetworkFacts:
    """Decode only complete current contracts; never infer IDs or migrate JSON."""
    try:
        payload = _object(
            json.loads(
                encoded,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            ),
            "envelope",
        )
        version = payload.get("schema_version")
        if version not in {"1.0.0", "1.1.0"}:
            raise UnsupportedMapNetworkFactsError("envelope: unsupported or missing schema_version")
        expected = {"schema_version", "network_import", "forwarding"}
        if version == "1.1.0":
            expected.add("owner")
        if set(payload) != expected:
            raise MapNetworkFactsError("envelope: unexpected or missing fields")
        owner_payload = payload.get("owner")
        owner = None
        if owner_payload is not None:
            owner_object = _object(owner_payload, "owner")
            _version(owner_object, "1.0.0", "owner")
            owner = MapFactsOwner.model_validate(owner_object)
            if _canonical(owner.model_dump(mode="json")) != _canonical(owner_object):
                raise MapNetworkFactsError("owner: incomplete or noncanonical reference")
        network = _object(payload["network_import"], "network_import")
        _version(network, "0.1.0", "network_import")
        revision = _object(network.get("revision"), "revision")
        _version(revision, "2.0.0", "revision")
        _identity(revision, "revision_id", "revision")
        parsed = _object(revision.get("parse_result"), "revision.parse_result")
        configuration = _object(parsed.get("configuration"), "configuration")
        _identity(configuration, "configuration_id", "configuration")
        if not isinstance(revision.get("sources"), list):
            raise MapNetworkFactsError("revision.sources: expected an explicit list")
        for source in revision["sources"]:
            _identity(_object(source, "revision.source"), "source_document_id", "revision.source")
        if not isinstance(network.get("documents"), list):
            raise MapNetworkFactsError("network_import.documents: expected an explicit list")
        for value in network["documents"]:
            document = _object(value, "document")
            _version(document, "0.1.0", "document")
            _version(_object(document.get("metadata"), "document.metadata"), "0.1.0", "metadata")
            _identity(
                _object(document.get("source"), "document.source"),
                "source_document_id",
                "document.source",
            )
        forwarding = payload["forwarding"]
        if forwarding is not None:
            _version(_object(forwarding, "forwarding"), "0.1.0", "forwarding")
        imported = NetworkImportResult.model_validate(network)
        context = ForwardingContext.model_validate(forwarding) if forwarding is not None else None
        # Full typed round-trip equality rejects omitted defaults, extra fields,
        # coercion and implicit migrations, including evidence/completeness gaps.
        if _canonical(imported.model_dump(mode="json")) != _canonical(network):
            raise MapNetworkFactsError("network_import: incomplete or noncanonical typed fields")
        if context is not None and _canonical(context.model_dump(mode="json")) != _canonical(
            forwarding
        ):
            raise MapNetworkFactsError("forwarding: incomplete or noncanonical typed fields")
        return MapNetworkFacts(imported, context, owner)
    except MapNetworkFactsError:
        raise
    except (ValueError, TypeError, RecursionError) as error:
        raise MapNetworkFactsError("envelope: malformed typed network facts") from error


def encode_map_network_facts(record: MapNetworkFacts) -> str:
    """Encode all typed fields canonically; reject opaque values without loss."""
    payload: dict[str, object] = {
        "schema_version": "1.1.0" if record.owner is not None else "1.0.0"
    }
    if record.owner is not None:
        payload["owner"] = record.owner.model_dump(mode="json")
    for label, model in (
        ("network_import", record.network_import),
        ("forwarding", record.forwarding),
    ):
        try:
            payload[label] = model.model_dump(mode="json") if model is not None else None
            _canonical(payload[label])
        except (ValueError, TypeError) as error:
            raise UnsupportedMapNetworkFactsError(
                f"{label}: unsupported serialized value"
            ) from error
    encoded = _canonical(payload)
    decode_map_network_facts(encoded)
    return encoded
