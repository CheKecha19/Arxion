"""Explicit captured inputs for policy/object/configured-NAT comparisons."""

from collections.abc import Mapping
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import ConfigDict, Field, JsonValue, StrictBool, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.network import Endpoint, Service
from firewall_compliance.domain.observation import ObservationEvidence
from firewall_compliance.domain.revision import DeviceRevision, RevisionSource
from firewall_compliance.domain.snapshot import freeze_snapshot_fields
from firewall_compliance.domain.source import SourceLocation

type PolicyEntityFamily = Literal["rule", "endpoint", "service", "nat"]


def _plain(value: Any) -> Any:
    if isinstance(value, DomainModel):
        return value.model_dump(mode="python")
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


class PolicyDiffModel(DomainModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def validate_nested(cls, value: Any) -> Any:
        return _plain(value)

    @model_validator(mode="after")
    def freeze(self) -> Self:
        freeze_snapshot_fields(self)
        return self

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        payload = self.model_dump(mode="python")
        payload.update(update or {})
        return self.__class__.model_validate(payload)


class PolicyCollectionEvidence(PolicyDiffModel):
    """Operator/provider assertion, never inferred from parser coverage alone."""

    family: PolicyEntityFamily
    scope_reference: str = Field(min_length=1, max_length=2048)
    enumeration_complete: StrictBool = False
    source_document_ids: tuple[UUID, ...] = Field(min_length=1, max_length=256)
    observation: ObservationEvidence
    identity_namespace: str | None = Field(default=None, min_length=1, max_length=256)
    identity_reference: str | None = Field(default=None, min_length=1, max_length=2048)
    order_complete: StrictBool = False
    order_semantics: Literal["first_match", "unknown"] = "unknown"

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if (self.identity_namespace is None) != (self.identity_reference is None):
            raise ValueError("identity namespace requires its explicit evidence reference")
        if len(set(self.source_document_ids)) != len(self.source_document_ids):
            raise ValueError("duplicate collection source IDs")
        if self.family not in {"rule", "nat"} and (
            self.order_complete or self.order_semantics != "unknown"
        ):
            raise ValueError("object inventories have no first-match ordering")
        if self.order_complete and self.order_semantics != "first_match":
            raise ValueError("complete order requires declared first-match semantics")
        return self


class ConfiguredNatRecord(PolicyDiffModel):
    """A supplied declaration, not an effective translation or collector result.

    Each address/service set must be explicit for a known comparison. Dynamic
    pools, interface PAT, application match and processing ambiguities stay unknown.
    """

    nat_id: str = Field(min_length=1, max_length=256)
    scope_reference: str = Field(min_length=1, max_length=2048)
    sequence: int = Field(ge=0, strict=True)
    kind: Literal["snat", "dnat", "twice_nat", "no_nat", "unknown"] = "unknown"
    processing_family: Literal["ipv4", "ipv6", "unknown"] = "unknown"
    processing_stage: str | None = Field(default=None, min_length=1, max_length=256)
    direction: Literal["in", "out", "bidirectional", "unknown"] = "unknown"
    enabled: StrictBool | None = None
    original_sources: tuple[Endpoint, ...] = Field(default=(), max_length=4096)
    original_destinations: tuple[Endpoint, ...] = Field(default=(), max_length=4096)
    original_services: tuple[Service, ...] = Field(default=(), max_length=4096)
    translated_sources: tuple[Endpoint, ...] = Field(default=(), max_length=4096)
    translated_destinations: tuple[Endpoint, ...] = Field(default=(), max_length=4096)
    translated_services: tuple[Service, ...] = Field(default=(), max_length=4096)
    data_status: DataStatus = DataStatus.UNKNOWN
    source_document_id: UUID
    source_location: SourceLocation


class PolicyDiffInput(PolicyDiffModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    revision: DeviceRevision
    # Includes integration/VDC/device context when relevant; names/IPs are not identity.
    scope_reference: str = Field(min_length=1, max_length=2048)
    collections: tuple[PolicyCollectionEvidence, ...] = Field(default=(), max_length=4)
    configured_nat: tuple[ConfiguredNatRecord, ...] | None = Field(default=None, max_length=20000)
    nat_sources: tuple[RevisionSource, ...] = Field(default=(), max_length=256)
    # Counts/anchors may be retained here; they are never converted to translations.
    nat_inventory_context: dict[str, JsonValue] | None = None

    @model_validator(mode="after")
    def validate_sources(self) -> Self:
        sources = (*self.revision.sources, *self.nat_sources)
        by_id = {source.source_document_id: source for source in sources}
        if len(by_id) != len(sources):
            raise ValueError("source IDs must be unique across revision and NAT documents")
        families = [value.family for value in self.collections]
        if len(set(families)) != len(families):
            raise ValueError("each family has at most one collection assertion")
        if self.configured_nat is None and any(value.family == "nat" for value in self.collections):
            raise ValueError("NAT collection evidence requires an explicit record tuple")
        parsed = self.revision.parse_result
        identifiers = (
            [rule.rule_id for rule in parsed.rules],
            [item.endpoint_id for item in parsed.endpoints],
            [item.service_id for item in parsed.services],
            [item.nat_id for item in self.configured_nat or ()],
        )
        if any(len(set(values)) != len(values) for values in identifiers):
            raise ValueError("entity IDs must be unambiguous within each captured family")
        for record in self.configured_nat or ():
            source = by_id.get(record.source_document_id)
            if source is None or source.source_name != record.source_location.source_name:
                raise ValueError("NAT record source must match a retained document")
        for evidence in self.collections:
            for identifier in evidence.source_document_ids:
                source = by_id.get(identifier)
                if source is None:
                    raise ValueError("collection source is not retained")
                if evidence.observation.observed_at > source.captured_at:
                    raise ValueError("collection observation cannot follow source capture")
            if evidence.family == "nat" and any(
                item.source_document_id not in evidence.source_document_ids
                for item in self.configured_nat or ()
            ):
                raise ValueError("NAT collection does not cover its records' sources")
        if any(source.captured_at > self.revision.imported_at for source in sources):
            raise ValueError("all input sources must be captured by revision import")
        return self

    def collection(self, family: PolicyEntityFamily) -> PolicyCollectionEvidence | None:
        return next((value for value in self.collections if value.family == family), None)


class PolicyEntityCorrespondence(PolicyDiffModel):
    family: PolicyEntityFamily
    before_id: str = Field(min_length=1, max_length=256)
    after_id: str = Field(min_length=1, max_length=256)
    reference: str = Field(min_length=1, max_length=2048)
    source_locations: tuple[SourceLocation, ...] = Field(min_length=1, max_length=64)


class PolicyDiffOptions(PolicyDiffModel):
    max_entities: int = Field(default=20000, ge=1, le=100000, strict=True)
    max_operations: int = Field(default=200000, ge=1, le=10000000, strict=True)
    correspondences: tuple[PolicyEntityCorrespondence, ...] = Field(default=(), max_length=20000)
    normalization_comparability_reference: str | None = Field(
        default=None, min_length=1, max_length=2048
    )

    @model_validator(mode="after")
    def unique_correspondences(self) -> Self:
        for side in ("before_id", "after_id"):
            keys = [(value.family, getattr(value, side)) for value in self.correspondences]
            if len(set(keys)) != len(keys):
                raise ValueError("correspondence evidence must be one-to-one")
        return self


class PolicyDiffLimitation(PolicyDiffModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    family: PolicyEntityFamily | None = None
    entity_ids: tuple[str, ...] = ()


class PolicyDiffChange(PolicyDiffModel):
    change_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    family: Literal["rule", "endpoint", "service", "nat", "configuration"]
    kind: Literal[
        "added",
        "removed",
        "modified",
        "first_observed",
        "not_observed",
        "order_changed",
        "representation_changed",
        "evidence_changed",
        "coverage_changed",
    ]
    before_ids: tuple[str, ...] = ()
    after_ids: tuple[str, ...] = ()
    changed_fields: tuple[str, ...] = ()
    before_value: dict[str, JsonValue] | None = None
    after_value: dict[str, JsonValue] | None = None
    basis: Literal[
        "explicit_correspondence",
        "stable_namespace",
        "equivalent_multiset",
        "collection_evidence",
        "source_metadata",
        "order_evidence",
    ]
    source_locations: tuple[SourceLocation, ...] = ()


class PolicyDiffComputation(PolicyDiffModel):
    semantic_changes: tuple[PolicyDiffChange, ...] = ()
    provenance_changes: tuple[PolicyDiffChange, ...] = ()
    normalization_changes: tuple[PolicyDiffChange, ...] = ()
    completeness_changes: tuple[PolicyDiffChange, ...] = ()
    limitations: tuple[PolicyDiffLimitation, ...] = ()
    operations_used: int = Field(ge=0, strict=True)

    @property
    def state(self) -> Literal["complete", "partial"]:
        return "partial" if self.limitations else "complete"
