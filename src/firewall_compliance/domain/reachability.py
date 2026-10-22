"""Нейтральный запрос потока и объяснимые результаты первого сетевого среза."""

from ipaddress import ip_address, ip_network
from typing import Literal
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator, model_validator

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.enums import Protocol
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.revision import RevisionSource
from firewall_compliance.domain.snapshot import freeze_snapshot_fields

RouteSelectionStatus = Literal[
    "selected", "equal_cost", "blackhole", "no_route", "unknown", "not_enough_evidence"
]


class ReachabilityQuery(DomainModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    revision_id: UUID
    device_id: str = Field(min_length=1)
    device_context: str | None = Field(default=None, min_length=1)
    ingress_interface_id: str = Field(min_length=1)
    source_ip: str
    destination_ip: str
    protocol: Literal[Protocol.TCP, Protocol.UDP, Protocol.ICMP]
    destination_port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    table_id: str = Field(default="default", min_length=1)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def normalize_ip(cls, value: str) -> str:
        address = ip_address(value)
        if "%" in value or address.is_multicast or address.is_unspecified:
            raise ValueError("запрос требует конкретный unicast IP без scope ID")
        if str(address) == "255.255.255.255":
            raise ValueError("broadcast не входит в контракт unicast-запроса")
        return str(address)

    @model_validator(mode="after")
    def validate_flow(self) -> "ReachabilityQuery":
        if ip_address(self.source_ip).version != ip_address(self.destination_ip).version:
            raise ValueError("source и destination должны иметь одно семейство IP")
        if self.protocol in {Protocol.TCP, Protocol.UDP} and self.destination_port is None:
            raise ValueError("TCP/UDP запрос требует destination_port")
        if self.protocol == Protocol.ICMP and self.destination_port is not None:
            raise ValueError("ICMP запрос не содержит destination_port")
        return self


class AnalysisReason(DomainModel):
    model_config = ConfigDict(frozen=True)

    code: str = Field(pattern=r"^[a-z][a-z0-9_]+$")
    category: Literal["missing_evidence", "unsupported", "contradiction", "pending"]
    message: str = Field(min_length=1)
    related_route_ids: tuple[str, ...] = ()


class PathHop(DomainModel):
    model_config = ConfigDict(frozen=True)

    device_id: str = Field(min_length=1)
    revision_id: UUID
    table_id: str = Field(min_length=1)
    route_id: str = Field(min_length=1)
    destination: str
    next_hop: str | None = None
    outgoing_interface_id: str | None = None
    disposition: Literal["forward_candidate", "discard"]
    evidence: Evidence

    @model_validator(mode="after")
    def validate_target(self) -> "PathHop":
        network = ip_network(self.destination, strict=False)
        if self.destination != str(network):
            raise ValueError("PathHop требует нормализованную сеть назначения")
        if self.next_hop is not None and ip_address(self.next_hop).version != network.version:
            raise ValueError("PathHop next_hop и destination должны иметь одно семейство IP")
        if self.disposition == "discard":
            if self.next_hop is not None or self.outgoing_interface_id is not None:
                raise ValueError("discard не содержит forwarding target")
        elif self.next_hop is None and self.outgoing_interface_id is None:
            raise ValueError("forward_candidate требует next_hop либо интерфейс")
        freeze_snapshot_fields(self)
        return self


class RouteSelectionResult(DomainModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["0.1.0"] = "0.1.0"
    engine_version: Literal["0.1.0"] = "0.1.0"
    query: ReachabilityQuery
    status: RouteSelectionStatus
    matched_route_ids: tuple[str, ...] = ()
    candidate_route_ids: tuple[str, ...] = ()
    hops: tuple[PathHop, ...] = ()
    reasons: tuple[AnalysisReason, ...] = ()
    sources: tuple[RevisionSource, ...]
    revision_schema_version: str
    application_version: str
    evidence: Evidence

    @model_validator(mode="after")
    def validate_selection(self) -> "RouteSelectionResult":
        for identifiers in (self.matched_route_ids, self.candidate_route_ids):
            if len(set(identifiers)) != len(identifiers):
                raise ValueError("идентификаторы маршрутов результата не должны повторяться")
        if not set(self.candidate_route_ids) <= set(self.matched_route_ids):
            raise ValueError("кандидаты должны входить в совпавшие маршруты")
        if any(
            hop.device_id != self.query.device_id
            or hop.revision_id != self.query.revision_id
            or hop.table_id != self.query.table_id
            for hop in self.hops
        ):
            raise ValueError("PathHop должен принадлежать контексту запроса")
        resolved = self.status in {"selected", "blackhole", "equal_cost"}
        if resolved:
            if tuple(hop.route_id for hop in self.hops) != self.candidate_route_ids:
                raise ValueError("каждый кандидат должен иметь один PathHop")
            expected_count = 1 if self.status != "equal_cost" else 2
            if len(self.hops) < expected_count or (
                self.status != "equal_cost" and len(self.hops) != 1
            ):
                raise ValueError("число PathHop не соответствует решению")
            disposition = "discard" if self.status == "blackhole" else "forward_candidate"
            if any(hop.disposition != disposition for hop in self.hops):
                raise ValueError("действие PathHop не соответствует решению")
        elif self.hops:
            raise ValueError("неопределённый выбор не публикует PathHop")
        if self.status == "no_route" and (self.matched_route_ids or self.candidate_route_ids):
            raise ValueError("no_route не содержит совпавших маршрутов")
        if self.status in {"unknown", "not_enough_evidence"} and not self.reasons:
            raise ValueError("неопределённый результат требует причины")
        freeze_snapshot_fields(self)
        return self


class ReachabilityResult(DomainModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["0.1.0"] = "0.1.0"
    status: Literal["unknown", "not_enough_evidence"]
    route_selection: RouteSelectionResult
    reasons: tuple[AnalysisReason, ...] = Field(min_length=1)
    direction: Literal["forward"] = "forward"

    @model_validator(mode="after")
    def freeze_result(self) -> "ReachabilityResult":
        freeze_snapshot_fields(self)
        return self
