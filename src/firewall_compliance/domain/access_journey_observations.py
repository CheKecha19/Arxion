"""Снимок наблюдений за отдельными взаимодействиями утверждённой цепочки."""

from ipaddress import ip_address
from typing import Any, Literal, Self

from pydantic import Field, SerializerFunctionWrapHandler, field_validator, model_serializer, model_validator

from firewall_compliance.domain.access_context import (
    AccessContextOrigin,
    ContextDigest,
    ContextIdentifier,
    ContextTime,
)
from firewall_compliance.domain.access_matrix import MatrixZonePair
from firewall_compliance.domain.controls import ControlModel

JourneyObservationOutcome = Literal["connected", "response_observed", "denied", "timeout", "unknown"]


class JourneyObservation(ControlModel):
    """Один обмен из журнала. Адреса и порт указываются в направлении запроса."""

    step_id: str = Field(min_length=1, max_length=128)
    context_id: ContextIdentifier
    source_ip: str
    destination_ip: str
    protocol: Literal["tcp", "udp", "icmp"]
    destination_port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    outcome: JourneyObservationOutcome
    origin: AccessContextOrigin
    session_id: ContextIdentifier | None = None
    trace_id: ContextIdentifier | None = None
    zone_pair: MatrixZonePair | None = None

    @model_serializer(mode="wrap")
    def serialize_zones(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload = handler(self)
        if self.zone_pair is None:
            payload.pop("zone_pair", None)
        return payload

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def normalize_address(cls, value: str) -> str:
        address = ip_address(value)
        if "%" in value or address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
            raise ValueError("Наблюдение требует конкретный unicast IP без идентификатора зоны")
        return str(address)

    @model_validator(mode="after")
    def validate_transport(self) -> Self:
        family = ip_address(self.source_ip).version
        if family != ip_address(self.destination_ip).version:
            raise ValueError("Адреса наблюдения должны принадлежать одному семейству IP")
        if self.protocol == "icmp":
            if self.destination_port is not None or family != 4:
                raise ValueError("В этом формате ICMP описывает IPv4 без номера порта")
        elif self.destination_port is None:
            raise ValueError("Для TCP и UDP требуется порт назначения")
        if self.outcome == "connected" and self.protocol != "tcp":
            raise ValueError("Состояние connected применимо только к TCP")
        return self


class JourneyObservationReference(ControlModel):
    source_name: ContextIdentifier
    record_id: ContextIdentifier


class JourneyTransactionObservation(ControlModel):
    """Внешняя запись о завершённой транзакции и о связанных с ней попытках."""

    trace_id: ContextIdentifier
    origin: AccessContextOrigin
    started_at: ContextTime
    completed_at: ContextTime
    outcome: Literal["completed"]
    samples: tuple[JourneyObservationReference, ...] = ()

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if not self.started_at <= self.completed_at <= self.origin.observed_at:
            raise ValueError("Время завершения должно быть между началом транзакции и записью источника")
        return self


class JourneyObservationSnapshot(ControlModel):
    """Офлайн-вход с точной ссылкой на проект, область и версию матрицы."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    project_id: ContextIdentifier
    scope_id: str = Field(min_length=1, max_length=256)
    matrix_id: str = Field(min_length=1, max_length=128)
    matrix_version: str = Field(min_length=1, max_length=64)
    matrix_checksum: ContextDigest
    journey_id: str = Field(min_length=1, max_length=128)
    captured_at: ContextTime
    observations: tuple[JourneyObservation, ...] = ()
    transactions: tuple[JourneyTransactionObservation, ...] = ()

    @model_validator(mode="after")
    def validate_records(self) -> Self:
        for entries in (self.observations, self.transactions):
            seen: set[tuple[str, str]] = set()
            for entry in entries:
                origin = entry.origin
                record = origin.source_name, origin.record_id
                if record in seen:
                    raise ValueError("Идентификатор записи должен быть уникальным в пределах источника")
                if origin.observed_at > self.captured_at:
                    raise ValueError("Время записи не может быть позже времени снимка наблюдений")
                seen.add(record)
        return self
