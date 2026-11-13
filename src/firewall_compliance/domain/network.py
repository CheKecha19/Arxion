"""Канонические модели сетевых объектов и сервисов."""

from ipaddress import ip_address, ip_network
from typing import Any

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.enums import DataStatus, EndpointKind, Protocol


class IpRange(DomainModel):
    """Включительный диапазон IP-адресов одной версии протокола."""

    start: str
    end: str

    @field_validator("start", "end")
    @classmethod
    def normalize_address(cls, value: str) -> str:
        """Проверить и нормализовать IP-адрес границы диапазона."""
        return str(ip_address(value))

    @model_validator(mode="after")
    def validate_range(self) -> "IpRange":
        """Проверить, что границы диапазона согласованы."""
        start = ip_address(self.start)
        end = ip_address(self.end)
        if start.version != end.version:
            raise ValueError("границы IP-диапазона должны иметь одну версию протокола")
        if int(start) > int(end):
            raise ValueError("начало IP-диапазона не может быть больше конца")
        return self


class Endpoint(DomainModel):
    """Адресный объект, группа, зона или специальное значение any."""

    endpoint_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    kind: EndpointKind
    cidrs: tuple[str, ...] = ()
    ip_ranges: tuple[IpRange, ...] = ()
    fqdn: str | None = None
    zone: str | None = None
    description: str | None = None
    resolution_status: DataStatus = DataStatus.KNOWN

    @field_validator("cidrs")
    @classmethod
    def normalize_cidrs(cls, cidrs: tuple[str, ...]) -> tuple[str, ...]:
        """Проверить, нормализовать и удалить повторяющиеся CIDR."""
        normalized = tuple(str(ip_network(cidr, strict=False)) for cidr in cidrs)
        return tuple(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def validate_representation(self) -> "Endpoint":
        """Проверить согласованность типа объекта и его значений."""
        if self.kind == EndpointKind.ANY and (self.cidrs or self.ip_ranges or self.fqdn):
            raise ValueError("endpoint any не может содержать адресные значения")
        if self.kind == EndpointKind.FQDN and not self.fqdn:
            raise ValueError("endpoint типа fqdn должен содержать fqdn")
        if self.kind == EndpointKind.RANGE and not self.ip_ranges:
            raise ValueError("endpoint типа range должен содержать IP-диапазон")
        if self.kind == EndpointKind.SUBNET and not self.cidrs:
            raise ValueError("endpoint типа subnet должен содержать CIDR")
        return self


class PortRange(DomainModel):
    """Включительный диапазон TCP или UDP портов."""

    start: int = Field(ge=0, le=65535)
    end: int = Field(ge=0, le=65535)

    @model_validator(mode="after")
    def validate_range(self) -> "PortRange":
        """Проверить порядок границ порта."""
        if self.end < self.start:
            raise ValueError("конец диапазона порта не может быть меньше начала")
        return self


class Service(DomainModel):
    """Сервис с протоколом и при необходимости диапазонами портов."""

    service_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    protocol: Protocol
    protocol_number: int | None = Field(default=None, ge=0, le=255)
    port_ranges: tuple[PortRange, ...] = ()
    source_port_ranges: tuple[PortRange, ...] = ()
    alg: str | None = None
    description: str | None = None
    resolution_status: DataStatus = DataStatus.KNOWN

    @model_validator(mode="after")
    def validate_ports(self) -> "Service":
        """Разрешить порты только для TCP и UDP."""
        if (
            self.port_ranges or self.source_port_ranges
        ) and self.protocol not in {Protocol.TCP, Protocol.UDP}:
            raise ValueError("диапазоны портов допустимы только для TCP и UDP")
        expected = {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.ICMP: 1}
        if (
            self.protocol_number is not None and self.protocol in expected
            and self.protocol_number != expected[self.protocol]
        ):
            raise ValueError("номер IP-протокола противоречит типу сервиса")
        if self.protocol == Protocol.IP and self.protocol_number is not None:
            raise ValueError("IP ANY не может содержать конкретный номер протокола")
        return self

    @model_serializer(mode="wrap")
    def omit_extended_defaults(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.protocol_number is None:
            payload.pop("protocol_number", None)
        if not self.source_port_ranges:
            payload.pop("source_port_ranges", None)
        if self.alg is None:
            payload.pop("alg", None)
        return payload
