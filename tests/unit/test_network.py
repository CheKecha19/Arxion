"""Проверки сетевых объектов канонической модели."""

import pytest
from pydantic import ValidationError

from firewall_compliance.domain import Endpoint, EndpointKind, IpRange, PortRange, Protocol, Service


def test_endpoint_normalizes_and_deduplicates_cidrs() -> None:
    """CIDR приводятся к сетевому виду и не дублируются."""
    endpoint = Endpoint(
        endpoint_id="address-1",
        name="dmz",
        kind=EndpointKind.SUBNET,
        cidrs=("10.10.10.1/24", "10.10.10.0/24"),
    )

    assert endpoint.cidrs == ("10.10.10.0/24",)


def test_ip_range_normalizes_addresses() -> None:
    """Адреса диапазона сохраняются в каноническом виде."""
    ip_range = IpRange(start="2001:0db8::1", end="2001:db8::2")

    assert ip_range.start == "2001:db8::1"
    assert ip_range.end == "2001:db8::2"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"start": "10.0.0.2", "end": "10.0.0.1"},
        {"start": "10.0.0.1", "end": "2001:db8::1"},
    ],
)
def test_ip_range_rejects_invalid_bounds(kwargs: dict[str, str]) -> None:
    """Диапазон не может идти назад или смешивать версии IP."""
    with pytest.raises(ValidationError):
        IpRange(**kwargs)


def test_service_rejects_ports_for_non_port_protocol() -> None:
    """ICMP не использует TCP/UDP-диапазоны портов."""
    with pytest.raises(ValidationError, match="TCP и UDP"):
        Service(
            service_id="icmp",
            name="icmp",
            protocol=Protocol.ICMP,
            port_ranges=(PortRange(start=8, end=8),),
        )


def test_any_endpoint_rejects_address_values() -> None:
    """Специальное значение any не смешивается с адресом."""
    with pytest.raises(ValidationError, match="endpoint any"):
        Endpoint(
            endpoint_id="any",
            name="any",
            kind=EndpointKind.ANY,
            cidrs=("0.0.0.0/0",),
        )
