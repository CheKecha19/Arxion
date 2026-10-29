"""Проверки семантического включения адресов и сервисов."""

from hypothesis import given
from hypothesis import strategies as st
from tests.policy_fixtures import endpoint, rule

from firewall_compliance.analysis.policy_matching import (
    intervals_cover,
    merge_intervals,
    resolve_addresses,
    resolve_rule,
)
from firewall_compliance.domain import Endpoint, EndpointKind, IpRange, PortRange, Protocol, Service


@given(
    st.lists(st.tuples(st.integers(0, 30), st.integers(0, 30))),
    st.lists(st.tuples(st.integers(0, 30), st.integers(0, 30))),
)
def test_interval_inclusion_matches_discrete_set_oracle(outer, inner) -> None:
    outside = [(min(a, b), max(a, b)) for a, b in outer]
    inside = [(min(a, b), max(a, b)) for a, b in inner]
    outer_points = {point for start, end in outside for point in range(start, end + 1)}
    inner_points = {point for start, end in inside for point in range(start, end + 1)}
    assert intervals_cover(merge_intervals(outside), merge_intervals(inside)) == (
        inner_points <= outer_points
    )


def test_cidr_union_and_range_have_same_normalized_match() -> None:
    subnets = resolve_addresses((endpoint("192.0.2.0/25"), endpoint("192.0.2.128/25")))
    whole = resolve_addresses((endpoint("192.0.2.0/24"),))
    ranged = resolve_addresses(
        (
            Endpoint(
                endpoint_id="range",
                name="range",
                kind=EndpointKind.RANGE,
                ip_ranges=(IpRange(start="192.0.2.0", end="192.0.2.255"),),
            ),
        )
    )
    assert subnets == whole == ranged


def test_ipv4_does_not_cover_ipv6() -> None:
    left = resolve_rule(rule(1))
    right = resolve_rule(
        rule(
            2,
            sources=(endpoint("2001:db8::/64"),),
            destinations=(endpoint("2001:db8:1::/64"),),
        )
    )
    assert left and right
    assert not left.covers(right)


def test_ip_covers_tcp_but_tcp_does_not_cover_udp_or_ip() -> None:
    any_service = resolve_rule(
        rule(1, services=(Service(service_id="ip", name="ip", protocol=Protocol.IP),))
    )
    tcp = resolve_rule(rule(2))
    udp = resolve_rule(
        rule(
            3,
            services=(
                Service(
                    service_id="udp",
                    name="udp",
                    protocol=Protocol.UDP,
                    port_ranges=(PortRange(start=443, end=443),),
                ),
            ),
        )
    )
    assert any_service and tcp and udp
    assert any_service.covers(tcp)
    assert not tcp.covers(any_service)
    assert not tcp.covers(udp)
