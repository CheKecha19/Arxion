"""Bounded exact packet-set subtraction for normalized first-match predicates."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from itertools import product
from typing import Any, Literal

from firewall_compliance.domain.policy_matching import Interval, RuleMatch

type Axes = tuple[Interval, Interval, Interval, Interval, Interval]


class CoverageLimitError(ValueError):
    """The configured complexity bound prevented a complete set operation."""


class UnsupportedCoverageError(ValueError):
    """A normalized predicate has no established interpretation in this algebra."""


@dataclass
class CoverageBudget:
    """Shared work bound; a limit is never returned as an empty residual."""

    max_fragments: int = 4096
    max_operations: int = 200000
    operations: int = 0

    def __post_init__(self) -> None:
        if self.max_fragments < 1 or self.max_operations < 1:
            raise ValueError("Coverage limits must be positive.")

    def charge(self, fragments: int = 0) -> None:
        self.operations += 1
        if self.operations > self.max_operations or fragments > self.max_fragments:
            raise CoverageLimitError("Packet-set complexity limit exceeded.")


@dataclass(frozen=True, order=True)
class PacketBox:
    """One family and five closed integer intervals: src,dst,protocol,port,direction.

    Direction 0 is ingress and 1 is egress. Ports exist only for TCP/UDP;
    all other protocols have a single dummy coordinate 0, never an inferred port.
    """

    family: Literal[4, 6]
    axes: Axes

    def intersection(self, other: PacketBox) -> PacketBox | None:
        if self.family != other.family:
            return None
        values = tuple(
            (max(a, c), min(b, d)) for (a, b), (c, d) in zip(self.axes, other.axes, strict=True)
        )
        if any(start > end for start, end in values):
            return None
        source, destination, protocol, port, direction = values
        return PacketBox(self.family, (source, destination, protocol, port, direction))

    def subtract(self, other: PacketBox) -> tuple[PacketBox, ...]:
        """Return disjoint slabs of self minus other, without enumerating packets."""
        overlap = self.intersection(other)
        if overlap is None:
            return (self,)
        core = list(self.axes)
        result = []
        for index, (start, end) in enumerate(overlap.axes):
            lower, upper = core[index]
            for interval in ((lower, start - 1), (end + 1, upper)):
                if interval[0] <= interval[1]:
                    source, destination, protocol, port, direction = (
                        interval if axis == index else value for axis, value in enumerate(core)
                    )
                    result.append(
                        PacketBox(self.family, (source, destination, protocol, port, direction))
                    )
            core[index] = start, end
        return tuple(result)

    def witness(self) -> dict[str, Any]:
        source, destination, protocol, port, direction = (value[0] for value in self.axes)
        # ip_address(0) is IPv4 even for an IPv6 box.
        address = IPv4Address if self.family == 4 else IPv6Address
        source_ip = str(address(source))
        destination_ip = str(address(destination))
        return {
            "family": self.family,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol_number": protocol,
            "destination_port": port if protocol in {6, 17} else None,
            "direction": "in" if direction == 0 else "out",
        }


def packet_boxes(
    match: RuleMatch, direction: Literal["in", "out", "global"], budget: CoverageBudget
) -> tuple[PacketBox, ...]:
    """Expand unions into disjoint products while keeping protocol/port correlation."""
    directions: Interval = {"in": (0, 0), "out": (1, 1), "global": (0, 1)}[direction]
    values: list[PacketBox] = []
    for family_index, family in enumerate((4, 6)):
        for protocol, ports in match.services:
            services: tuple[tuple[Interval, tuple[Interval, ...]], ...]
            if protocol == "ip":
                services = (
                    ((0, 5), ((0, 0),)),
                    ((6, 6), ((0, 65535),)),
                    ((7, 16), ((0, 0),)),
                    ((17, 17), ((0, 65535),)),
                    ((18, 255), ((0, 0),)),
                )
            elif protocol in {"tcp", "udp"}:
                number = 6 if protocol == "tcp" else 17
                services = (((number, number), ports),)
            elif protocol == "icmp" and family == 4:
                services = (((1, 1), ((0, 0),)),)
            elif match.sources[family_index] and match.destinations[family_index]:
                raise UnsupportedCoverageError(
                    "Unknown protocol semantics for this address family."
                )
            else:
                continue
            for protocols, service_ports in services:
                for source, destination, port in product(
                    match.sources[family_index], match.destinations[family_index], service_ports
                ):
                    budget.charge(len(values) + 1)
                    values.append(
                        PacketBox(
                            4 if family == 4 else 6,
                            (source, destination, protocols, port, directions),
                        )
                    )
    return tuple(values)


def subtract_boxes(
    residual: tuple[PacketBox, ...], covering: tuple[PacketBox, ...], budget: CoverageBudget
) -> tuple[tuple[PacketBox, ...], tuple[PacketBox, ...]]:
    """Subtract a union and return residual plus newly covered disjoint fragments."""
    remaining = residual
    covered: list[PacketBox] = []
    for outer in covering:
        updated: list[PacketBox] = []
        for inner in remaining:
            budget.charge(len(updated) + len(covered))
            overlap = inner.intersection(outer)
            if overlap is not None:
                covered.append(overlap)
            updated.extend(inner.subtract(outer))
            budget.charge(len(updated) + len(covered))
        remaining = tuple(updated)
        if not remaining:
            break
    return remaining, tuple(covered)
