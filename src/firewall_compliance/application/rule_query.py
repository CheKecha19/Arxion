"""Отбор заданных условий правил; неизвестный результат не означает совпадение."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network

from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.policy_matching import resolve_addresses, resolve_services


@dataclass(frozen=True, slots=True)
class RuleQuery:
    source: str = ""
    destination: str = ""
    protocol: str = ""
    ports: tuple[tuple[int, int], ...] = ()

    def __post_init__(self) -> None:
        for field in ("source", "destination"):
            value = getattr(self, field)
            if value:
                object.__setattr__(self, field, str(ip_network(value, strict=False)))
        if self.protocol not in {"", "tcp", "udp", "icmp", "icmpv6", "ip"}:
            raise ValueError("Неизвестный протокол")
        if self.ports and self.protocol not in {"tcp", "udp"}:
            raise ValueError("Для портов выберите TCP или UDP")
        if any(not 1 <= start <= end <= 65535 for start, end in self.ports):
            raise ValueError("Диапазон портов должен быть в пределах 1–65535")

    @property
    def active(self) -> bool:
        return bool(self.source or self.destination or self.protocol or self.ports)

    def matches(self, rule: Rule) -> bool | None:
        """AND между измерениями, пересечение внутри адресов и диапазонов портов."""
        results: list[bool | None] = []
        for value, endpoints, status in (
            (self.source, rule.sources, rule.source_status),
            (self.destination, rule.destinations, rule.destination_status),
        ):
            if not value:
                continue
            addresses = resolve_addresses(endpoints) if status == DataStatus.KNOWN else None
            if rule.match_status != DataStatus.KNOWN or addresses is None:
                results.append(None)
                continue
            network = ip_network(value)
            low, high = int(network.network_address), int(network.broadcast_address)
            results.append(any(
                start <= high and end >= low
                for start, end in addresses[0 if network.version == 4 else 1]
            ))
        if self.protocol or self.ports:
            services = resolve_services(rule.services) if rule.service_status == DataStatus.KNOWN else None
            if rule.match_status != DataStatus.KNOWN or services is None:
                results.append(None)
            else:
                results.append(any(
                    (not self.protocol or self.protocol == "ip" or protocol in {"ip", self.protocol})
                    and (not self.ports or (
                        protocol in {"ip", "tcp", "udp"}
                        and any(a <= end and b >= start for a, b in ranges for start, end in self.ports)
                    ))
                    for protocol, ranges in services
                ))
        if False in results:
            return False
        return None if None in results else True


def parse_port_ranges(text: str) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        bounds = token.split("-")
        if len(bounds) > 2:
            raise ValueError("Порты: 443 или 1000-2000; несколько значений через запятую")
        start = int(bounds[0])
        end = int(bounds[-1])
        if not 1 <= start <= end <= 65535:
            raise ValueError("Диапазон портов должен быть в пределах 1–65535")
        result.append((start, end))
    return tuple(sorted(set(result)))
