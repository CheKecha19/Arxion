"""Границы применимости локального решения маршрутизирующего VLAN ACL."""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from ipaddress import IPv6Interface, ip_interface

from firewall_compliance.analysis.policy_coverage import PacketBox
from firewall_compliance.domain.policy_matching import Interval, merge_intervals
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.domain.switch_policy import AclBinding

type _AddressAnchor = tuple[int, SourceLocation | None]
type _SubnetAnchor = tuple[Interval, SourceLocation | None]


@dataclass(frozen=True, slots=True)
class AttachmentScopeAssessment:
    reasons: tuple[str, ...] = ()
    source_locations: tuple[SourceLocation, ...] = ()
    same_segment: bool = False
    device_destination: bool = False
    outside_attachment_subnet: bool = False
    unresolved_attachment: bool = False

    @property
    def limits_path(self) -> bool:
        return (
            self.same_segment or self.device_destination or self.outside_attachment_subnet
            or self.unresolved_attachment
        )


def _first(locations: tuple[SourceLocation, ...]) -> SourceLocation | None:
    return locations[0] if locations else None


def matrix_attachment_interface_key(value: str) -> str:
    """Привязка и настроенный VLAN-интерфейс должны ссылаться на один интерфейс."""
    name = " ".join(value.casefold().removeprefix("interface:").replace(":", " ").split())
    match = re.fullmatch(r"vlan(?:-interface)?\s*([0-9]{1,4})", name)
    return f"vlan {int(match[1])}" if match is not None else name


def _shared_subnet_index(
    subnets: list[_SubnetAnchor],
) -> tuple[tuple[int, ...], tuple[_AddressAnchor, ...]]:
    starts: list[int] = []
    max_ends: list[_AddressAnchor] = []
    for (first, last), anchor in sorted(subnets, key=lambda item: item[0]):
        starts.append(first)
        # Use a single observed subnet for both endpoints. Merged ranges could join different VLANs.
        max_ends.append(max_ends[-1] if max_ends and max_ends[-1][0] >= last else (last, anchor))
    return tuple(starts), tuple(max_ends)


class MatrixAttachmentScope:
    """Index known addressing once. The classifier never changes the packet region passed to the ACL."""

    def __init__(
        self, revision: DeviceRevision, binding: AclBinding,
        guard: Callable[[], None] | None = None,
    ) -> None:
        self._guard = guard
        self._subject = matrix_attachment_interface_key(binding.subject)
        self._ingress = binding.direction == "routed-in"
        self._applicable = (
            (revision.device.platform in {"aos-cx", "aos-switch"} or (
                revision.device.platform == "comware" and binding.configured_profile is not None
            )) and binding.purpose == "transit"
            and binding.direction in {"routed-in", "routed-out"} and self._subject.startswith("vlan ")
        )
        self._unresolved = False
        self._disabled = False
        self._binding_location = _first(binding.source_locations)
        self._svi_location: SourceLocation | None = None
        self._connected: dict[int, tuple[Interval, ...]] = {}
        self._shared_subnets: dict[int, tuple[tuple[int, ...], tuple[_AddressAnchor, ...]]] = {}
        self._own_addresses: dict[int, tuple[_AddressAnchor, ...]] = {}
        if not self._applicable:
            return

        facts = revision.parse_result.switch_facts
        if facts is None or facts.platform != revision.device.platform:
            self._unresolved = True
            return
        interfaces = [
            item for item in facts.interfaces
            if item.kind == "vlan" and matrix_attachment_interface_key(item.name) == self._subject
        ]
        if len(interfaces) != 1:
            self._unresolved = True
            return
        svi = interfaces[0]
        self._disabled = svi.admin_state == "disabled"
        self._svi_location = _first(svi.source_locations)
        if svi.vrf is None or binding.vrf not in (None, svi.vrf) or svi.mode == "l2":
            self._unresolved = True
            return

        connected: dict[int, list[Interval]] = defaultdict(list)
        shared_subnets: dict[int, list[_SubnetAnchor]] = defaultdict(list)
        own_addresses: dict[int, list[_AddressAnchor]] = defaultdict(list)
        for interface in facts.interfaces:
            if guard is not None:
                guard()
            if interface.vrf != svi.vrf or interface.mode == "l2":
                continue
            for item in interface.addresses:
                if guard is not None:
                    guard()
                if item.status != "known" or item.cidr is None:
                    continue
                try:
                    address = ip_interface(item.cidr)
                except ValueError:
                    continue
                if isinstance(address, IPv6Interface) and address.scope_id is not None:
                    continue
                network = address.network
                anchor = _first(item.source_locations) or _first(interface.source_locations)
                own_addresses[address.version].append((int(address.ip), anchor))
                first, last = int(network.network_address), int(network.broadcast_address)
                if interface is svi:
                    if not connected and anchor is not None:
                        self._svi_location = anchor
                    connected[address.version].append((first, last))
                if interface.kind == "vlan" and interface.admin_state != "disabled":
                    if address.version == 4 and network.prefixlen <= 30:
                        first, last = first + 1, last - 1
                    if first < last:
                        shared_subnets[address.version].append(((first, last), anchor))

        self._connected = {family: merge_intervals(values) for family, values in connected.items()}
        self._shared_subnets = {
            family: _shared_subnet_index(values) for family, values in shared_subnets.items()
        }
        self._own_addresses = {
            family: tuple(sorted(values, key=lambda entry: entry[0])) for family, values in own_addresses.items()
        }
        self._unresolved = not self._connected or self._disabled

    def assess(self, boxes: Iterable[PacketBox]) -> AttachmentScopeAssessment:
        if not self._applicable:
            return AttachmentScopeAssessment()
        same_segment = device_destination = outside = False
        shared_location = own_location = None
        for box in boxes:
            if self._guard is not None:
                self._guard()
            source, destination = box.axes[:2]
            if not same_segment and (shared := self._shared_subnets.get(box.family)) is not None:
                starts, max_ends = shared
                index = bisect_right(starts, min(source[1], destination[1])) - 1
                if index >= 0 and max_ends[index][0] >= max(source[0], destination[0]):
                    same_segment = True
                    shared_location = max_ends[index][1]
            if not device_destination and (own := self._own_addresses.get(box.family)) is not None:
                index = bisect_left(own, destination[0], key=lambda entry: entry[0])
                if index < len(own) and own[index][0] <= destination[1]:
                    device_destination = True
                    own_location = own[index][1]
            if not outside and not self._unresolved:
                endpoint = source if self._ingress else destination
                ranges = self._connected.get(box.family, ())
                index = bisect_right(ranges, endpoint[0], key=lambda interval: interval[0]) - 1
                outside = index < 0 or ranges[index][1] < endpoint[1]
            if same_segment and device_destination and (outside or self._unresolved):
                break

        reasons = []
        if self._disabled:
            reasons.append(f"Интерфейс {self._subject} административно отключён в сохранённой конфигурации.")
        elif self._unresolved:
            reasons.append(f"Для {self._subject} нужны однозначная привязка и адресная настройка интерфейса.")
        if same_segment:
            reasons.append(
                "В области есть пары адресов из одной настроенной VLAN-подсети. "
                "Для них нужны сведения о L2-пути и фильтрации сегмента."
            )
        if device_destination:
            reasons.append(
                "Область назначения включает собственный адрес коммутатора. "
                "Доступ к сервисам устройства требует отдельной проверки."
            )
        if outside:
            endpoint = "источника" if self._ingress else "назначения"
            reasons.append(
                f"Часть адресов {endpoint} вне известных подсетей {self._subject}. "
                "Нужно уточнить, какой интерфейс используется для этого трафика."
            )
        locations: list[SourceLocation] = []
        if reasons:
            for location in (self._binding_location, self._svi_location, shared_location, own_location):
                if location is not None and location not in locations:
                    locations.append(location)
        return AttachmentScopeAssessment(
            reasons=tuple(reasons), source_locations=tuple(locations), same_segment=same_segment,
            device_destination=device_destination, outside_attachment_subnet=outside,
            unresolved_attachment=self._unresolved,
        )
