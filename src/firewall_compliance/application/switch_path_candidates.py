"""Локальная диагностика маршрута по сохранённой конфигурации коммутатора."""

from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
    ip_interface,
    ip_network,
)
from typing import Literal
from uuid import UUID

from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.domain.switch_facts import SwitchFacts, SwitchInterface, SwitchRoute

type PathStatus = Literal[
    "local_destination", "same_segment", "configured_candidate", "ambiguous",
    "insufficient_evidence", "unsupported",
]
type IPAddress = IPv4Address | IPv6Address
type IPInterface = IPv4Interface | IPv6Interface
type IPNetwork = IPv4Network | IPv6Network
_SWITCH_PLATFORMS = {"aos-cx", "aos-switch", "comware"}


@dataclass(frozen=True, slots=True)
class ConfiguredRouteCandidate:
    kind: Literal["connected", "static", "default"]
    prefix: str
    interface: str | None
    next_hop: str | None
    source_locations: tuple[SourceLocation, ...]
    qualification: str | None = None


@dataclass(frozen=True, slots=True)
class SwitchPathCandidate:
    status: PathStatus
    reason: str
    next_evidence: str
    revision_id: UUID
    source_ip: str
    destination_ip: str
    vrf: str | None = None
    source_interface: str | None = None
    routes: tuple[ConfiguredRouteCandidate, ...] = ()
    source_locations: tuple[SourceLocation, ...] = ()
    management_gateways: tuple[SwitchRoute, ...] = ()


@dataclass(frozen=True, slots=True)
class _InterfaceAddress:
    interface: SwitchInterface
    address: IPInterface
    source_locations: tuple[SourceLocation, ...]


def parse_switch_path_address(value: str) -> IPAddress:
    address = ip_address(value)
    if (
        "%" in value or address.is_unspecified or address.is_multicast
        or address.is_loopback or str(address) == "255.255.255.255"
    ):
        raise ValueError("Укажите конкретные IP-адреса источника и назначения")
    return address


def _host_in(address: IPAddress, network: IPNetwork) -> bool:
    if address not in network:
        return False
    if isinstance(network, IPv4Network) and network.prefixlen <= 30:
        return address not in (network.network_address, network.broadcast_address)
    return True


def _locations(*groups: tuple[SourceLocation, ...]) -> tuple[SourceLocation, ...]:
    unique: dict[tuple[str, int | None, int | None, str | None, str | None], SourceLocation] = {}
    for group in groups:
        for loc in group:
            key = (loc.source_name, loc.line_start, loc.line_end, loc.object_path, loc.object_id)
            unique.setdefault(key, loc)
    return tuple(unique.values())


def _interface_addresses(facts: SwitchFacts, version: int) -> tuple[_InterfaceAddress, ...]:
    addresses: list[_InterfaceAddress] = []
    for interface in facts.interfaces:
        if interface.mode == "l2" or (interface.mode == "unknown" and interface.kind not in {"vlan", "management"}):
            continue
        for entry in interface.addresses:
            if entry.status != "known" or entry.cidr is None:
                continue
            try:
                address = ip_interface(entry.cidr)
            except ValueError:
                continue
            if address.version == version:
                addresses.append(_InterfaceAddress(interface, address, entry.source_locations))
    return tuple(addresses)


def _connected(entry: _InterfaceAddress) -> ConfiguredRouteCandidate:
    return ConfiguredRouteCandidate(
        kind="connected", prefix=str(entry.address.network), interface=entry.interface.name,
        next_hop=None, source_locations=entry.source_locations,
        qualification="Интерфейс административно отключён."
        if entry.interface.admin_state == "disabled" else None,
    )


def _static(
    route: SwitchRoute, prefix: IPNetwork, connected: tuple[_InterfaceAddress, ...],
) -> ConfiguredRouteCandidate:
    interface = None
    locations = route.source_locations
    qualification = None
    try:
        hop = parse_switch_path_address(route.next_hop) if route.next_hop is not None else None
    except ValueError:
        hop = None
    if route.status != "known" or hop is None or hop.version != prefix.version:
        qualification = "Не подтверждён адрес следующего узла."
    elif route.parameters:
        qualification = "Дополнительные параметры маршрута требуют проверки."
    else:
        outgoing = [entry for entry in connected if _host_in(hop, entry.address.network)]
        if len({entry.interface.name for entry in outgoing}) == 1 and all(
            entry.interface.admin_state != "disabled" and entry.address.ip != hop for entry in outgoing
        ):
            interface = outgoing[0].interface.name
            locations = _locations(locations, *(entry.source_locations for entry in outgoing))
        else:
            qualification = "По настройкам не определён единственный выход к следующему узлу."
    return ConfiguredRouteCandidate(
        kind="default" if prefix.prefixlen == 0 else "static", prefix=str(prefix),
        interface=interface, next_hop=route.next_hop, source_locations=locations, qualification=qualification,
    )


def _destination_routes(
    facts: SwitchFacts, destination: IPAddress, vrf: str, connected: tuple[_InterfaceAddress, ...],
) -> tuple[tuple[ConfiguredRouteCandidate, ...], tuple[SourceLocation, ...] | None]:
    direct = [entry for entry in connected if _host_in(destination, entry.address.network)]
    static: list[tuple[SwitchRoute, IPNetwork]] = []
    unresolved: list[tuple[SourceLocation, ...]] = []
    for route in facts.routes:
        if route.kind != "static" or route.vrf not in (vrf, None):
            continue
        try:
            prefix = ip_network(route.prefix) if route.prefix else None
        except ValueError:
            prefix = None
        if prefix is None:
            unresolved.append(route.source_locations)
        elif destination in prefix:
            if route.vrf is None:
                unresolved.append(route.source_locations)
            else:
                static.append((route, prefix))
    unresolved_locations = _locations(*unresolved) if unresolved else None
    best_length = max(
        max((entry.address.network.prefixlen for entry in direct), default=-1),
        max((prefix.prefixlen for _, prefix in static), default=-1),
    )
    routes = [_connected(entry) for entry in direct if entry.address.network.prefixlen == best_length]
    routes.extend(_static(route, prefix, connected) for route, prefix in static if prefix.prefixlen == best_length)
    best: dict[tuple[str, str, str | None, str | None, str | None], ConfiguredRouteCandidate] = {}
    for route in routes:
        key = (route.kind, route.prefix, route.interface, route.next_hop, route.qualification)
        previous = best.get(key)
        if previous is not None:
            route = ConfiguredRouteCandidate(
                route.kind, route.prefix, route.interface, route.next_hop,
                _locations(previous.source_locations, route.source_locations), route.qualification,
            )
        best[key] = route
    return tuple(best.values()), unresolved_locations


def describe_switch_path(
    revision: DeviceRevision, source_ip: str, destination_ip: str, *, vrf: str | None = None,
) -> SwitchPathCandidate:
    """Объяснить один набор адресов в пределах настроек одного устройства."""
    source, destination = parse_switch_path_address(source_ip), parse_switch_path_address(destination_ip)
    if source.version != destination.version:
        raise ValueError("Источник и назначение должны иметь одно семейство IP")
    if vrf is not None and not vrf.strip():
        raise ValueError("Укажите имя VRF или оставьте выбор по подсети источника")
    context = vrf.strip() if vrf is not None else None
    facts = revision.parse_result.switch_facts
    source_interface = None
    source_locations: tuple[SourceLocation, ...] = ()
    gateways = tuple(route for route in facts.routes if route.kind == "management_gateway") if facts else ()

    def result(
        status: PathStatus, reason: str, next_evidence: str, *,
        routes: tuple[ConfiguredRouteCandidate, ...] = (),
        locations: tuple[SourceLocation, ...] = (),
    ) -> SwitchPathCandidate:
        return SwitchPathCandidate(
            status, reason, next_evidence, revision.revision_id, str(source), str(destination),
            context, source_interface, routes,
            _locations(source_locations, locations, *(route.source_locations for route in routes)), gateways,
        )

    if facts is None or facts.platform not in _SWITCH_PLATFORMS or revision.device.platform != facts.platform:
        return result(
            "unsupported", "Для выбранного снимка нет поддержанной конфигурации коммутатора.",
            "Откройте ревизию Aruba CX, ArubaOS-Switch или Comware с настройками интерфейсов.",
        )
    if source.is_link_local or destination.is_link_local:
        return result(
            "unsupported", "Для локального адреса требуется подтверждённый интерфейс связи.",
            "Уточните интерфейс и сегмент либо укажите адрес из маршрутизируемой сети.",
        )

    entries = _interface_addresses(facts, source.version)
    anchors = tuple(
        entry for entry in entries if (context is None or entry.interface.vrf in (context, None))
        and _host_in(source, entry.address.network)
    )
    if not anchors:
        return result(
            "insufficient_evidence", "В конфигурации нет подходящей подсети источника.",
            "Уточните VRF, интерфейс входа и конфигурацию ближайшего шлюза источника.",
        )
    source_locations = _locations(*(entry.source_locations for entry in anchors))
    possible_interfaces = {(entry.interface.vrf, entry.interface.name) for entry in anchors}
    ingress = anchors[0].interface
    if len(possible_interfaces) != 1 or ingress.vrf is None:
        return result(
            "ambiguous", "Адрес источника соответствует нескольким интерфейсам или VRF не определён.",
            "Подтвердите VRF и интерфейс входа источника.",
        )
    context, source_interface = ingress.vrf, ingress.name
    if ingress.admin_state == "disabled" or ingress.kind in {"management", "null"}:
        return result(
            "insufficient_evidence", "Подсеть источника найдена на управляющем или отключённом интерфейсе.",
            "Уточните действующий входной интерфейс или соберите отдельные настройки управления.",
        )
    if any(entry.address.ip == source for entry in anchors):
        return result(
            "insufficient_evidence", "Адрес источника назначен самому коммутатору.",
            "Для запроса от устройства укажите контекст исходящего трафика и его политику.",
        )

    owners = tuple(entry for entry in entries if entry.interface.vrf == context and entry.address.ip == destination)
    if owners:
        names = tuple(dict.fromkeys(entry.interface.name for entry in owners))
        locations = _locations(*(entry.source_locations for entry in owners))
        if len(names) > 1:
            return result(
                "ambiguous", "Адрес назначения задан на нескольких интерфейсах устройства.",
                "Уточните владельца адреса и действующие интерфейсы.", locations=locations,
            )
        return result(
            "local_destination", f"Назначение — собственный адрес коммутатора на {names[0]}.",
            "Проверьте состояние интерфейса, доступность сервиса и политику управления устройством.",
            locations=locations,
        )

    connected = tuple(
        entry for entry in entries if entry.interface.vrf == context and entry.interface.kind not in {"management", "null"}
    )
    if any(
        destination in entry.address.network and not _host_in(destination, entry.address.network)
        for entry in connected
    ):
        return result(
            "unsupported", "Назначение совпадает с адресом сети или broadcast настроенного сегмента.",
            "Выберите конкретный адрес устройства из этого сегмента.",
        )
    same = tuple(_connected(entry) for entry in anchors if _host_in(destination, entry.address.network))
    if same:
        other = tuple(
            _connected(entry) for entry in connected
            if entry.interface.name != source_interface and _host_in(destination, entry.address.network)
        )
        if other:
            return result(
                "ambiguous", "Подсеть источника и другой настроенный сегмент содержат адрес назначения.",
                "Подтвердите принадлежность адреса к VLAN и интерфейсу.", routes=(*same, *other),
            )
        return result(
            "same_segment", "Оба адреса попадают в одну настроенную подсеть входного интерфейса.",
            "Подтвердите VLAN и L2-связь между конечными устройствами и проверьте фильтрацию в сегменте.",
            routes=same,
        )

    routes, unresolved = _destination_routes(facts, destination, context, connected)
    if unresolved is not None or len(routes) > 1:
        return result(
            "ambiguous", "Есть конкурирующие или неоднозначно разобранные записи для маршрута.",
            "Соберите действующую таблицу маршрутизации и уточните параметры записей в этом VRF.",
            routes=routes, locations=unresolved or (),
        )
    if not routes:
        return result(
            "insufficient_evidence", "В распознанных настройках VRF нет префикса назначения.",
            "Соберите таблицу маршрутизации этого VRF и конфигурацию вышестоящего шлюза.",
        )
    route = routes[0]
    if route.qualification:
        return result(
            "insufficient_evidence", f"Найден настроенный префикс {route.prefix}. {route.qualification}",
            "Соберите таблицу маршрутизации и состояние интерфейсов для подтверждения следующего узла.",
            routes=routes,
        )
    return result(
        "configured_candidate", f"Наиболее специфичный распознанный префикс назначения — {route.prefix}.",
        "Проверьте действующий маршрут, привязанные политики, следующий узел и обратное направление.",
        routes=routes,
    )
