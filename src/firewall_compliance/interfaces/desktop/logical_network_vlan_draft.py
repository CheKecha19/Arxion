"""Предпросмотр логических сетей из выбранных наблюдений VLAN."""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import ip_interface
from typing import Any

type _VlanKey = tuple[str, int]


@dataclass(frozen=True, slots=True)
class LogicalNetworkVlanDraft:
    binding_key: _VlanKey | None
    vlan_id: int | None
    device: str
    site_id: str
    site: str
    name: str
    vrf: str
    subnets: tuple[str, ...]
    reason: str | None = None


def _vlan_id(value: object) -> int | None:
    return value if type(value) is int and 1 <= value <= 4094 else None


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _binding_key(value: object, vlan_id: int | None) -> _VlanKey | None:
    if not isinstance(value, (tuple, list)) or len(value) != 2 or vlan_id is None:
        return None
    device, number = value
    if not isinstance(device, str) or not device.strip() or _vlan_id(number) != vlan_id:
        return None
    return device, vlan_id


def _svi_values(
    observation: Mapping[str, Any], vlan_id: int | None,
) -> tuple[str, tuple[str, ...], str | None]:
    if vlan_id is None:
        return "", (), "Некорректный номер VLAN."
    names = {f"vlan {vlan_id}", f"vlan-interface{vlan_id}", f"vlan-interface {vlan_id}"}
    connections = observation.get("connections")
    matches = [
        interface for interface in connections
        if isinstance(interface, Mapping) and _text(interface.get("name")).casefold() in names
    ] if isinstance(connections, (list, tuple)) else []
    if len(matches) != 1:
        reason = "Несколько L3-интерфейсов VLAN." if matches else "L3-интерфейс VLAN не найден."
        return "", (), reason
    svi = matches[0]
    raw_vrf = _text(svi.get("vrf"))
    vrf = "" if raw_vrf == "default" else raw_vrf
    prefixes: set[str] = set()
    incomplete = bool(observation.get("incomplete_subnets")) or svi.get("address_method") in {"dhcp", "dhcp-bootp"}
    addresses = svi.get("vlan_addresses")
    if isinstance(addresses, (list, tuple)):
        for address in addresses:
            cidr = address.get("cidr") if isinstance(address, Mapping) and address.get("status") == "known" else None
            if not isinstance(cidr, str) or "/" not in cidr:
                incomplete = True
                continue
            try:
                prefixes.add(str(ip_interface(cidr).network))
            except ValueError:
                incomplete = True
    subnets = tuple(sorted(prefixes))
    if not raw_vrf:
        return vrf, subnets, "VRF L3-интерфейса VLAN не определён."
    if incomplete:
        return vrf, subnets, "Адреса L3-интерфейса VLAN распознаны не полностью."
    if not subnets:
        return vrf, subnets, "Нет подтверждённых подсетей L3-интерфейса VLAN."
    return vrf, subnets, None


def prepare_logical_network_vlan_drafts(
    observations: Sequence[Mapping[str, Any]], networks: Sequence[Mapping[str, Any]],
    bindings: Mapping[_VlanKey, str],
) -> tuple[LogicalNetworkVlanDraft, ...]:
    """Предложить отдельную сеть только для однозначного наблюдения."""
    domains = [(_text(row.get("site_id")), _vlan_id(row.get("vlan_id"))) for row in observations]
    repeated = Counter(domains)
    existing = {(_text(row.get("site_id")), _vlan_id(row.get("vlan_id"))) for row in networks}
    output: list[LogicalNetworkVlanDraft] = []
    for observation, domain in zip(observations, domains, strict=True):
        site_id, vlan_id = domain
        binding_key = _binding_key(observation.get("binding_key"), vlan_id)
        vrf, subnets, reason = _svi_values(observation, vlan_id)
        if binding_key is None:
            reason = "У наблюдения нет однозначного идентификатора устройства и VLAN."
        elif binding_key in bindings:
            reason = "VLAN уже привязан к логической сети."
        elif not site_id:
            reason = "Устройству нужно назначить площадку."
        elif domain in existing:
            reason = "На площадке уже есть сеть с этим VLAN ID. Проверьте привязку отдельно."
        elif repeated[domain] > 1:
            reason = "Выбрано несколько наблюдений VLAN на одной площадке. Проверьте их отдельно."
        name = _text(observation.get("name"))
        if not name or name == "—":
            name = f"VLAN {vlan_id}" if vlan_id is not None else "VLAN"
        device = _text(observation.get("device")) or (binding_key[0] if binding_key is not None else "—")
        output.append(LogicalNetworkVlanDraft(
            binding_key=binding_key, vlan_id=vlan_id, device=device, site_id=site_id,
            site=_text(observation.get("site")) or "Не назначена", name=name, vrf=vrf, subnets=subnets,
            reason=reason,
        ))
    return tuple(output)
