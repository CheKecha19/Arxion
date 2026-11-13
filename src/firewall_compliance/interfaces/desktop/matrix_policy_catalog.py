"""Поиск идентификаторов политик в сохранённых источниках сверки."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from ipaddress import ip_interface
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from firewall_compliance.application.cloud_analysis import vmware_device_id, vmware_scope_revision
from firewall_compliance.application.cloud_security_groups import security_group_snapshot
from firewall_compliance.application.cloud_sg_revision import (
    CloudSGRevisionProjector,
    CloudSGSelection,
    cloud_sg_policy_id,
    cloud_sg_revision,
)
from firewall_compliance.application.matrix_policy import matrix_catalog_switch_policy_contexts
from firewall_compliance.application.matrix_scope_cloud import matrix_scope_vmware_replacing_scan_id
from firewall_compliance.domain.cloud_security_groups import CloudSecurityGroupSnapshot, SGDirection
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.matrix_vmware_origin import VMwareMatrixOrigin
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.matrix_store import AccessMatrixStore

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.project_store import ProjectStore


type _Family = Literal[4, 6]
type _Projection = tuple[SGDirection, _Family]
type _Owner = tuple[str, ...]
type _Sources = dict[str, dict[_Owner, _PolicySource]]

_PROJECTIONS: tuple[_Projection, ...] = (
    ("ingress", 4), ("egress", 4), ("ingress", 6), ("egress", 6),
)
_PURPOSES = {
    "transit": "транзит", "management": "управление", "unbound": "без привязки", "unknown": "назначение неизвестно",
}


@dataclass(frozen=True, slots=True)
class MatrixPolicyChoice:
    policy_id: str
    label: str
    search: str = ""


@dataclass(frozen=True, slots=True)
class _SavedRunRevision:
    run_id: str
    item_id: str
    revision_id: UUID


type _DraftOrigin = _SavedRunRevision | VMwareMatrixOrigin | CloudSGSelection


@dataclass(frozen=True, slots=True)
class _PolicySource:
    label: str
    timestamp: str
    origin: _DraftOrigin | None
    source_token: str | None = None


@dataclass(frozen=True, slots=True)
class MatrixDraftSourceChoice:
    policy_id: str
    label: str
    search: str
    origin: _DraftOrigin
    source_token: str | None = None

    @property
    def provenance(self) -> str:
        return _draft_provenance(self.origin)


def _draft_provenance(origin: _DraftOrigin) -> str:
    if isinstance(origin, _SavedRunRevision):
        return f"запуск {origin.run_id} · элемент {origin.item_id}"
    if isinstance(origin, VMwareMatrixOrigin):
        return f"сбор {origin.scan_id} · Edge Gateway {origin.resource_id} · индекс записи {origin.record_index}"
    group = f"группа {origin.group_id}" if origin.group_id is not None else "все группы интерфейса"
    direction = "входящие" if origin.direction == "ingress" else "исходящие"
    return f"сбор {origin.scan_id} · интерфейс {origin.interface_id} · {group} · {direction} IPv{origin.family}"


def _policy_id(value: object) -> str | None:
    # Поле матрицы нормализует пробелы и ограничивает длину. Обрезанный ID
    # нельзя предлагать, поскольку он не найдёт исходную политику.
    return value if isinstance(value, str) and 0 < len(value) <= 256 and value == value.strip() else None


def _label(*parts: str | None) -> str:
    return " · ".join(dict.fromkeys(part for part in parts if part))


def _text(value: object) -> str | None:
    return (value.strip() or None) if isinstance(value, str) else None


def _endpoint(config: Mapping[str, Any]) -> str | None:
    site = _text(config.get("site"))
    if site is None:
        return None
    try:
        parsed = urlsplit(site if "://" in site else f"//{site}")
        host, port = parsed.hostname, parsed.port
        if host is not None and port is not None:
            return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        return host
    except ValueError:
        return None


def _local_sources(
    store: ProjectStore, project_id: str, site_id: str | None, vmware_headers: tuple[dict[str, Any], ...],
    sources: _Sources, cancelled: Callable[[], bool],
) -> None:
    for run_id, item_id, raw in store.latest_matrix_revisions(
        project_id, site_id, cancelled=cancelled, policies_only=True,
    ):
        if cancelled():
            return
        try:
            revision = DeviceRevision.model_validate(raw)
        except ValueError:
            continue
        device, parsed = revision.device, revision.parse_result
        rules = parsed.rules
        if device.platform == "cloud-ru-vmware-nsxt" and rules and (policy := rules[0].policy_id) is not None:
            if matrix_scope_vmware_replacing_scan_id(revision, vmware_headers, vmware_policy_ids=frozenset({policy})):
                continue
        vrfs = matrix_catalog_switch_policy_contexts(revision)
        facts = parsed.switch_facts
        name = device.hostname or (facts.hostname if facts else None) or device.device_id
        owner = "device", device.device_id, device.platform, device.context or ""
        origin = _SavedRunRevision(run_id, item_id, revision.revision_id)
        timestamp = parsed.configuration.captured_at.isoformat(timespec="seconds")
        counts: Counter[str] = Counter()
        purposes: dict[str, set[str]] = defaultdict(set)
        zone_pairs: dict[str, set[str]] = defaultdict(set)
        for rule in rules:
            if cancelled():
                return
            if not rule.enabled or (policy := _policy_id(rule.policy_id)) is None:
                continue
            counts[policy] += 1
            if rule.policy_purpose is not None:
                purposes[policy].add(_PURPOSES[rule.policy_purpose])
            if rule.zone_status == DataStatus.KNOWN and rule.source_zone is not None and rule.destination_zone is not None:
                zone_pairs[policy].add(f"{rule.source_zone} → {rule.destination_zone}")
        for policy, count in counts.items():
            zones = sorted(zone_pairs.get(policy, ()), key=str.casefold)
            zone_label = ", ".join(zones[:2])
            if len(zones) > 2:
                zone_label += f" (+{len(zones) - 2})"
            label = _label(
                name, device.platform, device.context, f"VRF {vrfs[policy]}" if policy in vrfs else None,
                ", ".join(sorted(purposes.get(policy, ()))), zone_label, f"правил: {count}",
            )
            sources.setdefault(policy, {})[owner] = _PolicySource(label, timestamp, origin)


def _vmware_sources(
    selections: tuple[tuple[dict[str, Any], tuple[dict[str, Any], ...]], ...],
    sources: _Sources, cancelled: Callable[[], bool],
) -> None:
    for header, records in selections:
        config = header["config"]
        endpoint, tenant = _endpoint(config), _text(config.get("tenant"))
        for record in records:
            if cancelled():
                return
            policy = _policy_id(record.get("id"))
            if policy is None or policy.startswith("sg:"):
                continue
            owner = "device", vmware_device_id(config, policy), "cloud-ru-vmware-nsxt", ""
            label = _label(
                _text(record.get("name")) or policy, "Cloud.ru VMware Edge Firewall", tenant, endpoint,
                _text(record.get("vdc")), "частичный сбор" if header["state"] == "partial" else None,
            )
            origin = VMwareMatrixOrigin(
                scan_id=header["id"], record_index=record["record_index"], resource_id=policy,
            )
            timestamp = _text(header.get("finished_at")) or _text(header.get("created_at")) or ""
            sources.setdefault(policy, {})[owner] = _PolicySource(label, timestamp, origin, _text(header.get("finished_at")))


def _sg_sources(
    snapshot: CloudSecurityGroupSnapshot, region: str | None, sources: _Sources, cancelled: Callable[[], bool],
) -> dict[str, tuple[_Owner, _PolicySource]]:
    groups = {group.group_id: group for group in snapshot.groups if group.scope_id == snapshot.scope_id}
    enabled: dict[str, set[_Projection]] = defaultdict(set)
    platform = f"Cloud.ru {snapshot.platform.capitalize()} SG"
    projections = _PROJECTIONS if snapshot.platform == "advanced" else _PROJECTIONS[:2]
    for group_id, group in groups.items():
        for rule in group.rules:
            if cancelled():
                return {}
            if rule.enabled is not False:
                enabled[group_id].update(
                    (direction, family) for direction, family in projections
                    if rule.direction in (None, direction) and rule.family in (None, family)
                )
    orders: dict[str, tuple[_Owner, _PolicySource]] = {}
    timestamp = snapshot.captured_at.isoformat(timespec="seconds")
    interface_counts = Counter(interface.interface_id for interface in snapshot.interfaces)
    for interface in snapshot.interfaces:
        if cancelled():
            return {}
        if (
            interface_counts[interface.interface_id] != 1 or interface.scope_id != snapshot.scope_id
            or interface.assignments_status != "present" or interface.security_enabled is False or not interface.addresses
        ):
            continue
        families = {ip_interface(address).version for address in interface.addresses}
        attached = {
            item.group_id for item in interface.assignments if item.state == "present" and item.group_id in groups
        }
        confirmed_assignments = bool(attached) and all(
            item.state == "present" and item.group_id in attached for item in interface.assignments
        )
        label = interface.name or interface.interface_id
        context = _label(
            platform, snapshot.project_id, region, interface.zone_id, interface.network_id or interface.subnet_id,
        )
        incomplete = "частичные сведения" if snapshot.scan_status != "completed" else None
        for direction, family in projections:
            if family not in families:
                continue
            projection = direction, family
            traffic = f"{'входящие' if direction == 'ingress' else 'исходящие'} IPv{family}"
            for group_id in attached:
                if cancelled():
                    return {}
                if projection not in enabled[group_id]:
                    continue
                group = groups[group_id]
                policy = cloud_sg_policy_id(snapshot.scope_id, group_id, direction, family)
                owner = "sg", snapshot.scope_id, interface.interface_id, group_id
                owner_label = _label(
                    group.name or group_id, traffic, context, label,
                    incomplete or ("частичные сведения" if group.rules_status != "present" else None),
                )
                origin = CloudSGSelection(
                    scan_id=snapshot.scan_id, group_id=group_id, interface_id=interface.interface_id,
                    scope_id=snapshot.scope_id, direction=direction, family=family,
                )
                sources.setdefault(policy, {})[owner] = _PolicySource(owner_label, timestamp, origin, snapshot.source_sha256)
            if not confirmed_assignments:
                continue
            policy = cloud_sg_policy_id(snapshot.scope_id, "interface/" + interface.interface_id, direction, family)
            owner = "sg", snapshot.scope_id, interface.interface_id, ""
            owner_label = _label("Все группы интерфейса", traffic, context, label, incomplete)
            if snapshot.platform == "evolution" and any(projection in enabled[group_id] for group_id in attached):
                origin = CloudSGSelection(
                    scan_id=snapshot.scan_id, interface_id=interface.interface_id,
                    scope_id=snapshot.scope_id, direction=direction, family=family,
                )
                sources.setdefault(policy, {})[owner] = _PolicySource(owner_label, timestamp, origin, snapshot.source_sha256)
            elif snapshot.platform == "advanced" and direction == "ingress" and len(attached) > 1:
                orders[policy] = owner, _PolicySource(owner_label, timestamp, None, snapshot.source_sha256)
    return orders


def _cloud_sources(
    store: ProjectStore, project_id: str, site_id: str | None, sources: _Sources, cancelled: Callable[[], bool],
    *, for_draft: bool,
) -> None:
    snapshots: dict[str, CloudSecurityGroupSnapshot] = {}
    ordered: dict[str, tuple[_Owner, _PolicySource]] = {}
    for scan in store.latest_matrix_cloud_scans(project_id, site_id, cancelled=cancelled):
        if cancelled():
            return
        if scan["state"] not in {"completed", "partial"}:
            continue
        try:
            snapshot = security_group_snapshot(scan)
        except ValueError:
            continue
        orders = _sg_sources(snapshot, _text(scan["config"].get("region")), sources, cancelled)
        if orders:
            snapshots[snapshot.scan_id] = snapshot
            ordered.update(orders)
    if not ordered or cancelled():
        return
    candidates: dict[str, dict[tuple[str, ...], CloudSGSelection]] = defaultdict(dict)
    projectors: dict[str, CloudSGRevisionProjector] = {}
    for selection in AccessMatrixStore(store.path).cloud_order_selections(
        project_id, site_id or project_id, snapshots, ordered.keys(), cancelled=cancelled,
    ):
        if cancelled():
            return
        order, snapshot = selection.order_evidence, snapshots.get(selection.scan_id)
        if order is None or snapshot is None:
            continue
        policy = cloud_sg_policy_id(
            selection.scope_id, "interface/" + selection.interface_id, selection.direction, selection.family,
        )
        if policy not in ordered or order.group_ids in candidates[policy]:
            continue
        if for_draft:
            if order.snapshot_sha256 != snapshot.source_sha256 or order.observed_at != snapshot.captured_at:
                continue
        else:
            if snapshot.scan_id not in projectors:
                projectors[snapshot.scan_id] = CloudSGRevisionProjector(snapshot)
            try:
                revision = projectors[snapshot.scan_id].project(selection, imported_at=snapshot.captured_at)
            except ValueError:
                continue
            if not any(rule.enabled and rule.policy_id == policy for rule in revision.parse_result.rules):
                continue
        candidates[policy][order.group_ids] = selection
    for policy, orders in candidates.items():
        if len(orders) == 1 and policy in ordered:
            owner, source = ordered[policy]
            label = _label(source.label, "подтверждён порядок")
            sources.setdefault(policy, {})[owner] = _PolicySource(
                label, source.timestamp, next(iter(orders.values())), source.source_token,
            )


def _saved_policy_sources(
    store: ProjectStore, project_id: str, site_id: str | None, cancelled: Callable[[], bool], *, for_draft: bool,
) -> _Sources:
    sources: _Sources = {}
    vmware = store.latest_matrix_vmware_policy_records(project_id, site_id, cancelled=cancelled)
    _local_sources(store, project_id, site_id, tuple(header for header, _ in vmware), sources, cancelled)
    _vmware_sources(vmware, sources, cancelled)
    _cloud_sources(store, project_id, site_id, sources, cancelled, for_draft=for_draft)
    return sources


def matrix_policy_choices(
    store: ProjectStore, project_id: str, site_id: str | None, *, cancelled: Callable[[], bool] | None = None,
) -> tuple[MatrixPolicyChoice, ...]:
    """Показать ID и доступные источники, сохраняя неоднозначность назначения."""
    stop = cancelled or (lambda: False)
    sources = _saved_policy_sources(store, project_id, site_id, stop, for_draft=False)
    if stop():
        return ()
    choices: list[MatrixPolicyChoice] = []
    for policy, owners in sources.items():
        if stop():
            return ()
        labels = sorted({source.label for source in owners.values()}, key=lambda label: (label.casefold(), label))
        owner_list = " / ".join(labels[:3])
        if len(labels) > 3:
            owner_list += f" (+{len(labels) - 3})"
        label = _label(
            owner_list, policy, f"источников: {len(owners)} · нужен выбор при сверке" if len(owners) > 1 else None,
        )
        search = " ".join(dict.fromkeys((label, *labels, *(part for owner in owners for part in owner[1:] if part))))
        choices.append(MatrixPolicyChoice(policy, label, search))
    return tuple(sorted(choices, key=lambda choice: (choice.label.casefold(), choice.policy_id)))


def matrix_draft_source_choices(
    store: ProjectStore, project_id: str, site_id: str | None, *, cancelled: Callable[[], bool] | None = None,
) -> tuple[MatrixDraftSourceChoice, ...]:
    """Показать конкретный источник каждой политики для просмотра её объявлений."""
    stop = cancelled or (lambda: False)
    choices = []
    for policy, owners in _saved_policy_sources(store, project_id, site_id, stop, for_draft=True).items():
        for owner, source in owners.items():
            if stop():
                return ()
            if source.origin is None:
                continue
            if isinstance(source.origin, _SavedRunRevision):
                owner_label = owner[1]
            elif isinstance(source.origin, CloudSGSelection):
                owner_label = source.origin.interface_id
            else:
                owner_label = None
            label = _label(source.label, policy, owner_label, source.timestamp)
            search = " ".join(dict.fromkeys((
                label, _draft_provenance(source.origin), *(part for part in owner[1:] if part),
            )))
            choices.append(MatrixDraftSourceChoice(policy, label, search, source.origin, source.source_token))
    return tuple(sorted(choices, key=lambda choice: (choice.label.casefold(), choice.policy_id, choice.provenance)))


def load_matrix_draft_revision(
    store: ProjectStore, project_id: str, site_id: str | None, choice: MatrixDraftSourceChoice,
) -> DeviceRevision:
    """Открыть выбранное объявление по его исходной записи в проекте."""
    origin = choice.origin
    if isinstance(origin, _SavedRunRevision):
        item = store.get_run_item(project_id, origin.run_id, origin.item_id)
        if item is None:
            raise ValueError("Выбранный снимок отсутствует в проекте.")
        revision = DeviceRevision.model_validate(item.get("revision"))
        if revision.revision_id != origin.revision_id:
            raise ValueError("Выбранный снимок больше не совпадает с исходной ревизией.")
        if site_id is not None:
            sites = store.workspace_metadata.device_sites(project_id)
            if sites.get(revision.device.device_id, "") != site_id:
                raise ValueError("Выбранное устройство больше не относится к площадке.")
    elif isinstance(origin, VMwareMatrixOrigin):
        scan = store.get_cloud_scan_header(project_id, origin.scan_id)
        if scan is None or _text(scan.get("finished_at")) != choice.source_token:
            raise ValueError("Выбранный сбор Edge Gateway изменился. Выберите снимок повторно.")
        ref = origin.scan_id, origin.record_index
        record = store.read_cloud_resource_records(project_id, (ref,)).get(ref)
        if record is None or record.get("type") != "edges":
            raise ValueError("Выбранная запись Edge Gateway отсутствует в проекте.")
        if store.get_cloud_scan_header(project_id, origin.scan_id) != scan:
            raise ValueError("Выбранный сбор Edge Gateway изменился. Выберите снимок повторно.")
        revision = vmware_scope_revision(scan, origin, project_id=project_id, site_id=site_id, record=record)
    else:
        scan = store.get_cloud_scan(project_id, origin.scan_id)
        if scan is None or scan["state"] not in {"completed", "partial"}:
            raise ValueError("Выбранный сбор групп безопасности отсутствует в проекте.")
        snapshot = security_group_snapshot(scan)
        if snapshot.source_sha256 != choice.source_token:
            raise ValueError("Выбранный сбор групп безопасности изменился. Выберите снимок повторно.")
        if site_id is not None and site_id not in snapshot.workspace_site_ids:
            raise ValueError("Выбранный сбор групп безопасности не относится к площадке.")
        revision = cloud_sg_revision(snapshot, origin, imported_at=snapshot.captured_at)
    if not any(rule.enabled and rule.policy_id == choice.policy_id for rule in revision.parse_result.rules):
        raise ValueError("В выбранном снимке нет активных правил этой политики.")
    return revision
