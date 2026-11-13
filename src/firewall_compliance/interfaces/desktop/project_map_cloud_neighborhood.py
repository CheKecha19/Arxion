"""Окружение одного ресурса по исходным записям сохранённого облачного сбора."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from firewall_compliance.application.cloud_security_groups import security_group_snapshot
from firewall_compliance.domain.cloud_security_groups import CloudSGRule
from firewall_compliance.interfaces.desktop.cloud_map_references import (
    CloudReference,
    canonical_cloud_reference,
    cloud_references,
    reference_value,
)
from firewall_compliance.interfaces.desktop.project_map import (
    ProjectMap,
    ProjectMapEdge,
    ProjectMapNode,
    RuleEvidence,
    build_project_map,
    identity,
)
from firewall_compliance.interfaces.desktop.workspace_models import cloud_resource_key

type TypedId = tuple[str, str]
_VMWARE_COVERAGE_WARNING = "Не собраны сетевые подключения ВМ:"


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _same_id(left: object, right: object, kind: str) -> bool:
    first, second = reference_value(left), reference_value(right)
    return bool(
        first and second
        and canonical_cloud_reference(first, kind) == canonical_cloud_reference(second, kind)
    )


def _group_references(value: object, path: str) -> tuple[CloudReference, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        CloudReference(
            "security_groups", canonical_cloud_reference(group_id, "security_groups"), f"{path}[{index}]",
        )
        for index, member in enumerate(value)
        if (group_id := reference_value(member)) is not None
    )


@dataclass(frozen=True, slots=True)
class _Record:
    index: int
    kind: str
    value: dict[str, Any]
    identities: frozenset[TypedId]
    references: tuple[CloudReference, ...]
    project: str | None
    zone: str | None


def _read_record(
    index: int, value: dict[str, Any], platform: str, provider_project: str | None,
) -> _Record:
    inventory = _object(value.get("inventory"))
    attachments = _object(value.get("data")).get("vm_networks", ())
    kind = str(value.get("type") or "unknown")
    aliases = frozenset(
        (kind, canonical_cloud_reference(raw, kind))
        for raw in (value.get("id"), inventory.get("id"), inventory.get("href"))
        if isinstance(raw, str) and raw.strip()
    )
    # Подтверждение SG у Advanced хранится в согласованной записи порта VPC.
    # Самостоятельные строки security_groups внутри карточки ВМ могут быть именами.
    references = list(cloud_references(inventory))
    references.extend(cloud_references(attachments, "data.vm_networks"))
    if (platform, kind) in {("evolution", "interfaces"), ("advanced", "ports")}:
        references.extend(_group_references(inventory.get("security_groups"), "inventory.security_groups"))
        vm_field = "device_id" if platform == "advanced" else "vm_id"
        if platform == "evolution" and not reference_value(inventory.get(vm_field)):
            vm_field = "vm"
        vm = reference_value(inventory.get(vm_field))
        if vm:
            references.append(CloudReference("vms", canonical_cloud_reference(vm, "vms"), f"inventory.{vm_field}"))
    if kind == "vms" and isinstance(attachments, list):
        for position, raw in enumerate(attachments):
            attachment = _object(raw)
            path = f"data.vm_networks[{position}]"
            if platform == "evolution" and reference_value(attachment.get("id")):
                vm = attachment.get("vm_id") or attachment.get("vm")
                attachment_project = reference_value(attachment.get("project_id") or attachment.get("tenant_id"))
                if (
                    (vm is None or _same_id(vm, value.get("id"), "vms"))
                    and (not attachment_project or _same_id(attachment_project, provider_project, "projects"))
                ):
                    references.extend(_group_references(
                        attachment.get("security_groups"), path + ".security_groups",
                    ))
            if platform == "advanced" and attachment.get("vpc_port_status") == "present":
                port = _object(attachment.get("vpc_port"))
                if (
                    _same_id(attachment.get("port_id"), port.get("id"), "interfaces")
                    and _same_id(port.get("device_id"), value.get("id"), "vms")
                    and _same_id(attachment.get("net_id"), port.get("network_id"), "networks")
                    and _same_id(port.get("tenant_id"), provider_project, "projects")
                ):
                    references.extend(_group_references(
                        port.get("security_groups"), path + ".vpc_port.security_groups",
                    ))
    return _Record(
        index, kind, value, aliases,
        tuple(sorted(set(references))),
        reference_value(inventory.get("project_id") or inventory.get("tenant_id")),
        reference_value(inventory.get("zone_id") or inventory.get("zone")),
    )


def _rule_rows(record: _Record) -> list[object] | None:
    rows = _object(record.value.get("data")).get("security_rules")
    if isinstance(rows, dict):
        rows = rows.get("items", rows.get("rules"))
    return rows if isinstance(rows, list) else None


def _rule_path(record: _Record, position: int) -> str:
    source = _object(record.value.get("data")).get("security_rules")
    path = f"/result/records/{record.index}/data/security_rules"
    if isinstance(source, dict):
        path += "/items" if "items" in source else "/rules"
    return f"{path}/{position}"


def _rule_group_refs(raw: object) -> frozenset[TypedId]:
    rule = _object(raw)
    return frozenset(
        ("security_groups", canonical_cloud_reference(group_id, "security_groups"))
        for field in ("remote_group_id", "remote_security_group")
        if (group_id := reference_value(rule.get(field))) is not None
    )


def _service(rule: CloudSGRule) -> tuple[str, ...]:
    service = rule.service
    if service is None:
        return ()
    protocol = str(service.protocol_number) if service.protocol == "number" else service.protocol.upper()
    ports = ", ".join(
        str(port.start) if port.start == port.end else f"{port.start}–{port.end}"
        for port in service.ports
    )
    if service.any_ports:
        ports = "все порты"
    if service.icmp_type is not None:
        ports = f"тип {service.icmp_type}"
        if service.icmp_code is not None:
            ports += f", код {service.icmp_code}"
    return (" ".join(part for part in (protocol, ports) if part),)


def _sg_group_record(record: _Record, include_rules: bool) -> dict[str, Any]:
    """Keep only the SG inputs consumed by the existing declaration parser."""
    inventory = _object(record.value.get("inventory"))
    return {
        "id": record.value.get("id"),
        "name": record.value.get("name"),
        "type": record.kind,
        "inventory": {
            key: inventory[key] for key in ("id", "project_id", "tenant_id", "zone", "zone_id", "vpc_id")
            if key in inventory
        },
        "data": {"security_rules": _rule_rows(record)} if include_rules else {},
    }


def _compatible(source: _Record, target: _Record, provider_project: str | None) -> bool:
    projects = [value for value in (provider_project, source.project, target.project) if value]
    return (
        len({canonical_cloud_reference(value, "projects") for value in projects}) < 2
        and (not source.zone or not target.zone or _same_id(source.zone, target.zone, "zones"))
    )


def cloud_resource_neighborhood(
    project_id: str,
    scan: dict[str, Any],
    record_index: int,
    *,
    resource_id: str | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> ProjectMap:
    """Выбрать прямые ссылки и относящиеся правила без построения всей карты."""
    if scan.get("project_id", project_id) != project_id or not scan.get("id"):
        raise ValueError("Облачный сбор не принадлежит выбранному проекту.")
    if scan.get("workspace_projection"):
        raise ValueError("Для окружения нужна полная запись исходного облачного сбора.")
    payload = _object(scan.get("result"))
    records = payload.get("records")
    if (
        not isinstance(records, list) or type(record_index) is not int
        or not 0 <= record_index < len(records) or not isinstance(records[record_index], dict)
    ):
        raise ValueError("Исходная запись облачного ресурса недоступна.")
    if resource_id is not None and records[record_index].get("id") != resource_id:
        raise ValueError("Сохранённая запись не совпадает с выбранным облачным ресурсом.")

    def guard() -> None:
        if cancelled is not None and cancelled():
            raise InterruptedError("Подготовка окружения отменена.")

    config = _object(scan.get("config"))
    if not isinstance(scan.get("config"), dict):
        raise ValueError("В сохранённом сборе отсутствуют сведения о подключении.")
    platform = str(config.get("platform") or "vmware")
    provider_project = reference_value(config.get("project_id"))
    all_records: dict[int, _Record] = {}
    by_id: dict[TypedId, set[int]] = defaultdict(set)
    for index, raw in enumerate(records):
        guard()
        if not isinstance(raw, dict):
            continue
        record = _read_record(index, raw, platform, provider_project)
        all_records[index] = record
        for reference in record.identities:
            by_id[reference].add(index)
    anchor = all_records[record_index]
    chosen = {anchor.index}
    explicit: list[tuple[_Record, CloudReference, frozenset[int]]] = []
    policy_groups = {anchor.index} if anchor.kind == "security_groups" else set()
    policy_edges = {anchor.index} if anchor.kind == "edges" else set()
    reverse_rule_indices: dict[int, set[int]] = {}

    def add_reference(record: _Record, ref: CloudReference) -> None:
        matches = frozenset(by_id.get((ref.kind, ref.identifier), ()))
        if matches == {record.index}:
            return
        explicit.append((record, ref, matches))
        chosen.add(record.index)
        if len(matches) == 1:
            target = all_records[next(iter(matches))]
            chosen.add(target.index)
            if not _compatible(record, target, provider_project):
                return
            if ref.kind == "security_groups":
                policy_groups.add(target.index)
            elif target.kind == "edges" and record.index == anchor.index:
                policy_edges.add(target.index)

    for record in all_records.values():
        guard()
        for ref in record.references:
            if record.index == anchor.index or (ref.kind, ref.identifier) in anchor.identities:
                add_reference(record, ref)

    # Когда ВМ связана с отдельной записью интерфейса, берём явно указанные на
    # этом интерфейсе группы. Соседние ВМ и сети не раскрываются рекурсивно.
    if anchor.kind == "vms":
        interfaces = {"interfaces", "ports"}
        linked_interfaces: set[int] = set()
        for record, _, matches in tuple(explicit):
            if len(matches) != 1:
                continue
            target = all_records[next(iter(matches))]
            if not _compatible(record, target, provider_project):
                continue
            attached = (
                record if record.kind in interfaces and target.index == anchor.index
                else target if target.kind in interfaces and record.index == anchor.index else None
            )
            if attached is not None:
                linked_interfaces.add(attached.index)
        for index in sorted(linked_interfaces):
            attached = all_records[index]
            for group_ref in attached.references:
                if group_ref.kind == "security_groups":
                    add_reference(attached, group_ref)

    if anchor.kind == "security_groups":
        for record in all_records.values():
            guard()
            if record.kind != "security_groups" or record.index == anchor.index:
                continue
            matching = set()
            for position, raw in enumerate(_rule_rows(record) or ()):
                guard()
                if _rule_group_refs(raw) & anchor.identities:
                    matching.add(position)
            if matching:
                reverse_rule_indices[record.index] = matching
                policy_groups.add(record.index)
                chosen.add(record.index)

    # Данные групп-получателей нужны для разрешения точных ссылок. Их собственные
    # правила не входят в окружение, если группа сама не связана с ресурсом.
    group_records = set(policy_groups)
    for index in sorted(policy_groups):
        guard()
        record = all_records[index]
        for alias in record.identities:
            group_records.update(by_id[alias])
        for position, raw in enumerate(_rule_rows(record) or ()):
            guard()
            if index in reverse_rule_indices and position not in reverse_rule_indices[index]:
                continue
            for ref in _rule_group_refs(raw):
                candidates = by_id.get(ref, set())
                group_records.update(candidates)
                if len(candidates) == 1:
                    chosen.update(candidates)

    used_keys: set[str] = set()
    keys: dict[int, str] = {}
    clouds: list[dict[str, Any]] = []
    for index in (anchor.index, *sorted(chosen - {anchor.index})):
        guard()
        record = all_records[index]
        key = "cloud:" + cloud_resource_key(scan, record.value, index)
        if key in used_keys:
            key += f":record:{index}"
        used_keys.add(key)
        keys[index] = key
        data = _object(record.value.get("data"))
        projected = record.value if index in policy_edges and platform == "vmware" else {
            **record.value, "inventory": _object(record.value.get("inventory")),
            "data": {field: value for field, value in data.items() if field not in {"security_rules", "firewall"}},
        }
        clouds.append({
            "id": key, "kind": "cloud", "scan": scan, "record_index": index, "platform": platform,
            "record": projected,
        })
    graph = build_project_map(
        project_id, (), clouds, group_rule_pairs=True, resolve_cloud_references=False,
        resolve_cloud_rule_addresses=False, cancelled=cancelled,
    )
    nodes = {node.key: node for node in graph.nodes}
    edges = list(graph.edges)
    anchor_key = keys[anchor.index]
    warnings = [warning for warning in graph.warnings if not warning.startswith(_VMWARE_COVERAGE_WARNING)]
    warnings.insert(
        0, f"Окружение по сохранённому сбору {scan['id']} · {scan.get('created_at', 'дата неизвестна')}.",
    )
    if scan.get("state") != "completed":
        warnings.append("Сбор неполный или прерван. Часть записей и связей может отсутствовать.")
    if payload.get("errors") or payload.get("integrity_warnings"):
        warnings.append("В сборе есть ошибки или предупреждения. Подробности доступны в исходной операции.")
    if anchor.kind == "vms" and not isinstance(_object(anchor.value.get("data")).get("vm_networks"), list):
        warnings.append("Сетевые подключения выбранной ВМ отсутствуют в сохранённом сборе.")
    for index in sorted(policy_edges):
        record = all_records[index]
        if not isinstance(_object(record.value.get("data")).get("firewall"), dict):
            warnings.append(f"{nodes[keys[index]].label}: правила Edge Firewall отсутствуют в сборе.")
    if policy_groups:
        warnings.append("Показаны объявления выбранной или явно связанной группы, порядок применения не рассчитывался.")
    if any(all_records[index].kind == "edges" for index in chosen - policy_edges):
        warnings.append("Правила соседнего Edge без прямой ссылки от выбранного ресурса не раскрывались.")

    for record, ref, matches in explicit:
        guard()
        source = nodes[keys[record.index]]
        target_record = all_records[next(iter(matches))] if len(matches) == 1 else None
        details = (
            f"Явная ссылка API: {ref.kind} / {ref.identifier}",
            f"Сбор: {scan['id']}, запись {record.index}, поле {ref.path}.",
        )
        if target_record is None:
            target_key = "cloud-reference:" + identity(scan["id"], ref.kind, ref.identifier)
            reason = "Объект не получен в этом сборе" if not matches else "Ссылка имеет несколько кандидатов"
            nodes.setdefault(target_key, ProjectMapNode(
                target_key, ref.kind + " · " + ref.identifier, "network", source.area,
                "Неразрешённые ссылки API", details=(reason, *details), scope=source.scope,
            ))
            edges.append(ProjectMapEdge(source.key, target_key, "attachment", status="unknown", details=(reason, *details)))
            continue
        target = nodes[keys[target_record.index]]
        compatible = _compatible(record, target_record, provider_project)
        if not compatible:
            details += ("Связь не подтверждена: проект или зона различаются.",)
        edges.append(ProjectMapEdge(
            source.key, target.key, "attachment", status="known" if compatible else "unknown", details=details,
        ))

    if policy_groups and platform in {"advanced", "evolution"}:
        guard()
        _add_group_policy(
            scan, policy_groups, group_records, reverse_rule_indices, all_records,
            by_id, keys, nodes, edges, warnings, guard,
        )
    if not edges:
        warnings.append("В сохранённых данных нет подтверждённых связей с выбранным ресурсом.")
    visible = {anchor_key, *(edge.source for edge in edges), *(edge.target for edge in edges)}
    visible.update(rule.owner_id for edge in edges for rule in edge.rules)
    return replace(
        graph, nodes=tuple(node for key, node in nodes.items() if key in visible),
        edges=tuple(edges), warnings=tuple(dict.fromkeys(warnings)),
    )


def _add_group_policy(
    scan: dict[str, Any],
    policy_groups: set[int],
    group_records: set[int],
    reverse_rule_indices: dict[int, set[int]],
    records: Mapping[int, _Record],
    by_id: Mapping[TypedId, set[int]],
    keys: Mapping[int, str],
    nodes: dict[str, ProjectMapNode],
    edges: list[ProjectMapEdge],
    warnings: list[str],
    guard: Callable[[], None],
) -> None:
    # Парсер получает только выбранные группы. Путь к правилу ниже строится
    # по индексу исходной записи, а не позиции группы в этой выборке.
    selected: list[dict[str, Any]] = []
    for index in sorted(group_records):
        guard()
        selected.append(_sg_group_record(records[index], index in policy_groups))
    try:
        snapshot = security_group_snapshot({**scan, "result": {"records": selected}})
    except (TypeError, ValueError):
        warnings.append("Условия группы безопасности не удалось восстановить из сохранённого сбора.")
        return
    grouped: dict[tuple[str, str, str, str, bool, str], list[RuleEvidence]] = defaultdict(list)
    for group in snapshot.groups:
        guard()
        alias = ("security_groups", canonical_cloud_reference(group.group_id, "security_groups"))
        candidates = by_id.get(alias, set())
        if not candidates & policy_groups:
            continue
        if len(candidates) != 1 or group.rules_status in {"ambiguous", "outside_scope"}:
            warnings.append(f"{group.name}: группа неоднозначна или относится к другой области.")
            continue
            index = next(iter(candidates))
        if index not in keys:
            continue
        owner = nodes[keys[index]]
        if group.rules_status == "missing":
            warnings.append(f"{group.name}: правила группы отсутствуют в сохранённом сборе.")
        for rule in group.rules:
            guard()
            path = rule.location.object_path or ""
            position_text = path.rsplit("/", 1)[-1]
            if not position_text.isdecimal():
                continue
            position = int(position_text)
            if index in reverse_rule_indices and position not in reverse_rule_indices[index]:
                continue
            peer = rule.peer
            target_indices: set[int] = set()
            if peer.kind == "security_group" and peer.reference_id is not None:
                group_id = canonical_cloud_reference(peer.reference_id, "security_groups")
                target_indices = by_id.get(("security_groups", group_id), set())
            target_index = next(iter(target_indices)) if len(target_indices) == 1 else None
            label = peer.cidr or peer.reference_id or "Удалённая сторона неизвестна"
            if peer.reference_state == "present" and target_index is not None and target_index in keys:
                target = keys[target_index]
                label = nodes[target].label
            else:
                target = "endpoint:" + identity(owner.scope, peer.kind, label, peer.reference_state)
                addresses = (peer.cidr,) if peer.cidr is not None else ()
                nodes.setdefault(target, ProjectMapNode(
                    target, label, "network", owner.area, "Условия группы безопасности",
                    addresses, ("Удалённая сторона условия группы безопасности.",), owner.scope,
                ))
            source, destination = (target, owner.key) if rule.direction == "ingress" else (owner.key, target)
            status = "unknown" if rule.limitations or rule.direction is None or rule.enabled is None else "known"
            kind = "condition" if rule.direction is None else "acl"
            enabled = rule.enabled is not False
            details = (
                f"Сбор: {scan['id']}",
                f"Приоритет: {rule.priority}" if rule.priority is not None else "Приоритет не указан.",
                "Состояние включения не указано." if rule.enabled is None
                else "Правило включено." if enabled else "Правило отключено.",
                *rule.limitations,
            )
            grouped[source, destination, kind, rule.action, enabled, status].append(RuleEvidence(
                owner.label, rule.rule_id or f"sg:{index}:{position}", f"Правило SG · {position + 1}",
                rule.action, enabled, _service(rule),
                label if rule.direction == "ingress" else owner.label,
                owner.label if rule.direction == "ingress" else label,
                status, f"{rule.location.source_name}:{_rule_path(records[index], position)}",
                owner.key, rule.direction or "unknown", details,
            ))
    for (source, destination, kind, action, enabled, status), rules in grouped.items():
        edges.append(ProjectMapEdge(
            source, destination, kind, action, enabled, status, tuple(rules),
            ("Направление объявлений неизвестно.",) if kind == "condition" else (),
        ))
