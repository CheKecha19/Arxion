"""Облачные источники общей сверки из последних сохранённых сборов."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from ipaddress import ip_interface
from itertools import chain
from typing import Any, Literal

from firewall_compliance.application.cloud_analysis import vmware_device_id, vmware_scope_revision
from firewall_compliance.application.cloud_security_groups import (
    CloudSGScanHeader, security_group_scan_header, security_group_snapshot,
)
from firewall_compliance.application.cloud_sg_revision import (
    CloudSGRevisionProjector, CloudSGSelection, cloud_sg_policy_id,
)
from firewall_compliance.application.matrix_scope_assessment import MatrixScopeInput
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixDiagnostic, MatrixRequirement
from firewall_compliance.domain.cloud_security_groups import CloudSecurityGroupSnapshot, SGDirection
from firewall_compliance.domain.matrix_vmware_origin import VMwareMatrixOrigin
from firewall_compliance.domain.revision import DeviceRevision

type _Family = Literal[4, 6]
type _Projection = tuple[SGDirection, _Family]
type _OrderDiagnostic = Callable[[str, str, str], None]
_DIRECTIONS: tuple[SGDirection, ...] = ("ingress", "egress")
_FAMILIES: tuple[_Family, ...] = (4, 6)
_TERMINAL_STATES = ("completed", "partial", "failed", "cancelled", "interrupted")


def matrix_scope_cloud_policy_ids(matrix: AccessMatrix, *, scope_id: str) -> frozenset[str]:
    return frozenset(
        row.policy_id for row in chain(matrix.requirements, matrix.boundaries)
        if row.scope_id == scope_id and row.policy_id is not None and row.policy_id.startswith("sg:")
    )


def matrix_scope_vmware_policy_ids(matrix: AccessMatrix, *, scope_id: str) -> frozenset[str]:
    """Идентификаторы, которые можно сверить с точным ID записи Edge Gateway."""
    return frozenset(
        row.policy_id for row in chain(matrix.requirements, matrix.boundaries)
        if row.scope_id == scope_id and row.policy_id is not None and not row.policy_id.startswith("sg:")
    )


def _vmware_scan_config(scan: Mapping[str, Any]) -> dict[str, Any] | None:
    config = scan.get("config")
    selection = scan.get("selection")
    if not isinstance(config, dict) or config.get("platform", "vmware") != "vmware":
        return None
    if not all(isinstance(value, str) and value for value in (config.get("site"), config.get("tenant"))):
        return None
    if not isinstance(selection, Mapping):
        return None
    resources, data = selection.get("resources"), selection.get("data")
    if not isinstance(resources, (list, tuple)) or "edges" not in resources:
        return None
    if not isinstance(data, (list, tuple)) or "firewall" not in data:
        return None
    return config


def latest_matrix_vmware_scan_ids(
    headers: Iterable[Mapping[str, Any]], *, project_id: str, selected_site_id: str | None = None,
) -> tuple[str, ...]:
    """Выбрать последнюю попытку сбора Firewall для каждого VMware tenant и адреса."""
    return tuple(
        latest_id for latest_id, _ in matrix_vmware_scan_pairs(
            headers, project_id=project_id, selected_site_id=selected_site_id,
        )
    )


def matrix_vmware_scan_pairs(
    headers: Iterable[Mapping[str, Any]], *, project_id: str, selected_site_id: str | None = None,
) -> tuple[tuple[str, str | None], ...]:
    """Найти последнюю попытку и ближайший предшествующий сбор с данными в том же контексте."""
    if selected_site_id == "":
        return ()
    latest: dict[tuple[str, str], tuple[datetime, str]] = {}
    available: dict[tuple[tuple[str, str], str], list[tuple[datetime, str]]] = defaultdict(list)
    for scan in headers:
        state = scan.get("state")
        if scan.get("project_id") != project_id or state not in _TERMINAL_STATES:
            continue
        config = _vmware_scan_config(scan)
        scan_id, created = scan.get("id"), scan.get("created_at")
        if config is None or not isinstance(scan_id, str) or not scan_id or not isinstance(created, str):
            continue
        sites = scan["selection"].get("workspace_site_ids")
        if selected_site_id is not None and (not isinstance(sites, (list, tuple)) or selected_site_id not in sites):
            continue
        try:
            started_at = datetime.fromisoformat(created)
        except ValueError:
            continue
        if started_at.utcoffset() is None:
            continue
        context = config["site"], config["tenant"]
        candidate = started_at, scan_id
        previous = latest.get(context)
        if previous is None or candidate > previous:
            latest[context] = candidate
        if state in ("completed", "partial"):
            prior = available[context, state]
            if not prior or candidate > prior[0]:
                prior.insert(0, candidate)
                del prior[2:]
            elif len(prior) == 1 or candidate > prior[1]:
                prior[1:] = [candidate]
    pairs = []
    for context in sorted(latest):
        current = latest[context]
        earlier = next((
            row for state in ("completed", "partial") for row in available.get((context, state), ()) if row < current
        ), None)
        pairs.append((current[1], earlier[1] if earlier is not None else None))
    return tuple(pairs)


def matrix_scope_vmware_replacing_scan_id(
    revision: DeviceRevision, scans: Iterable[Mapping[str, Any]], *, vmware_policy_ids: frozenset[str],
) -> str | None:
    """Проверить, покрывает ли выбранная прямая попытка тот же источник старого результата."""
    rules = revision.parse_result.rules
    if revision.device.platform != "cloud-ru-vmware-nsxt" or not rules:
        return None
    policy_id = rules[0].policy_id
    if policy_id is None or policy_id not in vmware_policy_ids:
        return None
    return next((
        scan_id for scan in scans
        if isinstance(scan_id := scan.get("id"), str) and (config := _vmware_scan_config(scan)) is not None
        and vmware_device_id(config, policy_id) == revision.device.device_id
    ), None)


def _vmware_records(scan: Mapping[str, Any]) -> Iterable[tuple[int, object]]:
    projection = scan.get("matrix_vmware_records")
    if projection is not None:
        return projection
    result = scan.get("result")
    records = result.get("records") if isinstance(result, Mapping) else None
    return enumerate(records) if isinstance(records, (list, tuple)) else ()


def matrix_scope_vmware_inputs(
    matrix: AccessMatrix, scans: Iterable[dict[str, Any]], *, project_id: str, scope_id: str,
    selected_site_id: str | None = None, diagnostics: list[MatrixDiagnostic] | None = None,
    expected_policies_by_scan: Mapping[str, Iterable[str]] | None = None,
    unavailable_policy_ids: set[str] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> tuple[MatrixScopeInput, ...]:
    """Восстановить только явно запрошенные политики из записей выбранных попыток."""
    policies = matrix_scope_vmware_policy_ids(matrix, scope_id=scope_id)
    if not policies or selected_site_id == "":
        return ()
    rows = tuple(scans)
    selected = latest_matrix_vmware_scan_ids(rows, project_id=project_id, selected_site_id=selected_site_id)
    if not selected:
        return ()
    by_id = {
        identifier: scan for scan in rows
        if scan.get("project_id") == project_id and isinstance(identifier := scan.get("id"), str)
    }
    requirements_by_policy: dict[str, list[str]] = defaultdict(list)
    if diagnostics is not None:
        for row in chain(matrix.requirements, matrix.boundaries):
            if cancelled is not None and cancelled():
                return ()
            if row.scope_id == scope_id and row.policy_id is not None and row.policy_id in policies:
                identifier = row.requirement_id if isinstance(row, MatrixRequirement) else row.boundary_id
                requirements_by_policy[row.policy_id].append(identifier)

    def note(policy: str, code: str, message: str) -> None:
        if unavailable_policy_ids is not None:
            unavailable_policy_ids.add(policy)
        if diagnostics is not None:
            diagnostics.append(MatrixDiagnostic(
                code=code, message=message, requirement_ids=tuple(requirements_by_policy[policy]),
            ))

    inputs: list[MatrixScopeInput] = []
    for scan_id in selected:
        if cancelled is not None and cancelled():
            break
        scan = by_id[scan_id]
        matches: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
        for index, record in _vmware_records(scan):
            if cancelled is not None and cancelled():
                return tuple(inputs)
            if not isinstance(record, dict) or record.get("type") != "edges":
                continue
            resource_id = record.get("id")
            if isinstance(resource_id, str) and resource_id in policies:
                matches[resource_id].append((index, record))
        expected = expected_policies_by_scan.get(scan_id, ()) if expected_policies_by_scan is not None else ()
        previous = scan.get("matrix_vmware_previous_policy_ids", ())
        for resource_id in sorted(policies.intersection(chain(expected, previous)).difference(matches)):
            if cancelled is not None and cancelled():
                return tuple(inputs)
            note(resource_id, "cloud_vmware_policy_unavailable",
                 f"Сбор VMware {scan_id} не дал актуальной записи политики этого Edge Gateway.")
        for resource_id, records in matches.items():
            if cancelled is not None and cancelled():
                return tuple(inputs)
            if len(records) != 1:
                note(resource_id, "cloud_vmware_policy_duplicate",
                     f"В сборе VMware {scan_id} есть несколько записей Edge Gateway с этим идентификатором.")
                continue
            index, record = records[0]
            origin = VMwareMatrixOrigin(scan_id=scan_id, record_index=index, resource_id=resource_id)
            try:
                revision = vmware_scope_revision(
                    scan, origin, project_id=project_id, site_id=selected_site_id, record=record,
                )
            except ValueError:
                note(resource_id, "cloud_vmware_policy_unavailable",
                     f"В сборе VMware {scan_id} нет пригодной для сверки политики этого Edge Gateway.")
                continue
            inputs.append(MatrixScopeInput(run_id=None, item_id=None, revision=revision, vmware_origin=origin))
    return tuple(inputs)


def latest_matrix_cloud_scan_ids(
    headers: Iterable[Mapping[str, Any]], *, project_id: str, selected_site_id: str | None = None,
) -> tuple[str, ...]:
    """Выбрать последнюю завершившуюся попытку сбора для каждого облачного контекста."""
    if selected_site_id == "":
        return ()
    latest: dict[str, CloudSGScanHeader] = {}
    for scan in headers:
        if scan.get("project_id") != project_id or scan.get("state") not in _TERMINAL_STATES:
            continue
        try:
            header = security_group_scan_header(scan)
        except ValueError:
            continue
        previous = latest.get(header.scope_id)
        if previous is None or (header.started_at, header.scan_id) > (previous.started_at, previous.scan_id):
            latest[header.scope_id] = header
    return tuple(
        header.scan_id for header in sorted(latest.values(), key=lambda value: value.scope_id)
        if selected_site_id is None or selected_site_id in header.workspace_site_ids
    )


def _requested_projections(
    snapshot: CloudSecurityGroupSnapshot, group_key: str, policies: frozenset[str],
) -> tuple[_Projection, ...]:
    return tuple(
        (direction, family) for direction in _DIRECTIONS for family in _FAMILIES
        if (family == 4 or snapshot.platform == "advanced")
        and cloud_sg_policy_id(snapshot.scope_id, group_key, direction, family) in policies
    )


def _snapshot_selections(
    snapshot: CloudSecurityGroupSnapshot, policies: frozenset[str], cancelled: Callable[[], bool] | None,
) -> Iterable[CloudSGSelection]:
    group_projections: dict[str, tuple[_Projection, ...]] = {}
    for group in snapshot.groups:
        if cancelled is not None and cancelled():
            return
        if group.scope_id == snapshot.scope_id:
            group_projections[group.group_id] = _requested_projections(snapshot, group.group_id, policies)
    for interface in snapshot.interfaces:
        if cancelled is not None and cancelled():
            return
        if (interface.scope_id != snapshot.scope_id or interface.assignments_status != "present"
                or interface.security_enabled is False or not interface.addresses):
            continue
        groups: dict[str | None, tuple[_Projection, ...]] = {
            assignment.group_id: group_projections[assignment.group_id]
            for assignment in interface.assignments
            if assignment.state == "present" and group_projections.get(assignment.group_id)
        }
        if (snapshot.platform == "evolution" and interface.assignments
                and all(assignment.state == "present" and assignment.group_id in group_projections
                        for assignment in interface.assignments)):
            groups[None] = _requested_projections(snapshot, "interface/" + interface.interface_id, policies)
        families = {ip_interface(address).version for address in interface.addresses}
        for group_id, projections in groups.items():
            for direction, family in projections:
                if family in families:
                    yield CloudSGSelection(
                        scan_id=snapshot.scan_id, group_id=group_id, interface_id=interface.interface_id,
                        scope_id=snapshot.scope_id, direction=direction, family=family,
                    )


def _advanced_order_sources(
    snapshot: CloudSecurityGroupSnapshot, projector: CloudSGRevisionProjector, policies: frozenset[str],
    recorded_orders: Iterable[CloudSGSelection], add_diagnostic: _OrderDiagnostic,
    cancelled: Callable[[], bool] | None,
) -> Iterable[MatrixScopeInput]:
    by_interface: dict[tuple[str, _Family], dict[tuple[str, ...], CloudSGSelection]] = defaultdict(dict)
    for selection in recorded_orders:
        order = selection.order_evidence
        if (
            order is not None and selection.scan_id == snapshot.scan_id and selection.scope_id == snapshot.scope_id
            and selection.direction == "ingress" and selection.group_id is None
            and order.snapshot_sha256 == snapshot.source_sha256 and order.observed_at == snapshot.captured_at
        ):
            by_interface[(selection.interface_id, selection.family)].setdefault(order.group_ids, selection)
    for interface in snapshot.interfaces:
        if cancelled is not None and cancelled():
            return
        if interface.scope_id != snapshot.scope_id or len(interface.assignments) < 2:
            continue
        families = {ip_interface(address).version for address in interface.addresses}
        for family in _FAMILIES:
            policy = cloud_sg_policy_id(snapshot.scope_id, "interface/" + interface.interface_id, "ingress", family)
            if family not in families or policy not in policies:
                continue
            compatible = by_interface.get((interface.interface_id, family), {})
            if not compatible:
                add_diagnostic(
                    policy, "cloud_group_order_missing",
                    "В истории нет наблюдённого порядка назначенных групп Advanced для последнего облачного сбора.",
                )
                continue
            candidate = None
            for selection in compatible.values():
                if cancelled is not None and cancelled():
                    return
                try:
                    revision = projector.project(selection, imported_at=snapshot.captured_at)
                except ValueError:
                    continue
                if candidate is not None:
                    add_diagnostic(
                        policy, "cloud_group_order_conflict",
                        "Для одного интерфейса в последнем сборе сохранены разные подтверждённые порядки групп Advanced.",
                    )
                    break
                candidate = MatrixScopeInput(
                    run_id=None, item_id=None, revision=revision, cloud_selection=selection,
                )
            else:
                if candidate is not None:
                    yield candidate
                else:
                    add_diagnostic(
                        policy, "cloud_group_order_unavailable",
                        "Сохранённый порядок групп Advanced нельзя применить к назначениям и правилам этого сбора.",
                    )


def matrix_scope_cloud_inputs(
    matrix: AccessMatrix, scans: Iterable[Mapping[str, Any]], *,
    project_id: str, scope_id: str, selected_site_id: str | None = None,
    recorded_orders: Iterable[CloudSGSelection] = (), diagnostics: list[MatrixDiagnostic] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> tuple[MatrixScopeInput, ...]:
    """Нормализовать только явно требуемые политики из выбранных сборов."""
    policies = matrix_scope_cloud_policy_ids(matrix, scope_id=scope_id)
    if not policies or selected_site_id == "":
        return ()
    rows = tuple(scans)
    selected = latest_matrix_cloud_scan_ids(rows, project_id=project_id, selected_site_id=selected_site_id)
    by_id = {
        identifier.strip(): scan for scan in rows
        if scan.get("project_id") == project_id and isinstance(identifier := scan.get("id"), str)
    }
    orders_by_scan: dict[str, list[CloudSGSelection]] = defaultdict(list)
    for order in recorded_orders:
        orders_by_scan[order.scan_id].append(order)
    requirements_by_policy: dict[str, list[str]] = defaultdict(list)
    if diagnostics is not None:
        for row in chain(matrix.requirements, matrix.boundaries):
            if row.scope_id == scope_id and row.policy_id is not None and row.policy_id in policies:
                identifier = row.requirement_id if isinstance(row, MatrixRequirement) else row.boundary_id
                requirements_by_policy[row.policy_id].append(identifier)

    def add_diagnostic(policy: str, code: str, message: str) -> None:
        if diagnostics is not None:
            diagnostics.append(MatrixDiagnostic(
                code=code, message=message, requirement_ids=tuple(requirements_by_policy[policy]),
            ))

    inputs: list[MatrixScopeInput] = []
    for scan_id in selected:
        if cancelled is not None and cancelled():
            break
        snapshot = security_group_snapshot(by_id[scan_id])
        projector = CloudSGRevisionProjector(snapshot)
        for selection in _snapshot_selections(snapshot, policies, cancelled):
            if cancelled is not None and cancelled():
                return tuple(inputs)
            revision = projector.project(selection, imported_at=snapshot.captured_at)
            inputs.append(MatrixScopeInput(run_id=None, item_id=None, revision=revision, cloud_selection=selection))
        if snapshot.platform == "advanced":
            inputs.extend(_advanced_order_sources(
                snapshot, projector, policies, orders_by_scan.get(scan_id, ()), add_diagnostic, cancelled,
            ))
    return tuple(inputs)
