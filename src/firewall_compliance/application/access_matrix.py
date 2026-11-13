"""Pure matrix diagnostics and conservative comparison of declared ACL conditions."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping
from ipaddress import ip_network
from typing import TYPE_CHECKING

from firewall_compliance.domain.access_matrix import (
    AccessMatrix, MatrixAssessment, MatrixDiagnostic, MatrixGroup,
    MatrixRequirement, MatrixRequirementAssessment, MatrixState,
)
from firewall_compliance.domain.enums import DataStatus, EndpointKind, Protocol
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.network import Endpoint, Service
from firewall_compliance.domain.policy_matching import (
    RuleMatch, resolve_addresses, resolve_rule, resolve_services,
)
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.matrix_context_inputs import MatrixContextInputs

if TYPE_CHECKING:
    from firewall_compliance.application.access_matrix_v2 import MatrixSessionResolver, VrfCatalogBindings
    from firewall_compliance.application.matrix_policy import MatrixCoverageCache


def matrix_diagnostics(matrix: AccessMatrix) -> tuple[MatrixDiagnostic, ...]:
    """Keep invalid references visible without imposing a silent row priority."""
    if matrix.schema_version == "2.0.0":
        from firewall_compliance.application.access_matrix_v2 import structural_diagnostics

        return structural_diagnostics(matrix)
    issues = []
    groups = {group.group_id: group for group in matrix.groups}
    for identifier, count in Counter(group.group_id for group in matrix.groups).items():
        if count > 1:
            issues.append(MatrixDiagnostic(
                code="duplicate_group", message="Повторяется ID группы", group_ids=(identifier,)
            ))
    for identifier, count in Counter(row.requirement_id for row in matrix.requirements).items():
        if count > 1:
            issues.append(MatrixDiagnostic(
                code="duplicate_requirement", message="Повторяется ID требования",
                requirement_ids=(identifier,),
            ))
    for group in matrix.groups:
        for member in group.members:
            if member.kind == "group" and member.value not in groups:
                issues.append(MatrixDiagnostic(
                    code="missing_group", message="Ссылка на неизвестную группу",
                    group_ids=(group.group_id, member.value),
                ))
    visited: set[str] = set()

    def walk(identifier: str, stack: tuple[str, ...]) -> None:
        if identifier in stack:
            issues.append(MatrixDiagnostic(
                code="group_cycle", message="Циклическая ссылка групп",
                group_ids=stack[stack.index(identifier):] + (identifier,),
            ))
            return
        if identifier in visited or identifier not in groups:
            return
        for member in groups[identifier].members:
            if member.kind == "group":
                walk(member.value, (*stack, identifier))
        visited.add(identifier)

    for identifier in groups:
        walk(identifier, ())
    previous: dict[str, MatrixRequirement] = {}
    for row in matrix.requirements:
        missing = tuple(key for key in (row.source_group, row.destination_group) if key not in groups)
        if missing:
            issues.append(MatrixDiagnostic(
                code="missing_requirement_group", message="Группа требования отсутствует",
                group_ids=missing, requirement_ids=(row.requirement_id,),
            ))
        key = row.model_dump_json(exclude={"requirement_id", "requirement", "owner", "review_date", "reason"})
        baseline = previous.get(key)
        if baseline is not None and baseline.requirement != row.requirement:
            issues.append(MatrixDiagnostic(
                code="conflicting_requirement", message="Противоречивые требования к одним условиям",
                requirement_ids=(baseline.requirement_id, row.requirement_id),
            ))
        else:
            previous[key] = row
    return tuple(issues)


def _group_endpoints(
    group_id: str, groups: dict[str, MatrixGroup], revision: DeviceRevision,
) -> tuple[Endpoint, ...] | None:
    endpoints: dict[str, Endpoint] = {}
    objects = {endpoint.endpoint_id: endpoint for endpoint in revision.parse_result.endpoints}
    if len(objects) != len(revision.parse_result.endpoints):
        return None
    pending = [group_id]
    visited: set[str] = set()
    while pending:
        identifier = pending.pop()
        if identifier in visited:
            continue
        if identifier not in groups or not groups[identifier].members:
            return None
        visited.add(identifier)
        for member in groups[identifier].members:
            if member.kind == "network":
                network = str(ip_network(member.value, strict=False))
                endpoints["network:" + network] = Endpoint(
                    endpoint_id="matrix:" + network, name=network,
                    kind=EndpointKind.SUBNET, cidrs=(network,),
                )
            elif member.kind == "object":
                if member.value not in objects:
                    return None
                endpoints["object:" + member.value] = objects[member.value]
            else:
                pending.append(member.value)
    return tuple(endpoints.values()) if endpoints else None


def _requirement_match(
    row: MatrixRequirement, groups: dict[str, MatrixGroup], revision: DeviceRevision
) -> RuleMatch | None:
    sources = _group_endpoints(row.source_group, groups, revision)
    destinations = _group_endpoints(row.destination_group, groups, revision)
    if sources is None or destinations is None:
        return None
    source_set, destination_set = resolve_addresses(sources), resolve_addresses(destinations)
    services = resolve_services((Service(
        service_id="matrix-service", name="Требование матрицы",
        protocol=Protocol(row.service.protocol), port_ranges=row.service.ports,
    ),))
    if source_set is None or destination_set is None or services is None:
        return None
    shared_sources = tuple(
        source_set[index] if destination_set[index] else () for index in (0, 1)
    )
    shared_destinations = tuple(
        destination_set[index] if source_set[index] else () for index in (0, 1)
    )
    if not any(shared_sources):
        return None
    return RuleMatch(
        (shared_sources[0], shared_sources[1]),
        (shared_destinations[0], shared_destinations[1]), services,
    )


def _overlap(left: RuleMatch, right: RuleMatch) -> bool:
    def intersects(a: tuple[tuple[int, int], ...], b: tuple[tuple[int, int], ...]) -> bool:
        return any(max(x, u) <= min(y, v) for x, y in a for u, v in b)

    addresses = any(
        intersects(left.sources[index], right.sources[index])
        and intersects(left.destinations[index], right.destinations[index])
        for index in (0, 1)
    )
    services = any(
        (a == b or "ip" in (a, b)) and intersects(x, y)
        for a, x in left.services for b, y in right.services
    )
    return addresses and services


def evaluate_access_matrix(
    matrix: AccessMatrix, revision: DeviceRevision, *, scope_id: str,
    profile_id: str, profile_version: str,
    bindings: Mapping[tuple[str, str], tuple[str, ...]] | None = None,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[int, int], None] | None = None,
    context_inputs: MatrixContextInputs | None = None,
    project_id: str | None = None,
    coverage_cache: MatrixCoverageCache | None = None,
    session_resolver: MatrixSessionResolver | None = None,
    bindings_by_vrf: VrfCatalogBindings | None = None,
) -> MatrixAssessment:
    """Compare requirements against one revision in an explicit caller-owned context.

    Legacy results retain their declaration-only semantics. V2 can additionally
    evaluate the ordered rules of an explicitly bound local ACL.
    """
    if matrix.schema_version == "2.0.0":
        from firewall_compliance.application.access_matrix_v2 import evaluate_v2

        return evaluate_v2(
            matrix, revision, scope_id=scope_id,
            profile_id=profile_id, profile_version=profile_version,
            bindings=bindings or {}, cancelled=cancelled, progress=progress,
            context_inputs=context_inputs, project_id=project_id,
            coverage_cache=coverage_cache, session_resolver=session_resolver,
            bindings_by_vrf=bindings_by_vrf,
        )
    matrix = AccessMatrix.model_validate(matrix.model_dump(mode="python"))
    revision = DeviceRevision.model_validate(revision.model_dump(mode="python"))
    diagnostics = list(matrix_diagnostics(matrix))
    groups = {group.group_id: group for group in matrix.groups}
    object_ids = {endpoint.endpoint_id for endpoint in revision.parse_result.endpoints}
    for group in matrix.groups:
        if any(member.kind == "object" and member.value not in object_ids for member in group.members):
            diagnostics.append(MatrixDiagnostic(
                code="unresolved_object", message="Объект группы отсутствует в выбранной ревизии",
                group_ids=(group.group_id,),
            ))
    matches = {
        row.requirement_id: _requirement_match(row, groups, revision)
        for row in matrix.requirements
    }
    # Different group names can still designate overlapping address spaces.
    for index, left in enumerate(matrix.requirements):
        for right in matrix.requirements[index + 1:]:
            a, b = matches[left.requirement_id], matches[right.requirement_id]
            if (
                left.scope_id == right.scope_id and left.policy_id == right.policy_id
                and left.identity == right.identity and left.schedule == right.schedule
                and left.requirement != right.requirement
                and a is not None and b is not None and _overlap(a, b)
            ):
                diagnostics.append(MatrixDiagnostic(
                    code="overlapping_requirements", message="Противоречие в пересекающихся условиях",
                    requirement_ids=(left.requirement_id, right.requirement_id),
                ))
    rows = []
    for row in matrix.requirements:
        state: MatrixState = "insufficient_evidence"
        reasons = []
        evidence = []
        match = matches[row.requirement_id]
        structural = any(issue.code in {"duplicate_group", "group_cycle"} for issue in diagnostics)
        conflict = any(row.requirement_id in issue.requirement_ids for issue in diagnostics)
        if row.scope_id != scope_id:
            state = "not_applicable"
            reasons.append("Требование относится к другой явно заданной области")
        elif structural or conflict:
            state = "requirement_conflict"
            reasons.append("Сначала устраните диагностику матрицы")
        elif row.requirement == "unregulated":
            state = "unregulated"
        elif row.identity is not None or row.schedule is not None:
            reasons.append("Identity и расписание требуют отдельного поддержанного сопоставления")
        elif match is None or row.policy_id is None:
            reasons.append("Не разрешены группы/объекты или не задан контекст политики")
        else:
            positive = False
            opposite = False
            unknown = False
            for rule in revision.parse_result.rules:
                if rule.policy_id != row.policy_id or not rule.enabled:
                    continue
                condition = resolve_rule(rule)
                if condition is None or rule.action.value not in {"allow", "deny", "drop", "reject"}:
                    unknown = True
                    continue
                if not _overlap(condition, match):
                    continue
                allows = rule.action.value == "allow"
                opposing = allows != (row.requirement == "permit")
                context_known = (
                    rule.zone_status == DataStatus.KNOWN
                    and rule.source_zone is None and rule.destination_zone is None
                )
                opposite |= opposing and context_known
                unknown |= not context_known
                positive |= not opposing and context_known and condition.covers(match)
                evidence.append(Evidence(
                    summary="Заданное условие правила пересекает требование матрицы",
                    related_rule_ids=(rule.rule_id,), source_locations=(rule.source_location,),
                    facts={
                        "action": rule.action.value, "covers_requirement": condition.covers(match),
                        "scope_known": context_known, "source_zone": rule.source_zone,
                        "destination_zone": rule.destination_zone,
                    },
                    limitations=("Порядок применения и сквозной путь не оценены",),
                ))
            parsed = revision.parse_result
            incomplete = bool(
                parsed.errors or parsed.unsupported_constructs
                or parsed.coverage.recognized_constructs != parsed.coverage.discovered_constructs
            )
            if incomplete:
                reasons.append("Разбор ревизии неполон; свидетельства ограничены известными правилами")
            if unknown:
                reasons.append("Есть правила с неизвестными условиями или действиями")
            if opposite:
                state = "declared_conflict"
                reasons.append("Есть противоположное заданное условие; это не итоговое решение потока")
            elif positive and not unknown and not incomplete:
                state = "declared_match"
                reasons.append("Найдено полностью покрывающее заданное условие в выбранной политике")
            else:
                reasons.append("Нет полного однозначного свидетельства; отсутствие правила не доказывает запрет")
        rows.append(MatrixRequirementAssessment(
            requirement_id=row.requirement_id, state=state, evidence=tuple(evidence), reasons=tuple(reasons),
        ))
    return MatrixAssessment(
        matrix_id=matrix.matrix_id, matrix_version=matrix.version,
        revision_id=revision.revision_id, profile_id=profile_id, profile_version=profile_version,
        scope_id=scope_id, diagnostics=tuple(diagnostics), requirements=tuple(rows),
    )
