"""Сверка необходимых взаимодействий и закрытых областей матрицы v2."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Mapping
from ipaddress import IPv4Address, IPv6Address, ip_network, summarize_address_range
from typing import Literal

from firewall_compliance.analysis.policy_coverage import CoverageLimitError, UnsupportedCoverageError, packet_boxes
from firewall_compliance.application.access_context import AccessContextIndex
from firewall_compliance.application.matrix_attachment_scope import AttachmentScopeAssessment, MatrixAttachmentScope
from firewall_compliance.application.matrix_catalog_bindings import CatalogBindings as CatalogBindings
from firewall_compliance.application.matrix_packet_index import PacketCandidateIndex
from firewall_compliance.application.matrix_policy import (
    Boxes, GroupAddressKey, MatrixBudget, MatrixCancelled, MatrixCoverageCache, MatrixPolicy, PolicyCoverage,
    matrix_catalog_switch_policy_contexts, matrix_policy_contexts, matrix_policy_supports_zones,
    matrix_transit_binding,
)
from firewall_compliance.domain.access_matrix import (
    AccessMatrix, MatrixAssessment, MatrixBoundary, MatrixDiagnostic, MatrixGroup,
    MatrixRequirement, MatrixRequirementAssessment, MatrixState, MatrixZonePair,
)
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.access_context import AccessContextResolution
from firewall_compliance.domain.enums import Protocol
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.matrix_context_inputs import MatrixContextInputs, MatrixContextSource
from firewall_compliance.domain.network import Service
from firewall_compliance.domain.policy_matching import (
    AddressSet, Interval, RuleMatch, merge_intervals, resolve_addresses, resolve_services,
)
from firewall_compliance.domain.revision import DeviceRevision

type VrfCatalogBindings = Mapping[str, CatalogBindings]
type MatrixRow = MatrixRequirement | MatrixBoundary
type Context = tuple[str, str | None, MatrixZonePair | None]
_ALLOWED = {"permit", "allow_optional"}


def _identifier(row: MatrixRow) -> str:
    return row.requirement_id if isinstance(row, MatrixRequirement) else row.boundary_id


def _address_only(row: MatrixRequirement) -> bool:
    return row.access_context is None and row.identity is None and row.schedule is None


def _context(row: MatrixRow) -> Context:
    return row.scope_id, row.policy_id, row.zone_pair


def structural_diagnostics(
    matrix: AccessMatrix, guard: Callable[[], None] | None = None,
) -> tuple[MatrixDiagnostic, ...]:
    """Проверить идентичность и ссылки черновика без раскрытия всех пакетов."""
    groups = {group.group_id: group for group in matrix.groups}
    requirements = {row.requirement_id: row for row in matrix.requirements}
    rows: tuple[MatrixRow, ...] = (*matrix.requirements, *matrix.boundaries)
    issues = [
        MatrixDiagnostic(code="duplicate_group", message="Повторяется ID группы", group_ids=(key,))
        for key, count in Counter(group.group_id for group in matrix.groups).items() if count > 1
    ]
    issues.extend(
        MatrixDiagnostic(
            code="duplicate_requirement", message="Повторяется ID требования или области",
            requirement_ids=(key,),
        )
        for key, count in Counter(map(_identifier, rows)).items() if count > 1
    )
    dependencies = {
        key: tuple(member.value for member in group.members if member.kind == "group")
        for key, group in groups.items()
    }
    for key, children in dependencies.items():
        for child in children:
            if guard:
                guard()
            if child not in groups:
                issues.append(MatrixDiagnostic(
                    code="missing_group", message="Ссылка на неизвестную группу", group_ids=(key, child),
                ))
    finished: set[str] = set()
    for key in groups:
        if key in finished:
            continue
        active = {key}
        stack = [(key, iter(dependencies[key]))]
        while stack:
            if guard:
                guard()
            parent, children = stack[-1]
            child = next(children, None)
            if child is None:
                stack.pop()
                active.remove(parent)
                finished.add(parent)
            elif child in active:
                issues.append(MatrixDiagnostic(
                    code="group_cycle", message="Циклическая ссылка групп", group_ids=(parent, child),
                ))
            elif child in groups and child not in finished:
                active.add(child)
                stack.append((child, iter(dependencies[child])))
    exact: dict[str, dict[bool, list[str]]] = {}
    for row in rows:
        if guard:
            guard()
        missing = tuple(
            key for key in (row.source_group, row.destination_group) if key not in groups
        )
        if missing:
            issues.append(MatrixDiagnostic(
                code="missing_requirement_group", message="Группа требования отсутствует",
                group_ids=missing, requirement_ids=(_identifier(row),),
            ))
        if isinstance(row, MatrixBoundary):
            for key in dict.fromkeys(row.allowed_requirement_ids):
                if guard:
                    guard()
                allowed = requirements.get(key)
                if not valid_boundary_reference(row, allowed):
                    issues.append(MatrixDiagnostic(
                        code="invalid_boundary_reference",
                        message="Область ссылается на отсутствующее разрешение или другую область, политику либо пару зон",
                        requirement_ids=(row.boundary_id, key),
                    ))
        elif row.requirement in _ALLOWED | {"deny"}:
            signature = row.model_dump_json(exclude={
                "requirement_id", "requirement", "owner", "review_date", "reason",
            })
            alternatives = exact.setdefault(signature, {})
            permits = row.requirement in _ALLOWED
            alternatives.setdefault(permits, []).append(row.requirement_id)
    for alternatives in exact.values():
        if guard:
            guard()
        if len(alternatives) == 2:
            issues.append(MatrixDiagnostic(
                code="conflicting_requirement",
                message="Разрешение и запрет заданы для одинаковых условий",
                requirement_ids=tuple((*alternatives[True], *alternatives[False])),
            ))
    return tuple(issues)


def valid_boundary_reference(
    boundary: MatrixBoundary, row: MatrixRequirement | None,
) -> bool:
    return (
        row is not None and row.requirement in _ALLOWED and row.scope_id == boundary.scope_id
        and (row.policy_id is None or row.policy_id == boundary.policy_id)
        and row.zone_pair == boundary.zone_pair
    )


class MatrixGroupResolver:
    """Раскрывает каждую группу один раз, сохраняя неизвестные ссылки и циклы."""

    def __init__(
        self, matrix: AccessMatrix, revision: DeviceRevision, bindings: CatalogBindings,
        guard: Callable[[], None], *, shared: MatrixGroupResolver | None = None,
        cache: MatrixCoverageCache | None = None,
    ) -> None:
        if shared is None:
            self._groups = {group.group_id: group for group in matrix.groups}
            counts = Counter(group.group_id for group in matrix.groups)
            self._duplicates = {key for key, count in counts.items() if count > 1}
            endpoints = revision.parse_result.endpoints
            object_counts = Counter(item.endpoint_id for item in endpoints)
            self._objects = {
                item.endpoint_id: item for item in endpoints if object_counts[item.endpoint_id] == 1
            }
        else:
            self._groups, self._duplicates, self._objects = shared._groups, shared._duplicates, shared._objects
        self._resolved: dict[str, AddressSet | None] = {}
        self._bindings = bindings
        self._guard = guard
        self._cache = cache

    def resolve(self, identifier: str) -> AddressSet | None:
        stack = [(identifier, False)]
        active: set[str] = set()
        while stack:
            self._guard()
            key, finish = stack.pop()
            if finish:
                active.discard(key)
                if key not in self._resolved:
                    self._resolved[key] = self._resolve_addresses(self._groups[key])
                continue
            if key in self._resolved:
                continue
            group = self._groups.get(key)
            if group is None or key in active or key in self._duplicates:
                self._resolved[key] = None
                continue
            active.add(key)
            stack.append((key, True))
            stack.extend(
                (member.value, False) for member in reversed(group.members)
                if member.kind == "group"
            )
        return self._resolved[identifier]

    def _resolve_addresses(self, group: MatrixGroup) -> AddressSet | None:
        if self._cache is None:
            return self._addresses(group)
        members: list[tuple[str, str, AddressSet | tuple[str, ...] | None]] = []
        weight = 1
        for member in group.members:
            self._guard()
            value: AddressSet | tuple[str, ...] | None = None
            if member.kind == "group":
                value = self._resolved[member.value]
                if value is None:
                    return None
                weight += sum(map(len, value))
            elif member.kind in {"resource", "logical_network"}:
                value = self._bindings.get((member.kind, member.value))
                if not value:
                    return None
                weight += len(value)
            members.append((member.kind, member.value, value))
        key: GroupAddressKey = tuple(members)
        return self._cache.group_addresses(key, weight + len(key), lambda: self._addresses(group))

    def _addresses(self, group: MatrixGroup) -> AddressSet | None:
        v4: list[Interval] = []
        v6: list[Interval] = []
        for member in group.members:
            self._guard()
            if member.kind == "group":
                addresses = self._resolved.get(member.value)
            elif member.kind == "object":
                endpoint = self._objects.get(member.value)
                addresses = resolve_addresses((endpoint,)) if endpoint else None
            else:
                prefixes = (
                    (member.value,) if member.kind == "network"
                    else self._bindings.get((member.kind, member.value), ())
                )
                if not prefixes:
                    return None
                try:
                    for prefix in prefixes:
                        self._guard()
                        net = ip_network(prefix, strict=False)
                        (v4 if net.version == 4 else v6).append(
                            (int(net.network_address), int(net.broadcast_address))
                        )
                except ValueError:
                    return None
                continue
            if addresses is None:
                return None
            v4.extend(addresses[0])
            v6.extend(addresses[1])
        return (merge_intervals(v4), merge_intervals(v6)) if v4 or v6 else None


def catalog_bindings_for_policy(
    bindings: CatalogBindings, bindings_by_vrf: VrfCatalogBindings,
    policy_contexts: Mapping[str, str], policy_id: str | None,
) -> CatalogBindings:
    """Дополнить общий каталог только привязками подтверждённого VRF политики."""
    context = policy_contexts.get(policy_id) if policy_id is not None else None
    scoped = bindings_by_vrf.get(context) if context is not None else None
    if not scoped:
        return bindings
    return {**bindings, **scoped} if bindings else scoped


class MatrixPolicyGroupResolver:
    """Кэш раскрытия групп с раздельным составом в разных VRF."""

    def __init__(
        self, matrix: AccessMatrix, revision: DeviceRevision, bindings: CatalogBindings,
        bindings_by_vrf: VrfCatalogBindings | None, guard: Callable[[], None], *,
        cache: MatrixCoverageCache | None = None,
    ) -> None:
        self._matrix, self._revision, self._guard = matrix, revision, guard
        self._bindings = bindings
        self._bindings_by_vrf = bindings_by_vrf or {}
        self._contexts = matrix_catalog_switch_policy_contexts(revision) if self._bindings_by_vrf else {}
        self._cache = cache
        self._base = MatrixGroupResolver(matrix, revision, bindings, guard, cache=cache)
        self._scoped: dict[str, MatrixGroupResolver] = {}

    def vrf_for_policy(self, policy_id: str | None) -> str | None:
        context = self._contexts.get(policy_id) if policy_id is not None else None
        return context if context is not None and self._bindings_by_vrf.get(context) else None

    def for_policy(self, policy_id: str | None) -> MatrixGroupResolver:
        context = self.vrf_for_policy(policy_id)
        if context is None:
            return self._base
        if context not in self._scoped:
            bindings = catalog_bindings_for_policy(self._bindings, self._bindings_by_vrf, self._contexts, policy_id)
            self._scoped[context] = MatrixGroupResolver(
                self._matrix, self._revision, bindings, self._guard, shared=self._base, cache=self._cache,
            )
        return self._scoped[context]


class MatrixSessionResolver:
    """Индексы снимков сеансов по сетевому контексту."""

    def __init__(self, inputs: MatrixContextInputs) -> None:
        self.inputs = inputs
        self._sources = {source.snapshot.context_id: source for source in inputs.contexts}
        self._selections = {item.requirement_id: item for item in inputs.sessions}
        self._indexes: dict[str, AccessContextIndex] = {}

    def source_for(self, requirement_id: str, context_id: str | None) -> MatrixContextSource:
        if (selection := self._selections.get(requirement_id)) is not None:
            return self._sources[self.inputs.context_for_selection(selection)]
        if context_id is not None and context_id in self._sources:
            return self._sources[context_id]
        return self._sources[self.inputs.snapshot.context_id]

    def session_for(self, requirement_id: str) -> str | None:
        selection = self._selections.get(requirement_id)
        return selection.session_id if selection is not None else None

    def index_for(self, requirement_id: str, context_id: str | None) -> AccessContextIndex:
        return self._index_for_source(self.source_for(requirement_id, context_id))

    def _index_for_source(self, source: MatrixContextSource) -> AccessContextIndex:
        context_id = source.snapshot.context_id
        index = self._indexes.get(context_id)
        if index is None:
            index = AccessContextIndex(source.snapshot)
            self._indexes[context_id] = index
        return index

    def resolve(
        self, row: MatrixRequirement, groups: MatrixGroupResolver, *, project_id: str,
        scope_id: str, context_id: str | None, guard: Callable[[], None],
    ) -> AccessContextResolution:
        if row.access_context is None:
            raise ValueError("Требование не содержит пользовательского контекста")
        addresses = groups.resolve(row.source_group)
        prefixes = []
        if addresses is not None:
            for family, intervals in zip((IPv4Address, IPv6Address), addresses, strict=True):
                for start, end in intervals:
                    guard()
                    prefixes.extend(str(net) for net in summarize_address_range(family(start), family(end)))
        source = self.source_for(row.requirement_id, context_id)
        guard()
        return self._index_for_source(source).resolve(
            row.access_context, session_id=self.session_for(row.requirement_id),
            project_id=project_id, scope_id=scope_id, context_id=context_id,
            at=source.evaluated_at, source_prefixes=prefixes,
        )


def _row_boxes(
    row: MatrixRow, groups: MatrixGroupResolver, budget: MatrixBudget, *, session_address: str | None = None,
    family: Literal[4, 6] | None = None,
    cache: MatrixCoverageCache | None = None,
) -> Boxes | None:
    if isinstance(row, MatrixRequirement) and (row.identity is not None or row.schedule is not None):
        return None
    if isinstance(row, MatrixRequirement) and row.access_context is not None:
        if session_address is None:
            return None
        network = ip_network(session_address, strict=True)
        host = ((int(network.network_address), int(network.broadcast_address)),)
        source = (host, ()) if network.version == 4 else ((), host)
    else:
        source = groups.resolve(row.source_group)
    destination = groups.resolve(row.destination_group)
    if source is None or destination is None:
        return None
    if family == 4:
        source, destination = (source[0], ()), (destination[0], ())
    elif family == 6:
        source, destination = ((), source[1]), ((), destination[1])
    services = resolve_services((Service(
        service_id="matrix-service", name="Условие матрицы",
        protocol=Protocol(row.service.protocol), port_ranges=row.service.ports,
    ),))
    if services is None:
        return None
    match = RuleMatch(source, destination, services)
    if cache is not None:
        return cache.row_boxes(match, budget) or None
    return packet_boxes(match, "global", budget) or None


def _projected_family(revision: DeviceRevision, policy_id: str | None) -> Literal[4, 6] | None:
    if (
        revision.device.platform not in {"cloud-ru-advanced-sg", "cloud-ru-evolution-sg"}
        or policy_id is None or not policy_id.startswith("sg:")
    ):
        return None
    if policy_id.endswith(":ipv4"):
        return 4
    if policy_id.endswith(":ipv6"):
        return 6
    return None


def _result_state(row: MatrixRow, coverage: PolicyCoverage, local: bool) -> tuple[MatrixState, str]:
    if isinstance(row, MatrixBoundary):
        if coverage.any_allowed:
            return "excess_allow", "Разрешающее условие выходит за перечисленные взаимодействия"
        if coverage.all_denied and not coverage.unknown:
            return "declared_match", "Запрещённый остаток покрыт найденными условиями запрета"
        return "insufficient_evidence", "Нет достаточных сведений для оценки запрещённого остатка"
    permitting = row.requirement == "permit"
    wanted = coverage.any_allowed if permitting else coverage.any_denied
    opposite = coverage.any_denied if permitting else coverage.any_allowed
    full = coverage.all_allowed if permitting else coverage.all_denied
    if opposite:
        if wanted and local:
            return "partial_match", "Часть условия соответствует требованию, часть ему противоположна"
        return "declared_conflict", "Найдено противоположное условие в выбранной политике"
    if full and not coverage.unknown:
        return "declared_match", "Условия выбранной политики покрывают требование"
    if wanted:
        return "partial_match", "Подтверждена только часть оценки; полное покрытие не доказано"
    return "insufficient_evidence", "Нет достаточных сведений для вывода о покрытии требования"


class _Evaluation:
    def __init__(
        self, matrix: AccessMatrix, revision: DeviceRevision, scope: str,
        bindings: CatalogBindings, bindings_by_vrf: VrfCatalogBindings | None,
        cancelled: Callable[[], bool] | None,
        context_inputs: MatrixContextInputs | None, project_id: str | None,
        coverage_cache: MatrixCoverageCache | None, session_resolver: MatrixSessionResolver | None,
    ) -> None:
        self.matrix = matrix
        self.revision = revision
        self.coverage_cache = (
            coverage_cache if coverage_cache is not None and coverage_cache.revision is revision
            else MatrixCoverageCache(revision)
        )
        self.scope = scope
        self.cancelled = cancelled
        self.context_inputs = context_inputs
        self.project_id = project_id
        self.session_resolver = session_resolver
        self.policy_contexts: dict[str, str | None] = {}
        self.context_rows: dict[str, AccessContextResolution] = {}
        self.bindings = bindings
        self.bindings_by_vrf = bindings_by_vrf
        self.groups: MatrixPolicyGroupResolver
        self.rows: tuple[MatrixRow, ...] = (*matrix.requirements, *matrix.boundaries)
        self.diagnostics: list[MatrixDiagnostic] = []
        self.conflicts: set[str] = set()
        self.structural_conflicts: set[str] = set()
        self.rules: dict[str, list[Rule]] = defaultdict(list)
        self.policies: dict[str, MatrixPolicy] = {}
        self.attachment_scopes: dict[str, MatrixAttachmentScope | None] = {}
        self.requirements: dict[str, MatrixRequirement] = {}
        self.matches: dict[str, Boxes | None] = {}
        self.scoped_matches: dict[tuple[str, str], Boxes | None] = {}
        self.unbound_denials: dict[tuple[str, MatrixZonePair | None], list[MatrixRequirement]] = defaultdict(list)
        self.scoped_denials: dict[tuple[str, str, MatrixZonePair | None], PacketCandidateIndex] = {}
        self.forbidden: dict[str, Boxes | None] = {}
        self.unresolved: dict[str, str] = {}
        self.results: list[MatrixRequirementAssessment] = []

    def guard(self) -> None:
        if self.cancelled is not None and self.cancelled():
            raise MatrixCancelled

    def conflict(self, left: str, right: str, code: str, message: str) -> None:
        self.conflicts.update((left, right))
        self.diagnostics.append(MatrixDiagnostic(
            code=code, message=message, requirement_ids=(left, right),
        ))

    def prepare(self) -> None:
        if self.context_inputs is not None and self.project_id is not None:
            self.guard()
            if self.session_resolver is None:
                self.session_resolver = MatrixSessionResolver(self.context_inputs)
            elif self.session_resolver.inputs is not self.context_inputs:
                raise ValueError("Индекс относится к другому набору снимков сеансов")
            self.policy_contexts = matrix_policy_contexts(self.revision)
        self.diagnostics.extend(structural_diagnostics(self.matrix, self.guard))
        duplicate_ids: set[str] = set()
        for diagnostic in self.diagnostics:
            self.guard()
            keys = diagnostic.requirement_ids
            if diagnostic.code == "duplicate_requirement":
                duplicate_ids.update(keys)
            self.structural_conflicts.update(keys[:1] if diagnostic.code == "invalid_boundary_reference" else keys)
        self.conflicts.update(self.structural_conflicts)
        self.groups = MatrixPolicyGroupResolver(
            self.matrix, self.revision, self.bindings, self.bindings_by_vrf, self.guard,
            cache=self.coverage_cache,
        )
        for row in self.matrix.requirements:
            self.guard()
            self.requirements[row.requirement_id] = row
            if self.bindings_by_vrf and row.policy_id is None and row.requirement == "deny" and _address_only(row):
                self.unbound_denials[row.scope_id, row.zone_pair].append(row)
        for rule in self.revision.parse_result.rules:
            self.guard()
            if rule.enabled and rule.policy_id is not None:
                self.rules[rule.policy_id].append(rule)
        for row in self.rows:
            self.guard()
            key = _identifier(row)
            if row.scope_id != self.scope or key in duplicate_ids:
                continue
            try:
                address = None
                if isinstance(row, MatrixRequirement) and row.access_context is not None:
                    resolution = self._resolve_session(row)
                    if resolution is None:
                        self.unresolved[key] = "Для требования не выбран снимок пользовательского контекста"
                        continue
                    elif resolution.source_cidr is None:
                        self.unresolved[key] = resolution.message
                        continue
                    else:
                        address = resolution.source_cidr
                self.matches[key] = _row_boxes(
                    row, self.groups.for_policy(row.policy_id), MatrixBudget(self.guard), session_address=address,
                    family=_projected_family(self.revision, row.policy_id),
                    cache=self.coverage_cache,
                )
            except (CoverageLimitError, UnsupportedCoverageError):
                self.unresolved[key] = "Сложность или протокол условий выходит за пределы расчёта"
        self._check_overlaps()
        self._prepare_boundaries()
        for boundary in self.matrix.boundaries:
            self.guard()
            if boundary.scope_id != self.scope:
                continue
            scoped = self.groups.vrf_for_policy(boundary.policy_id) is not None
            for key in boundary.allowed_requirement_ids:
                self.guard()
                requirement = self.requirements.get(key)
                conflicts = (
                    self.structural_conflicts
                    if scoped and requirement is not None and requirement.policy_id is None
                    else self.conflicts
                )
                if key in conflicts:
                    self.conflicts.add(boundary.boundary_id)
                    break

    def _resolve_session(self, row: MatrixRequirement) -> AccessContextResolution | None:
        if (
            self.session_resolver is None or self.context_inputs is None
            or self.project_id is None or row.access_context is None
        ):
            return None
        context = self.policy_contexts.get(row.policy_id or "", self.revision.device.context)
        result = self.session_resolver.resolve(
            row, self.groups.for_policy(row.policy_id),
            project_id=self.project_id, scope_id=self.scope, context_id=context,
            guard=self.guard,
        )
        self.context_rows[row.requirement_id] = result
        return result

    def _check_overlaps(self) -> None:
        denial_rows: dict[Context, list[MatrixRequirement]] = defaultdict(list)
        for row in self.matrix.requirements:
            self.guard()
            if row.requirement == "deny" and _address_only(row) and self.matches.get(row.requirement_id):
                denial_rows[_context(row)].append(row)
        indexes = {
            context: PacketCandidateIndex(
                ((index, box) for index, row in enumerate(rows)
                 for box in self.matches.get(row.requirement_id) or ()),
                self.guard,
            )
            for context, rows in denial_rows.items()
        }
        for row in self.matrix.requirements:
            self.guard()
            boxes = self.matches.get(row.requirement_id)
            context = _context(row)
            index = indexes.get(context)
            if row.requirement not in _ALLOWED or not _address_only(row) or boxes is None or index is None:
                continue
            for candidate in sorted(index.overlapping(boxes, self.guard)):
                self.guard()
                denial = denial_rows[context][candidate]
                if not {row.requirement_id, denial.requirement_id}.issubset(self.conflicts):
                    self.conflict(
                        row.requirement_id, denial.requirement_id, "overlapping_requirements",
                        "Разрешение и запрет пересекаются в одной области и политике",
                    )

    def _prepare_boundaries(self) -> None:
        allowed_rows: dict[Context, list[MatrixRequirement]] = defaultdict(list)
        for row in self.matrix.requirements:
            self.guard()
            if row.requirement in _ALLOWED and _address_only(row) and self.matches.get(row.requirement_id):
                allowed_rows[_context(row)].append(row)
        indexes = {
            context: PacketCandidateIndex(
                ((index, box) for index, row in enumerate(rows)
                 for box in self.matches.get(row.requirement_id) or ()),
                self.guard,
            )
            for context, rows in allowed_rows.items()
        }
        for boundary in self.matrix.boundaries:
            self.guard()
            key = boundary.boundary_id
            region = self.matches.get(key)
            if boundary.scope_id != self.scope or region is None:
                continue
            try:
                self._prepare_boundary(boundary, region, allowed_rows, indexes)
            except CoverageLimitError:
                self.unresolved[key] = "Не удалось точно вычислить остаток области в пределах бюджета"

    def _prepare_boundary(
        self, boundary: MatrixBoundary, region: Boxes,
        allowed_rows: dict[Context, list[MatrixRequirement]],
        indexes: dict[Context, PacketCandidateIndex],
    ) -> None:
        key = boundary.boundary_id
        context = _context(boundary)
        vrf = self.groups.vrf_for_policy(boundary.policy_id)
        budget = MatrixBudget(self.guard)
        accepted_ids = set(boundary.allowed_requirement_ids)
        forbidden = region
        for permitted_id in sorted(accepted_ids):
            self.guard()
            requirement = self.requirements.get(permitted_id)
            if requirement is None or not valid_boundary_reference(boundary, requirement):
                self.conflicts.add(key)
                return
            if permitted_id in (
                self.structural_conflicts if vrf is not None and requirement.policy_id is None else self.conflicts
            ):
                self.conflicts.add(key)
                return
            if not _address_only(requirement):
                self.unresolved[key] = "Состав исключения зависит от пользовательского условия или расписания"
                return
            if vrf is not None and requirement.policy_id is None:
                permitted = self._scoped_requirement_boxes(requirement, boundary.policy_id, vrf)
                if permitted and self._scoped_denial_index(boundary, vrf).overlapping(permitted, self.guard):
                    self.conflicts.add(key)
                    self.diagnostics.append(MatrixDiagnostic(
                        code="boundary_requirement_conflict",
                        message=f"Исключение {permitted_id} пересекается с запретом в VRF {vrf}.",
                        requirement_ids=(key,),
                    ))
                    return
            else:
                permitted = self.matches.get(permitted_id)
            if permitted is None:
                self.unresolved[key] = f"Состав разрешения области {permitted_id} не определён"
                return
            forbidden = self.coverage_cache.subtract_exception(forbidden, permitted, budget)
        self.forbidden[key] = forbidden
        index = indexes.get(context)
        if index is None or not forbidden:
            return
        for candidate in sorted(index.overlapping(forbidden, self.guard)):
            self.guard()
            row = allowed_rows[context][candidate]
            if not {key, row.requirement_id}.issubset(self.conflicts):
                self.conflict(
                    key, row.requirement_id, "boundary_requirement_conflict",
                    "Разрешающее требование выходит за перечисленные условия закрытой области",
                )

    def _scoped_requirement_boxes(
        self, row: MatrixRequirement, policy_id: str | None, vrf: str,
    ) -> Boxes | None:
        key = vrf, row.requirement_id
        if key not in self.scoped_matches:
            try:
                self.scoped_matches[key] = _row_boxes(
                    row, self.groups.for_policy(policy_id), MatrixBudget(self.guard), cache=self.coverage_cache,
                )
            except (CoverageLimitError, UnsupportedCoverageError):
                self.scoped_matches[key] = None
        return self.scoped_matches[key]

    def _scoped_denial_index(self, boundary: MatrixBoundary, vrf: str) -> PacketCandidateIndex:
        key = vrf, boundary.scope_id, boundary.zone_pair
        if key not in self.scoped_denials:
            rows = self.unbound_denials.get((boundary.scope_id, boundary.zone_pair), ())
            self.scoped_denials[key] = PacketCandidateIndex(
                (
                    (index, box)
                    for index, row in enumerate(rows)
                    if row.requirement_id not in self.structural_conflicts
                    for box in self._scoped_requirement_boxes(row, boundary.policy_id, vrf) or ()
                ),
                self.guard,
            )
        return self.scoped_denials[key]

    def assess(self, row: MatrixRow) -> MatrixRequirementAssessment:
        key = _identifier(row)
        if row.scope_id != self.scope:
            return MatrixRequirementAssessment(
                requirement_id=key, state="not_applicable",
                reasons=("Требование относится к другой явно заданной области.",),
            )
        if key in self.conflicts:
            return MatrixRequirementAssessment(
                requirement_id=key, state="requirement_conflict",
                reasons=("Сначала устраните конфликты требований.",),
            )
        if isinstance(row, MatrixRequirement) and row.requirement == "unregulated":
            return MatrixRequirementAssessment(requirement_id=key, state="unregulated")
        if row.zone_pair is not None and not matrix_policy_supports_zones(self.revision):
            return self.insufficient(key, "Для сверки по указанной паре зон нужен снимок UserGate или Ideco.")
        if isinstance(row, MatrixRequirement) and row.requirement == "allow_optional":
            if key not in self.unresolved and self.matches.get(key) is not None:
                return MatrixRequirementAssessment(
                    requirement_id=key, state="not_applicable",
                    reasons=("Наличие допустимого взаимодействия не требуется.",),
                )
        boxes = self.forbidden.get(key) if isinstance(row, MatrixBoundary) else self.matches.get(key)
        if key in self.unresolved:
            return self.insufficient(key, self.unresolved[key])
        if isinstance(row, MatrixRequirement) and (row.identity is not None or row.schedule is not None):
            return self.insufficient(key, "Для identity или расписания нет поддержанного сопоставления")
        groups = self.groups.for_policy(row.policy_id)
        missing = tuple(
            group for group in (row.source_group, row.destination_group)
            if groups.resolve(group) is None
        )
        if missing:
            return self.insufficient(key, f"Не определён состав групп: {', '.join(missing)}")
        if row.policy_id is None:
            return self.insufficient(key, "Для сверки нужно указать политику ревизии")
        if boxes is None:
            return self.insufficient(key, "Не удалось сопоставить семейство адресов или условия области")
        if not boxes:
            return MatrixRequirementAssessment(
                requirement_id=key, state="not_applicable",
                reasons=("Перечисленные разрешения покрывают всю область требования.",),
            )
        if not self.rules.get(row.policy_id):
            return self.insufficient(key, "В ревизии нет правил выбранной политики")
        cached = self.coverage_cache.get(row.policy_id, boxes, zone_pair=row.zone_pair)
        if cached is None:
            policy = self.policies.get(row.policy_id)
            if policy is None:
                policy = self.coverage_cache.prepare_policy(row.policy_id, tuple(self.rules[row.policy_id]), self.guard)
                self.policies[row.policy_id] = policy
            mode, coverage = policy.mode, policy.cover(
                boxes, MatrixBudget(self.guard), guard=self.guard, zone_pair=row.zone_pair,
            )
            attachment = self._assess_attachment(row.policy_id, boxes) if mode == "local_policy" else AttachmentScopeAssessment()
            self.coverage_cache.put(row.policy_id, boxes, mode, coverage, attachment, zone_pair=row.zone_pair)
        else:
            mode, coverage, attachment = cached
        state, reason = _result_state(row, coverage, mode == "local_policy")
        reasons = [reason]
        if row.zone_pair is not None:
            reasons.append(f"Пара зон политики: {row.zone_pair.source_zone} → {row.zone_pair.destination_zone}.")
        if coverage.limited:
            reasons.append("Превышен бюджет вычисления точного покрытия.")
        elif coverage.unknown:
            reasons.append("Часть сведений о политике не поддержана или не подтверждена.")
        evidence = coverage.evidence
        if attachment.limits_path:
            reasons.extend(attachment.reasons)
            evidence = (*evidence, Evidence(
                summary="Дополнительные сведения для проверки пути через VLAN",
                source_locations=attachment.source_locations, limitations=attachment.reasons,
            ))
        return MatrixRequirementAssessment(
            requirement_id=key, state=state, evidence=evidence,
            reasons=tuple(reasons), mode=mode, coverage_complete=coverage.complete,
            attachment_limited=attachment.limits_path,
        )

    def _assess_attachment(self, policy_id: str, boxes: Boxes) -> AttachmentScopeAssessment:
        if policy_id not in self.attachment_scopes:
            binding = matrix_transit_binding(self.revision, policy_id)
            self.attachment_scopes[policy_id] = (
                MatrixAttachmentScope(self.revision, binding, self.guard) if binding is not None else None
            )
        scope = self.attachment_scopes[policy_id]
        return scope.assess(boxes) if scope is not None else AttachmentScopeAssessment()

    @staticmethod
    def insufficient(key: str, reason: str) -> MatrixRequirementAssessment:
        return MatrixRequirementAssessment(
            requirement_id=key, state="insufficient_evidence", reasons=(reason,),
            coverage_complete=False,
        )


def evaluate_v2(
    matrix: AccessMatrix, revision: DeviceRevision, *, scope_id: str,
    profile_id: str, profile_version: str, bindings: CatalogBindings,
    cancelled: Callable[[], bool] | None, progress: Callable[[int, int], None] | None,
    context_inputs: MatrixContextInputs | None = None, project_id: str | None = None,
    coverage_cache: MatrixCoverageCache | None = None,
    session_resolver: MatrixSessionResolver | None = None,
    bindings_by_vrf: VrfCatalogBindings | None = None,
) -> MatrixAssessment:
    evaluator = _Evaluation(
        matrix, revision, scope_id, bindings, bindings_by_vrf, cancelled, context_inputs, project_id,
        coverage_cache, session_resolver,
    )
    total = len(evaluator.rows)
    status: Literal["complete", "partial", "cancelled"] = "complete"
    if progress is not None:
        progress(0, total)
    try:
        evaluator.guard()
        evaluator.prepare()
        for row in evaluator.rows:
            evaluator.guard()
            result = evaluator.assess(row)
            context = evaluator.context_rows.get(result.requirement_id)
            if context is not None:
                result = result.model_copy(update={
                    "context_resolution": context,
                    "coverage_complete": False,
                    "reasons": (*result.reasons, context.message),
                })
            evaluator.results.append(result)
            if progress is not None:
                progress(len(evaluator.results), total)
    except MatrixCancelled:
        status = "cancelled"
        evaluator.diagnostics.append(MatrixDiagnostic(
            code="cancelled", message="Сверка отменена; сохранена завершённая часть.",
        ))
    else:
        if any(item.coverage_complete is False for item in evaluator.results):
            status = "partial"
    modes = {result.mode for result in evaluator.results if result.mode is not None}
    mode: Literal["local_policy", "declared_rules", "mixed"] = (
        "mixed" if len(modes) > 1 else "local_policy" if "local_policy" in modes else "declared_rules"
    )
    return MatrixAssessment(
        schema_version="2.0.0", mode=mode, status=status,
        matrix_id=matrix.matrix_id, matrix_version=matrix.version,
        revision_id=revision.revision_id, profile_id=profile_id,
        profile_version=profile_version, scope_id=scope_id,
        diagnostics=tuple(evaluator.diagnostics), requirements=tuple(evaluator.results),
        limitations=(
            "Локальный порядок применяется к подтверждённому ACL или к поддержанной политике интерфейса Cloud.ru. "
            "В остальных случаях оцениваются объявленные условия.",
            "Маршрут, NAT, обратное направление и сквозной доступ не оценены.",
            "Пустая пара без явного ограничения области не регламентирована.",
        ),
    )
