"""Сравнение двух сохранённых оценок одной версии требований."""

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from firewall_compliance.application.matrix_artifact import MatrixAssessmentArtifact
from firewall_compliance.application.matrix_catalog_bindings import split_catalog_bindings
from firewall_compliance.application.matrix_policy import matrix_catalog_switch_policy_contexts
from firewall_compliance.application.matrix_scope_assessment import (
    SOURCE_FALLBACK_NOTE,
    MatrixScopeAssessment,
    MatrixScopeRowAssessment,
    MatrixScopeSource,
    matrix_scope_checksum,
    verify_scope_rows,
)
from firewall_compliance.domain.access_matrix import (
    AccessMatrix,
    MatrixRequirementAssessment,
    MatrixZonePair,
)

type ChangeState = Literal["changed", "evidence_changed", "unchanged", "inconclusive"]
type ChangeDirection = Literal["improved", "regressed"]
type _Reference = tuple[str, str]
type _RevisionPair = tuple[UUID, UUID]
type _BindingContext = tuple[UUID, UUID, str | None]


@dataclass(frozen=True, slots=True)
class MatrixAssessmentChange:
    requirement_id: str
    before: MatrixRequirementAssessment | None
    after: MatrixRequirementAssessment | None
    state: ChangeState


@dataclass(frozen=True, slots=True)
class MatrixScopeChange:
    requirement_id: str
    before: MatrixScopeRowAssessment | None
    after: MatrixScopeRowAssessment | None
    state: ChangeState | Literal["source_changed"]
    reason: str
    direction: ChangeDirection | None = None


def _policy_evidence(row: MatrixRequirementAssessment) -> tuple[bool, tuple[str, ...]]:
    # Идентификаторы и строки конфигурации могут измениться от вставки комментария.
    fragments = tuple(sorted(
        json.dumps({key: evidence.facts[key] for key in (
                    "action", "configured_profile", "fragment", "fragment_count", "priority", "reference", "security_group_id",
                    "security_group_position", "rule_source_zone", "rule_destination_zone",
                    )
                    if key in evidence.facts}, sort_keys=True, ensure_ascii=False)
        for evidence in row.evidence if "fragment" in evidence.facts
    ))
    return row.attachment_limited, fragments


def _compare_rows(
    previous: MatrixRequirementAssessment, current: MatrixRequirementAssessment,
    previous_mode: str, current_mode: str,
) -> ChangeState:
    uncertain = {"insufficient_evidence", "requirement_conflict", "not_applicable"}
    if (
        previous.state in uncertain or current.state in uncertain
        or previous.coverage_complete is False or current.coverage_complete is False
        or (previous.mode or previous_mode) != (current.mode or current_mode)
    ):
        return "inconclusive"
    if previous.state != current.state:
        return "changed"
    return "evidence_changed" if _policy_evidence(previous) != _policy_evidence(current) else "unchanged"


def compare_matrix_assessments(
    before: MatrixAssessmentArtifact, after: MatrixAssessmentArtifact,
) -> tuple[MatrixAssessmentChange, ...]:
    """Сопоставить выводы без переноса решений и повторного расчёта."""
    left, right = before.assessment, after.assessment
    old_device, new_device = before.revision.device, after.revision.device
    if before.origin_project_id != after.origin_project_id or (
        old_device.device_id, old_device.platform, old_device.context
    ) != (new_device.device_id, new_device.platform, new_device.context):
        raise ValueError("Выберите две сверки одного устройства и сетевого контекста")
    if before.matrix != after.matrix or set(before.bindings) != set(after.bindings):
        raise ValueError("Версия требований или состав ссылок каталога изменились")
    if (
        left.scope_id != right.scope_id
        or left.profile_id != right.profile_id
        or left.profile_version != right.profile_version
        or before.profile_settings_json is None
        or before.profile_settings_json != after.profile_settings_json
        or before.revision.parse_result.configuration.parser_version
        != after.revision.parse_result.configuration.parser_version
        or before.application_version != after.application_version
    ):
        raise ValueError("Область, профиль или версии анализа различаются либо не зафиксированы")

    old = {row.requirement_id: row for row in left.requirements}
    new = {row.requirement_id: row for row in right.requirements}
    if len(old) != len(left.requirements) or len(new) != len(right.requirements):
        raise ValueError("В результатах неоднозначные ID требований")
    policies = {row.requirement_id: row.policy_id for row in after.matrix.requirements}
    policies.update((row.boundary_id, row.policy_id) for row in after.matrix.boundaries)
    old_vrfs = matrix_catalog_switch_policy_contexts(before.revision)
    new_vrfs = matrix_catalog_switch_policy_contexts(after.revision)
    changes = []
    for identifier in dict.fromkeys((*old, *new)):
        previous, current = old.get(identifier), new.get(identifier)
        state: ChangeState
        if previous is None or current is None or "cancelled" in {left.status, right.status}:
            state = "inconclusive"
        elif old_vrfs.get(policies.get(identifier) or "") != new_vrfs.get(policies.get(identifier) or ""):
            state = "inconclusive"
        else:
            state = _compare_rows(previous, current, left.mode, right.mode)
        changes.append(MatrixAssessmentChange(identifier, previous, current, state))
    return tuple(changes)


def _source_identity(source: MatrixScopeSource) -> tuple[str, str, str | None]:
    return source.device_id, source.platform, source.device_context


class _CatalogDependencies:
    """Map changed references to nested groups once per compared source and VRF."""

    def __init__(self, matrix: AccessMatrix, scope_id: str) -> None:
        self.parents: dict[str, set[str]] = defaultdict(set)
        self.groups_by_reference: dict[_Reference, set[str]] = defaultdict(set)
        object_groups: set[str] = set()
        for group in matrix.groups:
            for member in group.members:
                if member.kind == "group":
                    self.parents[member.value].add(group.group_id)
                elif member.kind in {"logical_network", "resource"}:
                    self.groups_by_reference[member.kind, member.value].add(group.group_id)
                elif member.kind == "object":
                    object_groups.add(group.group_id)
        self.object_groups = self._with_parents(object_groups)

        requirements = {
            row.requirement_id: row for row in matrix.requirements if row.scope_id == scope_id
        }
        self.boundary_groups: dict[str, set[str]] = {}
        self.boundaries_with_unbound_exceptions: set[str] = set()
        self.denial_zones_by_group: dict[str, set[MatrixZonePair | None]] = defaultdict(set)
        for row in requirements.values():
            if row.requirement == "deny" and row.policy_id is None and (
                row.access_context is None and row.identity is None and row.schedule is None
            ):
                self.denial_zones_by_group[row.source_group].add(row.zone_pair)
                self.denial_zones_by_group[row.destination_group].add(row.zone_pair)

        for boundary in matrix.boundaries:
            if boundary.scope_id != scope_id:
                continue
            allowed_groups: set[str] = set()
            for identifier in boundary.allowed_requirement_ids:
                allowed = requirements.get(identifier)
                if (
                    allowed is None or allowed.zone_pair != boundary.zone_pair
                    or allowed.policy_id not in (None, boundary.policy_id)
                    or allowed.requirement not in {"permit", "allow_optional"}
                ):
                    continue
                allowed_groups.update((allowed.source_group, allowed.destination_group))
                if allowed.policy_id is None:
                    self.boundaries_with_unbound_exceptions.add(boundary.boundary_id)
            self.boundary_groups[boundary.boundary_id] = allowed_groups

    def affected_groups(self, references: set[_Reference]) -> set[str]:
        groups = {group for reference in references for group in self.groups_by_reference.get(reference, ())}
        return self._with_parents(groups)

    def _with_parents(self, groups: set[str]) -> set[str]:
        pending = list(groups)
        affected: set[str] = set()
        while pending:
            group = pending.pop()
            if group not in affected:
                affected.add(group)
                pending.extend(self.parents.get(group, ()))
        return affected

    def affects(
        self, row: MatrixScopeRowAssessment, groups: set[str], denial_zones: set[MatrixZonePair | None],
    ) -> bool:
        return row.source_group in groups or row.destination_group in groups or (
            row.kind == "boundary" and (
                not groups.isdisjoint(self.boundary_groups.get(row.requirement_id, ()))
                or (
                    row.zone_pair in denial_zones
                    and row.requirement_id in self.boundaries_with_unbound_exceptions
                )
            )
        )


def _direction(
    before: MatrixScopeRowAssessment, after: MatrixScopeRowAssessment,
) -> ChangeDirection | None:
    left, right = before.assessment, after.assessment
    if before.kind != after.kind or any(
        row.mode != "local_policy" or row.coverage_complete is not True or row.attachment_limited
        for row in (left, right)
    ):
        return None
    adverse = {"excess_allow"} if after.kind == "boundary" else {"declared_conflict", "partial_match"}
    if left.state in adverse and right.state == "declared_match":
        return "improved"
    if left.state == "declared_match" and right.state in adverse:
        return "regressed"
    return None


def compare_matrix_scope_assessments(
    before: MatrixScopeAssessment, after: MatrixScopeAssessment, *, matrix: AccessMatrix | None = None,
) -> tuple[MatrixScopeChange, ...]:
    """Сопоставить сохранённые выводы, проверяя состав каталога для каждой строки."""
    if (before.project_id, before.scope_id, before.selected_site_id) != (
        after.project_id, after.scope_id, after.selected_site_id,
    ):
        raise ValueError("Выберите сверки одной области проекта")
    if before.matrix_checksum != after.matrix_checksum:
        raise ValueError("Для сравнения нужна одна утверждённая версия матрицы")
    dependencies = None
    if matrix is not None:
        if matrix_scope_checksum(matrix) != after.matrix_checksum:
            raise ValueError("Версия требований не совпадает с сохранённой сверкой")
        verify_scope_rows(matrix, before)
        verify_scope_rows(matrix, after)
        dependencies = _CatalogDependencies(matrix, after.scope_id)
    old = {row.requirement_id: row for row in before.requirements}
    new = {row.requirement_id: row for row in after.requirements}
    if len(old) != len(before.requirements) or len(new) != len(after.requirements):
        raise ValueError("В сверке есть неоднозначные ID требований")
    previous_sources = {source.revision_id: source for source in before.sources}
    current_sources = {source.revision_id: source for source in after.sources}
    old_bindings = {key: split_catalog_bindings(source.bindings) for key, source in previous_sources.items()}
    new_bindings = {key: split_catalog_bindings(source.bindings) for key, source in current_sources.items()}
    same_bindings: dict[_BindingContext, bool] = {}
    base_changes: dict[_RevisionPair, set[_Reference]] = {}
    catalog_impact: dict[_BindingContext, tuple[set[str], set[MatrixZonePair | None]]] = {}

    def comparable_bindings(left: UUID, right: UUID, row: MatrixScopeRowAssessment) -> bool:
        old_base, old_scoped = old_bindings[left]
        new_base, new_scoped = new_bindings[right]
        vrf = row.policy_vrf
        old_overlay = old_scoped.get(vrf, {}) if vrf is not None else {}
        new_overlay = new_scoped.get(vrf, {}) if vrf is not None else {}
        scoped = bool(old_overlay or new_overlay)
        if not scoped:
            vrf = None
        key = left, right, vrf
        if dependencies is None:
            if key not in same_bindings:
                same_bindings[key] = old_base == new_base and old_overlay == new_overlay
            return same_bindings[key]
        if key not in catalog_impact:
            revisions = left, right
            if revisions not in base_changes:
                base_changes[revisions] = {
                    reference for reference in old_base.keys() | new_base.keys()
                    if old_base.get(reference) != new_base.get(reference)
                }
            references = base_changes[revisions]
            if scoped:
                # Привязка VRF перекрывает общий каталог для одной и той же ссылки.
                references = {
                    reference for reference in references | old_overlay.keys() | new_overlay.keys()
                    if old_overlay.get(reference, old_base.get(reference))
                    != new_overlay.get(reference, new_base.get(reference))
                }
            groups = dependencies.affected_groups(references)
            denial_zones: set[MatrixZonePair | None] = set()
            if scoped:
                denial_zones = {
                    zone for group in groups for zone in dependencies.denial_zones_by_group.get(group, ())
                }
            catalog_impact[key] = groups, denial_zones
        return not dependencies.affects(row, *catalog_impact[key])

    previous_candidates = {key: {_source_identity(previous_sources[item]) for item in values}
                           for key, values in before.policy_candidates.items()}
    current_candidates = {key: {_source_identity(current_sources[item]) for item in values}
                          for key, values in after.policy_candidates.items()}
    profile_matches = (before.profile_id, before.profile_version, before.application_version) == (
        after.profile_id, after.profile_version, after.application_version,
    )
    stale = {
        identifier for result in (before, after) for issue in result.diagnostics
        if issue.code == SOURCE_FALLBACK_NOTE for identifier in issue.requirement_ids
    }
    state_messages = {
        "changed": "Изменился вывод для проверяемой политики.",
        "evidence_changed": "Изменились основания или применимость политики.",
        "unchanged": "В сопоставимой части изменения не обнаружены.",
        "inconclusive": "Полнота или режим результатов не позволяют сопоставить вывод.",
    }
    changes: list[MatrixScopeChange] = []
    for identifier in dict.fromkeys((*old, *new)):
        left, right = old.get(identifier), new.get(identifier)
        state: ChangeState | Literal["source_changed"]
        if left is None or right is None:
            state, reason = "inconclusive", "В одном результате строка отсутствует."
        elif identifier in stale:
            state, reason = "inconclusive", "Один из снимков не обновился после более поздней попытки."
        elif "incomplete_policy_sources" in (left.routing, right.routing):
            state, reason = "inconclusive", "Одна из сверок опирается на неполный набор источников политики."
        elif left.zone_pair != right.zone_pair:
            state, reason = "inconclusive", "В результатах указаны разные пары зон политики."
        elif left.routing == right.routing == "resolved" and left.policy_vrf != right.policy_vrf:
            state, reason = "inconclusive", "Изменился подтверждённый VRF привязки ACL."
        elif (left.routing != right.routing or left.policy_id != right.policy_id
              or (left.routing in {"ambiguous", "target_not_found"}
                  and previous_candidates.get(left.policy_id or "") != current_candidates.get(right.policy_id or ""))):
            state, reason = "source_changed", "Изменилось наличие, назначение или число источников политики."
        elif left.routing == "unregulated" and right.routing == "unregulated":
            state, reason = "unchanged", "Требование остаётся нерегламентированным."
        elif left.revision_id is None or right.revision_id is None:
            state, reason = "inconclusive", "Для строки отсутствует однозначный источник политики."
        elif not profile_matches:
            state, reason = "inconclusive", "Сверки используют разные профили или версии приложения."
        else:
            old_source = previous_sources[left.revision_id]
            new_source = current_sources[right.revision_id]
            if _source_identity(old_source) != _source_identity(new_source):
                state, reason = "source_changed", "Выбраны разные устройства, платформы или сетевые контексты."
            elif old_source.parser_version != new_source.parser_version:
                state, reason = "inconclusive", "Изменилась версия разбора источника."
            elif (
                dependencies is not None
                and old_source.configuration_sha256.casefold() != new_source.configuration_sha256.casefold()
                and dependencies.affects(left, dependencies.object_groups, set())
            ):
                state, reason = "inconclusive", "Снимки различаются. Состав ссылок на объекты устройства не сохранён отдельно."
            elif not comparable_bindings(left.revision_id, right.revision_id, left):
                state, reason = "inconclusive", "Изменились сохранённые адресные привязки каталога."
            elif left.assessment.context_resolution != right.assessment.context_resolution:
                state, reason = "inconclusive", "Изменился проверяемый сеанс или его свидетельства."
            else:
                state = _compare_rows(left.assessment, right.assessment, before.mode, after.mode)
                reason = state_messages[state]
        direction = None
        if (
            state == "changed" and left is not None and right is not None
            and "cancelled" not in (before.status, after.status)
        ):
            direction = _direction(left, right)
        changes.append(MatrixScopeChange(identifier, left, right, state, reason, direction))
    return tuple(changes)
