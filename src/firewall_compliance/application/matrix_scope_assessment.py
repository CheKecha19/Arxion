"""Сверка требований по сохранённым политикам одной области проекта."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cached_property
from hashlib import sha256
from ipaddress import ip_network
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance import __version__
from firewall_compliance.application.access_matrix import evaluate_access_matrix
from firewall_compliance.application.access_matrix_v2 import (
    CatalogBindings, MatrixPolicyGroupResolver, MatrixRow, MatrixSessionResolver, structural_diagnostics,
)
from firewall_compliance.application.cloud_sg_revision import CloudSGSelection
from firewall_compliance.application.matrix_artifact import MatrixContextEvidenceValidator
from firewall_compliance.application.matrix_catalog_bindings import split_catalog_bindings
from firewall_compliance.application.matrix_policy import (
    MatrixCancelled, MatrixCoverageCache, matrix_catalog_switch_policy_contexts, matrix_policy_contexts,
)
from firewall_compliance.domain.access_matrix import (
    AccessMatrix, MatrixBoundary, MatrixCatalogBinding, MatrixDiagnostic, MatrixGroup, MatrixRequirement,
    MatrixRequirementAssessment, MatrixZonePair,
)
from firewall_compliance.domain.controls import ControlModel
from firewall_compliance.domain.matrix_context_inputs import MatrixContextInputs
from firewall_compliance.domain.matrix_vmware_origin import VMwareMatrixOrigin
from firewall_compliance.domain.revision import DeviceRevision

type _Progress = Callable[[int, int], None]
type _Mode = Literal["local_policy", "declared_rules", "mixed"]
type _Status = Literal["complete", "partial", "cancelled"]
type MatrixScopeRouting = Literal[
    "resolved", "ambiguous", "incomplete_policy_sources", "missing_policy", "policy_not_found", "target_not_found",
    "unregulated", "conflict",
]
SOURCE_FALLBACK_NOTE = "newer_source_attempt_failed"
HISTORICAL_BASELINE_NOTE = "historical_policy_baseline"
_SELECTABLE_ROUTINGS = {"ambiguous", "incomplete_policy_sources", "target_not_found"}
_POLICY_ROUTINGS = _SELECTABLE_ROUTINGS | {"resolved", "policy_not_found"}
_PATH_ONLY_ROUTINGS = _SELECTABLE_ROUTINGS | {"missing_policy", "policy_not_found"}


@dataclass(frozen=True, slots=True)
class MatrixScopeInput:
    run_id: str | None
    item_id: str | None
    revision: DeviceRevision
    cloud_selection: CloudSGSelection | None = None
    vmware_origin: VMwareMatrixOrigin | None = None

    def __post_init__(self) -> None:
        if self.vmware_origin is not None and any(
            origin is not None for origin in (self.run_id, self.item_id, self.cloud_selection)
        ):
            raise ValueError("Источник VMware должен ссылаться только на запись облачного сбора")


class MatrixScopeEvaluationCache:
    """Ограниченное повторное использование покрытия в одной области проекта."""

    def __init__(self) -> None:
        self._entries: dict[UUID, MatrixCoverageCache] = {}

    def prepare(self, revisions: Mapping[UUID, DeviceRevision]) -> dict[UUID, MatrixCoverageCache]:
        coverage_budget = max(1, 100_000 // max(1, len(revisions)))
        rule_counts = {key: max(1, len(revision.parse_result.rules)) for key, revision in revisions.items()}
        total_rules = max(1, sum(rule_counts.values()))
        entries: dict[UUID, MatrixCoverageCache] = {}
        for key, revision in revisions.items():
            prepared_budget = max(1, 100_000 * rule_counts[key] // total_rules)
            existing = self._entries.get(key)
            if existing is not None and existing.revision == revision:
                existing.resize(coverage_budget, prepared_budget)
                entries[key] = existing
            else:
                entries[key] = MatrixCoverageCache(revision, budget=coverage_budget, prepared_budget=prepared_budget)
        self._entries = entries
        return entries


class MatrixScopeTarget(ControlModel):
    device_id: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    device_context: str | None = None


class MatrixScopeSource(ControlModel):
    run_id: str | None = Field(default=None, min_length=1)
    item_id: str | None = Field(default=None, min_length=1)
    revision_id: UUID
    device_id: str = Field(min_length=1)
    device_label: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    device_context: str | None = None
    parser_version: str = Field(min_length=1)
    captured_at: AwareDatetime
    configuration_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    revision_checksum: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision_checksum_kind: Literal["canonical", "stored_json"] = "canonical"
    bindings: tuple[MatrixCatalogBinding, ...] = ()
    path_bindings: tuple[MatrixCatalogBinding, ...] = ()
    cloud_selection: CloudSGSelection | None = None
    imported_at: AwareDatetime | None = None
    vmware_origin: VMwareMatrixOrigin | None = None

    @model_validator(mode="after")
    def validate_origin(self) -> Self:
        if any(item.vrf is not None for item in self.path_bindings):
            raise ValueError("Адреса для разбора пути без политики должны быть общими для ревизии")
        binding_keys = [(item.vrf, item.kind, item.value) for item in (*self.bindings, *self.path_bindings)]
        if len(binding_keys) != len(set(binding_keys)):
            raise ValueError("Ссылки каталога в источнике сверки должны быть однозначны")
        selection = self.cloud_selection
        if self.revision_checksum_kind == "stored_json" and (
            self.bindings or selection is not None or self.vmware_origin is not None
            or self.platform not in {"aos-cx", "aos-switch", "comware"}
        ):
            raise ValueError("Компактный источник должен относиться к снимку коммутатора без политики")
        if self.vmware_origin is not None:
            if (
                selection is not None or self.run_id is not None or self.item_id is not None
                or self.imported_at is None or self.imported_at < self.captured_at
                or self.platform != "cloud-ru-vmware-nsxt" or self.device_context is not None
            ):
                raise ValueError("Облачный источник VMware должен ссылаться на самостоятельную политику Edge Gateway")
        elif selection is None:
            if self.run_id is None or self.item_id is None or self.imported_at is not None:
                raise ValueError("Источнику сверки нужны идентификаторы запуска и его элемента")
        elif (
            self.run_id is not None or self.item_id is not None or self.imported_at is None
            or self.imported_at < self.captured_at
            or self.platform not in {"cloud-ru-advanced-sg", "cloud-ru-evolution-sg"}
            or self.device_context != selection.scope_id
        ):
            raise ValueError("Облачный источник сверки должен содержать самостоятельный снимок группы безопасности")
        return self

    @model_serializer(mode="wrap")
    def serialize_origin(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        payload = handler(self)
        if self.revision_checksum_kind == "canonical":
            payload.pop("revision_checksum_kind", None)
        if not self.path_bindings:
            payload.pop("path_bindings", None)
        if self.cloud_selection is None:
            payload.pop("cloud_selection", None)
        if self.vmware_origin is None:
            payload.pop("vmware_origin", None)
        if self.cloud_selection is None and self.vmware_origin is None:
            payload.pop("imported_at", None)
        else:
            payload.pop("run_id", None)
            payload.pop("item_id", None)
        return payload

    @property
    def origin_key(self) -> tuple[str | None, ...]:
        if self.cloud_selection is not None:
            return "cloud", self.cloud_selection.model_dump_json()
        if self.vmware_origin is not None:
            return "vmware", self.vmware_origin.scan_id, str(self.vmware_origin.record_index)
        return "run", self.run_id, self.item_id


class MatrixScopeRowAssessment(ControlModel):
    kind: Literal["requirement", "boundary"]
    source_group: str
    destination_group: str
    policy_id: str | None
    zone_pair: MatrixZonePair | None = None
    policy_vrf: str | None = Field(default=None, min_length=1)
    routing: MatrixScopeRouting
    revision_id: UUID | None = None
    assessment: MatrixRequirementAssessment

    @property
    def requirement_id(self) -> str:
        return self.assessment.requirement_id

    @model_serializer(mode="wrap")
    def serialize_policy_context(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        payload = handler(self)
        if self.zone_pair is None:
            payload.pop("zone_pair", None)
        if self.policy_vrf is None:
            payload.pop("policy_vrf", None)
        return payload

    @model_validator(mode="after")
    def validate_routing(self) -> Self:
        if (self.routing == "resolved") != (self.revision_id is not None):
            raise ValueError("Подтверждённому назначению требуется выбранная ревизия")
        if self.routing in _POLICY_ROUTINGS and self.policy_id is None:
            raise ValueError("Для поиска источника политики нужен её ID")
        if self.policy_vrf is not None and self.routing != "resolved":
            raise ValueError("VRF должна относиться к выбранной политике сохранённой ревизии")
        return self


class MatrixScopeAssessment(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    application_version: str = Field(default=__version__, min_length=1)
    created_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    project_id: str = Field(min_length=1)
    scope_id: str = Field(min_length=1)
    selected_site_id: str | None = None
    baseline_run_id: str | None = Field(default=None, min_length=1)
    matrix_id: str
    matrix_version: str
    matrix_checksum: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile_id: str = Field(min_length=1)
    profile_version: str = Field(min_length=1)
    mode: _Mode
    status: _Status
    total_requirements: int = Field(ge=0)
    sources: tuple[MatrixScopeSource, ...]
    requirements: tuple[MatrixScopeRowAssessment, ...]
    policy_candidates: dict[str, tuple[UUID, ...]] = Field(default_factory=dict)
    targets_by_requirement: dict[str, MatrixScopeTarget] = Field(default_factory=dict)
    diagnostics: tuple[MatrixDiagnostic, ...] = ()
    context_inputs: MatrixContextInputs | None = None
    limitations: tuple[str, ...] = (
        "Сверка относится к сохранённым локальным политикам и объявлениям. Сквозной путь, NAT и обратный трафик не оценены.",
        "Политика назначается требованию по её ID в переданных снимках. Одинаковые ID разных ревизий требуют уточнения.",
        "Снимки могут относиться к разным моментам. Полнота охвата всей сети зависит от состава источников.",
    )

    @cached_property
    def payload_checksum(self) -> str:
        """Контрольная сумма компактного JSON для ссылок на исходную сверку."""
        return sha256(self.model_dump_json().encode("utf-8")).hexdigest()

    @model_serializer(mode="wrap")
    def serialize_optional_inputs(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        payload = handler(self)
        if self.context_inputs is None:
            payload.pop("context_inputs", None)
        if self.baseline_run_id is None:
            payload.pop("baseline_run_id", None)
        return payload

    @property
    def historical(self) -> bool:
        return self.baseline_run_id is not None or any(note.code == HISTORICAL_BASELINE_NOTE for note in self.diagnostics)

    def historical_run(self) -> str | None:
        if self.baseline_run_id is not None:
            return self.baseline_run_id
        for note in self.diagnostics:
            if note.code == HISTORICAL_BASELINE_NOTE:
                parts = note.message.split(" · ", maxsplit=3)
                if len(parts) == 4 and parts[0] == "Исторический срез" and parts[1].startswith("файловый запуск "):
                    return parts[2] or None
        return None

    def run_report_relation(self, run_id: str) -> Literal["historical_baseline", "evaluated_source"] | None:
        if self.historical:
            return "historical_baseline" if self.historical_run() == run_id else None
        revisions = {source.revision_id for source in self.sources if source.run_id == run_id}
        if revisions and any(row.revision_id in revisions for row in self.requirements):
            return "evaluated_source"
        return None

    @model_validator(mode="after")
    def validate_scope_result(self) -> Self:
        count = len(self.requirements)
        if count > self.total_requirements or (self.status != "cancelled" and count != self.total_requirements):
            raise ValueError("Число результатов не соответствует области сверки")
        sources = {source.revision_id: source for source in self.sources}
        if len(sources) != len(self.sources):
            raise ValueError("Источники сверки должны иметь уникальные ревизии")
        revisions = {key for key, source in sources.items() if source.revision_checksum_kind == "canonical"}
        if len({source.origin_key for source in self.sources}) != len(self.sources):
            raise ValueError("Источники сверки должны ссылаться на разные входные снимки")
        vrfs_by_revision: dict[UUID, set[str]] = defaultdict(set)
        policy_vrfs: dict[tuple[UUID, str | None], str | None] = {}
        for row in self.requirements:
            if row.revision_id is not None and row.revision_id not in revisions:
                raise ValueError("Результат ссылается на отсутствующий источник сверки")
            source = sources.get(row.revision_id) if row.revision_id is not None else None
            if row.revision_id is not None:
                key = row.revision_id, row.policy_id
                if policy_vrfs.setdefault(key, row.policy_vrf) != row.policy_vrf:
                    raise ValueError("Строки одной политики должны относиться к одному VRF")
                if row.policy_vrf is not None:
                    vrfs_by_revision[row.revision_id].add(row.policy_vrf)
            if (
                source is not None and source.vmware_origin is not None
                and row.policy_id != source.vmware_origin.resource_id
            ):
                raise ValueError("Результат ссылается на другую политику Edge Gateway")
            target = self.targets_by_requirement.get(row.requirement_id)
            if row.routing == "target_not_found" and target is None:
                raise ValueError("Для отсутствующего источника не указан выбор устройства")
            if row.routing == "incomplete_policy_sources" and (
                target is not None or row.assessment.state != "insufficient_evidence"
                or row.assessment.coverage_complete is not False
            ):
                raise ValueError("Неполный набор источников требует явного выбора устройства для оценки")
            if source is not None and target is not None:
                if (source.device_id, source.platform, source.device_context) != (
                    target.device_id, target.platform, target.device_context,
                ):
                    raise ValueError("Источник результата отличается от явно выбранного устройства")
        if self.status != "cancelled" and any(
            binding.vrf is not None and binding.vrf not in vrfs_by_revision[source.revision_id]
            for source in self.sources for binding in source.bindings
        ):
            raise ValueError("Состав каталога должен относиться к VRF оценённой политики")
        ambiguous = {row.policy_id for row in self.requirements if row.routing == "ambiguous"}
        required = ambiguous | {row.policy_id for row in self.requirements if row.routing == "incomplete_policy_sources"}
        selectable = required | {row.policy_id for row in self.requirements if row.routing == "target_not_found"}
        if not required.issubset(self.policy_candidates) or not selectable.issuperset(self.policy_candidates):
            raise ValueError("Список кандидатов не соответствует результатам выбора политики")
        for policy, candidates in self.policy_candidates.items():
            if (len(candidates) < (2 if policy in ambiguous else 1)
                    or len(set(candidates)) != len(candidates) or not revisions.issuperset(candidates)):
                raise ValueError("Неоднозначной политике нужны разные сохранённые ревизии")
            if any(
                (origin := sources[key].vmware_origin) is not None and origin.resource_id != policy for key in candidates
            ):
                raise ValueError("Кандидат относится к другой политике Edge Gateway")
        self._validate_context_evidence()
        return self

    def _validate_context_evidence(self) -> None:
        resolutions = [(row, resolution) for row in self.requirements
                       if (resolution := row.assessment.context_resolution) is not None]
        inputs = self.context_inputs
        if inputs is None:
            if resolutions:
                raise ValueError("Сверка не содержит исходных свидетельств сеансов")
            return
        snapshot = inputs.snapshot
        if (snapshot.project_id, snapshot.scope_id) != (self.project_id, self.scope_id):
            raise ValueError("Свидетельства сеансов относятся к другому проекту или области")
        if not resolutions:
            return
        if self.status == "complete":
            raise ValueError("Результат по одному сеансу не подтверждает полный охват требований")
        validator = MatrixContextEvidenceValidator(inputs)
        for row, resolution in resolutions:
            if (
                row.kind != "requirement" or row.routing != "resolved"
                or row.assessment.coverage_complete is not False
            ):
                raise ValueError("Результат сопоставления не относится к сохранённым свидетельствам")
            validator.validate(row.requirement_id, resolution)
            if resolution.status != "resolved" and (
                row.assessment.state not in {"insufficient_evidence", "requirement_conflict", "unregulated"}
                or row.assessment.evidence
            ):
                raise ValueError("Адресная оценка требует подтверждённого сеанса")

    def validate_session_requirements(self, matrix: AccessMatrix) -> None:
        if self.context_inputs is not None:
            referenced = {item.requirement_id for item in self.context_inputs.sessions}
            referenced.update(row.requirement_id for row in self.requirements
                              if row.assessment.context_resolution is not None)
            _validate_session_requirements(matrix, self.scope_id, referenced)

    def candidate_revisions(self, row: MatrixScopeRowAssessment) -> tuple[UUID, ...]:
        if row.routing not in _SELECTABLE_ROUTINGS or row.policy_id is None:
            return ()
        return self.policy_candidates.get(row.policy_id, ())


def _checksum(value: object) -> str:
    return sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def matrix_scope_checksum(matrix: AccessMatrix) -> str:
    """Контрольная сумма с той же канонизацией, что и у версии в истории матрицы."""
    return _checksum(matrix.model_dump(mode="json"))


def verify_scope_rows(matrix: AccessMatrix, result: MatrixScopeAssessment) -> None:
    """Match all saved atomic rows to the approved scope, including cancelled subsets."""
    scope = result.scope_id
    expected = Counter(
        ("requirement", row.requirement_id, row.source_group, row.destination_group, row.policy_id, row.zone_pair)
        for row in matrix.requirements if row.scope_id == scope
    )
    expected.update(
        ("boundary", row.boundary_id, row.source_group, row.destination_group, row.policy_id, row.zone_pair)
        for row in matrix.boundaries if row.scope_id == scope
    )
    actual = Counter(
        (row.kind, row.requirement_id, row.source_group, row.destination_group, row.policy_id, row.zone_pair)
        for row in result.requirements
    )
    if (
        result.total_requirements != expected.total() or actual - expected
        or (result.status != "cancelled" and actual != expected)
    ):
        raise ValueError("Строки сверки отличаются от утверждённых требований области")
    result.validate_session_requirements(matrix)


def matrix_scope_revision_checksum(revision: DeviceRevision) -> str:
    return _checksum(revision.model_dump(mode="json"))


def _identifier(row: MatrixRow) -> str:
    return row.requirement_id if isinstance(row, MatrixRequirement) else row.boundary_id


def _validate_session_requirements(matrix: AccessMatrix, scope_id: str, referenced: set[str]) -> None:
    if not referenced:
        return
    counts = Counter(row.requirement_id for row in matrix.requirements if row.requirement_id in referenced)
    counts.update(row.boundary_id for row in matrix.boundaries if row.boundary_id in referenced)
    eligible = {row.requirement_id for row in matrix.requirements
                if row.scope_id == scope_id and row.access_context is not None}
    if not eligible.issuperset(referenced) or any(counts[key] != 1 for key in referenced):
        raise ValueError("Сеансы относятся к однозначным требованиям с пользовательским контекстом этой области")


def _row_result(
    row: MatrixRow, routing: MatrixScopeRouting, assessment: MatrixRequirementAssessment, *,
    revision_id: UUID | None = None, policy_vrf: str | None = None,
) -> MatrixScopeRowAssessment:
    return MatrixScopeRowAssessment(
        kind="requirement" if isinstance(row, MatrixRequirement) else "boundary",
        source_group=row.source_group, destination_group=row.destination_group, policy_id=row.policy_id,
        zone_pair=row.zone_pair, policy_vrf=policy_vrf, routing=routing, revision_id=revision_id, assessment=assessment,
    )


def _unresolved(
    row: MatrixRow, conflicts: set[str], *, ambiguous: bool, target_missing: bool = False,
    incomplete_sources: bool = False,
) -> MatrixScopeRowAssessment:
    key = _identifier(row)
    if key in conflicts:
        return _row_result(row, "conflict", MatrixRequirementAssessment(
            requirement_id=key, state="requirement_conflict", reasons=("Сначала устраните конфликты требований.",),
        ))
    if isinstance(row, MatrixRequirement) and row.requirement == "unregulated":
        return _row_result(row, "unregulated", MatrixRequirementAssessment(requirement_id=key, state="unregulated"))
    routing: MatrixScopeRouting
    if row.policy_id is None:
        routing, reason = "missing_policy", "Для сверки нужно указать ID политики."
    elif target_missing:
        routing, reason = "target_not_found", "В последних снимках выбранного устройства и контекста нет нужной политики."
    elif ambiguous:
        routing, reason = "ambiguous", "Политика с этим ID есть в нескольких сохранённых ревизиях."
    elif incomplete_sources:
        routing = "incomplete_policy_sources"
        reason = "Сбор одного из источников этой политики недоступен. Выберите устройство для сверки."
    else:
        routing, reason = "policy_not_found", "В выбранных сохранённых ревизиях нет включённых правил этой политики."
    return _row_result(row, routing, MatrixRequirementAssessment(
        requirement_id=key, state="insufficient_evidence", coverage_complete=False, reasons=(reason,),
    ))


class _MatrixIndex:
    def __init__(self, matrix: AccessMatrix, scope_id: str, guard: Callable[[], None]) -> None:
        self.rows: tuple[MatrixRow, ...] = (*matrix.requirements, *matrix.boundaries)
        self.by_id: dict[str, list[int]] = defaultdict(list)
        self.groups: dict[str, list[tuple[int, MatrixGroup]]] = defaultdict(list)
        self.in_scope: list[int] = []
        self.unbound: list[int] = []
        self._matrix = matrix
        self._guard = guard
        for index, row in enumerate(self.rows):
            guard()
            self.by_id[_identifier(row)].append(index)
            if row.scope_id == scope_id:
                self.in_scope.append(index)
                if row.policy_id is None:
                    self.unbound.append(index)
        for index, group in enumerate(matrix.groups):
            guard()
            self.groups[group.group_id].append((index, group))

    def project(self, owners: Sequence[int]) -> tuple[AccessMatrix, tuple[int, ...]]:
        selected = set(owners)
        unbound_zones: set[MatrixZonePair | None] = set()
        for index in owners:
            self._guard()
            row = self.rows[index]
            if not isinstance(row, MatrixBoundary):
                continue
            for key in row.allowed_requirement_ids:
                self._guard()
                related = self.by_id.get(key, ())
                selected.update(related)
                if any(
                    isinstance(candidate, MatrixRequirement) and candidate.policy_id is None
                    and candidate.scope_id == row.scope_id and candidate.requirement in {"permit", "allow_optional"}
                    and candidate.zone_pair == row.zone_pair
                    for candidate in (self.rows[position] for position in related)
                ):
                    unbound_zones.add(row.zone_pair)
        if unbound_zones:
            # Исключение без политики может конфликтовать с другими требованиями этой же области.
            for index in self.unbound:
                self._guard()
                row = self.rows[index]
                if row.zone_pair not in unbound_zones:
                    continue
                selected.add(index)
                if isinstance(row, MatrixBoundary):
                    for key in row.allowed_requirement_ids:
                        self._guard()
                        selected.update(self.by_id.get(key, ()))
        for index in tuple(selected):
            self._guard()
            selected.update(self.by_id[_identifier(self.rows[index])])
        indices = tuple(sorted(selected))
        rows = [self.rows[index] for index in indices]
        groups = self._related_groups(rows)
        return AccessMatrix(
            schema_version="2.0.0", matrix_id=self._matrix.matrix_id, version=self._matrix.version,
            groups=groups, requirements=tuple(row for row in rows if isinstance(row, MatrixRequirement)),
            boundaries=tuple(row for row in rows if isinstance(row, MatrixBoundary)),
        ), indices

    def _related_groups(self, rows: Iterable[MatrixRow]) -> tuple[MatrixGroup, ...]:
        pending = [key for row in rows for key in (row.source_group, row.destination_group)]
        seen: set[str] = set()
        chosen: list[tuple[int, MatrixGroup]] = []
        while pending:
            self._guard()
            identifier = pending.pop()
            if identifier in seen:
                continue
            seen.add(identifier)
            for indexed in self.groups.get(identifier, ()):
                chosen.append(indexed)
                pending.extend(member.value for member in indexed[1].members if member.kind == "group")
        return tuple(group for _, group in sorted(chosen, key=lambda item: item[0]))


def _used_bindings(matrix: AccessMatrix, bindings: CatalogBindings, guard: Callable[[], None]) -> tuple[MatrixCatalogBinding, ...]:
    references = {(member.kind, member.value) for group in matrix.groups for member in group.members
                  if member.kind in {"logical_network", "resource"}}
    return _selected_bindings(references, bindings, guard)


def _used_vrf_bindings(
    index: _MatrixIndex, positions: Sequence[int], policy_contexts: Mapping[str, str],
    bindings_by_vrf: Mapping[str, CatalogBindings], guard: Callable[[], None],
) -> tuple[MatrixCatalogBinding, ...]:
    if not bindings_by_vrf:
        return ()
    rows_by_vrf: dict[str, list[MatrixRow]] = defaultdict(list)
    unbound_contexts: dict[tuple[str, MatrixZonePair | None], set[str]] = defaultdict(set)
    for position in positions:
        guard()
        row = index.rows[position]
        vrf = policy_contexts.get(row.policy_id or "")
        if vrf is None or vrf not in bindings_by_vrf:
            continue
        rows_by_vrf[vrf].append(row)
        if not isinstance(row, MatrixBoundary):
            continue
        for key in row.allowed_requirement_ids:
            guard()
            matches = index.by_id.get(key, ())
            allowed = index.rows[matches[0]] if len(matches) == 1 else None
            if (
                isinstance(allowed, MatrixRequirement) and allowed.policy_id in (None, row.policy_id)
                and allowed.scope_id == row.scope_id and allowed.zone_pair == row.zone_pair
                and allowed.requirement in {"permit", "allow_optional"}
            ):
                rows_by_vrf[vrf].append(allowed)
                if allowed.policy_id is None:
                    unbound_contexts[row.scope_id, row.zone_pair].add(vrf)
    if unbound_contexts:
        for position in index.unbound:
            guard()
            row = index.rows[position]
            if (
                isinstance(row, MatrixRequirement) and row.requirement == "deny"
                and row.access_context is None and row.identity is None and row.schedule is None
            ):
                for vrf in unbound_contexts.get((row.scope_id, row.zone_pair), ()):
                    guard()
                    rows_by_vrf[vrf].append(row)
    result: list[MatrixCatalogBinding] = []
    for vrf, rows in sorted(rows_by_vrf.items()):
        references = {
            (member.kind, member.value) for group in index._related_groups(rows) for member in group.members
            if member.kind in {"logical_network", "resource"}
        }
        result.extend(_selected_bindings(references, bindings_by_vrf[vrf], guard, vrf=vrf))
    return tuple(result)


def _selected_bindings(
    references: Iterable[tuple[str, str]], bindings: CatalogBindings, guard: Callable[[], None], *,
    vrf: str | None = None,
) -> tuple[MatrixCatalogBinding, ...]:
    result = []
    for kind, key in sorted(references):
        guard()
        if addresses := bindings.get((kind, key)):
            try:
                cidrs = tuple(dict.fromkeys(str(ip_network(address, strict=False)) for address in addresses))
                result.append(MatrixCatalogBinding.model_validate({"kind": kind, "value": key, "cidrs": cidrs, "vrf": vrf}))
            except ValueError:
                # Движок также рассматривает такую ссылку как неизвестную.
                continue
    return tuple(result)


def verify_scope_session_resolutions(
    matrix: AccessMatrix, result: MatrixScopeAssessment, revisions: Mapping[UUID, DeviceRevision],
) -> None:
    """Повторить сопоставление сеансов только для переданных исходных ревизий."""
    if result.context_inputs is None or not revisions:
        return
    contextual = {row.requirement_id for row in matrix.requirements
                  if row.scope_id == result.scope_id and row.access_context is not None}
    by_revision: dict[UUID, list[MatrixScopeRowAssessment]] = defaultdict(list)
    for row in result.requirements:
        if (
            row.revision_id is not None and row.revision_id in revisions
            and row.kind == "requirement" and row.requirement_id in contextual
        ):
            by_revision[row.revision_id].append(row)
    if not by_revision:
        return

    def guard() -> None:
        pass

    index = _MatrixIndex(matrix, result.scope_id, guard)
    session_resolver = MatrixSessionResolver(result.context_inputs)
    sources = {source.revision_id: source for source in result.sources}
    for revision_id, rows in by_revision.items():
        revision = revisions[revision_id]
        unique_rows = [row for row in rows if len(index.by_id[row.requirement_id]) == 1]
        if not unique_rows:
            continue
        projection, _ = index.project(tuple(index.by_id[row.requirement_id][0] for row in unique_rows))
        requirements = {row.requirement_id: row for row in projection.requirements}
        bindings, bindings_by_vrf = split_catalog_bindings(sources[revision_id].bindings)
        groups = MatrixPolicyGroupResolver(projection, revision, bindings, bindings_by_vrf, guard)
        policy_contexts = matrix_policy_contexts(revision)
        for row in unique_rows:
            resolution = session_resolver.resolve(
                requirements[row.requirement_id], groups.for_policy(row.policy_id),
                project_id=result.project_id, scope_id=result.scope_id,
                context_id=policy_contexts.get(row.policy_id or "", revision.device.context), guard=guard,
            )
            saved = row.assessment.context_resolution
            if saved is None or resolution.model_dump(exclude={"message"}) != saved.model_dump(exclude={"message"}):
                raise ValueError("Сопоставление сеанса отличается от результата на сохранённых входах")


def evaluate_matrix_scope(
    matrix: AccessMatrix, sources: Sequence[MatrixScopeInput], *,
    scope_id: str, project_id: str, profile_id: str, profile_version: str,
    selected_site_id: str | None = None,
    unavailable_policy_ids: frozenset[str] = frozenset(),
    targets_by_requirement: Mapping[str, MatrixScopeTarget] | None = None,
    bindings_by_revision: Mapping[UUID, CatalogBindings] | None = None,
    bindings_by_vrf_by_revision: Mapping[UUID, Mapping[str, CatalogBindings]] | None = None,
    path_sources: Sequence[MatrixScopeSource] = (),
    context_inputs: MatrixContextInputs | None = None,
    coverage_cache: MatrixScopeEvaluationCache | None = None,
    cancelled: Callable[[], bool] | None = None, progress: _Progress | None = None,
) -> MatrixScopeAssessment:
    """Индексировать политики один раз и проверять только связанные части матрицы."""
    if matrix.schema_version != "2.0.0":
        raise ValueError("Сверка по нескольким источникам требует матрицу v2")
    if not all(key.strip() for key in (scope_id, project_id, profile_id, profile_version)):
        raise ValueError("Нужны проект, область и версия профиля")
    if context_inputs is not None and (
        context_inputs.snapshot.project_id != project_id or context_inputs.snapshot.scope_id != scope_id
    ):
        raise ValueError("Свидетельства сеанса относятся к другому проекту или области")
    if context_inputs is not None:
        _validate_session_requirements(matrix, scope_id, {item.requirement_id for item in context_inputs.sessions})

    def guard() -> None:
        if cancelled is not None and cancelled():
            raise MatrixCancelled

    total = sum(row.scope_id == scope_id for row in (*matrix.requirements, *matrix.boundaries))
    completed = 0

    def tick() -> None:
        nonlocal completed
        completed += 1
        if progress is not None:
            progress(completed, total)

    if progress is not None:
        progress(0, total)
    summaries: dict[UUID, MatrixScopeSource] = {}
    revisions: dict[UUID, DeviceRevision] = {}
    policy_contexts_by_revision: dict[UUID, dict[str, str]] = {}
    origins: set[tuple[str | None, ...]] = set()
    candidates: dict[str, list[UUID]] = defaultdict(list)
    chosen_targets = dict(targets_by_requirement or {})
    target_candidates: dict[tuple[str, str, str, str | None], list[UUID]] = defaultdict(list)
    results: dict[int, MatrixScopeRowAssessment] = {}
    diagnostics: list[MatrixDiagnostic] = []
    status: _Status = "complete"
    try:
        guard()
        for source in path_sources:
            guard()
            if (
                source.revision_checksum_kind != "stored_json"
                or source.revision_id in summaries or source.origin_key in origins
            ):
                raise ValueError("Компактные источники пути должны ссылаться на разные сохранённые снимки")
            summaries[source.revision_id] = source
            origins.add(source.origin_key)
        index = _MatrixIndex(matrix, scope_id, guard)
        if chosen_targets and any(
            len(index.by_id.get(key, ())) != 1 or index.rows[index.by_id[key][0]].scope_id != scope_id
            or index.rows[index.by_id[key][0]].policy_id is None
            for key in chosen_targets
        ):
            raise ValueError("Выбранные устройства должны относиться к требованиям и политикам этой области")
        diagnostics.extend(structural_diagnostics(matrix, guard))
        conflicts = {
            key for item in diagnostics
            for key in (item.requirement_ids[:1] if item.code == "invalid_boundary_reference" else item.requirement_ids)
        }
        for source in sources:
            guard()
            revision = source.revision
            revision_id = revision.revision_id
            device, config = revision.device, revision.parse_result.configuration
            switch = revision.parse_result.switch_facts
            replayed = source.cloud_selection is not None or source.vmware_origin is not None
            summary = MatrixScopeSource(
                run_id=source.run_id, item_id=source.item_id, revision_id=revision_id,
                device_id=device.device_id,
                device_label=device.hostname or (switch.hostname if switch else None) or device.device_id,
                platform=device.platform, device_context=device.context, parser_version=config.parser_version,
                captured_at=config.captured_at,
                configuration_sha256=config.content_sha256, revision_checksum=matrix_scope_revision_checksum(revision),
                cloud_selection=source.cloud_selection, vmware_origin=source.vmware_origin,
                imported_at=revision.imported_at if replayed else None,
            )
            origin = summary.origin_key
            if revision_id in summaries or origin in origins:
                raise ValueError("Одна ревизия или один исходный снимок переданы несколько раз")
            origins.add(origin)
            revisions[revision_id] = revision
            summaries[revision_id] = summary
            policies = {source.vmware_origin.resource_id} if source.vmware_origin is not None else set()
            for rule in revision.parse_result.rules:
                guard()
                if source.vmware_origin is not None and rule.policy_id != source.vmware_origin.resource_id:
                    raise ValueError("Правило VMware относится к другой политике Edge Gateway")
                if rule.enabled and rule.policy_id is not None:
                    policies.add(rule.policy_id)
            for policy in policies:
                candidates[policy].append(revision_id)
                target_candidates[(policy, device.device_id, device.platform, device.context)].append(revision_id)

        by_revision: dict[UUID, list[int]] = defaultdict(list)
        for position in index.in_scope:
            guard()
            row = index.rows[position]
            owners = candidates.get(row.policy_id) if row.policy_id is not None else None
            selected = chosen_targets.get(_identifier(row))
            if row.policy_id is not None and selected is not None:
                owners = target_candidates.get((row.policy_id, selected.device_id, selected.platform, selected.device_context))
            singleton = owners is not None and len(owners) == 1
            incomplete_sources = (
                singleton and selected is None and row.policy_id is not None and row.policy_id in unavailable_policy_ids
            )
            if owners is not None and singleton and not incomplete_sources:
                revision_id = owners[0]
                revision = revisions[revision_id]
                device = revision.device
                if revision_id not in policy_contexts_by_revision:
                    policy_contexts_by_revision[revision_id] = matrix_catalog_switch_policy_contexts(revision)
                policy_vrf = policy_contexts_by_revision[revision_id].get(row.policy_id or "")
                incompatible = isinstance(row, MatrixBoundary) and any(
                    (target := chosen_targets.get(key)) is not None
                    and (target.device_id, target.platform, target.device_context)
                    != (device.device_id, device.platform, device.context)
                    for key in row.allowed_requirement_ids
                )
                if incompatible:
                    results[position] = _row_result(row, "resolved", MatrixRequirementAssessment(
                        requirement_id=_identifier(row), state="insufficient_evidence", coverage_complete=False,
                        reasons=("Исключение закрытой области привязано к другому устройству или контексту.",),
                    ), revision_id=revision_id, policy_vrf=policy_vrf)
                    tick()
                else:
                    by_revision[revision_id].append(position)
            else:
                results[position] = _unresolved(
                    row, conflicts, ambiguous=bool(owners) and not singleton,
                    target_missing=selected is not None and not owners, incomplete_sources=incomplete_sources,
                )
                tick()

        caches = coverage_cache.prepare({key: revisions[key] for key in by_revision}) if coverage_cache else {}
        guard()
        session_resolver = MatrixSessionResolver(context_inputs) if context_inputs is not None and by_revision else None
        for revision_id, positions in by_revision.items():
            guard()
            projection, indices = index.project(positions)
            target = set(positions)
            bindings = (bindings_by_revision or {}).get(revision_id, {})
            policy_contexts = policy_contexts_by_revision[revision_id]
            bound = _used_bindings(projection, bindings, guard)
            bound += _used_vrf_bindings(
                index, positions, policy_contexts, (bindings_by_vrf_by_revision or {}).get(revision_id, {}), guard,
            )
            summaries[revision_id] = summaries[revision_id].model_copy(update={"bindings": bound})
            frozen_bindings, frozen_by_vrf = split_catalog_bindings(bound)

            def inner_progress(count: int, _total: int) -> None:
                if count and indices[count - 1] in target:
                    tick()

            cache = caches.get(revision_id)
            value = evaluate_access_matrix(
                projection, cache.revision if cache is not None else revisions[revision_id],
                scope_id=scope_id, profile_id=profile_id,
                profile_version=profile_version, bindings=frozen_bindings, bindings_by_vrf=frozen_by_vrf,
                cancelled=cancelled,
                progress=inner_progress, context_inputs=context_inputs, project_id=project_id,
                coverage_cache=cache, session_resolver=session_resolver,
            )
            diagnostics.extend(item for item in value.diagnostics if item.code in {
                "overlapping_requirements", "boundary_requirement_conflict",
            })
            for position, assessment in zip(indices, value.requirements):
                if position in target:
                    row = index.rows[position]
                    results[position] = _row_result(
                        row, "resolved", assessment, revision_id=revision_id,
                        policy_vrf=policy_contexts.get(row.policy_id or ""),
                    )
            if value.status == "cancelled":
                raise MatrixCancelled
        path_only = tuple(
            index.rows[position] for position in index.in_scope
            if (result := results.get(position)) is not None
            and result.routing in _PATH_ONLY_ROUTINGS
            and isinstance(index.rows[position], MatrixRequirement)
        )
        if path_only and bindings_by_revision:
            path_groups = index._related_groups(path_only)
            references = {(member.kind, member.value) for group in path_groups for member in group.members
                          if member.kind in {"resource", "logical_network"}}
            path_bindings_cache: dict[int, tuple[MatrixCatalogBinding, ...]] = {}
            for revision_id, bindings in bindings_by_revision.items():
                guard()
                summary = summaries.get(revision_id)
                if summary is None:
                    continue
                revision = revisions.get(revision_id)
                if revision is not None and revision.parse_result.switch_facts is None:
                    continue
                existing = set(summary.bindings)
                key = id(bindings)
                if key not in path_bindings_cache:
                    path_bindings_cache[key] = _selected_bindings(references, bindings, guard)
                bound = path_bindings_cache[key]
                if bound:
                    summaries[revision_id] = summary.model_copy(update={
                        "path_bindings": tuple(binding for binding in bound if binding not in existing),
                    })
    except MatrixCancelled:
        status = "cancelled"
        diagnostics.append(MatrixDiagnostic(code="cancelled", message="Сверка отменена; сохранена завершённая часть."))
    rows = tuple(results[key] for key in sorted(results))
    if status == "complete" and any(
        row.assessment.coverage_complete is False or row.assessment.state == "requirement_conflict" for row in rows
    ):
        status = "partial"
    modes = {row.assessment.mode for row in rows if row.assessment.mode is not None}
    mode: _Mode = "mixed" if len(modes) > 1 else "local_policy" if "local_policy" in modes else "declared_rules"
    unique = {(item.code, item.message, item.group_ids, item.requirement_ids): item for item in diagnostics}
    selectable_policies = {row.policy_id for row in rows if row.policy_id is not None
                           and row.routing in _SELECTABLE_ROUTINGS and row.policy_id in candidates}
    return MatrixScopeAssessment(
        project_id=project_id, scope_id=scope_id, selected_site_id=selected_site_id,
        matrix_id=matrix.matrix_id, matrix_version=matrix.version,
        matrix_checksum=matrix_scope_checksum(matrix), profile_id=profile_id, profile_version=profile_version,
        mode=mode, status=status, total_requirements=total, sources=tuple(summaries.values()), requirements=rows,
        policy_candidates={key: tuple(candidates[key]) for key in sorted(selectable_policies)},
        targets_by_requirement=chosen_targets,
        diagnostics=tuple(unique.values()),
        context_inputs=context_inputs,
    )
