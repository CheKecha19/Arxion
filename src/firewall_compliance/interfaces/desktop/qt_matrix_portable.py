"""Перенос черновика с явными источниками ссылок каталога и ревизии."""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

from firewall_compliance.domain.access_matrix import (
    AccessMatrix, MatrixCatalogBinding, MatrixMember, MatrixRequirement, MatrixRequirementSet,
)
from firewall_compliance.domain.controls import ControlModel


class MatrixDraftReferenceError(ValueError):
    """Черновик с неразрешёнными ссылками нельзя перенести между контекстами."""


class MatrixDraftFile(ControlModel):
    format: Literal["arxion-matrix-draft-v1"] = "arxion-matrix-draft-v1"
    project_id: str
    revision_id: str | None = None
    matrix: AccessMatrix
    bindings: tuple[MatrixCatalogBinding, ...] = ()


@dataclass(frozen=True)
class ImportedMatrixDraft:
    matrix: AccessMatrix
    frozen_references: int
    same_project: bool

    @property
    def context_bound(self) -> bool:
        return any(
            row.access_context is not None or row.identity is not None or row.schedule is not None
            for row in _draft_requirements(self.matrix)
        )


def _draft_requirements(matrix: AccessMatrix) -> Iterator[MatrixRequirement]:
    yield from matrix.requirements
    for version in matrix.requirement_sets:
        yield from version.templates


def matrix_draft_scopes(matrix: AccessMatrix) -> set[str]:
    scopes = {row.scope_id for row in _draft_requirements(matrix)}
    scopes.update(row.scope_id for row in matrix.boundaries)
    scopes.update(group.scope_id for group in matrix.boundary_groups)
    scopes.update(journey.scope_id for journey in matrix.journeys)
    return scopes


def remap_matrix_scope(matrix: AccessMatrix, scope_id: str) -> AccessMatrix:
    """Перенести одну область с явной сменой идентичности версий шаблонов."""
    if len(matrix_draft_scopes(matrix)) != 1 or ImportedMatrixDraft(matrix, 0, True).context_bound:
        raise MatrixDraftReferenceError("Перенос доступен только для одной области без контекстных условий.")
    set_ids = {identifier: uuid4().hex for identifier in {row.set_id for row in matrix.requirement_sets}}
    revisions = {
        version.revision_id: MatrixRequirementSet.create(
            set_ids[version.set_id], version.version, version.name,
            tuple(row.model_copy(update={"scope_id": scope_id}) for row in version.templates),
        )
        for version in matrix.requirement_sets
    }
    return matrix.model_copy(update={
        "requirements": tuple(row.model_copy(update={"scope_id": scope_id}) for row in matrix.requirements),
        "boundaries": tuple(row.model_copy(update={"scope_id": scope_id}) for row in matrix.boundaries),
        "boundary_groups": tuple(
            group.model_copy(update={"scope_id": scope_id}) for group in matrix.boundary_groups
        ),
        "journeys": tuple(journey.model_copy(update={"scope_id": scope_id}) for journey in matrix.journeys),
        "requirement_sets": tuple(revisions.values()),
        "set_assignments": tuple(row.model_copy(update={
            "set_id": set_ids[row.set_id], "revision_id": revisions[row.revision_id].revision_id,
        }) for row in matrix.set_assignments),
    })


def load_matrix_draft(text: str, project_id: str, revision_id: str | None) -> ImportedMatrixDraft:
    payload = json.loads(text)
    if isinstance(payload, dict) and payload.get("format") == "arxion-matrix-draft-v1":
        package = MatrixDraftFile.model_validate(payload)
        matrix = package.matrix
    else:
        package = None
        matrix = AccessMatrix.model_validate(payload)
    same_project = package is not None and package.project_id == project_id
    imported = ImportedMatrixDraft(matrix, 0, same_project)
    if imported.context_bound and not same_project:
        raise MatrixDraftReferenceError(
            "Контекст пользователя или расписания требует исходного проекта. "
            "Подготовьте отдельный черновик без этих условий для переноса."
        )
    same_revision = (
        package is not None and same_project and revision_id is not None and package.revision_id == revision_id
    )
    if any(member.kind == "object" for group in matrix.groups for member in group.members) and not same_revision:
        raise MatrixDraftReferenceError(
            "Черновик содержит объекты исходной конфигурации. Откройте матрицу в той же ревизии проекта."
        )
    source_bindings = package.bindings if package is not None else ()
    if any(binding.vrf is not None for binding in source_bindings):
        raise MatrixDraftReferenceError("Состав каталога по VRF доступен только в результатах сверки.")
    if same_project:
        return imported
    bindings = {(binding.kind, binding.value): binding.cidrs for binding in source_bindings}
    if len(bindings) != len(source_bindings):
        raise MatrixDraftReferenceError("В файле повторяются ссылки каталога. Сохраните исправленный черновик.")
    frozen = 0
    groups = []
    for group in matrix.groups:
        members = []
        for member in group.members:
            if member.kind not in {"logical_network", "resource"}:
                members.append(member)
                continue
            addresses = bindings.get((member.kind, member.value))
            if not addresses:
                raise MatrixDraftReferenceError(
                    "Для переноса ссылок каталога нужны сохранённые адреса. "
                    "Экспортируйте файл из исходного проекта с разрешённым составом групп."
                )
            members.extend(MatrixMember(kind="network", value=address) for address in addresses)
            frozen += 1
        groups.append(group.model_copy(update={"members": tuple(members)}))
    return ImportedMatrixDraft(matrix.model_copy(update={"groups": tuple(groups)}), frozen, False)
