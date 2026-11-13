"""Предпросмотр пакетного назначения политики строкам черновика."""

from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field

from firewall_compliance.application.access_matrix_v2 import valid_boundary_reference
from firewall_compliance.application.matrix_requirement_sets import (
    MatrixRequirementCondition, linked_requirements, matrix_requirement_condition,
)
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixBoundary, MatrixRequirement


@dataclass(frozen=True, slots=True)
class MatrixPolicyAssignment:
    """Замены по индексам текущего черновика или ошибки всего пакета."""

    requirements: dict[int, MatrixRequirement] = field(default_factory=dict)
    boundaries: dict[int, MatrixBoundary] = field(default_factory=dict)
    errors: tuple[str, ...] = ()


def prepare_policy_assignment(
    matrix: AccessMatrix, scope_id: str, policy_id: str, identifiers: Sequence[str],
) -> MatrixPolicyAssignment:
    """Проверить назначения и зависимые исключения перед изменением черновика."""
    policy_id = policy_id.strip()
    if not 1 <= len(policy_id) <= 256:
        return MatrixPolicyAssignment(errors=("Укажите ID политики длиной от 1 до 256 символов.",))
    if not identifiers:
        return MatrixPolicyAssignment(errors=("Выберите требования или закрытые области.",))

    requirements = {row.requirement_id: index for index, row in enumerate(matrix.requirements)}
    boundaries = {row.boundary_id: index for index, row in enumerate(matrix.boundaries)}
    counts = Counter(row.requirement_id for row in matrix.requirements)
    counts.update(row.boundary_id for row in matrix.boundaries)
    linked = linked_requirements(matrix.set_assignments, matrix.requirement_sets)
    selected = Counter(identifiers)
    requirement_updates: dict[int, MatrixRequirement] = {}
    boundary_updates: dict[int, MatrixBoundary] = {}
    errors: list[str] = []

    for identifier, count in selected.items():
        if count != 1 or counts[identifier] > 1:
            errors.append(f"{identifier}. ID строки повторяется.")
            continue
        requirement_index = requirements.get(identifier)
        boundary_index = boundaries.get(identifier)
        if requirement_index is not None:
            requirement = matrix.requirements[requirement_index]
            if requirement.scope_id != scope_id or requirement.policy_id is not None:
                errors.append(f"{identifier}. Выберите строку текущей области с пустой политикой.")
            elif identifier in linked:
                errors.append(f"{identifier}. Создайте версию набора с нужной политикой и обновите назначение.")
            elif requirement.requirement == "unregulated":
                errors.append(f"{identifier}. Для нерегламентированной строки политика не назначается.")
            else:
                requirement_updates[requirement_index] = requirement.model_copy(update={"policy_id": policy_id})
        elif boundary_index is not None:
            boundary = matrix.boundaries[boundary_index]
            if boundary.scope_id != scope_id or boundary.policy_id is not None:
                errors.append(f"{identifier}. Выберите строку текущей области с пустой политикой.")
            else:
                boundary_updates[boundary_index] = boundary.model_copy(update={"policy_id": policy_id})
        else:
            errors.append(f"{identifier}. Строка отсутствует в черновике.")

    for index, boundary in enumerate(matrix.boundaries):
        proposed = boundary_updates.get(index, boundary)
        for identifier in dict.fromkeys(boundary.allowed_requirement_ids):
            requirement_index = requirements.get(identifier)
            if index not in boundary_updates and requirement_index not in requirement_updates:
                continue
            original = (
                matrix.requirements[requirement_index]
                if requirement_index is not None and counts[identifier] == 1 else None
            )
            updated = original if requirement_index is None else requirement_updates.get(requirement_index, original)
            if not valid_boundary_reference(proposed, updated) and (
                index in boundary_updates or valid_boundary_reference(boundary, original)
            ):
                errors.append(f"{boundary.boundary_id}. Исключение {identifier} несовместимо с назначением политики.")

    if requirement_updates:
        decisions: dict[MatrixRequirementCondition, dict[bool, str]] = defaultdict(dict)
        for row in matrix.requirements:
            if row.scope_id == scope_id and row.policy_id == policy_id and row.requirement != "unregulated":
                decisions[matrix_requirement_condition(row)].setdefault(row.requirement != "deny", row.requirement_id)
        for row in requirement_updates.values():
            alternatives = decisions[matrix_requirement_condition(row)]
            allows = row.requirement != "deny"
            if opposite := alternatives.get(not allows):
                errors.append(f"{row.requirement_id}. Условия совпадают с противоположным требованием {opposite}.")
            alternatives.setdefault(allows, row.requirement_id)

    if errors:
        return MatrixPolicyAssignment(errors=tuple(errors))
    return MatrixPolicyAssignment(requirements=requirement_updates, boundaries=boundary_updates)
