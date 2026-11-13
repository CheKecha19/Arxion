"""Требования к последовательным взаимодействиям через промежуточные ресурсы."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from itertools import pairwise
from typing import TYPE_CHECKING, Self

from pydantic import Field, model_validator

from firewall_compliance.domain.controls import ControlModel

if TYPE_CHECKING:
    from firewall_compliance.domain.access_matrix import AccessMatrix


class JourneyStep(ControlModel):
    step_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    source_group: str = Field(min_length=1, max_length=128)
    destination_group: str = Field(min_length=1, max_length=128)
    requirement_id: str | None = Field(default=None, min_length=1, max_length=128)


class AccessJourney(ControlModel):
    journey_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    scope_id: str = Field(min_length=1, max_length=256)
    steps: tuple[JourneyStep, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_continuity(self) -> Self:
        if len({step.step_id for step in self.steps}) != len(self.steps):
            raise ValueError("ID участков цепочки должны быть уникальны")
        if any(
            previous.destination_group != current.source_group
            for previous, current in pairwise(self.steps)
        ):
            raise ValueError("Назначение участка должно совпадать с источником следующего участка")
        return self


def validate_journeys(matrix: AccessMatrix, journeys: Sequence[AccessJourney]) -> None:
    """Проверить ссылки всех цепочек одним проходом по группам и требованиям."""
    if not journeys:
        return
    if len({journey.journey_id for journey in journeys}) != len(journeys):
        raise ValueError("ID цепочек должны быть уникальны")
    groups = Counter(group.group_id for group in matrix.groups)
    requirements = {row.requirement_id: row for row in matrix.requirements}
    result_ids = Counter(row.requirement_id for row in matrix.requirements)
    result_ids.update(row.boundary_id for row in matrix.boundaries)
    for journey in journeys:
        for step in journey.steps:
            if groups[step.source_group] != 1 or groups[step.destination_group] != 1:
                raise ValueError(f"Участок {step.step_id}: группа отсутствует или её ID неоднозначен")
            if step.requirement_id is None:
                continue
            requirement = requirements.get(step.requirement_id)
            if requirement is None or result_ids[step.requirement_id] != 1:
                raise ValueError(f"Участок {step.step_id}: требование отсутствует или его ID неоднозначен")
            if requirement.requirement != "permit" or (
                requirement.scope_id, requirement.source_group, requirement.destination_group
            ) != (journey.scope_id, step.source_group, step.destination_group):
                raise ValueError(f"Участок {step.step_id}: нужно обязательное разрешение для этих групп и области")


def validate_journey(matrix: AccessMatrix, journey: AccessJourney) -> None:
    """Проверить ссылки конкретной цепочки, в том числе до сохранения черновика."""
    validate_journeys(matrix, (journey,))
