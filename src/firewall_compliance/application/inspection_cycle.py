"""Headless collection/analysis orchestration with explicit per-input outcomes."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, Literal, Protocol, TypeVar

T = TypeVar("T")
R = TypeVar("R")
ItemState = Literal["complete", "partial", "failed", "cancelled"]

_SAFE_FAILURES = {
    "SOURCE_CHANGED": "Файл изменился во время обработки. Повторите получение данных.",
    "SOURCE_HASH_MISMATCH": (
        "Содержимое отличается от сохранённого снимка. Добавьте файл как новые данные."
    ),
}


class CycleFailure(ValueError):
    """Adapter diagnostic selected from safe messages, without exception payloads."""

    def __init__(self, code: str) -> None:
        if code not in _SAFE_FAILURES:
            raise ValueError("Unknown safe cycle diagnostic")
        self.code = code
        super().__init__(_SAFE_FAILURES[code])


class Cancellation(Protocol):
    def is_set(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class CycleSettings:
    """Canonical JSON freezes settings before any source callback executes."""

    json_value: str

    def __post_init__(self) -> None:
        value = json.loads(self.json_value)
        if not isinstance(value, dict):
            raise ValueError("Cycle settings must be an object")
        canonical = json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        object.__setattr__(self, "json_value", canonical)

    @classmethod
    def capture(cls, settings: Mapping[str, Any]) -> CycleSettings:
        if not isinstance(settings, Mapping):
            raise TypeError("Cycle settings must be a mapping")
        return cls(json.dumps(dict(settings), ensure_ascii=False, allow_nan=False))

    def values(self) -> dict[str, Any]:
        return json.loads(self.json_value)


@dataclass(frozen=True, slots=True)
class CycleProgress:
    stage: Literal["collection", "analysis", "finished"]
    completed: int
    total: int
    source_id: str | None = None
    item_id: str | None = None


@dataclass(frozen=True, slots=True)
class CycleInput(Generic[T]):
    input_id: str
    value: T

    def __post_init__(self) -> None:
        if not isinstance(self.input_id, str) or not self.input_id:
            raise ValueError("Input IDs must be nonempty strings")


@dataclass(frozen=True, slots=True)
class SourcePlan(Generic[T]):
    """Collectors own I/O and completeness; returning data is not proof of coverage."""

    source_id: str
    collect: Callable[[], tuple[CycleInput[T], ...]]

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not self.source_id:
            raise ValueError("Source IDs must be nonempty strings")
        if not callable(self.collect):
            raise TypeError("A collector callback is required")


@dataclass(frozen=True, slots=True)
class ItemOutcome(Generic[R]):
    source_id: str
    input_id: str
    state: ItemState
    value: R | None = None
    code: str = ""
    message: str = ""

    def __post_init__(self) -> None:
        if self.state not in {"complete", "partial", "failed", "cancelled"}:
            raise ValueError("Unsupported item state")


@dataclass(frozen=True, slots=True)
class SourceOutcome:
    source_id: str
    state: Literal["collected", "failed", "cancelled"]
    items: int = 0
    code: str = ""
    message: str = ""


@dataclass(frozen=True, slots=True)
class CycleOutcome(Generic[R]):
    sources: tuple[SourceOutcome, ...]
    items: tuple[ItemOutcome[R], ...]

    @property
    def state(self) -> Literal["complete", "partial", "failed", "cancelled"]:
        if any(source.state == "cancelled" for source in self.sources) or any(
            item.state == "cancelled" for item in self.items
        ):
            return "cancelled"
        successes = any(item.state in {"complete", "partial"} for item in self.items)
        failed = any(source.state == "failed" for source in self.sources) or any(
            item.state == "failed" for item in self.items
        )
        if not self.items or not successes:
            return "failed"
        if failed or any(item.state == "partial" for item in self.items):
            return "partial"
        return "complete"


def _failure(error: Exception) -> tuple[str, str]:
    if isinstance(error, CycleFailure):
        return error.code, _SAFE_FAILURES[error.code]
    if isinstance(error, OSError):
        return "SOURCE_IO_ERROR", "Не удалось получить или прочитать данные источника."
    if isinstance(error, (ValueError, TypeError)):
        return "INPUT_CONTRACT_ERROR", "Данные не соответствуют контракту обработки."
    return "PROCESSING_ERROR", "Обработка не завершена; источник требует проверки."


def run_inspection_cycle(
    sources: tuple[SourcePlan[T], ...],
    settings: CycleSettings,
    analyze: Callable[[str, CycleInput[T], CycleSettings], ItemOutcome[R]],
    *,
    cancel: Cancellation,
    progress: Callable[[CycleProgress], None] | None = None,
    persist_item: Callable[[ItemOutcome[R]], None] | None = None,
    persist_source: Callable[[SourceOutcome], None] | None = None,
) -> CycleOutcome[R]:
    """Run independent sources; persistence failures abort rather than disappear.

    Cancellation is cooperative between sources/items. A running parser is not
    interrupted. Persistence callbacks run outside error conversion: a storage
    failure must reach the transaction/job owner. Progress consumers should be
    nonblocking (for Qt, enqueue events rather than touching widgets).
    """
    if len({source.source_id for source in sources}) != len(sources):
        raise ValueError("Source IDs must be unique")
    emit = progress or (lambda _event: None)
    collected: list[tuple[str, CycleInput[T]]] = []
    source_results: list[SourceOutcome] = []
    emit(CycleProgress("collection", 0, len(sources)))
    for position, source in enumerate(sources, 1):
        if cancel.is_set():
            result = SourceOutcome(source.source_id, "cancelled")
        else:
            try:
                values = tuple(source.collect())
                if len({item.input_id for item in values}) != len(values):
                    raise ValueError("Duplicate input IDs in one source")
                if not values:
                    result = SourceOutcome(
                        source.source_id, "failed", code="SOURCE_EMPTY",
                        message="Источник не предоставил данных для анализа.",
                    )
                else:
                    collected.extend((source.source_id, item) for item in values)
                    result = SourceOutcome(source.source_id, "collected", len(values))
            except Exception as error:
                code, message = _failure(error)
                result = SourceOutcome(source.source_id, "failed", code=code, message=message)
        source_results.append(result)
        if persist_source is not None:
            persist_source(result)
        emit(CycleProgress("collection", position, len(sources), source.source_id))

    results: list[ItemOutcome[R]] = []
    emit(CycleProgress("analysis", 0, len(collected)))
    for position, (source_id, item) in enumerate(collected, 1):
        if cancel.is_set():
            outcome = ItemOutcome[R](
                source_id, item.input_id, "cancelled", code="CANCELLED",
                message="Отменено до начала анализа.",
            )
        else:
            try:
                outcome = analyze(source_id, item, settings)
                if outcome.source_id != source_id or outcome.input_id != item.input_id:
                    raise ValueError("Analyzer returned another input's result")
            except Exception as error:
                code, message = _failure(error)
                outcome = ItemOutcome(source_id, item.input_id, "failed", code=code, message=message)
        if persist_item is not None:
            persist_item(outcome)
        results.append(outcome)
        emit(CycleProgress("analysis", position, len(collected), source_id, item.input_id))
    emit(CycleProgress("finished", len(results), len(collected)))
    return CycleOutcome(tuple(source_results), tuple(results))
