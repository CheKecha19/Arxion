"""Общие настройки доменных моделей."""

from collections.abc import Mapping
from typing import Any, Self

from pydantic import BaseModel, ConfigDict


class DomainModel(BaseModel):
    """Базовый класс строгих доменных моделей."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_assignment=True)

    __slots__ = ("_snapshot_locked",)

    def _check_snapshot(self) -> None:
        if getattr(self, "_snapshot_locked", False):
            raise TypeError("snapshot неизменяем")

    def __init__(self, **data: Any) -> None:
        self._check_snapshot()
        super().__init__(**data)

    def __setattr__(self, name: str, value: Any) -> None:
        self._check_snapshot()
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        self._check_snapshot()
        super().__delattr__(name)

    def __setstate__(self, state: dict[Any, Any]) -> None:
        self._check_snapshot()
        super().__setstate__(state)

    def as_snapshot(self) -> Self:
        """Вернуть отдельный глубокий неизменяемый снимок того же класса."""
        from firewall_compliance.domain.snapshot import snapshot

        return snapshot(self)

    def __copy__(self) -> Self:
        if getattr(self, "_snapshot_locked", False):
            return self.as_snapshot()
        return super().__copy__()

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        if getattr(self, "_snapshot_locked", False):
            from firewall_compliance.domain.snapshot import _snapshot

            return _snapshot(self, memo if memo is not None else {}, set())
        return super().__deepcopy__(memo)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Копия снимка, включая update, остаётся глубоким снимком."""
        if not getattr(self, "_snapshot_locked", False):
            return super().model_copy(update=update, deep=deep)
        copied = BaseModel.__copy__(self)
        object.__setattr__(copied, "__dict__", dict(copied.__dict__))
        object.__setattr__(copied, "__pydantic_fields_set__", set(self.model_fields_set))
        if copied.__pydantic_extra__ is not None:
            object.__setattr__(copied, "__pydantic_extra__", dict(copied.__pydantic_extra__))
        return BaseModel.model_copy(copied, update=update, deep=deep).as_snapshot()
