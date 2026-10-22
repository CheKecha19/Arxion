"""Глубокие снимки без изменения настроек builder-моделей.

Гарантия относится к обычным операциям экземпляров. object.__setattr__,
model_construct и прямые вызовы методов базовых типов обходят защиту.
"""

from datetime import date, time, timedelta
from decimal import Decimal
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import PurePath
from typing import Any, NoReturn, cast
from uuid import UUID

from pydantic import BaseModel
from pydantic_core import PydanticUndefined

from firewall_compliance.domain.base import DomainModel


def _immutable(*args: Any, **kwargs: Any) -> NoReturn:
    raise TypeError("snapshot неизменяем")


class _SnapshotDict(dict[Any, Any]):
    """Словарь, совместимый со стандартной сериализацией Pydantic."""

    __slots__ = ()
    __init__ = _immutable
    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __copy__(self) -> "_SnapshotDict":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "_SnapshotDict":
        return _snapshot(self, memo, set())


class _SnapshotList(list[Any]):
    """Список для вложенных значений Any без изменяющих операций."""

    __slots__ = ()
    __init__ = _immutable
    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable

    def __copy__(self) -> "_SnapshotList":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "_SnapshotList":
        return _snapshot(self, memo, set())


class _SnapshotSet(set[Any]):
    """Множество для вложенных значений Any без изменяющих операций."""

    __slots__ = ()
    __init__ = _immutable
    __ior__ = _immutable
    __iand__ = _immutable
    __isub__ = _immutable
    __ixor__ = _immutable
    add = _immutable
    clear = _immutable
    discard = _immutable
    pop = _immutable
    remove = _immutable
    update = _immutable
    difference_update = _immutable
    intersection_update = _immutable
    symmetric_difference_update = _immutable

    def __copy__(self) -> "_SnapshotSet":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "_SnapshotSet":
        return _snapshot(self, memo, set())


_ATOMIC_TYPES = (
    type(None),
    bool,
    int,
    float,
    complex,
    str,
    bytes,
    date,
    time,
    timedelta,
    Decimal,
    UUID,
    PurePath,
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
    Enum,
)


def snapshot[T](value: T) -> T:
    """Отделить граф значений и запретить его мутации, сохранив класс модели.

    Поддержаны DomainModel, dict, tuple, list, set, frozenset и доменные скаляры.
    Циклы и неизвестные объекты отклоняются вместо ложной гарантии неизменяемости.
    JSON не хранит признак снимка: после валидации его следует создать снова.
    """
    return _snapshot(value, {}, set())


def freeze_snapshot_fields(value: DomainModel) -> None:
    """Заморозить self после инвариантов, отделив все вложенные значения."""
    if getattr(value, "_snapshot_locked", False):
        return
    frozen = snapshot(value)
    for name in (
        "__dict__",
        "__pydantic_extra__",
        "__pydantic_private__",
        "__pydantic_fields_set__",
    ):
        object.__setattr__(value, name, getattr(frozen, name))
    object.__setattr__(value, "_snapshot_locked", True)


def _snapshot[T](value: T, memo: dict[int, Any], active: set[int]) -> T:
    if isinstance(value, _ATOMIC_TYPES) or value is PydanticUndefined:
        return value
    identity = id(value)
    if identity in memo:
        return cast(T, memo[identity])
    if identity in active:
        raise ValueError("snapshot не поддерживает циклические значения")
    active.add(identity)
    try:
        result: Any
        if isinstance(value, DomainModel):
            result = BaseModel.__copy__(value)
            for name in ("__dict__", "__pydantic_extra__", "__pydantic_private__"):
                object.__setattr__(result, name, _snapshot(getattr(value, name), memo, active))
            object.__setattr__(result, "__pydantic_fields_set__", frozenset(value.model_fields_set))
            object.__setattr__(result, "_snapshot_locked", True)
        elif isinstance(value, dict):
            result = dict.__new__(_SnapshotDict)
            dict.__init__(
                result,
                (
                    (_snapshot(k, memo, active), _snapshot(v, memo, active))
                    for k, v in value.items()
                ),
            )
        elif isinstance(value, list):
            result = list.__new__(_SnapshotList)
            list.__init__(result, (_snapshot(v, memo, active) for v in value))
        elif isinstance(value, set):
            result = set.__new__(_SnapshotSet)
            set.__init__(result, (_snapshot(v, memo, active) for v in value))
        elif isinstance(value, tuple):
            result = tuple(_snapshot(v, memo, active) for v in value)
        elif isinstance(value, frozenset):
            result = frozenset(_snapshot(v, memo, active) for v in value)
        else:
            raise TypeError(f"snapshot не поддерживает тип {type(value).__name__}")
        memo[identity] = result
        return cast(T, result)
    finally:
        active.remove(identity)
