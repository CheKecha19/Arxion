"""Отбор предшествующих правил перед точной проверкой включения условий."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Iterator, Sequence
from heapq import merge
from itertools import islice
from typing import Literal

from firewall_compliance.domain import Rule
from firewall_compliance.domain.policy_matching import Interval, RuleMatch, resolve_rule

type _Axis = tuple[Literal["source", "destination", "service"], int | str]
type _Posting = tuple[list[int], int]
_IP_AXIS: _Axis = ("service", "ip")
_ADDRESS_AXES: tuple[Literal["source", "destination"], ...] = ("source", "destination")
_PAIR_WORK_FACTOR = 8


class CoverageSearchLimit(Exception):
    """Поиск по оставшимся правилам области не завершён."""


class _PointIndex:
    """Интервал хранится в узлах над координатами запросов, списки упорядочены по ACL."""

    def __init__(self, points: set[int]) -> None:
        self._points = sorted(points)
        self._base = 1 << (len(points) - 1).bit_length()
        self._nodes: dict[int, list[int]] = defaultdict(list)

    def add(self, position: int, interval: Interval) -> None:
        start, end = interval
        left = self._base + bisect_left(self._points, start)
        right = self._base + bisect_right(self._points, end)
        while left < right:
            if left % 2:
                self._nodes[left].append(position)
                left += 1
            if right % 2:
                right -= 1
                self._nodes[right].append(position)
            left //= 2
            right //= 2

    def prior_postings(self, point: int, before: int) -> Iterator[_Posting]:
        node = self._base + bisect_left(self._points, point)
        while node:
            if positions := self._nodes.get(node):
                end = bisect_left(positions, before)
                if end:
                    yield positions, end
            node //= 2


def _points(match: RuleMatch) -> Iterator[tuple[_Axis, int]]:
    # Любое покрывающее правило обязано содержать оба края каждого выбранного интервала.
    for family, (source, destination) in enumerate(zip(match.sources, match.destinations, strict=True)):
        for side, intervals in zip(_ADDRESS_AXES, (source, destination), strict=True):
            if intervals:
                start, end = max(intervals, key=lambda value: value[1] - value[0])
                axis: _Axis = (side, family)
                yield axis, start
                if end != start:
                    yield axis, end
    protocol, intervals = match.services[0]
    start, end = max(intervals, key=lambda value: value[1] - value[0])
    yield ("service", protocol), start
    if end != start:
        yield ("service", protocol), end


def _intervals(match: RuleMatch) -> Iterator[tuple[_Axis, Interval]]:
    for family, (source, destination) in enumerate(zip(match.sources, match.destinations, strict=True)):
        yield from ((("source", family), interval) for interval in source)
        yield from ((("destination", family), interval) for interval in destination)
    for protocol, ports in match.services:
        yield from ((("service", protocol), interval) for interval in ports)


class OrderedCoverageIndex:
    """Необходимые условия отбора без перечисления комбинаций адресов и сервисов."""

    def __init__(self, rules: Sequence[Rule], max_pair_rules: int) -> None:
        matches = []
        for rule in rules:
            match = resolve_rule(rule)
            assert match is not None  # Допустимость всех условий уже проверена _pair_groups.
            matches.append(match)
        self.matches = tuple(matches)
        self._points = tuple(tuple(_points(match)) for match in matches)
        coordinates: dict[_Axis, set[int]] = defaultdict(set)
        for points in self._points:
            for axis, point in points:
                coordinates[axis].add(point)
                if axis[0] == "service":
                    coordinates[_IP_AXIS].add(point)
        self._axes = {axis: _PointIndex(points) for axis, points in coordinates.items()}
        self._weights = []
        for position, match in enumerate(matches):
            weight = 0
            for axis, interval in _intervals(match):
                weight += 1
                if index := self._axes.get(axis):
                    index.add(position, interval)
            self._weights.append(weight)
        # Прежняя настройка числа правил задаёт бюджет работы на область.
        self._remaining_work = _PAIR_WORK_FACTOR * max_pair_rules**2

    def covers(self, outer: int, inner: int) -> bool:
        # Вес ограничивает перебор интервалов при сравнении сложных условий.
        self._remaining_work -= self._weights[outer] * self._weights[inner]
        if self._remaining_work < 0:
            raise CoverageSearchLimit
        return self.matches[outer].covers(self.matches[inner])

    def first_covering(self, targets: tuple[int, ...], *, before: int) -> int | None:
        if before == 0:
            return None
        candidates = merge(*(self._candidates(target, before) for target in targets))
        for candidate, target in candidates:
            if self.covers(candidate, target):
                return candidate
        return None

    def _candidates(self, target: int, before: int) -> Iterator[tuple[int, int]]:
        best: list[_Posting] = []
        best_count: int | None = None
        for axis, point in self._points[target]:
            postings = list(self._axes[axis].prior_postings(point, before))
            if axis[0] == "service" and axis != _IP_AXIS:
                postings.extend(self._axes[_IP_AXIS].prior_postings(point, before))
            count = sum(end for _, end in postings)
            if count == 0:
                return
            if best_count is None or count < best_count:
                best, best_count = postings, count
        # Каждое нормализованное условие покрывает точку одним интервалом на оси.
        # IP и конкретные протоколы взаимоисключаются при нормализации сервисов.
        for candidate in merge(*(islice(ids, end) for ids, end in best)):
            yield candidate, target
