"""Индекс пересечений для кандидатов, сгруппированных по сетевому контексту."""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from heapq import merge

from firewall_compliance.analysis.policy_coverage import PacketBox
from firewall_compliance.domain.policy_matching import Interval

type IndexEntry = tuple[int, int, int]

_SORT_BATCH = 8192


def _ordered(
    entries: list[IndexEntry], guard: Callable[[], None], *,
    key: Callable[[IndexEntry], int],
) -> list[IndexEntry]:
    chunks = []
    for start in range(0, len(entries), _SORT_BATCH):
        guard()
        chunks.append(sorted(entries[start:start + _SORT_BATCH], key=key))
    if len(chunks) == 1:
        return chunks[0]
    result = []
    for index, entry in enumerate(merge(*chunks, key=key)):
        if index % _SORT_BATCH == 0:
            guard()
        result.append(entry)
    return result


@dataclass(frozen=True)
class _IntervalNode:
    center: int
    span: Interval
    size: int
    starts: tuple[IndexEntry, ...]
    ends: tuple[IndexEntry, ...]
    left: _IntervalNode | None
    right: _IntervalNode | None

    @classmethod
    def build(cls, entries: list[IndexEntry], guard: Callable[[], None]) -> _IntervalNode | None:
        if not entries:
            return None
        guard()
        center = entries[len(entries) // 2][0]
        left, spanning, right = [], [], []
        upper = center
        for offset, entry in enumerate(entries):
            if offset % _SORT_BATCH == 0:
                guard()
            start, end, _ = entry
            upper = max(upper, end)
            if end < center:
                left.append(entry)
            elif start > center:
                right.append(entry)
            else:
                spanning.append(entry)
        return cls(
            center, (entries[0][0], upper), len(entries), tuple(spanning),
            tuple(_ordered(spanning, guard, key=lambda item: -item[1])),
            cls.build(left, guard), cls.build(right, guard),
        )

    def count(self, interval: Interval, guard: Callable[[], None]) -> int:
        first, last = interval
        result = 0
        pending = [self]
        while pending:
            guard()
            node = pending.pop()
            lower, upper = node.span
            if first > upper or last < lower:
                continue
            if first <= lower and last >= upper:
                result += node.size
                continue
            if last < node.center:
                result += bisect_right(node.starts, last, key=lambda item: item[0])
            elif first > node.center:
                result += bisect_right(node.ends, -first, key=lambda item: -item[1])
            else:
                result += len(node.starts)
            if node.left is not None and first < node.center:
                pending.append(node.left)
            if node.right is not None and last > node.center:
                pending.append(node.right)
        return result

    def overlaps(self, interval: Interval, guard: Callable[[], None]) -> Iterable[int]:
        first, last = interval
        pending = [self]
        while pending:
            guard()
            node = pending.pop()
            if last < node.center:
                for start, _, index in node.starts:
                    if start > last:
                        break
                    yield index
            elif first > node.center:
                for _, end, index in node.ends:
                    if end < first:
                        break
                    yield index
            else:
                yield from (index for _, _, index in node.starts)
            if node.left is not None and first < node.center:
                pending.append(node.left)
            if node.right is not None and last > node.center:
                pending.append(node.right)


def _noop() -> None:
    pass


class PacketCandidateIndex:
    """Отбор по пересечению всех осей одного блока, без смешения условий."""

    def __init__(
        self, entries: Iterable[tuple[int, PacketBox]], guard: Callable[[], None] = _noop,
    ) -> None:
        axes: dict[tuple[int, int], list[IndexEntry]] = defaultdict(list)
        self._entries: list[tuple[int, PacketBox]] = []
        for owner, box in entries:
            guard()
            index = len(self._entries)
            self._entries.append((owner, box))
            for axis, (start, end) in enumerate(box.axes):
                axes[box.family, axis].append((start, end, index))
        self._axes = {
            key: _IntervalNode.build(_ordered(values, guard, key=lambda item: item[0]), guard)
            for key, values in axes.items()
        }

    def overlapping(self, boxes: Iterable[PacketBox], guard: Callable[[], None] = _noop) -> set[int]:
        owners: set[int] = set()
        for box in boxes:
            guard()
            best: tuple[int, _IntervalNode, Interval] | None = None
            for axis, interval in enumerate(box.axes):
                tree = self._axes.get((box.family, axis))
                count = tree.count(interval, guard) if tree else 0
                if not count or tree is None:
                    best = None
                    break
                if best is None or count < best[0]:
                    best = count, tree, interval
            if best is None:
                continue
            _, tree, interval = best
            for index in tree.overlaps(interval, guard):
                guard()
                owner, candidate = self._entries[index]
                if owner not in owners and all(
                    lo <= end and start <= hi
                    for (lo, hi), (start, end) in zip(candidate.axes, box.axes, strict=True)
                ):
                    owners.add(owner)
        return owners
