"""Подготовка связанных назначений и явных копий требований."""

from collections import defaultdict
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from heapq import merge
from uuid import UUID, uuid4

from firewall_compliance.domain.access_matrix import (
    MatrixRequirement, MatrixRequirementSet, MatrixService, MatrixSetAssignment, MatrixZonePair,
)
from firewall_compliance.domain.policy_matching import Interval, merge_intervals


@dataclass(frozen=True)
class CopyEntry:
    row: MatrixRequirement
    original_id: str
    disposition: str
    related_id: str = ""


_ALL_PORTS: tuple[Interval, ...] = ((0, 65535),)
_INDEX_THRESHOLD = 64
type MatrixRequirementCondition = tuple[str, str, tuple[Interval, ...]]


def _ports(service: MatrixService) -> tuple[Interval, ...]:
    return merge_intervals([(port.start, port.end) for port in service.ports]) or _ALL_PORTS


def matrix_requirement_condition(row: MatrixRequirement) -> MatrixRequirementCondition:
    fields = {"requirement_id", "requirement", "service", "owner", "reason", "review_date"}
    ports = _ports(row.service) if row.service.protocol in {"tcp", "udp"} else ()
    return row.model_dump_json(exclude=fields), row.service.protocol, ports


def _ports_overlap(first: tuple[Interval, ...], second: tuple[Interval, ...]) -> bool:
    left = right = 0
    while left < len(first) and right < len(second):
        start, end = first[left]
        other_start, other_end = second[right]
        if end < other_start:
            left += 1
        elif other_end < start:
            right += 1
        else:
            return True
    return False


def _context_overlaps(first: MatrixRequirement, second: MatrixRequirement) -> bool:
    left, right = first.access_context, second.access_context
    if left is None or right is None:
        return True
    return left.channel == right.channel and (
        left.device_id is None or right.device_id is None or left.device_id == right.device_id
    )


type _PairKey = tuple[str, str, str, MatrixZonePair | None, bool]
type _AccessKey = tuple[str, str | None]


@dataclass(frozen=True, slots=True)
class _IndexedRequirement:
    row: MatrixRequirement
    ports: tuple[Interval, ...]
    order: int

    def conflicts(self, other: "_IndexedRequirement") -> bool:
        first, second = self.row, other.row
        return all(
            left is None or right is None or left == right
            for left, right in (
                (first.policy_id, second.policy_id), (first.identity, second.identity),
                (first.schedule, second.schedule),
            )
        ) and _context_overlaps(first, second) and (
            "ip" in (first.service.protocol, second.service.protocol)
            or first.service.protocol == second.service.protocol and _ports_overlap(self.ports, other.ports)
        )


class _PortIndex:
    """Postings for covered segments of the 16-bit destination port space."""

    def __init__(self) -> None:
        self._nodes: dict[int, list[int]] = {}

    def add(self, position: int, ports: tuple[Interval, ...]) -> None:
        for start, end in ports:
            pending = [(1, 0, 65535)]
            while pending:
                node, lo, hi = pending.pop()
                postings = self._nodes.setdefault(node, [])
                if start <= lo and hi <= end:
                    postings.append(position)
                    continue
                middle = (lo + hi) // 2
                if start <= middle:
                    pending.append((2 * node, lo, middle))
                if end > middle:
                    pending.append((2 * node + 1, middle + 1, hi))

    def postings(
        self, ports: tuple[Interval, ...], *, below: int,
    ) -> list[Sequence[int]] | None:
        count = 0
        result: list[Sequence[int]] = []
        visited: set[int] = set()
        for start, end in ports:
            pending = [(1, 0, 65535)]
            while pending:
                node, lo, hi = pending.pop()
                postings = self._nodes.get(node)
                if postings is None:
                    continue
                if postings and node not in visited:
                    visited.add(node)
                    count += len(postings)
                    if count >= below:
                        return None
                    result.append(postings)
                if lo == hi:
                    continue
                middle = (lo + hi) // 2
                if start <= middle:
                    pending.append((2 * node, lo, middle))
                if end > middle:
                    pending.append((2 * node + 1, middle + 1, hi))
        return result


class _ConflictPostings:
    def __init__(self, protocol: str) -> None:
        self.fields: dict[tuple[int, str | None], list[int]] = defaultdict(list)
        self.access: dict[_AccessKey | None, list[int]] = defaultdict(list)
        self.channels: dict[str, list[int]] = defaultdict(list)
        self.ports = _PortIndex() if protocol in {"tcp", "udp"} else None

    @staticmethod
    def fields_for(row: MatrixRequirement) -> tuple[str | None, ...]:
        return row.policy_id, row.identity, row.schedule

    def add(self, position: int, entry: _IndexedRequirement) -> None:
        for axis, value in enumerate(self.fields_for(entry.row)):
            self.fields[axis, value].append(position)
        context = entry.row.access_context
        access_key = (context.channel, context.device_id) if context is not None else None
        self.access[access_key].append(position)
        if context is not None:
            self.channels[context.channel].append(position)
        if self.ports is not None:
            self.ports.add(position, entry.ports)

    def candidates(self, entry: _IndexedRequirement, count: int) -> Iterator[int]:
        best: list[Sequence[int]] | None = None
        for axis, value in enumerate(self.fields_for(entry.row)):
            if value is not None:
                candidates: list[Sequence[int]] = [self.fields.get((axis, key), ()) for key in (None, value)]
                size = sum(map(len, candidates))
                if size < count:
                    best, count = candidates, size
        context = entry.row.access_context
        if context is not None:
            candidates = [self.access.get(None, ())]
            if context.device_id is None:
                candidates.append(self.channels.get(context.channel, ()))
            else:
                candidates.extend(
                    self.access.get((context.channel, key), ()) for key in (None, context.device_id)
                )
            size = sum(map(len, candidates))
            if size < count:
                best, count = candidates, size
        if self.ports is not None and entry.row.service.protocol != "ip" and entry.ports != _ALL_PORTS and count:
            indexed = self.ports.postings(entry.ports, below=count)
            if indexed is not None:
                best = indexed
        return iter(range(count)) if best is None else merge(*best)


class _ConflictBucket:
    def __init__(self, protocol: str) -> None:
        self.protocol = protocol
        self.entries: list[_IndexedRequirement] = []
        self.postings: _ConflictPostings | None = None

    def add(self, entry: _IndexedRequirement) -> None:
        position = len(self.entries)
        self.entries.append(entry)
        if self.postings is not None:
            self.postings.add(position, entry)
        elif len(self.entries) == _INDEX_THRESHOLD:
            self.postings = _ConflictPostings(self.protocol)
            for index, current in enumerate(self.entries):
                self.postings.add(index, current)

    def first_conflict(self, entry: _IndexedRequirement) -> _IndexedRequirement | None:
        if self.entries and self.entries[0].conflicts(entry):
            return self.entries[0]
        positions = (
            self.postings.candidates(entry, len(self.entries)) if self.postings
            else iter(range(1, len(self.entries)))
        )
        previous = 0
        for position in positions:
            if position != previous and (candidate := self.entries[position]).conflicts(entry):
                return candidate
            previous = position
        return None


class _RequirementIndex:
    """Быстрый предпросмотр для одинаковых пар групп и областей."""

    def __init__(self, existing: Sequence[MatrixRequirement]) -> None:
        self.by_pair: dict[_PairKey, dict[str, _ConflictBucket]] = defaultdict(dict)
        self.exact: dict[tuple[object, ...], str] = {}
        self.identifiers: set[str] = set()
        self._next_order = 0
        for row in existing:
            self._remember(row, _ports(row.service))

    @staticmethod
    def _exact_key(row: MatrixRequirement, ports: tuple[Interval, ...]) -> tuple[object, ...]:
        return (
            row.source_group, row.destination_group, row.scope_id, row.policy_id, row.zone_pair,
            row.identity, row.schedule, row.requirement, row.service.protocol, ports, row.access_context,
        )

    @staticmethod
    def _pair(row: MatrixRequirement, denied: bool) -> _PairKey:
        return row.source_group, row.destination_group, row.scope_id, row.zone_pair, denied

    def _remember(self, row: MatrixRequirement, ports: tuple[Interval, ...]) -> None:
        self.identifiers.add(row.requirement_id)
        self.exact.setdefault(self._exact_key(row, ports), row.requirement_id)
        if row.requirement != "unregulated":
            protocols = self.by_pair[self._pair(row, row.requirement == "deny")]
            protocol = row.service.protocol
            bucket = protocols.get(protocol)
            if bucket is None:
                bucket = protocols[protocol] = _ConflictBucket(protocol)
            bucket.add(_IndexedRequirement(row, ports, self._next_order))
            self._next_order += 1

    def preview(self, row: MatrixRequirement, original_id: str) -> CopyEntry:
        if row.requirement_id in self.identifiers:
            return CopyEntry(row, original_id, "Противоречие", row.requirement_id)
        ports = _ports(row.service)
        duplicate = self.exact.get(self._exact_key(row, ports), "")
        if row.requirement != "unregulated":
            indexed = _IndexedRequirement(row, ports, self._next_order)
            protocols = self.by_pair.get(self._pair(row, row.requirement != "deny"), {})
            protocol = row.service.protocol
            conflict = min((
                match for kind, bucket in protocols.items()
                if "ip" in (kind, protocol) or kind == protocol
                if (match := bucket.first_conflict(indexed)) is not None
            ), key=lambda candidate: candidate.order, default=None)
            if conflict is not None:
                return CopyEntry(row, original_id, "Противоречие", conflict.row.requirement_id)
        if duplicate:
            return CopyEntry(row, original_id, "Совпадение", duplicate)
        self._remember(row, ports)
        return CopyEntry(row, original_id, "Добавится")


def copy_preview(
    chosen: Sequence[MatrixRequirement], existing: Sequence[MatrixRequirement],
    targets: Sequence[str], replace_source: bool,
) -> tuple[CopyEntry, ...]:
    index = _RequirementIndex(existing)
    axis = "source_group" if replace_source else "destination_group"
    output = []
    for original in chosen:
        for target in targets:
            identifier = "copy-" + uuid4().hex
            while identifier in index.identifiers:
                identifier = "copy-" + uuid4().hex
            row = original.model_copy(update={"requirement_id": identifier, axis: target})
            output.append(index.preview(row, original.requirement_id))
    return tuple(output)


def new_requirements_preview(
    candidates: Sequence[MatrixRequirement], existing: Sequence[MatrixRequirement], *,
    reserved_ids: set[str],
) -> tuple[CopyEntry, ...]:
    """Показать повторения и противоположные условия для новых требований."""
    index = _RequirementIndex(existing)
    index.identifiers.update(reserved_ids)
    return tuple(index.preview(row, str(number)) for number, row in enumerate(candidates, start=1))


def assignment_ids(
    assignment: MatrixSetAssignment, version: MatrixRequirementSet,
) -> Iterator[str]:
    for template in version.templates:
        for group in assignment.group_ids:
            yield assignment.row_id(template.requirement_id, group)


def linked_requirements(
    assignments: Sequence[MatrixSetAssignment], versions: Sequence[MatrixRequirementSet],
) -> dict[str, UUID]:
    by_revision = {version.revision_id: version for version in versions}
    return {
        identifier: assignment.assignment_id
        for assignment in assignments
        for identifier in assignment_ids(assignment, by_revision[assignment.revision_id])
    }


def assignment_preview(
    assignment: MatrixSetAssignment, version: MatrixRequirementSet,
    existing: Sequence[MatrixRequirement], *, unchanged: Mapping[str, MatrixRequirement] | None = None,
) -> tuple[CopyEntry, ...]:
    """Подготовить строки закреплённой версии для одной явной операции."""
    if assignment.revision_id != version.revision_id or assignment.set_id != version.set_id:
        raise ValueError("Назначение ссылается на другую версию набора")
    index = _RequirementIndex(existing)
    candidates = _assignment_candidates(assignment, version)
    if not unchanged:
        return tuple(index.preview(row, original_id) for row, original_id in candidates)

    materialized = list(candidates)
    retained: set[int] = set()
    for position, (row, _) in enumerate(materialized):
        if row.requirement_id not in index.identifiers and unchanged.get(row.requirement_id) == row:
            index._remember(row, _ports(row.service))
            retained.add(position)
    return tuple(
        CopyEntry(row, original_id, "Добавится") if position in retained else index.preview(row, original_id)
        for position, (row, original_id) in enumerate(materialized)
    )


def _assignment_candidates(
    assignment: MatrixSetAssignment, version: MatrixRequirementSet,
) -> Iterator[tuple[MatrixRequirement, str]]:
    for template in version.templates:
        for group in assignment.group_ids:
            yield template.model_copy(update={
                "requirement_id": assignment.row_id(template.requirement_id, group),
                assignment.axis: group,
            }), template.requirement_id
