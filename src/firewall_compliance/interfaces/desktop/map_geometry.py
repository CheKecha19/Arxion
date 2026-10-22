"""Deterministic straight-edge crossings, excluding shared endpoints."""

from __future__ import annotations

from collections import defaultdict
from math import hypot

Point = tuple[float, float]
Segment = tuple[Point, Point]


def crossing(first: Segment, second: Segment) -> tuple[float, float] | None:
    (ax, ay), (bx, by) = first
    (cx, cy), (dx, dy) = second
    ux, uy, vx, vy = bx - ax, by - ay, dx - cx, dy - cy
    determinant = ux * vy - uy * vx
    if abs(determinant) < 1e-8:
        return None
    t = ((cx - ax) * vy - (cy - ay) * vx) / determinant
    s = ((cx - ax) * uy - (cy - ay) * ux) / determinant
    if not (0 < t < 1 and 0 < s < 1):
        return None
    # A bridge must not touch the end icons or another edge's endpoint.
    if min(t, 1 - t) * hypot(ux, uy) < 16 or min(s, 1 - s) * hypot(vx, vy) < 16:
        return None
    return t, s


def bridge_positions(segments: list[Segment]) -> dict[int, tuple[float, ...]]:
    """Later edges jump over earlier edges; spatial bins avoid a full pair scan."""
    cells: dict[tuple[int, int], list[int]] = defaultdict(list)
    result: dict[int, tuple[float, ...]] = {}
    for index, segment in enumerate(segments):
        (ax, ay), (bx, by) = segment
        # Walk the segment rather than filling its whole bounding rectangle.
        steps = max(1, int(max(abs(bx - ax), abs(by - ay)) / 100) + 1)
        occupied: set[tuple[int, int]] = set()
        for step in range(steps + 1):
            x = int((ax + (bx - ax) * step / steps) // 100)
            y = int((ay + (by - ay) * step / steps) // 100)
            occupied.update((x + ox, y + oy) for ox in (-1, 0, 1) for oy in (-1, 0, 1))
        candidates = {previous for cell in occupied for previous in cells[cell]}
        length = hypot(bx - ax, by - ay)
        positions: list[float] = []
        for previous in sorted(candidates):
            point = crossing(segment, segments[previous])
            if point is not None:
                positions.append(point[0])
        filtered: list[float] = []
        for position in sorted(positions):
            if not filtered or (position - filtered[-1]) * length > 20:
                filtered.append(position)
        if filtered:
            result[index] = tuple(filtered)
        for cell in occupied:
            cells[cell].append(index)
    return result
