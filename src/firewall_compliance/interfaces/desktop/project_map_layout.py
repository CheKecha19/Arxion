"""Стабильные слоты узлов представления; не часть сетевой модели."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ZoneLayout:
    columns: int
    slots: dict[str, int] = field(default_factory=dict)


class ProjectMapLayouts:
    MAX_VIEWS = 32

    def __init__(self) -> None:
        self.views: dict[str, dict[str, ZoneLayout]] = {}
        self.changed = False

    @classmethod
    def load(cls, value: object) -> ProjectMapLayouts:
        result = cls()
        if not isinstance(value, dict):
            return result
        for view_id, raw_zones in list(value.items())[-cls.MAX_VIEWS:]:
            if not isinstance(view_id, str) or not isinstance(raw_zones, dict):
                continue
            zones: dict[str, ZoneLayout] = {}
            for zone_id, raw in list(raw_zones.items())[:500]:
                if not isinstance(zone_id, str) or not isinstance(raw, dict):
                    continue
                columns, slots = raw.get("columns"), raw.get("slots")
                if type(columns) is not int or not 1 <= columns <= 8 or not isinstance(slots, dict):
                    continue
                accepted = {
                    key: slot for key, slot in list(slots.items())[:1000]
                    if isinstance(key, str) and type(slot) is int and 0 <= slot < 1000
                }
                if len(set(accepted.values())) != len(accepted):
                    continue
                zones[zone_id] = ZoneLayout(columns, accepted)
            result.views[view_id] = zones
        return result

    def zone(self, view_id: str, zone_id: str, keys: tuple[str, ...], columns: int) -> ZoneLayout:
        if view_id not in self.views:
            if len(self.views) >= self.MAX_VIEWS:
                self.views.pop(next(iter(self.views)))
            self.views[view_id] = {}
            self.changed = True
        zones = self.views[view_id]
        if zone_id not in zones:
            zones[zone_id] = ZoneLayout(columns)
            self.changed = True
        layout = zones[zone_id]
        # Освобождённые слоты используются новыми узлами, остальные не сдвигаются.
        active = set(keys)
        retained = {key: slot for key, slot in layout.slots.items() if key in active}
        if retained != layout.slots:
            layout.slots = retained
            self.changed = True
        occupied = set(layout.slots.values())
        candidate = 0
        for key in keys:
            if key in layout.slots:
                continue
            while candidate in occupied:
                candidate += 1
            layout.slots[key] = candidate
            occupied.add(candidate)
            self.changed = True
        return layout

    def to_json(self) -> dict[str, dict[str, object]]:
        return {
            view_id: {
                zone_id: {"columns": zone.columns, "slots": dict(zone.slots)}
                for zone_id, zone in zones.items()
            }
            for view_id, zones in self.views.items()
        }
