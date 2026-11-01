"""Count-change diagnostics are attention signals, never proof of collection failure."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CountDropWarning:
    code: str
    before: int
    after: int
    threshold_percent: int
    before_reference: str
    unit: str

    @property
    def message(self) -> str:
        return (
            f"Резкое сокращение ({self.unit}): {self.before} → {self.after}; "
            f"порог {self.threshold_percent}%. Предыдущее основание: {self.before_reference}. "
            "Сравните снимки и полноту получения данных. Это предупреждение не доказывает ошибку "
            "сбора, удаление правил или улучшение безопасности."
        )


def count_drop_warning(
    before: int, after: int, *, threshold_percent: int = 30,
    before_reference: str, unit: str,
) -> CountDropWarning | None:
    if type(threshold_percent) is not int or not 1 <= threshold_percent <= 100:
        raise ValueError("Порог сокращения должен быть целым числом от 1 до 100")
    if type(before) is not int or type(after) is not int or min(before, after) < 0:
        raise ValueError("Для сравнения нужны известные неотрицательные счётчики")
    if not before_reference or not unit:
        raise ValueError("Укажите происхождение счётчика и единицу измерения")
    if before == 0 or after >= before or (before - after) * 100 < before * threshold_percent:
        return None
    return CountDropWarning("COLLECTION_COUNT_DROP", before, after, threshold_percent, before_reference, unit)
