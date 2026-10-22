"""Утилиты сравнения результатов с неизменяемыми golden-файлами."""

import json
from pathlib import Path

from pydantic import BaseModel


def assert_matches_golden(model: BaseModel, golden_path: Path) -> None:
    """Сравнить JSON-представление модели с заранее сохранённым эталоном."""
    expected = json.loads(golden_path.read_text(encoding="utf-8"))
    actual = model.model_dump(mode="json")

    assert actual == expected
