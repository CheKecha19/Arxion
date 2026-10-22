"""Проверки моделей трассировки до исходной конфигурации."""

import pytest
from pydantic import ValidationError

from firewall_compliance.domain import SourceLocation


def test_source_location_accepts_line_range() -> None:
    """Диапазон строк является достаточной трассировкой."""
    location = SourceLocation(source_name="edge.cfg", line_start=12, line_end=14)

    assert location.line_start == 12
    assert location.line_end == 14


def test_source_location_accepts_object_path_without_lines() -> None:
    """JSON/XML-путь допустим без номеров строк."""
    location = SourceLocation(source_name="export.json", object_path="$.policies[0]")

    assert location.object_path == "$.policies[0]"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"source_name": "edge.cfg"}, "source location"),
        ({"source_name": "edge.cfg", "line_end": 4}, "line_end"),
        ({"source_name": "edge.cfg", "line_start": 5, "line_end": 4}, "line_end"),
    ],
)
def test_source_location_rejects_invalid_anchor(kwargs: dict[str, object], message: str) -> None:
    """Некорректная трассировка должна быть отклонена."""
    with pytest.raises(ValidationError, match=message):
        SourceLocation(**kwargs)
