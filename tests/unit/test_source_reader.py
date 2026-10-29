"""Проверки инфраструктурного адаптера чтения исходных файлов."""

import os
from datetime import UTC, datetime
from pathlib import Path

from firewall_compliance.infrastructure import FileSourceReader


def test_file_source_reader_returns_content_without_full_path() -> None:
    """Адаптер передаёт в parser байты и имя, а не полный путь к файлу."""
    source_file = Path(__file__).parents[1] / "fixtures" / "legacy" / "test_sample.json"

    document = FileSourceReader().read(source_file)

    assert document.source_name == "test_sample.json"
    assert document.content == source_file.read_bytes()
    assert document.observation is None
    assert document.file_modified_at is not None


def test_file_mtime_does_not_become_capture_or_observation_time(tmp_path: Path) -> None:
    source_file = tmp_path / "test.cfg"
    source_file.write_bytes(b"synthetic")
    old_time = datetime(2001, 1, 1, tzinfo=UTC)
    os.utime(source_file, (old_time.timestamp(), old_time.timestamp()))
    before = datetime.now(UTC)
    document = FileSourceReader().read(source_file)
    assert before <= document.captured_at <= datetime.now(UTC)
    assert document.file_modified_at == old_time
    assert document.observation is None
