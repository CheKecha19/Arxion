"""Инфраструктурный адаптер чтения файлов в память."""

from datetime import UTC, datetime
from pathlib import Path

from firewall_compliance.parsers.contracts import SourceDocument


class FileSourceReader:
    """Читает локальный файл и создаёт SourceDocument для парсеров."""

    def read(self, path: Path) -> SourceDocument:
        """Прочитать байты файла без передачи пути в parser adapter."""
        resolved_path = path.resolve(strict=True)
        file_modified_at = datetime.fromtimestamp(resolved_path.stat().st_mtime, tz=UTC)
        content = resolved_path.read_bytes()
        return SourceDocument(
            source_name=resolved_path.name,
            content=content,
            captured_at=datetime.now(UTC),
            file_modified_at=file_modified_at,
        )
