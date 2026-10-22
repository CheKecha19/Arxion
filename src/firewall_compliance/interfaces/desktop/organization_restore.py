"""File handling primitives for workspace database restoration."""

import hashlib
import os
from pathlib import Path


def _database_file_family(database: Path) -> tuple[Path, ...]:
    """Return the database and its SQLite sidecar paths without accessing them."""
    return (
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
        database.with_name(database.name + "-journal"),
    )


def _copy_forensic_file(source: Path, destination: Path) -> tuple[int, str]:
    """Copy raw bytes exclusively, retaining any partial output on failure."""
    digest = hashlib.sha256()
    bytes_copied = 0
    with source.open("rb") as source_file, destination.open("xb") as destination_file:
        while chunk := source_file.read(1024 * 1024):
            destination_file.write(chunk)
            digest.update(chunk)
            bytes_copied += len(chunk)
        destination_file.flush()
        os.fsync(destination_file.fileno())
    return bytes_copied, digest.hexdigest()
