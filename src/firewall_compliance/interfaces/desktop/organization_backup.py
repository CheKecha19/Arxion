"""Private path preconditions for organization backup preparation."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import ExitStack, closing
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from firewall_compliance.interfaces.desktop.organization_inspection import inspect_workspace
from firewall_compliance.interfaces.desktop.organization_models import WorkspaceInspection


@dataclass(frozen=True, slots=True)
class WorkspaceBackup:
    """Published backup file metadata."""

    path: Path
    sha256: str
    size_bytes: int


def _validate_backup_destination(source: Path, destination: Path) -> None:
    """Reject a destination that aliases the source without changing either path.

    This checks current filesystem identity only; callers must preserve that
    identity throughout any later backup operation.
    """
    if source.resolve() == destination.resolve():
        raise ValueError("Backup destination must differ from the source database")
    if source.exists() and destination.exists() and source.samefile(destination):
        raise ValueError("Backup destination must differ from the source database")


def _open_backup_source(source: Path) -> sqlite3.Connection:
    """Open a read-only backup source; the caller owns closing the connection."""
    connection = sqlite3.connect(
        source.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.1, isolation_level=None
    )
    try:
        connection.execute("PRAGMA query_only=ON")
    except BaseException:
        connection.close()
        raise
    return connection


def _copy_backup_snapshot(source: Path, candidate: Path) -> None:
    """Copy into a new unpublished candidate owned by the caller.

    Failures retain any partial candidate; the caller owns its cleanup.
    """
    _validate_backup_destination(source, candidate)
    with ExitStack() as stack:
        source_connection = stack.enter_context(closing(_open_backup_source(source)))
        with candidate.open("xb"):
            pass
        target_connection = stack.enter_context(closing(sqlite3.connect(candidate)))
        source_connection.backup(target_connection)


def _backup_candidate_path(destination: Path) -> Path:
    """Return an unreserved hidden candidate path beside the destination."""
    return destination.parent.resolve() / f".{destination.name}.{uuid4().hex}.candidate"


def _verify_sqlite_integrity(candidate: Path) -> None:
    """Check physical SQLite integrity only, without domain or version validation."""
    with closing(_open_backup_source(candidate)) as connection:
        rows = connection.execute("PRAGMA integrity_check").fetchall()
    if rows != [("ok",)]:
        details = repr(rows)[:300]
        raise ValueError(f"Backup candidate SQLite integrity check failed: {details}")


def _backup_sha256(candidate: Path) -> str:
    """Return the candidate's SHA-256 digest using bounded binary reads."""
    digest = hashlib.sha256()
    with candidate.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_backup_candidate(candidate: Path) -> WorkspaceInspection:
    """Require physical integrity and a supported typed-readable v1 snapshot."""
    _verify_sqlite_integrity(candidate)
    inspection = inspect_workspace(candidate)
    if inspection.schema_version != 1 or inspection.phase != "legacy":
        issue_codes = ", ".join(issue.code for issue in inspection.issues)
        raise ValueError(
            f"Backup candidate is not supported: version={inspection.schema_version}, "
            f"phase={inspection.phase}, issues={issue_codes}"
        )
    return inspection


def _finalize_backup_candidate(candidate: Path) -> None:
    """Make only an owned unpublished candidate a standalone SQLite main file."""
    with closing(
        sqlite3.connect(candidate.resolve().as_uri() + "?mode=rw", uri=True)
    ) as connection:
        row = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
        if row != ("delete",):
            raise ValueError(f"Backup candidate journal mode is not DELETE: {row!r}")


def create_workspace_backup(source: Path, destination: Path) -> WorkspaceBackup:
    """Create a validated backup and return its published file metadata.

    The caller must hold the workflow lease and preserve path identities.
    Validation currently supports only v1 legacy stores; guarded v2 support
    awaits read-only inspector version dispatch. The destination is atomically
    replaced only after candidate validation and file synchronization.
    ValueError, SQLite and filesystem errors propagate; failures before
    publication retain the candidate and leave the existing destination intact.
    """
    source = source.resolve()
    destination = destination.resolve()
    _validate_backup_destination(source, destination)
    candidate = _backup_candidate_path(destination)
    _copy_backup_snapshot(source, candidate)
    _finalize_backup_candidate(candidate)
    _validate_backup_candidate(candidate)
    digest = _backup_sha256(candidate)
    size_bytes = candidate.stat().st_size
    with candidate.open("rb") as stream:
        os.fsync(stream.fileno())
    os.replace(candidate, destination)
    return WorkspaceBackup(path=destination, sha256=digest, size_bytes=size_bytes)
