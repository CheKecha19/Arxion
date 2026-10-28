"""Canonical path selection for organization workflow leases."""

from __future__ import annotations

import errno
import json
import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


def _workspace_lock_path(database: Path) -> Path:
    """Return the same-directory lease path without creating any files.

    Parent aliases are resolved strictly, including for bootstrap when the
    database does not exist. The database entry itself must be a regular file,
    not a symlink/reparse point or hard-link alias. Windows case aliases share
    the same normalized key. Callers must keep path identities stable until
    acquisition; this helper does not acquire a lock or exclude legacy writers.
    """
    if not database.name or database.name in {".", ".."}:
        raise ValueError("Database path must name a file")
    if os.name == "nt":
        if database.drive and not database.is_absolute():
            raise ValueError("Drive-relative database paths are unsupported")
        if (
            database.is_reserved()
            or database.name.endswith((".", " "))
            or any(char in database.name for char in '<>:"/\\|?*')
            or any(ord(char) < 32 for char in database.name)
        ):
            raise ValueError("Database filename is unsafe on Windows")
    parent = database.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("Database parent must be an existing directory")
    canonical = parent / database.name
    try:
        info = canonical.lstat()
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
            or info.st_nlink != 1
        ):
            raise ValueError("Database must be a regular non-aliased file")
        canonical = canonical.resolve(strict=True)
    canonical = Path(os.path.normcase(str(canonical)))
    return canonical.with_name(canonical.name + ".org.lock")


@dataclass(frozen=True, slots=True)
class LeaseOwner:
    """Diagnostic owner metadata, never evidence that an OS lock is held."""

    pid: int
    acquired_at_utc: str
    format_version: int = 1


class WorkspaceBusyError(RuntimeError):
    """Another process currently owns the organization workflow lease."""

    def __init__(self, owner: LeaseOwner | None = None) -> None:
        super().__init__("Workspace workflow is busy")
        self.owner = owner


_MAX_OWNER_METADATA_BYTES = 512


def _read_lease_owner(descriptor: int) -> LeaseOwner | None:
    """Read bounded, untrusted diagnostic metadata after the reserved byte."""
    try:
        os.lseek(descriptor, 1, os.SEEK_SET)
        encoded = os.read(descriptor, _MAX_OWNER_METADATA_BYTES + 1)
        if len(encoded) > _MAX_OWNER_METADATA_BYTES:
            return None
        payload = json.loads(encoded.decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != {
            "pid",
            "acquired_at_utc",
            "format_version",
        }:
            return None
        pid = payload["pid"]
        timestamp = payload["acquired_at_utc"]
        version = payload["format_version"]
        if (
            type(pid) is not int
            or pid <= 0
            or type(version) is not int
            or version != 1
            or not isinstance(timestamp, str)
            or len(timestamp) > 64
        ):
            return None
        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
            return None
        return LeaseOwner(pid, parsed.astimezone(UTC).isoformat())
    except (OSError, ValueError, TypeError):
        return None


def _write_lease_owner(descriptor: int) -> LeaseOwner:
    """Write diagnostics only after acquisition, preserving reserved byte zero."""
    owner = LeaseOwner(os.getpid(), datetime.now(UTC).isoformat())
    encoded = json.dumps(
        {
            "format_version": owner.format_version,
            "pid": owner.pid,
            "acquired_at_utc": owner.acquired_at_utc,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _MAX_OWNER_METADATA_BYTES:
        raise ValueError("Workspace owner metadata exceeds its size bound")
    os.lseek(descriptor, 1, os.SEEK_SET)
    remaining = memoryview(encoded)
    while remaining:
        written = os.write(descriptor, remaining)
        if written == 0:
            raise OSError("Workspace owner metadata write made no progress")
        remaining = remaining[written:]
    os.ftruncate(descriptor, 1 + len(encoded))
    os.fsync(descriptor)
    return owner


def _check_lock_identity(path: Path, descriptor: int) -> None:
    """Reject redirected, replaced or multiply linked lock files."""
    opened = os.fstat(descriptor)
    named = path.lstat()
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or getattr(named, "st_file_attributes", 0) & 0x400
        or opened.st_nlink != 1
        or named.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise ValueError("Workspace lock file identity is unsafe or changed")


def _acquire_os_lock(descriptor: int) -> None:
    """Acquire the platform lock without waiting for another owner."""
    if sys.platform == "win32":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_os_lock(descriptor: int) -> None:
    """Release the platform lock while its owning handle remains open."""
    if sys.platform == "win32":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


class WorkspaceLease:
    """Own an acquired OS lock until explicitly closed; never unlink its file."""

    def __init__(self, path: Path, descriptor: int, owner: LeaseOwner) -> None:
        self.path = path
        self.owner = owner
        self._descriptor: int | None = descriptor

    def close(self) -> None:
        """Release and close once, also closing if explicit unlock fails."""
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        try:
            _release_os_lock(descriptor)
        finally:
            os.close(descriptor)


def acquire_workspace_lease(database: Path) -> WorkspaceLease:
    """Acquire a nonblocking workflow lease and return its owning resource.

    The database and directories are never created. A persistent lock file is
    created if absent; it must not be removed or replaced by callers. The
    returned resource must be closed. Cooperative processes share this lock;
    legacy applications and arbitrary external path mutations are not excluded.
    """
    path = _workspace_lock_path(database)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        _check_lock_identity(path, descriptor)
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
        try:
            _acquire_os_lock(descriptor)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise WorkspaceBusyError(_read_lease_owner(descriptor)) from error
            raise
        _check_lock_identity(path, descriptor)
        owner = _write_lease_owner(descriptor)
        return WorkspaceLease(path, descriptor, owner)
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def workspace_lease(database: Path) -> Iterator[WorkspaceLease]:
    """Hold a workflow lease through the body and always attempt its release.

    Cleanup failures propagate on normal exit. During exception unwinding the
    original body exception takes precedence and receives a safe cleanup note.
    """
    lease = acquire_workspace_lease(database)
    body_error: BaseException | None = None
    try:
        yield lease
    except BaseException as error:
        body_error = error
        raise
    finally:
        try:
            lease.close()
        except BaseException:
            if body_error is None:
                raise
            body_error.add_note("Workspace lease cleanup also failed")
