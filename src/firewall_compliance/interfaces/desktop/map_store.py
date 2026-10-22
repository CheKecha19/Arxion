"""Explicit-path, no-overwrite storage for complete network-facts archives."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from uuid import uuid4

from firewall_compliance.interfaces.desktop.map_network_facts import (
    MapNetworkFacts,
    decode_map_network_facts,
    encode_map_network_facts,
)
from firewall_compliance.interfaces.desktop.organization_lock import (
    _workspace_lock_path,
    workspace_lease,
)

DEFAULT_MAP_FACTS_BUDGET = 64 * 1024 * 1024
_IO_CHUNK = 1024 * 1024


def _artifact_path(path: Path) -> Path:
    """Reuse lease path rules without creating a lock or any directory."""
    if os.path.normcase(path.name).endswith((".candidate", ".org.lock")):
        raise ValueError("Reserved temporary or lock filename is not an archive")
    lock = _workspace_lock_path(path)
    return lock.with_name(lock.name.removesuffix(".org.lock"))


def _budget(max_bytes: int) -> None:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("Archive size budget must be a positive integer")


def _regular_identity(path: Path) -> tuple[int, int, int, int, int]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or getattr(info, "st_file_attributes", 0) & 0x400
    ):
        raise ValueError("Archive must be a regular non-linked file")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def read_map_network_facts(
    source: Path,
    *,
    max_bytes: int = DEFAULT_MAP_FACTS_BUDGET,
) -> MapNetworkFacts:
    """Open an existing complete archive with bounded reads; never bootstrap.

    Temporary candidates, aliases, changed files, oversized or invalid envelopes
    raise explicit errors. Failure never becomes an empty map snapshot.
    """
    _budget(max_bytes)
    source = _artifact_path(source)
    before = _regular_identity(source)
    if before[2] > max_bytes:
        raise ValueError("Network-facts archive exceeds its size budget")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(source, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != before[:2] or opened.st_nlink != 1:
            raise ValueError("Archive identity changed while opening")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, min(_IO_CHUNK, max_bytes - size + 1)):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("Network-facts archive exceeds its size budget")
            chunks.append(chunk)
        if size != before[2] or _regular_identity(source) != before:
            raise ValueError("Archive changed while reading")
    finally:
        os.close(descriptor)
    return decode_map_network_facts(b"".join(chunks).decode("utf-8"))


def write_map_network_facts(
    destination: Path,
    record: MapNetworkFacts,
    *,
    max_bytes: int = DEFAULT_MAP_FACTS_BUDGET,
) -> Path:
    """Publish a complete new archive while holding its cooperative lease.

    Existing destinations always raise FileExistsError, including same-revision
    collisions. No original or historical JSON is overwritten. Failures retain
    exclusively owned candidates for explicit recovery; candidates are never
    accepted by the reader. On POSIX publication uses a no-clobber hard link,
    followed by removal of the temporary name. Interrupted dual-link publication
    fails the reader's alias guard until explicitly reconciled. Windows rename
    atomically fails if the destination exists. File fsync does not certify
    directory durability across sudden power loss, especially on Windows.
    """
    _budget(max_bytes)
    encoded = encode_map_network_facts(record).encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError("Network-facts archive exceeds its size budget")
    destination = _artifact_path(destination)
    with workspace_lease(destination):
        if os.path.lexists(destination):
            raise FileExistsError("Network-facts destination already exists")
        candidate = destination.with_name(f".{destination.name}.{uuid4().hex}.candidate")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(candidate, flags, 0o600)
        try:
            original = _regular_identity(candidate)
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != original[:2]:
                raise ValueError("Candidate identity changed while opening")
            remaining = memoryview(encoded)
            while remaining:
                written = os.write(descriptor, remaining[:_IO_CHUNK])
                if written == 0:
                    raise OSError("Archive write made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
            completed = _regular_identity(candidate)
            if completed[:2] != original[:2] or completed[2] != len(encoded):
                raise ValueError("Candidate identity or length changed during writing")
        finally:
            os.close(descriptor)
        if _regular_identity(candidate) != completed:
            raise ValueError("Candidate changed before publication")
        if os.name == "nt":
            os.rename(candidate, destination)
        else:
            os.link(candidate, destination, follow_symlinks=False)
            candidate.unlink()
    return destination
