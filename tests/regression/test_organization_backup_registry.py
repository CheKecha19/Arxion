"""Native backup publication and complete additive registry preservation."""

import hashlib
import os
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from firewall_compliance.interfaces.desktop import organization_backup
from firewall_compliance.interfaces.desktop.organization_inspection import inspect_workspace
from firewall_compliance.interfaces.desktop.organization_restore import _copy_forensic_file
from firewall_compliance.interfaces.desktop.project_store import ProjectStore

REGISTRY_TABLES = (
    "infrastructure_resources",
    "infrastructure_resource_aliases",
    "infrastructure_resource_events",
)


@pytest.fixture
def source_store():
    root = Path("artifacts/organization-backup-registry-tests")
    root.mkdir(parents=True, exist_ok=True)
    store = ProjectStore(root / f"{uuid4()}.sqlite3")
    project = store.create_project("Synthetic backup")
    resources = store.resource_registry
    manual_id = resources.add_manual(project, {"name": "Synthetic router", "city": "Moscow"})
    discovered = resources.reconcile(
        project,
        [
            {
                "identity": "device:synthetic-backup-router",
                "name": "Imported router",
                "platform": "aruba-aos-cx",
                "resource_type": "device",
                "category": "network",
                "first_seen": "2026-01-01T00:00:00Z",
                "source": {"kind": "device", "device_id": "synthetic-backup-router"},
            }
        ],
    )
    discovered_id = next(row["id"] for row in discovered if row["origin"] == "discovered")
    resources.link_manual(project, manual_id, discovered_id)
    resources.archive(project, manual_id)
    return store, project, manual_id


def registry_rows(path):
    with sqlite3.connect(path) as db:
        return {
            table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in REGISTRY_TABLES
        }


def test_public_backup_fsync_and_restore_preserve_entire_registry(source_store, monkeypatch):
    store, project, manual_id = source_store
    source_bytes = store.path.read_bytes()
    source_rows = registry_rows(store.path)
    destination = store.path.with_suffix(".backup.sqlite3")
    destination.write_bytes(b"previous destination")
    original_fsync = os.fsync
    synchronized = []

    def require_writable_descriptor(fd):
        # Zero-byte write detects the Windows requirement on Linux too, without
        # modifying the snapshot; real native fsync still executes afterwards.
        os.write(fd, b"")
        original_fsync(fd)
        synchronized.append(True)

    monkeypatch.setattr(organization_backup.os, "fsync", require_writable_descriptor)
    backup = organization_backup.create_workspace_backup(store.path, destination)
    assert synchronized == [True]
    assert backup.path == destination.resolve()
    assert backup.size_bytes == destination.stat().st_size
    assert backup.sha256 == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert store.path.read_bytes() == source_bytes
    assert registry_rows(destination) == source_rows
    assert inspect_workspace(destination).phase == "legacy"

    restored_path = store.path.with_suffix(".restored.sqlite3")
    copied_size, copied_hash = _copy_forensic_file(destination, restored_path)
    assert (copied_size, copied_hash) == (backup.size_bytes, backup.sha256)
    restored = ProjectStore(restored_path)
    assert registry_rows(restored_path) == source_rows
    assert inspect_workspace(restored_path).phase == "legacy"
    assert restored.resource_registry.list_resources(project, include_archived=True) == (
        store.resource_registry.list_resources(project, include_archived=True)
    )
    assert restored.resource_registry.history(project, manual_id) == (
        store.resource_registry.history(project, manual_id)
    )


def test_failed_fsync_keeps_source_and_existing_destination(source_store, monkeypatch):
    store, _, _ = source_store
    source_bytes = store.path.read_bytes()
    destination = store.path.with_suffix(".failed-backup.sqlite3")
    destination.write_bytes(b"previous destination")

    def failed_fsync(fd):
        raise OSError("Synthetic fsync failure")

    monkeypatch.setattr(organization_backup.os, "fsync", failed_fsync)
    with pytest.raises(OSError, match="Synthetic fsync failure"):
        organization_backup.create_workspace_backup(store.path, destination)
    assert destination.read_bytes() == b"previous destination"
    assert store.path.read_bytes() == source_bytes
    candidates = list(destination.parent.glob(f".{destination.name}.*.candidate"))
    assert len(candidates) == 1
    assert registry_rows(candidates[0]) == registry_rows(store.path)
