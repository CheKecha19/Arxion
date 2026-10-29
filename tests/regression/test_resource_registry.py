"""Synthetic registry contracts: persistence, provenance, lifecycle and explicit identity."""

import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.resource_registry import ResourceRegistry


@pytest.fixture
def registry():
    root = Path("artifacts/resource-registry-tests")
    root.mkdir(parents=True, exist_ok=True)
    store = ProjectStore(root / f"{uuid4()}.sqlite3")
    project = store.create_project("Synthetic registry")
    return store, project, ResourceRegistry(store.path)


def observation(**overrides):
    return {
        "identity": "device:synthetic-router",
        "name": "router-observed",
        "platform": "aruba-aos-cx",
        "resource_type": "device",
        "category": "network",
        "first_seen": "2026-01-01T10:00:00+00:00",
        "last_scan": "2026-10-01T10:00:00+00:00",
        "last_check": "2026-10-01T10:01:00+00:00",
        "source": {"kind": "device", "run_id": "synthetic-run", "item_id": "synthetic-item"},
        **overrides,
    }


def test_full_workspace_backup_preserves_registry_and_audit(registry):
    from firewall_compliance.interfaces.desktop.organization_backup import (
        _copy_backup_snapshot,
        _validate_backup_candidate,
    )

    store, project, resources = registry
    resource_id = resources.add_manual(project, {"name": "Synthetic manual", "city": "Moscow"})
    resources.archive(project, resource_id)
    destination = store.path.with_name(f"{uuid4()}.backup.sqlite3")
    # Exercise the actual SQLite snapshot and validation, independently of the
    # publication/fsync workflow (which has its own platform-specific tests).
    _copy_backup_snapshot(store.path, destination)
    assert _validate_backup_candidate(destination).phase == "legacy"
    restored = ResourceRegistry(destination)
    assert restored.list_resources(project, include_archived=True) == resources.list_resources(
        project, include_archived=True
    )
    assert restored.history(project, resource_id) == resources.history(project, resource_id)


def test_registry_does_not_take_over_legacy_schema_initialization():
    root = Path("artifacts/resource-registry-tests")
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{uuid4()}.sqlite3"
    resources = ResourceRegistry(path)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0
        assert db.execute("SELECT name FROM sqlite_master WHERE name='projects'").fetchone() is None
    store = ProjectStore(path)
    project = store.create_project("Synthetic initialization")
    resource_id = resources.add_manual(project, {"name": "Synthetic resource"})
    assert resources.list_resources(project)[0]["id"] == resource_id
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1


def test_metadata_survives_new_observation_and_reopen(registry):
    store, project, resources = registry
    row = resources.reconcile(project, [observation()])[0]
    resources.update(
        project,
        row["id"],
        {
            "label": "Core switch",
            "description": "Office distribution",
            "comments": "Synthetic note",
            "country": "RU",
            "region": "Moscow",
            "province": "Moscow",
            "city": "Moscow",
            "site": "Site A",
            "street": "Test",
            "house": "1",
            "floor": "2",
            "room": "101",
            "rack": "R1",
            "rack_position": "10–12U",
            "status": "В эксплуатации",
        },
    )
    resources.reconcile(
        project, [observation(name="new-imported-name", last_scan="2026-10-26T10:00:00Z")]
    )
    restored = ResourceRegistry(store.path).list_resources(project)[0]
    assert restored["label"] == "Core switch" and restored["name"] == "new-imported-name"
    assert restored["rack_position"] == "10–12U" and restored["status"] == "В эксплуатации"
    assert restored["observed"]["name"] == "new-imported-name"
    assert restored["metadata"]["comments"] == "Synthetic note"
    assert restored["first_seen"] == "2026-01-01T10:00:00.000000+00:00"
    assert restored["last_scan"] == "2026-10-26T10:00:00.000000+00:00"


def test_absence_and_rediscovery_preserve_archive(registry):
    _, project, resources = registry
    row = resources.reconcile(project, [observation()])[0]
    resources.reconcile(project, [])
    assert len(resources.list_resources(project)) == 1
    resources.archive(project, row["id"])
    resources.reconcile(project, [observation(last_scan="2026-10-26T10:00:00Z")])
    assert resources.list_resources(project) == []
    assert resources.list_resources(project, include_archived=True)[0]["lifecycle"] == "archived"
    resources.restore(project, row["id"])
    assert resources.list_resources(project)[0]["id"] == row["id"]
    assert [e["action"] for e in resources.history(project, row["id"])] == [
        "discover",
        "archive",
        "observe",
        "restore",
    ]


def test_unknown_dates_stay_unknown_and_manual_creation_is_explicit(registry):
    _, project, resources = registry
    discovered = resources.reconcile(
        project, [observation(first_seen=None, last_scan=None, last_check=None)]
    )[0]
    assert all(
        discovered[key] is None for key in ("first_seen", "last_scan", "last_check", "added_at")
    )
    manual_id = resources.add_manual(project, {"name": "Manual NGFW", "category": "ngfw"})
    manual = next(row for row in resources.list_resources(project) if row["id"] == manual_id)
    assert manual["added_at"] == manual["created_at"]
    assert manual["category"] == "ngfw" and manual["origin"] == "manual"
    assert all(manual[key] is None for key in ("first_seen", "last_scan", "last_check"))


def test_same_name_never_links_automatically_and_explicit_link_keeps_metadata(registry):
    store, project, resources = registry
    manual_id = resources.add_manual(
        project, {"name": "router-observed", "label": "Manual label", "comments": "Keep manual"}
    )
    discovered = next(
        row
        for row in resources.reconcile(project, [observation()])
        if row["origin"] == "discovered"
    )
    resources.update(
        project,
        discovered["id"],
        {"description": "Imported row annotation", "comments": "Other note"},
    )
    assert len(resources.list_resources(project)) == 2
    resources.link_manual(project, manual_id, discovered["id"])
    rows = resources.list_resources(project, include_archived=True)
    assert len(rows) == 1 and rows[0]["id"] == manual_id
    assert (
        rows[0]["comments"] == "Keep manual" and rows[0]["description"] == "Imported row annotation"
    )
    assert "device:synthetic-router" in rows[0]["identities"]
    resources.reconcile(
        project, [observation(name="new-hostname", last_scan="2026-10-26T10:00:00Z")]
    )
    restored = ResourceRegistry(store.path).list_resources(project)
    assert len(restored) == 1 and restored[0]["id"] == manual_id
    assert restored[0]["name"] == "router-observed"
    assert restored[0]["observed"]["name"] == "new-hostname"
    assert {event["action"] for event in resources.history(project, manual_id)} >= {
        "link",
        "linked_into",
        "edit",
        "observe",
    }
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT COUNT(*) FROM infrastructure_resources").fetchone()[0] == 2


def test_link_to_archived_manual_does_not_restore_it(registry):
    _, project, resources = registry
    manual_id = resources.add_manual(project, {"name": "Manual"})
    resources.archive(project, manual_id)
    discovered_id = next(
        row["id"]
        for row in resources.reconcile(project, [observation()])
        if row["origin"] == "discovered"
    )
    resources.link_manual(project, manual_id, discovered_id)
    assert resources.list_resources(project) == []
    resources.restore(project, manual_id)
    assert len(resources.list_resources(project)) == 1


def test_noop_reconcile_does_not_flood_audit(registry):
    _, project, resources = registry
    row = resources.reconcile(project, [observation()])[0]
    resources.reconcile(project, [observation()])
    resources.update(project, row["id"], {})
    resources.restore(project, row["id"])
    assert len(resources.history(project, row["id"])) == 1


def test_out_of_order_observations_preserve_newest_values_and_earliest_first_seen(registry):
    _, project, resources = registry
    row = resources.reconcile(
        project, [observation(name="newest", last_scan="2026-10-26T10:00:00Z")]
    )[0]
    resources.reconcile(project, [observation(name="older", first_seen="2025-01-01T10:00:00Z")])
    result = resources.list_resources(project)[0]
    assert result["id"] == row["id"] and result["name"] == "newest"
    assert result["first_seen"].startswith("2025-01-01")
    assert result["last_scan"].startswith("2026-10-26")


def test_vdc_and_region_override_can_be_reset_without_changing_observed(registry):
    _, project, resources = registry
    row = resources.reconcile(
        project,
        [observation(identity="cloud:synthetic-vm", category="cloud", vdc="VDC-A", region="ru-1")],
    )[0]
    resources.update(project, row["id"], {"vdc": "User VDC", "region": "User region"})
    resources.reconcile(
        project,
        [
            observation(
                identity="cloud:synthetic-vm",
                category="cloud",
                vdc="VDC-B",
                region="ru-2",
                last_scan="2026-10-26T10:00:00Z",
            )
        ],
    )
    assert resources.list_resources(project)[0]["vdc"] == "User VDC"
    resources.update(project, row["id"], {"vdc": None, "region": None})
    restored = resources.list_resources(project)[0]
    assert restored["vdc"] == "VDC-B" and restored["region"] == "ru-2"


def test_project_isolation_for_updates_archives_links_and_aliases(registry):
    store, project, resources = registry
    other = store.create_project("Other")
    one = resources.reconcile(project, [observation()])[0]
    two = resources.reconcile(other, [observation()])[0]
    assert one["id"] != two["id"]
    for action in (
        lambda: resources.update(other, one["id"], {"label": "forbidden"}),
        lambda: resources.archive(other, one["id"]),
        lambda: resources.restore(other, one["id"]),
        lambda: resources.history(other, one["id"]),
        lambda: resources.link_manual(other, one["id"], two["id"]),
    ):
        with pytest.raises(ValueError):
            action()
    assert resources.list_resources(project)[0]["lifecycle"] == "active"


@pytest.mark.parametrize(
    "fields",
    [
        {"identity": "new"},
        {"first_seen": "2020"},
        {"lifecycle": "archived"},
        {"name": "not manual"},
    ],
)
def test_discovered_observations_are_not_rewritten_by_metadata_edits(registry, fields):
    _, project, resources = registry
    row = resources.reconcile(project, [observation()])[0]
    with pytest.raises(ValueError):
        resources.update(project, row["id"], fields)


@pytest.mark.parametrize(
    "changes",
    [
        {"first_seen": "2026-01-01"},
        {"last_scan": "invalid"},
        {"category": "unknown-category"},
        {"identity": "manual:guess"},
        {"source": []},
        {"unexpected": "value"},
    ],
)
def test_invalid_observation_batch_is_atomic(registry, changes):
    _, project, resources = registry
    with pytest.raises(ValueError):
        resources.reconcile(
            project, [observation(), observation(**{"identity": "device:second", **changes})]
        )
    assert resources.list_resources(project) == []


def test_sql_text_is_data_and_existing_schema_and_history_are_untouched(registry):
    store, project, resources = registry
    run_id = store.create_run(project)
    store.finish_run(run_id)
    before = store.get_run(run_id)
    with sqlite3.connect(store.path) as db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
    resource_id = resources.add_manual(
        project, {"name": "x'); DROP TABLE projects; --", "category": "unclassified"}
    )
    resources.update(
        project, resource_id, {"label": "Оборудование 'quoted'", "comments": "{} []; --"}
    )
    resources.archive(project, resource_id)
    ResourceRegistry(store.path)
    assert store.get_run(run_id) == before
    assert store.get_project(project)["id"] == project
    with sqlite3.connect(store.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == version
