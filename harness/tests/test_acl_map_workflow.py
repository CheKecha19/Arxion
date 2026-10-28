"""Synthetic ACL-map filtering, storage and real CLI orchestration contracts."""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from test_policy_union_shadowing import revision, rule
from typer.testing import CliRunner

from firewall_compliance.analysis.acl_map import AclMapFilter, build_acl_map, filter_acl_relations
from firewall_compliance.application.acl_map import (
    AclMapBatch,
    AclMapBatchFailure,
    build_acl_map_batch,
    export_acl_map_html,
    export_acl_map_json,
)
from firewall_compliance.application.acl_map_store import AclMapStore
from firewall_compliance.domain.acl_map import AclMap
from firewall_compliance.domain.enums import DataStatus, EndpointKind
from firewall_compliance.domain.network import Endpoint
from firewall_compliance.interfaces.cli.acl_map_commands import app

NOW = datetime(2026, 10, 28, tzinfo=UTC)
RUNNER = CliRunner()
COMWARE = """version 7.1.045
sysname SYNTHETIC-MAP
acl number 3000
 rule 10 permit tcp source any destination 198.51.100.10 0 destination-port eq 443 logging
 rule 20 deny ip source any destination any
#
"""


@pytest.fixture
def directory():
    root = Path(__file__).resolve().parents[2]
    path = root / "artifacts" / "acl-map-tests" / uuid4().hex
    path.mkdir(parents=True)
    return path


def graph(*rules):
    return build_acl_map(revision(*(rules or (rule("allow", 10),))), built_at=NOW)


def database(path):
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript("""
        CREATE TABLE projects(id TEXT PRIMARY KEY);
        CREATE TABLE runs(id TEXT PRIMARY KEY,project_id TEXT REFERENCES projects(id));
        CREATE TABLE items(id TEXT PRIMARY KEY,run_id TEXT REFERENCES runs(id),payload TEXT);
        INSERT INTO projects VALUES ('project-a'),('project-b');
        INSERT INTO runs VALUES ('run-a','project-a'),('run-b','project-b');
    """)
    return connection


def capture(connection, value, *, item_id="item-a", run_id="run-a"):
    payload = json.dumps({"revision": value.revision.model_dump(mode="json")})
    connection.execute("INSERT INTO items VALUES (?,?,?)", (item_id, run_id, payload))
    connection.commit()


@pytest.mark.parametrize(
    "filters,selected",
    [
        ({"source_cidr": "0.0.0.1/32"}, ["allow"]),
        ({"source_cidr": "192.0.2.0/24"}, []),
        ({"destination_cidr": "0.0.0.2/31"}, ["allow"]),
        ({"destination_cidr": "2001:db8::/32"}, []),
        ({"protocol": "tcp", "destination_port": 8}, ["allow"]),
        ({"protocol": "tcp", "destination_port": 9}, []),
        ({"protocol": "udp"}, []),
        ({"enabled": False}, []),
    ],
)
def test_network_filter_uses_semantic_overlap_and_preserves_graph(filters, selected):
    value = graph()
    before = export_acl_map_json(value)
    relations = filter_acl_relations(value, AclMapFilter(**filters))
    assert [item.rule.rule_id for item in relations] == selected
    assert export_acl_map_json(value) == before


def test_unknown_is_visible_unless_explicitly_excluded_and_known_disjoint_still_excludes():
    value = graph(rule("unknown", 10, source_status=DataStatus.UNKNOWN))
    assert filter_acl_relations(value, AclMapFilter(source_cidr="192.0.2.0/24"))
    assert not filter_acl_relations(
        value, AclMapFilter(source_cidr="192.0.2.0/24", include_unknown=False)
    )
    assert not filter_acl_relations(
        value, AclMapFilter(source_cidr="192.0.2.0/24", destination_cidr="192.0.2.0/24")
    )


def test_ipv6_filter_does_not_flatten_into_ipv4():
    endpoint = Endpoint(
        endpoint_id="v6", name="v6", kind=EndpointKind.SUBNET, cidrs=("2001:db8::/64",)
    )
    value = graph(rule("v6", 10, sources=(endpoint,), destinations=(endpoint,)))
    assert filter_acl_relations(value, AclMapFilter(source_cidr="2001:db8::1"))
    assert not filter_acl_relations(value, AclMapFilter(source_cidr="0.0.0.0/0"))


@pytest.mark.parametrize(
    "filters",
    [
        {"source_cidr": "bad"},
        {"destination_port": 0},
        {"protocol": "icmp", "destination_port": 443},
    ],
)
def test_invalid_filters_fail_instead_of_becoming_any(filters):
    with pytest.raises(ValueError):
        AclMapFilter(**filters)


def test_html_includes_all_provenance_and_escapes_hostile_values():
    value = graph(rule("<script>alert(1)</script>", 10))
    rendered = export_acl_map_html(value)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert str(value.revision.revision_id) in rendered
    assert value.revision.sources[0].content_sha256 in rendered
    assert "synthetic.cfg" in rendered
    assert all(reason in rendered for reason in value.limitations)
    assert "unknown" in export_acl_map_html(value, filters=AclMapFilter(source_cidr="0.0.0.0/0"))


def test_batch_keeps_same_named_devices_separate_and_roundtrips():
    first = graph().revision
    second = first.model_copy(update={"revision_id": uuid4()})
    result = build_acl_map_batch((("one", first), ("two", second)), built_at=NOW)
    restored = AclMapBatch.model_validate_json(result.model_dump_json())
    assert len(restored.items) == 2
    assert (
        restored.items[0].graph.relations[0].relation_id
        != restored.items[1].graph.relations[0].relation_id
    )
    with pytest.raises(TypeError):
        restored.items[0].graph.revision.device.device_id = "different"


@pytest.mark.parametrize("options", [{"max_maps": 1}, {"max_rules": 1}, {"max_maps": 0}])
def test_batch_budgets_are_explicit_failures(options):
    with pytest.raises(ValueError):
        build_acl_map_batch(
            (("one", graph().revision), ("two", graph().revision)), built_at=NOW, **options
        )


def test_batch_preserves_failed_inputs_and_rejects_duplicate_reference():
    failure = AclMapBatchFailure(input_reference="bad", code="PARSE_FAILURE", message="Not parsed")
    result = build_acl_map_batch((("good", graph().revision),), built_at=NOW, failures=(failure,))
    assert result.failures == (failure,)
    with pytest.raises(ValueError):
        build_acl_map_batch((("bad", graph().revision),), built_at=NOW, failures=(failure,))


def test_store_is_additive_and_persists_exact_original_snapshot(directory):
    path = directory / "project.sqlite3"
    with database(path) as connection:
        value = graph()
        capture(connection, value)
        before = connection.execute("SELECT payload FROM items").fetchall()
        store = AclMapStore(connection)
        identifier = store.save("project-a", value, run_id="run-a", item_id="item-a")
        assert (
            store.save("project-a", value, run_id="run-a", item_id="item-a", map_id=identifier)
            == identifier
        )
        assert store.get("project-a", identifier) == value
        assert store.list("project-a")[0]["rule_count"] == 1
        assert connection.execute("SELECT payload FROM items").fetchall() == before
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    with sqlite3.connect(path) as reopened:
        assert AclMapStore(reopened).get("project-a", identifier) == value


def test_store_rejects_cross_project_run_item_and_altered_revision(directory):
    with database(directory / "db.sqlite3") as connection:
        value = graph()
        capture(connection, value)
        store = AclMapStore(connection)
        with pytest.raises(ValueError):
            store.save("project-b", value, run_id="run-a")
        with pytest.raises(ValueError):
            store.save("project-a", value, run_id="run-a", item_id="other")
        with pytest.raises(ValueError):
            store.save("project-a", graph(rule("changed", 10)), run_id="run-a")
        with pytest.raises(KeyError):
            store.save("missing", value)
        identifier = store.save("project-a", value)
        with pytest.raises(KeyError):
            store.get("project-b", identifier)
        with pytest.raises(ValueError):
            store.save("project-a", graph(rule("changed", 10)), map_id=identifier)


def test_store_immutable_triggers_and_checksum_metadata_tamper(directory):
    with database(directory / "db.sqlite3") as connection:
        store = AclMapStore(connection)
        identifier = store.save("project-a", graph())
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM acl_maps WHERE id=?", (identifier,))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE acl_maps SET rule_count=2 WHERE id=?", (identifier,))
        connection.execute("DROP TRIGGER acl_maps_immutable_update")
        connection.execute("UPDATE acl_maps SET project_id='project-b' WHERE id=?", (identifier,))
        with pytest.raises(ValueError, match="checksum"):
            store.get("project-b", identifier)


def test_savepoint_does_not_commit_unrelated_outer_transaction(directory):
    connection = database(directory / "db.sqlite3")
    try:
        store = AclMapStore(connection)
        connection.commit()
        connection.execute("BEGIN")
        connection.execute("INSERT INTO projects VALUES ('pending')")
        store.save("project-a", graph())
        connection.rollback()
        assert connection.execute("SELECT 1 FROM projects WHERE id='pending'").fetchone() is None
        assert store.list("project-a") == []
    finally:
        connection.close()


def test_cli_build_export_and_storage_without_source_reopen(directory):
    source = directory / "source.cfg"
    source.write_text(COMWARE, encoding="utf-8")
    saved = directory / "map.json"
    assert RUNNER.invoke(app, ["build", str(source), "-o", str(saved)]).exit_code == 0
    original = AclMap.model_validate_json(saved.read_text(encoding="utf-8"))
    source.unlink()
    html = directory / "map.html"
    result = RUNNER.invoke(
        app,
        [
            "export",
            str(saved),
            "-o",
            str(html),
            "--source",
            "192.0.2.0/24",
            "--protocol",
            "tcp",
            "--port",
            "443",
        ],
    )
    assert result.exit_code == 0, result.output
    assert original.revision.sources[0].content_sha256 in html.read_text(encoding="utf-8")
    path = directory / "project.sqlite3"
    database(path).close()
    result = RUNNER.invoke(
        app, ["save", str(saved), "--database", str(path), "--project", "project-a"]
    )
    assert result.exit_code == 0, result.output
    identifier = result.output.strip()
    listed = RUNNER.invoke(app, ["list", str(path), "--project", "project-a"])
    assert listed.exit_code == 0, listed.output
    assert json.loads(listed.output)[0]["map_id"] == identifier
    loaded = directory / "loaded.json"
    result = RUNNER.invoke(
        app,
        ["load", str(path), "--project", "project-a", "--map-id", identifier, "-o", str(loaded)],
    )
    assert result.exit_code == 0, result.output
    assert AclMap.model_validate_json(loaded.read_text(encoding="utf-8")) == original


def test_cli_batch_keeps_parse_failure_visible(directory):
    good, bad, output = (directory / name for name in ("good.cfg", "bad.cfg", "batch.json"))
    good.write_text(COMWARE, encoding="utf-8")
    bad.write_text("unrecognized synthetic", encoding="utf-8")
    result = RUNNER.invoke(app, ["batch", str(good), str(bad), "-o", str(output)])
    assert result.exit_code == 2
    batch = AclMapBatch.model_validate_json(output.read_text(encoding="utf-8"))
    assert len(batch.items) == 1
    assert batch.failures[0].input_reference == "2:bad.cfg"


def test_cli_blocks_hardlink_overwrite_and_filtered_json_ambiguity(directory):
    saved = directory / "map.json"
    before = export_acl_map_json(graph())
    saved.write_text(before, encoding="utf-8")
    alias = directory / "alias.json"
    alias.hardlink_to(saved)
    result = RUNNER.invoke(app, ["export", str(saved), "-o", str(alias)])
    assert result.exit_code == 2
    assert saved.read_text(encoding="utf-8") == before
    output = directory / "filtered.json"
    result = RUNNER.invoke(
        app, ["export", str(saved), "-o", str(output), "--format", "json", "--source", "0.0.0.0/0"]
    )
    assert result.exit_code == 2
    assert not output.exists()
