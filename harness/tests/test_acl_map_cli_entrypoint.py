"""Real module entrypoint acceptance for autonomous maps and existing project databases."""

import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from firewall_compliance.application.acl_map import AclMapBatch
from firewall_compliance.domain.acl_map import AclMap
from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.project_store import ProjectStore

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "aruba": (
        "; ArubaOS-Switch 16.10\nhostname SYNTHETIC-MAP\n"
        "ip access-list extended AUDIT\n"
        " 10 permit tcp any host 198.51.100.10 eq 443\n"
        " 20 deny ip any any\nexit\n"
    ),
    "comware": (
        "version 7.1.045\nsysname SYNTHETIC-MAP\nacl number 3000\n"
        " rule 10 permit tcp source any destination 198.51.100.10 0"
        " destination-port eq 443 logging\n"
        " rule 20 deny ip source any destination any\n#\n"
    ),
}


@pytest.fixture
def directory():
    path = ROOT / "artifacts" / "acl-map-entrypoint-tests" / uuid4().hex
    path.mkdir(parents=True)
    return path


def cli(*arguments):
    environment = os.environ.copy()
    environment.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    return subprocess.run(
        [sys.executable, "-m", "firewall_compliance", "acl-map", *map(str, arguments)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )


def source_file(directory, platform="comware"):
    path = directory / ("синтетический-" + platform + ".cfg")
    path.write_text(SOURCES[platform], encoding="utf-8")
    return path


def built_map(directory, platform="comware"):
    source = source_file(directory, platform)
    output = directory / (platform + "-map.json")
    process = cli("build", source, "--output", output)
    assert process.returncode == 0, process.stderr.decode("utf-8")
    return source, output, AclMap.model_validate_json(output.read_text(encoding="utf-8"))


def test_main_entrypoint_registers_all_map_commands():
    process = cli("--help")
    assert process.returncode == 0
    assert {"build", "export", "batch", "save", "list", "load"} <= set(
        process.stdout.decode("utf-8").split()
    )


@pytest.mark.parametrize("platform", ["aruba", "comware"])
def test_build_captures_supported_vendor_rules_with_original_evidence(directory, platform):
    source, _, graph = built_map(directory, platform)
    assert len(graph.relations) == 2
    assert graph.mode == "declared_rules"
    assert (
        graph.revision.parse_result.configuration.content_sha256
        == sha256(source.read_bytes()).hexdigest()
    )
    assert graph.revision.sources[0].source_name == source.name
    assert [relation.rule.action.value for relation in graph.relations] == ["allow", "deny"]
    assert all(relation.rule.source_location.line_start for relation in graph.relations)
    assert graph.limitations


@pytest.mark.parametrize("format_name", ["json", "dot", "html"])
def test_saved_map_exports_after_original_source_path_becomes_unavailable(directory, format_name):
    source, saved, graph = built_map(directory)
    source.rename(directory / "original-source-no-longer-at-captured-path.cfg")
    original = saved.read_bytes()
    output = directory / ("экспорт." + format_name)

    process = cli("export", saved, "--output", output, "--format", format_name)

    assert process.returncode == 0, process.stderr.decode("utf-8")
    assert saved.read_bytes() == original and not source.exists()
    document = output.read_text(encoding="utf-8")
    if format_name == "json":
        assert AclMap.model_validate_json(document) == graph
    elif format_name == "dot":
        assert "digraph acl_map" in document and "not reachability" in document
        assert str(graph.revision.revision_id) in document
    else:
        assert "Показано правил: 2 из 2" in document
        assert graph.revision.sources[0].content_sha256 in document
        assert all(limitation in document for limitation in graph.limitations)


def test_batch_retains_both_vendor_maps_and_explicit_failed_input(directory):
    first = source_file(directory, "aruba")
    second = source_file(directory, "comware")
    invalid = directory / "unsupported.cfg"
    invalid.write_text("SYNTHETIC-UNSUPPORTED-PAYLOAD\n", encoding="utf-8")
    output = directory / "batch.json"

    process = cli("batch", first, second, invalid, "--output", output)

    assert process.returncode == 2
    batch = AclMapBatch.model_validate_json(output.read_text(encoding="utf-8"))
    assert len(batch.items) == 2 and len(batch.failures) == 1
    assert len({item.graph.revision.revision_id for item in batch.items}) == 2
    assert all(len(item.graph.relations) == 2 for item in batch.items)
    assert batch.failures[0].code == "PARSE_FAILURE"
    assert batch.failures[0].source_name == invalid.name
    assert batch.failures[0].content_sha256 == sha256(invalid.read_bytes()).hexdigest()
    assert batch.failures[0].diagnostics
    assert b"SYNTHETIC-UNSUPPORTED-PAYLOAD" not in process.stderr + output.read_bytes()


def test_project_database_roundtrip_survives_process_restarts_without_mutating_reads(directory):
    source, saved, graph = built_map(directory)
    store = ProjectStore(directory / "projects.sqlite3")
    project = store.create_project("Synthetic map project")
    other = store.create_project("Unrelated project")
    saved_bytes = saved.read_bytes()
    process = cli("save", saved, "--database", store.path, "--project", project)
    assert process.returncode == 0, process.stderr.decode("utf-8")
    identifier = process.stdout.decode("utf-8").strip()
    assert str(UUID(identifier)) == identifier
    assert ProjectStore(store.path).get_acl_map(project, identifier) == graph
    source.rename(directory / "unavailable-original.cfg")
    database_digest = sha256(store.path.read_bytes()).hexdigest()

    listed = cli("list", store.path, "--project", project)
    other_list = cli("list", store.path, "--project", other)
    loaded = directory / "reopened-map.json"
    restored = cli("load", store.path, "--project", project, "--map-id", identifier, "-o", loaded)

    assert listed.returncode == other_list.returncode == restored.returncode == 0
    records = json.loads(listed.stdout)
    assert len(records) == 1 and records[0]["map_id"] == identifier
    assert records[0]["project_id"] == project
    assert records[0]["revision_id"] == str(graph.revision.revision_id)
    assert records[0]["rule_count"] == 2
    assert json.loads(other_list.stdout) == []
    assert AclMap.model_validate_json(loaded.read_text(encoding="utf-8")) == graph
    assert sha256(store.path.read_bytes()).hexdigest() == database_digest
    assert saved.read_bytes() == saved_bytes
    assert not source.exists()


def test_save_with_run_and_item_requires_exact_captured_revision(directory):
    source = source_file(directory)
    session = analyze_file(source)
    assert isinstance(session, AnalysisSession)
    store = ProjectStore(directory / "projects.sqlite3")
    project = store.create_project("Synthetic exact revision")
    run = store.create_run(project)
    item = store.record_session(run, session)
    store.finish_run(run)
    revision = directory / "revision.json"
    revision.write_text(session.revision.model_dump_json(), encoding="utf-8-sig")
    saved = directory / "exact-map.json"
    built = cli("build", revision, "--revision-json", "-o", saved)
    assert built.returncode == 0, built.stderr.decode("utf-8")
    persisted = cli(
        "save", saved, "--database", store.path, "--project", project, "--run", run, "--item", item
    )
    assert persisted.returncode == 0, persisted.stderr.decode("utf-8")
    graph = AclMap.model_validate_json(saved.read_text(encoding="utf-8"))
    assert graph.revision == session.revision
    identifier = persisted.stdout.decode("utf-8").strip()
    assert store.get_acl_map(project, identifier) == graph
    assert store.list_acl_maps(project)[0]["item_id"] == item

    independently_parsed = directory / "independent-map.json"
    assert cli("build", source, "-o", independently_parsed).returncode == 0
    rejected = cli(
        "save",
        independently_parsed,
        "--database",
        store.path,
        "--project",
        project,
        "--run",
        run,
        "--item",
        item,
    )
    assert rejected.returncode == 2
    assert len(store.list_acl_maps(project)) == 1


def test_wrong_project_load_preserves_existing_artifact_and_database(directory):
    _, saved, _ = built_map(directory)
    store = ProjectStore(directory / "projects.sqlite3")
    project, other = store.create_project("First"), store.create_project("Second")
    persisted = cli("save", saved, "--database", store.path, "--project", project)
    assert persisted.returncode == 0
    output = directory / "existing.json"
    output.write_text("Previous valid artifact", encoding="utf-8")
    digest = sha256(store.path.read_bytes()).hexdigest()

    rejected = cli(
        "load",
        store.path,
        "--project",
        other,
        "--map-id",
        persisted.stdout.decode("utf-8").strip(),
        "-o",
        output,
    )

    assert rejected.returncode == 2
    assert output.read_text(encoding="utf-8") == "Previous valid artifact"
    assert sha256(store.path.read_bytes()).hexdigest() == digest
    assert b"Traceback" not in rejected.stderr


@pytest.mark.parametrize("command", ["build", "batch", "export"])
@pytest.mark.parametrize("alias", [False, True])
def test_map_outputs_cannot_overwrite_input_or_hardlink(directory, command, alias):
    source, saved, _ = built_map(directory)
    path = saved if command == "export" else source
    original = path.read_bytes()
    output = path
    if alias:
        output = directory / "output-alias"
        os.link(path, output)

    process = cli(command, path, "--output", output)

    assert process.returncode == 2
    assert path.read_bytes() == original and output.read_bytes() == original
    assert b"Traceback" not in process.stderr


def test_html_network_filters_work_through_main_entrypoint(directory):
    _, saved, _ = built_map(directory)
    output = directory / "filtered.html"
    process = cli(
        "export",
        saved,
        "--output",
        output,
        "--protocol",
        "udp",
        "--port",
        53,
        "--destination",
        "203.0.113.10/32",
    )
    assert process.returncode == 0, process.stderr.decode("utf-8")
    assert "Показано правил: 1 из 2" in output.read_text(encoding="utf-8")
    invalid = cli("export", saved, "--output", output, "--format", "json", "--port", 443)
    assert invalid.returncode == 2
    assert output.read_text(encoding="utf-8").startswith("<!doctype html>")


@pytest.mark.parametrize("alias", [False, True])
def test_load_cannot_overwrite_its_database_or_hardlink(directory, alias):
    _, _, graph = built_map(directory)
    store = ProjectStore(directory / "projects.sqlite3")
    project = store.create_project("Database output protection")
    identifier = store.save_acl_map(project, graph)
    output = store.path
    if alias:
        output = directory / "database-output-alias.sqlite3"
        os.link(store.path, output)
    original = store.path.read_bytes()

    process = cli("load", store.path, "--project", project, "--map-id", identifier, "-o", output)

    assert process.returncode == 2
    assert store.path.read_bytes() == output.read_bytes() == original
    assert b"Traceback" not in process.stderr


@pytest.mark.parametrize("alias", [False, True])
def test_save_cannot_open_its_map_input_as_database_or_hardlink(directory, alias):
    _, saved, _ = built_map(directory)
    database = saved
    if alias:
        database = directory / "map-input-alias.sqlite3"
        os.link(saved, database)
    original = saved.read_bytes()

    process = cli("save", saved, "--database", database, "--project", "synthetic-project")

    assert process.returncode == 2
    assert saved.read_bytes() == database.read_bytes() == original
    assert b"Traceback" not in process.stderr
