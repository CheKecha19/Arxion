"""Real file/ZIP provenance and console-only packaging contracts, no customer inputs."""

import hashlib
import json
import os
import zipfile
from importlib import metadata
from pathlib import Path
from uuid import uuid4

import pytest
from scripts import package_inventory as inventory

EPOCH = 1_761_523_201
COMMIT = "a" * 40


@pytest.fixture
def workspace():
    directory = Path("artifacts/cli-distribution-tests") / str(uuid4())
    directory.mkdir(parents=True)
    return directory.resolve()


@pytest.fixture
def bundle(workspace, monkeypatch):
    project = workspace / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname="synthetic-cli"\nversion="0.3.0"\n', encoding="utf-8"
    )
    (project / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    source = project / "src/firewall_compliance/__main__.py"
    source.parent.mkdir(parents=True)
    source.write_text("print('synthetic')\n", encoding="utf-8")
    root = workspace / "ArxionCLI"
    (root / "_internal").mkdir(parents=True)
    (root / "ArxionCLI.exe").write_bytes(b"MZsynthetic-not-executable")
    (root / "_internal/python312.dll").write_bytes(b"synthetic runtime bytes")
    (root / "README.txt").write_text("Synthetic console bundle\n", encoding="utf-8")
    analysis = workspace / "analysis.json"
    inventory.capture_analysis(
        [("firewall_compliance.__main__", str(source), "PYMODULE")], analysis
    )
    monkeypatch.setattr(inventory.metadata, "distributions", lambda: [])
    inventory.create_inventory(root, analysis, project, EPOCH, COMMIT)
    return root, project, analysis


def test_zip_and_inventory_repeat_exactly_despite_file_mtime_and_creation_order(bundle, workspace):
    root, project, analysis = bundle
    first = workspace / "first.zip"
    second = workspace / "second.zip"
    digest = inventory.deterministic_zip(root, first, EPOCH)
    manifest = (root / inventory.MANIFEST).read_bytes()
    sbom = (root / inventory.SBOM).read_bytes()
    for path in root.rglob("*"):
        os.utime(path, (1_000_000_000, 1_000_000_000))
    inventory.create_inventory(root, analysis, project, EPOCH, COMMIT)
    assert (root / inventory.MANIFEST).read_bytes() == manifest
    assert (root / inventory.SBOM).read_bytes() == sbom
    assert inventory.deterministic_zip(root, second, EPOCH) == digest
    assert first.read_bytes() == second.read_bytes()
    inventory.verify_archive(root, second)
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == sorted(archive.namelist())
        assert archive.testzip() is None
        assert len({entry.date_time for entry in archive.infolist()}) == 1
        assert all(entry.create_system == 3 for entry in archive.infolist())


def test_inventory_and_sbom_identify_actual_files_runtime_and_source_inputs(bundle):
    root, project, _ = bundle
    manifest = inventory.verify_inventory(root)
    sbom = json.loads((root / inventory.SBOM).read_text(encoding="utf-8"))
    files = {entry["path"]: entry for entry in manifest["files"]}
    assert inventory.MANIFEST not in files
    assert inventory.SBOM in files
    assert files["ArxionCLI.exe"]["sha256"] == inventory.sha256(root / "ArxionCLI.exe")
    assert manifest["uv_lock_sha256"] == inventory.sha256(project / "uv.lock")
    assert len(manifest["source_inputs_sha256"]) == 64
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.6"
    assert sbom["metadata"]["component"]["version"] == "0.3.0"
    runtime = next(row for row in sbom["components"] if row["bom-ref"] == "runtime:CPython")
    assert runtime["version"] == manifest["runtime"]["python"]
    native = next(row for row in sbom["components"] if row["name"] == "_internal/python312.dll")
    assert "version" not in native and "licenses" not in native
    assert native["hashes"][0]["content"] == inventory.sha256(root / native["name"])


@pytest.mark.parametrize("kind", ["modified", "missing", "unexpected", "sbom"])
def test_inventory_rejects_changed_missing_or_unlisted_files(bundle, kind):
    root, _, _ = bundle
    if kind == "modified":
        (root / "ArxionCLI.exe").write_bytes(b"different same source identity")
    elif kind == "missing":
        (root / "README.txt").rename(root.parent / "moved-readme.txt")
    elif kind == "unexpected":
        (root / "customer-secret.txt").write_text("synthetic canary", encoding="utf-8")
    else:
        (root / inventory.SBOM).write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="missing or modified|unlisted"):
        inventory.verify_inventory(root)


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "C:/file",
        "a\\b",
        "a/../b",
        "a//b",
        "CON",
        "a/AUX.txt",
        "file.",
        "file ",
        "a?b",
        "a|b",
    ],
)
def test_windows_path_and_archive_extraction_hazards_are_rejected(name):
    with pytest.raises(ValueError):
        inventory.relative_name(name)


def test_manifest_path_traversal_never_opens_external_file(bundle, workspace):
    root, _, _ = bundle
    external = workspace / "external.txt"
    external.write_text("synthetic external canary", encoding="utf-8")
    manifest = json.loads((root / inventory.MANIFEST).read_text(encoding="utf-8"))
    manifest["files"][0]["path"] = "../external.txt"
    (root / inventory.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe"):
        inventory.verify_inventory(root)
    assert external.read_text(encoding="utf-8") == "synthetic external canary"


def test_archive_tampering_and_duplicate_members_are_rejected(bundle, workspace):
    root, _, _ = bundle
    archive = workspace / "tampered.zip"
    with zipfile.ZipFile(archive, "w") as package:
        for name, path in inventory._files(root).items():
            package.writestr(root.name + "/" + name, path.read_bytes())
        package.writestr("ArxionCLI/unlisted.txt", "synthetic")
    with pytest.raises(ValueError, match="file list"):
        inventory.verify_archive(root, archive)
    assert not (workspace / "unlisted.txt").exists()


def test_zip_destination_inside_bundle_is_rejected(bundle):
    root, _, _ = bundle
    with pytest.raises(ValueError, match="outside"):
        inventory.deterministic_zip(root, root / "archive.zip", EPOCH)


def test_native_symlink_or_junction_cannot_escape_bundle(bundle, workspace):
    root, _, _ = bundle
    target = workspace / "outside"
    target.mkdir()
    (target / "canary.txt").write_text("synthetic outside file", encoding="utf-8")
    link = root / "linked"
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks and reparse points"):
        inventory.verify_inventory(root)
    with pytest.raises(ValueError, match="symlinks and reparse points"):
        inventory.plain_root(link)
    assert (target / "canary.txt").read_text(encoding="utf-8") == "synthetic outside file"


def distribution(site, name, version, files):
    info = site / f"{name}-{version}.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nLicense-Expression: MIT\n",
        encoding="utf-8",
    )
    (info / "RECORD").write_text("".join(f"{file},,\n" for file in files), encoding="utf-8")
    return metadata.PathDistribution(info)


def test_python_sbom_includes_only_distributions_with_collected_sources(workspace):
    site = workspace / "site"
    site.mkdir()
    runtime = site / "runtime_lib.py"
    runtime.write_text("# synthetic runtime\n", encoding="utf-8")
    used = distribution(site, "runtime-lib", "1.2.3", [runtime.name])
    unused = distribution(site, "unused-development-tool", "9.8.7", ["never_collected.py"])
    entries = [{"module": "runtime_lib", "source": str(runtime), "kind": "PYMODULE"}]
    components, unmapped = inventory.python_components(entries, workspace, "0.3.0", [used, unused])
    assert [row["name"] for row in components] == ["runtime-lib"]
    assert components[0]["version"] == "1.2.3" and not unmapped
    assert components[0]["licenses"] == [{"expression": "MIT"}]
    assert components[0]["properties"][0]["value"] == "runtime_lib"


def test_unknown_python_component_is_explicit_without_guessed_version(workspace):
    source = workspace / "unknown_module.py"
    source.write_text("# synthetic unknown dependency\n", encoding="utf-8")
    entries = [{"module": "unknown_module", "source": str(source), "kind": "PYMODULE"}]
    components, unmapped = inventory.python_components(entries, workspace, "0.3.0", [])
    assert not components
    assert unmapped == [
        {"module": "unknown_module", "source_name": source.name, "kind": "PYMODULE"}
    ]


def test_duplicate_distribution_ownership_is_rejected(workspace):
    site = workspace / "site"
    site.mkdir()
    source = site / "ambiguous.py"
    source.write_text("# synthetic ambiguity\n", encoding="utf-8")
    entries = [{"module": "ambiguous", "source": str(source), "kind": "PYMODULE"}]
    first = distribution(site, "owner-one", "1", [source.name])
    second = distribution(site, "owner-two", "2", [source.name])
    with pytest.raises(ValueError, match="ambiguous"):
        inventory.python_components(entries, workspace, "0.3.0", [first, second])


@pytest.mark.parametrize("module", ["PySide6.QtCore", "pytest", "hypothesis", "tkinter"])
def test_forbidden_gui_and_development_modules_cannot_enter_console_bundle(workspace, module):
    source = workspace / "synthetic.py"
    source.write_text("# synthetic module\n", encoding="utf-8")
    analysis = workspace / "analysis.json"
    inventory.capture_analysis([(module, str(source), "PYMODULE")], analysis)
    with pytest.raises(ValueError, match="forbidden GUI/development"):
        inventory.read_analysis(analysis)


def test_source_change_updates_provenance_even_when_git_commit_is_same(bundle):
    root, project, analysis = bundle
    before = inventory.verify_inventory(root)["source_inputs_sha256"]
    serial = json.loads((root / inventory.SBOM).read_text(encoding="utf-8"))["serialNumber"]
    (project / "src/firewall_compliance/__main__.py").write_text("# changed synthetic source\n")
    after = inventory.create_inventory(root, analysis, project, EPOCH, COMMIT)
    assert after["source_commit"] == COMMIT and after["source_inputs_sha256"] != before
    assert json.loads((root / inventory.SBOM).read_text(encoding="utf-8"))["serialNumber"] != serial


def test_early_epoch_is_clamped_only_for_zip_and_invalid_epochs_rejected(bundle, workspace):
    root, _, _ = bundle
    archive = workspace / "early.zip"
    inventory.deterministic_zip(root, archive, 0)
    with zipfile.ZipFile(archive) as package:
        assert all(row.date_time == (1980, 1, 1, 0, 0, 0) for row in package.infolist())
    for invalid in (-1, True, 4_354_819_200):
        with pytest.raises(ValueError):
            inventory.epoch_datetime(invalid)


def test_archive_hash_is_the_exact_produced_bytes(bundle, workspace):
    root, _, _ = bundle
    archive = workspace / "hash.zip"
    digest = inventory.deterministic_zip(root, archive, EPOCH)
    assert digest == hashlib.sha256(archive.read_bytes()).hexdigest()
