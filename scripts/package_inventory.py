"""Standard-library packaging evidence, strict file verification and deterministic ZIPs.

This module runs in the build environment, never in the delivered application.
Python component attribution uses actual Analysis TOC source paths and installed
distribution RECORDs, with an explicit source-tree application component.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import sysconfig
import tempfile
import tomllib
import zipfile
from collections.abc import Iterable
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import NAMESPACE_URL, uuid5

MANIFEST = "manifest.json"
SBOM = "SBOM.cdx.json"
_FORBIDDEN = {
    "pyside6",
    "shiboken6",
    "pyqt5",
    "pyqt6",
    "tkinter",
    "_tkinter",
    "pytest",
    "_pytest",
    "hypothesis",
    "mypy",
    "ruff",
    "docker",
    "pip",
    "uv",
}


def relative_name(value: object) -> str:
    """Reject ambiguous Windows paths, traversal and ZIP extraction hazards."""
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("unsafe relative filename")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {".", ".."} for part in path.parts):
        raise ValueError("unsafe relative filename")
    for part in path.parts:
        stem = part.split(".", 1)[0].upper()
        if (
            part.endswith((" ", "."))
            or any(ord(char) < 32 or char in '<>"|?*' for char in part)
            or stem
            in {
                "CON",
                "PRN",
                "AUX",
                "NUL",
                *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10)),
            }
        ):
            raise ValueError("unsafe Windows filename")
    return value


def _plain(path: Path) -> os.stat_result:
    info = path.lstat()
    if (
        path.is_symlink()
        or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError("symlinks and reparse points are not permitted")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise ValueError("only regular files and directories are permitted")
    return info


def plain_root(path: Path) -> Path:
    absolute = path.absolute()
    for parent in (*reversed(absolute.parents), absolute):
        _plain(parent)
    if not absolute.is_dir():
        raise ValueError("bundle root must be a directory")
    return absolute.resolve(strict=True)


def _files(root: Path) -> dict[str, Path]:
    root = plain_root(root)
    result: dict[str, Path] = {}
    seen: set[str] = set()

    def visit(directory: Path) -> None:
        for path in sorted(directory.iterdir(), key=lambda value: value.name):
            name = relative_name(path.relative_to(root).as_posix())
            if name.casefold() in seen:
                raise ValueError("case-insensitive filename collision")
            seen.add(name.casefold())
            info = _plain(path)
            if stat.S_ISDIR(info.st_mode):
                visit(path)
            else:
                result[name] = path

    visit(root)
    return result


def sha256(path: Path) -> str:
    _plain(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: object) -> None:
    parent = plain_root(path.parent)
    relative_name(path.name)
    if path.exists() or path.is_symlink():
        _plain(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".packaging-", dir=parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def capture_analysis(entries: Iterable[tuple[str, str, str]], output: Path) -> None:
    rows = []
    for name, source, kind in entries:
        rows.append({"module": name, "source": source, "kind": kind})
    _write_json(
        output,
        {
            "schema_version": 1,
            "entries": sorted(rows, key=lambda row: (row["module"], row["source"], row["kind"])),
        },
    )


def read_analysis(path: Path) -> list[dict[str, str]]:
    _plain(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("unsupported Analysis inventory")
    rows = value.get("entries")
    if not isinstance(rows, list):
        raise ValueError("Analysis entries must be a list")
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"module", "source", "kind"}:
            raise ValueError("malformed Analysis entry")
        if not all(isinstance(value, str) and value for value in row.values()):
            raise ValueError("malformed Analysis entry")
        if any(ord(char) < 32 for value in row.values() for char in value):
            raise ValueError("malformed Analysis entry")
        source = Path(row["source"])
        if not source.is_absolute() or not stat.S_ISREG(_plain(source).st_mode):
            raise ValueError("Analysis source must be a regular absolute file")
        if row["module"].split(".", 1)[0].casefold() in _FORBIDDEN:
            raise ValueError("forbidden GUI/development module in console bundle")
        result.append(dict(row))
    return result


def _distribution_component(distribution: metadata.Distribution) -> dict[str, Any]:
    name = distribution.metadata.get("Name")
    version = distribution.version
    if not name or not version:
        raise ValueError("bundled distribution has no name/version")
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    component: dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": version,
        "bom-ref": f"pkg:pypi/{normalized}@{version}",
        "purl": f"pkg:pypi/{normalized}@{version}",
    }
    expression = distribution.metadata.get("License-Expression")
    license_name = distribution.metadata.get("License")
    if expression:
        component["licenses"] = [{"expression": expression}]
    elif license_name and license_name.strip().upper() != "UNKNOWN":
        component["licenses"] = [{"license": {"name": license_name.strip()}}]
    return component


def python_components(
    entries: list[dict[str, str]],
    project: Path,
    version: str,
    distributions: Iterable[metadata.Distribution] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Attribute collected sources, not every package in the build environment."""
    wanted = {os.path.normcase(str(Path(row["source"]).resolve())) for row in entries}
    owners: dict[str, metadata.Distribution] = {}
    for distribution in distributions if distributions is not None else metadata.distributions():
        for file in distribution.files or ():
            source_key = os.path.normcase(str(Path(str(distribution.locate_file(file))).resolve()))
            if source_key in wanted:
                if source_key in owners and owners[source_key].metadata.get(
                    "Name"
                ) != distribution.metadata.get("Name"):
                    raise ValueError("ambiguous distribution ownership")
                owners[source_key] = distribution
    stdlib = Path(sysconfig.get_path("stdlib")).resolve()
    dlls = Path(sys.base_prefix, "DLLs").resolve()
    site_paths = {Path(sysconfig.get_path(name)).resolve() for name in ("purelib", "platlib")}
    app_root = (project / "src" / "firewall_compliance").resolve()
    components: dict[str, dict[str, Any]] = {}
    modules: dict[str, set[str]] = {}
    unmapped = []
    for row in entries:
        source = Path(row["source"]).resolve()
        owner = owners.get(os.path.normcase(str(source)))
        if source.is_relative_to(app_root):
            continue  # Source project version is authoritative for editable installs.
        if owner is not None:
            component = _distribution_component(owner)
            reference = component["bom-ref"]
            components[reference] = component
            modules.setdefault(reference, set()).add(row["module"])
        elif (
            (
                source.is_relative_to(stdlib)
                and not any(source.is_relative_to(site) for site in site_paths)
            )
            or source.is_relative_to(dlls)
            or source.parent == Path(sys.base_prefix).resolve()
        ):
            continue  # Belongs to the explicitly versioned CPython runtime.
        elif source == (project / "scripts" / "cli_launcher.py").resolve():
            continue
        elif row["kind"] in {"PYMODULE", "PYSOURCE", "EXTENSION"}:
            unmapped.append(
                {"module": row["module"], "source_name": source.name, "kind": row["kind"]}
            )
    for reference, names in modules.items():
        components[reference]["properties"] = [
            {"name": "arxion:analysis-modules", "value": "\n".join(sorted(names))}
        ]
    return sorted(components.values(), key=lambda value: value["bom-ref"]), sorted(
        unmapped, key=lambda row: row["module"]
    )


def epoch_datetime(epoch: int) -> datetime:
    if type(epoch) is not int or epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative integer")
    value = datetime.fromtimestamp(epoch, UTC)
    if value.year > 2107:
        raise ValueError("SOURCE_DATE_EPOCH exceeds ZIP date range")
    return value


def create_inventory(
    root: Path,
    analysis: Path,
    project: Path,
    epoch: int,
    commit: str,
) -> dict[str, Any]:
    root, project = plain_root(root), plain_root(project)
    date = epoch_datetime(epoch)
    if not re.fullmatch(r"[a-fA-F0-9]{40,64}", commit):
        raise ValueError("source commit must be a full Git hash")
    project_metadata = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    version = str(project_metadata["version"])
    entries = read_analysis(analysis)
    components, unmapped = python_components(entries, project, version)
    source_inputs = [
        {"module": row["module"], "kind": row["kind"], "sha256": sha256(Path(row["source"]))}
        for row in entries
    ]
    lock_hash = sha256(project / "uv.lock")
    source_fingerprint = hashlib.sha256(
        json.dumps(source_inputs, sort_keys=True).encode("utf-8")
    ).hexdigest()
    payload = _files(root)
    for name in payload:
        if Path(name).suffix.lower() in {".dll", ".pyd"} and Path(name).name.casefold().startswith(
            ("qt5", "qt6", "pyside", "shiboken", "tcl", "tk8")
        ):
            raise ValueError("GUI native library in console bundle")
    files: list[dict[str, Any]] = [
        {"path": name, "size": path.stat().st_size, "sha256": sha256(path)}
        for name, path in sorted(payload.items())
        if name not in {MANIFEST, SBOM}
    ]
    application: dict[str, Any] = {
        "type": "application",
        "name": "ArxionCLI",
        "version": version,
        "bom-ref": "application:ArxionCLI",
    }
    license_value = project_metadata.get("license")
    license_name = license_value.get("text") if isinstance(license_value, dict) else license_value
    if license_name:
        application["licenses"] = [{"license": {"name": str(license_name)}}]
    runtime = {
        "type": "application",
        "name": "CPython",
        "version": platform.python_version(),
        "bom-ref": "runtime:CPython",
        "properties": [{"name": "arxion:runtime-build", "value": sys.version}],
    }
    native = [
        {
            "type": "file",
            "name": file["path"],
            "bom-ref": "file:" + file["path"],
            "hashes": [{"alg": "SHA-256", "content": file["sha256"]}],
        }
        for file in files
        if Path(str(file["path"])).suffix.lower() in {".exe", ".dll", ".pyd", ".zip"}
    ]
    seed = json.dumps(
        [files, components, runtime, epoch, commit, source_fingerprint, lock_hash], sort_keys=True
    )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid5(NAMESPACE_URL, seed)),
        "metadata": {
            "timestamp": date.isoformat().replace("+00:00", "Z"),
            "component": application,
            "properties": [
                {"name": "arxion:source-commit", "value": commit},
                {"name": "arxion:source-inputs-sha256", "value": source_fingerprint},
                {"name": "arxion:uv-lock-sha256", "value": lock_hash},
            ],
        },
        "components": [runtime, *components, *native],
        "dependencies": [
            {
                "ref": application["bom-ref"],
                "dependsOn": [
                    runtime["bom-ref"],
                    *[component["bom-ref"] for component in components],
                ],
            }
        ],
    }
    _write_json(root / SBOM, sbom)
    files.append(
        {"path": SBOM, "size": (root / SBOM).stat().st_size, "sha256": sha256(root / SBOM)}
    )
    inventory = {
        "schema_version": 1,
        "artifact": "ArxionCLI",
        "application_version": version,
        "source_commit": commit,
        "source_inputs_sha256": source_fingerprint,
        "uv_lock_sha256": lock_hash,
        "source_date_epoch": epoch,
        "runtime": {"python": platform.python_version(), "architecture": platform.machine()},
        "build_tools": {"PyInstaller": metadata.version("pyinstaller")},
        "analysis": {"entries": len(entries), "unmapped_python_modules": unmapped},
        "files": sorted(files, key=lambda value: str(value["path"])),
    }
    _write_json(root / MANIFEST, inventory)
    verify_inventory(root)
    return inventory


def verify_inventory(root: Path) -> dict[str, Any]:
    paths = _files(root)
    if MANIFEST not in paths:
        raise ValueError("inventory is missing")
    value = json.loads(paths[MANIFEST].read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or not isinstance(value.get("files"), list)
    ):
        raise ValueError("malformed inventory")
    expected: set[str] = set()
    folded: set[str] = set()
    for entry in value["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise ValueError("malformed inventory entry")
        name = relative_name(entry["path"])
        if name == MANIFEST or name.casefold() in folded:
            raise ValueError("duplicate or self-referencing inventory entry")
        folded.add(name.casefold())
        expected.add(name)
        if (
            type(entry["size"]) is not int
            or entry["size"] < 0
            or not isinstance(entry["sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"])
        ):
            raise ValueError("malformed size/hash")
        if (
            name not in paths
            or paths[name].stat().st_size != entry["size"]
            or sha256(paths[name]) != entry["sha256"]
        ):
            raise ValueError("bundle file missing or modified: " + name)
    if set(paths) != expected | {MANIFEST}:
        raise ValueError("unlisted bundle file")
    return value


def deterministic_zip(root: Path, destination: Path, epoch: int) -> str:
    root = plain_root(root)
    parent = plain_root(destination.parent)
    destination = parent / relative_name(destination.name)
    if destination.is_relative_to(root):
        raise ValueError("archive must be outside the bundle")
    if destination.exists() or destination.is_symlink():
        _plain(destination)
    verify_inventory(root)
    date = epoch_datetime(epoch)
    if date.year < 1980:
        date = datetime(1980, 1, 1, tzinfo=UTC)
    stamp = (date.year, date.month, date.day, date.hour, date.minute, date.second // 2 * 2)
    descriptor, temporary = tempfile.mkstemp(prefix=".cli-archive-", dir=parent)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for name, path in sorted(_files(root).items()):
                info = zipfile.ZipInfo(relative_name(root.name + "/" + name), date_time=stamp)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (
                    stat.S_IFREG | (0o755 if path.suffix.lower() == ".exe" else 0o644)
                ) << 16
                archive.writestr(
                    info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
                )
        verify_archive(root, Path(temporary))
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return sha256(destination)


def verify_archive(root: Path, archive: Path) -> None:
    """Check the produced archive against the actual inventory without extraction."""
    root = plain_root(root)
    _plain(archive)
    verify_inventory(root)
    expected = {root.name + "/" + name: path for name, path in _files(root).items()}
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        if len(names) != len(set(names)) or set(names) != set(expected):
            raise ValueError("archive file list differs from bundle")
        for name, path in expected.items():
            relative_name(name)
            info = package.getinfo(name)
            if info.file_size != path.stat().st_size or not stat.S_ISREG(info.external_attr >> 16):
                raise ValueError("archive metadata differs from bundle: " + name)
            digest = hashlib.sha256()
            with package.open(info) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != sha256(path):
                raise ValueError("archive file differs from bundle: " + name)


def smoke(executable: Path, output: Path, expected_version: str) -> dict[str, Any]:
    """Run only the executable, with Python/uv absent from its search path."""
    _plain(executable)
    output.mkdir(parents=True, exist_ok=True)
    output = plain_root(output)
    source = output / "synthetic.cfg"
    if source.exists() or source.is_symlink():
        _plain(source)
    source.write_text(
        "hostname synthetic-cli\n"
        "access-list OUTSIDE extended permit tcp any any eq 443\n"
        "access-group OUTSIDE in interface outside\n",
        encoding="ascii",
    )
    environment = dict(os.environ)
    for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        environment.pop(key, None)
    system = Path(environment.get("SystemRoot", "C:/Windows"))
    environment["PATH"] = os.pathsep.join((str(system / "System32"), str(system)))
    environment["PYTHONUTF8"] = "1"
    version = subprocess.run(
        [str(executable), "version"],
        cwd=output,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=45,
        check=True,
    )
    if version.stdout.strip() != expected_version:
        raise ValueError("frozen CLI version differs from project version")
    analysis = subprocess.run(
        [str(executable), "analyze", str(source)],
        cwd=output,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=45,
        check=True,
    )
    result = json.loads(analysis.stdout)
    if (
        not isinstance(result, dict)
        or result.get("schema_version") != "1.0.0"
        or not result.get("checks")
    ):
        raise ValueError("frozen CLI did not produce a nonempty assurance report")
    if result.get("application_version") != expected_version:
        raise ValueError("frozen analysis version differs from project version")
    extended = subprocess.run(
        [str(executable), "analyze", str(source), "--extended-policy-checks"],
        cwd=output,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=45,
        check=True,
    )
    optional_result = json.loads(extended.stdout)
    optional_ids = {row["check_id"] for row in optional_result.get("checks", [])}
    if (
        not {
            "FW-PARTIAL-SHADOWED",
            "FW-UNION-SHADOWED",
            "FW-DANGEROUS-SERVICES",
            "FW-ADMIN-UNTRUSTED",
        }
        <= optional_ids
    ):
        raise ValueError("frozen optional checks are unavailable")
    _write_json(output / "analysis.json", result)
    _write_json(output / "extended-analysis.json", optional_result)
    evidence = {
        "version": version.stdout.strip(),
        "checks": len(result["checks"]),
        "extended_checks": len(optional_result["checks"]),
        "standalone_path": environment["PATH"],
        "executable_sha256": sha256(executable),
    }
    _write_json(output / "smoke.json", evidence)
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("package")
    package.add_argument("--root", type=Path, required=True)
    package.add_argument("--analysis", type=Path, required=True)
    package.add_argument("--project", type=Path, required=True)
    package.add_argument("--epoch", type=int, required=True)
    package.add_argument("--commit", required=True)
    package.add_argument("--archive", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("root", type=Path)
    native = commands.add_parser("smoke")
    native.add_argument("--executable", type=Path, required=True)
    native.add_argument("--output", type=Path, required=True)
    native.add_argument("--version", required=True)
    args = parser.parse_args()
    if args.command == "verify":
        verify_inventory(args.root)
        print("Inventory verified")
    elif args.command == "smoke":
        print(json.dumps(smoke(args.executable.resolve(), args.output, args.version)))
    else:
        create_inventory(args.root, args.analysis, args.project, args.epoch, args.commit)
        print(deterministic_zip(args.root, args.archive, args.epoch))


if __name__ == "__main__":
    main()
