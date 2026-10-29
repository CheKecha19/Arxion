"""Static project inventory, reverse import impact and documented layer checks."""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "firewall_compliance"


def module_name(path: str) -> str:
    parts = Path(path).with_suffix("").parts
    if parts[0] == "src":
        parts = parts[1:]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def inventory() -> dict:
    modules = {}
    for folder in (ROOT / "src", ROOT / "tests"):
        for path in sorted(folder.rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            name = module_name(relative)
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=relative)
            package = name if path.name == "__init__.py" else name.rpartition(".")[0]
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    base = node.module or ""
                    if node.level:
                        parent = package.split(".")
                        base = ".".join(parent[: len(parent) - node.level + 1]) + (
                            "." + base if base else ""
                        )
                    imports.add(base)
                    imports.update(base + "." + alias.name for alias in node.names)
            modules[name] = {
                "path": relative,
                "imports": sorted(imports),
                "public_definitions": sorted(
                    node.name
                    for node in tree.body
                    if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                    and not node.name.startswith("_")
                ),
            }
    for info in modules.values():
        edges = set()
        for imported in info["imports"]:
            while imported and imported not in modules:
                imported = imported.rpartition(".")[0]
            if imported:
                edges.add(imported)
        info["dependencies"] = sorted(edges)
    return modules


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("context", "impact", "architecture"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--base", default="HEAD")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    modules = inventory()
    violations = []
    # Only enforce boundaries explicitly documented in ARCHITECTURE.md.
    allowed = {
        "domain": {"domain"},
        "analysis": {"analysis", "domain", "checks"},
        "parsers": {"parsers", "domain", "devices"},
        "checks": {"checks", "analysis", "domain"},
        "devices": {"devices", "parsers", "domain", "infrastructure"},
    }
    for name, info in modules.items():
        layer = name.split(".")[1] if name.startswith(PREFIX + ".") else ""
        for imported in info["imports"]:
            if imported.startswith(PREFIX + "."):
                target = imported.split(".")[1]
                if layer in allowed and target not in allowed[layer]:
                    violations.append({"path": info["path"], "import": imported})
    changed = set(args.paths)
    if args.mode == "impact":
        for command in (
            ["git", "diff", "--name-only", "-z", args.base, "--"],
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        ):
            changed.update(
                filter(None, subprocess.check_output(command, cwd=ROOT).decode().split("\0"))
            )
    affected = {module_name(p) for p in changed if p.endswith(".py")}
    while True:
        consumers = {
            n for n, info in modules.items() if affected.intersection(info["dependencies"])
        }
        updated = affected | consumers
        if updated == affected:
            break
        affected = updated
    report = {
        "mode": args.mode,
        "base": args.base,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "modules": modules,
        "layer_violations": violations,
        "changed_paths": sorted(changed),
        "affected_modules": sorted(affected),
        "candidate_tests": sorted(
            info["path"]
            for n, info in modules.items()
            if n in affected
            and info["path"].startswith("tests/")
            and Path(info["path"]).name.startswith("test_")
        ),
        "limitations": [
            "Static imports and top-level definitions only; not a full API/schema inventory.",
            "Dynamic imports, Qt signals, resources, SQL and runtime wiring require manual review.",
            "Candidate tests are a lower bound, never permission to omit the full required gate.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"{len(modules)} modules; {len(violations)} boundary violations; "
        f"{len(report['candidate_tests'])} candidate tests; {args.output}"
    )
    return int(args.mode == "architecture" and bool(violations))


if __name__ == "__main__":
    raise SystemExit(main())
