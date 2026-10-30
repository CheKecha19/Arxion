"""Render static source structure and imports without importing application code."""

from __future__ import annotations

from pathlib import Path


def label(value: str) -> str:
    """Escape labels using Mermaid numeric entities, including untrusted filenames."""
    return "".join(char if char.isalnum() or char in "._ /-" else f"#{ord(char)};" for char in value)


def graph(nodes: set[str], edges: set[tuple[str, str]], relation: str) -> str:
    ordered = sorted(nodes)
    ids = {name: f"n{index}" for index, name in enumerate(ordered)}
    lines = ["flowchart LR"]
    lines.extend(f'    {ids[name]}["{label(name)}"]' for name in ordered)
    lines.extend(
        f"    {ids[source]} -->|{relation}| {ids[target]}" for source, target in sorted(edges)
    )
    if not ordered:
        lines.append('    empty["No source modules found"]')
    return "\n".join(lines) + "\n"


def write_maps(modules: dict, output: Path, head: str, dirty: bool) -> list[str]:
    """Generate a fresh bundle in the runner's unique artifact directory."""
    output.mkdir(parents=True, exist_ok=True)
    packages = {}
    for name, info in modules.items():
        packages[name] = name if info["path"].endswith("/__init__.py") else name.rpartition(".")[0]

    package_nodes = set(packages.values())
    for package in list(package_nodes):
        parent = package.rpartition(".")[0]
        while parent:
            package_nodes.add(parent)
            parent = parent.rpartition(".")[0]
    structure = {
        (package.rpartition(".")[0], package)
        for package in package_nodes
        if package.rpartition(".")[0] in package_nodes
    }
    imports = {
        (name, dependency)
        for name, info in modules.items()
        for dependency in info["dependencies"]
        if dependency in modules and dependency != name
    }
    package_imports = {
        (packages[source], packages[target])
        for source, target in imports
        if packages[source] != packages[target]
    }
    diagrams = {
        "structure.mmd": graph(package_nodes, structure, "contains"),
        "dependencies.mmd": graph(package_nodes, package_imports, "imports"),
    }
    details = []
    for index, package in enumerate(sorted(set(packages.values()))):
        members = {name for name in modules if packages[name] == package}
        edges = {(source, target) for source, target in imports if source in members}
        nodes = members | {target for _, target in edges}
        filename = f"package-{index:03d}.mmd"
        diagrams[filename] = graph(nodes, edges, "imports")
        details.append((package, filename, members))

    lines = [
        "# Generated project maps",
        "",
        f"Commit: `{head}`. Working tree modified/untracked: `{dirty}`.",
        "Maps describe the checkout at generation time, including local edits if present.",
        "",
        "Scope: Python files under src/firewall_compliance only; tests and external libraries omitted.",
        "Structure arrows mean contains; dependency arrows mean imports (source -> dependency).",
        "Imports in functions, conditional branches and TYPE_CHECKING blocks are included.",
        "Resolution uses the inventory's longest known module prefix; re-exports are not traced.",
        "This is not a call graph or data-flow diagram. Dynamic imports, Qt signals, SQL,",
        "runtime wiring and semantic changes require manual review. Isolated nodes are retained.",
        "Each package detail shows its direct members and outgoing imports, including other packages.",
        "Large diagrams can be opened individually; Markdown embeds the same Mermaid source.",
        "",
    ]
    for title, filename in (
        ("Package structure", "structure.mmd"),
        ("Package imports", "dependencies.mmd"),
    ):
        lines.extend([f"## {title}", "", f"[Mermaid source]({filename})", "", "```mermaid"])
        lines.extend([diagrams[filename].rstrip(), "```", ""])
    lines.extend(["## Package details", ""])
    for package, filename, members in details:
        markdown = filename.replace(".mmd", ".md")
        lines.append(f"- [{package}]({markdown}) — {len(members)} modules")
        detail = [f"# {package}", "", f"Commit: `{head}`; modified/untracked: `{dirty}`.", ""]
        detail.extend(["[Index and limitations](README.md)", "", f"[Mermaid source]({filename})", ""])
        detail.extend(["```mermaid", diagrams[filename].rstrip(), "```", "", "## Source files", ""])
        detail.extend(f"- `{name}`: `{modules[name]['path']}`" for name in sorted(members))
        (output / markdown).write_text("\n".join(detail) + "\n", encoding="utf-8")
    for filename, content in diagrams.items():
        (output / filename).write_text(content, encoding="utf-8")
    (output / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return sorted(path.name for path in output.iterdir() if path.is_file())
