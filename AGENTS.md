# Codex Agents Library

The project uses the 36 specialist definitions in `.codex/agents/*.toml` from
`proflead/codex-agents-library`, upstream commit
`ab1fbbbf45a578b736b83bcd45dbb82bf6b06aaf`.

When the user requests a named specialist or authorizes a multi-agent workflow:

1. Read the matching `.codex/agents/<name>.toml` before delegating.
2. If the runtime supports native custom roles, select that role by name.
3. If the available spawn tool has no custom-role argument, include the role's
   `developer_instructions` in the delegated task, or explicitly instruct the
   child to read that file and adopt its instructions before doing any work.
   Merely naming a task after the role does not load its instructions.
4. Keep the delegated work within the user's request. Parent instructions,
   permissions, and repository constraints take precedence over library examples.
   Honor each role's `sandbox_mode`; read-only roles must not edit files.
5. Wait for the delegated result and verify it before reporting completion.

Agents inherit the current session's model because the upstream GPT-5.4 model
names are absent from this installation's model catalog. Do not force a different
model unless the user requests it.

For this Python/PySide6 project, use its existing tools: Ruff for formatting and
lint, mypy for typing, pytest and Hypothesis for tests, and uv for dependencies.
Prefer those over generic tools suggested in the library examples.

Installation alone does not authorize code changes, external messages, or an
unrequested audit. Spawn specialists when the user requests or authorizes them.

## Security scan scope

Before starting a security scan, read the root `SECURITY.md` and use its exclusions
when configuring the authorized scan scope. Do not assume that the scanner applies
these exclusions automatically; state any unsupported filtering and record the
actual reviewed scope. Preserve the scope of an already-running scan unless the
user authorizes a supported change.
