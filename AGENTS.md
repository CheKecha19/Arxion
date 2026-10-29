# Engineering Harness

Windows distribution builds must follow `specifications/WINDOWS_DISTRIBUTION.md`:
build the entire project into `dist/FirewallComplience_v<project.version>`;
overwrite the same version, do not create ZIP archives or separate CLI/feature
distributions. Use `scripts/build_desktop.ps1` as the single build implementation.

Start with `GOALS.md`, `PLANS.md`, `harness/context` and `harness/project-map.md`.
Work in the existing checkout; cloud tasks are already isolated.
Do not create worktrees unless asked.
Use `.agents/skills/` for task-specific procedures. Preserve the specialist
instructions below.

Before editing, inspect Git status and relevant contracts. For substantial work,
record a scoped plan in PLANS.md and update it with evidence as work proceeds.
Run `python harness/build impact <prospective-paths>` before substantial edits;
review downstream callers, JSON/schema and SQLite compatibility, Qt wiring and
candidate tests. Use `python harness/build context` for the current import map.
Static impact is incomplete; inspect runtime consumers and run the full gate.
Keep application behavior, fixtures and golden outputs unchanged in harness-only
tasks. Never refresh goldens merely to make a test pass. Use synthetic data only.
Do not commit, push, delete files, publish, or access live cloud accounts unless
the user authorizes that action. Never log credentials or customer configurations.

Install: `python harness/build setup`. Required checks: `python harness/build all`.
Separate commands: `architecture`, `quality`, `test`, `smoke`, `package`, `security`.
Each invocation writes a unique report under ignored `artifacts/harness/` and
returns nonzero if any required command fails. Inspect the report and actual test
counts; an unrun, skipped or zero-test suite is not a passing validation.
Record baseline failures without fixing application code outside the task scope.
Linux offscreen results do not validate a native Windows release.
Update `harness/build-log.md` with the baseline SHA, commands, results and limits.

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
