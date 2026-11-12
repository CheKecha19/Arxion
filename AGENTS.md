# Development priority until v1.0

Prioritize application code and requested functionality.
Do not create new tests, test cases, fixtures, smoke scripts or test-only
infrastructure unless the user explicitly requests them. Do not proactively
expand, reorganize or delete the existing test suite. Defer the comprehensive
testing and code-reorganization strategy until the user starts v1.0 preparation.
Run all automated checks through GitHub Actions by default. Do not run local
tests, lint, format checks, type checks, harness gates, smoke checks, builds or
security checks unless the user explicitly requests local execution.
Local source inspection and diff review are allowed. Report what was reviewed,
the available CI results and what remains unverified.
These rules take precedence over conflicting test/full-gate instructions in
project skills, plans and historical documents until the user changes them.

# Working procedure

For small tasks: inspect Git status and relevant files, make the requested change,
review the edited diff and report the result briefly. No mandatory planning
document, full context inventory or build-log update for small tasks.

For substantial changes affecting multiple components, architecture or persisted
contracts: read relevant sections of DOCUMENTATION.md, DEVELOPMENT.md and PROJECT_STATUS.md. Record a scoped plan and progress in PROJECT_STATUS.md.
Inspect downstream consumers, JSON/schema and SQLite compatibility, Qt wiring
and runtime imports directly. Run automated impact/context analysis in GitHub
Actions; local harness execution requires an explicit user request.
Static impact is incomplete; inspect relevant runtime consumers directly.
Impact analysis does not require a full test run.

Work in the existing checkout. Do not create worktrees unless asked.
Use relevant procedures from `.agents/skills/` within the current user scope.
Preserve existing unrelated edits and avoid unrelated fixes.
Keep application behavior unchanged in harness-only tasks.
Never refresh golden outputs merely to make a test pass.
Use synthetic data for development checks; never log credentials or customer
configurations. Do not commit, push, delete files, publish or access live cloud
accounts unless the user authorizes that action.

# Tools and validation

Follow `DEVELOPMENT.md` (Git and release policy) for future commit/PR titles,
version increments, tags and GitHub Release names. Read it before preparing
a commit or release. This naming policy does not authorize commit, push,
tag creation or publication; existing user-authorization limits still apply.

Windows distribution builds must follow `DEVELOPMENT.md` (Windows distribution):
build the entire project into `dist/FirewallComplience_v<project.version>`;
overwrite the same version, do not create ZIP archives or separate CLI/feature
distributions. Use `scripts/build_desktop.ps1` as the single build implementation.

Use the existing Python/PySide6 toolchain: uv for dependencies, Ruff for
formatting/lint and mypy for typing. Use pytest/Hypothesis only within the testing
policy above. Install locked tooling with `python harness/build setup` in CI;
local setup requires an explicit user request.
Available harness commands: context, impact, architecture, quality, test, smoke,
package, security and all. Their availability does not make them mandatory.

The workflow `.github/workflows/harness.yml` runs independent harness jobs on Windows
for pull requests, pushes to main and manual dispatches. Keep harness and test
sources versioned in this repository. After authorized publication, use CI logs
and artifacts to diagnose failures, make fixes locally and publish them only
within the user's commit/push authorization. This CI policy does not itself
authorize commits or pushes. Do not reproduce CI failures locally unless asked.

When reviewing harness checks, inspect their reports and actual results.
An unrun, skipped or zero-test suite is not a passing validation.
For substantial work, requested builds or broad validation, record the baseline
SHA, commands, results and limits in PROJECT_STATUS.md. Keep summaries concise.
Linux offscreen checks do not validate a native Windows release.

# Delegation

The user authorizes autonomous delegation when it helps complete the task.
Use specialists for suitable independent subtasks or focused investigations;
no additional user confirmation is needed. Avoid duplicate exploration and
unnecessary agents. Delegation must stay within the authorized task and the
same testing, data-access and external-action limits as the parent task.

When using a specialist from `.codex/agents/<name>.toml`:
1. Read the matching role definition before delegating.
2. Select the matching native role when available; otherwise give the child its
   developer instructions or direct it to read and adopt the role definition.
3. Honor the role sandbox; read-only roles must not edit files.
4. Assign clear file/responsibility ownership. Tell workers to preserve others'
   edits and accommodate concurrent changes.
5. Wait for the result and verify it before reporting completion.

Agents inherit the current session model unless the user requests another model.
Library examples do not authorize unrelated changes, external messages or audits.

# Security scan scope

Before an authorized security scan, read root SECURITY.md and apply its exclusions
to the actual reviewed scope. Do not assume automatic filtering. Report unsupported
filtering. Preserve an already-running scan's scope unless the user authorizes a
supported change.

# Documentation layout

Keep working Markdown consolidated: AGENTS.md/DEVELOPMENT.md/SECURITY.md for
instructions, README.md/DOCUMENTATION.md for application functionality and
PROJECT_STATUS.md for the single status, roadmap, backlog, plan and work log.
Do not create separate task/roadmap/status documents unless explicitly requested.
Historical sources live in the ignored flat root архив directory. Do not use them
as current instructions or scan their contents without a task-specific reason.

# Specifications

The root спецификации/ directory contains maintained requirements, architecture,
platform limits and data/check contracts restored from the archive. Read its
README.md and the sections relevant to a substantial change. Do not treat these
contracts as disposable historical notes. Keep them aligned with code changes;
PROJECT_STATUS.md remains the single status/roadmap/backlog. Current user and
AGENTS instructions override old test/local-execution prescriptions in specs.

Version format: MAJOR.MINOR.PATCH[.REVISION], as defined in DEVELOPMENT.md.
Document-only/service-only checkpoints increment REVISION; functional changes
increment the appropriate first three components and reset REVISION. Keep
pyproject.toml, __version__ and the project uv.lock entry consistent.

<!-- gitbook-agent-instructions:start -->

## GitBook Documentation Editing

This repository contains documentation synced with GitBook via Git Sync.

Before editing GitBook-synced Markdown, YAML, or asset files, make sure the GitBook skill is available and up to date in your local agent environment. Prefer installing or updating it with:

```bash
npx skills add gitbookio/gitbook-skills
```

This command may add or update local agent skill files. Use them only as local agent instructions; do not commit those installed skill files or any tool-generated agent configuration unless the user explicitly asks for it.

If `npx` is unavailable, load the skill from:

https://gitbook.com/docs/skill.md

When making changes, preserve GitBook sync metadata such as frontmatter, `SUMMARY.md`, `gitbook-docs.yaml`, `.gitbook/`, and asset links unless the requested edit explicitly requires changing them.

<!-- gitbook-agent-instructions:end -->
