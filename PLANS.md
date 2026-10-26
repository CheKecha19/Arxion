# Working plans

For a substantial task record: objective, baseline SHA/status, allowed paths,
constraints, ordered steps, verification commands, risks and completion evidence.
Keep plans current. Failed checks remain open until diagnosed; do not change
assertions or disable checks to close a plan.

## Harness foundation

Baseline: `c97c8a06205c6259a7893c67a2494f0dced2e058`, clean working tree after
fast-forward from the original initial commit. User approved implementation.

Allowed changes: AGENTS.md, GOALS.md, PLANS.md, harness/**, .agents/skills/**,
the .gitignore exception necessary to track harness/build, and .github/workflows/harness.yml.
Application code, tests, root pyproject.toml and uv.lock stay unchanged.

1. Inspect project, contracts, tests and security scope. Completed.
2. Add minimal runner, context, goals and reusable Codex skills. Completed.
3. Lock separate security/build tooling and run all gates. Completed; baseline failures recorded.
4. Add static project map, impact and architecture gates and CI draft from supplied chat. Completed.
5. Record results and review the diff. Completed; see harness/build-log.md.
   No deletion or push.

Verification: `python harness/build setup`, then `python harness/build all`.
Reports live in artifacts/harness; reviewed results live in harness/build-log.md.
Known limits: shared ChatGPT reference returned HTTP 403; the user subsequently
supplied its text, which was read and incorporated. Native Windows validation is
unavailable on this Linux machine. Application failures are reported without
modifying its code during this task. CI is prepared locally and has not run remotely.

## INFRA-001: temporarily hide the infrastructure inspector

User explicitly requested a visibility-only application change after backlog
collection. Keep the six inspector tabs and their models/handlers instantiated,
but comment out their attachment to the visible layout and hide the widget.
The infrastructure table should occupy the available width. Preserve other pages,
stored data and existing uncommitted harness/backlog work. No deletion or push.

Affected application path: src/firewall_compliance/interfaces/desktop/qt_app.py.
The corresponding _build_devices layout is shared by local c97c8a0 and the inspected
origin/main 2924860; no unrelated remote changes are merged during this UI edit.
Impact report: artifacts/harness/20261026T123145Z-97bea318/impact.json.

Verification: offscreen visibility/selection check, relevant existing Qt tests,
then required harness gates. Record baseline failures separately.

Completed in the local worktree. Offscreen check using a real saved synthetic
HP/Aruba analysis passed: one full-width table, six retained hidden tabs, selection
and navigation safe; findings inspector remains visible on its own page.
Eight relevant existing Qt tests passed. Full harness report:
artifacts/harness/20261026T123326Z-2ca36258/results.json. Qt smoke and packaging
passed; application pytest retains the baseline 1813 passed / 7 failed / 1 skipped
and exit 139. Follow-up quality report after wrapping the modified heading line:
artifacts/harness/20261026T123454Z-478df6e1/results.json; remaining failures are
the pre-existing formatting, six lint errors and twelve mypy errors.

## v0.3 release preparation

User authorized Git push and publication of v0.3 with release notes. Version set
to 0.3.0 in the package, runtime and root lock entry; dependency versions unchanged.
Local wheel/sdist built and version metadata inspected. Locked setup passed.
Full verification: artifacts/harness/20261026T131806Z-1b5c3fa6/results.json.
1804 tests passed, 16 failed, 1 skipped, process exit 139. Nine new snapshot
differences were traced to application_version only; the other seven are the
previous Linux DPAPI failures. Golden files were not overwritten.

External blocker: Git fetch and push dry-run cannot authenticate; gh release list
returns Forbidden. GH_TOKEN is reported invalid by gh. The policy snapshot lists
github.com but not api.github.com or uploads.github.com; effective API access
requires checking both credentials and network configuration, not bypassing proxy.

Prepare a local release branch/commit, but do not tag or publish the stale source
base. Once access is restored, fetch the current main, integrate these changes,
resolve final validation and build native Windows assets before a Windows release.
Initial access errors were followed by a successful real push of release/v0.3.
Fresh main 2924860 was fetched and merged without conflicts; the UI change is
retained. That main removes tests/fixtures and some smoke scripts (recoverable
from history). Post-merge full harness reports missing inputs, not a passing suite:
artifacts/harness/20261026T132600Z-16f61bb0/results.json. A separate self-contained
offscreen synthetic check passed for version, CLI, stored analysis and inspector.
Direct GitHub Releases REST access remains Forbidden. No force push was used.

## Template for the next substantial task

- Task ID / objective / acceptance criteria:
- Baseline SHA and working-tree changes to preserve:
- Allowed changes / explicit exclusions:
- Impact report and downstream callers:
- Schema, SQLite, Qt and source-evidence risks:
- Ordered implementation steps and rollback approach:
- Required tests, manual checks and expected baseline failures:
- Review findings, actual results and unresolved issues:
- Decision/context documents updated:
