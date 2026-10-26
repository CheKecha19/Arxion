# Harness validation log

Baseline: c97c8a06205c6259a7893c67a2494f0dced2e058.
Date: 2026-10-23. Linux, CPython 3.12.14, uv 0.12.23.
User-approved harness infrastructure only. Existing application, tests, root
dependency declarations/lock and specialist agents were preserved.

## Commands and evidence

- `python harness/build setup`: passed repeatedly; locked root dependencies with
  all groups/extras and isolated harness tooling. Last setup report:
  `artifacts/harness/20261023T081011Z-2208117c/results.json`.
- `python harness/build all`: completed, exit 1, correctly preserving failed
  gates. Final full report:
  `artifacts/harness/20261023T081510Z-346570ae/results.json`.
- `python harness/build context`: passed, 205 source/test modules, import edges
  and public top-level definitions. Report:
  `artifacts/harness/20261023T081414Z-8e8d3ebf/context.json`.
- `python harness/build impact src/firewall_compliance/domain/source.py`: passed;
  76 candidate test modules after reverse-import traversal. Last report:
  `artifacts/harness/20261023T081616Z-55748d68/impact.json`.
  This final follow-up excludes helper/fixture modules from candidate tests.
- Harness-specific Ruff checks and two harness regression tests passed after
  that follow-up. Tests demonstrate relative import propagation into downstream
  tests and a failing architecture gate for a forbidden domain -> interface import.

| Gate | Result | Evidence / interpretation |
| --- | --- | --- |
| Architecture | PASS | 205 modules, no violations of enforced domain/analysis/parser boundaries |
| Git whitespace | PASS | git diff --check |
| Harness Ruff + regression tests | PASS | 2 tests passed; no harness lint/format errors |
| Project formatting | FAIL | existing qt_app.py needs formatting |
| Project lint | FAIL | 6 existing violations in map_network_facts.py, qt_acl_map.py and qt_network.py |
| Project typing | FAIL | 12 errors in 4 files; 107 source files checked |
| Application pytest | FAIL | 1821 collected: 1813 passed, 7 failed, 1 skipped; process exit 139 after summary |
| CLI | PASS | actual fixture analysis; 7 checks, 14 findings, no parse_errors |
| Qt smoke | PASS | 80 synthetic files, navigation, keyboard, history, reports, hash guard, close |
| Python packaging | PASS | sdist and wheel built from sdist with locked build/Hatchling tools, no isolation downloads |
| Bandit | FAIL / needs triage | 88 static warnings: 84 low, 4 medium; no scanner parse errors |
| Dependency audit | FAIL | 44 locked installed-platform packages audited; pytest 8.4.2 has PYSEC-2026-1845 |
| Workflow YAML | PASS locally | parsed and inspected jobs/matrix; GitHub execution unrun |
| Native Windows release | UNRUN | requires Windows GUI, DPAPI and portable EXE checks |

## Baseline failures and next work

Mypy errors are in organization_lock.py, windows_secrets.py, topology_map.py and
qt_acl_map.py. Pytest failures are all in tests/unit/test_qt_navigation.py:
credential switching, cloud scan persistence/interruption, and Advanced/Evolution
form/connection behavior. Some traces explicitly reject secret storage on Linux;
other expectations concern UI field/selection behavior. Their behavior on Windows
remains unverified. Exit 139 after the summary is an additional unresolved native
process failure; the JUnit file does not erase that exit status.

Bandit warnings are candidates, not 88 confirmed vulnerabilities. Exact source
targets and findings are in results.json and bandit.json. Python source coverage:
src/firewall_compliance/**/*.py (excluding caches) and scripts/qt_launcher.py.
Tests, installed libraries, caches and agent definitions were excluded. Bandit
does not check build_desktop.ps1, FirewallCompliance.spec or Start-Desktop.cmd;
manual review of those policy-scoped files and a full validated source security
audit remain separate work. No warning suppressions were added.

Dependency advisory: PYSEC-2026-1845 / CVE-2025-71176 / GHSA-6w46-j5rx-g56g,
reported by PyPI for pytest 8.4.2, with fixed version 9.0.3. The root manifest
currently requires pytest <9, so remediation requires a separately authorized
dependency/compatibility change. This is development-tool risk, not proof of an
exploitable application path. Audit exports the root lock including extras/dev
dependencies; environment markers select packages on the current OS. Advisory
data changes over time, even with a fixed lockfile.

## Review and limits

Added context, goals/plans, runner, graph/impact gate, isolated tools lock, four
native Codex skills in .agents/skills, harness regression tests and a local
Linux/Windows GitHub Actions workflow. The supplied chat was read and incorporated.
Its shared URL returned HTTP 403; the uploaded text supplied the missing context.
Existing architecture ADRs and roadmap remain authoritative; the compact map
links to them instead of duplicating product plans.

The runner never updates golden files, applies application fixes or deletes
artifacts. Local reports are in ignored artifacts/harness; installed environments
are ignored. There was no commit, push, PR creation or remote CI activation.
CI has no advisory bypasses and will expose these baseline failures when run.
Reviewing local YAML is not equivalent to a successful GitHub Actions run.

Final review: git diff --check passed; src/, tests/, scripts/, specifications/,
SECURITY.md, .codex/, root pyproject.toml and uv.lock match baseline c97c8a0.
The only changed existing files are AGENTS.md and the .gitignore exception that
makes the extensionless harness/build script trackable. No files were deleted.

## User-requested repeat run — 2026-10-23

Executed `python harness/build setup && python harness/build all`.
Setup passed and confirmed both locked environments are repeatable.
Setup report: `artifacts/harness/20261023T090234Z-d908cf95/results.json`.
Full report: `artifacts/harness/20261023T090234Z-65263f4e/results.json`.

Architecture, Git whitespace, both harness tests, CLI contract, Qt 80-file smoke
and wheel/sdist packaging passed. Root pytest completed 1821 cases: 1813 passed,
7 failed and 1 skipped, then exited 139. Ruff still reports 1 unformatted source
file and 6 lint errors; mypy reports 12 errors. Bandit completed with 84 low and
4 medium warnings and no scanner errors. Dependency audit checked 44 packages
and again reported PYSEC-2026-1845 for pytest 8.4.2. The full gate exited 1.

Read-only comparison confirms application sources/tests/scripts, specifications,
root dependencies, SECURITY.md and existing Codex configuration still match the
baseline. No application fixes, deletions, commits, pushes or remote CI runs were
performed. Remaining failures are the same baseline issues described above.

## INFRA-001: hide the infrastructure inspector

User explicitly authorized a temporary visibility change in application code.
Only _build_devices in qt_app.py changed: the six-tab inspector is parented to
its page, its attachment/size lines are commented out, and it is explicitly
hidden. Models, callbacks and data are retained. Other inspectors are unaffected.
The current local source baseline is c97c8a0; the inspected remote 2924860 has
the same infrastructure layout. No remote code was merged and no push was made.

Validation:

- Offscreen functional check with a real stored synthetic HP/Aruba result passed:
  selected rows refresh the hidden inspector, only the full-width table appears,
  tabs stay hidden across navigation, and the findings inspector remains visible.
- Relevant existing Qt tests: 8 passed, 26 deselected. No test assertions changed.
- Full harness: artifacts/harness/20261026T123326Z-2ca36258/results.json.
  Architecture, harness tests, CLI, Qt smoke and wheel/sdist packaging passed.
  Application tests: 1813 passed, 7 failed, 1 skipped; exit 139 after the summary,
  matching the previously diagnosed Linux/DPAPI baseline.
- Follow-up quality after correcting a long line introduced during the edit:
  artifacts/harness/20261026T123454Z-478df6e1/results.json. Remaining formatting
  differences predate this task; 6 lint errors and 12 mypy errors remain unchanged.
- Security gates were run by the required full harness; see its JSON for scanner
  results. They were not treated as passing or remediated during this UI change.

No native Windows EXE was built or run. No database migration or deletion.
