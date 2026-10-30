# Harness validation log

## Requested full Windows rebuild — 2026-10-30

Baseline HEAD: 93dc8969f9c0d64c3c7194bf941ff29634d470df.
Read GIT_RELEASE_POLICY.md and WINDOWS_DISTRIBUTION.md; retained version 0.3.2
for a rebuild without a new feature release. Command: scripts/build_desktop.ps1,
exit 0, PyInstaller 6.22.3 / Python 3.12.13 / Windows 10.
Replaced dist/FirewallComplience_v0.3.2 with the full application, EXE, _internal
and README; no archive generated. Source/diff review only; no automated checks,
EXE launch or runtime validation. No CI result established for this commit.
Existing release-policy documentation changes preserved. User requested a Git
commit; no tag or GitHub Release publication performed. Binary stays local in dist.

## Requested Windows v0.3.2 build — 2026-10-30

Baseline HEAD: ab9e7dcb6c374e79d4f6f012d2c658453c55365a; existing qt_app.py
integration settings changes preserved and included in the requested build.
Updated pyproject.toml, package __version__, root uv.lock and distribution path
example to 0.3.2. Command: scripts/build_desktop.ps1; exit 0, PyInstaller 6.22.3,
Python 3.12.13, Windows 10. Full output:
dist/FirewallComplience_v0.3.2/FirewallComplience_v0.3.2.exe with _internal.
No archive generated. Build emitted the optional tzdata hidden-import warning.
Reviewed version/source diff and existing integration handlers. No tests, local
gates, smoke, EXE launch or runtime validation performed. CI result not established
for this revision. User authorized committing and pushing source after the build;
dist remains an ignored local artifact, with no GitHub release or tag requested.

## Requested Windows v0.3.1 build — 2026-10-30

Baseline HEAD: 0893237147fd00aed1bae8d54c93192863adafd1 with existing local edits.
User authorized a local application build and then requested version 0.3.1.
The already-running 0.3.0 build finished with exit 0 before version edits.
Updated pyproject.toml, package __version__ and root uv.lock to 0.3.1, then ran
powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1 again: exit 0,
PyInstaller 6.22.3 / Python 3.12.13 / Windows 10. Full application output:
dist/FirewallComplience_v0.3.1/FirewallComplience_v0.3.1.exe and _internal.
Build emitted a missing optional tzdata hidden-import warning. Source/version
diff and generated file metadata reviewed; no tests, gates, EXE launch or startup
timing performed. No ZIP, commit, push, tag or GitHub release publication.

## Desktop deferred startup — 2026-10-30

Baseline HEAD: 0893237147fd00aed1bae8d54c93192863adafd1, with existing local edits.
Source inspection: desktop entrypoint/MainWindow, jobs, SQLite history readers,
snapshot derivation, map selectors/scenes, cloud/report/registry panels and
navigation-history restoration. Commands: git status --short, git rev-parse HEAD,
rg/Get-Content source reads and git diff on scoped application/documentation files.
Independent read-only review identified and resolved creation-flow, hidden map,
cache-token and startup-error/close races. SQLite schema, stored JSON and analysis
semantics unchanged. No local automated checks, tests, profiling, EXE launch or
build performed under AGENTS.md. No tests added or edited. No CI run validates
these unpublished local edits; impact/context, CI and native Windows timing remain
pending. Existing dist/FirewallCompliance binary has not been replaced.

## Unified distribution rules — 2026-10-29

Baseline HEAD: 49e2bcae3f825e81f133245bf3ee0fecb81ee0dc with existing local edits.
Source/diff review only: build_desktop.ps1, build_cli.ps1, Qt launcher, delivery
README and specification consumers. Versioned bundle and EXE naming, same-version
overwrite, full package submodule collection, no ZIP or separate CLI/feature build.
No automated commands, build, EXE launch or CI dispatch run for this change.
The preceding successful build predates these script changes and does not validate them.

## CHECKS-003 / CHECKS-005 — 2026-10-29

Baseline HEAD `da964e8`; preserved the untracked Aruba controller and policy
revision-diff work. Added explicit, opt-in `FW-EXCESSIVE-ACCESS` and
`FW-ACL-ATTACHMENT` checks. The former evaluates configured address/port breadth
and role source/service requirements; the latter evaluates unbound policy IDs and
required role/interface-direction attachments only when inventory completeness is
explicitly true. Unknown, incomplete parse and bounded-work outcomes remain
partial. Profiles, exceptions, exact sources and fingerprints are replayable.

Impact/context: `20261028T163157Z-2b3b16a9` and
`20261028T163157Z-63ac194c`. Focused plus analysis-result/adapter/cloud/extended
regressions:109 passed. Final focused policy/UI contract:11 passed. Strict mypy
on12 changed source modules and scoped Ruff passed.

Required full gate: `artifacts/harness/20261029T050155Z-38dcdd93/results.json`.
Architecture, diff check, lint, full source mypy,830 harness tests, legacy CLI
7-check/14-finding contract, Qt smoke, wheel/sdist and dependency audit passed.
Historical tests:1812 passed and the same nine application-version golden
differences failed; goldens were not changed. Format failed only on the existing
quote style in `harness/tests/test_cloud_xml_parser.py`. Bandit completed with
115 LOW /3 MEDIUM /0 HIGH; the MEDIUM findings are the existing dynamic SQL table
name and two wildcard-address parser reports. Dependency audit found no known
vulnerabilities. Overall gate therefore remains nonzero.

At the user's explicit delivery request, ran only
`scripts/build_desktop.ps1` after the final source changes. PyInstaller6.22.3 on
Python3.12.13/Windows10 completed with exit0 and replaced the main portable
artifacts. EXE:8492149 bytes, SHA256
`139666814BA4C6141E305A99D81573AC35FCA2E9B95D520D5D45143C737A631A`.
ZIP:57971731 bytes, SHA256
`09A6C439A07C73C0DA2009252FC2478132FE323C8DC055D089F15ED3C58567DC`.
Only file metadata and hashes were inspected. Per user instruction, no additional
tests, EXE launch, self-test or archive execution was performed. Visible native
GUI, clean OS and live device/cloud validation remain outstanding.

## Post-build continuation, 2026-10-28

Delivered EXE remains untested as requested; subsequent source work is separate.
Cloud XML now uses locked defusedxml with DTD/entity/external denial independent
of encoding.21 synthetic UTF8/UTF16/malformed-input tests passed, strict mypy and
Ruff passed. No live Cloud Director requests. Impact160710Z-bef067a3.

PolicyAttachment domain and omitted-when-empty ParseResult.policy_attachments
preserve declared role/ACL association with exact source-map identity. No
effective direction/order inferred. Source types/lint pass; seven attachment
tests plus five common-result version tests pass (12 total). Impact
160950Z-964b0f89. Controller parser owner will populate the new field.

Governance MainWindow integration:18 owned tests exit0; combined64 assertions
across governance/controls/common-results/registry passed, but native subprocess
returned3221226505 (0xC0000409) at teardown. Combined validation is FAILED,
not64 passing tests. Runtime minimization and read-only lifetime review ongoing;
no test disabled or assertion weakened. Current binary was not launched.

## Requested EXE without checks, 2026-10-28

User explicitly requested a fresh EXE without checks, then continued backlog work.
Ran only scripts/build_desktop.ps1 for this build: PyInstaller6.22.3/Python3.12.13,
Windows10, exit0. Primary dist/FirewallCompliance/FirewallCompliance.exe and
dist/FirewallCompliance-windows-x64.zip replaced by the build script. Version
remains0.3.0, interim snapshot; no Git push or final release performed.
No tests, frozen self-test, runtime launch, archive test or hash verification run
for this artifact. Earlier test evidence must not be treated as its acceptance.

After delivering that EXE, root resumed backlog and wired GovernancePanel into
Reports as 'Метаданные правил', with project lifecycle, cached-result refresh
and shutdown. This subsequent source change is NOT inside the just-built EXE.
Verification of that MainWindow integration is pending; panel's preceding
standalone tests predate the new build and dependency upgrade.

Dependency lock/env: pytest9.0.3, setuptools84.1.0, defusedxml0.7.1 and stubs
installed before build. Subsequent locked security audit has not run. Cloud XML
code has not yet been migrated to defusedxml. Old XML finding remains unresolved.
The previously started pytest compatibility session54943 is no longer present;
root did not restart it after the user's no-checks request.

## Backlog continuation, 2026-10-28

Baseline HEAD ba991ab; existing worktree edits preserved. Intermediate EXE from
27 October remains the published local checkpoint below; subsequent source
changes are not claimed to be inside that EXE. No push/release performed.

- Required `harness/build all`: first sandbox attempt
  20261028T031751Z-b01d9d03 could not access the existing uv cache outside the
  workspace; those commands were unrun, not passing. Approved native rerun:
  artifacts/harness/20261028T042510Z-e1ba2c99/results.json. Architecture,
  diff/format/lint/types, 471 harness tests, CLI and JSON contract, Qt smoke and
  wheel/sdist passed. Historical suite: 1812 passed, nine failed on previously
  diagnosed application-version goldens. No goldens changed. Bandit and locked
  audit failed: four MEDIUM source findings (XML parser, static SQL table-name
  interpolation, two parsed wildcard address literals); two dependency advisories
  (pytest8.4.2 and setuptools84.0.0). Full gate remains NOT green. Source work
  continued while this checkpoint ran, so this is not final-tree validation.
- Common AnalysisResult accepted on 96 model/adapter/store/Qt tests and 30
  workflow/real CLI tests. Hardlink output aliases were found and fixed, covering
  configuration and selected profiles. The shared result now preserves actual
  forwarding parser and flow-derived binding while rejecting unrelated changes.
- ACL-map backend: 26 new +123 historical tests; real CLI entrypoint: 21 tests;
  Qt filters/HTML/PNG: 15 new and 131 related tests. Source snapshot retained,
  no source reread, unknown visible, bounded PNG, exact project/run/item isolation.
  Full project batch/persistence integration is still in progress; task not closed.
- Exposure and order evidence now versioned1.0/1.1. Saved versions replay
  separately; JSON canonical comparison avoids rejecting tuple/list forms of
  administrative evidence. Combined versions/core/adapter/workflow: 103 passed.
  Check-level versioning preserves existing catalogue membership and finding IDs.

Security scope stays as root SECURITY.md: own application Python and launcher,
no tests/caches/installed library scan; dependency audit separately uses uv.lock.
No clean OS/visible GUI acceptance or v0.4 completion claimed.

## Current backlog EXE checkpoint, 2026-10-27

User explicitly requested building the current EXE before continuing backlog work.
Baseline HEAD ba991ab with the in-progress source changes preserved. Captured
135 application/launcher/data inputs before PyInstaller and verified their hashes
unchanged before EXE execution. No live cloud or customer configuration accessed.

- Full required gate: artifacts/harness/20261027T162645Z-48374de9/results.json.
  Architecture, diff-check, format/lint, strict mypy, 367 harness tests and Python
  packaging passed. Historical application suite: 1812 passed / nine failed;
  the nine historical golden application-version differences remain explicit.
  CLI contract failed on Windows output encoding; old Qt smoke still expects
  the former 14-findings scenario despite the additional selected checks. Both
  gate issues are assigned for diagnosis, not skipped. Overall gate is NOT green.
  Bandit: 113 LOW / four MEDIUM. Dependency audit: pytest8.4.2 PYSEC-2026-1845,
  setuptools84.0.0 GHSA-xmj3-9gf7-h52w. No dependency remediation in this checkpoint.
- Source self-contained smoke passed with 23 selected checks and shared result
  persistence, JSON/CSV/HTML exports, registry, dashboard, cloud and DPAPI scenarios.
- New frozen Windows10 EXE passed --self-test with the same scenarios:
  build/verification/current-backlog-exe-smoke-20261027/smoke-result.json.
- Main dist/FirewallCompliance updated; no extra stale files compared with staging.
  Main ZIP integrity and embedded EXE match verified. EXE SHA256:
  61cb57047c90394f0f2ba5c05315f0f87884dc7790609e9d85d810ade7954b0f.
  ZIP SHA256: 14605d0aeaa3205f9bd2b2dc469c86394d393284d5a201fa827dd278f3946f06.
  Evidence: build/verification/current-backlog-artifacts-20261027.json.
  Native visible GUI/clean Windows11 testing not performed. Version remains0.3.0;
  this is an interim build, not the requested final releasev0.4.

CLI distribution separately passed 32 focused tests, standalone native version/
7-or-11-check smoke with system-only PATH, actual inventory/CycloneDX validation
and a byte-identical independent build. Contract: WINDOWS_CLI_DISTRIBUTION.md.
EXE SHA256 a5705e99d203a06b77ca633088fa4353ab19d8aa798c705c3adcb00a3e1d4e0f;
ZIP SHA256 6fec3e4dc70be5024f869b303caabbbb97bc438200303375fc99db79ddb86566.

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

## v0.3 preparation and current-main integration

Version updated to 0.3.0 in pyproject, package and the root lock entry. Dependency
versions unchanged; locked setup passes. Pre-merge run:
artifacts/harness/20261026T131806Z-1b5c3fa6/results.json. 1804 passed, 16 failed,
1 skipped, exit 139; nine additional golden mismatches were verified recursively
to contain only the intentional application_version change. No goldens refreshed.

Initial Git auth failures were followed by a successful push to release/v0.3.
Current main 2924860 was fetched and merged. Its existing deletion of tests,
fixtures and smoke scripts is preserved; those files remain recoverable from
the old commits. No unrelated test restoration or behavior changes were made.

Post-merge run: artifacts/harness/20261026T132600Z-16f61bb0/results.json.
Locked setup, architecture, 2 harness tests and package build passed. Main pytest
exit 4 (tests absent); fixture-based CLI and Qt smoke commands cannot run because
their inputs/scripts were removed in main. Ruff/mypy and security gates also fail.
These outcomes are not represented as successful application validation.

A separate self-contained synthetic offscreen check passed on the merged source:
runtime/CLI version 0.3.0, CLI findings JSON, saved analysis/device selection,
one full-width infrastructure table and six retained hidden tabs; findings
inspector on its own page remains visible. No live Cloud.ru requests were made.
No native Windows binary built. GitHub Releases API returns Forbidden.

## 2026-10-26 — CLOUD-001 VMware Edge analysis and map (Windows)

Fetched origin and fast-forwarded clean main 2924860 to 1503106. At the user's
subsequent request switched to release/v0.3 at ab56db0 (same source tree). No
commit, push, tag or publication. Baseline full report before code changes:
artifacts/harness/20261026T161509Z-bc52102d/results.json. It confirms missing
tests/fixtures/Qt scripts, baseline lint/type failures, sandbox temp-directory
failures and initially missing tools in harness/tools/.venv. Installed that
environment with its existing lock; root dependency declarations stayed unchanged.

Impact/context: 20261026T161321Z-3f5ec7e1 and 20261026T161320Z-25900221.
Added a pure VMware-to-domain adapter and reused the seven existing FW checks.
Analysis creates ordinary runs/items atomically, with additive cloud_origin JSON
linking the exact scan/resource/source path. Original scans/results/marks and
SQLite schema definitions remain unchanged. Only requested static IP sets and
application profiles are resolved on future collections; missing/dynamic/L7 and
unrepresentable conditions remain explicitly partial. NAT is not an ALLOW rule.
Maps use the same adapter, isolate connection/VDC scope and expose rule evidence.
The intentionally hidden INFRA-001 inspector is preserved.

Validation:

- Focused synthetic VMware pipeline: 21 passed, including all seven check types,
  incomplete conditions, source paths, persistence, project isolation, automatic
  analysis, duplicate IPs across VDCs and map-to-rule navigation.
- Required full gate: artifacts/harness/20261026T163305Z-daadd4d3/results.json.
  Architecture, diff-check, 23 harness tests and wheel/sdist packaging passed.
  Main pytest/fixture CLI/legacy Qt smoke could not run because their inputs were
  removed upstream. Full lint retains six baseline errors plus the missing tests
  path; full mypy retains twelve baseline errors in three unchanged modules.
- Ruff passed for changed Python paths; targeted strict mypy passed for twelve
  changed modules. Source self-contained packaged smoke passed.
- Full gate security scope was Python application sources plus qt_launcher.py,
  excluding caches, tests and third-party environments per SECURITY.md. Bandit
  retains 103 LOW/4 MEDIUM findings (new smoke asserts are B101 LOW); dependency
  audit reports pytest and setuptools. No dependency update or unrelated source
  security remediation was performed. PowerShell/Windows launch scripts are not
  covered by Bandit. The overall gate is explicitly NOT green.
- Built portable Windows EXE from this source and ran --self-test successfully,
  including cloud_vmware_seven_checks_and_map and existing DPAPI/cloud scenarios.
  Main dist/FirewallCompliance and dist/FirewallCompliance-windows-x64.zip updated;
  stage/main/ZIP EXE digests and ZIP integrity verified. Artifacts are under ignored
  build/verification. Offscreen Qt ran on Windows 10; visible GUI validation and a
  clean Windows 11 run were not performed. No live Cloud.ru account accessed.

Remaining scope: VMware NSX-T Edge Firewall only; Advanced/Evolution policy
analysis, dynamic group membership, L7/source-port conditions and effective
end-to-end/NAT reachability remain unsupported. INFRA-001 metadata/lifecycle and
DASH-001 redesign are proposals for later work, not implemented by this change.

## Structural migration 2026-10-29
Baseline beb4d7b. Impact 20261029T065150Z-a604a912. Platform/check implementations relocated; old modules alias new implementations to preserve private/runtime imports. Source and test imports updated. Cache/build data moved where accessible; .pytest_cache access denied. Full gate 20261029T065257Z-a956f527: architecture/diff/format/types passed; test import lint fixed after invocation. Test execution ongoing. Functional subdivision of combined modules and test consolidation remain outstanding. No EXE rebuild or live cloud access.

## Structural refactor completed 2026-10-29
Baseline beb4d7bab8f348d8a656e04e835f801c075175d3; no commit/push. Devices/checks relocated, policy classes split, management definitions grouped; Advanced/Evolution clients separated with common transport. Tests consolidated under tests/regression and tests/harness, imports updated; test source no longer ignored. Existing controller and policy diff work preserved. Disposable caches and build outputs moved to _temp_files, protected cache move completed with approval. Empty legacy directories archived. Shared Aruba switch grammar stays in a common vendor implementation.
Final full gate: artifacts/harness/20261029T070657Z-63ca1ae1/results.json. Architecture, diff, format, lint, strict mypy, 5 harness tests, CLI contract, Qt smoke, wheel/sdist and dependency audit pass. Full pytest: 2643 passed, 9 existing version golden failures; goldens untouched. Bandit: 3 pre-existing MEDIUM, 115 LOW; overall gate remains nonzero.
Windows build scripts/build_desktop.ps1 exit 0. Final dist EXE and ZIP rebuilt from final source. Packaged synthetic --self-test: exit 0, passed=true, frozen=true; report _temp_files/runs/reorganized-exe/smoke-result.json. No clean-OS or visible interactive acceptance claimed. EXE SHA256 7D902D47CFE8F5F25DC20D8DBADCF0DD70BB827CCC5E0943CE5D46A4970F30AB; ZIP SHA256 5AACBCAE42F06AD570AFA97D7DEFDCD4DC71CF63BBB90B9D9A9F815050F568B1.


## UserGate read-only integration — 2026-10-29

Baseline beb4d7bab8f348d8a656e04e835f801c075175d3. Impact exit 0:
20261029T072957Z-eeaba100/impact.json. Architecture exit 0, no layer violations:
20261029T073307Z-b09737e9/architecture.json. Focused `.venv/Scripts/python -m
ruff check` and `ruff format --check` pass for new collector/parser/dialog,
CLI and registry. Focused mypy including qt_app.py (`--follow-imports silent`)
passes. Inline synthetic checks: read-only collection 6.1.5, write-method rejection,
XML decoding, registry parsing including missing/unresolved selectors, complete
application analysis pipeline and Qt dialog construction with three profiles pass.
No persistent test files added, full suites or real device calls made. Native
interactive GUI, real HTTP/HTTPS firmware interoperability and executable build
remain unverified. See specifications/USERGATE.md for supported semantic subset.

## 2026-10-29 Ideco classic v23 API integration
Baseline SHA: beb4d7bab8f348d8a656e04e835f801c075175d3; unrelated edits preserved.
Impact: python harness/build impact <Ideco/registry/CLI/Qt paths>, exit 0;
artifacts/harness/20261029T084304Z-d600a041/impact.json inspected, direct runtime
consumers registry/analyze_source/stage_paths/JobRunner reviewed.
.venv/Scripts/python.exe -m ruff check (six relevant files): pass.
.venv/Scripts/python.exe -m ruff format --check (five relevant files): pass.
.venv/Scripts/python.exe -m mypy (collector/parser/registry/CLI/dialog,
--follow-imports=silent): pass, 5 source files. Agent collector/parser checks pass.
Inline synthetic collector session/filtering, parser unsupported selectors and
analyze_source: pass. Parent synthetic default-registry -> analyze_source and
Qt offscreen dialog construction: pass. CLI ideco-collect --help: exit 0.
python harness/build architecture: exit 0; no layer violations, report
artifacts/harness/20261029T084447Z-d382a39f/architecture.json inspected.
Scoped git diff --check: pass. No tests added or full suites run per AGENTS.md.
No live device, VCE switching, native interactive GUI, EXE build or effective
policy completeness verified. Interface/routing/statistics collection deferred.

## Requested EXE build only — 2026-10-29

Baseline HEAD: 49e2bcae3f825e81f133245bf3ee0fecb81ee0dc, with existing local changes.
Command: scripts/build_desktop.ps1. Exit 0; PyInstaller 6.22.3, Python 3.12.13, Windows.
Generated dist/FirewallCompliance/FirewallCompliance.exe and dist/FirewallCompliance-windows-x64.zip.
Per explicit user request, no tests, checks, executable launch or runtime validation performed.

## Windows distribution build — 2026-10-30

User requested local application build without tests. Baseline:
0893237147fd00aed1bae8d54c93192863adafd1 plus current checkout edits.
Command: powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1.
Initial attempt failed reading project.version because Windows PowerShell removed
Python -c string quotes. Changed version reading to pipe source via stdin;
reviewed the one-line script diff. Repeat build exited 0 (PyInstaller 6.22.3,
Python 3.12.13). Output: dist/FirewallComplience_v0.3.0/FirewallComplience_v0.3.0.exe
with _internal and README.txt. PyInstaller reported hidden import tzdata missing.
No tests, lint, types, harness gates, smoke, executable launch or ZIP creation.
Runtime/native GUI behavior remains unverified; CI not run for this local build.

## Application rebuild — 2026-10-30
User explicitly requested local application build. Baseline HEAD:
0893237147fd00aed1bae8d54c93192863adafd1 with existing checkout changes preserved.
Reviewed specifications/WINDOWS_DISTRIBUTION.md and scripts/build_desktop.ps1.
Command: powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1.
Exit 0 (PyInstaller 6.22.3, Python 3.12.13, Windows). Replaced current-version
bundle dist/FirewallComplience_v0.3.0; EXE, _internal and README.txt present.
Build warning: hidden import tzdata not found. No source fixes, tests, lint,
types, harness gates, smoke, EXE launch, CI run or ZIP creation performed.
Application runtime remains unverified.

## Requested Windows rebuild and Git push — 2026-10-30

Baseline: 2a19895a9aa15953115e91ff3a19d6ddde4f58da, branch release/v0.3.
Command: powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1.
Result: exit 0, PyInstaller 6.22.3 / Python 3.12.13. Entire project rebuilt into
 dist/FirewallComplience_v0.3.2 with EXE, _internal and README.txt; no ZIP.
UserGate settings entry is present in source. No local tests, lint, type checks,
smoke or application launch. Runtime compatibility remains unverified.
Unrelated pending GIT_RELEASE_POLICY.md edits excluded from this delivery commit.
