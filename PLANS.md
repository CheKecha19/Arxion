# Working plans

## Git delivery cadence requested by user, 2026-10-28

User explicitly requests pushing the current completed checkpoint now and then
committing/pushing after every five additional completed backlog tasks. Current
tracker has13 closed tasks; next automatic checkpoint is18, then23, etc.
After the full objective: final application build, Git push and GitHub releasev0.4
with release notes. Interim checkpoints do not publish a release or mark the
whole goal complete. Unfinished standalone policy/NAT/object diff and controller
parser files remain local until their complete contracts/tests/docs are ready.

## Latest steering: EXE first without checks, then backlog, 2026-10-28

Completed scripts/build_desktop.ps1 exit0; main EXE and ZIP updated. No tests,
self-test/runtime launch or artifact validation for this interim0.3 build, per
explicit user request. Workers froze source edits during packaging. No final
release/push; full objective remains open. New GovernancePanel MainWindow wiring
was added only AFTER build and is pending integration checks/next artifact.

Next: verify project/governance lifecycle and new dependencies when checks are
resumed; implement XML parser hardening with installed defusedxml; resume typed
policy/NAT/object diff, standalone ArubaOS8.10 parser and optional authoritative
control references. New standalone modules may be partial; inspect actual files
before resuming. No completed scope inferred from plans or worker intent.

Continuation after artifact delivery: impact160710Z-bef067a3 covers cloud XML
and MainWindow integration. Root replaces byte-pattern DTD filtering with
defusedxml rejecting DTD/entities/external references independent of encoding,
using the already-installed locked dependency. Existing namespace parsing and
safe CloudError messages preserved. No live cloud request or EXE self-test.

Current workers:
- policy_diff/fullstack_expert: new domain/analysis/application policy_revision_diff
  modules, test_policy_revision_diff.py and POLICY_REVISION_DIFF.md. Exact
  snapshots and explicit scope/identity/order/collection evidence; optional typed
  configured NAT records, no guessed translations; four replayed bounded channels.
  No old SR005/SQLite/Qt changes. Impact160742Z-bfbfcda7.
- controller_parser/backend_developer: standalone aruba_controller.py, tests and
  ARUBA_CONTROLLER_SCOPE.md; explicit ArubaOS8.10 declaration subset, role/source
  provenance and unsupported context retained. Root owns registry integration.
- governance_acceptance/test_generator: test_governance_project_ui.py only;
  MainWindow lifecycle/restart/project isolation and reports result refresh.
  Root owns UI fixes. Focused source checks are separate from the user's explicit
  no-checks EXE build; artifact remains unlaunched and untested.
- control_references/backend_developer: new optional reference catalogue factory,
  tests and CONTROL_REFERENCES.md only; primary NIST/CIS evidence and explicit
  partial technical mappings, internal baseline stays default. Impact
  160908Z-85362d98.
- qt_lifetime_review/debug_detective: read-only source review of panel/worker/Qt
  teardown. governance_acceptance owns runtime minimization:64 assertions pass
  but process exits0xC0000409, so combined validation remains failed.

## Continuation 2026-10-28: common reports and ACL map workflow

Baseline remains ba991ab with the existing uncommitted backlog implementation.
Common-result model/adapter/store/Qt acceptance: 96 tests passed. CLI workflow
acceptance found hardlink aliases could overwrite selected input files; root
added filesystem identity checks for source and profile inputs. No schema or
legacy analyze output changes. Impact: 20261028T031659Z-ecd487dc.

Current isolated ownership:
- workflow_acceptance/test_generator: test_analysis_workflow_cli.py; real CLI,
  source-independent exports and failure/alias boundaries; root owns source.
- check_passports/backend_developer: CHECK_PASSPORTS.md and
  test_check_passport_acceptance.py; runtime review only, explicit profile,
  unknown, provenance, order and work bounds; no SQLite/Qt changes. Impact:
  20261028T031634Z-f1a3184e. Broader CHECKS requirements remain open until proven.
- acl_map_completion/fullstack_expert: application/acl_map.py,
  analysis/acl_map.py, new application/acl_map_store.py, isolated
  interfaces/cli/acl_map_commands.py, test_acl_map_workflow.py and
  ACL_MAP_WORKFLOW.md. Add network filters, HTML, batch and additive SQLite
  with exact project/run constraints; preserve AclMap1.0 and old JSON/DOT.
  Root handles main CLI registration, ProjectStore/Qt/PNG integration afterward.
- acl_map_qt/frontend_developer: qt_acl_map.py and test_acl_map_filters_ui.py;
  CIDR/service view filters, HTML and bounded PNG with source/limitations legend.
  Impact 20261028T042536Z-2aedf7ad; never replace full immutable map by subset.
- acl_map_completion now owns project_store.py, qt_app.py and
  test_acl_map_project_integration.py for wrappers and saved/run batch UI;
  exact run/item provenance and worker project/ticket guards. Impact
  20261028T042545Z-f656ae9a. Root registered isolated acl-map CLI subapp.

Common AnalysisResult accepted: 96 model/adapter/store/Qt and 30 workflow/CLI
tests pass including input hardlink aliases. Legacy common-report task closed;
full backlog, full gate and final release remain open.

Further parallel ownership:
- check_passports: versioned1.1 concrete exposure witnesses and opposite-action
  order classification in existing four checks, preserving version1.0 replay,
  stable finding IDs and catalogue membership; root handles replay selection.
- controls_catalogue/backend_developer: new domain/controls.py,
  application/control_assessment.py, test_control_assessment.py and
  CONTROL_ASSESSMENT.md. Immutable internal baseline profiles/many-to-many
  mappings/approved exceptions, truthful evidence states and coverage; no external
  certification or invented NIST/CIS requirements. Impact042750Z-b8c7c74d.
- release_dependency_gate/backend_developer: pyproject/uv.lock and harness/tools
  equivalents + DEPENDENCY_GATE.md; minimal patched pytest/setuptools and XML
  parser dependency/stubs. Generate locks, coordinate installation with root;
  preserve unrelated pins. Impact042839Z-abdff4e3. Root owns cloud XML source.

Current full checkpoint042510Z-e1ba2c99: 471 harness tests,1812 old tests pass;
nine old golden version failures and Bandit/dependency audit remain explicit.
Neither baseline failures nor a green focused suite prove final release readiness.

Governance follow-through (impact043526Z-d64fea3a): root added optional profile,
exact revision inputs and operation budget to PolicyAnalysisOptions; absent
fields omitted for old JSON/idempotency. New checks use catalogue1.4 only when
explicitly selected. check_passports owns new governance_workflow.py,
governance_commands.py and test_governance_workflow.py. Saved bundle is input:
append a new governance-only stage on its exact revision, preserve prior policy
components and decisions/timestamps; never infer metadata for a new random UUID.
Root registered CLI subapp governance; no default legacy checks changed.

Controls persistence/UI follow-through (impact043651Z-2dd4828e):
controls_catalogue owns standalone control_assessment_store.py, qt_controls.py
and test_controls_project_ui.py. Exact persisted source result in same project,
immutable checksum/history, explicit profile/catalogue input, worker/ticket guards,
four states/coverage and exports. Root will wire panel after tested handback.

Real-font validation exposed registry header height regression across Qt suites.
Scoped header padding preserves30px rows, normal5/filtered4 visible rows at
1000x650. 53 related tests and offscreen screenshots with installedArial pass;
no bundled font or visible native acceptance claimed. Common-result pending
save cancellation now tracks job ID and clears busy only for matching cancelled
job;10 UI tests include queuedrun/network retry and non-cancellable running save.

Risks: input/output aliases, expensive replay in worker contexts, archived or
foreign-project references, unknown conditions hidden by filtering, and map
projection confused with reachability. Preserve immutable snapshots, evidence
and explicit limitations. Targeted tests, architecture/quality and full gate
remain required; clean OS acceptance and final release remain outstanding.

## Active goal: fresh product backlog, then legacy product backlog

Current user steering: build the present EXE first, then resume the full backlog.
Checkpoint completed 2026-10-27: source+frozen self-test including common reports,
primary EXE/ZIP refreshed and checksums/file-set verified; see build-log. Version0.3
is retained for this interim build. Do not confuse this checkpoint with finalv0.4.
Model, SQLite persistence and Qt common-result exports are accepted on focused
tests; adapter coverage and CLI application-level generation/export are next.

Root common-result CLI scope: extract the existing pure source-to-revision
construction without changing analyze_source behavior; add typed workflow and
explicit analyze-bundle/analysis-export commands. Preserve legacy analyze JSON,
do not reread source files during exports, use bounded UTF-8 input and separate
explicit output paths. Verify CLI on synthetic files and all three formats.

User authorizes implementation of PRODUCT_BACKLOG.md first, then BACKLOG.md,
explicitly using programming subagents. Goal remains active until its full scope
is verified; delivery of a useful subset is not completion. Work stays on
release/v0.3 with the existing uncommitted work preserved. On 2026-10-27 the user
requested repository updates: reviewed documentation-only commits 1398f36 and
ba991ab were fast-forwarded from ab56db0. Local PRODUCT_BACKLOG status edits were
retained alongside the exact appended CHECKS/COMPLIANCE sections; architecture.md
matches the fetched commit. Recovery copies and hashes are under ignored
artifacts/backlog-sync-20261027. No application changes were pulled by these commits.
The updated objective authorizes final Git push and release v0.4 with release notes
after completing all requested changes. No interim publication or live customer
cloud requests. Keep the full backlog scope intact.

Current wave ownership (all agents read their matching .codex/agents role):
- inventory_storage/backend_developer: resource_registry.py and its tests.
  Additive SQLite registry, persistent manual metadata, cumulative observation
  identity, archive/restore, explicit manual/discovered linking, edit audit.
- inventory_ui/frontend_developer: qt_infrastructure_registry.py and its tests.
  Full editable registry UI, multi-field/date filters, sorting and lifecycle actions.
- compact_dashboard/fullstack_expert: dashboard.py, qt_dashboard.py and tests.
  Compact overview, actual-report-based coverage, separate VM/integration counts,
  last five checks, all five severity counts and recent operations.
- cloud_acceptance/fullstack_expert: existing VMware adapter/analysis/panel/map
  and new acceptance tests; close correctness gaps against agreed CLOUD-001 scope.
- root: ProjectStore/MainWindow wiring, compatibility integration, tracker/docs,
  acceptance review, required harness gates and Windows artifact verification.

Impact: artifacts/harness/20261026T180426Z-d6f04db7/impact.json (integration),
20261026T180348Z-df03f069 (registry), 20261026T180404Z-6316f611 (registry UI).
Independent modules are edited in parallel; qt_app.py/project_store.py are root-only.
Preserve old projects/reports/marks. Imported facts and manual metadata remain
separate; absence never deletes resources. Choose reversible archive for removal,
require explicit linking on rediscovery and do not fabricate scan/check dates.
After fresh-backlog acceptance, work through the remaining legacy backlog in
dependency order. Keep deferred/conditional product decisions visible instead of
silently pretending they are implemented. Track requirements/evidence separately.

For a substantial task record: objective, baseline SHA/status, allowed paths,
constraints, ordered steps, verification commands, risks and completion evidence.
Keep plans current. Failed checks remain open until diagnosed; do not change
assertions or disable checks to close a plan.

Legacy wave, 2026-10-27: SR-005 now has classified, versioned comparisons and
legacy-reader preservation (21 focused regressions); forms preserve explicit
unknown observation/completeness (11 self-contained tests); finding decision
transitions are append-only and projected in Qt (14 storage + five UI tests).
Configured exposure checks have 28 engine tests and nine CLI/local/cloud/Qt
integration tests; profiles persist in project/run settings. Old default seven
engine checks remain compatible; explicitly selected new checks use catalog1.3.
Partial/union shadowing uses exact bounded Cartesian subtraction and source
evidence; its owner is finishing final scope diagnostics. No goldens refreshed.

Next parallel ownership: compact_dashboard/fullstack creates scripts/build_cli.ps1,
cli_launcher.py, cli_distribution_README.txt, package_inventory.py, focused tests
and WINDOWS_CLI_DISTRIBUTION.md. CLI output/work directories separate from GUI;
fixed hash seed/source epoch, deterministic ZIP, actual bundle inventory/SBOM,
native version/analyze smoke, no claims of clean-OS validation. policy_exposure/
backend owns new application AnalysisResult and JSON/CSV/HTML exports; root will
wire storage/UI/CLI after strict typed mixed-result acceptance. Other old backlog
items stay open. Final authorized deliverable is EXE + Git push + releasev0.4
with notes after full-scope verification, not this interim source checkpoint.

Fresh-backlog integration evidence (2026-10-26): MainWindow now presents the
persistent registry before legacy snapshots and the compact dashboard in place
of the hidden previous overview. Cumulative full history is read once per SQLite
change and reconciled without overwriting metadata. Archive aliases hide resources
from the active project map; immutable scans, runs and findings remain available.
Five Qt/SQLite integration tests cover cumulative scans/runs, reopening, project
isolation, manual/archive/restore and historical report navigation. Source packaged
smoke also exercises registry persistence and both new visible pages.
The required full gate report 20261026T182006Z-d30e02df has 92 passing harness
tests and passing architecture/diff/wheel/sdist; missing historical tests/fixtures
and Qt smoke, existing map/lock type errors and dependency/security findings keep
the overall gate failing. Do not equate scoped acceptance with a green release.
Quality follow-ups own organization_lock, topology_map and qt_acl_map separately.
Windows backup fsync was fixed with non-truncating writable open; backup/restore
regressions preserve registry tables and audit. Build and artifact checks pending.

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

## CLOUD-VMWARE-ANALYSIS: existing checks and network map

User authorized fetching the latest GitHub source and implementing VMware cloud
rule analysis and map integration. Fast-forwarded clean main to 1503106 (v0.3
preparation merge). No worktree, commit, push, release publication or live cloud
account access is part of this task. Only synthetic inputs are used.

User subsequently requested release/v0.3 as the working branch and supplied the
INFRA-001/DASH-001/CLOUD-001 backlog. Switched to release/v0.3 at ab56db0; its tree
matches main 1503106. Preserve the intentionally hidden infrastructure inspector.
Sequence: current CLOUD-001, then INFRA-001 identity/metadata lifecycle, then
DASH-001 counters based on explicit collected/analyzed/partial states. The latter
two remain proposals, not blanket implementation authorization.

Impact: artifacts/harness/20261026T161321Z-3f5ec7e1/impact.json; context report
artifacts/harness/20261026T161320Z-25900221/context.json. Static downstream routes
include desktop persistence, findings/reports, resource views and project/ACL maps.

Implementation: add a pure VMware-to-domain adapter, retain unknown/unsupported
address/service semantics and API source paths; use the existing seven FW checks.
Collect referenced firewall groups/application port profiles with read-only API
requests during new scans. Old scans remain analyzable with unresolved references
explicitly partial. Save derived revisions/reports in ordinary analysis runs,
linked to the source scan via additive JSON provenance (no schema rewrite).
Expose analysis for saved scans and automatic analysis after collection. Render
the same canonical rules on the project map, preserving cloud scope and evidence.
Keep NAT separate from access-control policy and do not infer end-to-end reachability.

Allowed paths: new application/cloud_analysis.py, desktop/cloud_analysis.py,
cloud_panel.py, qt_app.py, project_store.py, project_map.py, resource_details.py,
infrastructure/cloud_vmware.py, focused tests/synthetic smoke, VMware guide,
PLANS.md and harness/build-log.md. Existing unrelated baseline failures stay recorded.
Also included: the project-map widget rule-navigation signal, additive workspace
projection metadata, self-contained cloud-analysis EXE smoke, focused regression
tests in harness/tests, and short README/distribution instructions. No versions,
dependencies, schema definitions, original results or infrastructure layout changed.

Verification: focused synthetic adapter/check/map/Qt/SQLite round-trip tests;
required harness all (known missing tests/fixtures/scripts and baseline quality
failures must be reported), Ruff/mypy on changed paths, portable Windows EXE
self-test and matching main EXE/ZIP. Status: implemented for VMware NSX-T Edge
Firewall. Required full-gate and focused-test evidence is recorded in
harness/build-log.md (2026-10-26 CLOUD-001 entry); full gate retains explicit
upstream failures. Original data is preserved and analysis can run offline on
saved scans. No live account requests, Git writes beyond fetch/branch checkout,
or release publication were performed.

- Task ID / objective / acceptance criteria:
- Baseline SHA and working-tree changes to preserve:
- Allowed changes / explicit exclusions:
- Impact report and downstream callers:
- Schema, SQLite, Qt and source-evidence risks:
- Ordered implementation steps and rollback approach:
- Required tests, manual checks and expected baseline failures:
- Review findings, actual results and unresolved issues:
- Decision/context documents updated:
