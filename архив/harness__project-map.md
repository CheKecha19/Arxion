# Architecture and change routes

Authoritative design: specifications/ARCHITECTURE.md; accepted decisions:
specifications/DECISIONS.md. Generate the current static import and public
definition inventory with `python harness/build context`; do not load the whole
ROADMAP_V2_FULL.md on every task. Use SPECIFICATION_INDEX.md to select documents.

## Automatically generated Mermaid maps

`python harness/build maps` writes a fresh bundle to
`artifacts/harness/<run>/maps/`, alongside `maps.json`, `maps.log` and `results.json`.
Local execution requires an explicit user request under AGENTS.md; CI is the default.
The command needs only Python and Git, without importing the application or installing
its dependencies. It is also included in `all`.

- `README.md`: commit, working-tree state, legend, overview diagrams and detail index.
- `structure.mmd`: package containment inferred from current source paths.
- `dependencies.mmd`: imports aggregated by the containing package.
- `package-*.md` / `package-*.mmd`: direct module members and outgoing imports for each
  package, with external-to-package targets retained and source paths listed.
- `maps.json`: source-only inventory, static dependencies and generated filenames
  (relative to the sibling `maps/` directory).

In GitHub Actions, open **Engineering Harness**, select a run, download the
**project-maps** artifact, then open `<run>/maps/README.md` in a Mermaid-capable
Markdown viewer or open individual `.mmd` sources in a Mermaid editor. Artifacts
contain source diagrams, not pre-rendered SVG/PNG. A separate Windows job generates
maps, context, change-impact reports and architecture boundaries independently
of the Windows checks.
Existing workflow triggers remain PRs, pushes to main and manual dispatches.
PR impact uses the PR base; push impact uses the previous commit; manual runs
use HEAD. If the event base is unavailable, impact falls back to the checked-out
commit, which is recorded in the report (no historical change coverage then).

Each generation discovers packages and modules afresh: added, moved and deleted
files need no hand-maintained module list. Ordering and node IDs are deterministic
for a given inventory. Runs use separate directories, so old files cannot leak
into a new bundle. No source documentation is overwritten or auto-committed.

Only `src/firewall_compliance` Python sources are mapped. Tests and third-party
libraries are omitted. Edges mean static imports, including conditional and
type-checking imports; they do not imply calls or data flow. The existing resolver
uses the longest known module prefix, without tracing re-exports. Dynamic imports,
Qt signals, SQL and changes in business meaning require manual scenario review.
Generation is not Mermaid rendering validation or application validation.

## CI checks by purpose

Engineering Harness reports six independent checks. Failures in one check do not
cancel the others; artifacts are uploaded even after a failed gate.

| Check | Runner | Harness commands | Artifact |
| --- | --- | --- | --- |
| Project maps and architecture | Windows | maps, architecture, context, impact | project-maps |
| Code quality | Windows | quality | harness-quality |
| Automated tests | Windows | test | harness-test |
| CLI and Qt smoke | Windows, offscreen | smoke | harness-smoke |
| Python packaging | Windows | package | harness-package |
| Static security and dependencies | Windows | security | harness-security |

Each Windows check installs the locked environments using the existing setup
command, then runs only its own gate. Artifacts contain setup and gate manifests
and logs in separate run directories. Test results include pytest.xml when pytest
produces it. Python packaging creates wheel/sdist, not the Windows EXE bundle.
All six checks use Windows runners. The maps job only parses source and Git metadata.
The test gate retains the existing suite and harness tests unchanged. These jobs
do not replace native interactive Windows acceptance or distribution validation.
The `all` command remains available; CI invokes its component gates independently.
Branch protection referring to old `verify (ubuntu-latest)` / `verify
(windows-latest)` checks needs to select the new check names in GitHub settings.

| Area | Responsibility | Regression route |
| --- | --- | --- |
| domain | Pydantic contracts, snapshots, revisions, completeness | unit, contract, golden; SCHEMA_MIGRATIONS.md |
| parsers | Vendor config to domain with source evidence | contract, fixture integrity, parser golden |
| analysis/application | Findings, policies, orchestration | unit, integration, golden |
| interfaces/cli | Analyze command and JSON | CLI test and smoke |
| interfaces/desktop | Qt, SQLite workspaces, reports, maps, jobs | Qt tests, preservation oracle, Qt smoke |
| infrastructure | Files, cloud clients, Windows secret storage | source/cloud tests; native Windows DPAPI |
| scripts + spec | Packaging and synthetic smoke entrypoints | wheel/sdist gate; separate Windows EXE validation |

Before substantive edits run `python harness/build impact <prospective-paths>`;
use `--base <commit>` to include committed changes since a known baseline. The
report includes uncommitted tracked changes and untracked paths, reverse imports
and candidate tests. Record risks and manual consumers (Qt signals, JSON/DB
contracts, assets and cloud wiring) in PLANS.md. Static imports cannot prove the
absence of impact. Review CI evidence by default; local automated execution requires explicit user request under AGENTS.md.

Architecture gate enforces domain -> domain; analysis -> analysis/domain;
parsers -> parsers/domain, including relative and conditional static imports.
It does not claim complete enforcement of UI/application orchestration or I/O.
Existing qt_app.py is a large integration module; splitting it is a separate
task requiring contract and preservation tests.

Git and hosted CI are active. Actual Git status/log and the current workflow take precedence over historical descriptions. Keep product ADRs
in the existing DECISIONS.md rather than introducing a competing ADR log.

For substantial tasks update the scoped plan, evidence record and relevant
context links; small tasks follow the lightweight procedure in AGENTS.md. New sessions read this index and actual Git status before acting.
