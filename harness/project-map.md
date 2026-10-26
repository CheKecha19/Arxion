# Architecture and change routes

Authoritative design: specifications/ARCHITECTURE.md; accepted decisions:
specifications/DECISIONS.md. Generate the current static import and public
definition inventory with `python harness/build context`; do not load the whole
ROADMAP_V2_FULL.md on every task. Use SPECIFICATION_INDEX.md to select documents.

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
absence of impact. Run the full required gate before handing off.

Architecture gate enforces domain -> domain; analysis -> analysis/domain;
parsers -> parsers/domain, including relative and conditional static imports.
It does not claim complete enforcement of UI/application orchestration or I/O.
Existing qt_app.py is a large integration module; splitting it is a separate
task requiring contract and preservation tests.

Context discrepancy: DEVELOPMENT_RULES.md says there is no Git repository.
Actual Git status/log take precedence for repository facts. Keep product ADRs
in the existing DECISIONS.md rather than introducing a competing ADR log.

For each completed task update its plan, reviewed check record and relevant
context links. New sessions read this index and actual Git status before acting.
