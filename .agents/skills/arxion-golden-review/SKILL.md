---
name: arxion-golden-review
description: Diagnose Arxion fixture or golden contract regressions and review explicitly requested golden updates.
---

AGENTS.md takes precedence. Automated commands below are CI procedures, not
authorization for local execution. Run them through GitHub Actions by default.
Local setup, impact/context, tests, lint, format/type checks, harness gates,
smoke, builds and security commands require an explicit user request.
Do not create or reorganize tests without explicit user request before v1.0.
Source inspection and diff review are allowed; report CI evidence and unverified
items. This skill does not authorize commit, push or an unrequested audit.

Read DOCUMENTATION.md (formats and compatibility), relevant fixture manifests and domain contracts.
Run the failing contract/golden tests through the locked pytest environment.
Compare expected versus actual schema, completeness, unknown semantics, evidence
and source mappings. Distinguish intentional contract changes from regressions.
Default to diagnosis; regenerate only when the user explicitly requests fixture
or golden changes. Read existing generator scripts before running them and
inspect every changed expected file. Never copy real device exports into fixtures.
Rerun affected tests and the full harness test gate; record results and scope.
