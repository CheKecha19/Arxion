---
name: arxion-quality
description: Run and diagnose Arxion Python quality, tests, CLI and Qt smoke checks using the existing locked toolchain.
---

AGENTS.md takes precedence. Automated commands below are CI procedures, not
authorization for local execution. Run them through GitHub Actions by default.
Local setup, impact/context, tests, lint, format/type checks, harness gates,
smoke, builds and security commands require an explicit user request.
Do not create or reorganize tests without explicit user request before v1.0.
Source inspection and diff review are allowed; report CI evidence and unverified
items. This skill does not authorize commit, push or an unrequested audit.

Read AGENTS.md, DOCUMENTATION.md and the relevant specifications. Inspect Git status.
Run `python harness/build setup` when dependencies need preparing. Run
`python harness/build quality`, `test` and `smoke` for development validation;
use `all` for the full gate. Inspect every results.json command and pytest counts.
Diagnose failures from the unique run logs. Preserve a failing baseline when
application changes are outside the request. Never disable assertions, silently
skip Qt, or update goldens to turn failures green. Record commands, evidence,
unrun Windows checks and limitations in PROJECT_STATUS.md.
