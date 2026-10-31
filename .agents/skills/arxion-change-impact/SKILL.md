---
name: arxion-change-impact
description: Map Arxion modules and assess downstream contracts and regression risks before substantial changes.
---

AGENTS.md takes precedence. Automated commands below are CI procedures, not
authorization for local execution. Run them through GitHub Actions by default.
Local setup, impact/context, tests, lint, format/type checks, harness gates,
smoke, builds and security commands require an explicit user request.
Do not create or reorganize tests without explicit user request before v1.0.
Source inspection and diff review are allowed; report CI evidence and unverified
items. This skill does not authorize commit, push or an unrequested audit.

Read AGENTS.md, PROJECT_STATUS.md and DEVELOPMENT.md. Inspect Git status.
Run `python harness/build context` and `python harness/build impact <paths>`;
inspect the generated JSON and relevant source instead of loading the full roadmap.
Record the task objective, prospective paths, downstream consumers, API/JSON/DB
compatibility, source evidence/unknown semantics, risks and required tests in
PROJECT_STATUS.md. Check Qt signal wiring, runtime imports, assets, persistence and reports
manually: static reachability is not complete. Run the architecture gate after
changes and the full required gate before completion. Review the Git diff for
scope, fixture changes and unexpected files. Use existing branches/checkouts;
branch creation, commits and PR publication follow the user's authorization.
