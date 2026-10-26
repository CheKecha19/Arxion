---
name: arxion-change-impact
description: Map Arxion modules and assess downstream contracts and regression risks before substantial changes.
---

Read AGENTS.md, GOALS.md, PLANS.md and harness/project-map.md. Inspect Git status.
Run `python harness/build context` and `python harness/build impact <paths>`;
inspect the generated JSON and relevant source instead of loading the full roadmap.
Record the task objective, prospective paths, downstream consumers, API/JSON/DB
compatibility, source evidence/unknown semantics, risks and required tests in
PLANS.md. Check Qt signal wiring, runtime imports, assets, persistence and reports
manually: static reachability is not complete. Run the architecture gate after
changes and the full required gate before completion. Review the Git diff for
scope, fixture changes and unexpected files. Use existing branches/checkouts;
branch creation, commits and PR publication follow the user's authorization.
