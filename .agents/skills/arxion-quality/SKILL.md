---
name: arxion-quality
description: Run and diagnose Arxion Python quality, tests, CLI and Qt smoke checks using the existing locked toolchain.
---

Read AGENTS.md, harness/context and the relevant specifications. Inspect Git status.
Run `python harness/build setup` when dependencies need preparing. Run
`python harness/build quality`, `test` and `smoke` for development validation;
use `all` for the full gate. Inspect every results.json command and pytest counts.
Diagnose failures from the unique run logs. Preserve a failing baseline when
application changes are outside the request. Never disable assertions, silently
skip Qt, or update goldens to turn failures green. Record commands, evidence,
unrun Windows checks and limitations in harness/build-log.md.
