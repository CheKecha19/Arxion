---
name: arxion-golden-review
description: Diagnose Arxion fixture or golden contract regressions and review explicitly requested golden updates.
---

Read tests/golden/README.md, relevant fixture manifests and domain contracts.
Run the failing contract/golden tests through the locked pytest environment.
Compare expected versus actual schema, completeness, unknown semantics, evidence
and source mappings. Distinguish intentional contract changes from regressions.
Default to diagnosis; regenerate only when the user explicitly requests fixture
or golden changes. Read existing generator scripts before running them and
inspect every changed expected file. Never copy real device exports into fixtures.
Rerun affected tests and the full harness test gate; record results and scope.
