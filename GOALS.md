# Engineering goals

Prepare a dependable local firewall configuration analysis product, following
`specifications/PRODUCT_VISION.md`, `CURRENT_STATE.md`, `SUPPORTED_PLATFORMS.md`
and `REQUIREMENT_STATUS.md`. Those documents define product scope; this file
does not expand supported platforms or claim effective network reachability.

Harness success means one documented command installs locked dependencies and
another runs format/lint, strict types, the existing test suite, CLI/Qt smoke,
Python packaging, and scoped security checks with inspectable exit statuses.
Tools must preserve source, fixtures, dependency declarations and golden files.
Maintain an automatically generated static project map, reverse import impact
reports, and checks for documented domain/analysis/parser layer boundaries.
Use synthetic fixtures; preserve unknown/partial semantics and source evidence.

Completion requires a reviewed diff, factual validation record and explicit
remaining failures. Native Windows GUI, DPAPI and portable EXE validation require
Windows; Linux checks alone cannot establish release readiness.

Out of scope: application changes, repository splitting, deployment, automatic
golden regeneration, automatic fixes, commits and pushes.
