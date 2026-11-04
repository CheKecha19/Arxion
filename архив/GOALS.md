# Engineering goals

Current development priority: requested application functionality toward v1.0.
Working and validation policy: AGENTS.md; current capabilities/limits:
`specifications/CURRENT_STATE.md`, platform scope: `SUPPORTED_PLATFORMS.md`.

Preserve source evidence and explicit unknown/partial semantics. Do not claim
end-to-end reachability or certification from configured policy alone.
Maintain clear device/check modules, stable persisted contracts and useful reports.

The harness supplies independently reported CI gates and source maps. Run it in
GitHub Actions by default. Local checks/builds/setup require explicit user request;
new tests require explicit request until v1.0 preparation. No mandatory local full gate.
Record relevant evidence and remaining failures for substantial work. Windows
release readiness requires Windows-specific evidence; packaging success alone
is insufficient. Follow GIT_RELEASE_POLICY.md and WINDOWS_DISTRIBUTION.md.
No commit, push, deletion, publication or live account access without authorization.

Historical harness-only scope restrictions belong to their individual plans;
they do not prohibit user-authorized application work.
