---
name: arxion-security
description: Run Arxion scoped static and locked dependency security gates and guide manual Codex review.
---

AGENTS.md takes precedence. Automated commands below are CI procedures, not
authorization for local execution. Run them through GitHub Actions by default.
Local setup, impact/context, tests, lint, format/type checks, harness gates,
smoke, builds and security commands require an explicit user request.
Do not create or reorganize tests without explicit user request before v1.0.
Source inspection and diff review are allowed; report CI evidence and unverified
items. This skill does not authorize commit, push or an unrequested audit.

Read SECURITY.md and SECURITY.md before review.
Run `python harness/build security` after setup. Inspect Bandit and pip-audit
JSON and logs; tool failures or advisory network failures do not establish safety.
Bandit covers src Python files and scripts/qt_launcher.py only. Manually review
scripts/build_desktop.ps1, FirewallCompliance.spec and Start-Desktop.cmd when
relevant; these are in policy scope but not covered by Python static analysis.
Dependency input is the root lock export including optional/dev dependencies.
Record exact scope and exclusions, tool versions, findings and remaining gaps.
Use available Codex Security skills for a requested deeper source audit; this
gate is not a substitute for their validation. Do not automatically remediate,
change dependencies, suppress findings, or claim absence of vulnerabilities.
