> Сверка 31.10.2026: это накопленный трекер этапов, а не единый актуальный статус релиза. Текущее приложение — 0.3.2; UserGate/Ideco подключены экспериментально, ACL workflow и controls/governance присутствуют в исходниках. Блоки старой поставки ZIP и старых проверок — исторические свидетельства; они не подтверждают текущий EXE. Полноту закрытия широких задач CHECKS/COMPLIANCE не выводить из наличия отдельных модулей. Актуальная сводка: [CURRENT_STATE](CURRENT_STATE.md).

# Implementation goal: fresh backlog followed by legacy backlog

The user authorized implementation and programming subagents on 2026-10-26.
Source requirements remain PRODUCT_BACKLOG.md and BACKLOG.md. This tracker does
not replace or narrow them. A check mark requires current verification evidence.

## Fresh backlog (first)

- [x] INFRA-001: cumulative persistent registry; imported and manual metadata
  separated; name/label/platform/type/status/description/comments; complete physical
  location; cloud VDC; truthful first/last dates; compound filtering and chronological
  sorting; manual create/edit; reversible removal/restore; explicit rediscovery/linking;
  project isolation, preservation and restart tests; integrated Qt workflow.
- [x] DASH-001: replace visible overview; category totals and actual checked counts;
  separate integrations/VMs; actual executed checks; five most recent checks and
  explicit latest check datetime; five finding severities; recent operations;
  correct empty/repeated/partial/failed/manual-only behavior.
- [x] CLOUD-001: agreed VMware Edge Firewall adapter, existing FW checks, problems
  and reports, canonical map conditions/evidence/navigation, unknown/partial
  semantics, collected vs checked distinction and end-to-end acceptance evidence.

## Legacy active backlog (after the fresh backlog)

Fetched product additions, 2026-10-27, origin/release/v0.3 ba991ab:

- [ ] CHECKS-001: expanded check passports and platform-specific evidence gates.
- [ ] CHECKS-002: administrative service exposure; reconcile the implemented
  explicit exposure profile against the newly recorded acceptance requirements.
- [x] CHECKS-003: explicit address/port breadth thresholds and role-specific
  source/service policy with exact profile evidence, exceptions, bounded replay
  and unknown/partial semantics; POLICY_SCOPE_CHECKS.md.
- [ ] CHECKS-004: allow/deny intersections and order dependence; reuse the existing
  partial/union engine rather than duplicate it, and verify the remaining scope.
- [x] CHECKS-005: unbound policies and required role/interface-direction filtering
  over declared attachments; negative conclusions require explicitly complete
  attachment inventory; POLICY_SCOPE_CHECKS.md.
- [ ] CHECKS-006: violations of an explicitly approved access matrix.
- [ ] CHECKS-007: egress and approved DNS resolver policy.
- [ ] CHECKS-008: NAT publications with routing/policy processing context.
- [ ] CHECKS-009: IPv6 coverage and explicitly required dual-stack policy.
- [ ] CHECKS-010: owner, justification, expiry and review of temporary permissions.
- [ ] CHECKS-011: unused-rule candidates supported by observation statistics.
- [ ] CHECKS-012: newly allowed access across comparable revisions.
- [ ] CHECKS-013: cloud VM management exposure and east-west rules, sharing the
  existing CLOUD-001 pipeline with explicit SG/Edge platform semantics.
- [ ] COMPLIANCE-001: versioned profiles, controls mappings, evidence and coverage;
  no certification claim. NIST/CIS/PCI references are proposed sources, not an
  automatically imposed organizational policy. User selected the internal baseline.

The fetched document records proposals and open profile questions. Their exact
requirements remain in PRODUCT_BACKLOG.md; existing implementations are not marked
complete for a broader new task solely because their titles overlap.

- [x] Map approved internal architecture/security baseline to specifications (P0).
- [x] SR-005: distinguish network values, provenance and completeness in diff.
- [x] AclMap SQLite/CLI, network filters, HTML/PNG, batch scope and integrated Qt:
  immutable project archive, exact run/item provenance, selected/all batch,
  explicit failures/cancellation, restart and source-independent exports.
- [ ] ArubaOS controller session ACL/user-role scope, fixtures and semantic adapter.
- [x] Advanced network metadata/binding forms with explicit source/time/completeness.
- [ ] Revision diff for policy/NAT/objects.
- [x] Partial shadowing and union coverage with semantic fixtures.
- [x] Dangerous services/untrusted administrative access checks.
- [ ] Inter-device links and consistent NetworkSnapshot.
- [ ] Source/destination/service path queries with explained decisions.
- [ ] Network groups and reproducible access matrices.
- [x] Finding decision transition history (existing policy runs/marks are preserved).
- [x] Common evidence-based AnalysisResult and JSON/CSV/HTML reports: typed
  inputs/results/limitations, immutable project persistence, Qt and CLI workflows;
  96 model/adapter/store/UI + 30 workflow/CLI tests. ANALYSIS_RESULT.md.
- [x] Bounded catalogue of technical controls: internal versioned profile/mappings,
  explicit coverage/four states, exceptions, retained analysis and CLI exports;
  57 tests. Full COMPLIANCE-001 and integrated Qt assessment remain open.
- [x] Reproducible Windows CLI packaging without Docker.
- [ ] Clean offline Windows OS validation, dependency/runtime inventory and SBOM.
- [ ] REST API and schema.
- [ ] PostgreSQL adapter.
- [ ] Roles and audit log.
- [ ] SSO.
- [ ] Web UI over the stable API.
- [ ] SSH/API collectors, scheduling and SIEM integration.
- [ ] Ticketing integration for findings without policy-application workflow.
- [ ] Container distribution and image scan if distribution is explicitly selected.

## Existing explicit boundaries in the legacy backlog

Cisco effective NAT/PBR, further ASA/IOS/XE adapters and Cisco path expansion are
marked deferred pending a separate decision. Vulnerability Control, attack-vector
management and Change Management are explicitly outside that roadmap. These are
not silently counted complete or replaced with a cosmetic placeholder.

## Evidence

Fresh scope accepted on synthetic inputs: 138 harness tests, six integrated
MainWindow/SQLite scenarios, themed minimum-size geometry checks, registry backup
and restore, VMware normalization/checks/map/source navigation. Required full gate
20261026T182616Z-684d6597: architecture/format/lint/mypy/harness-tests/CLI/Qt smoke/
wheel/sdist pass; historical pytest import path and security gates remained failing.
The pytest launcher was subsequently corrected to python -m pytest; native full
test report 20261027T045153Z-5999607e: 1804 passed, 17 failed (nine historical
golden application versions and eight old synthetic API/UI expectations).
Goldens were not regenerated. The eight stale non-golden tests have since been
reviewed and updated with stronger request assertions; focused 59 tests pass.

Frozen EXE self-test passed: build/verification/fresh-backlog-exe-smoke/smoke-result.json.
Main dist/FirewallCompliance and dist/FirewallCompliance-windows-x64.zip updated;
stage/main/ZIP EXE SHA256 3221d9c0ae6e81316ca30e27d5249ffed0c34949181b0fd09975983dcca63f82.
ZIP integrity and embedded EXE match verified. This is the fresh-backlog checkpoint,
not release v0.4 or completion of the full objective. Real-cloud/clean-Windows11
acceptance and outstanding quality/security/release work remain explicit.

Legacy work started: SR-005, typed network forms, finding transition history,
partial/union shadowing and configured service/admin exposure checks. Internal
architecture/security baseline is mapped in REQUIREMENTS_TRACEABILITY.md; the
external mandatory requirements document is absent; the user explicitly selected
the internal baseline, so that scoped P0 mapping is complete.

Updated user objective: after ALL requested changes, build EXE, push Git and
publish release v0.4 with release notes. This supersedes the earlier no-publication
restriction for the final verified release. Do not publish this interim checkpoint.

Baseline: release/v0.3 ab56db0 with preceding uncommitted VMware work. Existing
full gate has missing legacy tests/fixtures/smoke and known quality/security
failures; see harness/build-log.md. New scope needs current targeted/full gate
results and review before any completion claim.
