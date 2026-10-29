# Source layout

Application package: `src/firewall_compliance`.

- `devices/network/hpe_aruba`: shared AOS-Switch/AOS-CX grammar and isolated experimental ArubaOS controller parser. Shared grammar intentionally stays together; support is selected by explicit syntax, not filename.
- `devices/network/hpe_h3c/comware`: Comware configuration parser.
- `devices/ngfw/cisco/asa`: policy, network, forwarding, route/interface parsers.
- `devices/cloud/cloud_ru`: VMware client, separate Advanced/Evolution clients, shared public transport/configuration.
- `checks/access`: any-any, prohibited services, untrusted administration, excessive access.
- `checks/attachments`: ACL bindings.
- `checks/policy_quality`: duplicates, shadowing variants, merge candidates.
- `checks/rule_hygiene`: logging, descriptions, disabled rules.
- `checks/governance`: lifecycle and unused candidates.
- `checks/management/{access,snmp,logging,time}`: grouped management definitions; a shared evaluator preserves evidence/completeness semantics.
- `checks/common`: shared bounded matching/evidence operations.
- `domain`: stable models; `application`: workflows; `analysis`: network/diff/maps and check orchestration; `interfaces`: CLI/Qt; `infrastructure`: shared I/O.

Old parser/check/cloud import paths remain compatibility adapters. They must resolve to the same implementations; serialized IDs/schema do not change.

Tests are maintained under `tests`: unit/contract/integration/golden, regression, harness and synthetic fixtures. Tests are versioned source, excluded from EXE. Packaged self-test remains in the application package because the EXE launcher invokes it.

`_temp_files/cache`, `_temp_files/build`, `_temp_files/runs` are disposable. `artifacts` retains validation/release evidence; `dist` contains deliverables; `.venv` is the source runtime. Specifications, scripts, harness, lockfiles and CI are maintained engineering inputs.

The shared Aruba parser implements both switch grammars in one vendor module. Splitting that grammar further is a separate behavior refactor, rather than creating duplicate parser implementations. The controller remains outside the default registry.
