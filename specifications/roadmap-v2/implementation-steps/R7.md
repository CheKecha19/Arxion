# R7: небольшие шаги реализации

[Вход и правила](../IMPLEMENTATION_STEPS.md) · [Матрица покрытия](COVERAGE.md)

Каждый XS включает свой код/документ и focused проверку. Будущие проверки ещё не выполнены. Пути модулей относительно src/firewall_compliance/, кроме явных artifacts/specifications/tests/scripts; предлагаемые модули разрешаются JIT до GO. accepted_bounded_existing_evidence означает только historical synthetic U01–U06, не полную приёмку всех связанных UX требований.

<a id="step-r7-001"></a>
## STEP-R7-001 — Контракт трёх claim layers и кванторов

- Результат: Контракт трёх claim layers и кванторов.
- Внутри: Контракт трёх claim layers и кванторов; необходимые регрессии и независимая приёмка этого результата.
- За границей: Полный reachable по local permit.
- Файлы/контракт: domain/reachability.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/001; размер S.
- Приёмка и проверки: Declared/effective/model path и any/all/selected различны.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N01, network-family:NET-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-001-01` | Declared layer enum | planned |
| `XS-R7-001-02` | Effective-policy layer validator | planned |
| `XS-R7-001-03` | Model-path claim validator | planned |
| `XS-R7-001-04` | Existential quantifier validator | planned |
| `XS-R7-001-05` | Universal quantifier validator | planned |
| `XS-R7-001-06` | Selected-path validator | planned |

<a id="step-r7-002"></a>
## STEP-R7-002 — Extended query validation

- Результат: Extended query validation.
- Внутри: Extended query validation; необходимые регрессии и независимая приёмка этого результата.
- За границей: Sample-based proof.
- Файлы/контракт: domain/reachability.py;  domain/policy_decision.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/002; размер S.
- Приёмка и проверки: Family/src/dst/protocol/ports/VRF/time/ingress exact; множества не заменены sample IP.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N02, network-family:NET-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-002-01` | Address-family query validator | planned |
| `XS-R7-002-02` | Source query-set validator | planned |
| `XS-R7-002-03` | Destination query-set validator | planned |
| `XS-R7-002-04` | Protocol query validator | planned |
| `XS-R7-002-05` | Port query validator | planned |
| `XS-R7-002-06` | VRF query validator | planned |
| `XS-R7-002-07` | Time query validator | planned |
| `XS-R7-002-08` | Ingress query validator | planned |

<a id="step-r7-003"></a>
## STEP-R7-003 — Structured result evidence/reasons

- Результат: Structured result evidence/reasons.
- Внутри: Structured result evidence/reasons; необходимые регрессии и независимая приёмка этого результата.
- За границей: Flat bool result.
- Файлы/контракт: domain/reachability.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/003; размер S.
- Приёмка и проверки: Layer/outcome/witness/counterexample/unknown/budget/provenance versioned.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N02, network-family:NET-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-003-01` | Layered outcome validator | planned |
| `XS-R7-003-02` | Witness field validator | planned |
| `XS-R7-003-03` | Counterexample field validator | planned |
| `XS-R7-003-04` | Unknown reason formatter | planned |
| `XS-R7-003-05` | Budget result validator | planned |
| `XS-R7-003-06` | Result provenance serializer | planned |

<a id="step-r7-004"></a>
## STEP-R7-004 — Per-query capability gate

- Результат: Per-query capability gate.
- Внутри: Per-query capability gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Переписать neutral core.
- Файлы/контракт: application/device_decision.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/004; размер S.
- Приёмка и проверки: Required facts точного query; global flag не даёт reachable; existing neutral API reused.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N03, network-family:NET-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-004-01` | Per-query required-fact resolver | planned |
| `XS-R7-004-02` | Binding gate predicate | planned |
| `XS-R7-004-03` | Completeness gate predicate | planned |
| `XS-R7-004-04` | Unknown gate formatter | planned |
| `XS-R7-004-05` | Neutral evaluator public call wire | planned |

<a id="step-r7-005"></a>
## STEP-R7-005 — Neutral single-device Qt wiring

- Результат: Neutral single-device Qt wiring.
- Внутри: Neutral single-device Qt wiring; необходимые регрессии и независимая приёмка этого результата.
- За границей: Новая Cisco expansion.
- Файлы/контракт: interfaces/desktop/network_backend.py;  interfaces/desktop/qt_network.py.
- Зависимости: STEP-R7-004. Порядок: R7/005; размер S.
- Приёмка и проверки: Selected supported profile вызывает existing neutral evaluator; missing binding explicit; desktop ранее unwired.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: ux:UX07-E.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-005-01` | Selected neutral profile resolver | planned |
| `XS-R7-005-02` | Qt neutral evaluator dispatch | planned |
| `XS-R7-005-03` | Missing-binding UI reason | planned |

<a id="step-r7-006"></a>
## STEP-R7-006 — Non-Cisco network source passport

- Результат: Non-Cisco network source passport.
- Внутри: Non-Cisco network source passport; необходимые регрессии и независимая приёмка этого результата.
- За границей: Ожидание Cisco NAT.
- Файлы/контракт: parsers/network_contracts.py;  parsers/catalog.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/006; размер S.
- Приёмка и проверки: Один готовый vendor/version/route/interface/neighbor source documented; другие slices отдельно.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N04, network-family:NET-02, platform:V-NET.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-006-01` | Non-Cisco version/format key | planned |
| `XS-R7-006-02` | Route source passport | planned |
| `XS-R7-006-03` | Interface source passport | planned |
| `XS-R7-006-04` | Neighbor source passport | planned |

<a id="step-r7-007"></a>
## STEP-R7-007 — Network interface/VRF import

- Результат: Network interface/VRF import.
- Внутри: Network interface/VRF import; необходимые регрессии и независимая приёмка этого результата.
- За границей: Route selection.
- Файлы/контракт: domain/network.py;  выбранный non-Cisco parser.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/007; размер S.
- Приёмка и проверки: Overlapping networks/VRF scopes exact; missing facts unknown.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N05, network-family:NET-02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-007-01` | Network interface scoped ID | planned |
| `XS-R7-007-02` | VRF scoped ID | planned |
| `XS-R7-007-03` | Overlapping-network guard | planned |
| `XS-R7-007-04` | Missing-interface branch | planned |

<a id="step-r7-008"></a>
## STEP-R7-008 — Route input decode

- Результат: Route input decode.
- Внутри: Route input decode; необходимые регрессии и независимая приёмка этого результата.
- За границей: Runtime FIB из config.
- Файлы/контракт: domain/network.py;  выбранный non-Cisco parser.
- Зависимости: STEP-R7-006. Порядок: R7/008; размер S.
- Приёмка и проверки: RIB/FIB/type/next-hop provenance различны; unknown attrs не defaults.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N05, network-family:NET-02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-008-01` | RIB/FIB type decoder | planned |
| `XS-R7-008-02` | Route prefix decoder | planned |
| `XS-R7-008-03` | Route next-hop decoder | planned |
| `XS-R7-008-04` | Route source span | planned |
| `XS-R7-008-05` | Unknown route-attribute branch | planned |

<a id="step-r7-009"></a>
## STEP-R7-009 — Route selection/recursive resolution

- Результат: Route selection/recursive resolution.
- Внутри: Route selection/recursive resolution; необходимые регрессии и независимая приёмка этого результата.
- За границей: NAT composition.
- Файлы/контракт: analysis/route_selection.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/009; размер S.
- Приёмка и проверки: LPM/VRF/recursive loop/no-route/unknown independent table cases.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N05, network-family:NET-02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-009-01` | LPM candidate selector | planned |
| `XS-R7-009-02` | VRF route scope predicate | planned |
| `XS-R7-009-03` | Recursive next-hop resolver | planned |
| `XS-R7-009-04` | Recursive-loop branch | planned |
| `XS-R7-009-05` | Proven no-route branch | planned |
| `XS-R7-009-06` | Unknown route-selection branch | planned |

<a id="step-r7-010"></a>
## STEP-R7-010 — L2 adjacency/neighbor evidence

- Результат: L2 adjacency/neighbor evidence.
- Внутри: L2 adjacency/neighbor evidence; необходимые регрессии и независимая приёмка этого результата.
- За границей: Инференс как физический факт.
- Файлы/контракт: parsers/network_contracts.py;  domain/network.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/010; размер S.
- Приёмка и проверки: Inferred segment не proven adjacency; stale/missing neighbor снижает claim.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N05, network-family:NET-02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-010-01` | Neighbor observation decoder | planned |
| `XS-R7-010-02` | Adjacency provenance validator | planned |
| `XS-R7-010-03` | Stale-neighbor predicate | planned |
| `XS-R7-010-04` | Inferred-segment claim guard | planned |

<a id="step-r7-011"></a>
## STEP-R7-011 — Exact packet-set primitive

- Результат: Exact packet-set primitive.
- Внутри: Exact packet-set primitive; необходимые регрессии и независимая приёмка этого результата.
- За границей: Выбор одной IP из CIDR.
- Файлы/контракт: domain/policy_matching.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/011; размер S.
- Приёмка и проверки: IPv4/6/protocol/ports/ICMP symbolic sets finite independent exhaustive oracle.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N06, network-family:NET-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-011-01` | IPv4 symbolic-set primitive | planned |
| `XS-R7-011-02` | IPv6 symbolic-set primitive | planned |
| `XS-R7-011-03` | Protocol-set primitive | planned |
| `XS-R7-011-04` | Port-set primitive | planned |
| `XS-R7-011-05` | ICMP-set primitive | planned |
| `XS-R7-011-06` | Independent finite-universe equality validator | planned |

<a id="step-r7-012"></a>
## STEP-R7-012 — Packet-set budgets/partial result

- Результат: Packet-set budgets/partial result.
- Внутри: Packet-set budgets/partial result; необходимые регрессии и независимая приёмка этого результата.
- За границей: No-crash как единственный gate.
- Файлы/контракт: предлагаемый packet-set engine.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/012; размер S.
- Приёмка и проверки: Limit exhaustion возвращает partial/unresolved scope и reason; truncated set не reachable/blocked.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N06, network-family:NET-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-012-01` | Packet-set size budget counter | planned |
| `XS-R7-012-02` | Budget exhaustion branch | planned |
| `XS-R7-012-03` | Unresolved-scope formatter | planned |
| `XS-R7-012-04` | Truncated-result claim guard | planned |

<a id="step-r7-013"></a>
## STEP-R7-013 — Vendor policy transfer profile

- Результат: Vendor policy transfer profile.
- Внутри: Vendor policy transfer profile; необходимые регрессии и независимая приёмка этого результата.
- За границей: Unsupported vendor inheritance.
- Файлы/контракт: analysis/forwarding_policy.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/013; размер S.
- Приёмка и проверки: One declared profile stage/order/default/attachment evidence exact.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N07, network-family:NET-01, network-family:NET-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-013-01` | Policy stage selector | planned |
| `XS-R7-013-02` | Rule-order transfer predicate | planned |
| `XS-R7-013-03` | Profile default-action resolver | planned |
| `XS-R7-013-04` | Attachment transfer gate | planned |

<a id="step-r7-014"></a>
## STEP-R7-014 — NAT coordinate relation model

- Результат: NAT coordinate relation model.
- Внутри: NAT coordinate relation model; необходимые регрессии и независимая приёмка этого результата.
- За границей: NAT как подпись edge.
- Файлы/контракт: domain/forwarding.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/014; размер S.
- Приёмка и проверки: Pre/post src/dst/ports/zone/VRF и rule provenance exact.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N08, network-family:NET-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-014-01` | Pre-NAT tuple validator | planned |
| `XS-R7-014-02` | Post-NAT tuple validator | planned |
| `XS-R7-014-03` | NAT relation identity key | planned |
| `XS-R7-014-04` | NAT source provenance validator | planned |

<a id="step-r7-015"></a>
## STEP-R7-015 — DNAT transfer

- Результат: DNAT transfer.
- Внутри: DNAT transfer; необходимые регрессии и независимая приёмка этого результата.
- За границей: SNAT/PAT.
- Файлы/контракт: analysis/forwarding_policy.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/015; размер S.
- Приёмка и проверки: Destination changes correct policy/route stage; relation inverse supported/unknown explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N08, network-family:NET-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-015-01` | DNAT destination transfer helper | planned |
| `XS-R7-015-02` | DNAT route-coordinate selector | planned |
| `XS-R7-015-03` | DNAT inverse relation branch | planned |

<a id="step-r7-016"></a>
## STEP-R7-016 — SNAT/PAT transfer

- Результат: SNAT/PAT transfer.
- Внутри: SNAT/PAT transfer; необходимые регрессии и независимая приёмка этого результата.
- За границей: Feasibility как allocation proof.
- Файлы/контракт: analysis/forwarding_policy.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/016; размер S.
- Приёмка и проверки: Exact source/port relation; allocation uncertainty отдельно.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N08, network-family:NET-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-016-01` | SNAT source transfer helper | planned |
| `XS-R7-016-02` | PAT port relation helper | planned |
| `XS-R7-016-03` | PAT resource-unknown branch | planned |

<a id="step-r7-017"></a>
## STEP-R7-017 — NAT priority/exemption

- Результат: NAT priority/exemption.
- Внутри: NAT priority/exemption; необходимые регрессии и независимая приёмка этого результата.
- За границей: ASA defaults на других vendor.
- Файлы/контракт: analysis/forwarding_policy.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/017; размер S.
- Приёмка и проверки: Identity/noNAT/overlap stage profile-specific; unsupported unknown.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N08, network-family:NET-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-017-01` | NAT priority comparator | planned |
| `XS-R7-017-02` | Identity/noNAT predicate | planned |
| `XS-R7-017-03` | NAT exemption branch | planned |
| `XS-R7-017-04` | Unknown NAT profile branch | planned |

<a id="step-r7-018"></a>
## STEP-R7-018 — Reverse/stateful flow

- Результат: Reverse/stateful flow.
- Внутри: Reverse/stateful flow; необходимые регрессии и независимая приёмка этого результата.
- За границей: Forward permit как reverse proof.
- Файлы/контракт: application/device_decision.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/018; размер S.
- Приёмка и проверки: Reverse из relation/stateful semantics; asymmetry/missing facts unknown, не swapped IP.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N08, network-family:NET-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-018-01` | Reverse relation builder | planned |
| `XS-R7-018-02` | Stateful return predicate | planned |
| `XS-R7-018-03` | Asymmetric return branch | planned |
| `XS-R7-018-04` | Missing reverse-fact unknown | planned |

<a id="step-r7-019"></a>
## STEP-R7-019 — Policy/resource feasibility separation

- Результат: Policy/resource feasibility separation.
- Внутри: Policy/resource feasibility separation; необходимые регрессии и независимая приёмка этого результата.
- За границей: Actual session allocation.
- Файлы/контракт: domain/reachability.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/019; размер S.
- Приёмка и проверки: PAT pool/port/session exhaustion uncertainty отдельно от policy allow.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:NET-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-019-01` | Policy feasibility field | planned |
| `XS-R7-019-02` | Resource feasibility field | planned |
| `XS-R7-019-03` | Pool exhaustion reason | planned |
| `XS-R7-019-04` | Session-limit unknown reason | planned |

<a id="step-r7-020"></a>
## STEP-R7-020 — Coherent multidevice manifest

- Результат: Coherent multidevice manifest.
- Внутри: Coherent multidevice manifest; необходимые регрессии и независимая приёмка этого результата.
- За границей: Current unrelated snapshots.
- Файлы/контракт: domain/snapshot.py.
- Зависимости: STEP-R2-022. Порядок: R7/020; размер S.
- Приёмка и проверки: Time/version/VRF/source hashes exact; incoherent inputs gated; replay immutable.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N09, storage:DATA-09, network-family:NET-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-020-01` | Snapshot timestamp bounds | planned |
| `XS-R7-020-02` | Snapshot version/hash tuple | planned |
| `XS-R7-020-03` | Snapshot VRF references | planned |
| `XS-R7-020-04` | Incoherent manifest gate | planned |

<a id="step-r7-021"></a>
## STEP-R7-021 — Transfer graph construction

- Результат: Transfer graph construction.
- Внутри: Transfer graph construction; необходимые регрессии и независимая приёмка этого результата.
- За границей: Worklist evaluation.
- Файлы/контракт: предлагаемый analysis/path_engine.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/021; размер S.
- Приёмка и проверки: Device/interface/VRF/stage edges provenance; boundary exits explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N10, network-family:NET-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-021-01` | Device stage node key | planned |
| `XS-R7-021-02` | Transfer edge builder | planned |
| `XS-R7-021-03` | Edge provenance validator | planned |
| `XS-R7-021-04` | Organization-boundary exit | planned |

<a id="step-r7-022"></a>
## STEP-R7-022 — Worklist exact-state propagation

- Результат: Worklist exact-state propagation.
- Внутри: Worklist exact-state propagation; необходимые регрессии и независимая приёмка этого результата.
- За границей: Sampling paths.
- Файлы/контракт: предлагаемый analysis/path_engine.py.
- Зависимости: STEP-R7-021, STEP-R7-011. Порядок: R7/022; размер S.
- Приёмка и проверки: Packet sets monotone; witness reconstruct exact transformed tuple.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N10, network-family:NET-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-022-01` | Worklist state key | planned |
| `XS-R7-022-02` | Monotone packet propagation | planned |
| `XS-R7-022-03` | Witness predecessor record | planned |
| `XS-R7-022-04` | Transformed tuple reconstruction | planned |

<a id="step-r7-023"></a>
## STEP-R7-023 — Loop/subsumption termination

- Результат: Loop/subsumption termination.
- Внутри: Loop/subsumption termination; необходимые регрессии и независимая приёмка этого результата.
- За границей: Truncated visited list как block.
- Файлы/контракт: предлагаемый analysis/path_engine.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/023; размер S.
- Приёмка и проверки: Finite cycle/subsumption proof; budget exhaustion explicit partial.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N10, network-family:NET-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-023-01` | Subsumption predicate | planned |
| `XS-R7-023-02` | Cycle fixed-point branch | planned |
| `XS-R7-023-03` | Termination budget branch | planned |
| `XS-R7-023-04` | Partial graph result formatter | planned |

<a id="step-r7-024"></a>
## STEP-R7-024 — ECMP/alternative quantifiers

- Результат: ECMP/alternative quantifiers.
- Внутри: ECMP/alternative quantifiers; необходимые регрессии и независимая приёмка этого результата.
- За границей: Any-path permit как universal.
- Файлы/контракт: предлагаемый analysis/path_engine.py.
- Зависимости: STEP-R7-023. Порядок: R7/024; размер S.
- Приёмка и проверки: One permit+one block различают any/all/selected; witness/counterexample independent.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N10, network-family:NET-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-024-01` | Any-path outcome reducer | planned |
| `XS-R7-024-02` | All-path outcome reducer | planned |
| `XS-R7-024-03` | Selected-path reducer | planned |
| `XS-R7-024-04` | Permit/block alternative counterexample | planned |

<a id="step-r7-025"></a>
## STEP-R7-025 — Cloud/organization boundary

- Результат: Cloud/organization boundary.
- Внутри: Cloud/organization boundary; необходимые регрессии и независимая приёмка этого результата.
- За границей: Универсальная ACL для cloud.
- Файлы/контракт: предлагаемый analysis/path_engine.py;  cloud transfer contract.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/025; размер S.
- Приёмка и проверки: SG/NACL/route semantics независимы где supported; outsideorg unknown boundary.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:NET-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-025-01` | Cloud SG transfer adapter contract | planned |
| `XS-R7-025-02` | Cloud NACL transfer adapter contract | planned |
| `XS-R7-025-03` | Cloud route adapter contract | planned |
| `XS-R7-025-04` | Outside-organization unknown exit | planned |

<a id="step-r7-026"></a>
## STEP-R7-026 — Versioned control-flow intent

- Результат: Versioned control-flow intent.
- Внутри: Versioned control-flow intent; необходимые регрессии и независимая приёмка этого результата.
- За границей: Live polling.
- Файлы/контракт: предлагаемый domain/control_flows.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/026; размер S.
- Приёмка и проверки: Exact query/expected layer/as-of/scope pins profile; ambiguous intent rejected.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N11, network-family:NET-05.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-026-01` | Control intent ID/version | planned |
| `XS-R7-026-02` | Expected-layer validator | planned |
| `XS-R7-026-03` | Expected-quantifier validator | planned |
| `XS-R7-026-04` | Intent profile/snapshot references | planned |

<a id="step-r7-027"></a>
## STEP-R7-027 — Control-flow evaluation

- Результат: Control-flow evaluation.
- Внутри: Control-flow evaluation; необходимые регрессии и независимая приёмка этого результата.
- За границей: Mark как результат сети.
- Файлы/контракт: предлагаемый application/control_flows.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/027; размер S.
- Приёмка и проверки: Expected/observed exact layer/quantifier; insufficient evidence unknown.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:N11, network-family:NET-05.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-027-01` | Control query evaluator call | planned |
| `XS-R7-027-02` | Expected/observed comparator | planned |
| `XS-R7-027-03` | Insufficient-evidence result | planned |

<a id="step-r7-028"></a>
## STEP-R7-028 — Comparable control-flow change diff

- Результат: Comparable control-flow change diff.
- Внутри: Comparable control-flow change diff; необходимые регрессии и независимая приёмка этого результата.
- За границей: Provenance-only как network change.
- Файлы/контракт: предлагаемый application/control_flows.py;  analysis/revision_diff.py.
- Зависимости: STEP-R2-028, STEP-R7-027. Порядок: R7/028; размер S.
- Приёмка и проверки: Comparable snapshots only; UNKNOWN disappearance не confirmed removal; old API compatible.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:NET-05, storage:DATA-11.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-028-01` | Control snapshot comparability | planned |
| `XS-R7-028-02` | Unknown disappearance branch | planned |
| `XS-R7-028-03` | Confirmed change witness | planned |
| `XS-R7-028-04` | Legacy structural compatibility dispatch | planned |

<a id="step-r7-029"></a>
## STEP-R7-029 — NEW-20 / C / FW-RULE-NO-HITS-WINDOW — нет срабатываний за достаточное окно

- Результат: NEW-20 / C / FW-RULE-NO-HITS-WINDOW — нет срабатываний за достаточное окно.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R7-004, STEP-R2-020. Порядок: R7/029; размер S.
- Приёмка и проверки: counter device/rule identity validator; observation window sufficiency; reset/wrap normalization; zero-hit window predicate; gapped window unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-20, package:R7:C03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-029-01` | NEW-20: counter device/rule identity validator | planned |
| `XS-R7-029-02` | NEW-20: observation window sufficiency | planned |
| `XS-R7-029-03` | NEW-20: reset/wrap normalization | planned |
| `XS-R7-029-04` | NEW-20: zero-hit window predicate | planned |
| `XS-R7-029-05` | NEW-20: gapped window unknown | planned |
| `XS-R7-029-06` | NEW-20: registry wire после predicate gates | planned |

<a id="step-r7-030"></a>
## STEP-R7-030 — NEW-24 / C / FW-NO-ROUTE-CONTROL-FLOW — нет применимого маршрута к точному адресу

- Результат: NEW-24 / C / FW-NO-ROUTE-CONTROL-FLOW — нет применимого маршрута к точному адресу.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R7-004, STEP-R7-009, STEP-R7-026. Порядок: R7/030; размер S.
- Приёмка и проверки: control-flow exact destination/VRF resolver; complete route inventory predicate; no applicable route predicate; partial route unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-24, package:R7:C03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-030-01` | NEW-24: control-flow exact destination/VRF resolver | planned |
| `XS-R7-030-02` | NEW-24: complete route inventory predicate | planned |
| `XS-R7-030-03` | NEW-24: no applicable route predicate | planned |
| `XS-R7-030-04` | NEW-24: partial route unknown | planned |
| `XS-R7-030-05` | NEW-24: registry wire после predicate gates | planned |

<a id="step-r7-031"></a>
## STEP-R7-031 — NEW-25 / C / FW-NAT-PROTECTED-SERVICE-PUBLICATION — запрещённая публикация через NAT

- Результат: NEW-25 / C / FW-NAT-PROTECTED-SERVICE-PUBLICATION — запрещённая публикация через NAT.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R7-004, STEP-R7-014, STEP-R7-015, STEP-R7-016, STEP-R6-004. Порядок: R7/031; размер S.
- Приёмка и проверки: translated protected service relation; external publication predicate; protected asset witness; missing NAT/profile unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-25, package:R7:C03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-031-01` | NEW-25: translated protected service relation | planned |
| `XS-R7-031-02` | NEW-25: external publication predicate | planned |
| `XS-R7-031-03` | NEW-25: protected asset witness | planned |
| `XS-R7-031-04` | NEW-25: missing NAT/profile unknown | planned |
| `XS-R7-031-05` | NEW-25: registry wire после predicate gates | planned |

<a id="step-r7-032"></a>
## STEP-R7-032 — Topology layer карты

Ровно один active source XS: XS-R7-032-02 — preparatory logical-link topology renderer в qt_topology_map.py, native selectable/movable items; ещё не done. XS-R7-032-05 — implementation_done_unverified: frozen topology_map.py builder по exact NetworkImportResult/DeviceRevision/ForwardingContext; device/interface/subnet configured attachment, evidence/scope; operational/VRF unknown. Нет reread/routes/cables/reachability claims. Remaining topology/NET source и functional gates открыты; physical-link XS-R7-032-01 dependency сохранена для full composition. Все verification gates deferred; UI не запускали, acceptance нет. Recorded policy-widget build topology не включает.

- Результат: Topology layer карты.
- Внутри: Topology layer карты; необходимые регрессии и независимая приёмка этого результата.
- За границей: Path overlay.
- Файлы/контракт: предлагаемый interfaces/desktop/qt_acl_map.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/032; размер S.
- Приёмка и проверки: Physical/logical/inferred links visually distinct; no false path claim.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-03, network:M05.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-032-01` | Physical-link visual item | planned |
| `XS-R7-032-02` | Preparatory logical-link renderer, qt_topology_map.py | active; not done |
| `XS-R7-032-03` | Inferred-link visual item | planned |
| `XS-R7-032-04` | Topology table row | planned |
| `XS-R7-032-05` | Frozen evidence-scoped topology builder, topology_map.py | implementation_done_unverified |

<a id="step-r7-033"></a>
## STEP-R7-033 — Decision/path overlay карты

- Результат: Decision/path overlay карты.
- Внутри: Decision/path overlay карты; необходимые регрессии и независимая приёмка этого результата.
- За границей: Новый backend engine.
- Файлы/контракт: предлагаемый interfaces/desktop/qt_acl_map.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/033; размер S.
- Приёмка и проверки: Exact snapshot/quantifier/witness/stage refs; unknown/failure table navigation.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-03, network:M05.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-033-01` | Path witness edge overlay | planned |
| `XS-R7-033-02` | Decision stage label | planned |
| `XS-R7-033-03` | Selected quantifier label | planned |
| `XS-R7-033-04` | Unknown/failure table navigation | planned |

<a id="step-r7-034"></a>
## STEP-R7-034 — User flow form/presets

- Результат: User flow form/presets.
- Внутри: User flow form/presets; необходимые регрессии и независимая приёмка этого результата.
- За границей: Unsupported profile как ready.
- Файлы/контракт: interfaces/desktop/qt_network.py;  interfaces/desktop/network_backend.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/034; размер S.
- Приёмка и проверки: Ordinary controls вместо JSON editor; validation/missing inputs понятны.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-13, journey-screen:J17, ux:UX07-E.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-034-01` | Flow source form action | planned |
| `XS-R7-034-02` | Flow destination form action | planned |
| `XS-R7-034-03` | Flow service form action | planned |
| `XS-R7-034-04` | VRF/time form action | planned |
| `XS-R7-034-05` | Missing-input submit guard | planned |
| `XS-R7-034-06` | Preset selection action | planned |

<a id="step-r7-035"></a>
## STEP-R7-035 — Expert query/result tools и CLI

- Результат: Expert query/result tools и CLI.
- Внутри: Expert query/result tools и CLI; необходимые регрессии и независимая приёмка этого результата.
- За границей: Новый внешний API.
- Файлы/контракт: interfaces/desktop/qt_network.py;  interfaces/cli/main.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/035; размер S.
- Приёмка и проверки: Versioned import/export same identity/quantifier; unsupported version clear.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: ux:UX07-E.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-035-01` | Expert query import | planned |
| `XS-R7-035-02` | Expert result export | planned |
| `XS-R7-035-03` | CLI query dispatch | planned |
| `XS-R7-035-04` | Unsupported-version diagnostic | planned |

<a id="step-r7-036"></a>
## STEP-R7-036 — Help/source acquisition R7

- Результат: Help/source acquisition R7.
- Внутри: Help/source acquisition R7; необходимые регрессии и независимая приёмка этого результата.
- За границей: Fake native source support.
- Файлы/контракт: specifications/USER_GUIDE.md;  предлагаемый source guide.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/036; размер S.
- Приёмка и проверки: Policy/routes/NAT/reverse/multidevice required sources exact; limits honest.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-18, platform:V-NET.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-036-01` | Policy-source help entry | planned |
| `XS-R7-036-02` | Route-source help entry | planned |
| `XS-R7-036-03` | NAT-source help entry | planned |
| `XS-R7-036-04` | Reverse-flow help entry | planned |
| `XS-R7-036-05` | Multidevice help entry | planned |

<a id="step-r7-037"></a>
## STEP-R7-037 — Independent finite oracle/vendor lab report

- Результат: Independent finite oracle/vendor lab report.
- Внутри: Independent finite oracle/vendor lab report; необходимые регрессии и независимая приёмка этого результата.
- За границей: Statistical proof по synthetic.
- Файлы/контракт: предлагаемые NET fixtures/lab artifacts.
- Зависимости: нет; доступный подготовительный срез. Порядок: R7/037; размер S.
- Приёмка и проверки: Exhaustive finite oracle независим; documented versioned vendor lab reproducible; real holdout absence open.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network:Q01, checks:CHECK-Q-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-037-01` | Finite-oracle independence validator | planned |
| `XS-R7-037-02` | Versioned lab input manifest | planned |
| `XS-R7-037-03` | Lab expected-outcome record | planned |
| `XS-R7-037-04` | Real holdout missing gate | planned |

<a id="step-r7-038"></a>
## STEP-R7-038 — Независимый R7 gate

- Результат: Независимый R7 gate.
- Внутри: Независимый R7 gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Развитие Cisco сверх existing behavior.
- Файлы/контракт: предлагаемый R7 gate artifact.
- Зависимости: STEP-R7-001, STEP-R7-002, STEP-R7-003, STEP-R7-004, STEP-R7-005, STEP-R7-006, STEP-R7-007, STEP-R7-008, STEP-R7-009, STEP-R7-010, STEP-R7-011, STEP-R7-012, STEP-R7-013, STEP-R7-014, STEP-R7-015, STEP-R7-016, STEP-R7-017, STEP-R7-018, STEP-R7-019, STEP-R7-020, STEP-R7-021, STEP-R7-022, STEP-R7-023, STEP-R7-024, STEP-R7-025, STEP-R7-026, STEP-R7-027, STEP-R7-028, STEP-R7-029, STEP-R7-030, STEP-R7-031, STEP-R7-032, STEP-R7-033, STEP-R7-034, STEP-R7-035, STEP-R7-036, STEP-R7-037. Порядок: R7/038; размер S.
- Приёмка и проверки: Supported neutral slice runtime UI; quantifiers/NAT/reverse/loops/budgets/NEW3/CLI/frozen evidence; unknown scope не скрыт.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: stage:R7.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R7-038-01` | Neutral runtime UI checkpoint | planned |
| `XS-R7-038-02` | NAT/reverse checkpoint | planned |
| `XS-R7-038-03` | Quantifier/loop/budget checkpoint | planned |
| `XS-R7-038-04` | NEW-C evidence checkpoint | planned |
| `XS-R7-038-05` | CLI/frozen checkpoint | planned |
| `XS-R7-038-06` | R7 manifest gate | planned |
