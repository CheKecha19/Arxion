# R4: небольшие шаги реализации

[Вход и правила](../IMPLEMENTATION_STEPS.md) · [Матрица покрытия](COVERAGE.md)

Каждый XS включает свой код/документ и focused проверку. Будущие проверки ещё не выполнены. Пути модулей относительно src/firewall_compliance/, кроме явных artifacts/specifications/tests/scripts; предлагаемые модули разрешаются JIT до GO. accepted_bounded_existing_evidence означает только historical synthetic U01–U06, не полную приёмку всех связанных UX требований.

<a id="step-r4-001"></a>
## STEP-R4-001 — Версионированный source/capability passport contract

- Результат: Версионированный source/capability passport contract.
- Внутри: Версионированный source/capability passport contract; необходимые регрессии и независимая приёмка этого результата.
- За границей: Новая grammar без источника.
- Файлы/контракт: parsers/catalog.py;  parsers/contracts.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/001; размер S.
- Приёмка и проверки: Format/version/field поддержка подкреплена primary source и sample hash; unsupported отдельный.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P01, platform:P01-A, ux:UX07-B.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-001-01` | Format/version passport key | planned |
| `XS-R4-001-02` | Primary-source citation record | planned |
| `XS-R4-001-03` | Sample hash validator | planned |
| `XS-R4-001-04` | Support-status classifier | planned |

<a id="step-r4-002"></a>
## STEP-R4-002 — MatchExpression по измерениям пакета

- Результат: MatchExpression по измерениям пакета.
- Внутри: MatchExpression по измерениям пакета; необходимые регрессии и независимая приёмка этого результата.
- За границей: Vendor defaults.
- Файлы/контракт: domain/policy_matching.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/002; размер S.
- Приёмка и проверки: IPv4/6/protocol/source+destination port/time dimensions явны; unknown не any.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:P01-B, checks:CHECK-ARCH-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-002-01` | Address-family match validator | planned |
| `XS-R4-002-02` | Protocol match validator | planned |
| `XS-R4-002-03` | Source-port condition validator | planned |
| `XS-R4-002-04` | Destination-port condition validator | planned |
| `XS-R4-002-05` | Time-condition validator | planned |
| `XS-R4-002-06` | Unknown-vs-any constructor | planned |

<a id="step-r4-003"></a>
## STEP-R4-003 — Typed ObjectReference contract

- Результат: Typed ObjectReference contract.
- Внутри: Typed ObjectReference contract; необходимые регрессии и независимая приёмка этого результата.
- За границей: Разрешение циклов угадыванием.
- Файлы/контракт: domain/configuration.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/003; размер S.
- Приёмка и проверки: Typed scoped group ID; unresolved/missing/proven empty различны.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:P01-B, checks:CHECK-A-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-003-01` | Typed-reference key builder | planned |
| `XS-R4-003-02` | Group-member validator | planned |
| `XS-R4-003-03` | Missing-target branch | planned |
| `XS-R4-003-04` | Scope-collision predicate | planned |

<a id="step-r4-004"></a>
## STEP-R4-004 — Binding/order/default-action contract

- Результат: Binding/order/default-action contract.
- Внутри: Binding/order/default-action contract; необходимые регрессии и независимая приёмка этого результата.
- За границей: Route/NAT.
- Файлы/контракт: domain/policy_decision.py;  parsers/contracts.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/004; размер S.
- Приёмка и проверки: Attachment/direction/stage/order/default action имеют provenance; absent binding не permit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:P01-B.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-004-01` | Attachment identity builder | planned |
| `XS-R4-004-02` | Direction normalizer | planned |
| `XS-R4-004-03` | Order provenance validator | planned |
| `XS-R4-004-04` | Default-action unknown branch | planned |

<a id="step-r4-005"></a>
## STEP-R4-005 — Field completeness dependency resolver

- Результат: Field completeness dependency resolver.
- Внутри: Field completeness dependency resolver; необходимые регрессии и независимая приёмка этого результата.
- За границей: Все checks UNKNOWN из-за одного поля.
- Файлы/контракт: domain/parse_result.py;  analysis/policy_checks.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/005; размер S.
- Приёмка и проверки: Required field проверяется в точном scope; partial только зависимый check, не глобальный ложный pass.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: checks:CHECK-ARCH-02, package:R4:P01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-005-01` | Required-field resolver | planned |
| `XS-R4-005-02` | Field-completeness predicate | planned |
| `XS-R4-005-03` | Localized limitation formatter | planned |

<a id="step-r4-006"></a>
## STEP-R4-006 — Intersection и difference точных множеств

- Результат: Intersection и difference точных множеств.
- Внутри: Intersection и difference точных множеств; необходимые регрессии и независимая приёмка этого результата.
- За границей: Heuristic prefix count.
- Файлы/контракт: domain/policy_matching.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/006; размер S.
- Приёмка и проверки: Finite independent oracle и Hypothesis на disjoint/partial/unknown/IPv6/port correlations.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: checks:CHECK-ARCH-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-006-01` | Address intersection helper | planned |
| `XS-R4-006-02` | Service intersection helper | planned |
| `XS-R4-006-03` | Address difference helper | planned |
| `XS-R4-006-04` | Service difference helper | planned |
| `XS-R4-006-05` | Unknown operand propagation | planned |

<a id="step-r4-007"></a>
## STEP-R4-007 — Union/equality/witness точных множеств

- Результат: Union/equality/witness точных множеств.
- Внутри: Union/equality/witness точных множеств; необходимые регрессии и независимая приёмка этого результата.
- За границей: Unsupported как пустое множество.
- Файлы/контракт: domain/policy_matching.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/007; размер S.
- Приёмка и проверки: Union coverage без pairwise shortcut; witness принадлежит exact set и source; limits дают unresolved.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: checks:CHECK-ARCH-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-007-01` | Normalized union helper | planned |
| `XS-R4-007-02` | Set equality predicate | planned |
| `XS-R4-007-03` | Exact witness generator | planned |
| `XS-R4-007-04` | Witness source provenance | planned |

<a id="step-r4-008"></a>
## STEP-R4-008 — Versioned check registry

- Результат: Versioned check registry.
- Внутри: Versioned check registry; необходимые регрессии и независимая приёмка этого результата.
- За границей: UI registry editing.
- Файлы/контракт: analysis/policy_checks.py;  предлагаемый checks registry.
- Зависимости: STEP-R4-005. Порядок: R4/008; размер S.
- Приёмка и проверки: ID/layer/deps/parameters/units/severity стабильны; invalid profile отвергнут; legacy IDs совместимы.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P04, checks:CHECK-ARCH-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-008-01` | Check ID/version validator | planned |
| `XS-R4-008-02` | Layer/dependency registry entry | planned |
| `XS-R4-008-03` | Parameter units/default validator | planned |
| `XS-R4-008-04` | Severity-rule validator | planned |

<a id="step-r4-009"></a>
## STEP-R4-009 — Инвентарь legacy technical controls FR-014

- Результат: Инвентарь legacy technical controls FR-014.
- Внутри: Инвентарь legacy technical controls FR-014; необходимые регрессии и независимая приёмка этого результата.
- За границей: Закрытие FR014 названием пакета.
- Файлы/контракт: compliance;  specifications/LEGACY_MIGRATION_MAP.md.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/009; размер S.
- Приёмка и проверки: Каждый legacy control явно mapped implemented/new/justified scope; 25NEW не замена control catalog.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P04.
- Раскрытие: До GO перечислить actual controls/checks/views/matrix cells/participants по исходному протоколу; стабильные дополнительные XS, один элемент на leaf. Закрытие родителя запрещено до покрытия roster.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-009-01` | Legacy control inventory row schema | planned |
| `XS-R4-009-02` | Unmatched legacy-control coverage error | planned |

<a id="step-r4-010"></a>
## STEP-R4-010 — Версионированный technical-control catalog

- Результат: Версионированный technical-control catalog.
- Внутри: Версионированный technical-control catalog; необходимые регрессии и независимая приёмка этого результата.
- За границей: Control execution.
- Файлы/контракт: предлагаемый compliance/catalog.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/010; размер S.
- Приёмка и проверки: Для каждого control ID/applicability/input/evidence/status schema machine-verifiable.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-010-01` | Control record validator | planned |
| `XS-R4-010-02` | Control applicability predicate | planned |
| `XS-R4-010-03` | Control status enum reader | planned |
| `XS-R4-010-04` | Catalog version dispatch | planned |

<a id="step-r4-011"></a>
## STEP-R4-011 — Technical-control runner с четырьмя статусами

- Результат: Technical-control runner с четырьмя статусами.
- Внутри: Technical-control runner с четырьмя статусами; необходимые регрессии и независимая приёмка этого результата.
- За границей: Объявление compliance по отсутствию findings.
- Файлы/контракт: предлагаемый compliance/evaluator.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/011; размер S.
- Приёмка и проверки: PASS/FAIL/UNKNOWN/N/A и evidence по control; missing input не pass; control family split перед GO.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P04.
- Раскрытие: До GO перечислить actual controls/checks/views/matrix cells/participants по исходному протоколу; стабильные дополнительные XS, один элемент на leaf. Закрытие родителя запрещено до покрытия roster.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-011-01` | Single-control applicability evaluator contract | planned |
| `XS-R4-011-02` | Single-control evidence predicate contract | planned |
| `XS-R4-011-03` | Single-control unknown branch contract | planned |
| `XS-R4-011-04` | Final runner dispatch after catalog leaf expansion | planned |

<a id="step-r4-012"></a>
## STEP-R4-012 — Comware config-order выбранного release

- Результат: Comware config-order выбранного release.
- Внутри: Comware config-order выбранного release; необходимые регрессии и независимая приёмка этого результата.
- За границей: Auto-order.
- Файлы/контракт: parsers/comware.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/012; размер S.
- Приёмка и проверки: Rule number/text order/source spans; reorder counterexample независим; unknown release не поддержан.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P02, platform:P02-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-012-01` | Numbered-rule ordering helper | planned |
| `XS-R4-012-02` | Text-order mapping | planned |
| `XS-R4-012-03` | Missing-order evidence branch | planned |

<a id="step-r4-013"></a>
## STEP-R4-013 — Comware packet-filter attachment

- Результат: Comware packet-filter attachment.
- Внутри: Comware packet-filter attachment; необходимые регрессии и независимая приёмка этого результата.
- За границей: Route reachability.
- Файлы/контракт: parsers/comware.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/013; размер S.
- Приёмка и проверки: Interface/direction/ACL link exact; missing/ambiguous attachment видим.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:P02-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-013-01` | Interface attachment parser | planned |
| `XS-R4-013-02` | Direction attachment parser | planned |
| `XS-R4-013-03` | Unknown ACL attachment branch | planned |

<a id="step-r4-014"></a>
## STEP-R4-014 — Comware auto-order comparator

- Результат: Comware auto-order comparator.
- Внутри: Comware auto-order comparator; необходимые регрессии и независимая приёмка этого результата.
- За границей: Перенос ASA order.
- Файлы/контракт: parsers/comware.py;  domain/policy_matching.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/014; размер S.
- Приёмка и проверки: Release-specific comparator vs documented effective output synthetic lab; unknown release blocked.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:P02-B.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-014-01` | Selected-release auto-order key | planned |
| `XS-R4-014-02` | Comparator tie predicate | planned |
| `XS-R4-014-03` | Effective-output parity case | planned |
| `XS-R4-014-04` | Unknown-release gate | planned |

<a id="step-r4-015"></a>
## STEP-R4-015 — AOS-S source ports и дополнительные условия

- Результат: AOS-S source ports и дополнительные условия.
- Внутри: AOS-S source ports и дополнительные условия; необходимые регрессии и независимая приёмка этого результата.
- За границей: AOS-CX grammar.
- Файлы/контракт: parsers/hp_aruba.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/015; размер S.
- Приёмка и проверки: Source-port/conditions сохраняются; unsupported token снижает exact field capability; source spans.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P03, platform:P03-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-015-01` | AOS-S source-port parser | planned |
| `XS-R4-015-02` | AOS-S documented qualifier parser per selected qualifier | planned |
| `XS-R4-015-03` | Unsupported-token field degradation | planned |

<a id="step-r4-016"></a>
## STEP-R4-016 — AOS-CX exact supported modes

- Результат: AOS-CX exact supported modes.
- Внутри: AOS-CX exact supported modes; необходимые регрессии и независимая приёмка этого результата.
- За границей: Switch/controller смешение.
- Файлы/контракт: parsers/hp_aruba.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/016; размер S.
- Приёмка и проверки: CX grammar/order/binding passport отдельно от AOS-S; fixtures и unsupported cases.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:P03-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-016-01` | AOS-CX format dispatch | planned |
| `XS-R4-016-02` | CX rule-order helper | planned |
| `XS-R4-016-03` | CX attachment parser | planned |
| `XS-R4-016-04` | CX unsupported-mode gate | planned |

<a id="step-r4-017"></a>
## STEP-R4-017 — Switch interface/VLAN/VRF facts

- Результат: Switch interface/VLAN/VRF facts.
- Внутри: Switch interface/VLAN/VRF facts; необходимые регрессии и независимая приёмка этого результата.
- За границей: Фактический route claim.
- Файлы/контракт: parsers/hp_aruba.py;  parsers/comware.py;  domain/network.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/017; размер S.
- Приёмка и проверки: Scoped IDs/overlapping VRF различимы; VLAN и L3 association имеют provenance.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:P03-B.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-017-01` | Interface scoped key | planned |
| `XS-R4-017-02` | AOS-S VLAN membership parser | planned |
| `XS-R4-017-03` | Comware VLAN membership parser | planned |
| `XS-R4-017-04` | AOS-CX VRF membership parser | planned |
| `XS-R4-017-05` | Overlapping-network identity check | planned |

<a id="step-r4-018"></a>
## STEP-R4-018 — Native HP/Aruba partial-ACL/logging acceptance

- Результат: Native HP/Aruba partial-ACL/logging acceptance.
- Внутри: Native HP/Aruba partial-ACL/logging acceptance; необходимые регрессии и независимая приёмка этого результата.
- За границей: Старый frozen smoke другой fixture как доказательство.
- Файлы/контракт: interfaces/desktop/resource_details.py;  scripts packaged smoke contract.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/018; размер S.
- Приёмка и проверки: Declared fixture partial ACL/logging details/source provenance native100/150/frozen; inherited unknown не enabled.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-018-01` | Partial-ACL native details row check | planned |
| `XS-R4-018-02` | Logging native details row check | planned |
| `XS-R4-018-03` | Frozen partial-ACL action check | planned |
| `XS-R4-018-04` | Frozen logging action check | planned |

<a id="step-r4-019"></a>
## STEP-R4-019 — NEW-03 / A / FW-DISALLOWED-PROTOCOL — разрешение запрещённого профилем протокола

- Результат: NEW-03 / A / FW-DISALLOWED-PROTOCOL — разрешение запрещённого профилем протокола.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/019; размер S.
- Приёмка и проверки: forbidden protocol membership; forbidden protocol witness; missing profile/protocol unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-03, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-019-01` | NEW-03: forbidden protocol membership | planned |
| `XS-R4-019-02` | NEW-03: forbidden protocol witness | planned |
| `XS-R4-019-03` | NEW-03: missing profile/protocol unknown | planned |
| `XS-R4-019-04` | NEW-03: registry wire после predicate gates | planned |

<a id="step-r4-020"></a>
## STEP-R4-020 — NEW-04 / A / FW-BROAD-SERVICE-RANGE — избыточное множество портов

- Результат: NEW-04 / A / FW-BROAD-SERVICE-RANGE — избыточное множество портов.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/020; размер S.
- Приёмка и проверки: canonical service union; exact port cardinality threshold; threshold boundary; unknown service branch; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-04, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-020-01` | NEW-04: canonical service union | planned |
| `XS-R4-020-02` | NEW-04: exact port cardinality threshold | planned |
| `XS-R4-020-03` | NEW-04: threshold boundary | planned |
| `XS-R4-020-04` | NEW-04: unknown service branch | planned |
| `XS-R4-020-05` | NEW-04: registry wire после predicate gates | planned |

<a id="step-r4-021"></a>
## STEP-R4-021 — NEW-05 / A / FW-BROAD-SOURCE — слишком широкое множество источников

- Результат: NEW-05 / A / FW-BROAD-SOURCE — слишком широкое множество источников.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/021; размер S.
- Приёмка и проверки: source normalized-set measure; source breadth threshold; nested alias unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-05, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-021-01` | NEW-05: source normalized-set measure | planned |
| `XS-R4-021-02` | NEW-05: source breadth threshold | planned |
| `XS-R4-021-03` | NEW-05: nested alias unknown | planned |
| `XS-R4-021-04` | NEW-05: registry wire после predicate gates | planned |

<a id="step-r4-022"></a>
## STEP-R4-022 — NEW-06 / A / FW-BROAD-DESTINATION — слишком широкое множество назначений

- Результат: NEW-06 / A / FW-BROAD-DESTINATION — слишком широкое множество назначений.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/022; размер S.
- Приёмка и проверки: destination normalized-set measure; destination breadth threshold; unresolved destination; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-06, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-022-01` | NEW-06: destination normalized-set measure | planned |
| `XS-R4-022-02` | NEW-06: destination breadth threshold | planned |
| `XS-R4-022-03` | NEW-06: unresolved destination | planned |
| `XS-R4-022-04` | NEW-06: registry wire после predicate gates | planned |

<a id="step-r4-023"></a>
## STEP-R4-023 — NEW-09 / A / FW-PARTIAL-SHADOW — непустая перекрытая и непустая остающаяся часть

- Результат: NEW-09 / A / FW-PARTIAL-SHADOW — непустая перекрытая и непустая остающаяся часть.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/023; размер S.
- Приёмка и проверки: eligible prior rule; shadowed intersection; nonempty remainder; two-witness formatter; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-09, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-023-01` | NEW-09: eligible prior rule | planned |
| `XS-R4-023-02` | NEW-09: shadowed intersection | planned |
| `XS-R4-023-03` | NEW-09: nonempty remainder | planned |
| `XS-R4-023-04` | NEW-09: two-witness formatter | planned |
| `XS-R4-023-05` | NEW-09: registry wire после predicate gates | planned |

<a id="step-r4-024"></a>
## STEP-R4-024 — NEW-10 / A / FW-UNION-SHADOW — полное покрытие несколькими предыдущими правилами

- Результат: NEW-10 / A / FW-UNION-SHADOW — полное покрытие несколькими предыдущими правилами.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/024; размер S.
- Приёмка и проверки: predecessor union reducer; full coverage predicate; uncovered gap counterexample; unknown coverage; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-10, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-024-01` | NEW-10: predecessor union reducer | planned |
| `XS-R4-024-02` | NEW-10: full coverage predicate | planned |
| `XS-R4-024-03` | NEW-10: uncovered gap counterexample | planned |
| `XS-R4-024-04` | NEW-10: unknown coverage | planned |
| `XS-R4-024-05` | NEW-10: registry wire после predicate gates | planned |

<a id="step-r4-025"></a>
## STEP-R4-025 — NEW-11 / A / FW-CONFLICTING-OVERLAP — противоположные действия на общих условиях

- Результат: NEW-11 / A / FW-CONFLICTING-OVERLAP — противоположные действия на общих условиях.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/025; размер S.
- Приёмка и проверки: opposing action predicate; effective scope compatibility; overlap witness; ambiguous binding unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-11, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-025-01` | NEW-11: opposing action predicate | planned |
| `XS-R4-025-02` | NEW-11: effective scope compatibility | planned |
| `XS-R4-025-03` | NEW-11: overlap witness | planned |
| `XS-R4-025-04` | NEW-11: ambiguous binding unknown | planned |
| `XS-R4-025-05` | NEW-11: registry wire после predicate gates | planned |

<a id="step-r4-026"></a>
## STEP-R4-026 — NEW-12 / A / FW-EQUIVALENT-OBJECTS — разные объекты с одинаковым значением

- Результат: NEW-12 / A / FW-EQUIVALENT-OBJECTS — разные объекты с одинаковым значением.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/026; размер S.
- Приёмка и проверки: object type/scope compatibility; normalized value equality; ambiguous graph unknown; equivalence evidence pair; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-12, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-026-01` | NEW-12: object type/scope compatibility | planned |
| `XS-R4-026-02` | NEW-12: normalized value equality | planned |
| `XS-R4-026-03` | NEW-12: ambiguous graph unknown | planned |
| `XS-R4-026-04` | NEW-12: equivalence evidence pair | planned |
| `XS-R4-026-05` | NEW-12: registry wire после predicate gates | planned |

<a id="step-r4-027"></a>
## STEP-R4-027 — NEW-13 / A / FW-UNREFERENCED-OBJECT — нет поддержанных ссылок на объект

- Результат: NEW-13 / A / FW-UNREFERENCED-OBJECT — нет поддержанных ссылок на объект.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/027; размер S.
- Приёмка и проверки: complete reference graph predicate; inbound reference count; unused object predicate; incomplete graph unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-13, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-027-01` | NEW-13: complete reference graph predicate | planned |
| `XS-R4-027-02` | NEW-13: inbound reference count | planned |
| `XS-R4-027-03` | NEW-13: unused object predicate | planned |
| `XS-R4-027-04` | NEW-13: incomplete graph unknown | planned |
| `XS-R4-027-05` | NEW-13: registry wire после predicate gates | planned |

<a id="step-r4-028"></a>
## STEP-R4-028 — NEW-14 / A / FW-MISSING-OBJECT-REFERENCE — ссылка без цели

- Результат: NEW-14 / A / FW-MISSING-OBJECT-REFERENCE — ссылка без цели.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/028; размер S.
- Приёмка и проверки: typed target lookup; dangling reference predicate; cross-scope nonmatch; source witness; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-14, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-028-01` | NEW-14: typed target lookup | planned |
| `XS-R4-028-02` | NEW-14: dangling reference predicate | planned |
| `XS-R4-028-03` | NEW-14: cross-scope nonmatch | planned |
| `XS-R4-028-04` | NEW-14: source witness | planned |
| `XS-R4-028-05` | NEW-14: registry wire после predicate gates | planned |

<a id="step-r4-029"></a>
## STEP-R4-029 — NEW-15 / A / FW-CYCLIC-GROUP — цикл вложенных групп

- Результат: NEW-15 / A / FW-CYCLIC-GROUP — цикл вложенных групп.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/029; размер S.
- Приёмка и проверки: DFS state transition; cycle path reconstruction; self-cycle branch; unresolved edge unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-15, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-029-01` | NEW-15: DFS state transition | planned |
| `XS-R4-029-02` | NEW-15: cycle path reconstruction | planned |
| `XS-R4-029-03` | NEW-15: self-cycle branch | planned |
| `XS-R4-029-04` | NEW-15: unresolved edge unknown | planned |
| `XS-R4-029-05` | NEW-15: registry wire после predicate gates | planned |

<a id="step-r4-030"></a>
## STEP-R4-030 — NEW-16 / A / FW-EMPTY-GROUP-IN-RULE — доказанно пустая группа в активном правиле

- Результат: NEW-16 / A / FW-EMPTY-GROUP-IN-RULE — доказанно пустая группа в активном правиле.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006. Порядок: R4/030; размер S.
- Приёмка и проверки: proven empty group predicate; active reference predicate; missing/cycle not-empty-proof guard; empty-group witness; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-16, package:R4:C01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-030-01` | NEW-16: proven empty group predicate | planned |
| `XS-R4-030-02` | NEW-16: active reference predicate | planned |
| `XS-R4-030-03` | NEW-16: missing/cycle not-empty-proof guard | planned |
| `XS-R4-030-04` | NEW-16: empty-group witness | planned |
| `XS-R4-030-05` | NEW-16: registry wire после predicate gates | planned |

<a id="step-r4-031"></a>
## STEP-R4-031 — FW-ANY-ANY — широкий matcher адресов

- Результат: FW-ANY-ANY — широкий matcher адресов.
- Внутри: Один existing check и его scoped regression/independent QA.
- За границей: Другие checks и hardware claims.
- Файлы/контракт: analysis/policy_checks.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/031; размер S.
- Приёмка и проверки: Точные semantic micro predicates ниже; positive/negative/unknown и evidence без потерь.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: existing-check:FW-ANY-ANY.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-031-01` | ANY-ANY normalized universe predicate | planned |
| `XS-R4-031-02` | ANY-ANY IPv6 universe predicate | planned |
| `XS-R4-031-03` | ANY-ANY unresolved alias branch | planned |
| `XS-R4-031-04` | ANY-ANY evidence formatter | planned |

<a id="step-r4-032"></a>
## STEP-R4-032 — FW-DUPLICATE — равенство matcher и эффекта

- Результат: FW-DUPLICATE — равенство matcher и эффекта.
- Внутри: Один existing check и его scoped regression/independent QA.
- За границей: Другие checks и hardware claims.
- Файлы/контракт: analysis/policy_checks.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/032; размер S.
- Приёмка и проверки: Точные semantic micro predicates ниже; positive/negative/unknown и evidence без потерь.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: existing-check:FW-DUPLICATE.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-032-01` | DUPLICATE matcher equality | planned |
| `XS-R4-032-02` | DUPLICATE effect equality | planned |
| `XS-R4-032-03` | DUPLICATE binding/time guard | planned |
| `XS-R4-032-04` | DUPLICATE evidence pair | planned |

<a id="step-r4-033"></a>
## STEP-R4-033 — FW-SHADOWED — полное покрытие одним предыдущим правилом

- Результат: FW-SHADOWED — полное покрытие одним предыдущим правилом.
- Внутри: Один existing check и его scoped regression/independent QA.
- За границей: Другие checks и hardware claims.
- Файлы/контракт: analysis/policy_checks.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/033; размер S.
- Приёмка и проверки: Точные semantic micro predicates ниже; positive/negative/unknown и evidence без потерь.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: existing-check:FW-SHADOWED.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-033-01` | SHADOWED single-predecessor eligibility | planned |
| `XS-R4-033-02` | SHADOWED full coverage | planned |
| `XS-R4-033-03` | SHADOWED unknown-order branch | planned |
| `XS-R4-033-04` | SHADOWED witness | planned |

<a id="step-r4-034"></a>
## STEP-R4-034 — FW-MERGE-CANDIDATE — сжатие без расширения доступа

- Результат: FW-MERGE-CANDIDATE — сжатие без расширения доступа.
- Внутри: Один existing check и его scoped regression/independent QA.
- За границей: Другие checks и hardware claims.
- Файлы/контракт: analysis/policy_checks.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/034; размер S.
- Приёмка и проверки: Точные semantic micro predicates ниже; positive/negative/unknown и evidence без потерь.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: existing-check:FW-MERGE-CANDIDATE.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-034-01` | MERGE address/service correlation guard | planned |
| `XS-R4-034-02` | MERGE action/binding compatibility | planned |
| `XS-R4-034-03` | MERGE no-broadening verifier | planned |
| `XS-R4-034-04` | MERGE candidate formatter | planned |

<a id="step-r4-035"></a>
## STEP-R4-035 — FW-LOGGING — регистрация событий по назначению

- Результат: FW-LOGGING — регистрация событий по назначению.
- Внутри: Один existing check и его scoped regression/independent QA.
- За границей: Другие checks и hardware claims.
- Файлы/контракт: analysis/policy_checks.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/035; размер S.
- Приёмка и проверки: Точные semantic micro predicates ниже; positive/negative/unknown и evidence без потерь.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: existing-check:FW-LOGGING.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-035-01` | LOGGING configured value reader | planned |
| `XS-R4-035-02` | LOGGING inherited/default resolver | planned |
| `XS-R4-035-03` | LOGGING unavailable effective branch | planned |
| `XS-R4-035-04` | LOGGING intent evidence | planned |

<a id="step-r4-036"></a>
## STEP-R4-036 — FW-COMMENTS — описание намерения

- Результат: FW-COMMENTS — описание намерения.
- Внутри: Один existing check и его scoped regression/independent QA.
- За границей: Другие checks и hardware claims.
- Файлы/контракт: analysis/policy_checks.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/036; размер S.
- Приёмка и проверки: Точные semantic micro predicates ниже; positive/negative/unknown и evidence без потерь.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: existing-check:FW-COMMENTS.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-036-01` | COMMENTS normalized intent predicate | planned |
| `XS-R4-036-02` | COMMENTS profile-required predicate | planned |
| `XS-R4-036-03` | COMMENTS unsupported metadata branch | planned |
| `XS-R4-036-04` | COMMENTS evidence formatter | planned |

<a id="step-r4-037"></a>
## STEP-R4-037 — FW-DISABLED — lifecycle отключённых правил

- Результат: FW-DISABLED — lifecycle отключённых правил.
- Внутри: Один existing check и его scoped regression/independent QA.
- За границей: Другие checks и hardware claims.
- Файлы/контракт: analysis/policy_checks.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/037; размер S.
- Приёмка и проверки: Точные semantic micro predicates ниже; positive/negative/unknown и evidence без потерь.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: existing-check:FW-DISABLED.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-037-01` | DISABLED lifecycle classifier | planned |
| `XS-R4-037-02` | DISABLED effective-policy exclusion | planned |
| `XS-R4-037-03` | DISABLED recommendation formatter | planned |
| `XS-R4-037-04` | DISABLED known/unknown normalization | planned |

<a id="step-r4-038"></a>
## STEP-R4-038 — Structured evidence/templates новой семантики

- Результат: Structured evidence/templates новой семантики.
- Внутри: Structured evidence/templates новой семантики; необходимые регрессии и независимая приёмка этого результата.
- За границей: Exception workflow.
- Файлы/контракт: interfaces/desktop/check_presentation.py;  interfaces/desktop/result_presentation.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/038; размер S.
- Приёмка и проверки: Witness/dependency/source scope сохранены Qt/HTML/raw; no mutation, correlation не теряет findings.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: checks:CHECK-UX-01, ux:UX05-A, ux:UX05-C, ux:UX05-D, ux:UX05-F.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-038-01` | Finding correlation key | planned |
| `XS-R4-038-02` | New-check witness field formatter | planned |
| `XS-R4-038-03` | Unknown dependency formatter | planned |
| `XS-R4-038-04` | Qt evidence field action | planned |
| `XS-R4-038-05` | HTML evidence field formatter | planned |

<a id="step-r4-039a"></a>
## STEP-R4-039A — Проекция новых полей правил

- Результат: Проекция новых полей правил.
- Внутри: Проекция новых полей правил; необходимые регрессии и независимая приёмка этого результата.
- За границей: Object graph view.
- Файлы/контракт: interfaces/desktop/resource_details.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/039A; размер S.
- Приёмка и проверки: Exact new dimensions доступны/readable; unknown/source anchors/keyboard/selection сохраняются.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: ux:UX03-A, ux:UX03-B, ux:UX03-D, ux:UX03-E, ux:UX04-A, ux:UX04-B, ux:UX04-E, ux:UX04-F.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-039A-01` | Rule semantic column formatter | planned |
| `XS-R4-039A-02` | Rule source-anchor action | planned |
| `XS-R4-039A-03` | Rule filter restore action | planned |

<a id="step-r4-039b"></a>
## STEP-R4-039B — Проекция новых object semantics

- Результат: Проекция новых object semantics.
- Внутри: Проекция новых object semantics; необходимые регрессии и независимая приёмка этого результата.
- За границей: Check computation.
- Файлы/контракт: interfaces/desktop/object_presentation.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/039B; размер S.
- Приёмка и проверки: Typed/missing/cyclic refs показаны без crash; scoped navigation exact.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: ux:UX04-C.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-039B-01` | Typed object-reference row | planned |
| `XS-R4-039B-02` | Malformed-reference error formatter | planned |
| `XS-R4-039B-03` | Object source-anchor action | planned |

<a id="step-r4-040"></a>
## STEP-R4-040 — UI плана checks и параметров

- Результат: UI плана checks и параметров.
- Внутри: UI плана checks и параметров; необходимые регрессии и независимая приёмка этого результата.
- За границей: Обязательная анкета до файлов.
- Файлы/контракт: interfaces/desktop/qt_app.py;  interfaces/desktop/check_presentation.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/040; размер S.
- Приёмка и проверки: Applicability/defaults/units/dependencies видны до запуска; неподготовленный profile не false safe.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-07, ux:UX07-B, journey-screen:J07.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-040-01` | Applicable check-list helper | planned |
| `XS-R4-040-02` | Parameter units/default formatter | planned |
| `XS-R4-040-03` | Missing dependency warning | planned |
| `XS-R4-040-04` | Run-plan submit action | planned |

<a id="step-r4-041"></a>
## STEP-R4-041 — CLI checks/control parity

- Результат: CLI checks/control parity.
- Внутри: CLI checks/control parity; необходимые регрессии и независимая приёмка этого результата.
- За границей: Удалённый API.
- Файлы/контракт: interfaces/cli/main.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/041; размер S.
- Приёмка и проверки: Registry parameters и control statuses совпадают с library; useful errors/exit codes.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-041-01` | CLI registry parameter validator | planned |
| `XS-R4-041-02` | CLI control selector validator | planned |
| `XS-R4-041-03` | CLI status formatter | planned |
| `XS-R4-041-04` | CLI error exit mapping | planned |

<a id="step-r4-042"></a>
## STEP-R4-042 — Независимый A/existing-check corpus report

- Результат: Независимый A/existing-check corpus report.
- Внутри: Независимый A/existing-check corpus report; необходимые регрессии и независимая приёмка этого результата.
- За границей: Claim99.9 по test count.
- Файлы/контракт: tests fixtures;  предлагаемый A metrics report.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/042; размер S.
- Приёмка и проверки: 12NEW A и existing7 имеют positive/negative/unknown, witnesses и отдельный holdout per claim; unsupported/coverage опубликованы.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: checks:CHECK-Q-01.
- Раскрытие: До GO перечислить actual controls/checks/views/matrix cells/participants по исходному протоколу; стабильные дополнительные XS, один элемент на leaf. Закрытие родителя запрещено до покрытия roster.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-042-01` | Single-check metric-row schema | planned |
| `XS-R4-042-02` | Oracle independence validator | planned |
| `XS-R4-042-03` | Scoped confidence formatter | planned |

<a id="step-r4-043"></a>
## STEP-R4-043 — Help/capability catalog R4

- Результат: Help/capability catalog R4.
- Внутри: Help/capability catalog R4; необходимые регрессии и независимая приёмка этого результата.
- За границей: План как готовая поддержка.
- Файлы/контракт: specifications/USER_GUIDE.md;  parsers/catalog.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R4/043; размер S.
- Приёмка и проверки: Exact format/version и check boundaries объясняют unsupported; primary sources versioned.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-18, ux:UX07-B.
- Раскрытие: До GO перечислить actual controls/checks/views/matrix cells/participants по исходному протоколу; стабильные дополнительные XS, один элемент на leaf. Закрытие родителя запрещено до покрытия roster.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-043-01` | Supported platform capability help entry | planned |
| `XS-R4-043-02` | Check parameter help entry contract | planned |
| `XS-R4-043-03` | Supported source link action | planned |

<a id="step-r4-044"></a>
## STEP-R4-044 — Независимый R4 gate

- Результат: Независимый R4 gate.
- Внутри: Независимый R4 gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Новая Cisco expansion.
- Файлы/контракт: предлагаемый R4 acceptance artifact.
- Зависимости: STEP-R4-001, STEP-R4-002, STEP-R4-003, STEP-R4-004, STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R4-009, STEP-R4-010, STEP-R4-011, STEP-R4-012, STEP-R4-013, STEP-R4-014, STEP-R4-015, STEP-R4-016, STEP-R4-017, STEP-R4-018, STEP-R4-019, STEP-R4-020, STEP-R4-021, STEP-R4-022, STEP-R4-023, STEP-R4-024, STEP-R4-025, STEP-R4-026, STEP-R4-027, STEP-R4-028, STEP-R4-029, STEP-R4-030, STEP-R4-031, STEP-R4-032, STEP-R4-033, STEP-R4-034, STEP-R4-035, STEP-R4-036, STEP-R4-037, STEP-R4-038, STEP-R4-039A, STEP-R4-039B, STEP-R4-040, STEP-R4-041, STEP-R4-042, STEP-R4-043. Порядок: R4/044; размер S.
- Приёмка и проверки: Declared profiles+catalog+12A+7existing gates; regression/native/CLI/evidence independent QA; неизвестная firmware открыта.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: stage:R4.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R4-044-01` | Parser-profile gate record | planned |
| `XS-R4-044-02` | Control-catalog parity gate | planned |
| `XS-R4-044-03` | Twelve-A evidence gate | planned |
| `XS-R4-044-04` | Existing-seven evidence gate | planned |
| `XS-R4-044-05` | Native/CLI evidence gate | planned |
