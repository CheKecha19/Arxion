# R6: небольшие шаги реализации

[Вход и правила](../IMPLEMENTATION_STEPS.md) · [Матрица покрытия](COVERAGE.md)

Каждый XS включает свой код/документ и focused проверку. Будущие проверки ещё не выполнены. Пути модулей относительно src/firewall_compliance/, кроме явных artifacts/specifications/tests/scripts; предлагаемые модули разрешаются JIT до GO. accepted_bounded_existing_evidence означает только historical synthetic U01–U06, не полную приёмку всех связанных UX требований.

<a id="step-r6-001"></a>
## STEP-R6-001 — Versioned organization profile schema

- Результат: Versioned organization profile schema.
- Внутри: Versioned organization profile schema; необходимые регрессии и независимая приёмка этого результата.
- За границей: Profile editor.
- Файлы/контракт: предлагаемый domain/organization_profile.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/001; размер S.
- Приёмка и проверки: Defaults/thresholds/units/required fields valid; historical versions immutable.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: checks:CHECK-ARCH-04, ux:UX07-C.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-001-01` | Profile version ID validator | planned |
| `XS-R6-001-02` | Profile units/default validator | planned |
| `XS-R6-001-03` | Immutable profile update guard | planned |
| `XS-R6-001-04` | Unsupported profile reader | planned |

<a id="step-r6-002"></a>
## STEP-R6-002 — Asset/service registry

- Результат: Asset/service registry.
- Внутри: Asset/service registry; необходимые регрессии и независимая приёмка этого результата.
- За границей: Auto-classification по IP.
- Файлы/контракт: предлагаемый domain/organization_profile.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/002; размер S.
- Приёмка и проверки: Asset ID/address/service/role/environment scopes exact; overlaps/unknown category явны.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R6:C02, checks:CHECK-B-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-002-01` | Asset scoped ID | planned |
| `XS-R6-002-02` | Asset address-set validator | planned |
| `XS-R6-002-03` | Asset service resolver | planned |
| `XS-R6-002-04` | Ambiguous asset category branch | planned |

<a id="step-r6-003"></a>
## STEP-R6-003 — Directed segmentation matrix

- Результат: Directed segmentation matrix.
- Внутри: Directed segmentation matrix; необходимые регрессии и независимая приёмка этого результата.
- За границей: Path engine.
- Файлы/контракт: предлагаемый domain/organization_profile.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/003; размер S.
- Приёмка и проверки: Allowed/forbidden direction exact; category ambiguity unknown.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-003-01` | Directed category-pair key | planned |
| `XS-R6-003-02` | Allowed-flow relation validator | planned |
| `XS-R6-003-03` | Forbidden-flow relation validator | planned |
| `XS-R6-003-04` | Unspecified intent unknown | planned |

<a id="step-r6-004"></a>
## STEP-R6-004 — Profile storage/version activation

- Результат: Profile storage/version activation.
- Внутри: Profile storage/version activation; необходимые регрессии и независимая приёмка этого результата.
- За границей: In-place profile edit.
- Файлы/контракт: предлагаемый profile store;  interfaces/desktop/organization_workspace.py.
- Зависимости: STEP-R6-001, STEP-R2-012. Порядок: R6/004; размер S.
- Приёмка и проверки: Run pins exact immutable version; later edits не rewrite; cancel сохраняет прежнюю.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: checks:CHECK-ARCH-04, storage:DATA-07.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-004-01` | Saved profile version write | planned |
| `XS-R6-004-02` | Run profile reference capture | planned |
| `XS-R6-004-03` | Profile activation action | planned |
| `XS-R6-004-04` | Historical profile reader | planned |

<a id="step-r6-005"></a>
## STEP-R6-005 — Exception lifecycle model

- Результат: Exception lifecycle model.
- Внутри: Exception lifecycle model; необходимые регрессии и независимая приёмка этого результата.
- За границей: Finding deletion.
- Файлы/контракт: предлагаемый domain/exception.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/005; размер S.
- Приёмка и проверки: ID/scope/owner/basis/start/end/evidence validated; expired not applied.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: ux:UX07-D, checks:CHECK-ARCH-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-005-01` | Exception scoped-target validator | planned |
| `XS-R6-005-02` | Exception owner/basis validator | planned |
| `XS-R6-005-03` | Exception TZ start/end validator | planned |
| `XS-R6-005-04` | Missing expiry branch | planned |
| `XS-R6-005-05` | Expired-exception predicate | planned |

<a id="step-r6-006"></a>
## STEP-R6-006 — Применение exceptions как отдельного решения

- Результат: Применение exceptions как отдельного решения.
- Внутри: Применение exceptions как отдельного решения; необходимые регрессии и независимая приёмка этого результата.
- За границей: Исключение как отсутствие нарушения.
- Файлы/контракт: analysis/policy_checks.py;  предлагаемый decision API.
- Зависимости: STEP-R6-005. Порядок: R6/006; размер S.
- Приёмка и проверки: Raw finding остаётся; applicability/exception/as-of отдельно; overlapping exceptions explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: ux:UX05-E, ux:UX07-D.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-006-01` | Raw finding immutable guard | planned |
| `XS-R6-006-02` | Exception applicability predicate | planned |
| `XS-R6-006-03` | Effective finding-status projection | planned |
| `XS-R6-006-04` | As-of exception selector | planned |

<a id="step-r6-007"></a>
## STEP-R6-007 — Profile editor UI

- Результат: Profile editor UI.
- Внутри: Profile editor UI; необходимые регрессии и независимая приёмка этого результата.
- За границей: Обязательная анкета.
- Файлы/контракт: предлагаемый profile editor;  interfaces/desktop/qt_app.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/007; размер S.
- Приёмка и проверки: Fields/defaults/units validated; cancel не сохраняет; run plan объясняет missing.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: ux:UX07-C, journey-screen:J07.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-007-01` | Profile threshold widget action | planned |
| `XS-R6-007-02` | Profile category widget action | planned |
| `XS-R6-007-03` | Profile units widget action | planned |
| `XS-R6-007-04` | Validate-and-save profile action | planned |
| `XS-R6-007-05` | Cancel edit preserves version | planned |

<a id="step-r6-008"></a>
## STEP-R6-008 — Exceptions/history UI

- Результат: Exceptions/history UI.
- Внутри: Exceptions/history UI; необходимые регрессии и независимая приёмка этого результата.
- За границей: Скрытая массовая exception.
- Файлы/контракт: предлагаемый exception view;  interfaces/desktop/workspace_history.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/008; размер S.
- Приёмка и проверки: Narrow scope/expiry явны; history после restart; user decision не actual remediation.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: ux:UX07-D, journey-task:JRN-10.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-008-01` | Narrow exception target action | planned |
| `XS-R6-008-02` | Expiry editor action | planned |
| `XS-R6-008-03` | Decision-history row | planned |
| `XS-R6-008-04` | Restart selection restore | planned |

<a id="step-r6-009"></a>
## STEP-R6-009 — NEW-01 / B / FW-MANAGEMENT-UNTRUSTED — административное разрешение вне допустимого источника

- Результат: NEW-01 / B / FW-MANAGEMENT-UNTRUSTED — административное разрешение вне допустимого источника.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/009; размер S.
- Приёмка и проверки: management service predicate; approved source set resolver; untrusted permit witness; missing profile unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-01, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-009-01` | NEW-01: management service predicate | planned |
| `XS-R6-009-02` | NEW-01: approved source set resolver | planned |
| `XS-R6-009-03` | NEW-01: untrusted permit witness | planned |
| `XS-R6-009-04` | NEW-01: missing profile unknown | planned |
| `XS-R6-009-05` | NEW-01: registry wire после predicate gates | planned |

<a id="step-r6-010"></a>
## STEP-R6-010 — NEW-02 / B / FW-DATABASE-EXPOSURE — доступ к зарегистрированной БД из запрещённой категории

- Результат: NEW-02 / B / FW-DATABASE-EXPOSURE — доступ к зарегистрированной БД из запрещённой категории.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/010; размер S.
- Приёмка и проверки: registered DB/service intersection; forbidden category predicate; exposure witness; unregistered asset unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-02, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-010-01` | NEW-02: registered DB/service intersection | planned |
| `XS-R6-010-02` | NEW-02: forbidden category predicate | planned |
| `XS-R6-010-03` | NEW-02: exposure witness | planned |
| `XS-R6-010-04` | NEW-02: unregistered asset unknown | planned |
| `XS-R6-010-05` | NEW-02: registry wire после predicate gates | planned |

<a id="step-r6-011"></a>
## STEP-R6-011 — NEW-07 / B / FW-UNRESTRICTED-EGRESS — все сервисы из доверенной в недоверенную область

- Результат: NEW-07 / B / FW-UNRESTRICTED-EGRESS — все сервисы из доверенной в недоверенную область.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/011; размер S.
- Приёмка и проверки: trusted/untrusted category resolver; all-services universe predicate; egress intersection witness; ambiguous category unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-07, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-011-01` | NEW-07: trusted/untrusted category resolver | planned |
| `XS-R6-011-02` | NEW-07: all-services universe predicate | planned |
| `XS-R6-011-03` | NEW-07: egress intersection witness | planned |
| `XS-R6-011-04` | NEW-07: ambiguous category unknown | planned |
| `XS-R6-011-05` | NEW-07: registry wire после predicate gates | planned |

<a id="step-r6-012"></a>
## STEP-R6-012 — NEW-08 / B / FW-SEGMENTATION-MATRIX — пересечение с запрещённым потоком

- Результат: NEW-08 / B / FW-SEGMENTATION-MATRIX — пересечение с запрещённым потоком.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/012; размер S.
- Приёмка и проверки: directed matrix lookup; forbidden flow intersection; reverse-flow nonequivalence guard; unknown intent; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-08, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-012-01` | NEW-08: directed matrix lookup | planned |
| `XS-R6-012-02` | NEW-08: forbidden flow intersection | planned |
| `XS-R6-012-03` | NEW-08: reverse-flow nonequivalence guard | planned |
| `XS-R6-012-04` | NEW-08: unknown intent | planned |
| `XS-R6-012-05` | NEW-08: registry wire после predicate gates | planned |

<a id="step-r6-013"></a>
## STEP-R6-013 — NEW-17 / B / FW-EXPIRED-TEMPORARY-PERMIT — срок истёк, разрешение ещё действует в настройках

- Результат: NEW-17 / B / FW-EXPIRED-TEMPORARY-PERMIT — срок истёк, разрешение ещё действует в настройках.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/013; размер S.
- Приёмка и проверки: timezone/as-of comparator; still-active permit predicate; expired temporary witness; unknown expiry; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-17, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-013-01` | NEW-17: timezone/as-of comparator | planned |
| `XS-R6-013-02` | NEW-17: still-active permit predicate | planned |
| `XS-R6-013-03` | NEW-17: expired temporary witness | planned |
| `XS-R6-013-04` | NEW-17: unknown expiry | planned |
| `XS-R6-013-05` | NEW-17: registry wire после predicate gates | planned |

<a id="step-r6-014"></a>
## STEP-R6-014 — NEW-18 / B / FW-TEMPORARY-PERMIT-WITHOUT-END — временное разрешение без конечного срока

- Результат: NEW-18 / B / FW-TEMPORARY-PERMIT-WITHOUT-END — временное разрешение без конечного срока.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/014; размер S.
- Приёмка и проверки: explicit temporary predicate; missing finite end predicate; unsupported metadata unknown; temporary witness; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-18, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-014-01` | NEW-18: explicit temporary predicate | planned |
| `XS-R6-014-02` | NEW-18: missing finite end predicate | planned |
| `XS-R6-014-03` | NEW-18: unsupported metadata unknown | planned |
| `XS-R6-014-04` | NEW-18: temporary witness | planned |
| `XS-R6-014-05` | NEW-18: registry wire после predicate gates | planned |

<a id="step-r6-015"></a>
## STEP-R6-015 — NEW-19 / B / FW-MISSING-OWNER-CHANGE-BASIS — нет обязательного владельца или основания

- Результат: NEW-19 / B / FW-MISSING-OWNER-CHANGE-BASIS — нет обязательного владельца или основания.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/015; размер S.
- Приёмка и проверки: owner-required predicate; basis-required predicate; proven missing metadata; unsupported metadata unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-19, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-015-01` | NEW-19: owner-required predicate | planned |
| `XS-R6-015-02` | NEW-19: basis-required predicate | planned |
| `XS-R6-015-03` | NEW-19: proven missing metadata | planned |
| `XS-R6-015-04` | NEW-19: unsupported metadata unknown | planned |
| `XS-R6-015-05` | NEW-19: registry wire после predicate gates | planned |

<a id="step-r6-016"></a>
## STEP-R6-016 — NEW-21 / B / FW-LOG-RECEIVER-MISSING — внешний получатель не соответствует профилю

- Результат: NEW-21 / B / FW-LOG-RECEIVER-MISSING — внешний получатель не соответствует профилю.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/016; размер S.
- Приёмка и проверки: log-receiver endpoint normalization; approved receiver membership; proven missing configured receiver; runtime delivery claim guard; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-21, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-016-01` | NEW-21: log-receiver endpoint normalization | planned |
| `XS-R6-016-02` | NEW-21: approved receiver membership | planned |
| `XS-R6-016-03` | NEW-21: proven missing configured receiver | planned |
| `XS-R6-016-04` | NEW-21: runtime delivery claim guard | planned |
| `XS-R6-016-05` | NEW-21: registry wire после predicate gates | planned |

<a id="step-r6-017"></a>
## STEP-R6-017 — NEW-22 / B / FW-NTP-PROFILE — нет approved time source в настройках

- Результат: NEW-22 / B / FW-NTP-PROFILE — нет approved time source в настройках.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/017; размер S.
- Приёмка и проверки: NTP source normalization; approved NTP membership; proven missing configured source; runtime sync claim guard; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-22, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-017-01` | NEW-22: NTP source normalization | planned |
| `XS-R6-017-02` | NEW-22: approved NTP membership | planned |
| `XS-R6-017-03` | NEW-22: proven missing configured source | planned |
| `XS-R6-017-04` | NEW-22: runtime sync claim guard | planned |
| `XS-R6-017-05` | NEW-22: registry wire после predicate gates | planned |

<a id="step-r6-018"></a>
## STEP-R6-018 — NEW-23 / B / FW-SNMP-LEGACY-SCOPE — SNMP v1/v2c вне approved management set

- Результат: NEW-23 / B / FW-SNMP-LEGACY-SCOPE — SNMP v1/v2c вне approved management set.
- Внутри: Один check: exact predicate/witness/unknown branch; independent oracle и focused regression.
- За границей: Соседние checks, автоматическое исправление, непроверенные operational claims.
- Файлы/контракт: analysis/policy_checks.py; domain/policy_matching.py.
- Зависимости: STEP-R4-005, STEP-R4-006, STEP-R4-007, STEP-R4-008, STEP-R0-006, STEP-R6-004. Порядок: R6/018; размер S.
- Приёмка и проверки: SNMP version decoder; legacy version predicate; approved management set difference; incomplete profile/SNMP unknown; positive/negative/unknown случаи с независимыми expected и сохранением evidence scope.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: new-check:NEW-23, package:R6:C02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-018-01` | NEW-23: SNMP version decoder | planned |
| `XS-R6-018-02` | NEW-23: legacy version predicate | planned |
| `XS-R6-018-03` | NEW-23: approved management set difference | planned |
| `XS-R6-018-04` | NEW-23: incomplete profile/SNMP unknown | planned |
| `XS-R6-018-05` | NEW-23: registry wire после predicate gates | planned |

<a id="step-r6-019"></a>
## STEP-R6-019 — Huawei VRP selected-release passport

- Результат: Huawei VRP selected-release passport.
- Внутри: Huawei VRP selected-release passport; необходимые регрессии и независимая приёмка этого результата.
- За границей: Comware grammar по сходству.
- Файлы/контракт: parsers/catalog.py;  предлагаемый Huawei source bundle.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/019; размер S.
- Приёмка и проверки: ACL family/format/version/sample hash documented.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R6:V04, platform:V04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-019-01` | Huawei version/format key | planned |
| `XS-R6-019-02` | Huawei primary-source sample validator | planned |

<a id="step-r6-020"></a>
## STEP-R6-020 — Huawei ACL grammar

- Результат: Huawei ACL grammar.
- Внутри: Huawei ACL grammar; необходимые регрессии и независимая приёмка этого результата.
- За границей: Все releases supported.
- Файлы/контракт: предлагаемый parsers/huawei_vrp.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/020; размер S.
- Приёмка и проверки: Basic/advanced declared syntax source mapped; unknown token local.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-020-01` | Huawei basic-ACL address decoder | planned |
| `XS-R6-020-02` | Huawei advanced-ACL source decoder | planned |
| `XS-R6-020-03` | Huawei destination decoder | planned |
| `XS-R6-020-04` | Huawei protocol decoder | planned |
| `XS-R6-020-05` | Huawei source-port decoder | planned |
| `XS-R6-020-06` | Huawei destination-port decoder | planned |
| `XS-R6-020-07` | Huawei rule-order number | planned |
| `XS-R6-020-08` | Huawei source map | planned |
| `XS-R6-020-09` | Huawei unknown syntax branch | planned |

<a id="step-r6-021"></a>
## STEP-R6-021 — Huawei groups/resolver

- Результат: Huawei groups/resolver.
- Внутри: Huawei groups/resolver; необходимые регрессии и независимая приёмка этого результата.
- За границей: Guess object values.
- Файлы/контракт: предлагаемый parsers/huawei_vrp.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/021; размер S.
- Приёмка и проверки: Typed refs/ranges/groups только documented syntax; cycle/missing explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-021-01` | Huawei object key | planned |
| `XS-R6-021-02` | Huawei group-member resolver | planned |
| `XS-R6-021-03` | Huawei missing-target branch | planned |
| `XS-R6-021-04` | Huawei cycle branch | planned |

<a id="step-r6-022"></a>
## STEP-R6-022 — Huawei interface/binding/order

- Результат: Huawei interface/binding/order.
- Внутри: Huawei interface/binding/order; необходимые регрессии и независимая приёмка этого результата.
- За границей: Comware defaults.
- Файлы/контракт: предлагаемый parsers/huawei_vrp.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/022; размер S.
- Приёмка и проверки: Release attachment/direction/default/order exact и independently checked.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V04, platform:V-GATE.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-022-01` | Huawei interface attachment | planned |
| `XS-R6-022-02` | Huawei direction decoder | planned |
| `XS-R6-022-03` | Huawei selected-release order key | planned |
| `XS-R6-022-04` | Huawei default-action unknown | planned |

<a id="step-r6-023"></a>
## STEP-R6-023 — Huawei check/map gate

- Результат: Huawei check/map gate.
- Внутри: Huawei check/map gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Operational99.9.
- Файлы/контракт: application/acl_map.py;  предлагаемый Huawei lab.
- Зависимости: STEP-R6-020, STEP-R6-021, STEP-R6-022, STEP-R4-008. Порядок: R6/023; размер S.
- Приёмка и проверки: Source-backed versioned independent cases end-to-end; actual limits.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V04, platform:V-GATE.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-023-01` | Huawei checks wire | planned |
| `XS-R6-023-02` | Huawei map wire | planned |
| `XS-R6-023-03` | Huawei positive reference | planned |
| `XS-R6-023-04` | Huawei negative reference | planned |
| `XS-R6-023-05` | Huawei unknown reference | planned |

<a id="step-r6-024"></a>
## STEP-R6-024 — Junos set-format passport/decoder

- Результат: Junos set-format passport/decoder.
- Внутри: Junos set-format passport/decoder; необходимые регрессии и независимая приёмка этого результата.
- За границей: Hierarchy grammar.
- Файлы/контракт: предлагаемый parsers/junos.py;  parsers/catalog.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/024; размер S.
- Приёмка и проверки: Versioned set grammar/source spans exact; unknown tokens explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R6:V05, platform:V05-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-024-01` | Junos set tokenizer | planned |
| `XS-R6-024-02` | Junos quoted escape decoder | planned |
| `XS-R6-024-03` | Junos release-format passport | planned |
| `XS-R6-024-04` | Junos set context path | planned |

<a id="step-r6-025"></a>
## STEP-R6-025 — Junos ordered filter terms/actions

- Результат: Junos ordered filter terms/actions.
- Внутри: Junos ordered filter terms/actions; необходимые регрессии и независимая приёмка этого результата.
- За границей: SRX zone policy.
- Файлы/контракт: предлагаемый parsers/junos.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/025; размер S.
- Приёмка и проверки: Ordered terms/conditions/nonterminating actions/default exact; independent oracle.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V05-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-025-01` | Junos term order reducer | planned |
| `XS-R6-025-02` | Junos source-address condition | planned |
| `XS-R6-025-03` | Junos destination-address condition | planned |
| `XS-R6-025-04` | Junos protocol condition | planned |
| `XS-R6-025-05` | Junos port condition | planned |
| `XS-R6-025-06` | Junos terminating action | planned |
| `XS-R6-025-07` | Junos nonterminating action | planned |
| `XS-R6-025-08` | Junos default-action resolver | planned |

<a id="step-r6-026"></a>
## STEP-R6-026 — Junos hierarchy parser

- Результат: Junos hierarchy parser.
- Внутри: Junos hierarchy parser; необходимые регрессии и независимая приёмка этого результата.
- За границей: Set parser reused blindly.
- Файлы/контракт: предлагаемый parsers/junos.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/026; размер S.
- Приёмка и проверки: Braces/comments/quotes/context normalize without loss; malformed explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V05-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-026-01` | Junos brace tokenizer | planned |
| `XS-R6-026-02` | Junos hierarchy stack transition | planned |
| `XS-R6-026-03` | Junos comment/quoted-brace branch | planned |
| `XS-R6-026-04` | Junos facts normalizer | planned |

<a id="step-r6-027"></a>
## STEP-R6-027 — Junos set↔hierarchy differential

- Результат: Junos set↔hierarchy differential.
- Внутри: Junos set↔hierarchy differential; необходимые регрессии и независимая приёмка этого результата.
- За границей: Oracle из production parser.
- Файлы/контракт: предлагаемые Junos fixtures.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/027; размер S.
- Приёмка и проверки: Independent equivalent exports same facts; inactive/replace/unsupported explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V05-A, platform:V-GATE.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-027-01` | Equivalent set/hierarchy differential case | planned |
| `XS-R6-027-02` | Inactive hierarchy branch | planned |
| `XS-R6-027-03` | Replace-semantics branch | planned |
| `XS-R6-027-04` | Unsupported hierarchy case | planned |

<a id="step-r6-028"></a>
## STEP-R6-028 — Junos filter attachments

- Результат: Junos filter attachments.
- Внутри: Junos filter attachments; необходимые регрессии и независимая приёмка этого результата.
- За границей: SRX binding.
- Файлы/контракт: предлагаемый parsers/junos.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/028; размер S.
- Приёмка и проверки: Interface/family/direction/filter chain exact; absent unknown.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V05-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-028-01` | Junos family attachment | planned |
| `XS-R6-028-02` | Junos direction attachment | planned |
| `XS-R6-028-03` | Junos ordered filter chain | planned |

<a id="step-r6-029"></a>
## STEP-R6-029 — SRX zone-policy passport

- Результат: SRX zone-policy passport.
- Внутри: SRX zone-policy passport; необходимые регрессии и независимая приёмка этого результата.
- За границей: Firewall filters как SRX policy.
- Файлы/контракт: parsers/catalog.py;  предлагаемый SRX source bundle.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/029; размер S.
- Приёмка и проверки: SRX semantic scope/source/version separately documented.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V05-B.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-029-01` | SRX version/format passport | planned |
| `XS-R6-029-02` | Filter-vs-zone policy guard | planned |

<a id="step-r6-030"></a>
## STEP-R6-030 — SRX address/application resolver

- Результат: SRX address/application resolver.
- Внутри: SRX address/application resolver; необходимые регрессии и независимая приёмка этого результата.
- За границей: Global name-only match.
- Файлы/контракт: предлагаемый parsers/junos.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/030; размер S.
- Приёмка и проверки: Zone/global address-book scope и application-set refs exact; cycles/missing явны.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V05-B.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-030-01` | Zone address-book scoped key | planned |
| `XS-R6-030-02` | Global address lookup | planned |
| `XS-R6-030-03` | Application member decoder | planned |
| `XS-R6-030-04` | Application-set resolver | planned |
| `XS-R6-030-05` | SRX cycle branch | planned |
| `XS-R6-030-06` | SRX missing-target branch | planned |

<a id="step-r6-031"></a>
## STEP-R6-031 — SRX policy order/bindings

- Результат: SRX policy order/bindings.
- Внутри: SRX policy order/bindings; необходимые регрессии и независимая приёмка этого результата.
- За границей: Reverse flow implicit.
- Файлы/контракт: предлагаемый parsers/junos.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/031; размер S.
- Приёмка и проверки: From-zone→to-zone order/actions exact; ambiguity unknown.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V05-B.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-031-01` | From/to-zone pair key | planned |
| `XS-R6-031-02` | SRX policy-order reducer | planned |
| `XS-R6-031-03` | SRX action decoder | planned |
| `XS-R6-031-04` | SRX ambiguous-binding unknown | planned |

<a id="step-r6-032"></a>
## STEP-R6-032 — Junos/SRX independent gates

- Результат: Junos/SRX independent gates.
- Внутри: Junos/SRX independent gates; необходимые регрессии и независимая приёмка этого результата.
- За границей: Hardware proof по synthetic.
- Файлы/контракт: предлагаемый Junos/SRX lab report.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/032; размер S.
- Приёмка и проверки: Filter и zone-policy claims раздельны; documented independent oracle.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V05-A/B, platform:V-GATE.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-032-01` | Junos filter gate | planned |
| `XS-R6-032-02` | SRX policy gate | planned |
| `XS-R6-032-03` | Junos declared-version metric row | planned |
| `XS-R6-032-04` | SRX declared-version metric row | planned |

<a id="step-r6-033"></a>
## STEP-R6-033 — ArubaOS controller passport

- Результат: ArubaOS controller passport.
- Внутри: ArubaOS controller passport; необходимые регрессии и независимая приёмка этого результата.
- За границей: Switch grammar.
- Файлы/контракт: parsers/catalog.py;  предлагаемый ArubaOS source bundle.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/033; размер S.
- Приёмка и проверки: Controller release/session ACL/role export documented.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R6:V06, platform:V06-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-033-01` | ArubaOS controller release passport | planned |
| `XS-R6-033-02` | Session/role export contract | planned |
| `XS-R6-033-03` | Switch-vs-controller guard | planned |

<a id="step-r6-034"></a>
## STEP-R6-034 — ArubaOS session ACL grammar

- Результат: ArubaOS session ACL grammar.
- Внутри: ArubaOS session ACL grammar; необходимые регрессии и независимая приёмка этого результата.
- За границей: AOS-S substitution.
- Файлы/контракт: предлагаемый parsers/arubaos.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/034; размер S.
- Приёмка и проверки: Actions/order/services/roles source mapped; unknown explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V06-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-034-01` | Session ACL action decoder | planned |
| `XS-R6-034-02` | Session ACL rule order | planned |
| `XS-R6-034-03` | Session service protocol decoder | planned |
| `XS-R6-034-04` | Session service port decoder | planned |
| `XS-R6-034-05` | Session unknown-condition branch | planned |

<a id="step-r6-035"></a>
## STEP-R6-035 — ArubaOS role hierarchy

- Результат: ArubaOS role hierarchy.
- Внутри: ArubaOS role hierarchy; необходимые регрессии и независимая приёмка этого результата.
- За границей: Inferred user state.
- Файлы/контракт: предлагаемый parsers/arubaos.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/035; размер S.
- Приёмка и проверки: Role refs/inheritance/user-binding origin точны; cycles/missing unknown.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V06-A.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-035-01` | Role scoped key | planned |
| `XS-R6-035-02` | Parent-role resolver | planned |
| `XS-R6-035-03` | User binding source reference | planned |
| `XS-R6-035-04` | Inheritance cycle branch | planned |
| `XS-R6-035-05` | Missing-role unknown | planned |

<a id="step-r6-036"></a>
## STEP-R6-036 — ArubaOS effective hierarchy/API

- Результат: ArubaOS effective hierarchy/API.
- Внутри: ArubaOS effective hierarchy/API; необходимые регрессии и независимая приёмка этого результата.
- За границей: Undocumented format.
- Файлы/контракт: предлагаемый parsers/arubaos.py;  предлагаемый controller collector.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/036; размер S.
- Приёмка и проверки: Только documented effective output/API; coherence/auth/cancel/partial explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V06-B.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-036-01` | Effective-output/API version guard | planned |
| `XS-R6-036-02` | Effective hierarchy decoder | planned |
| `XS-R6-036-03` | Controller snapshot completeness | planned |
| `XS-R6-036-04` | Ambiguous effective-output branch | planned |

<a id="step-r6-037"></a>
## STEP-R6-037 — ArubaOS check/map gate

- Результат: ArubaOS check/map gate.
- Внутри: ArubaOS check/map gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Operational reachability.
- Файлы/контракт: application/acl_map.py;  предлагаемый controller lab.
- Зависимости: STEP-R6-034, STEP-R6-035, STEP-R6-036, STEP-R4-008. Порядок: R6/037; размер S.
- Приёмка и проверки: Binding/unknown/reference end-to-end independent; version scope explicit.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: platform:V06-A/B, platform:V-GATE.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-037-01` | Controller checks wire | planned |
| `XS-R6-037-02` | Controller map wire | planned |
| `XS-R6-037-03` | Controller positive case | planned |
| `XS-R6-037-04` | Controller negative case | planned |
| `XS-R6-037-05` | Controller unknown case | planned |

<a id="step-r6-038"></a>
## STEP-R6-038 — Source/help для remaining vendors

- Результат: Source/help для remaining vendors.
- Внутри: Source/help для remaining vendors; необходимые регрессии и независимая приёмка этого результата.
- За границей: Unsupported recipe.
- Файлы/контракт: specifications/USER_GUIDE.md;  предлагаемый source guide registry.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/038; размер S.
- Приёмка и проверки: Huawei/Junos/SRX/controller exact format/version/capability steps.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-05, journey-task:JRN-18, journey-screen:J03, journey-screen:J24.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-038-01` | Huawei acquisition guide | planned |
| `XS-R6-038-02` | Junos filter guide | planned |
| `XS-R6-038-03` | SRX guide | planned |
| `XS-R6-038-04` | Controller guide | planned |
| `XS-R6-038-05` | Built-in source-help anchor action | planned |

<a id="step-r6-039"></a>
## STEP-R6-039 — Profile/B findings consumer projection

- Результат: Profile/B findings consumer projection.
- Внутри: Profile/B findings consumer projection; необходимые регрессии и независимая приёмка этого результата.
- За границей: Обновление всех consumers одним XS.
- Файлы/контракт: interfaces/desktop/check_presentation.py;  interfaces/desktop/batch_reports.py;  interfaces/cli/main.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R6/039; размер S.
- Приёмка и проверки: Raw violation/exception/as-of раздельны; исторический profile стабилен; каждый consumer отдельный XS.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: ux:UX05-E, ux:UX07-C, ux:UX07-D.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-039-01` | Profile finding Qt row | planned |
| `XS-R6-039-02` | Exception Qt status | planned |
| `XS-R6-039-03` | Raw violation HTML field | planned |
| `XS-R6-039-04` | As-of HTML manifest | planned |
| `XS-R6-039-05` | CLI profile argument | planned |
| `XS-R6-039-06` | CLI exception status | planned |

<a id="step-r6-040"></a>
## STEP-R6-040 — Независимый R6 gate

- Результат: Независимый R6 gate.
- Внутри: Независимый R6 gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Реальное соответствие по synthetic.
- Файлы/контракт: предлагаемый R6 gate artifact.
- Зависимости: STEP-R6-001, STEP-R6-002, STEP-R6-003, STEP-R6-004, STEP-R6-005, STEP-R6-006, STEP-R6-007, STEP-R6-008, STEP-R6-009, STEP-R6-010, STEP-R6-011, STEP-R6-012, STEP-R6-013, STEP-R6-014, STEP-R6-015, STEP-R6-016, STEP-R6-017, STEP-R6-018, STEP-R6-019, STEP-R6-020, STEP-R6-021, STEP-R6-022, STEP-R6-023, STEP-R6-024, STEP-R6-025, STEP-R6-026, STEP-R6-027, STEP-R6-028, STEP-R6-029, STEP-R6-030, STEP-R6-031, STEP-R6-032, STEP-R6-033, STEP-R6-034, STEP-R6-035, STEP-R6-036, STEP-R6-037, STEP-R6-038, STEP-R6-039. Порядок: R6/040; размер S.
- Приёмка и проверки: 10NEW B positive/negative/unknown + pinned profiles/exceptions + declared vendor slices; real gates открыты.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: stage:R6.
- Раскрытие: До GO перечислить actual controls/checks/views/matrix cells/participants по исходному протоколу; стабильные дополнительные XS, один элемент на leaf. Закрытие родителя запрещено до покрытия roster.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R6-040-01` | B-check evidence ledger schema | planned |
| `XS-R6-040-02` | Profile replay checkpoint | planned |
| `XS-R6-040-03` | Exception as-of checkpoint | planned |
| `XS-R6-040-04` | Huawei checkpoint | planned |
| `XS-R6-040-05` | Junos checkpoint | planned |
| `XS-R6-040-06` | SRX checkpoint | planned |
| `XS-R6-040-07` | Controller checkpoint | planned |
| `XS-R6-040-08` | R6 stage manifest | planned |
