# R8: небольшие шаги реализации

[Вход и правила](../IMPLEMENTATION_STEPS.md) · [Матрица покрытия](COVERAGE.md)

Каждый XS включает свой код/документ и focused проверку. Будущие проверки ещё не выполнены. Пути модулей относительно src/firewall_compliance/, кроме явных artifacts/specifications/tests/scripts; предлагаемые модули разрешаются JIT до GO. accepted_bounded_existing_evidence означает только historical synthetic U01–U06, не полную приёмку всех связанных UX требований.

<a id="step-r8-001"></a>
## STEP-R8-001 — Dependency/build inputs manifest

- Результат: Dependency/build inputs manifest.
- Внутри: Dependency/build inputs manifest; необходимые регрессии и независимая приёмка этого результата.
- За границей: Новый инструмент сборки.
- Файлы/контракт: pyproject.toml;  uv.lock;  scripts/build_desktop.ps1.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/001; размер S.
- Приёмка и проверки: Exact lock/interpreter/PySide/SQLite/PyInstaller/source hashes и recorded environment.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-001-01` | Lockfile hash record | planned |
| `XS-R8-001-02` | Interpreter version record | planned |
| `XS-R8-001-03` | Qt/SQLite runtime record | planned |
| `XS-R8-001-04` | PyInstaller/build-script record | planned |
| `XS-R8-001-05` | Source hash manifest | planned |

<a id="step-r8-002"></a>
## STEP-R8-002 — Portable artifact manifest

- Результат: Portable artifact manifest.
- Внутри: Portable artifact manifest; необходимые регрессии и независимая приёмка этого результата.
- За границей: Claim по исходникам.
- Файлы/контракт: предлагаемый release artifact manifest.
- Зависимости: STEP-R8-001. Порядок: R8/002; размер S.
- Приёмка и проверки: Actual EXE/ZIP hashes/resources/platform limits; bundled assets реально доступны.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-002-01` | EXE hash record | planned |
| `XS-R8-002-02` | ZIP hash record | planned |
| `XS-R8-002-03` | Bundled-resource inventory | planned |
| `XS-R8-002-04` | Portable platform-limits record | planned |

<a id="step-r8-003"></a>
## STEP-R8-003 — Frozen org/migration smoke

- Результат: Frozen org/migration smoke.
- Внутри: Frozen org/migration smoke; необходимые регрессии и независимая приёмка этого результата.
- За границей: Пользовательская БД.
- Файлы/контракт: scripts packaged smoke contract.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/003; размер S.
- Приёмка и проверки: Actual exe 0/1/multi synthetic DB migrate/restart/failure walkthrough; guards active.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-02, journey-task:JRN-15.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-003-01` | Frozen new-DB case | planned |
| `XS-R8-003-02` | Frozen one-project migration case | planned |
| `XS-R8-003-03` | Frozen multiproject migration case | planned |
| `XS-R8-003-04` | Frozen failure-recovery case | planned |
| `XS-R8-003-05` | Frozen restart case | planned |

<a id="step-r8-004"></a>
## STEP-R8-004 — Frozen history/evidence/report smoke

- Результат: Frozen history/evidence/report smoke.
- Внутри: Frozen history/evidence/report smoke; необходимые регрессии и независимая приёмка этого результата.
- За границей: Старый binary.
- Файлы/контракт: scripts packaged smoke contract.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/004; размер S.
- Приёмка и проверки: Saved result→evidence→decision→diff→selected export exact provenance; current settings не historical.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-004-01` | Frozen saved-result case | planned |
| `XS-R8-004-02` | Frozen evidence case | planned |
| `XS-R8-004-03` | Frozen decision-history case | planned |
| `XS-R8-004-04` | Frozen revision-diff case | planned |
| `XS-R8-004-05` | Frozen selected-export case | planned |

<a id="step-r8-005"></a>
## STEP-R8-005 — Frozen map/NET smoke

- Результат: Frozen map/NET smoke.
- Внутри: Frozen map/NET smoke; необходимые регрессии и независимая приёмка этого результата.
- За границей: Source-tree proxy.
- Файлы/контракт: scripts packaged smoke contract.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/005; размер S.
- Приёмка и проверки: Configured map и supported path с unknown gates; actual exe hash.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-005-01` | Frozen configured-map case | planned |
| `XS-R8-005-02` | Frozen supported-flow case | planned |
| `XS-R8-005-03` | Frozen unknown-gate case | planned |

<a id="step-r8-006"></a>
## STEP-R8-006 — Clean Windows10 offline gate

- Результат: Clean Windows10 offline gate.
- Внутри: Clean Windows10 offline gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Dev machine smoke.
- Файлы/контракт: предлагаемый Win10 VM evidence.
- Зависимости: STEP-R8-002. Порядок: R8/006; размер S.
- Приёмка и проверки: Actual binary first launch/import/report/resources без Python/network/admin; actual profile recorded.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-006-01` | Win10 clean-profile record | planned |
| `XS-R8-006-02` | Win10 first-launch case | planned |
| `XS-R8-006-03` | Win10 offline import case | planned |
| `XS-R8-006-04` | Win10 offline report case | planned |
| `XS-R8-006-05` | Win10 bundled-resource case | planned |

<a id="step-r8-007"></a>
## STEP-R8-007 — Clean Windows11 offline gate

- Результат: Clean Windows11 offline gate.
- Внутри: Clean Windows11 offline gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Synthetic OS result.
- Файлы/контракт: предлагаемый Win11 VM evidence.
- Зависимости: STEP-R8-002. Порядок: R8/007; размер S.
- Приёмка и проверки: Actual clean Win11 profile, тот же binary; отсутствующая VM gate открыт.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-007-01` | Win11 clean-profile record | planned |
| `XS-R8-007-02` | Win11 first-launch case | planned |
| `XS-R8-007-03` | Win11 offline import case | planned |
| `XS-R8-007-04` | Win11 offline report case | planned |
| `XS-R8-007-05` | Win11 bundled-resource case | planned |

<a id="step-r8-008"></a>
## STEP-R8-008 — Same-user DPAPI restore gate

- Результат: Same-user DPAPI restore gate.
- Внутри: Same-user DPAPI restore gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Different-user portability.
- Файлы/контракт: infrastructure/windows_secrets.py;  предлагаемый Windows evidence.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/008; размер S.
- Приёмка и проверки: Original protected values доступны после backup/restore sameuser; errors honest; секрет не в log.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-03, storage:DATA-04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-008-01` | Same-user encrypted-value fixture | planned |
| `XS-R8-008-02` | Same-user restore decrypt case | planned |
| `XS-R8-008-03` | Same-user restore error case | planned |

<a id="step-r8-009"></a>
## STEP-R8-009 — Different-user DPAPI behavior gate

- Результат: Different-user DPAPI behavior gate.
- Внутри: Different-user DPAPI behavior gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Выдуманный пользовательский trial.
- Файлы/контракт: infrastructure/windows_secrets.py;  предлагаемый second-user evidence.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/009; размер S.
- Приёмка и проверки: Actual second user fails honestly→explicit reauth; no secret/empty replacement; original data retained.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-009-01` | Second-user profile record | planned |
| `XS-R8-009-02` | Foreign-user decrypt-failure case | planned |
| `XS-R8-009-03` | Reauth preserves-identity case | planned |
| `XS-R8-009-04` | Secret-free diagnostic check | planned |

<a id="step-r8-010"></a>
## STEP-R8-010 — Qt DPI/theme/keyboard release matrix

- Результат: Qt DPI/theme/keyboard release matrix.
- Внутри: Qt DPI/theme/keyboard release matrix; необходимые регрессии и независимая приёмка этого результата.
- За границей: Screenshot другой версии.
- Файлы/контракт: предлагаемые native/frozen UI artifacts.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/010; размер S.
- Приёмка и проверки: 100/150/200 light/dark/tab/focus/labels; actual normal/hover/focus contrast ratios повторно проверены.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-02, journey-task:JRN-16, followup:R2UX:LINK-CONTRAST.
- Раскрытие: До GO перечислить actual controls/checks/views/matrix cells/participants по исходному протоколу; стабильные дополнительные XS, один элемент на leaf. Закрытие родителя запрещено до покрытия roster.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-010-01` | DPI100 view checkpoint | planned |
| `XS-R8-010-02` | DPI150 view checkpoint | planned |
| `XS-R8-010-03` | DPI200 view checkpoint | planned |
| `XS-R8-010-04` | Light-theme anchor contrast | planned |
| `XS-R8-010-05` | Dark-theme normal contrast | planned |
| `XS-R8-010-06` | Dark-theme hover contrast | planned |
| `XS-R8-010-07` | Dark-theme focus contrast | planned |
| `XS-R8-010-08` | Keyboard label/tab checkpoint | planned |

<a id="step-r8-011"></a>
## STEP-R8-011 — Assistive-technology scenario

- Результат: Assistive-technology scenario.
- Внутри: Assistive-technology scenario; необходимые регрессии и независимая приёмка этого результата.
- За границей: Теоретическая accessibility.
- Файлы/контракт: предлагаемый assistive-tech evidence.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/011; размер S.
- Приёмка и проверки: Actual screenreader labels/order/errors/table map; недоступное устройство gate открыт.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-16.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-011-01` | Assistive-tech actual profile | planned |
| `XS-R8-011-02` | Screenreader label check | planned |
| `XS-R8-011-03` | Screenreader error announcement | planned |
| `XS-R8-011-04` | Accessible table-map case | planned |

<a id="step-r8-012"></a>
## STEP-R8-012 — Formative protocol и реальные представители

- Результат: Formative protocol и реальные представители.
- Внутри: Formative protocol и реальные представители; необходимые регрессии и независимая приёмка этого результата.
- За границей: Генерация участников.
- Файлы/контракт: предлагаемый usability protocol.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/012; размер S.
- Приёмка и проверки: Восемь representative participants/roles включая assistive needs; provenance и consent/data rules; не accuracy proxy.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-17.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-012-01` | Participant role eligibility rule | planned |
| `XS-R8-012-02` | Eight-participant provenance ledger | planned |
| `XS-R8-012-03` | Assistive-needs recruitment record | planned |
| `XS-R8-012-04` | Observation protocol consent/data rule | planned |

<a id="step-r8-013"></a>
## STEP-R8-013 — First-use participant observations

- Результат: First-use participant observations.
- Внутри: First-use participant observations; необходимые регрессии и независимая приёмка этого результата.
- За границей: Synthetic participant.
- Файлы/контракт: предлагаемые observation records.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/013; размер S.
- Приёмка и проверки: Actual J01–20 completion/errors/help/cancel/confusion и participant provenance; не scripted success.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-17.
- Раскрытие: До GO перечислить actual controls/checks/views/matrix cells/participants по исходному протоколу; стабильные дополнительные XS, один элемент на leaf. Закрытие родителя запрещено до покрытия roster.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-013-01` | First-launch observation record | planned |
| `XS-R8-013-02` | Import-preview observation record | planned |
| `XS-R8-013-03` | Finding/evidence observation record | planned |
| `XS-R8-013-04` | Decision/reimport observation record | planned |
| `XS-R8-013-05` | Compare/report observation record | planned |

<a id="step-r8-014"></a>
## STEP-R8-014 — Repeat-use participant observations

- Результат: Repeat-use participant observations.
- Внутри: Repeat-use participant observations; необходимые регрессии и независимая приёмка этого результата.
- За границей: Общий опрос вместо trial.
- Файлы/контракт: предлагаемые observation records.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/014; размер S.
- Приёмка и проверки: Weekly check/urgent finding/audit slice/new vendor реальные task outcomes.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-17, journey-screen:J21, journey-screen:J22, journey-screen:J23, journey-screen:J24.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-014-01` | Weekly-check observation record | planned |
| `XS-R8-014-02` | Urgent-finding observation record | planned |
| `XS-R8-014-03` | Audit-slice observation record | planned |
| `XS-R8-014-04` | New-vendor observation record | planned |

<a id="step-r8-015"></a>
## STEP-R8-015 — Usability p50/p90 report

- Результат: Usability p50/p90 report.
- Внутри: Usability p50/p90 report; необходимые регрессии и независимая приёмка этого результата.
- За границей: Усреднение скрывающее failures.
- Файлы/контракт: предлагаемый usability metric report.
- Зависимости: STEP-R8-013, STEP-R8-014. Порядок: R8/015; размер S.
- Приёмка и проверки: Exact task-time/error denominators и individual records; p50/p90/limits reproducible.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-17.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-015-01` | Task completion denominator | planned |
| `XS-R8-015-02` | Task error denominator | planned |
| `XS-R8-015-03` | Task time p50 function | planned |
| `XS-R8-015-04` | Task time p90 function | planned |
| `XS-R8-015-05` | Missing/failed trial rule | planned |

<a id="step-r8-016"></a>
## STEP-R8-016 — Statistical claim report

- Результат: Statistical claim report.
- Внутри: Statistical claim report; необходимые регрессии и независимая приёмка этого результата.
- За границей: Claim99.9 по 2995любыхтестов.
- Файлы/контракт: предлагаемый claim registry/report.
- Зависимости: STEP-R0-004, STEP-R0-005. Порядок: R8/016; размер S.
- Приёмка и проверки: Per-stratum numerator/denominator/lower95 bound/precision/recall/prevalence/unknown/coverage; недостаточный n unproven.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R0:Q00, checks:CHECK-Q-01, network:Q01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-016-01` | Claim stratum identity | planned |
| `XS-R8-016-02` | Numerator/denominator validator | planned |
| `XS-R8-016-03` | One-sided exact confidence bound | planned |
| `XS-R8-016-04` | Precision/recall prevalence report | planned |
| `XS-R8-016-05` | Unknown/coverage report | planned |
| `XS-R8-016-06` | Insufficient-sample claim guard | planned |

<a id="step-r8-017"></a>
## STEP-R8-017 — Performance regression release gate

- Результат: Performance regression release gate.
- Внутри: Performance regression release gate; необходимые регрессии и независимая приёмка этого результата.
- За границей: Непомеренные гарантии.
- Файлы/контракт: предлагаемые benchmark results.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/017; размер S.
- Приёмка и проверки: Same hardware/inputs против baseline latency/memory/render; raw repeats, p50/p90/peak; failures не прячутся mean.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R0:B04, network:Q02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-017-01` | Hardware/input parity check | planned |
| `XS-R8-017-02` | Latency regression metric | planned |
| `XS-R8-017-03` | Memory regression metric | planned |
| `XS-R8-017-04` | Render regression metric | planned |
| `XS-R8-017-05` | Failing target release gate | planned |

<a id="step-r8-018"></a>
## STEP-R8-018 — Reference-safe retention release check

- Результат: Reference-safe retention release check.
- Внутри: Reference-safe retention release check; необходимые регрессии и независимая приёмка этого результата.
- За границей: Автоматическое destructive cleanup.
- Файлы/контракт: предлагаемый retention contract.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/018; размер S.
- Приёмка и проверки: Saved run/source/profile/decision/map/export references protected; dryrun/cancel/free-space; no silent data loss.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:DATA-12, storage:REL-03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-018-01` | Retained-run reference check | planned |
| `XS-R8-018-02` | Retained-source reference check | planned |
| `XS-R8-018-03` | Retained-profile/decision reference check | planned |
| `XS-R8-018-04` | Retained-map/export reference check | planned |
| `XS-R8-018-05` | Dry-run cancel case | planned |

<a id="step-r8-019"></a>
## STEP-R8-019 — Atomic-export orphan/recovery release check

- Результат: Atomic-export orphan/recovery release check.
- Внутри: Atomic-export orphan/recovery release check; необходимые регрессии и независимая приёмка этого результата.
- За границей: Удалить все временные файлы без identity.
- Файлы/контракт: interfaces/desktop/batch_reports.py;  предлагаемые export writers.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/019; размер S.
- Приёмка и проверки: Crash before/afterreplace; orphan не completed; existing output preserved; permission/cancel honest.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:DATA-11, storage:REL-02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-019-01` | Crash-before-replace export case | planned |
| `XS-R8-019-02` | Crash-after-replace export case | planned |
| `XS-R8-019-03` | Orphan candidate not-complete case | planned |
| `XS-R8-019-04` | Existing-output preservation case | planned |

<a id="step-r8-020"></a>
## STEP-R8-020 — Final controls/CLI parity ledger

- Результат: Final controls/CLI parity ledger.
- Внутри: Final controls/CLI parity ledger; необходимые регрессии и независимая приёмка этого результата.
- За границей: Пропуск неудобного CLI сценария.
- Файлы/контракт: предлагаемый compliance catalog;  interfaces/cli/main.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/020; размер S.
- Приёмка и проверки: Каждая legacy capability/control actual scoped gate либо explicit still open; NEW25 не заменяют controls.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R4:P04.
- Раскрытие: До GO перечислить actual controls/checks/views/matrix cells/participants по исходному протоколу; стабильные дополнительные XS, один элемент на leaf. Закрытие родителя запрещено до покрытия roster.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-020-01` | Legacy CLI capability ledger validator | planned |
| `XS-R8-020-02` | Legacy technical-control ledger validator | planned |
| `XS-R8-020-03` | Still-open parity diagnostic | planned |

<a id="step-r8-021"></a>
## STEP-R8-021 — Final docs/release notes

- Результат: Final docs/release notes.
- Внутри: Final docs/release notes; необходимые регрессии и независимая приёмка этого результата.
- За границей: Переписать исходное исследование.
- Файлы/контракт: specifications/USER_GUIDE.md;  README.md;  specifications/CURRENT_STATE.md.
- Зависимости: нет; доступный подготовительный срез. Порядок: R8/021; размер S.
- Приёмка и проверки: Binary/version/schema/ADR/release notes согласованы; actual scope/limits; checked links; no unproven99.9.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: storage:REL-04, journey-task:JRN-18.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-021-01` | Actual workflow USER_GUIDE update | planned |
| `XS-R8-021-02` | Actual README release update | planned |
| `XS-R8-021-03` | CURRENT_STATE evidence update | planned |
| `XS-R8-021-04` | SCHEMA_MIGRATIONS reader update | planned |
| `XS-R8-021-05` | DECISIONS release update | planned |
| `XS-R8-021-06` | Release-notes manifest update | planned |

<a id="step-r8-022"></a>
## STEP-R8-022 — Независимый итоговый roadmap audit

- Результат: Независимый итоговый roadmap audit.
- Внутри: Независимый итоговый roadmap audit; необходимые регрессии и независимая приёмка этого результата.
- За границей: Закрытие всего roadmap по этому плану.
- Файлы/контракт: предлагаемый final acceptance manifest.
- Зависимости: STEP-R8-001, STEP-R8-002, STEP-R8-003, STEP-R8-004, STEP-R8-005, STEP-R8-006, STEP-R8-007, STEP-R8-008, STEP-R8-009, STEP-R8-010, STEP-R8-011, STEP-R8-012, STEP-R8-013, STEP-R8-014, STEP-R8-015, STEP-R8-016, STEP-R8-017, STEP-R8-018, STEP-R8-019, STEP-R8-020, STEP-R8-021. Порядок: R8/022; размер S.
- Приёмка и проверки: Все mandatory card+section→XS evidence проверены; missing native format/VM/holdout gates открыты; product tests только реальными logs.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: stage:R8.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R8-022-01` | Canonical requirement evidence audit | planned |
| `XS-R8-022-02` | Unnamed-clause evidence audit | planned |
| `XS-R8-022-03` | Missing native-format gate audit | planned |
| `XS-R8-022-04` | Missing VM/holdout gate audit | planned |
| `XS-R8-022-05` | Final release manifest acceptance | planned |
