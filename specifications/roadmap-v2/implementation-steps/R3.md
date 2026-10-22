# R3: небольшие шаги реализации

[Вход и правила](../IMPLEMENTATION_STEPS.md) · [Матрица покрытия](COVERAGE.md)

Текущий пользовательский приоритет — network map. Ровно один active source XS: XS-R7-032-02 — preparatory logical-link topology renderer в qt_topology_map.py, native selectable/movable items; ещё не done. XS-R3-008-05 — implementation_done_unverified. Далее topology/NET source dependencies с reuse существующего neutral backend; неизвестное остаётся unknown, functional gates сохраняются. XS-R3-001-02 graph identity verification deferred.

Policy-map canvas/wiring source milestone — implementation_done_unverified: build_map_state exact UUID current/saved (empty/unsupported/invalid/partial); configured-policy label; selectable/movable/focusable exact-ID nodes; directional action/disabled/unknown edges with full refs; actual selection → plaintext details; actual one-device load and Qt _build_map/result selector. Refresh covers analysis, _refresh_all, saved run, device/rule/finding, project and new analysis. Current=session revision exact item ID; saved=embedded revision only. Budget 500 nodes/300 rules/1500 segments → explicit limited, full model/details via relation selector, no silent loss. Rule junction source → rule → destination/service; physical topology/effective reachability не заявлены. UI не запускали; checks/review deferred, acceptance нет. Проверки, review и приёмка отложены; implementation не означает acceptance. Функциональные dependencies сохранены, inactive UI adapter допускается implementation-first режимом. R2 отложен по приоритету, не отменён; цельные migration/restore API не завершены. Пути модулей относительно src/firewall_compliance/, кроме явных artifacts/specifications/tests/scripts; предлагаемые модули разрешаются JIT до GO. accepted_bounded_existing_evidence означает только historical synthetic U01–U06, не полную приёмку всех связанных UX требований.

Штатный build отдельно разрешён пользователем: powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1 -ArubaUpdate; terminal session 51728, exit 0. EXE dist/ArubaUpdate/FirewallCompliance/FirewallCompliance.exe — 7,873,912 B; ZIP dist/FirewallCompliance-ArubaUpdate-windows-x64.zip — 55,768,583 B. Log build/desktop-widget-build-20261017.log содержит только exit+metadata; native PyInstaller stream остался в terminal. Warning: missing hidden import tzdata. Historical artifacts: dist/widget-build-preserved-R1-20261017. Build включает policy-widget/navigation, будущая topology НЕ входит; затем source freeze снят. App/test/smoke/QA не запускались; acceptance нет.

<a id="step-r3-001"></a>
## STEP-R3-001 — Повторное использование AclMap API

- Результат: Повторное использование AclMap API.
- Внутри: Повторное использование AclMap API; необходимые регрессии и независимая приёмка этого результата.
- За границей: Новый параллельный graph core.
- Файлы/контракт: domain/acl_map.py;  application/acl_map.py.
- Зависимости: STEP-R1-009. Порядок: R3/001; размер S.
- Приёмка и проверки: Source identity/deny/disabled/unknown инварианты существующего backend проверены; historical123 не новый запуск.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: package:R3:M01, network:M01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-001-01` | Desktop adapter existing AclMap в qt_acl_map.py | implementation_done_unverified |
| `XS-R3-001-02` | Проверить graph source identity | verification_deferred |
| `XS-R3-001-03` | Показать declared-vs-effective label | implementation_done_unverified |

<a id="step-r3-002"></a>
## STEP-R3-002 — Qt graph одного устройства

- Результат: Qt graph одного устройства.
- Внутри: Qt graph одного устройства; необходимые регрессии и независимая приёмка этого результата.
- За границей: Path engine.
- Файлы/контракт: предлагаемый interfaces/desktop/qt_acl_map.py.
- Зависимости: STEP-R3-001. Порядок: R3/002; размер S.
- Приёмка и проверки: Existing AclMap nodes/edges drawn/selectable; подпись configured policy; нет заявления effective reachability.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-01, network:M01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-002-01` | Создать scene node item | implementation_done_unverified |
| `XS-R3-002-02` | Создать scene edge item | implementation_done_unverified |
| `XS-R3-002-03` | Обработать node selection | implementation_done_unverified |
| `XS-R3-002-04` | Загрузить one-device graph | implementation_done_unverified |

<a id="step-r3-003"></a>
## STEP-R3-003 — Доступная табличная карта

- Результат: Доступная табличная карта.
- Внутри: Доступная табличная карта; необходимые регрессии и независимая приёмка этого результата.
- За границей: Только mouse graph.
- Файлы/контракт: interfaces/desktop/qt_models.py;  предлагаемый qt_acl_map.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/003; размер S.
- Приёмка и проверки: Все visible node/edge доступны keyboard; row identity соответствует canvas; no lost nodes.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-01, journey-task:JRN-16.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-003-01` | Спроецировать graph node table row | planned |
| `XS-R3-003-02` | Спроецировать graph edge table row | planned |
| `XS-R3-003-03` | Синхронизировать table/canvas selection | planned |
| `XS-R3-003-04` | Открыть evidence keyboard action | planned |

<a id="step-r3-004"></a>
## STEP-R3-004 — Evidence navigation узлов/рёбер

- Результат: Evidence navigation узлов/рёбер.
- Внутри: Evidence navigation узлов/рёбер; необходимые регрессии и независимая приёмка этого результата.
- За границей: Ссылка на текущую вместо saved revision.
- Файлы/контракт: предлагаемый qt_acl_map.py;  interfaces/desktop/workspace_navigation.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/004; размер S.
- Приёмка и проверки: Click ведёт к saved rule/object/source/run; back сохраняет selection.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-01, journey-task:JRN-13, journey-screen:J16.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-004-01` | Открыть node rule | planned |
| `XS-R3-004-02` | Открыть object source | planned |
| `XS-R3-004-03` | Открыть edge run | planned |
| `XS-R3-004-04` | Восстановить map-back context | planned |

<a id="step-r3-005"></a>
## STEP-R3-005 — Фильтры actions/states

- Результат: Фильтры actions/states.
- Внутри: Фильтры actions/states; необходимые регрессии и независимая приёмка этого результата.
- За границей: Сетевые фильтры.
- Файлы/контракт: предлагаемый qt_acl_map.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/005; размер S.
- Приёмка и проверки: Allow/deny/disabled/unknown отдельно; hidden counts exact; сброс восстанавливает graph.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-01, package:R3:M03, network:M02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-005-01` | Отфильтровать action | planned |
| `XS-R3-005-02` | Отфильтровать disabled state | planned |
| `XS-R3-005-03` | Отфильтровать unknown state | planned |
| `XS-R3-005-04` | Рассчитать hidden-edge count | planned |

<a id="step-r3-006"></a>
## STEP-R3-006 — Network/service/scope фильтры

- Результат: Network/service/scope фильтры.
- Внутри: Network/service/scope фильтры; необходимые регрессии и независимая приёмка этого результата.
- За границей: Approximate selection как complete.
- Файлы/контракт: analysis/acl_map.py:filter contract.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/006; размер S.
- Приёмка и проверки: CIDR/IPv6/ports/VRF boundaries exact; unresolved явно остаётся; intersect oracle independent.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-01, package:R3:M03, network:M02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-006-01` | Проверить address/CIDR filter | planned |
| `XS-R3-006-02` | Проверить protocol/port filter | planned |
| `XS-R3-006-03` | Проверить VRF/binding filter | planned |
| `XS-R3-006-04` | Сохранить unknown-match branch | planned |

<a id="step-r3-007"></a>
## STEP-R3-007 — Раскрываемая semantic aggregation

- Результат: Раскрываемая semantic aggregation.
- Внутри: Раскрываемая semantic aggregation; необходимые регрессии и независимая приёмка этого результата.
- За границей: Изменение разрешённых множеств.
- Файлы/контракт: analysis/acl_map.py:aggregation contract.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/007; размер S.
- Приёмка и проверки: Membership conserved; expand возвращает исходные edges/evidence; overlaps не теряются.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-01, package:R3:M03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-007-01` | Построить semantic aggregate key | planned |
| `XS-R3-007-02` | Свести aggregate memberships | planned |
| `XS-R3-007-03` | Раскрыть aggregate | planned |
| `XS-R3-007-04` | Проверить count conservation | planned |

<a id="step-r3-008"></a>
## STEP-R3-008 — Deterministic bounded layout

- Результат: Deterministic bounded layout.
- Внутри: Deterministic bounded layout; необходимые регрессии и независимая приёмка этого результата.
- За границей: Гарантированный FPS без измерений.
- Файлы/контракт: предлагаемый qt_acl_map.py:layout contract.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/008; размер S.
- Приёмка и проверки: Same snapshot→stable positions; limits/cancel не вешают Qt и показаны явно; нагрузка измерена.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-01.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-008-01` | Упорядочить nodes детерминированно | planned |
| `XS-R3-008-02` | Вычислить bounded layout positions | planned |
| `XS-R3-008-03` | Отменить layout | planned |
| `XS-R3-008-04` | Показать too-large-graph diagnostic | planned |
| `XS-R3-008-05` | Native view zoom/pan/fit interaction | implementation_done_unverified |

<a id="step-r3-009"></a>
## STEP-R3-009 — Saved map snapshot schema

- Результат: Saved map snapshot schema.
- Внутри: Saved map snapshot schema; необходимые регрессии и независимая приёмка этого результата.
- За границей: View-only state как immutable snapshot.
- Файлы/контракт: domain/acl_map.py;  предлагаемый map_store.py.
- Зависимости: STEP-R2-022. Порядок: R3/009; размер S.
- Приёмка и проверки: Exact org/revisions/algorithm/layout/filter versions manifest; roundtrip validates projection.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, storage:DATA-09, package:R3:M02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-009-01` | Проверить map manifest schema | planned |
| `XS-R3-009-02` | Построить revision/source references | planned |
| `XS-R3-009-03` | Записать algorithm/layout version key | planned |

<a id="step-r3-010"></a>
## STEP-R3-010 — SQLite persistence карты

- Результат: SQLite persistence карты.
- Внутри: SQLite persistence карты; необходимые регрессии и независимая приёмка этого результата.
- За границей: Переписывание raw results.
- Файлы/контракт: предлагаемый map_store.py.
- Зависимости: STEP-R3-009, STEP-R2-012. Порядок: R3/010; размер S.
- Приёмка и проверки: Graph+manifest transaction; restart equality; corrupt/older reader explicit, guard соблюдён.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, package:R3:M02, network:M03.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-010-01` | Записать map snapshot SQLite | planned |
| `XS-R3-010-02` | Выбрать snapshot read version | planned |
| `XS-R3-010-03` | Отклонить corrupt snapshot | planned |

<a id="step-r3-011"></a>
## STEP-R3-011 — View-state persistence

- Результат: View-state persistence.
- Внутри: View-state persistence; необходимые регрессии и независимая приёмка этого результата.
- За границей: Изменение saved graph.
- Файлы/контракт: предлагаемый qt_acl_map.py;  предлагаемый map_store.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/011; размер S.
- Приёмка и проверки: Zoom/selection/filter/layout только для same snapshot/version; stale state не применяется молча.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, package:R3:M02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-011-01` | Сериализовать zoom state | planned |
| `XS-R3-011-02` | Сохранить selected node | planned |
| `XS-R3-011-03` | Сохранить filter state | planned |
| `XS-R3-011-04` | Сбросить incompatible view state | planned |

<a id="step-r3-012"></a>
## STEP-R3-012 — Explicit refresh новым snapshot

- Результат: Explicit refresh новым snapshot.
- Внутри: Explicit refresh новым snapshot; необходимые регрессии и независимая приёмка этого результата.
- За границей: In-place незаметный refresh.
- Файлы/контракт: application/acl_map.py;  предлагаемый map_store.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/012; размер S.
- Приёмка и проверки: Saved map immutable; changed source создаёт новый snapshot; cancellation оставляет прежний.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-012-01` | Построить source-changed manifest | planned |
| `XS-R3-012-02` | Выполнить refresh в новый map | planned |
| `XS-R3-012-03` | Сохранить old snapshot при cancel | planned |

<a id="step-r3-013"></a>
## STEP-R3-013 — Comparable map diff backend

- Результат: Comparable map diff backend.
- Внутри: Comparable map diff backend; необходимые регрессии и независимая приёмка этого результата.
- За границей: NET control-flow diff.
- Файлы/контракт: analysis/acl_map.py;  предлагаемый snapshot comparator.
- Зависимости: STEP-R3-009. Порядок: R3/013; размер S.
- Приёмка и проверки: Added/removed/changed только comparable manifests; unknown не false removal; independent exact-edge oracle.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, package:R3:M04, network:M04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-013-01` | Проверить graph comparability | planned |
| `XS-R3-013-02` | Классифицировать node change | planned |
| `XS-R3-013-03` | Классифицировать edge change | planned |
| `XS-R3-013-04` | Отделить unknown removal | planned |

<a id="step-r3-014"></a>
## STEP-R3-014 — Qt overlay сравнения карт

- Результат: Qt overlay сравнения карт.
- Внутри: Qt overlay сравнения карт; необходимые регрессии и независимая приёмка этого результата.
- За границей: Вывод remediation.
- Файлы/контракт: предлагаемый qt_acl_map.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/014; размер S.
- Приёмка и проверки: Legend/selected revisions/evidence доказывают каждое изменение; missing context visible.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, package:R3:M04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-014-01` | Сформатировать diff legend | planned |
| `XS-R3-014-02` | Открыть selected-node evidence | planned |
| `XS-R3-014-03` | Построить changed-edge overlay item | planned |

<a id="step-r3-015"></a>
## STEP-R3-015 — JSON graph snapshot export

- Результат: JSON graph snapshot export.
- Внутри: JSON graph snapshot export; необходимые регрессии и независимая приёмка этого результата.
- За границей: HTML graph.
- Файлы/контракт: application/acl_map.py:JSON export.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/015; размер S.
- Приёмка и проверки: Existing versioned snapshot roundtrip с stable IDs/source map; atomic file failures честны.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, package:R3:M04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-015-01` | Сериализовать JSON graph | planned |
| `XS-R3-015-02` | Выбрать JSON manifest version reader | planned |
| `XS-R3-015-03` | Проверить source identity roundtrip | planned |

<a id="step-r3-016"></a>
## STEP-R3-016 — DOT graph snapshot export

- Результат: DOT graph snapshot export.
- Внутри: DOT graph snapshot export; необходимые регрессии и независимая приёмка этого результата.
- За границей: Прямая shell interpolation.
- Файлы/контракт: application/acl_map.py:DOT export.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/016; размер S.
- Приёмка и проверки: Quotes/labels/IDs escaped; scope/deny/unknown retained; independent expected graph comparison.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, package:R3:M04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-016-01` | Экранировать DOT ID/label | planned |
| `XS-R3-016-02` | Сформатировать DOT edge semantics | planned |
| `XS-R3-016-03` | Сформатировать snapshot source header | planned |

<a id="step-r3-017"></a>
## STEP-R3-017 — Автономный HTML graph export

- Результат: Автономный HTML graph export.
- Внутри: Автономный HTML graph export; необходимые регрессии и независимая приёмка этого результата.
- За границей: PNG writer.
- Файлы/контракт: предлагаемый graph HTML exporter.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/017; размер S.
- Приёмка и проверки: Offline assets/legend/table/source anchors работают; hostile labels escaped; rows равны graph.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, package:R3:M04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-017-01` | Сформатировать HTML node row | planned |
| `XS-R3-017-02` | Сформатировать HTML edge legend | planned |
| `XS-R3-017-03` | Проверить offline asset link | planned |
| `XS-R3-017-04` | Записать HTML graph атомарно | planned |

<a id="step-r3-018"></a>
## STEP-R3-018 — PNG graph export

- Результат: PNG graph export.
- Внутри: PNG graph export; необходимые регрессии и независимая приёмка этого результата.
- За границей: Произвольный screenshot вместо export.
- Файлы/контракт: предлагаемый qt_acl_map.py:PNG export.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/018; размер S.
- Приёмка и проверки: Bounds/scale/legend точны; large/cancel/error не дают false success; image visually inspected.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, package:R3:M04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-018-01` | Вычислить PNG bounds | planned |
| `XS-R3-018-02` | Нарисовать PNG legend | planned |
| `XS-R3-018-03` | Проверить PNG scale/clip | planned |
| `XS-R3-018-04` | Обработать PNG write failure | planned |

<a id="step-r3-019"></a>
## STEP-R3-019 — Map CLI integration

- Результат: Map CLI integration.
- Внутри: Map CLI integration; необходимые регрессии и независимая приёмка этого результата.
- За границей: Qt-only feature parity.
- Файлы/контракт: interfaces/cli/main.py.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/019; размер S.
- Приёмка и проверки: Same snapshot/filter/output parity; unknown manifest meaningful exit; JSON/DOT/HTML/PNG capabilities честны.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: network-family:MAP-02, package:R3:M04.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-019-01` | Разобрать CLI map arguments | planned |
| `XS-R3-019-02` | Разрешить saved snapshot ID | planned |
| `XS-R3-019-03` | Выбрать CLI export writer | planned |
| `XS-R3-019-04` | Показать unsupported-version exit | planned |

<a id="step-r3-020"></a>
## STEP-R3-020 — First-map journey/help

- Результат: First-map journey/help.
- Внутри: First-map journey/help; необходимые регрессии и независимая приёмка этого результата.
- За границей: NET query form.
- Файлы/контракт: предлагаемый qt_acl_map.py;  specifications/USER_GUIDE.md.
- Зависимости: нет; доступный подготовительный срез. Порядок: R3/020; размер S.
- Приёмка и проверки: Empty/missing/single-device map не real path; keyboard100/150; следующий полезный шаг понятен.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: journey-task:JRN-13, journey-task:JRN-16, journey-task:JRN-18, journey-screen:J16.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-020-01` | Показать first-map empty state | planned |
| `XS-R3-020-02` | Пояснить unsupported binding | planned |
| `XS-R3-020-03` | Открыть first-map help anchor | planned |

<a id="step-r3-021"></a>
## STEP-R3-021 — Независимый R3 acceptance checkpoint

- Результат: Независимый R3 acceptance checkpoint.
- Внутри: Независимый R3 acceptance checkpoint; необходимые регрессии и независимая приёмка этого результата.
- За границей: Приёмка по наличию backend123tests.
- Файлы/контракт: artifacts roadmap map gate;  scripts packaged smoke contract.
- Зависимости: STEP-R3-001, STEP-R3-002, STEP-R3-003, STEP-R3-004, STEP-R3-005, STEP-R3-006, STEP-R3-007, STEP-R3-008, STEP-R3-009, STEP-R3-010, STEP-R3-011, STEP-R3-012, STEP-R3-013, STEP-R3-014, STEP-R3-015, STEP-R3-016, STEP-R3-017, STEP-R3-018, STEP-R3-019, STEP-R3-020. Порядок: R3/021; размер S.
- Приёмка и проверки: Fixture graph equality+filters+restart+diff+4 exports; native/frozen independent QA с exact hash.
- Статус: **planned**. Доказательства: нет; результат и проверки предстоят.
- Требования: stage:R3, network-family:MAP-01, network-family:MAP-02.

| Исполняемый XS | Один результат + focused проверка в его границе | Статус |
|---|---|---|
| `XS-R3-021-01` | Принять fixture graph parity checkpoint | planned |
| `XS-R3-021-02` | Принять filter/keyboard native checkpoint | planned |
| `XS-R3-021-03` | Принять persistence/diff checkpoint | planned |
| `XS-R3-021-04` | Принять JSON/DOT export checkpoint | planned |
| `XS-R3-021-05` | Принять HTML/PNG export checkpoint | planned |
| `XS-R3-021-06` | Принять frozen-artifact evidence checkpoint | planned |
