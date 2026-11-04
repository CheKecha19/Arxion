# Исполнение roadmap небольшими шагами

Начните с одного **XS**, затем реализуйте следующий функционально доступный XS; проверки и приёмка отложены по указанию пользователя. STEP — навигационный пакет, его нельзя брать целиком в работу. Нормативный объём остаётся в [ROADMAP_V2_FULL.md](ROADMAP_V2_FULL.md); исходное исследование и старый [tracker](../../artifacts/roadmap-execution/tracker.md) сохраняются. Связь требования с планом не означает готовность функции.

Текущий пользовательский приоритет — network map R3; приоритет R2 отложен, работа не отменена. Базовый порядок остальных этапов: R0/R1 → R2 → R3 → R4 → R5 → R6 → R7 → R8. R0 ведётся постоянно. Приоритет этапов не запрещает доступную независимую подготовку: Qt AclMap API после R1, UserGate/Ideco без ожидания PT, non-Cisco NET без новой Cisco NAT. Обязательные недоступные входы остаются открытыми gates; их не удаляют ради скорости.

| Навигация | Содержание |
|---|---|
| [R0](implementation-steps/R0.md) | Корпус, capabilities, oracle, метрики и измерения |
| [R1](implementation-steps/R1.md) | Принятый bounded U01–U06 и отдельные открытые расширения |
| [R2](implementation-steps/R2.md) | Организация, безопасная миграция, история, поиск, полный первый цикл |
| [R3](implementation-steps/R3.md) | Qt карта заданных ACL, persistence, diff и exports |
| [R4](implementation-steps/R4.md) | Контракты, controls, parsers, 12 NEW A и семь existing checks |
| [R5](implementation-steps/R5.md) | UserGate, Ideco, PT: documented versioned native grammars и reproducible labs |
| [R6](implementation-steps/R6.md) | Профиль/exceptions, 10 NEW B, Huawei/Junos/SRX/controllers |
| [R7](implementation-steps/R7.md) | Policy/route/NAT/reverse/multidevice, три NEW C и topology |
| [R8](implementation-steps/R8.md) | Actual binary, чистые ОС, DPAPI, UX, статистика, итоговая приёмка |
| [COVERAGE](implementation-steps/COVERAGE.md) | Все 244 canonical cards, 278 sections с unnamed clauses, 10 carryover |
| [steps.json](implementation-steps/steps.json), [coverage.json](implementation-steps/coverage.json) | Машинные XS/dependencies/status и namespace aliases; полный текст не дублируется |

## Точка продолжения

Ровно один active source XS: XS-R7-032-02 — preparatory logical-link topology renderer в qt_topology_map.py, native selectable/movable items; ещё не done. XS-R3-008-05 zoom/pan/fit — implementation_done_unverified. XS-R7-032-05 — implementation_done_unverified: frozen topology_map.py builder по exact NetworkImportResult/DeviceRevision/ForwardingContext; device/interface/subnet configured attachment, evidence/scope; operational/VRF unknown. Нет reread/routes/cables/reachability claims. Remaining topology/NET source и functional gates открыты; physical-link XS-R7-032-01 dependency сохранена для full composition. Далее topology/NET source dependencies с reuse существующего neutral backend; неизвестное остаётся unknown, functional gates сохраняются. XS-R3-001-02 graph identity verification deferred. Policy-map canvas/wiring source milestone — implementation_done_unverified: build_map_state exact UUID current/saved (empty/unsupported/invalid/partial); configured-policy label; selectable/movable/focusable exact-ID nodes; directional action/disabled/unknown edges with full refs; actual selection → plaintext details; actual one-device load and Qt _build_map/result selector. Refresh covers analysis, _refresh_all, saved run, device/rule/finding, project and new analysis. Current=session revision exact item ID; saved=embedded revision only. Budget 500 nodes/300 rules/1500 segments → explicit limited, full model/details via relation selector, no silent loss. Rule junction source → rule → destination/service; physical topology/effective reachability не заявлены. UI не запускали; checks/review deferred, acceptance нет. R2 отложен по приоритету, не отменён: цельные migration/restore API не завершены. XS-R2-012-02/03/05 — implementation_done_unverified (pure legacy21 DDL, exact guard verifier, trusted_schema predicate); guard wrapper не написан. XS-R2-009-06/07/08/09 — implementation_done_unverified (context/origins; profiles/settings-sources/conflicts/selections; devices/aliases/bindings; connections/scan provenance/stableUUID binding). XS-R2-009-01 full DDL частичен: нет revisioncatalog/decisions/snapshots/onboarding/migration tables; seed/SQL/wiring отсутствуют. XS-R2-012-01 — implementation_done_unverified: register_organization_write_guard/approved_scope/close, connection-local default-deny UDF, active transaction + same connection/thread, finally reset, nested/reregistration revoke. XS-R2-003-01/02/03/04 — implementation_done_unverified: canonical same-dir .org.lock (absent DB, strict parent/link guards), nonblocking msvcrt/fcntl WorkspaceLease, bounded safe LeaseOwner и finally release. Callers не подключены; новых проверок нет. XS-R2-008-07 — implementation_done_unverified: private `_copy_forensic_file` в `src/firewall_compliance/interfaces/desktop/organization_restore.py`: raw bounded copy → exclusive xb → hash/flush/fsync → (size, sha256), без SQL/logical premise; partial owned output сохраняется при ошибке. XS-R2-008-06 file-family helper — implementation_done_unverified; full restore wiring открыт. Backup API XS-R2-004-13 — implementation_done_unverified, uncalled/not UI-wired; caller lease/stable source identity required. XS-R2-004-01/05/06/07/08/09/10/11/12 — implementation_done_unverified, не accepted; finalizer меняет только owned candidate (mode=rw, journal_mode=DELETE), не запускался. `_validate_backup_candidate` принимает только supported v1 legacy; guarded v2 reader dispatch compatibility pending и обязателен к будущей реализации, не финальное v1-only ограничение. Helpers не запускались, broad typed candidate acceptance открыт. Исходные функциональные gates для broader wiring/activation сохранены. Проверки, review и приёмка отложены по указанию пользователя «все проверки оставь на потом, сначала займись реализацией». XS-R2-001-01 принят только для null-report `parse_result={}` branch: [static review](../../artifacts/roadmap-r2/xs-r2-001-01-review.md). XS-R2-001-02 принят только для future-report99 + malformed `parse_result={}` branch: [static review](../../artifacts/roadmap-r2/xs-r2-001-02-review.md). XS-R2-001-03 принят только для SAMEUUID `fact=rules`: [static review](../../artifacts/roadmap-r2/xs-r2-001-03-review.md). XS-R2-001-04 принят только для SAMEUUID `device_id=OTHER-DEVICE`: [static review](../../artifacts/roadmap-r2/xs-r2-001-04-review.md). XS06: test edit завершён; historical focused 1 passed, Ruff/format exit 0; независимый review отменён, acceptance нет. Остальные P2 branches и весь R2 ещё открыты.

R0 частичен и не принят. R1 исторически принят только в bounded synthetic U01–U06: recorded 1680 pytest, Ruff/mypy, actual native/frozen100/150 и сохранённое независимое review. Это не full roadmap/R1 accuracy claim. [Checkpoint](../../artifacts/roadmap-r1/release-gate-checkpoint.md), [review closure](../../artifacts/roadmap-r1/review-closure.md).

R2 slice1 реализован, recorded70passed в [evidence-v2](../../artifacts/roadmap-r2/slice1-evidence-v2.md); отдельного combined70 stdout нет. Сохранены oracle26 и green44 logs. QA сверил nine-file freeze-v2 и 266 baseline files; новые runtime проверки при составлении плана не запускались. Независимая P2 приёмка и selected protocol review остаются открытыми. [Slice2 protocol](../../artifacts/roadmap-r2/slice2-protocol.md) — proposal, не реализация.

Четыре ранее принятых XS сохраняют scoped acceptance. XS06–09, aggregate XS05 и protocol review имеют статус `verification_deferred`; gates не приняты. Implementation queue: XS-R7-032-02 → remaining topology/NET только после source dependencies; existing neutral backend reuse, unknown truthful; functional gates сохранены. R2 guard/schema/migration и broader backup/restore wiring остаются открытыми; actual SQLite readback и protocol verification обязательны перед activation. Обход разрешён только для явно сохранённых `deferred_verification_dependencies`; функциональные зависимости обязательны. Private inactive helper разрешён; опасная активация на пользовательской БД ожидает проверок.

| XS | Узкий результат |
|---|---|
| XS-R2-004-05 | Private backup destination guard — implementation_done_unverified |
| XS-R2-004-06 | Private read-only source opener — implementation_done_unverified |
| XS-R2-004-07 | Private snapshot copy — implementation_done_unverified |
| XS-R2-004-01 | Private candidate-path helper — implementation_done_unverified |
| XS-R2-004-08 | Private SQLite integrity helper — implementation_done_unverified; never executed |
| XS-R2-004-09 | Private bounded streaming SHA256 — implementation_done_unverified |
| XS-R2-004-10 | Private candidate validation — implementation_done_unverified; v1 legacy only, v2 pending |
| XS-R2-004-11 | WorkspaceBackup immutable return contract — implementation_done_unverified |
| XS-R2-004-12 | Private standalone candidate finalizer — implementation_done_unverified; never invoked |
| XS-R2-004-13 | create_workspace_backup composition — implementation_done_unverified; v2 compatibility still required |
| XS-R2-008-06 | Pure _database_file_family main/-wal/-shm/-journal — implementation_done_unverified |
| XS-R2-008-07 | Private raw forensic file copy, hash/flush/fsync — implementation_done_unverified; uncalled |
| XS-R2-004-02 | Broader backup wiring — open, functional gates preserved |
| XS-R2-003-01 | Canonical lock key — implementation_done_unverified; verification deferred |
| XS-R2-003-02 | OS byte lock — implementation_done_unverified; callers not wired |
| XS-R2-003-03 | Bounded safe LeaseOwner metadata — implementation_done_unverified |
| XS-R2-003-04 | workspace_lease finally release — implementation_done_unverified |
| XS-R2-012-01 | Connection-local default-deny UDF approved scope — implementation_done_unverified |
| XS-R2-012-02 | Pure legacy21 trigger DDL fixed allowlist — implementation_done_unverified |
| XS-R2-012-03/05 | Exact guard verifier / trusted_schema predicate — implementation_done_unverified |
| XS-R2-009-06/07/08/09 | Inactive schema fragments — implementation_done_unverified; full DDL partial |
| XS-R3-001-01/03 | AclMap adapter / configured label — implementation_done_unverified |
| XS-R3-002-01/02/03/04 | Policy-map nodes/edges/details/canvas+wiring — implementation_done_unverified |
| XS-R3-008-05 | Native Qt view zoom/pan/fit — implementation_done_unverified |
| XS-R7-032-05 | Frozen topology model builder — implementation_done_unverified |
| XS-R7-032-02 | Preparatory logical-link topology renderer — active |
| XS-R2-001-01 | Null-report ParseResult={} branch — accepted, только static review |
| XS-R2-001-02 | Future sibling не скрывает malformed supported child — accepted, только static review |
| XS-R2-001-03 | Один SAMEUUID altered-rule mismatch — accepted, только static case rules |
| XS-R2-001-04 | Один SAMEUUID parse→revision device-ID mismatch — accepted, только static case OTHER-DEVICE |
| XS-R2-001-06 | Отдельный source-map mismatch branch — verification_deferred; test edit завершён |
| XS-R2-001-07 | Отдельный coverage mismatch branch — verification_deferred |
| XS-R2-001-08 | Отдельный report parser-version mismatch branch — verification_deferred |
| XS-R2-001-09 | Отдельный envelope-hash mismatch branch — verification_deferred |
| XS-R2-001-05 | Запись scoped closure после всех P2 branch reviews — verification_deferred |
| XS-R2-002-01 | Review одного second-RO backup reservation invariant — verification_deferred |
| XS-R2-002-02 | Review connection-local stale-v1 writer guard — verification_deferred |
| XS-R2-002-03 | Review restore-swap journal crash branch — verification_deferred |

Штатный build отдельно разрешён пользователем: powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1 -ArubaUpdate; terminal session 51728, exit 0. EXE dist/ArubaUpdate/FirewallCompliance/FirewallCompliance.exe — 7,873,912 B; ZIP dist/FirewallCompliance-ArubaUpdate-windows-x64.zip — 55,768,583 B. Log build/desktop-widget-build-20261017.log содержит только exit+metadata; native PyInstaller stream остался в terminal. Warning: missing hidden import tzdata. Historical artifacts: dist/widget-build-preserved-R1-20261017. Build включает policy-widget/navigation, будущая topology НЕ входит; затем source freeze снят. App/test/smoke/QA не запускались; acceptance нет.

## Как выполнять один XS

```powershell
python -X utf8 artifacts/roadmap-execution/decomposition-context.py next
python -X utf8 artifacts/roadmap-execution/decomposition-context.py show XS-R7-032-02
python -X utf8 artifacts/roadmap-execution/decomposition-context.py check
```

Helper читает только документационные артефакты и печатает один пакет контекста ≤2500 символов: короткая точная выдержка, path+symbol, relevant test, dependencies/current proof, граница и gate. Полные roadmap/tracker в рабочий запрос не подставляются. Для будущих XS точный symbol/selector и excerpt разрешаются JIT до GO; предлагаемый module не выдаётся за существующий. Материалы XS — не более половины обычного объёма; это дисциплина передачи контекста, не изменение окна модели или настроек Codex.

WIP=1: один writer/reviewer работает над одним XS. Для рискованного кода — programmer и независимый QA; они проверяют разные основания expected. Для простой документации/тестового артефакта достаточно соразмерной проверки. Переиспользуйте текущего работника в том же модуле; при разрешённом делегировании передавайте только bounded pack и инструкции роли. Модель наследуется; дополнительные чаты/публикации/Git не создаются.

Один XS даёт один helper/function/validation condition/error branch/widget action/invariant и узкий meaningful case, обычно один production файл и один test файл. Если требуется читать около 1000 строк, менять несколько подсистем или получаются независимые outcomes — остановить GO и разделить XS ещё раз, сохранив ID. Общий migration/check/vendor importer никогда не один XS. Final public wiring/activation идёт отдельным последним XS после atomic helpers и safety gates. Dynamic rosters (controls, views, participants, supported grammar fields) имеют `expansion_required`; их обязательно перечислить дополнительными stable XS перед исполнением, родитель не закрывается по placeholder.

Программист фиксирует результат и focused proof; независимый QA принимает exact outcome либо возвращает конкретный finding. После исправления и actual gate координатор пишет evidence/checkpoint, переводит статус и без нового пользовательского подтверждения берёт следующий доступный XS. Не запускать полную suite после каждого helper: focused pytest/Hypothesis, Ruff/mypy по затронутой границе; полная regression/native/frozen — в integration/release checkpoints. План теста не равен выполнению. Package accepted только после всех mandatory XS, отдельный gate не закрывается одной ссылкой.

## Сохранность и постоянные правила

Прочитать постоянные документы из [SPECIFICATION_INDEX](../SPECIFICATION_INDEX.md): [DEVELOPMENT_RULES](../DEVELOPMENT_RULES.md), [PROJECT_CONVENTIONS](../PROJECT_CONVENTIONS.md), [TECH_STACK](../TECH_STACK.md), [DEPLOYMENT_TARGETS](../DEPLOYMENT_TARGETS.md), [SECURITY_BASELINE](../SECURITY_BASELINE.md), [PRODUCT_VISION](../PRODUCT_VISION.md). [CURRENT_STATE](../CURRENT_STATE.md) и [checkpoints](../../artifacts/roadmap-execution/checkpoints.md) дают actual evidence; эта навигация их не переписывает.

Перед изменением сохранить exact source/test hashes и разрешённый локальный checkpoint; не откатывать чужие изменения. При ошибке восстановить только собственный согласованный scope по сохранённым bytes, записать failed outcome. Пользовательская DB/config не тестовый стенд: synthetic explicit paths, SQLite-aware verified backup/restore, writer guard и crash reconciliation до активации. Invalid/open failure не создаёт тихо пустую БД. Immutable JSON/source guard, cancellation, legacy readers и seven legacy namespaces сохраняются до доказанной замены.

LINK-CONTRAST закрывается в ближайшем UI edit с actual normal/hover/focus foreground/background измерениями и fresh frozen screenshot. SR005: UNKNOWN исчезновение не confirmed removal; старый structural diff API совместим. AclMap backend/historical123tests не закрывает Qt/persistence/CLI. TASK008 neutral backend остаётся ограниченным, desktop wiring открыто. Все три российских NGFW обязательны: documented firmware/export grammar, synthetic reproducible lab, independent oracle; unsupported native formats и 99.9% не объявляются доказанными. Новое развитие Cisco остаётся backlog.

Если gate требует отсутствующую VM, participant, real export, firmware или holdout — записать точный missing input, оставить gate открытым и продолжить независимый XS. Если helper сообщает broken dependency/hash/context overflow — остановить конкретный XS, исправить артефакт/разбиение и повторить `check`; не перечитывать весь roadmap вместо устранения локальной причины. Генератор `decomposition-build.py` создаёт план: после начала изменения статусов его нельзя перезапускать поверх актуального состояния без сохранения и переноса evidence.
