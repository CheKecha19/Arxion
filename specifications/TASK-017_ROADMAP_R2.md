# TASK-017 — R2: одна организация, сохранение истории и пользовательский путь

Статус: в реализации. 16.10.2026. Нормативная область: roadmap v2 R2/O01–O05, DATA-01–12 и связанные JRN. Этот task не объявляет R2 завершённым по готовности отдельного слоя.

## Цель и порядок

В обычной работе существует один контекст организации. Все старые проекты остаются происхождением исторических данных; одинаковые устройства/подключения из разных источников не сливаются автоматически. Новые импорты, пользовательские решения, снимки и отчёты получают устойчивые ссылки и воспроизводимые версии. Миграция, backup и recovery сохраняют исходные байты и работоспособность старых readers.

Контракт перед схемой: `artifacts/roadmap-r2/contract.md`. Исходный baseline после R1 frozen gate: `artifacts/roadmap-r2/baseline-files.json`. История R1 остаётся отдельной, её evidence не переименовывается в R2.

| Slice | Реализация | Статус |
|---|---|---|
| 1 | Read-only preflight, версия/типы/связи/payload dispatch, all-origin compatibility DTO/facade, независимый preservation oracle | Реализован код, проходит проверку; это только часть DATA-01/02 |
| 2 | Ownership writers, проверенные backup/recovery, additive v1→v2, bootstrap/version dispatch, crash/restart | Не реализован; до кода нужен конкретный review activation/stale-writer protocol |
| 3 | Runtime single-org, stable UID/connection identities, profile conflicts, atomic item/catalog/progress, decision events/as-of | Не реализован |
| 4 | Общая projection/search, фиксированные manifests, export snapshots и comparable diff provenance | Не реализован |
| 5 | PySide6 welcome/overview/settings/migration/recovery/search и полный пользовательский цикл | Не реализован |
| 6 | Full regression/native/frozen/review, руководство, schema/current-state/release notes | Не завершён |

DATA-11/JRN-11 carryover: текущий `analysis/revision_diff.py` сравнивает полные facts вместе с provenance и может показать REMOVED, если в after отсутствует fact при UNKNOWN collection status. Это structural inventory diff и не доказательство сетевого удаления/устранения. В slice 4 нужно разделить semantic identity, provenance и certainty через версионированный новый результат/envelope либо additive presentation с old-reader compatibility. Нельзя просто переписать прежнюю JSON семантику/старые тесты. Unknown after, отсутствующий source или выключенная check не получают подпись «исправлено/подтверждённо удалено». Нужны meaningful replacement regression и replay старых результатов; slice 1 этот source не меняет.

Все DATA-01…12 остаются в области задачи. Нет закрытия DATA-05 по DTO или DATA-10 по локальному фильтру таблицы. Все новые synthetic fixtures находятся в явных временных путях; реальная пользовательская БД не используется.

## Slice 1: конкретный интерфейс

Production файлы: `interfaces/desktop/organization_models.py`, `organization_inspection.py`, `organization_workspace.py`. Existing ProjectStore, backend, Qt/CloudPanel, history и batch reports в этом slice не изменяются. Перед первым созданием проверено, что этих трёх модулей нет в baseline; before-copy для отсутствующего файла не создаётся. Не допускается перезаписывать правки других агентов.

`inspect_workspace(path: Path) -> WorkspaceInspection` возвращает состояние `absent`, `legacy`, `unsupported`, `invalid`, `busy` или `access`. Значение `ready` зарезервировано типом для последующего runtime и не выдаётся за готовую миграцию. Путь отсутствующего файла не создаётся. Отказ открыть существующую БД не превращается в welcome для пустой организации.

`inspect_v1_snapshot(path: Path) -> LegacyWorkspaceSnapshot` выполняет один явный read transaction. Семь v1 families захватываются в неизменяемые tuples с точными SQLite values и внутренними rowid. Counts сопровождаются logical digest с SQLite типом и точным значением; это multiset, а не count-only проверка. Raw values скрыты из repr. Snapshot — внутренний preservation-инструмент; его нельзя публиковать в logs/exports, потому что он сохраняет protected credentials.

`LegacyOrganizationWorkspace(path)` поддерживает:

- `inspect()`;
- `list_origins()`, включая пустые origins;
- `list_runs()` и `list_cloud_scans()` по всем origins;
- `get_run(run_id)` с original payload JSON и текущими mark texts в одном snapshot;
- `list_devices()` с composite `(origin_project_id, raw_device_id)` и последним поддержанным анализом.

Раздельные вызовы методов не обещают общий transaction. Для run/items/marks используется один `get_run`. Это ещё не организация с постоянным UUID, не четырёхчасовая health projection и не исполняемый migration coordinator.

Каждый legacy device/run/scan сохраняет origin. `organization_id`/`device_uid` не выдумываются в read-only режиме. V1 rowid служит только deterministic snapshot-local tie-break. Для chronology явно остаётся `sequence_unavailable`; совпадающие даты между независимыми origins не доказывают порядок событий.

## Payload/version policy

SQLite schema 1 и result schema — разные контракты. До typed domain parsing проверяются поддержанные версии:

- assurance report: только явно `1.0.0`; отсутствие/будущая версия unsupported;
- DeviceRevision: `2.0.0`, а также документированный адаптер модели для `1.0.0` и unversioned legacy формы;
- сохранённый item envelope: текущая unversioned форма; явно versioned envelope пока unsupported;
- ParseResult: текущая unversioned форма; явно versioned форма unsupported.

Неизвестная версия сохраняется opaque exact text, идентифицируется issue и не попадает в typed device projection. Operation metadata и original raw item доступны через generic read; `semantic_support="unsupported"`. Это не проверенный результат и не разрешение на миграцию: default migration до reviewed quarantine должна отклонять неподдержанный semantic payload до изменения БД.

Malformed JSON, duplicate keys, nonfinite constants, неправильный storage type/NULL primary key, нарушенные relations, некорректные states/timestamps и известная неподходящая domain форма дают invalid. Исторический payload не перезаписывается и не удаляется. Finding mark должен ссылаться на finding своего run; opaque future payload не интерпретируется для мнимого доказательства такой связи.

## SQLite и ограничения первого slice

Используется URI `mode=ro` с `uri=True`, явный BEGIN, query_only и закрытие connection. Нет вызова ProjectStore bootstrap, смены journal mode или `immutable=1`. Коммитированные WAL frames должны читаться; read-only SQLite может потребовать sidecars, поэтому неизменность main-file SHA не является обещанием filesystem-wide read-only. Вынужденное recovery отличимо от busy/access только при подтверждающем SQLite error code; наличие journal filename само по себе не доказывает recovery.

Slice 1 не пишет схему, не содержит restore и не защищает от старого уже запущенного v1 writer. Существующий v1 exe не знает нового OS lock. Slice 2 обязан решить это DB-enforced guard/drift policy и проверить фактические process/activation boundaries. Для повреждённого вытесняемого store нужен forensic exact-byte комплект; его нельзя объявлять verified restorable backup или требовать его логической исправности для восстановления из хорошего backup.

## Проверка и доказательства

Backend focused tests: `tests/integration/test_organization_read_boundary.py`. Независимый QA owns `tests/test_organization_preservation_oracle.py` и `tests/organization_oracle_fixtures.py`; ожидаемые multisets не строятся production digest.

Проверяются absent/0/1/many origins, совпадающие name/hash/device IDs, immutable DTO, failed latest attempt, unknown report/revision/envelope versions, exact text preservation, malformed/empty/duplicate-key JSON, NULL/type/relations, unsupported/newer/corrupt store, committed WAL и busy lock. Независимый QA дополняет cross-origin facade и concurrent snapshot gates.

Первый combined actual запуск: 37 passed (17 focused + 20 oracle), 2.38 s. Первый sandbox запуск не прошёл из-за WinError5 создания/cleanup pytest basetemp; это не product test failure. Затем выполнен одобренный elevated retry с новым synthetic basetemp. После финальных refinements выполняется повторная проверка; окончательные результаты/команды/hashes фиксируются в `artifacts/roadmap-r2/slice1-evidence.md` и manifest. Ruff текущих четырёх файлов clean; полный mypy src — 90 source files без ошибок на промежуточной проверке. Эти результаты не заменяют финальный freeze и не доказывают весь R2.

Полный конечный путь остаётся: отсутствующая БД → одна организация → файлы → явное UID-сопоставление → анализ/coverage → evidence → решение → внешнее исправление → новая ревизия → сравнение сопоставимых результатов → фиксированный отчёт → restart/history. Отдельно проверяются upgrade нескольких origins, profile conflicts, независимые подключения, backup/restore/history replay. Без фактической clean OS/representative/hardware проверки её статус остаётся открытым; synthetic данные разрешены пользователем, но не равны лабораторной сертификации.
