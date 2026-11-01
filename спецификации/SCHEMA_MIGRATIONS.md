# Изменения контрактов данных

## Проекции карт R3, 2026-11-01

Приложение 0.8.0 сохраняет необязательный map_view_settings в существующем project.settings JSON: node_limit, line_limit и layouts. Layouts — ограниченный кэш стабильных слотов узлов по виду/зоне; повреждённые записи пропускаются, отсутствие кэша означает стандартную раскладку. Схема SQLite и доменные JSON AnalysisResult/AclMap/DeviceRevision не меняются. Область облачного источника дополнительно различает явно заданные ECS/VPC endpoints; старые подписи зон сохраняются отдельно и не переносятся по совпадению IP/имени.

ProjectMap — неперсистентная UI-проекция. Она содержит структурную принадлежность интерфейсов/сегментов, VDC и явных облачных ссылок, сохраняет исходные RuleEvidence и ссылки на нормализованные Rule для фильтров. Облачные URN/href/UUID сопоставляются только внутри типа, подключения и одного сбора. Неизвестная цель ссылки/локальная сеть ВМ обозначается явно и не становится общим адресным пространством. Визуальные группы и линии не добавляют доказательств reachability. Оригинальная AclMap остаётся гиперграфом с одной relation на правило.

## Завершение реализации R2, 2026-11-01

Приложение 0.7.0 добавляет opt-in workspace_source_sites_meta/version=1 и workspace_source_sites (ключ origin_project_id/source_key/site_id). Перед DDL создаётся отдельная полная резервная копия; миграция транзакционна, legacy user_version=1 не меняется. Таблицы связывают существующие integrations с workspace_sites, допускают несколько площадок и удаляют только текущие назначения при удалении подключения (ON DELETE CASCADE). Чтение не инициализирует схему. История runs/marks и исходные ревизии не переписываются; будущая активация org_context требует явного переноса метаданных.

Settings новых запусков могут содержать workspace_input_sites и source_site_ids как снимок заявленной области. В профиле допустимы rule_count_drop_percent/inventory_count_drop_percent; отсутствие полей в старом JSON не меняет старый fingerprint при чтении. Элементы запуска имеют необязательные collection_warnings и диагностику COLLECTION_COUNT_DROP; исходный AnalysisResult/DeviceRevision остаётся прежней версии. В cloud_scans.result добавлена необязательная integrity_warnings с причинами сравнения счётчиков. Эти предупреждения не меняют семантику findings/полноты и не являются доказательствами удаления. Старые readers, игнорирующие дополнительные поля SQLite JSON, сохраняют совместимость; строгим внешним читателям нового внутреннего payload требуется поддержка этих дополнительных полей.

## Основа рабочего пространства R1, 2026-11-01

Версия приложения 0.5.0. Legacy SQLite user_version=1 сохраняется. При явном действии пользователя добавляются workspace_metadata/schema_version=1, workspace_sites и workspace_device_sites; отдельно workspace_profile_history_meta/version=1 и append-only workspace_profile_history. Каждая инициализация перед DDL создаёт резервную копию полным SQLite backup, затем применяет DDL транзакционно. Инициализация не вызывается при простом открытии диалога или чтении. Неизвестные версии метаданных отклоняются. Конструкторы не активируют org_context.

Назначение площадки имеет ключ (origin_project_id, device_id), не меняет исходную ревизию и может быть снято. Проект не считается физической площадкой. История профилей сохраняет только параметры анализа; версия и SHA-256 canonical JSON фиксируются в settings нового run при включённой истории в одной транзакции с созданием run. Параметры подключения и секреты в профиль не входят. Исторические run/settings/marks не переписываются.

Перед будущей активацией org_context требуется явное перенесение этих таблиц в организационный контракт. При наличии org_context legacy writer отказывает; автоматическая конверсия старых projects в sites отсутствует. Откат — восстановление резервной копии при закрытом приложении. Поле текущего назначения площадки используется только в проекции просмотра и не объявляется историческим фактом размещения.

Публичные AnalysisResult, AclMap и DeviceRevision не меняют schema_version. Новый адресный индекс проектной карты является проекцией: ключ включает контекст и снимок; новые локальные контексты не равны старому default. Старые сохранённые пользовательские подписи адресных групп сохраняются в настройках и требуют явного сопоставления с новой группировкой. Порядок и смысл ACL при этом не изменяются.

## Общие результаты и архив ACL, 2026-10-28

AnalysisResult1.0 хранится отдельно в immutable checksummed analysis_results,
AclMap1.0 — в отдельной immutable acl_maps с project/run/item provenance.
SQLite user_version1 и существующие payload не переписываются. Проекции и
результаты проверяются при сохранении/чтении, источники не перечитываются.
Backup включает новые таблицы; semantic inspector v1 пока описывает старый
каталог таблиц, поэтому его digest не доказывает перенос новых результатов.

У четырёх дополнительных checks поддержаны evidence versions1.0/1.1.
Новая версия добавляет witness и классификацию действий; прежняя сохраняет
исходные поля и finding IDs. Replay выбирает сохранённую версию каждого check.
Каталог1.3 сохраняет прежний набор IDs. Governance checks имеют свой check
version1.0 и явно выбранный каталог1.4; новые optional governance options при
отсутствии не сериализуются, сохраняя прежние JSON и идентичность payload.
Контракты: ANALYSIS_RESULT.md, ACL_MAP_WORKFLOW.md, CHECK_PASSPORTS.md.

## Evidence-aware DeviceRevisionDiff 2.0.0, 2026-10-27

DeviceRevision 2.0.0 остаётся без изменения. Новый результат сравнения имеет
свою schema_version=2.0.0 и отдельные changes/provenance_changes/
normalization_changes/completeness_changes. Прежний unversioned JSON сохраняет
старую семантику и сериализацию, не переклассифицируется при чтении.
Полный контракт: [SR005_DIFF_CONTRACT](SR005_DIFF_CONTRACT.md).

## Дополнительные таблицы локального проекта, 2026-10-27

Реестр ресурсов, его идентификаторы/аудит и история статусов findings добавляются
в отдельные таблицы SQLite v1. Исходные runs/items/marks не переписываются;
старое текущее решение становится явно неполным legacy baseline, без создания
вымышленных переходов. Backup сохраняет полную SQLite-базу и новые таблицы.
Inspector организационного workspace v1 пока не учитывает добавочные таблицы
в semantic digest; будущая миграция обязана сохранять их отдельно.

## Дополнительные policy checks, каталог 1.3.0

FirewallAssuranceResult 1.0.0 и прежний каталог по умолчанию сохранены. Явный
выбор новых checks получает catalogue 1.3.0; параметры организационного профиля
сохраняются в настройках запуска и evidence новых findings. Неизвестный профиль
даёт not_executed с причиной, а не успешную пустую проверку. Профиль не переносит
результат сквозной достижимости и не доказывает назначение сервиса только по порту.

## Карта заданных условий ACL 1.0.0, 2026-10-11

Добавлен отдельный `AclMap` schema `1.0.0`, analyzer `0.1.0`, режим
`declared_rules` (ADR-020, ACL_MAP.md). JSON содержит независимый снимок
`DeviceRevision`, вершины объектов, связи правил и обязательные ограничения.
Чтение повторно проверяет вход и точное соответствие проекции. Результат не
является FirewallAssuranceResult, effective-policy решением или reachability.
Старые схемы, parser/check versions и SQLite не меняются; миграция не нужна.
Подключение нового вида результата к хранилищу — отдельная задача.

## Условная forwarding policy 0.1.0, 2026-10-11

Добавлен ForwardingPolicyResult (schema/engine 0.1.0) по ADR-019. Он хранит полный
ForwardingContext snapshot, физические ingress/egress ID, caller_supplied_conditional
egress_basis, policy_status и восемь этапов trace с rule_trace/positions/reasons.
Верхний status допускает только unknown/not_enough_evidence; runtime_pending
обязателен. Чтение JSON и model_copy повторяют чистый расчёт всех этапов.
Новая версия результата требует своей ветки reader, не выдаётся за прежний
SingleDeviceDecisionResult/PolicyDecisionResult. Старые схемы и SQLite не меняются.
Matcher перенесён в domain с совместимым analysis facade; старые public imports и
семантика прежних checks/одной ACL сохраняются. Прежние 28 JSON golden-файлов
не меняются; восемь новых эталонов добавлены явными командами после просмотра.

## ASA forwarding binding 0.1.0, 2026-10-11

Добавлен отдельный ForwardingBindingResult 0.1.0: imported/forwarding snapshots,
interface mappings с двумя форматами ID и UUID источников, status и reasons.
Чтение JSON и model_copy повторяют проверку доказательств. Consistent означает
согласованность связи, not_enough_evidence - недостаток обязательных доказательств;
явное противоречие отвергается с ValueError. Эти статусы не являются вердиктами
о доступе. DeviceRevision 2.0.0, NetworkImportResult/ForwardingParseResult 0.1.0,
SQLite, отчёты и parser/check versions не меняются. Миграция старых данных не нужна.

## HP/Aruba parser 0.2.0 и проверки 1.1.0, 2026-10-11

Схема FirewallAssuranceResult 1.0.0 и SQLite v1 не изменены. Description и source_map
используют существующие поля: дополнительные ключи acl-range/acl-binding позволяют
локализовать ограничения, description:<rule_id> сохраняет строки комментариев.
Aruba checks/catalog получают 1.1.0; остальные adapters сохраняют каталог 1.0.0.
CHECK_NOT_EXECUTED в limitations означает пропуск проверки; сериализованный статус
остаётся partial для совместимости. Qt/HTML выводят «Не выполнена» по этому коду.
Metadata-only предупреждения отделены от пакетных условий, а платформенное scope
warning не запрещает проверку пригодной ACL. Прежние сохранённые результаты не
переоцениваются при чтении; новую семантику получают только новые запуски.

## ASA forwarding adapter 0.1.0, 2026-10-10

Отдельный CiscoAsaForwardingParser получает ForwardingParseRequest: SourceDocument с байтами, ForwardingSource с заявленными доказательствами, revision/configuration UUID, imported_at и необязательный профиль. До разбора повторно валидируются вложенные данные, SHA-256 исходных байтов, имя, время получения и observation. Detect требует metadata; имя файла не определяет роль. Роль configuration ограничена точными show running-config/show running-config all ветки 9.16; effective NAT и PBR state здесь не разбираются.

ForwardingParseResult schema_version=0.1.0 сохраняет parser_id=cisco-asa-forwarding-9.16, parser_version=0.1.0, отдельный ForwardingContext, coverage, diagnostics и source_map. ParseFailure применяется для неприменимого формата/профиля или недекодируемого источника; частичные поддержанные данные сохраняются с диагностикой. Результат не меняет DeviceRevision и не доказывает принадлежность UUID существующей ревизии: application binding ещё предстоит реализовать. ACL ParserRegistry, CLI и старые схемы остаются прежними.

Новые эталоны фиксируют разбор собственных excerpts, не packet-processing semantics. Effective NAT всегда unknown для этого конфигурационного входа; NAT/PBR присутствие unsupported, трансляция/выбор route-map не выполняются. Нет evaluator, operational validation или окончательного reachable/blocked. Аппаратное подтверждение вывода выбранной сборки остаётся отдельным quality gate.

## ForwardingContext 0.1.0, 2026-10-10

Реализован отдельный нейтральный контейнер ForwardingContext schema_version=0.1.0 по ADR-015. Источники, feature inventories, typed facts и flow declarations сериализуются внутри него. FeatureInventory.enumeration_complete отделяет полный перечень от complete семантической полноты; UNKNOWN с полным перечнем не повышается до known. Пропуски остаются неизвестными, не absent.

Это не миграция DeviceRevision 2.0.0 или Reachability/PolicyDecisionResult 0.1.0. Старые parser/check/report контракты и golden-файлы не меняются. На момент данного среза adapter не был реализован; последующая запись выше фиксирует отдельный конфигурационный вход. Binding к существующей ревизии и evaluator контекста ещё не реализованы. Новый model_copy проверяет update; остальные семейства сохраняют прежнее поведение.

## Подготовка forwarding context, 2026-10-10

ADR-015/FORWARDING_CONTEXT и fixture manifest 1.0.0 определяют будущую область, не новый runtime-контракт. Asa_forwarding_config в manifest - предлагаемая роль, не поддерживаемый parser source_kind. Новые канонические модели и их версии будут приняты при реализации. Существующие схемы, parser/check/report версии и golden results не изменяются. Configured NAT и effective NAT должны иметь разные evidence; ни старый JSON, ни полный running-config автоматически не получает effective_nat=absent.

## Локальные interface/ACL решения 0.1.0, 2026-10-10

ADR-013 добавляет PolicyBindingEvidence, PolicyTraceEntry, PolicyDecisionResult, InterfaceDecisionResult и SingleDeviceDecisionResult 0.1.0. Это новые отдельные контракты API, не миграция старого ReachabilityResult. DeviceRevision 2.0.0, ACL parser 0.2.0, network parser 0.1.0, FirewallAssuranceResult 1.0.0 и старые эталоны остаются неизменными.

Источники/позиции и явные декларации mapping, полноты и терминальности сохраняются в результате. Никакие defaults старых JSON не превращаются в доказанный binding, implicit deny или отсутствие NAT. No_match является локальным отсутствием совпадения, не конечным blocked. Новый составной результат не допускает reachable/blocked. Контракты предназначены для независимого аналитического API; визуальный интерфейс реализуется отдельно.

## Входной срез 8.2: сетевой импорт 0.1.0, 2026-10-10

ADR-012 принимает отдельный `NetworkFactsParser` для Cisco ASA 9.16 с `parser_id=cisco-asa-network-9.16`, `parser_version=0.1.0`. `NetworkDocumentMetadata` и независимый `NetworkParseResult` имеют `schema_version=0.1.0`. Завершение реализации и общих проверок фиксируется отдельно; эта запись определяет совместимость входного среза, а не закрытие шага 8.2.

`DeviceRevision` сохраняет `schema_version=2.0.0`; существующий ACL parser сохраняет `0.2.0`, его registry и ParseResult не получают сетевые роли. Контракты Firewall Assurance и нейтрального route-selection не меняются. Новые сетевые metadata/result читаются отдельно; миграция старых ревизий или постоянного хранилища этим решением не вводится.

- Metadata явно связывает роль, точную команду, заявленную версию и ссылки на происхождение версии/источника, устройство/контекст, режим, family/table, SHA-256 байтов, encoding, selection/extent, capture success и заявление полноты. Поддержанная область - single context с context=None, routed, IPv4, data/default. Complete=true требует completeness_reference; request проверяет совпадение хеша с SourceDocument.
- Целевой профиль версии - 9.16 / 9.16(x). Documentation и operator_declared не доказывают аппаратный capture. ObservationEvidence сохраняется отдельно; captured_at, mtime, версия и хеш не мигрируют в observed_at. Старые источники без новых metadata не получают полноту, роль или поддержанную область автоматически.
- NetworkParseResult разделяет interfaces, configured_routes и routing_table. Known допускается только для полного успешного all-scope захвата с явным основанием полноты, известным наблюдением, чистым разбором и известными фактами; пустой набор при тех же условиях допускает absent. Excerpt/filter/truncated, unsupported/malformed, warnings/errors и отсутствующий/неоднозначный binding сохраняют unknown и неполноту.
- Interface.name сохраняет физический ID; label и security_level имеют отдельные source-mapped InterfaceSettings. Label не мигрирует в zone, отсутствие shutdown не устанавливает enabled=true, административная настройка не становится operational state. Конфликты labels/физических identities не разрешаются перезаписью.
- Настроенный static/default требует явную AD 1..254, не получает RIB metric и не становится установленным маршрутом. Конфигурационный Null0 без AD сохраняет None, без gateway/outgoing interface. У C route отсутствующие AD/metric остаются None. Defaults и неуказанные аргументы не угадываются; L/dynamic/continuation в RIB дают unsupported и partial результат.
- Application создаёт новую ревизию, копирует исходные sources и повторно валидирует её; существующие факты не перезаписываются. NetworkImportResult.documents отдельно сохраняет каждый результат и provenance configured routes. При наличии RIB выбирается RIB, даже частичная, без заполнения пробелов конфигурацией. Configured routes без RIB сохраняют свой scope и не дают полноту наблюдаемой таблицы.

Существующая CollectionEvidence в DeviceRevision 2.0.0 не имеет отдельных полей family/table: ответственность за подтверждение единственной поддержанной области остаётся у сетевого adapter/application. Читатель одной ревизии не должен выводить происхождение версии или metadata из default полей. Сохранение нового NetworkImportResult должно сохранять и documents, чтобы конфигурационный provenance не терялся при выборе RIB.

NetworkImportResult имеет собственную schema_version=0.1.0; это новый контейнер revision/documents/warnings, а не миграция DeviceRevision. Полный статус реализации и проверок приведён в TASK-008_NETWORK_ASSURANCE.md.

Исходные восемь сетевых synthetic payloads и manifest неизменны, excerpt/truncated, complete=false, observed_at=null. Synthetic complete record в тесте подтверждает поведение контракта, а не полный аппаратный экспорт Cisco. Этот срез не вводит CLI, policy decision или reachable/blocked. Официальные primary Cisco и ограничения версий приведены в [NETWORK_INPUTS](NETWORK_INPUTS.md).

## Фаза 7, 2026-10-09

Первый контракт `FirewallAssuranceResult` имеет `schema_version=1.0.0`, каталог встроенных проверок - `1.0.0`, Cisco ASA parser adapter - `0.2.0`.

В JSON `Rule` добавлены поля:

| Поле | Значение по умолчанию для старого JSON | Назначение |
|---|---|---|
| `policy_id` | `null` | Область политики/ACL |
| `policy_direction` | `null` | `in`, `out` или `global` |
| `policy_semantics` | `null` | Подтверждённая `first_match` семантика |
| `match_status` | `unknown` | Полнота разбора всех условий |
| `description_status` | `unknown` | Достоверность сведений об описании |

В JSON `Finding` добавлен необязательный `revision_id` с default `null`. Все findings нового анализатора его заполняют.

Текущие модели читают прежние JSON с указанными default. Полнота условий и область не выводятся автоматически из старых полей: для попарного анализа нужно повторно разобрать оригинальный synthetic источник новым парсером. Читатели прежней строгой схемы могут отклонять новые поля и должны обновиться вместе с приложением.

Локальная БД ещё не реализована, миграция постоянного хранилища не требуется. Golden-эталоны обновлены явной командой; у прежних fixtures сохранены число правил и все ранее сериализованные значения, кроме версии парсера. Legacy-файлы и baseline не изменены.

## Планируемые уточнения после сверки спецификаций

Сверка SPECIFICATION_REVIEW не меняла код, версии схем и golden-файлы. Исправления SR-001–SR-004 реализуются в TASK-008 с отдельным описанием совместимости, версий и регрессионными тестами. В частности, сохранение IP интерфейса вместо нормализованной сети меняет смысл поля `addresses`; хостовую часть из прежних JSON восстановить нельзя, потребуется повторный импорт источника. Время файла не должно автоматически мигрировать в достоверное время наблюдения устройства.

## Шаг 8.0, 2026-10-10

Уточнения реализованы: DeviceRevision имеет schema_version=2.0.0. FirewallAssuranceResult/check catalog/ASA ACL adapter сохраняют версии 1.0.0/1.0.0/0.2.0; их контракт не изменён.

- Добавлены CollectionEvidence для четырёх наборов и ObservationEvidence/ObservationWindow; observed_at допускает null. captured_at означает получение, file_modified_at сохраняет прежнее файловое mtime отдельно.
- Interface.addresses сохраняет хостовую часть; addresses_status неизвестен по умолчанию. Route добавляет administrative_distance=null, route_kind=unknown и table_id=default; metric не переинтерпретируется как дистанция.
- Старый JSON без версии или с 1.0.0 читается с понижением статусов всех сетевых наборов и фактов до unknown. Старое observed_at переносится в legacy_observed_at, новое observed_at=null; основания полноты удаляются, сохраняется migration_limitations. Хостовая часть адреса не восстанавливается, нужна повторная загрузка исходных данных.
- Неизвестная версия отвергается. Model copy/update не считается миграцией или доверенным импортом; вход DeviceRevision повторно валидирует модели и публикует snapshot.
- Прежний собственный golden сохранён в tests/fixtures/revisions/device_revision_v1.json для регрессии реального старого контракта. Два golden ревизии обновлены явными командами после просмотра diff; остальные эталоны и legacy baseline не менялись.

JSON не содержит runtime-признак заморозки: DeviceRevision автоматически создаёт snapshot при чтении/валидации. Самостоятельные модели парсинга после чтения остаются builder-моделями. Старые строгие читатели не должны молча принимать новый контракт; необходимо обновление читателя.

## Шаг 8.1, 2026-10-10

Добавлены нейтральные контракты `ReachabilityQuery`, `AnalysisReason`, `PathHop`, `RouteSelectionResult` и `ReachabilityResult` (ADR-011). `RouteSelectionResult` имеет `schema_version=0.1.0` и `engine_version=0.1.0`; `ReachabilityResult` имеет `schema_version=0.1.0`. Это отдельные результаты анализа, миграция сохранённых ревизий не требуется. `DeviceRevision` сохраняет схему 2.0.0; версии и контракты парсера, проверок, каталога и отчёта Firewall Assurance не меняются.

- Запрос привязан к ревизии, устройству, контексту и входному интерфейсу, содержит конкретные unicast IP одного семейства. Для TCP/UDP обязателен destination_port 1–65535; ICMP не имеет порта. Механизм поддерживает только единственную IPv4 таблицу `default`.
- Требуется полная наблюдаемая RIB (`routing_table`, `complete=true`, `known` либо доказанно пустой `absent`) с согласованным наблюдением. `configured_routes` её не заменяет. `CollectionEvidence` не имеет области family/table; IPv6 и иные таблицы дают `unknown`, а не доказанное `no_route`. Адаптер 8.2 обязан подтвердить покрытие единственной IPv4 таблицы `default` или сохранить данные `unknown`, без автоматического повышения достоверности старых JSON.
- Выбор использует LPM, явную AD и затем metric только для одного вида `connected`/`static`; отсутствующие приоритеты не получают значений по умолчанию. Динамические/неизвестные наиболее специфичные кандидаты неподдержаны. Сортировка кандидатов по route_id детерминирует представление, а не предпочтение. `equal_cost` не доказывает ECMP или ветвь потока; равенство с участием discard даёт `unknown`.
- `PathHop` описывает маршрут-кандидат, а не фактический узел; рекурсия next_hop, ARP и состояние интерфейсов ещё не проверены. `no_route` и `blackhole` - локальные результаты маршрутизации, из которых нельзя вывести окончательный `blocked` до проверки NAT/PBR. `ReachabilityResult` 0.1.0 допускает только `unknown`/`not_enough_evidence`, даже при `selected`; контракт `reachable`/`blocked` отложен до 8.2.

Идентичность источников, время наблюдения, SHA-256 и provenance остаются независимыми основаниями. Сохранение sources/evidence в результате выбора не закрывает SR-006 и не меняет правила доверия к прежним ревизиям.
# Management Assurance 1.0.0, 2026-10-19

Добавлены опциональные ParseResult.management и FirewallAssuranceResult.management_profile.
При отсутствии данных поля не сериализуются; прежние JSON/golden читаются без изменений.
Полнота экспорта передаётся SourceDocument.configuration_complete (default false) и
сохраняется в management inventory. Каталог с MGMT-проверками имеет версию 1.2.0;
версии прежних ACL-проверок не меняются. Схема SQLite не меняется, новые данные
хранятся в JSON payload. Новые payload не обещают чтения старой версией приложения.
Подробности: [MANAGEMENT_ASSURANCE.md](MANAGEMENT_ASSURANCE.md).

