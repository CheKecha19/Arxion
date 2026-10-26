# Подключение UI к аналитическому ядру

Дата сверки: 2026-10-11, после условного evaluator ASA forwarding policy.
Статус: прежние API подключены к desktop UI отдельными сценариями; forwarding binding/evaluator доступны в ядре и требуют отдельного UI wiring.
Описание экранов и проверок: DESKTOP_UI.md, TASK-009_DESKTOP_INTEGRATION.md.
Пользовательские инструкции: [USER_GUIDE.md](USER_GUIDE.md) и
[NETWORK_UI_GUIDE.md](NETWORK_UI_GUIDE.md). Desktop wiring принят ADR-016.
Ограничения ядра ниже сохраняются; общего сетевого evaluator/AnalysisResult пока нет.

## С чего начать в отдельном чате

Прочитать PROJECT_CONVENTIONS, ARCHITECTURE, CURRENT_STATE, этот документ и DESKTOP_UI. Фактический код важнее устаревшего описания прототипа; изменения публичных контрактов согласовывать со SCHEMA_MIGRATIONS. Не переносить аналитику в виджеты и не менять ядро ради демонстрационных DTO.

Основной продукт: локальная Windows 10/11 система Network Assurance и Firewall Assurance.
Desktop построен на PySide6 / Qt и вызывает ядро через отдельный worker. SQLite сохраняет policy-проекты и запуски (ADR-018). REST API и сервер отсутствуют. Используются вызовы Python
внутри приложения; HTTP и Docker не требуются.

Последняя полная проверка после HP/Aruba и Comware: 1208 тестов, Ruff и mypy успешны
(60 source files). Оконный smoke проверяет также новые форматы; детали в TASK-011.
Предыдущие два GC stress-прогона относятся к TASK-009. Это не подтверждение
промышленной поддержки оборудования.

## Что уже можно подключить

Новый независимый API карты (ADR-020): `analysis.acl_map.build_acl_map(session.revision,
built_at=...)` возвращает `AclMap` schema `1.0.0`. `select_acl_relations` фильтрует
связи по ACL, rule_id, действию и enabled. `application.acl_map` экспортирует JSON
и DOT. Подробности и пример: [ACL_MAP.md](ACL_MAP.md). Это заданные условия,
не effective permissions и не reachability. Qt и SQLite пока не подключены.
Активная проверяемая область — HP/Aruba и Comware; новое развитие Cisco отложено.

| Экран/сценарий | Существующий API и модуль | Что реально возвращается |
|---|---|---|
| Анализ одного файла | application/firewall_assurance.py: analyze_source(source, registry, *, imported_at, revision_id=None, require_logging=True, require_comments=True) | FirewallAssuranceResult либо ParseFailure |
| Инвентарь правил и объектов | parsers/catalog.py: create_default_registry().parse(ParseRequest(...)) | ParseResult с configuration, rules, endpoints/services, coverage, diagnostics и source_map; либо ParseFailure |
| Проверки готовой ревизии | analysis/firewall_assurance.py: analyze_firewall(revision, *, analyzed_at=None, require_logging=True, require_comments=True, max_pair_rules=1000, checks=None) | Семь checks, findings, evidence и ограничения |
| Интерфейсы и маршруты | application/network_import.py: import_network_documents(base, requests, *, revision_id) | NetworkImportResult с новой revision и полными результатами документов; либо ParseFailure |
| Выбор маршрута | analysis/route_selection.py: select_route(revision, query) | RouteSelectionResult: кандидаты, статусы, причины и evidence; не фактический путь |
| Предварительный сетевой результат | analysis/route_selection.py: analyze_reachability(revision, query) | ReachabilityResult только unknown/not_enough_evidence |
| Одна явно привязанная ACL | analysis/policy_decision.py: evaluate_policy(revision, query, binding) | PolicyDecisionResult с локальным действием, trace и причинами |
| Административные настройки интерфейса | analysis/device_decision.py: evaluate_interface(revision, interface_id) | InterfaceDecisionResult; enabled не означает operational up |
| Локальная композиция решений | application/device_decision.py: analyze_imported_device(imported, query, binding) | SingleDeviceDecisionResult; проверяется imported label/interface mapping, итоговая достижимость не вычисляется |
| Конфигурационный контекст ASA | parsers/cisco_asa_forwarding.py: CiscoAsaForwardingParser().parse(request) | ForwardingParseResult с interfaces, ACL, in/out/global bindings, inventories и diagnostics; либо ParseFailure |
| Привязка контекста к ревизии | application/forwarding_binding.py: bind_forwarding_context(imported, parsed) | ForwardingBindingResult 0.1.0: снимки входов, mappings с evidence, consistent/not_enough_evidence и причины; противоречия дают ValueError |
| Условная цепочка ACL | analysis/forwarding_policy.py: evaluate_forwarding_policy(context, ingress_interface_id=..., egress_interface_id=...) | ForwardingPolicyResult 0.1.0: policy_status отдельно от верхнего status, восемь этапов trace, причины и context snapshot; egress условный |
| Сравнение ревизий | analysis/revision_diff.py: compare_device_revisions(before, after) | Структурный DeviceRevisionDiff; не изменение доступности, ограничение SR-005 остаётся |

Пути в таблице указаны относительно src/firewall_compliance. Эти API существуют, но сетевые и forwarding сценарии не являются готовым единым сервисом обработки произвольной очереди файлов.

## Минимальный запуск Firewall Assurance

Этот пример соответствует composition root текущего CLI и пригоден для фонового обработчика UI:

```python
from datetime import UTC, datetime
from pathlib import Path

from firewall_compliance.application.firewall_assurance import analyze_source
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.parsers import ParseFailure
from firewall_compliance.parsers.catalog import create_default_registry

source = FileSourceReader().read(Path("tests/fixtures/assurance/policy_quality.cfg"))
result = analyze_source(
    source,
    create_default_registry(),
    imported_at=datetime.now(UTC),
)
if isinstance(result, ParseFailure):
    payload = result.model_dump(mode="json")
else:
    payload = result.model_dump(mode="json")
    findings = [finding for check in result.checks for finding in check.findings]
```

Разные ветви нужны для разных состояний UI; ParseFailure не содержит checks. FileSourceReader может выбросить OSError, registry - ошибки выбора/контракта парсера, модели - ValidationError, проверки входных связей - ValueError. Перехватывать их на границе задания, показывать безопасную диагностику, не полный raw content или traceback с секретами.

analyze_source создаёт ревизию внутри, но возвращает только отчёт, не DeviceRevision/ParseResult.
Полный инвентарь правил из отчёта восстановить нельзя: evidence findings содержит только
связанные правила. Текущий desktop `backend.py` реализует отдельный orchestration:
сохраняет ParseResult, строит DeviceRevision и вызывает analyze_firewall, следуя построению
ревизии в application/firewall_assurance.py и сохраняя revision/configuration/device IDs.
Общего application aggregate-сервиса пока нет; не запускать два независимых analyze_source
с разными UUID и не выдавать их за одну ревизию.

## Контракты отображения

- FirewallAssuranceResult 1.0.0: checks[].findings, checks[].status/limitations, parse_warnings, parse_errors, unsupported_constructs и parse_coverage. Общего поля findings нет.
- Finding: finding_id, check_id, revision_id, configuration_id, device_id, severity, status, recommendation и evidence. Статус finding не заменяет статус полноты check.
- ParseResult: configuration, rules, endpoints/services, source_map и coverage. Полный инвентарь всех vendor objects и NAT не обещается.
- DeviceRevision 2.0.0: устройство, ParseResult, сетевые факты, sources, CollectionEvidence, imported_at и необязательные observed_at/observation_window. Не изменять snapshots из UI.
- NetworkImportResult 0.1.0: revision, documents, warnings. Сохранить documents вместе с revision: настройки nameif/security-level и дополнительный provenance нельзя восстанавливать только из revision.
- ForwardingParseResult/ForwardingContext 0.1.0: отдельный контекст и parser diagnostics/source_map. UUID сам по себе не доказывает связь с ревизией. `application/forwarding_binding.py: bind_forwarding_context(imported, parsed)` возвращает ForwardingBindingResult 0.1.0 с проверенными mappings, status и reasons. Consistent не означает полноту inventories или достижимость; ValueError обозначает явное противоречие входов.
- RouteSelectionResult, ReachabilityResult и локальные decision results: версии 0.1.0, reasons, evidence и trace там, где он предусмотрен. Не объединять разные модели в придуманный backend AnalysisResult.

Для JSON использовать model_dump(mode="json") или model_dump_json(); не __dict__, repr или ручное преобразование UUID/datetime. При загрузке проверять тип результата и schema_version соответствующей моделью. UI DTO разрешён как отдельная модель представления, но не как замена сохраняемого backend-контракта. Demo DTO и реальные результаты должны быть явно различимы.

SourceLocation задаёт имя источника и позиции; номера строк начинаются с 1. Не каждая позиция строковая: возможны object_path/object_id. Source mapping не содержит raw строки. Просмотр фрагмента требует отдельного контролируемого чтения исходного документа с проверкой SHA-256, а не чтения произвольного пути из evidence. captured_at/file_modified_at не заменяют observed_at.

## Обязательные ограничения UI

- complete означает выполнение check в его границе, не безопасность устройства. partial/unknown/unsupported показывать явно, включая причины; ноль findings не равен успешному аудиту.
- selected/equal_cost - выбор кандидатов по RIB, не reachable. no_route/blackhole сами по себе не означают конечный blocked.
- Локальный ACL allow/deny не равен итоговому решению цепочки. No_match не превращать в implicit deny без доказанного конца цепочки.
- Не создавать PolicyBindingEvidence с complete/terminal=True по нажатию кнопки или наличию ACL. Нужны реальные основания полноты, source mapping и декларация acl_input. Не подставлять NAT-нормализацию.
- Configured NAT и effective NAT различны. Forwarding adapter не вычисляет NAT/PBR и всегда оставляет effective NAT unknown.
- Структурный diff пока может смешивать изменение значений и происхождения/полноты (SR-005). Показывать как экспериментальное сравнение данных, не «правило удалено на устройстве» или расширение доступа.
- Marks/status/comments сохраняются в отдельном desktop repository по запуску/finding ID. Исходный отчёт ядра не переписывается; статусы между запусками не переносятся.
- JSON текущего результата можно сохранить локально; общих CSV/HTML exporters ещё нет. Не обозначать demo JSON как реальный отчёт.

## Сетевые входы

ForwardingPolicyResult подключается отдельно от прежнего SingleDeviceDecisionResult:
показывать policy_status как «Условная политика», верхний status - как неопределённость
итогового доступа. Восемь этапов trace включают skipped/not_applicable, rule_trace,
positions и причины. Не превращать локальный allow/deny в reachable/blocked.
Egress_basis=caller_supplied_conditional должен быть виден пользователю. API принимает
физические forwarding IDs, не сетевые interface:... IDs; использовать явные mappings
из ForwardingBindingResult. FlowApplicability заполняется только подтверждёнными
декларациями с origin/reference, без автоматических true/defaults. Конфигурационные
результаты parser не получают effective NAT absence от UI. Оркестрация с RIB и
хранение нового результата в SQLite пока не подключены.

NetworkParseRequest требует SourceDocument, NetworkDocumentMetadata и imported_at. Роли существующего CiscoAsaNetworkParser: asa_running_config_interfaces, asa_running_config_static_routes, asa_ipv4_rib. Команда, версия, single/routed, IPv4 data/default, происхождение и полнота задаются явно. Для import_network_documents нужен чистый базовый ASA DeviceRevision: запрещено накладывать новые факты на уже заполненные наборы; revision_id нового снимка отличается от base.

ForwardingParseRequest требует SourceDocument, ForwardingSource, revision/configuration UUID и imported_at; профиль необязателен, но заявленные признаки требуют profile_reference. Поддержан только конфигурационный источник с точной командой и одним согласованным ASA заголовком. Общий ACL ParserRegistry не определяет эти роли. Нельзя направлять все выбранные файлы в один парсер независимо от роли или подставлять вымышленные observation/полноту.

## Aruba и Juniper: внешние примеры

Пользователь предоставил семь частично обезличенных конфигураций и указал производителей Aruba и Juniper. Это заявленное происхождение, не выполненная проверка точной модели, ОС, версии, полноты или удаления секретов. Общие CLI-маркеры не определяют производителя однозначно.

Внешние оригиналы не перенесены в fixtures или golden results и не направляются
принудительно в ASA adapter. TASK-011 добавил отдельные экспериментальные HP/Aruba
AOS-Switch/AOS-CX и Comware конфигурационные адаптеры в общий каталог CLI/UI.
Juniper не подключён по текущему scope; ArubaOS controller session ACL распознаются
для явного отказа ARUBAOS_CONTROLLER_UNSUPPORTED. Legacy-код не засчитывается как поддержка.
Для неизвестного формата сохраняется отдельное состояние без заключения о безопасности.

Проверено 79 внешних masked TXT только чтением: 70 HP/Aruba и 7 Comware дают partial
инвентарь, два ArubaOS controller файла — явный отказ; внутренних исключений нет.
Локальный отчёт перечисляет только файлы, семейства, счётчики и коды диагностики,
не содержимое/секреты. Замена masked IP/ACL identifiers проверялась только в памяти
по запросу пользователя; механизма подстановки в продукте нет. Она не восстанавливает
истинные отношения подсетей. Coverage новых adapters относится к ACL/management-срезу.

Дальнейшая работа с примерами: уточнить ОС/версии и команду экспорта, локально проверить остаточные идентификаторы/секреты, определить согласованную область разбора, затем создать собственные synthetic fixtures и принять отдельное решение об adapter. Не коммитить частично обезличенные оригиналы, raw exports, секреты или их копии в отчётах. Новые примеры не отменяют ADR о первом ASA-срезе.

## Реализованный порядок подключения и следующий шаг

1. Выполнено: отдельный live/demo, фоновый orchestration одного разбора и диагностика.
2. Выполнено: согласованный session state ParseResult/revision/report, правила и объекты.
3. Выполнено: исходный JSON-экспорт и чтение FirewallAssuranceResult 1.0.0. История
   ограничена памятью сессии; сохранённый отчёт не восстанавливает полный снимок.
4. Выполнено: сетевой импорт с явными metadata и просмотр интерфейсов/маршрутов/ограничений.
5. Выполнено: route/local ACL/interface/device APIs; forwarding показан отдельным
   инвентарём, без утверждения о проверке всего пути.
6. Далее: application binding и условный evaluator готовы для отдельного подключения; composition с RIB и полный путь требуют следующих backend-срезов
   отдельным изменением. Матрицы и реальные пути пока не реализованы; общий desktop policy HTML/JSON доступен отдельно от сетевых результатов.

Фоновый worker не обращается к Qt виджетам. Результат/ошибку доставлять через очередь, которую GUI-поток читает через QTimer/poll. Ядро не предоставляет callbacks прогресса или кооперативной отмены: UI может отображать этапы и отменять ещё не начатые задания; прекращение ожидания не означает остановку анализа. Каждому заданию назначать job_id и контекст ревизии, не применять поздний результат к другому выбранному устройству.

## Проверки интеграции

- На synthetic policy_quality.cfg реальный сценарий возвращает семь checks и 14 findings; версия отчёта 1.0.0, ACL parser 0.2.0. Проверить UI фильтры и evidence, а не жёстко кодировать эти числа для других входов.
- ParseFailure/ошибка чтения/неподдержанный формат не оставляют старые findings под новым именем файла.
- Правила и findings одного запуска имеют согласованные revision/configuration/device IDs.
- Partial, unknown, unsupported, пустые списки и no_match отображаются без ложного успешного состояния.
- JSON roundtrip не теряет diagnostics, ограничения, источники и версии; demo JSON не читается как backend model.
- Фоновое выполнение не блокирует окно; поздние результаты не меняют другой пользовательский контекст.
- Тесты и screenshots используют synthetic данные. Исходные частично обезличенные примеры не попадают в артефакты UI QA.

