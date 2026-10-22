# Архитектура

## Цель проектирования

Сохранить независимость изменений в парсерах, доменной логике, анализе, отчётности, хранилище и пользовательских интерфейсах.

## Слои

```text
CLI / Desktop UI / будущий API
              |
       Application services
       /        |         \
  analysis    parsers    infrastructure
       \        |         /
          domain / контракты
```

Это направление зависимостей, не порядок обработки данных. Domain не импортирует адаптеры. Infrastructure обращается к файлам и в будущем к хранилищам/экспорту; движки анализа не выполняют I/O.

## Правила зависимостей

- `domain` не зависит от других слоёв проекта.
- `analysis` зависит только от `domain`.
- `parsers` преобразуют внешние форматы в доменные объекты и не формируют отчёты.
- `application` оркестрирует сценарии, но не содержит вендорскую логику парсинга.
- `interfaces` вызывают application services и не реализуют логику анализа.
- `infrastructure` реализует адаптеры файлов, БД, отчётов и интеграций.
- Визуализации получают DTO/JSON-модель, а не внутренности парсеров или анализатора.

Чистая алгебра условий находится в domain/policy_matching.py; прежний
analysis/policy_matching.py сохраняет совместимые импорты. Условная цепочка политик
вычисляется domain/forwarding_policy_evaluation.py без I/O и vendor adapters.
analysis/forwarding_policy.py публикует evaluate_forwarding_policy. Доменный
ForwardingPolicyResult повторяет тот же расчёт при чтении/копировании, поэтому
сохранённый результат не может оставить прежний allow после замены context.
Такое разделение обеспечивает проверку схемы без зависимости domain от analysis.

Карта ACL следует тому же разделению (ADR-020): domain/acl_map.py содержит DTO и
чистую проекцию заданных правил, analysis/acl_map.py — build_acl_map и фильтр
представления, application/acl_map.py — проверяемые JSON/DOT-экспорты без I/O.
Карта не зависит от Qt/NetworkX и не вычисляет effective policy или reachability.
Сохранение нового результата и UI wiring остаются отдельными задачами этапа карты.

CLI и desktop создают FileSourceReader и общий каталог адаптеров через
`parsers/catalog.py:create_default_registry`: Cisco ASA, HP/Aruba и Comware.
Bootstrap пока содержит только пакет-заготовку. Интерфейсы сохраняют работу с вводом,
application services и представлением результата. Прямые вызовы чистых analysis API
допустимы из выделенного orchestration/controller, не из виджетов; итоговые сценарии
следует оформлять в application. Juniper не подключён; ArubaOS controllers дают явный отказ.

## Целевая структура пакета

```text
src/firewall_compliance/
  domain/
  analysis/
  parsers/
  compliance/
  application/
  infrastructure/
  interfaces/
  bootstrap/
```

## Целевой конвейер обработки

```text
Загрузка -> Определение -> Парсинг -> Валидация -> Нормализация -> Ревизия устройства
        -> Разрешение объектов -> Firewall Assurance / Network Assurance
        -> Findings и объяснения пути -> Сохранение -> Экспорт
```

Каждый этап имеет явные типы входа и выхода и сохраняет предупреждения/ошибки, а не отбрасывает информацию молча.

## Реализованные сценарии

```text
CLI -> FileSourceReader -> SourceDocument -> ParserRegistry -> ParseOutcome
      -> DeviceRevision в памяти -> policy checks -> FirewallAssuranceResult -> JSON stdout
```

ParseFailure завершает обработку текущего файла с диагностикой. Analyze_source возвращает отчёт, не построенную ревизию: для UI с полным инвентарём нужен согласованный orchestration поверх ParseResult/DeviceRevision/analyze_firewall. Сборщик текущего CLI задаёт сетевым наборам unknown.

```text
Base DeviceRevision + NetworkParseRequest[]
    -> import_network_documents -> NetworkImportResult (новая revision + documents)
    -> select_route / analyze_reachability
    -> analyze_imported_device при явном PolicyBindingEvidence

SourceDocument + ForwardingSource + UUID/profile declarations
    -> CiscoAsaForwardingParser -> ForwardingParseResult (отдельный ForwardingContext)
```

Network Assurance реализован частично: выбор маршрута и локальные interface/ACL решения не доказывают полный путь. Forwarding parser пока не связан application API с существующей ревизией и не имеет evaluator цепочки. Configured NAT/PBR presence unsupported; effective NAT неизвестен. Qt desktop добавляет SQLite-историю проектов и policy-запусков, автономный HTML и JSON-пакет. Общий доменный AnalysisResult и REST API пока не реализованы.

## Фактические модули

| Пакет | Реализовано | Граница |
|---|---|---|
| domain | Configuration/Rule, findings/evidence, DeviceRevision 2.0.0, сетевые и локальные decision модели, ForwardingContext 0.1.0 | Типы и инварианты; без UI/I/O/vendor parsing |
| parsers | Нейтральный ACL контракт/registry и общий catalog; ASA и HP/Aruba ACL 0.2.0, Comware ACL 0.1.0; отдельные ASA network/forwarding 0.1.0 | Все входы в памяти; роли и metadata не смешиваются; Juniper/controller semantics отсутствуют |
| analysis | Семь policy checks, структурный diff, route selection, локальные ACL/interface решения | Чистые вычисления; полная цепочка и NAT/PBR semantics отсутствуют |
| application | analyze_source, import_network_documents, analyze_imported_device | Оркестрация; forwarding application binding ещё нет |
| infrastructure | FileSourceReader | Нет collectors или серверного repository |
| interfaces | CLI analyze/version, Qt desktop, отдельные project_store/batch_reports adapters | SQLite-история policy-запусков; network/forwarding имеют прежние границы ядра и живут в памяти |
| compliance, bootstrap | Пакеты-заготовки | Не считать наличием исполняемых controls/composition root |

Публичные точки подключения, DTO, версии и примеры перечислены в `UI_BACKEND_INTEGRATION.md`. UI session state хранит согласованные IDs и результаты; SQLite repository сохраняет normalized snapshots и ограниченные evidence-фрагменты, а не полные исходники. JSON-пакет desktop версионируется отдельно и не заменяет доменные aggregate/contracts.

Desktop orchestration принят ADR-016; Qt, проекты и общий policy-отчёт — ADR-018.
ADR-015 относится к forwarding context. Tk-прототип остаётся историческим кодом.
Пользовательские сценарии описаны в [USER_GUIDE.md](USER_GUIDE.md) и
[NETWORK_UI_GUIDE.md](NETWORK_UI_GUIDE.md).

Desktop wiring находится в `interfaces/desktop/backend.py` и `network_backend.py`:
один parse -> ParseResult -> DeviceRevision -> analyze_firewall, сетевые сценарии вызываются
отдельно с явными заявлениями пользователя. `jobs.py` не зависит от GUI toolkit и доставляет
результаты только через poll GUI-потока. Представление не экспортируется вместо оригинальных
backend-моделей. `NetworkState` сохраняет NetworkImportResult.documents и самостоятельные
forwarding/decision результаты, не выдумывая единый AnalysisResult.

## Архитектурные ограничения

- `ConfigurationParser.parse()` возвращает `ParseOutcome`: `ParseResult` либо `ParseFailure`.
- `PolicyCheck.evaluate()` возвращает `CheckResult`: ноль или более `Finding`, статус полноты и причины ограничений. Проверка не пишет файлы и не читает аргументы CLI.
- Текущий JSON строится из `FirewallAssuranceResult`; после Фазы 9 общие отчёты используют `AnalysisResult` без повторного парсинга.
- Finding содержит evidence и уровень уверенности.
- Конфигурационные данные, секреты и raw content не попадают в логи по умолчанию.
- Network Assurance использует явный запрос достижимости и не интерпретирует отсутствие маршрута, политики или NAT как разрешённый доступ.
- Ручные сведения о сегментах и связях не смешиваются с данными, импортированными из конфигурации.
- Фактические пробелы snapshot, provenance и времени отмечены в `SPECIFICATION_REVIEW.md`; входные критерии Network Assurance определены в TASK-008.

