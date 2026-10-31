# Архитектура

Сверка исходников 31.10.2026, приложение 0.3.2. Это карта реализации, не заявление
о прохождении проверок или промышленной поддержке. Принятые решения хранятся в
[DECISIONS.md](DECISIONS.md), текущие рабочие ограничения — в [AGENTS.md](../AGENTS.md).

## Реальные границы пакетов

| Пакет | Ответственность |
|---|---|
| `domain` | Типы, snapshots, provenance, полнота и чистые инварианты; без UI/I/O/vendor adapters |
| `devices` | Перенесённые ASA/HP-Aruba/Comware парсеры, отдельный controller-прототип, VMware/Advanced/Evolution клиенты |
| `parsers` | Общие контракты/registry/catalog, compatibility imports; новые UserGate и Ideco парсеры пока здесь |
| `checks` | Чистые проверки: access, attachments, policy_quality, rule_hygiene, governance, management; общие операции в common |
| `analysis` | Оркестрация каталога, network decisions, diff, карты; старые check imports сохранены для совместимости |
| `application` | Анализ источника/общий AnalysisResult, replay/export, network import, forwarding binding, ACL-map workflow, governance и controls |
| `infrastructure` | Чтение файлов, защита секретов Windows, UserGate/Ideco API; прежние cloud imports совместимы |
| `interfaces` | Typer CLI, PySide6/Qt, фоновые задания, локальное SQLite-хранилище, представления/экспорт |
| `compliance`, `bootstrap` | Пакеты-заготовки; исполняемые controls находятся в application/domain |

Актуальные пути: [SOURCE_LAYOUT.md](../DOCUMENTATION.md). `domain` не импортирует
адаптеры. Чистые проверки и аналитические вычисления не выполняют сеть/файловый I/O.
Статический harness проверяет ограниченный набор границ, включая новые checks/devices;
он не доказывает отсутствие runtime/Qt/SQL зависимостей. Фактический Qt composition
root `qt_app.py` остаётся крупным интеграционным модулем.

## Конвейеры

```text
Файл -> FileSourceReader -> SourceDocument -> ParserRegistry -> ParseOutcome
     -> DeviceRevision -> checks -> FirewallAssuranceResult
     -> общий AnalysisResult / проектное хранение / отчёты

Явно выбранный API-сбор -> сохранённый снимок -> нормализация -> анализ
```

Каталог CLI/Qt включает ASA, HP/Aruba, Comware, UserGate и Ideco. Формат определяется
по содержимому. Legacy-парсеры не подмешиваются. Controller-прототип и Juniper не
подключены. VMware Edge использует отдельный адаптер сохранённого сбора; Advanced/
Evolution собирают инвентарь и SG без автоматического анализа качества SG-правил.
UserGate/Ideco сохраняют собственные JSON-снимки; их NAT не становится разрешением.

```text
Base DeviceRevision + NetworkParseRequest[] -> NetworkImportResult
  -> select_route / analyze_reachability / локальные ACL-interface решения
ForwardingParseRequest -> отдельный ForwardingContext
  -> bind_forwarding_context -> условный evaluate_forwarding_policy
```

Forwarding binding/evaluator существуют в ядре. Сетевой UI показывает отдельные
сценарии, а полный маршрут через устройства, effective NAT/PBR, operational state,
итоговые reachable/blocked и единый сетевой CLI не реализованы. Явный egress и
декларации полноты не подставляются по отсутствию команд.

## Результаты и хранение

Сохраняются версии схем/движков/профилей и источник доказательств. Общий
`AnalysisResult` реализован с replay, SQLite-персистентностью и JSON/CSV/HTML.
Старые FirewallAssuranceResult и batch-report остаются отдельными контрактами.
Controls дают техническое сопоставление с версионированным профилем, не сертификацию.
Сетевые формы сохраняют оригинальные модели отдельно; типизированный контейнер не
означает автоматическую композицию любого сетевого сценария.

Карта ACL: domain DTO/проекция -> analysis builder/filter -> application export/
store -> CLI/Qt. Реализованы SQLite, фильтры, batch, JSON/DOT/HTML и Qt PNG.
Это карта заданных условий, не effective permissions или сквозная достижимость.

`project_store.py` сохраняет нормализованные данные и ограниченные evidence-фрагменты,
а не полный исходник. Повторное подключение источника проверяет SHA-256. Пользовательские
решения хранятся отдельно от исходного отчёта, с историей переходов. Структурный diff
SR-005 разделяет значения, полноту и происхождение; это не доказательство изменения
доступа. Отдельный policy/NAT/object diff не считать законченным UI-workflow по одному
наличию его доменного/аналитического модуля.

## Desktop и поставка

Desktop entrypoint использует deferred startup: окно появляется до загрузки проекта,
история читается фоново в общий `ProjectSnapshot`, скрытые страницы/карты заполняются
при переходе. Invalidation учитывает изменения backing store. Фактические времена
запуска не измерены этой сверкой. Qt callbacks доставляются GUI-потоком; поздние
результаты защищены project/job ticket идентичностью.

REST API и серверного repository нет. Поставка — единая Windows-папка с EXE и
`_internal`, см. [WINDOWS_DISTRIBUTION.md](../DEVELOPMENT.md).
