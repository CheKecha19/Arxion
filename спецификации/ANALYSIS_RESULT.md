# Общий AnalysisResult 1.0.0

## Пользовательские сценарии

В «Отчётах» доступны сохранение выбранного запуска либо последнего сетевого
расчёта, список общих результатов текущего проекта и экспорт JSON/CSV/HTML.
Загрузка и проверка выполняются в worker; смена проекта отменяет доставку
устаревшего результата. Исходная конфигурация для экспорта не требуется.
Старые отчёты продолжают открываться отдельно без изменения их содержимого.

```text
firewall-compliance analyze-bundle switch.cfg --output analysis.json
firewall-compliance analyze-bundle switch.cfg --output analysis.json --complete-config \
  --extended-policy-checks --policy-exposure-profile exposure.json
firewall-compliance analysis-export analysis.json --output analysis.html --format html
firewall-compliance analysis-export analysis.json --output analysis.csv --format csv
```

CLI сохраняет типизированную диагностику нераспознанного входа и возвращает
код 2; такой результат не считается успешным анализом. Экспорт принимает
сохранённый пакет, проверяет его целостность и соответствие входам. Вход JSON
ограничен 64 МиБ. Выход должен отличаться от входа и выбранных профилей,
включая жёсткие ссылки на тот же файл. Версия промежуточных EXE остаётся 0.3.0;
последующие изменения CLI попадут в следующую сборку.

Приёмка: 96 тестов модели, desktop adapter, SQLite и Qt; 30 тестов pure workflow
и CLI. В том числе исходный forwarding parser без flow и производная привязка
с явно заданным flow сохраняются совместно; произвольные другие изменения
контекста, source hash, query, профиля и результата отвергаются.

Контракт находится в application/analysis_result.py. Он не импортирует desktop,
Qt, SQLite, файловые читатели или сетевые клиенты. Экспортёры в
application/analysis_reports.py возвращают строки; запись выбранного файла,
постоянное хранение, CLI и Qt — обязанности вызывающего слоя.

## Область результата

AnalysisResult объединяет результаты разных этапов одной явно сохранённой
операции, сохраняя исходные типизированные входы каждого этапа. Это не общий
вердикт соответствия стандарту и не доказательство сквозной достижимости.
Старые FirewallAssuranceResult, batch-report и сетевые JSON продолжают читаться
своими readers; они не становятся новым пакетом по переименованию полей.

Оболочка содержит schema_version=1.0.0, analysis_id, application_version,
started_at/finished_at с часовыми поясами, необязательные project_reference и
run_reference, sources, components, decisions и limitations. State и summary
выводятся из компонентов. Подставленные несовместимые значения отвергаются при
чтении JSON и model_copy. Решения пользователя не изменяют исходные findings;
время решения может быть позже завершения исходного анализа.

Типы компонентов различаются по kind:

| kind | Точные входы и сохранённый результат |
|---|---|
| policy | DeviceRevision, PolicyAnalysisOptions, FirewallAssuranceResult |
| route | Ревизия, query, RouteSelectionResult |
| reachability | Ревизия, query, ReachabilityResult |
| interface | Ревизия, interface_id, InterfaceDecisionResult |
| policy_decision | Ревизия, query, PolicyBindingEvidence, PolicyDecisionResult |
| device_decision | Ревизия, query, binding, SingleDeviceDecisionResult |
| forwarding | Ревизия, query, FlowApplicability, профиль, контекст, ingress/egress, ForwardingPolicyResult; при наличии — исходные ForwardingParseResult и ForwardingBindingResult |
| revision_diff | Обе DeviceRevision и новый DeviceRevisionDiff 2.0.0 |
| attempt | family, operation, failed/cancelled/not_executed, диагностический код и сообщение, доступные типизированные входы |

Для сетевых компонентов сохраняется целый NetworkImportResult, когда у ревизии
есть дополнительные документы относительно policy-источника. Нельзя заменить
его одной обогащённой revision, удалить документы или повторить один source ID
вместо отсутствующего документа. Сохраняются metadata, настройки, происхождение,
полнота и диагностика NetworkParseResult. Ручные факты исходной ревизии без
дополнительных документов допустимы сами по себе.

Forwarding пока ограничен существующим профилем
asa-9.16-single-routed-ipv4-data-default. Он сохраняет условный характер egress
и неполноту. Наличие полного JSON не расширяет поддержку NAT, runtime или
производителей. Forwarding binding проверяется своим контрактом; его imported,
parsed и context не могут относиться к разным снимкам.

Неуспешный attempt не выдаётся за пустой успешный отчёт. Сохранённые query,
binding и flow должны соответствовать сохранённой ревизии. Невалидный сырой ввод
не подставляется вместо типизированного снимка: его отказ описывается диагностикой.

## Источники и основание хеша

AnalysisSource хранит source_document_id, имя, SHA-256 и hash_basis, а также
доступные source_kind, captured_at, file_modified_at и observation. Неизвестное
время остаётся None. Переданные метаданные должны совпадать с ревизией.

- raw_file — записанный SHA-256 исходных байтов. Сам исходный файл в пакет не
  копируется; наличие записанного хеша не означает повторное чтение файла.
- canonical_api_record — SHA-256 сохранённой API-записи после канонического
  JSON с sort_keys=True, ensure_ascii=False и стандартными разделителями Python.
  Это не хеш байтов HTTP-ответа. Запись сохраняется в canonical_api_record,
  а хеш повторно проверяется при чтении.

source_manifest(revisions, api_records={source_uuid: record}) создаёт manifest
без чтения файлов. Для известного адаптера cloud-ru-vmware-nsxt API-запись
обязательна: отсутствие api_records не переименовывает хеш в raw_file.
Неизвестный внешний адаптер должен явно передать корректный AnalysisSource;
этот контракт не угадывает происхождение произвольного хеша по имени файла.
Manifest точно соответствует использованным источникам: отсутствующие,
дублирующиеся и лишние UUID отвергаются.

## Проверка, версии и неизменяемость

Входные модели копируются и глубоко замораживаются. Изменение исходного словаря
после создания пакета не изменяет пакет. JSON/model_copy заново проверяют связи
и воспроизводят поддерживаемый чистый расчёт: policy из ревизии и явных options,
сетевые этапы из snapshot/query/binding/flow, diff из обеих ревизий.
Это не файловое, сетевое или авторизационное действие.

PolicyAnalysisOptions содержит точные check_ids в порядке исходного отчёта,
require_logging/comments, max_pair_rules, организационные management/exposure
профили и лимиты дополнительных проверок. Неподдерживаемые каталоги/версии либо
не совпавший результат отвергаются; старый отчёт не переписывается новым расчётом.
Версии конкретных движков/контрактов сохраняются в типизированных результатах.

Replay при загрузке может быть затратным и должен выполняться worker-сценарием
вызывающего приложения. Предварительно проверенный immutable instance экспортируется
без повторного анализа. Неизвестные будущие schema_version не принимаются.
Внешняя подлинность данных, подпись, авторство и права доступа не выводятся из
совпадения хеша: эти свойства обеспечивает слой хранения/авторизации.

## Состояния и summary

Complete означает выполнение описанного этапа, а не безопасность политики.
Unknown/not_enough_evidence сетевого результата сохраняются и дают partial.
Пустой пакет и полностью невыполненный анализ дают not_executed. Смешанные
состояния компонентов дают partial. Отдельно считаются фактически выполненные
checks, findings, сетевые результаты и четыре канала сравнения. Not_applicable
и CHECK_NOT_EXECUTED не увеличивают число выполненных checks.
Общие ограничения не могут оставить весь пакет complete.

## Экспорт

- export_analysis_json(result, indent=2) сохраняет полный валидируемый пакет,
  включая точные snapshots и canonical API-записи.
- export_analysis_csv(result) выдаёт строки analysis/source/component/check/
  finding/change/limitation/decision. Все семейства, ошибки и неизвестные
  результаты остаются видны даже при отсутствии findings. Сохраняются IDs,
  состояния, source refs и JSON-доказательства. Строки с формулами электронных
  таблиц экранируются, переносы строк и Unicode сохраняются через CSV quoting.
- export_analysis_html(result) показывает все семейства, исходные параметры,
  версии, evidence, ограничения и сведения источников. Имена, комментарии и
  JSON экранируются. Исходные конфигурации не добавляются; canonical API payload
  не выводится в HTML/CSV, но его хеш и основание видны.

Все три формата считаются чувствительными данными. Экспорт не означает
маскирование адресного плана, правил или комментариев. JSON может содержать
сохранённые API-данные, введённые профили и нормализованные сетевые документы.

## Проверка реализации

tests/regression/test_analysis_result.py использует authored synthetic данные и
проверяет смешанный пакет, типизированные сетевые результаты, действительный
forwarding parser/binding, сохранение network documents, подмену ID/query/flow/
профиля/результата/хеша, deep freeze, derived summary, неизвестную версию,
ошибки/отмену, временные метаданные, VMware hash basis, сохранение комментариев,
HTML/CSV injection и экспорт без I/O/replay. Подключение постоянного хранения
и пользовательских сценариев проверяется отдельными интеграционными тестами.
