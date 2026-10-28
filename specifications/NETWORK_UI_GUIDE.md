# Сетевой экран desktop: руководство пользователя

Обновление исходников 27.10.2026: metadata, observations/window, binding и
forwarding profile вводятся через именованные поля форм. Неизвестные дата и
полнота остаются незаданными; пользователь явно подтверждает время, область
и основание полноты. Раскрываемый JSON-режим сохранён для точного импорта
существующего контракта. Примеры JSON ниже применимы к этому дополнительному режиму.

Сверено с Qt-панелью `qt_network.py`, `network_backend.py` и контрактами ядра 2026-10-11.
Общий запуск и проекты: [USER_GUIDE](USER_GUIDE.md); API: [UI_BACKEND_INTEGRATION](UI_BACKEND_INTEGRATION.md).

Раздел **«Анализ → Расширенные инструменты»** вызывает локальное Python-ядро в фоне. Он не
подключается к устройствам и не исполняет CLI-команды из metadata: команды описывают
происхождение выбранного файла. Документы/сетевые результаты существуют в памяти
до закрытия; сохраните их через «Экспорт оригинального JSON». Общий HTML запуска
не включает эти дополнительные результаты автоматически.

## 1. Подготовить policy-сессию и выбрать базу

1. Запустите Qt desktop, создайте/выберите проект и добавьте synthetic
   `tests/fixtures/assurance/policy_quality.cfg` через «Добавить файлы».
2. После определения нажмите **«Запустить проверку файлов»** в «Операции → Файлы и проверки».
3. Откройте **«Анализ → Расширенные инструменты»**, нажмите **«Обновить сессии»** и выберите
   ASA-базу в верхнем списке. HP/Aruba/Comware исключены из этого списка.
4. Если открыт старый запуск после перезапуска программы, сначала в «Инфраструктура → Источники» выбранного устройства
   выберите ASA и нажмите **«Подключить исходник»**. Нужен совпадающий SHA-256.

Policy-сессия содержит исходный документ, `ParseResult`, исходную `DeviceRevision` и отчёт
`FirewallAssuranceResult`. Сетевой импорт создаёт **другую ревизию** и сохраняет полный
`NetworkImportResult`, включая `documents`. Исходный snapshot и policy-отчёт не изменяются.
В заголовке панели показаны UUID базы и нового сетевого снимка. Сетевые запросы используют
новый снимок, если он импортирован; иначе — исходную policy-ревизию с неизвестными сетевыми данными.

Сетевая база должна быть Cisco ASA 9.16 без уже заполненных интерфейсов, маршрутов, сегментов
или topology links. Повторный импорт через панель снова строится от чистой policy-базы,
а не накладывается на предыдущий сетевой снимок. Перед новым импортом активный сетевой результат
сбрасывается; ошибка нового импорта не оставляет предыдущую сеть действующим контекстом запросов.

Панель имеет пять вкладок. У вкладки есть внешняя вертикальная прокрутка, у JSON-редакторов —
собственная. Если нижние кнопки не видны, прокрутите всю вкладку полосой справа.
JSON использует двойные кавычки, `true`/`false` и `null`; комментарии внутри JSON не допускаются.

## 2. «Сетевые документы»: явные metadata и совместный импорт

Слева расположены путь, **«Выбрать файл»**, редактор metadata и отдельный редактор
**«Observation этого файла»**. Нажатие **«Добавить документ»** сохраняет
в очереди путь и текущие заявления. Оно ещё не читает и не анализирует файл.
Изменение редактора после добавления не меняет уже поставленный документ:
выберите его в очереди, нажмите **«Убрать выбранный документ»** и добавьте заново.

Справа — observation базовой конфигурации, согласованный интервал и очередь ролей.
**«Импортировать → новая ревизия»** читает файлы, проверяет модели и вызывает
`import_network_documents`. Можно импортировать одну, две или три разные роли.
Повторение одной роли не разрешено: конфликт источников ядро не разрешает автоматически.
Adapter сам обрабатывает интерфейсы перед маршрутизирующими документами независимо от очереди.

| Поля metadata | Что вводить |
| --- | --- |
| `source_kind` | Одну из трёх точных ролей ниже |
| `command` | Точную команду соответствующего раздела; это заявление, не действие UI |
| `declared_version`, `version_provenance`, `version_reference` | Версию и основание: `documentation`, `operator_declared` или `device_export` |
| `origin`, `origin_reference` | `synthetic`, `operator_declared` или `device_export` и конкретную ссылку/основание |
| `context_mode`, `context`, `firewall_mode` | Поддержан single/routed; для single `context` равен `null` |
| `address_family`, `table_role`, `table_id` | Поддержан профиль `ipv4` / `data` / `default` |
| `encoding` | `ascii` или `utf-8`, соответствующие байтам файла |
| `selection`, `extent` | Реальную область: например `authored_excerpt` и `excerpt` для fixtures |
| `capture_success` | Подтверждение успешного получения документа; не полноты конфигурации |
| `complete`, `completeness_reference` | Полноту заявляют только с основанием; для fixtures ниже `false` и `null` |

Роли и команды:

| `source_kind` | `command` | Набор результата |
| --- | --- | --- |
| `asa_running_config_interfaces` | `show running-config interface` | `interfaces` |
| `asa_running_config_static_routes` | `show running-config route` | `configured_routes` |
| `asa_ipv4_rib` | `show route` | `routing_table` |

`device_id`, UUID документа и SHA-256 заполняются из выбранной сессии и фактически прочитанных
байтов. Их не нужно вводить в metadata. SHA-256 подтверждает идентичность содержимого,
но не подлинность экспортировавшего устройства. Имя источника — имя файла, не произвольный путь
из evidence. Время получения файла и время импорта регистрируются программой; они не являются
`observed_at`. Чтение выполняется при запуске импорта, поэтому не меняйте файлы во время задания.

### Observation и согласованный интервал

Для неизвестного observation оставьте **`{}`** во всех трёх редакторах:
observation документа, observation базовой конфигурации, согласованный интервал.
Дата создания fixture, `captured_at` и `file_modified_at` не заменяют время состояния устройства.

Если время состояния действительно известно, отдельный `ObservationEvidence` имеет поля
`observed_at` (ISO 8601 с часовым поясом), `method` (`operator_declared`, `device_export`,
`synthetic`) и непустой `reference`. Заявление базового observation относится именно к
исходному policy-файлу; наблюдение нового интерфейсного экспорта не доказывает время policy.
Наблюдение не может быть позже получения документа.

Необязательный `ObservationWindow` имеет `start`, `end` (ISO 8601 с часовым поясом) и `reason`.
Интервал должен содержать observation базы, завершаться до импорта и покрывать observation
используемых документов. Интервал требует реального основания временной согласованности,
а не просто близких времён файлов. В примере ниже observation и интервал неизвестны;
готовых временных значений для подстановки здесь намеренно нет.

`complete=true` требует `selection="all"`, `extent="full"`, `capture_success=true` и
`completeness_reference`. Для известного полного набора также нужны observation, поддержанное
покрытие и отсутствие исключающей диагностики. Само переключение флага не доказывает полноту.

### Воспроизводимый пример на существующих synthetic файлах

Файлы — авторские выдержки, не выполненные CLI-захваты. Их происхождение и ограничения записаны
в [README сетевых fixtures](../tests/fixtures/network_asa/README.md) и
[manifest](../tests/fixtures/network_asa/manifest.json). У них `observed_at=null`,
`complete=false`; команды никогда не запускались. В этом walkthrough `capture_success=false`
не заявляет успешный аппаратный захват. Наличие файла и его успешное локальное чтение проверяет UI.

Для каждого документа выберите указанный файл, полностью замените metadata соответствующим
JSON, оставьте observation документа `{}` и нажмите **«Добавить документ»**.
Общие поля заполнены по manifest; `origin_reference` обозначает конкретный authored scenario.

**Первый документ:** `tests/fixtures/network_asa/connected_static_default/interfaces.cfg`.

```json
{
  "source_kind": "asa_running_config_interfaces",
  "context_mode": "single",
  "context": null,
  "firewall_mode": "routed",
  "declared_version": "9.16",
  "version_provenance": "documentation",
  "version_reference": "tests/fixtures/network_asa/README.md",
  "origin": "synthetic",
  "origin_reference": "tests/fixtures/network_asa/manifest.json: connected_static_default/interfaces.cfg",
  "address_family": "ipv4",
  "table_role": "data",
  "table_id": "default",
  "command": "show running-config interface",
  "encoding": "ascii",
  "selection": "authored_excerpt",
  "extent": "excerpt",
  "capture_success": false,
  "complete": false,
  "completeness_reference": null
}
```

**Второй документ:** `tests/fixtures/network_asa/connected_static_default/static_routes.cfg`.

```json
{
  "source_kind": "asa_running_config_static_routes",
  "context_mode": "single",
  "context": null,
  "firewall_mode": "routed",
  "declared_version": "9.16",
  "version_provenance": "documentation",
  "version_reference": "tests/fixtures/network_asa/README.md",
  "origin": "synthetic",
  "origin_reference": "tests/fixtures/network_asa/manifest.json: connected_static_default/static_routes.cfg",
  "address_family": "ipv4",
  "table_role": "data",
  "table_id": "default",
  "command": "show running-config route",
  "encoding": "ascii",
  "selection": "authored_excerpt",
  "extent": "excerpt",
  "capture_success": false,
  "complete": false,
  "completeness_reference": null
}
```

**Третий документ:** `tests/fixtures/network_asa/connected_static_default/show_route.txt`.

```json
{
  "source_kind": "asa_ipv4_rib",
  "context_mode": "single",
  "context": null,
  "firewall_mode": "routed",
  "declared_version": "9.16",
  "version_provenance": "documentation",
  "version_reference": "tests/fixtures/network_asa/README.md",
  "origin": "synthetic",
  "origin_reference": "tests/fixtures/network_asa/manifest.json: connected_static_default/show_route.txt",
  "address_family": "ipv4",
  "table_role": "data",
  "table_id": "default",
  "command": "show route",
  "encoding": "ascii",
  "selection": "authored_excerpt",
  "extent": "excerpt",
  "capture_success": false,
  "complete": false,
  "completeness_reference": null
}
```

Оставьте справа observation базы и интервал `{}`. Нажмите
**«Импортировать → новая ревизия»**. Успешный результат — `NetworkImportResult 0.1.0`
с новой `DeviceRevision 2.0.0`, двумя интерфейсами, двумя configured routes и четырьмя RIB-строками.
Все три набора имеют статус `unknown`. Предупреждения о неполном захвате, отсутствии observation,
неподтверждённом capture и несогласованном наблюдении ожидаемы. Они не исчезают из-за успешного
выполнения фонового задания. Это успешный импорт ограниченных данных, а не успешный аудит сети.

## 3. «Интерфейсы / маршруты»: факты и источники

Таблица показывает **«Документ / набор»**, **«Роль»**, **«Статус»**, **«Фактов»**.
Нажатие строки открывает оригинальный `NetworkParseResult` выбранного документа во вкладке
**«Результаты / JSON»**. Интерфейсы, адреса, `enabled`, configured routes и наблюдаемая RIB
находятся в соответствующих `interfaces`/`routes` этого JSON.

**«Показать и экспортировать полный NetworkImportResult»** открывает весь импорт с `revision`,
`documents` и общими warnings. Для сохранения затем используйте кнопку JSON на вкладке результата.

Следует читать не только факты, но и `metadata`, `status`, `collection_evidence`, `coverage`,
`warnings`, `errors`, `unsupported_constructs`, `limitations` и `source_map`.
`interface_labels` и `interface_settings` сохраняют `nameif`, security-level и позиции строк.
Configured routes остаются в документах даже при наличии RIB. Для `revision.routes` ядро выбирает
RIB, если она передана; конфигурационное намерение не доказывает установленный маршрут.

У отдельного факта может быть `data_status="known"`, пока весь набор `unknown`:
строка распознана, но полнота всего снимка и общее observation не доказаны.
Позиции `SourceLocation` начинаются с 1. Mapping показывает позиции, а не копии raw-конфигурации.

## 4. «Маршрут / локальная ACL»: запрос и пять отдельных API

Заполните поля следующего запроса для импортированного примера:

| Поле интерфейса | Значение |
| --- | --- |
| «Входной interface_id» | `interface:GigabitEthernet0/0` |
| «Source IP в координатах acl_input» | `192.0.2.10` |
| «Destination IP в координатах acl_input» | `203.0.113.10` |
| «TCP / UDP / ICMP (tcp/udp/icmp)» | `tcp` |
| «Destination port (пусто для ICMP)» | `443` |
| «Таблица» | `default` |

ID интерфейса скопируйте из `documents[].interfaces[].interface_id`; строковое имя `outside`
не заменяет ID. Для TCP/UDP порт обязателен, для ICMP поле порта оставляют пустым.
Адреса — конкретные unicast IP одного семейства. UI не выполняет NAT-преобразований;
пользователь должен задавать координаты `acl_input` осознанно.
Device/revision/context запроса программа берёт из текущего snapshot.

| Кнопка | API / оригинальная модель | Как читать |
| --- | --- | --- |
| «Выбор RIB» | `select_route` / `RouteSelectionResult` | Кандидаты, matched IDs, причины, evidence; не итог доступности |
| «Предварительный результат» | `analyze_reachability` / `ReachabilityResult` | Только `unknown` или `not_enough_evidence` |
| «Админ. интерфейс» | `evaluate_interface` / `InterfaceDecisionResult` | Достаточно interface_id; остальные query-поля не нужны |
| «Одна ACL» | `evaluate_policy` / `PolicyDecisionResult` | Нужны query и явный binding; локальное действие и trace |
| «Локальная композиция» | `analyze_imported_device` / `SingleDeviceDecisionResult` | Нужен сохранённый NetworkImportResult и подтверждаемый label/interface mapping |

В приведённом walkthrough **«Выбор RIB»** и **«Предварительный результат»** возвращают
`not_enough_evidence`. **«Админ. интерфейс»** возвращает `unknown`: fixtures не содержат
`shutdown`/`no shutdown`, поэтому административное состояние не подставляется из vendor defaults.
Если другой документ явно доказывает `administratively_enabled`, это всё равно не operational up.

`selected` и `equal_cost` обозначают выбранные RIB-кандидаты. `no_route` и `blackhole` сами по себе
не означают конечный `blocked`. Нельзя получать окончательный путь, матрицу доступа или
reachable/blocked путём переименования этих результатов.

### Явный PolicyBindingEvidence: пример для AUDIT

Сначала откройте полный `NetworkImportResult`. В `revision.sources` найдите источник с
`source_name="policy_quality.cfg"` и скопируйте его `source_document_id`. UUID генерируется
в текущей сессии; UUID документа `interfaces.cfg` или нового forwarding context сюда не подходит.
Policy ID `AUDIT` виден в исходных правилах. В неизменённом policy fixture строка 12 содержит
`access-group AUDIT in interface outside`; строка 2 интерфейсного fixture содержит `nameif outside`.

Вставьте JSON ниже в редактор `PolicyBindingEvidence`. Замените единственный placeholder
`ВСТАВЬТЕ_UUID_POLICY_SOURCE` действительным UUID. До замены модель его не примет.
Это declaration для собственного synthetic примера: полнота ACL и конец цепочки не заявляются.

```json
{
  "policy_id": "AUDIT",
  "direction": "in",
  "interface_id": "interface:GigabitEthernet0/0",
  "interface_label": "outside",
  "interface_mapping_reference": "tests/fixtures/network_asa/connected_static_default/interfaces.cfg:2, nameif outside",
  "source_document_id": "ВСТАВЬТЕ_UUID_POLICY_SOURCE",
  "binding_location": {
    "source_name": "policy_quality.cfg",
    "line_start": 12,
    "line_end": 12
  },
  "complete": false,
  "completeness_reference": null,
  "declaration_origin": "synthetic",
  "implicit_action": "unknown",
  "terminal": false,
  "terminal_reference": null,
  "coordinate_space": "acl_input"
}
```

Нажмите **«Одна ACL»**: ожидается `not_enough_evidence`, в том числе отсутствие полноты ACL и
общего observation. Нажмите **«Локальная композиция»**: для этого fixture mapping распознан,
поэтому возвращается `SingleDeviceDecisionResult` со статусом `not_enough_evidence` и отдельными
route/interface/policy этапами. Сопоставление сохраняется в `policy.evidence.facts.interface_mapping`.
Наличие распознанного mapping не делает весь интерфейсный набор полным.

Если импорт отсутствует, label не совпадает, mapping неоднозначен или сам факт интерфейса
неизвестен/неподдержан, композиция отклоняет ввод. Это не повод заменить UUID либо выставить
`complete=true` для прохождения проверки.

Полное локальное решение требует самостоятельного основания полноты ACL, исходной позиции
привязки, согласованного observation и поддержанных фактов. `implicit_deny` дополнительно требует
`implicit_action="deny"`, `terminal=true` и доказательства конца цепочки в `terminal_reference`.
Для fixtures walkthrough этих оснований нет. Нельзя использовать дату создания fixtures,
наличие `access-list` или отсутствие следующей строки как основание полноты/terminal.
Даже доказанный локальный `allow`/`deny` не является итогом всего пути. `no_match` не означает
implicit deny без доказанного конца цепочки.

## 5. «Forwarding ASA»: отдельный конфигурационный контекст

Это независимый parser-сценарий, не обогащение `NetworkImportResult` и не привязка нового ACL
к существующему policy snapshot. UUID выбранной базы передаются в запрос, но application binding
forwarding context пока не реализован. Он показывает интерфейсы, ACL, in/out/global bindings,
inventories, source mapping и parser diagnostics. Сам по себе он не вычисляет полный путь.

Выберите `tests/fixtures/forwarding_asa/ingress_permit_outbound_deny.cfg`.
Его происхождение описано в [README forwarding fixtures](../tests/fixtures/forwarding_asa/README.md)
и [manifest](../tests/fixtures/forwarding_asa/manifest.json). Вставьте следующие metadata:

```json
{
  "purpose": "configuration",
  "command": "show running-config",
  "declared_version": "9.16",
  "version_provenance": "documentation",
  "version_reference": "tests/fixtures/forwarding_asa/manifest.json: declared_version",
  "origin": "synthetic",
  "origin_reference": "tests/fixtures/forwarding_asa/ingress_permit_outbound_deny.cfg",
  "selection": "authored_excerpt",
  "extent": "excerpt",
  "encoding": "ascii",
  "capture_success": false,
  "complete_scopes": [],
  "completeness_reference": null
}
```

Observation оставьте `{}`. В необязательный профиль вставьте:

```json
{
  "context_mode": "single",
  "firewall_mode": "routed",
  "address_family": "ipv4",
  "table_role": "data",
  "table_id": "default",
  "profile_reference": "tests/fixtures/forwarding_asa/manifest.json: ingress_permit_outbound_deny; авторский условный профиль, не runtime evidence"
}
```

Если профиль не заявляется, допустим `{}`. Если его признаки заявлены, `profile_reference`
обязателен. Разрешены только шесть показанных полей; `source`, `metadata`, `revision_id`,
`configuration_id` и `imported_at` переопределять через профиль нельзя.
Имя/хеш/получение источника, device/context и UUID заполняются программой.

Нажмите **«Разобрать отдельный forwarding-контекст»**. Ожидается `ForwardingParseResult 0.1.0`,
контекст с двумя интерфейсами, ACL и привязками, а не firewall/path verdict. Проверьте
`context.inventories`: effective NAT остаётся `unknown`. Конфигурационные NAT и PBR могут
сохраняться как inventory/unsupported diagnostics, но эффективные преобразования и их влияние
не вычисляются. Configured NAT не равен effective NAT.

Adapter требует конфигурационный purpose, точную команду `show running-config` и один
согласованный ASA header. Другие purpose/команды, неполные или конфликтующие заголовки
могут вернуть `ParseFailure`. Перечень fixtures не доказывает промышленную поддержку ASA.
Нельзя направлять RIB в forwarding parser или использовать его новые source UUID как источник
policy binding исходной конфигурации.

## 6. «Результаты / JSON»: сохранение без потери контракта

После задания открывается оригинальный JSON-модельный результат. В списке сверху можно выбрать
сохранённые в памяти результаты этого базового контекста: сетевой импорт, локальные API,
forwarding inventory. Для одной операции хранится последний принятый результат; это не полная
история всех запусков. Предыдущие важные результаты экспортируйте до повторного запуска.

**«Сохранить оригинальную модель JSON»** записывает текущую модель в выбранный локальный файл
UTF-8 через `model_dump_json()`. Сохраняются schema/parser/engine versions, diagnostics,
limitations, sources и evidence. Если текущий просмотр — отдельный `NetworkParseResult`,
экспортируется именно документ; если полный импорт — весь `NetworkImportResult` с ревизией
и документами. Аналогично отдельно экспортируются route, reachability, policy/interface/device
results, forwarding result и `ParseFailure`. Общий выдуманный `AnalysisResult` не создаётся.

Запись выполняется фоново. Сообщение об успешном сохранении относится только к завершённой
записи, не к успешности анализа. Ошибка чтения, валидации или парсинга не должна интерпретироваться
как отсутствие проблем на устройстве. `ParseFailure` можно экспортировать, но он не содержит
успешного инвентаря. Ошибки задания отображаются безопасным сообщением без raw-файла/traceback.

Сетевые формы не загружают обратно JSON snapshot и не восстанавливают сетевые документы
после перезапуска. Qt сохраняет policy-проекты и пользовательские marks в SQLite,
а общий HTML/JSON формирует по policy-запуску. Сетевой JSON остаётся отдельным результатом.

## 7. Проверки результата и ограничения текущего сценария

Пример документа проверен без GUI через те же desktop backend API на перечисленных файлах,
с неизвестными observation/полнотой. В неизменённых fixtures ожидается:

| Действие | Проверенный результат |
| --- | --- |
| Совместный импорт | Три документа: `interfaces` 2 факта, `configured_routes` 2, `routing_table` 4; все наборы `unknown` |
| Выбор RIB | `RouteSelectionResult.status="not_enough_evidence"` |
| Предварительный результат | `ReachabilityResult.status="not_enough_evidence"` |
| Админ. интерфейс outside | `InterfaceDecisionResult.status="unknown"` |
| Одна AUDIT ACL с приведённым binding | `PolicyDecisionResult.status="not_enough_evidence"` |
| Локальная композиция | `SingleDeviceDecisionResult.status="not_enough_evidence"` |
| Отдельный forwarding fixture | `ForwardingParseResult`, effective NAT inventory `unknown` |

Оконный интерфейс не превращает неполные fixtures в достоверный `selected`/`allow`.
Для этих статусов нужны другие источники с реальными доказательствами; изменение metadata
ради желаемого результата нарушает смысл модели. Во всех сценариях читайте reasons/trace/evidence,
а не только status. Окончательная достижимость, NAT/PBR evaluator, полный chain и сетевой CLI
не входят в поддержанный срез. Не предусмотрен общий parser произвольной сетевой очереди.

HP/Aruba и Comware имеют отдельный конфигурационный parser на основном импорте,
но сетевые ASA adapters этой панели их не поддерживают. Juniper не подключён.
Заявленное происхождение внешнего файла не
разрешает принудительно выбрать ASA и показывать synthetic findings как его анализ.
Используйте свои данные только в локальных файлах/экспортах; не добавляйте исходные конфигурации,
секреты или их копии в fixtures, Git и общедоступные артефакты.

Worker не обращается к Qt виджетам; поздний результат сохраняется за своим исходным базовым UUID
и не переключает другой пользовательский контекст. Переход на другую вкладку/раздел либо
смена устройства не означает остановку вычисления: у ядра нет кооперативной отмены.
При возвращении выберите нужный результат из списка. Очередь drafts и последний сетевой импорт
сохраняются в пределах работающего приложения, но заполненные редакторы формы не являются
постоянно сохраняемым проектом.


