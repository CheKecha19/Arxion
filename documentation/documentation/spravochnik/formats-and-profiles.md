# Форматы и профили

Эта страница описывает JSON-входы рабочего дерева Arxion 0.13.0. Примеры синтетические; они показывают структуру, но не являются утверждённой политикой вашей организации. Сохраните каждый пример в отдельный файл UTF-8 и передайте соответствующей опции CLI.

Не копируйте идентификаторы примеров в оценку реальной инфраструктуры. ID правила, политики, компонента и UUID ревизии нужно брать из конкретного сохранённого результата. Статическая сверка примеров выполнена по моделям; выполнение CLI с ними здесь не подтверждалось.

## Различайте документы

| Документ              | Как получают                                       | Где используют                                                 |
| --------------------- | -------------------------------------------------- | -------------------------------------------------------------- |
| Исходная конфигурация | Экспорт устройства или собственный снимок сборщика | analyze, analyze-bundle, inspect, acl-map build                |
| DeviceRevision        | Сохранённая нормализованная ревизия                | acl-map build/batch с --revision-json                          |
| Firewall Assurance    | analyze                                            | Просмотр результата этого анализа                              |
| AnalysisResult        | analyze-bundle, общий результат GUI                | analysis-export, controls assess, governance assess            |
| AclMap                | acl-map build                                      | acl-map export/save                                            |
| Пакет карт            | acl-map batch                                      | Разбор результатов и отказов пакета; не вход одиночного export |
| ControlAssessment     | controls assess                                    | controls export                                                |
| Сверка матрицы        | Сохранённая сверка GUI                             | Предпросмотр и экспорт матрицы                                 |

Сгенерированные снимки и результаты сохраняйте полностью: удаление непонятных полей может нарушить связь с исходниками, параметрами или контрольными суммами. Форматы больших результатов следует получать через приложение, а не собирать вручную.

## Профиль управления устройствами

Передаётся через --management-profile. Пример:

```json
{
  "profile_id": "demo-management",
  "version": "1",
  "approved_admin_networks": ["192.0.2.0/24"],
  "approved_snmp_networks": ["192.0.2.0/24"],
  "approved_syslog_servers": ["198.51.100.10"],
  "approved_ntp_servers": ["198.51.100.11"],
  "allow_snmp_write": false,
  "require_syslog": true,
  "require_ntp": true,
  "require_banner": true,
  "max_idle_seconds": 900
}
```

Все поля имеют значения по умолчанию; пустой объект означает базовый профиль, а не отсутствие требований. По умолчанию требуются syslog, NTP и banner; SNMP write запрещён, максимальный idle timeout равен 900 секундам.

Для approved\_\* различаются:

* поле отсутствует или null — организационный список не задан;
* \[] — явно задан пустой список;
* массив значений — конкретные разрешённые сети или серверы.

Сети управления задаются корректными сетевыми CIDR: адрес с установленными host bits, например 192.0.2.1/24, не следует использовать вместо 192.0.2.0/24. Серверы могут быть IP-адресами или DNS-именами; сравнение не выполняет DNS-запросы. max\_idle\_seconds — целое от 1 до 86400. Не добавляйте пароли и SNMP community: это профиль требований, а не подключение.

## Профиль опасных и административных сервисов

Передаётся через --policy-exposure-profile.

```json
{
  "schema_version": "1.0.0",
  "profile_id": "demo-exposure",
  "version": "1",
  "dangerous_services": [
    {
      "selector_id": "telnet",
      "name": "Telnet запрещён политикой",
      "protocol": "tcp",
      "port_ranges": [{"start": 23, "end": 23}]
    }
  ],
  "administrative_services": [
    {
      "selector_id": "ssh",
      "name": "Администрирование SSH",
      "protocol": "tcp",
      "port_ranges": [{"start": 22, "end": 22}]
    }
  ],
  "administrative_targets": ["198.51.100.0/24"],
  "trusted_admin_networks": ["192.0.2.0/24"]
}
```

Профиль задаёт значение сервиса явно; приложение не должно угадывать организационное назначение порта. Для TCP/UDP нужен непустой список port\_ranges. Каждая граница — число 0–65535, end не меньше start. Для ICMP список портов должен отсутствовать или быть пустым.

selector\_id уникален внутри соответствующего каталога. dangerous\_services, administrative\_services, administrative\_targets и trusted\_admin\_networks допускают null: это неизвестная политика. Пустой массив — явный пустой набор требований. Не заменяйте одно другим.

## Профиль области и чрезмерного доступа

Передаётся через --policy-scope-profile. Минимальный практический пример порогов:

```json
{
  "profile_id": "demo-scope",
  "version": "1",
  "excessive_access_enabled": true,
  "max_source_addresses": 256,
  "max_destination_addresses": 16,
  "max_destination_ports": 10
}
```

Пример задаёт только пороги: отсутствие role\_requirements оставляет ролевые требования неизвестными и может дать ROLE\_ACCESS\_POLICY\_UNKNOWN. Если ролевых требований явно нет, добавьте "role\_requirements": \[].

При excessive\_access\_enabled=true обязателен хотя бы один порог. При false пороги должны отсутствовать либо быть null. Число адресов не меньше 1; число портов — 1–65536. Исключения задаются массивом exception\_rule\_ids с реальными уникальными ID правил.

Пример требования к роли и к применению ACL:

```json
{
  "profile_id": "demo-role-and-attachment",
  "version": "1",
  "role_requirements": [
    {
      "requirement_id": "employee-portal",
      "role_id": "employee",
      "destination_networks": ["198.51.100.20/32"],
      "approved_source_networks": ["192.0.2.0/24"],
      "approved_services": [
        {
          "selector_id": "https",
          "name": "Портал HTTPS",
          "protocol": "tcp",
          "port_ranges": [{"start": 443, "end": 443}]
        }
      ]
    }
  ],
  "attachment_inventory_complete": true,
  "required_attachments": [
    {
      "requirement_id": "uplink-in",
      "subject_kind": "interface",
      "subject_id": "demo-interface-id",
      "direction": "in",
      "allowed_policy_ids": ["demo-policy-id"]
    }
  ]
}
```

Идентификаторы demo-interface-id и demo-policy-id замените идентификаторами из нормализованных данных, а не похожими подписями интерфейса. role\_id (employee в примере) — устойчивый организационный идентификатор роли; сопоставление требований выполняется по сетям и сервисам, а не поиском этой роли в ревизии.

Во втором примере не заданы пороги excessive\_access\_enabled: возможна диагностика EXCESSIVE\_THRESHOLDS\_UNKNOWN. Если пороговый анализ сознательно не нужен, добавьте "excessive\_access\_enabled": false.

Для subject\_kind=interface обязательно направление in или out. Для user\_role направление должно отсутствовать/null. requirement\_id уникален во всём профиле, включая обе коллекции требований. Не утверждайте attachment\_inventory\_complete=true, если полнота инвентаря применения ACL не подтверждена.

## Профиль governance

Governance использует метаданные и статистику правил конкретной сохранённой ревизии. Профиль передаётся через governance assess --profile.

```json
{
  "profile_id": "demo-governance",
  "version": "1",
  "lifecycle_enabled": true,
  "require_owner": true,
  "require_justification": true,
  "require_temporary_expiry": true,
  "require_review_date": true,
  "include_disabled_rules": false,
  "unused_enabled": true,
  "unused_min_observation_seconds": 86400,
  "unused_max_age_seconds": 604800
}
```

Неуказанное/null требование отличается от явно отключённого false. Интервал наблюдения — целое 1–315360000 секунд, максимальный возраст — 0–315360000 секунд. Одного нулевого значения счётчика недостаточно, чтобы заключить, что правило не используется.

### Свидетельства governance

Файл --inputs относится строго к одной ревизии. Все записи внутри него должны иметь тот же revision\_id. В примере UUID и ID правила демонстрационные:

```json
{
  "schema_version": "1.0.0",
  "input_id": "demo-evidence",
  "revision_id": "11111111-1111-4111-8111-111111111111",
  "metadata": [
    {
      "evidence_id": "metadata-rule-1",
      "revision_id": "11111111-1111-4111-8111-111111111111",
      "rule_id": "demo-rule-1",
      "observed_at": "2026-11-13T09:00:00Z",
      "reference": "demo-change-42",
      "source_location": {
        "source_name": "demo-register.json",
        "object_path": "/rules/demo-rule-1"
      },
      "owner": "Сетевая команда",
      "justification": "Доступ к демонстрационному порталу",
      "temporary": false,
      "review_status": "known",
      "review_at": "2027-01-01T00:00:00Z"
    }
  ],
  "statistics": [
    {
      "evidence_id": "statistics-rule-1",
      "revision_id": "11111111-1111-4111-8111-111111111111",
      "rule_id": "demo-rule-1",
      "observed_at": "2026-11-13T09:00:00Z",
      "reference": "demo-counter-window",
      "source_location": {
        "source_name": "demo-counters.json",
        "object_path": "/rules/demo-rule-1"
      },
      "window_start": "2026-11-12T09:00:00Z",
      "window_end": "2026-11-13T09:00:00Z",
      "hits": 0,
      "count_kind": "window_delta",
      "coverage": "complete",
      "counter_resets": 0,
      "revision_stable": true
    }
  ]
}
```

Для реальной оценки замените revision\_id на UUID ревизии выбранного --component, а rule\_id — на существующее правило этой ревизии. Совпадение имени правила в другом снимке не делает данные совместимыми.

Обязательные поля документа: input\_id и revision\_id; metadata/statistics по умолчанию пусты. В каждой записи обязательны evidence\_id, revision\_id, rule\_id, observed\_at, reference, source\_location. evidence\_id уникален по всему документу; в каждой коллекции допускается одна запись на правило.

owner/justification=null означают неизвестность, пустая строка — известное отсутствие. Для expiry\_status и review\_status допустимы known, absent, unknown. known требует соответствующую дату expires\_at/review\_at; absent/unknown не допускают дату.

Все даты должны иметь часовой пояс. Окно статистики задаётся обеими границами, начало не позже конца, observed\_at не раньше конца окна. count\_kind: window\_delta, cumulative\_sample или unknown; coverage: complete, partial или unknown. Снимок накопительного счётчика не заменяет дельту за подтверждённый интервал.

Дата оценки --assessed-at должна быть не раньше окончания исходного результата и сохранённых пользовательских решений. Без --inputs предыдущие свидетельства автоматически не переиспользуются.

## Карта IP → роль для контроллера

Параметр controller-role --user-roles принимает простой JSON-объект, а не профиль governance:

```json
{
  "192.0.2.10": "employee",
  "198.51.100.20": "application"
}
```

Ключи и значения должны быть строками. Смысл — IP-адрес и известная роль адреса в контексте запроса. Не помещайте сюда пользователей, пароли или списки правил. Имена ролей должны соответствовать контексту выбранного экспорта. --at-time для запроса также требует явного часового пояса.

## Профиль технических контролей

controls assess принимает AnalysisResult и профиль OrganizationControlProfile. Минимальный пример с существующим ID внутреннего каталога:

```json
{
  "schema_version": "1.0.0",
  "profile_id": "demo-controls",
  "version": "1",
  "organization": "Демонстрационная организация",
  "scope_reference": "Проект демонстрационного стенда",
  "requirements": [
    {
      "control_id": "TECH-POLICY-LOGGING",
      "applicable": true,
      "justification": "Правила должны журналироваться",
      "parameters": {"require_logging": true}
    }
  ]
}
```

Обязательны profile\_id, version, organization, scope\_reference и непустые requirements. Для каждого требования нужны control\_id, applicable и justification.

Если component\_ids отсутствует или null, выбираются все policy-компоненты сохранённого bundle, а не все устройства организации. Чтобы задать точную область, добавьте непустой массив уникальных реальных component\_id:

```json
{
  "profile_id": "demo-controls-one-component",
  "version": "1",
  "organization": "Демонстрационная организация",
  "scope_reference": "Один компонент сохранённого результата",
  "component_ids": ["demo-component-id"],
  "requirements": [
    {
      "control_id": "TECH-BROAD-ALLOW",
      "applicable": true,
      "justification": "Проверка широких разрешений"
    }
  ]
}
```

demo-component-id обязательно заменяется на ID из AnalysisResult. Сами результаты содержат связь с revision\_id. Не переносите исключение или свидетельство на другой компонент по совпавшему названию устройства.

parameters сравниваются с сохранёнными параметрами анализа, а не перенастраивают и не запускают исходную проверку. Допустимые ключи: require\_logging, require\_comments, management\_profile, exposure\_profile. При несовпадении параметров нельзя считать свидетельства достаточными.

Внутренний каталог включает TECH-BROAD-ALLOW, TECH-POLICY-LOGGING, TECH-POLICY-COMMENTS, TECH-DANGEROUS-SERVICES и TECH-ADMIN-SOURCES. Получайте актуальный каталог командой controls catalogue.

### Исключения контролей

Необязательный массив exceptions содержит записи со следующими обязательными полями: exception\_id, control\_id, component\_id, finding\_id (UUID находки), reason, approved\_by, approved\_at, expires\_at. Даты имеют часовой пояс, expires\_at позже approved\_at. control\_id должен быть выбран в requirements; component\_id должен попадать в явно заданную область, если она есть.

Исключение относится к точной находке и компоненту. Его наличие не доказывает устранение технического нарушения и не означает сертификацию. Не создавайте исключения с вымышленными согласующими лицами.

## Происхождение данных

SourceLocation указывает, где проверить утверждение. Обязателен source\_name и хотя бы один якорь: line\_start, object\_path или object\_id. line\_start — от 1; line\_end допустим только вместе с line\_start и не меньше него.

Используйте реальное происхождение свидетельства. Корректный синтаксис ссылки не делает её доказательством, если соответствующий источник не существует.

## Проверка совместимости

При отказе импорта:

1. Уточните ожидаемый тип документа команды.
2. Проверьте кодировку UTF-8 и JSON без комментариев.
3. Сверьте версии схем и допустимые поля.
4. Различайте null, пустой массив, false и неизвестное состояние.
5. Для governance сопоставьте component → revision → rule; для контролей — component → finding → exception.
6. Сохраните исходный файл и исправляйте отдельную копию.

Примеры описывают формат входов. Они не заменяют организационное утверждение требований, подтверждение полноты экспорта или проверку качества статистики.

## Связанные разделы

* [Командная строка](cli.md)
* [Проверки и результаты](../prakticheskie-rukovodstva/checks-and-results.md)
* [Общее оглавление](../)
