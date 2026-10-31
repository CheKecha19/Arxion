# Карта ACL: фильтры, пакетный запуск и сохранение

Этот workflow продолжает ADR-020. `AclMap` 1.0.0 / analyzer 0.1.0 сохраняет
исходный контракт: одна связь на правило, полная нормализованная ревизия,
источники, SHA-256 и ограничения. Старые JSON/DOT не меняют формат. Наличие
ALLOW, пересечения адресов или совпадения фильтра не доказывает разрешённый путь.
Порядок применения, маршруты, NAT и first-match здесь не вычисляются.

## Фильтры представления

`analysis.acl_map.AclMapFilter` и `filter_acl_relations(graph, filters)` добавляют
source/destination CIDR, протокол и destination port к существующим policy/rule/
action/enabled фильтрам. Условия объединяются через AND. CIDR означает
пересечение с адресными условиями правила, а не полное включение, выбор
конкретного устройства или доказательство достижимости. Host нормализуется в
/32 или /128; IPv4 и IPv6 не смешиваются. Порядок исходных правил сохраняется.
Сервис IP соответствует любому протоколу. Порт применим к TCP/UDP; сочетание
порта с ICMP отвергается.

Неизвестные условия не становятся ANY. При невозможности решить совпадение
правило по умолчанию остаётся видимым (`include_unknown=True`). Явное исключение
неизвестных меняет только вид. Известное несовпадение одного измерения исключает
правило даже при неизвестности другого измерения. Наличие неизвестных условий
и полная диагностика остаются в исходной карте. Фильтр не изменяет ревизию,
relations, nodes, полноту или ограничения сохранённого результата.

`export_acl_map_html(graph, filters=...)` создаёт автономный UTF-8 HTML с
фильтрами, числом выбранных/всех правил, источниками, ревизией, действиями,
активностью, последовательностью, нормализованными условиями и source mapping.
Все значения источника экранируются. JSON/DOT сохраняют полную карту; CLI
отвергает сетевые фильтры для этих форматов, чтобы не выдать неполный результат
за полный снимок. PNG и интерактивное отображение относятся к Qt-слою.

## Пакетный охват

`build_acl_map_batch(((reference, revision), ...), built_at=..., failures=...)`
возвращает `AclMapBatch` schema 1.0.0, mode `declared_rules_batch`.
Каждый item содержит независимую полную карту и уникальную ссылку на вход.
Одинаковые имена устройств, ACL, адреса и даже совпадающие revision UUID не
сливают источники разных входов. Для одного и того же снимка его внутренние IDs
сохраняются; потребитель обязан использовать также input_reference.

Отказы представлены отдельно в `failures`: reference, code, message, известные
source_name/content_sha256 и диагностика парсера. Отказ не создаёт пустую карту
и не доказывает отсутствие правил. Пустой набор items/failures означает пустой
запрос, а не успешное исследование инфраструктуры. Снимки и диагностика глубоко
заморожены. Дублирующиеся references и превышение бюджета дают явный отказ.
По умолчанию до 1000 входов и суммарно 100000 правил; CLI дополнительно
ограничивает каждый входной файл 64 МиБ.

Парсеры берутся из существующего registry. Добавление CLI не расширяет
поддержку ArubaOS controller, Cisco effective NAT/PBR или иных платформ.
Полнота документа и область поставщика не угадываются. Поддержанные
HP/Aruba AOS-S/AOS-CX и Comware используют прежние adapters.

## Аддитивное SQLite-хранилище

`application.acl_map_store.AclMapStore(connection)` получает существующее
SQLite-соединение с таблицами projects/runs/items. Модуль не открывает файлы,
не обращается к Qt, исходным конфигурациям или облачным аккаунтам.
Он добавляет только `acl_maps`, индекс проекта и запрет UPDATE/DELETE
append-only triggers; `PRAGMA user_version` и старые таблицы не меняются.
База с user_version > 1 отвергается, как в текущем ProjectStore.

- `save(project_id, graph, run_id=None, item_id=None, map_id=None) -> str`:
  validates полную проекцию, подтверждает проект и при наличии run/item
  требует точную сохранённую DeviceRevision из этой области. Совпадения
  UUID или имени недостаточно. item без run запрещён.
- `get(project_id, map_id) -> AclMap`: проверяет область проекта, checksum,
  метаданные, текущие связи с исходным сохранённым run/item и проекцию.
- `list(project_id) -> list[AclMapRecord]`: возвращает краткие проверенные
  метаданные, не превращая повреждённый payload в достоверную запись.
- `initialize=False`: чтение уже существующей таблицы без DDL; отсутствующая
  таблица даёт явный отказ. CLI list/load используют SQLite mode=ro.

Checksum покрывает payload и id/project/run/item/revision/created_at/built_at/
rule_count. Это обнаружение случайной порчи, а не подпись и не доказательство
авторства. Повторный save с тем же map_id и точно тем же содержимым идемпотентен;
конфликт отвергается. Savepoint не коммитит чужую внешнюю транзакцию.
До 64 МиБ UTF-8 payload на одну сохранённую карту. Все карты содержат
чувствительные нормализованные данные; экспорт не выполняет маскирование.

## CLI

Root CLI регистрирует `interfaces.cli.acl_map_commands.app` как `acl-map`:

```text
firewall-compliance acl-map build switch.cfg --output map.json
firewall-compliance acl-map build revision.json --revision-json --output map.json
firewall-compliance acl-map batch one.cfg two.cfg --output maps.json
firewall-compliance acl-map export map.json --output map.html --format html \
  --source 192.0.2.0/24 --destination 198.51.100.0/24 --protocol tcp --port 443
firewall-compliance acl-map save map.json --database projects.sqlite3 --project PROJECT_ID
firewall-compliance acl-map save map.json --database projects.sqlite3 --project PROJECT_ID \
  --run RUN_ID --item ITEM_ID
firewall-compliance acl-map list projects.sqlite3 --project PROJECT_ID
firewall-compliance acl-map load projects.sqlite3 --project PROJECT_ID --map-id MAP_ID \
  --output restored-map.json
```

Batch пишет пригодные карты и явные отказы вместе; при любом отказе exit code 2.
Source-independent export/load не перечитывают конфигурацию. Отчёт не может
перезаписать выбранный вход, в том числе через hardlink. JSON-входы — UTF-8 с
необязательным BOM, не более 64 МиБ. Неизвестные версии, неверные снимки,
несуществующие проекты и некорректные фильтры дают безопасный отказ.
CLI не создаёт новую пустую базу при опечатке в пути.

## Qt и проверка

На карте заданных правил есть фильтры источника/назначения IP/CIDR,
протокола/порта, показ неизвестных условий и экспорт текущего вида HTML/PNG.
Исходная карта не изменяется фильтром. PNG содержит источник, SHA-256 и
ограничения; размер ограничен16 млн пикселей и16384 по стороне. При превышении
бюджета выводится отказ с предложением уточнить фильтры, а не обрезанная карта.

«Архив ACL…» открывает сохранённые карты проекта и пакетный выбор входов
запуска. Можно сохранить текущую карту, загрузить прежнюю, выбрать входы либо
весь запуск. Карты сохраняют точную project/run/item provenance. Отказы и
отменённые входы показаны отдельно; успешные записи пакета сохраняются атомарно.
Смена проекта исключает устаревшую доставку; отмена очереди освобождает controls.
Повторное открытие приложения не требует исходных конфигураций для карты.

`tests/regression/test_acl_map_workflow.py`: synthetic semantic IPv4/IPv6/service
filters, unknown cases, HTML escaping/provenance, batch isolation/budgets/failures,
SQLite additivity/persistence/project/run/item boundaries/immutability/tamper/
transaction rollback, CLI build/batch/export/save/list/load and hardlink refusal.
Legacy unit/integration ACL map tests retain JSON/DOT contracts.

Дополнительно:21 real CLI tests,15 Qt filter/export tests и13 project Qt/SQLite
tests. Проверены сохранение, перезапуск, исходные снимки, ошибки/отмена и
проектная изоляция. PNG просмотрен со шрифтом Arial из Windows в offscreen;
это не видимая нативная приёмка и не clean Windows OS validation.
