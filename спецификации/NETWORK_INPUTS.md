# Сетевые входы Cisco ASA: граница 8.0 и входной срез 8.2

Дополнение 08.11.2026: switch-конфигурации дают отдельный SwitchFacts 1.0.0
в ParseResult (SWITCH_CONFIG_IMPORT.md). Они не являются NetworkSourceKind ASA
или наблюдаемым RIB и не заполняют автоматически known forwarding-наборы.

Дата: 2026-10-10. Статус: граница принята ADR-010, отдельный сетевой adapter 0.1.0 принят ADR-012. Завершение реализации и общих проверок входного среза 8.2 фиксируется отдельно.

## Официальные доказательства

Основной источник - CLI Book 1, Cisco ASA 9.16. Это версия документации, а не подтверждённый вывод конкретной сборки 9.16(x); устройство или эмулятор не использовались.

| Код | Источник | Основание |
|---|---|---|
| C1 | [Интерфейсы routed/transparent, ASA 9.16](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/interface-routed-tfw.html) | Раздел Configure General Routed Mode Interface Parameters: interface, nameif, security-level, IPv4 адрес/маска, DHCP |
| C2 | [Базовые интерфейсы, ASA 9.16](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/interface-basic.html) | Административная настройка и состояние интерфейса |
| C3 | [Статические маршруты, ASA 9.16](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/route-static.html) | Configure Default/Static Routes, Route to null0, Static Route Tracking |
| C4 | [Маршрутизация, ASA 9.16](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/route-overview.html) | Routing tables, Display the Routing Table; примеры интерфейсов и строк C/S/S* |
| R1 | [Справочник show running-config/show route](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/m_show_p-show_r.html) | Синтаксис выборки команды, история формата и local routes |
| R2 | [Справочник route](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/ret-rz-commands.html) | Пример route null0 без gateway |

R1/R2 обновляемые, не привязанные исключительно к 9.16 справочники. Более поздние возможности не включаются автоматически. Полный running-config пример R1 относится к 9.0(1), а не доказывает формат полного экспорта 9.16.

C3 называет аргумент distance административной дистанцией и ограничивает 1..254; R2 использует имя аргумента metric для административной дистанции и допускает 255. Первый срез принимает явно заданные 1..254, вариант 255 требует отдельной проверки. В RIB значения в скобках distance/metric не смешиваются с одним аргументом конфигурации. Документированный default не становится наблюдаемым значением: неуказанные аргументы не угадываются.

Пример C4 не перечисляет все возможные строки современного RIB. R1 указывает local host routes L с 9.2(1). Вывод Null0 в RIB для точного формата 9.16 здесь не установлен; такую строку не придумываем.

R1 различает `show running-config [all] [command]`: selector command выбирает раздел, `all` включает defaults. Для `show route` protocol/address selectors ограничивают выборку, `summary` не содержит обычный перечень маршрутов, `management-only` выбирает management RIB. `domain-name` появился в 9.20(2) и не включается в профиль 9.16. Полный результат выбранной команды не доказывает полноту более широкой области.

Целевая заявленная версия адаптера - `9.16` / `9.16(x)`. `version_provenance=documentation` либо `operator_declared` сохраняет происхождение заявления; эти значения не доказывают capture конкретной сборки. Даже заявление `device_export` требует отдельной ссылки на происхождение, а SHA-256 сам по себе не подтверждает подлинность Cisco.

## Выбранная узкая граница

IPv4 unicast, routed mode, одно устройство, `context_mode=single`, `context=None`, `table_role=data`, `table_id=default`; обычные физические L3-интерфейсы с явным IPv4/непрерывной dotted mask. Интерфейсные labels не объявляются зонами или доверенными сетями. Наличие IP и отсутствие shutdown не доказывают operational state и не дают автоматического enabled=true.

Конфигурационная часть: interface/nameif/security-level/ip address, явно настроенные статические/default маршруты без tracking, конфигурационный Null0. RIB: только документированные формы C/S/S* с dotted mask. Полнота RIB оценивается по фактическому содержимому и metadata; наличие неподдержанных строк сохраняет частичный результат.

## Форматы и выбор роли

| Метаданные source_kind | Команда | Роль |
|---|---|---|
| asa_running_config_interfaces | show running-config interface | Настроенные интерфейсы; выбранный один интерфейс не является полным инвентарём |
| asa_running_config_static_routes | show running-config route | Настроенные IPv4 маршруты, не установленные маршруты |
| asa_ipv4_rib | show route | Наблюдаемая IPv4 data/default таблица; параметры и pipe-filter не входят в профиль |

Полный show running-config остаётся форматом существующего ACL адаптера ADR-005. Сетевой `NetworkFactsParser` работает отдельно от ACL `ParserRegistry`, с `parser_id=cisco-asa-network-9.16`, `parser_version=0.1.0`. Исходный fixture набор содержит тела разделов/выдержки. Selector раздела использует синтаксис show running-config [command] из R1; конкретную доступность на выбранной сборке необходимо подтвердить до коммерческой поддержки. Полный успешный результат selector может покрывать свой раздел, но не полную конфигурацию или RIB.

Adapter 0.1.0 принимает только точные команды из таблицы, без дополнительных аргументов, `all` или pipe-filter. Документированные Cisco варианты приведены выше для объяснения ограничений selection/table/version, а не как поддержанные команды этого адаптера.

`NetworkDocumentMetadata` имеет `schema_version=0.1.0`. Обязательны source_document_id, source_kind, command, declared_version, version_provenance/version_reference, origin/origin_reference, device_id/context_mode, режим, адресное семейство, table_role/table_id, SHA-256 исходных байтов, encoding, selection, extent и capture_success. Заявление complete по умолчанию false; true требует completeness_reference. Поддержанная область проверяется явно, а не подставляется из defaults доменной Route. `NetworkParseRequest` обязан проверить совпадение хеша с байтами SourceDocument до разбора; encoding задаёт декодирование. Каждый факт и отдельные настройки имеют source mapping. ObservationEvidence и его observed_at задаются независимо от captured_at/mtime; неизвестное наблюдение блокирует known/absent.

По телу interface/route, имени файла или одной строке RIB нельзя установить версию, команду, контекст и полноту. Пустой документ нельзя автоматически определить. Detect без явных сетевых metadata не выбирает роль. Sidecar проекта не является форматом Cisco; его отдельный runtime-контракт определён в parsers/network_contracts.py. Метаданные, противоречащие роли/команде или поддержанной области, требуют диагностики, а не угадывания.

## Представление и обогащение

`NetworkParseResult` 0.1.0 независим от ACL ParseResult и имеет ровно одну область: interfaces, configured_routes либо routing_table. `Interface.name` - физический ID; label и security_level сохраняются отдельно в InterfaceSettings со ссылками на исходные строки. По C1 nameif нечувствителен к регистру и имеет длину до 48 символов. Binding разрешается однозначно внутри устройства и контекста; повтор label, конфликт физических IDs или отсутствующая связь не допускают выбора первого/последнего значения и блокируют полноту. Label не становится zone. Явное no shutdown означает административную настройку, а не link/protocol up.

Application создаёт только новую DeviceRevision, копирует исходные sources и повторно валидирует результат. Существующая ревизия и уже имеющиеся сетевые факты не перезаписываются. `NetworkImportResult.documents` сохраняет результаты всех документов и отдельный provenance configured routes. При наличии RIB выбирается именно она, даже частичная; config не дополняет её пробелы. При отсутствии RIB configured routes сохраняют конфигурационный scope и не считаются установленными. Конфликты с существующими фактами требуют явной диагностики.

DeviceRevision остаётся 2.0.0, ACL parser остаётся 0.2.0. Этот входной срез 8.2 не вводит CLI, policy decision или вердикты reachable/blocked.

## Формы текста

Ниже ограниченные формы для fixtures, не полная грамматика производителя:

```text
interface <physical-id>
 nameif <label>
 security-level <0..100>
 ip address <host-ipv4> <dotted-mask>
!
route <label> <network-ipv4> <dotted-mask> <next-hop-ipv4> <distance>
route <label> 0.0.0.0 0.0.0.0 <next-hop-ipv4> <distance>
route null0 <network-ipv4> <dotted-mask>
C    <network-ipv4> <dotted-mask> is directly connected, <label>
S    <network-ipv4> <dotted-mask> [<distance>/<metric>] via <next-hop-ipv4>, <label>
S*   0.0.0.0 0.0.0.0 [<distance>/<metric>] via <next-hop-ipv4>, <label>
```

Null0 здесь не получает выдуманный gateway или наблюдаемую дистанцию: отсутствующая AD сохраняется как None. Обычный static/default требует явную AD 1..254. Строка C не содержит distance/metric; оба поля остаются None, отсутствие значения не является наблюдаемым нулём. Сеть интерфейса вычисляется отдельно и не становится наблюдаемым connected route автоматически.

## Полнота и ограничения

- Настроенные маршруты не доказывают полную RIB; её отсутствие сохраняется отдельно.
- Отсутствующий документ не является пустым набором. Пустой набор требует полного успешного захвата соответствующей области и известного наблюдения.
- Выдержка, фильтр, повреждение и усечение сохраняют неизвестность. Показатель количества разобранных строк не доказывает полноту.
- Known требует совместно selection=all, extent=full, capture_success=true, complete=true с completeness_reference, известное согласованное наблюдение, чистый разбор и известные факты. Для пустого набора эти же условия допускают absent. Unsupported/malformed, warnings/errors и отсутствующий/неоднозначный binding блокируют полноту независимо от доли распознанных строк.
- Полнота относится только к согласованным роли, команде, устройству/контексту, family/table и наблюдению. Full означает весь результат команды; single_interface, protocol/address selection и pipe-filter не доказывают общий all-scope набор.
- Полная понятная RIB может доказать отсутствие подходящего маршрута только в своём контексте/семействе/времени, но не общий вердикт Firewall Assurance.
- Административная настройка не доказывает link/protocol up, ARP/соседа, FIB, доставку пакета или работу приложения.
- L, динамика, ECMP/continuation rows, DHCP/PPPoE, tracking/SLA, PBR, VPN, management tables, IPv6, multicast, bridge/BVI, subinterfaces, EtherChannel, failover/cluster и multi-context требуют последующих срезов или явной unsupported диагностики.
- Фактические неподдержанные L/dynamic/continuation строки сохраняют partial результат и source mapping; упоминание кода в легенде само по себе не является строкой маршрута. Настроенный Null0 не становится наблюдаемым discard.
- NAT, ACL completeness/direction, security-level policy, inspection, reverse path и stateful behavior остаются самостоятельными источниками/семантикой.

## Синтетические доказательства

[README](../tests/fixtures/network_asa/README.md) и [manifest](../tests/fixtures/network_asa/manifest.json) содержат три сценария и восемь собственных payloads: connected/static/default; более узкий маршрут и настроенный Null0 без RIB; DHCP/tracking и оборванная RIB.

Исходные восемь payloads и manifest не меняются: extent остаётся excerpt либо truncated, complete=false, observed_at=null. Все RIB здесь являются выдержками. Файлы не подтверждают полного вывода оборудования, фактического времени наблюдения или reachable. Созданная для теста synthetic complete record с явными metadata/observation проверяет переходы контракта, но не является реальным полным аппаратным экспортом. Хеши защищают байты, а не подлинность производителя. Legacy baseline не меняется. Дальнейшая работа требует проверки точного варианта вывода; коммерческий статус остаётся экспериментальным. Число тестов, результаты общих checks и завершение реализации приведены в TASK-008_NETWORK_ASSURANCE.md.
