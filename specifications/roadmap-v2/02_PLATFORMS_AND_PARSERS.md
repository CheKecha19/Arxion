# Платформы, парсеры и достоверность нормализации

Дата исследования: 14.10.2026. Расширение всех пунктов раздела 4 первого roadmap. Это исследование и проект требований, а не заявление о выполненной реализации. Код приложения и тесты не изменялись, оборудование не опрашивалось. Российские UserGate, Ideco и PT NGFW обязательны; порядок зависит от готовности подтверждённых входов. Новое развитие Cisco отложено, существующие сценарии должны сохраняться.

## 1. От чего отталкиваемся

Проверенный `src/firewall_compliance/parsers/catalog.py` включает только `CiscoAsaParser`, `HpArubaParser`, `ComwareParser`. Старые описания UserGate, Huawei и Juniper в `SUPPORTED_PLATFORMS.md` относятся к наследию прототипа; они не доказывают наличие адаптера в новом каталоге. Остаточный `__pycache__/juniper...` также не является исходным кодом подключённого адаптера. HP/Aruba уже различает AOS-Switch, AOS-CX и неподдержанный controller-синтаксис; Comware намеренно отвергает Huawei/VRP. Это полезные границы, их необходимо сохранить.

`Rule` уже содержит последовательность, действие, активность, адреса, сервисы, зоны, описание, owner, policy_id, direction и first_match. Но отдельного проверяемого условия source port, application, identity, time, VRF и NAT в этой модели нет. `Endpoint` представляет CIDR, диапазон и FQDN, но не хранит исходный граф членства групп. `Service` хранит один протокол и destination port ranges; `PortRange` допускает 1…65535. Это необходимо учитывать для платформ с документированным портом 0: либо расширять контракт отдельным ADR и проверять совместимость, либо сохранять такую конструкцию unsupported, не менять её на 1.

`ParseResult` требует source_map для каждого правила и согласованность ссылок. `ParseCoverage` считает конструкции внутри выбранного среза. Даже coverage=1 не доказывает полноту конфигурации устройства: файл с одной ACL может быть разобран идеально и не содержать остальных политик. Registry выбирает по содержимому, при равном максимальном confidence сообщает неоднозначность. В будущем confidence detection остаётся эвристикой выбора, а не статистической точностью анализа.

В `tests/contract` существуют контракты HP/Aruba и Comware, присутствуют synthetic fixtures и golden-инфраструктура. Исследование подтвердило их наличие, но не прохождение. Сетевые входы и forwarding описаны отдельными ASA-контрактами; из их существования нельзя автоматически вывести готовность сетевого анализа новых производителей.

## 2. Общая стратегия: шесть независимых ступеней

**Parser** устанавливает производителя, продукт, версию, формат и границы снимка; разбирает синтаксис без потерь. **Resolver** связывает объекты, группы и сервисы, обнаруживает циклы и неизвестные ссылки. **Bindings** устанавливает место применения, направление, область, порядок и default action. **Checks** запускает только проверки, предпосылки которых подтверждены. **Map** показывает настроенные связи с ограничениями. **Network** добавляет интерфейсы, VRF, маршруты, NAT, stateful-семантику и обратное направление. Каждая ступень имеет собственный статус; готовность первой не повышает автоматически остальные.

Потенциал подхода — единые поиск, карточки и проверки для разных вендоров при сохранении существенных различий. Пользователь сможет сравнить два снимка и увидеть, что изменилась политика, объект, применение или качество входов. Он сможет перейти от находки к точному фрагменту, а от отсутствующей возможности — к инструкции получения конкретного файла. Для большой группы правил сначала отображается символическая группа; её содержимое раскрывается отдельно. Декартово произведение адресных групп не требуется для интерфейса и не должно бесконтрольно создаваться в памяти.

Срез определяется кортежем «vendor/product/release/model/exporter/version/format/policy-kind/context/address-family». Например, «Junos set IPv4 stateless filter» не означает «SRX security policies и NAT». В паспорте дополнительно фиксируются область выгрузки, доступ пользователя к разделам и границы времени capture. Все существенные неподдержанные условия сохраняются: их нельзя удалить и затем оценивать упрощённое правило как полное.

## 3. Матрица возможностей по срезам

Обозначения: **E** — существующий экспериментальный срез, установленный по коду; **P** — проект следующего среза; **U** — внешний формат или семантика требуют подтверждения; **—** — в этот срез не входит. Таблица не является рекламной матрицей готовой поддержки.

| Срез | Policy/objects | Resolver | Bindings/order | Checks/map | Interfaces/routes | NAT/time/identity/apps/counters |
|---|---|---|---|---|---|---|
| AOS-S IPv4 ACL | E: ограниченные адреса/порты | E/P: явные значения, новые ссылки отдельно | E: interface/VLAN; management отдельно | E в пригодных областях / расширение P | P: сначала configured interfaces/VLAN | U/P по отдельным условиям; NAT — |
| AOS-CX IPv4 ACL | E: access-list ip | E/P | E: interface/VLAN/control-plane; режим применения сохранить | E/P | P: VRF и RIB отдельным входом | P: counters; остальные по паспорту |
| Comware IPv4 basic/advanced | E: rule, eq/range | E/P | P: packet-filter; auto U до проверки release | Ограниченный E; полный срез P | P | P: time/counters/SNMP; NAT отдельно |
| UserGate 7.5+ native text | P; транспорт подтверждён, полная grammar U | P | P после экспорта | P | P после грамматики | U/P независимо по типам |
| UserGate converter package | P; exporter-specific контракт U | P | P: device/MC templates различать | P | P | U/P; не равен native text |
| Ideco выбранной версии CSV | P: только фактически экспортированные поля | U: полнота каталога объектов | U: order/context/placement | P в подтверждённом CSV scope | — | U; нулевые поля не доказаны |
| Ideco API-snapshot | U: endpoint/schema/полнота | U | U | P после паспорта | U | U |
| PT NGFW выбранной версии | U: export/API schema | U | U: manager/deployed/node scope | P после паспорта | U | U |
| Huawei VRP IPv4 ACL | P: отдельная grammar | P | P: применение + order по release | P | P после ACL | P: time; прочее отдельными срезами |
| Junos stateless filter | P: set сначала, hierarchy позже | P: prefix-list/groups | P: interface/filter-list/term behavior | P | P | next term/modifiers P; SRX NAT — |
| SRX security policy | P: отдельный family | P: address-books/applications | P: zone-pair/global/context | P | P | U/P: schedule/identity/NAT/statefulness |
| ArubaOS controller session ACL | P: session ACL/netdestination/netservice | P | P: user-role/global/local overrides | P | P | U/P: user/app/time/NAT/session state |
| Cisco ASA текущий | E сохраняется | E сохраняется | E сохраняется | E сохраняется | E в текущей границе | Существующие unknown сохраняются; новое развитие отложено |

Для capability необходимо хранить не булево «платформа поддержана», а статус, scope, reason, источник доказательства и версию контракта. Полнота object catalog, bindings inventory и routes inventory измеряется отдельно. `absent`, `not_exported`, `redacted`, `unsupported`, `ambiguous` и «доказанно пусто» должны оставаться различимыми.

## 4. HP/Aruba AOS-Switch и AOS-CX

Официальный AOS-S 16.11 справочник показывает `show running-config` с Configuration Editor и release в заголовке. Для CX официальный справочник `show access-list` 10.13 различает именованную ACL, interface/VLAN, направления in/out/routed-in/routed-out и вывод configuration/commands. Это подтверждает возможность получать полезные текстовые срезы; таблица show-команды и полный running-config — разные форматы и нуждаются в разных паспортах. [AOS-S running-config](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/kb/sho-run-con129.htm), [CX ACL](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/acls_6300-6400-8100-8360/Content/Chp_ACLs/ACLs_cmds/sho-acc-lis.htm).

Потенциал первой очереди — превратить уже разобранные ACL в полноценный инвентарь области применения. Один и тот же набор ACE может быть применён к нескольким VLAN и интерфейсам, но эти области не становятся одной политикой. Для switchport input и routed input сохраняется точный mode; нынешнее представление direction=in может быть удобным UI-сводным полем, но недостаточно как единственная семантика для будущего evaluator.

Parser расширяется отдельными grammar production для sequence, remark/comment, permit/deny, protocol number, source/destination address и портовых операторов. Quoted ACL names и comments разбираются лексером, не split по пробелам. Дополнительные ACE conditions, fragments, flags, DSCP, IPv6, noncontiguous wildcard и непредставимые значения получают свои коды. Положительный parser не должен молча игнорировать хвост строки. Resolver добавляет только документированные для выбранного продукта виды ссылок; нельзя перенести Cisco object-group в AOS-S по сходству имени.

Bindings расширяет журнал «ACL→target kind→target ID→mode→VRF→source». Management `ip authorized-managers`, CX control-plane и transit остаются разными областями. При конфликте sequence сохраняются обе строки и ambiguous order; имя объекта не является основанием для угадывания применения. Checks используют отдельно пригодные ACL, а unsupported одной области не должен отключать независимую полностью разобранную область. Map показывает не только source/rule/destination, но и место применения с текстовой легендой.

Network начинается с configured interfaces, VLAN membership, SVI addresses и VRF. Следующий срез — operational RIB с timestamp; наличие static route в конфигурации ещё не означает её установку. NAT не вводится как обязательная зависимость switch ACL map. Counters подключаются только вместе с точным operational форматом и reset semantics. Приёмка: сопоставимые S/CX примеры дают разные платформы; одинаковые ACE на двух VLAN дают две области; control-plane не разрешает transit; source port или DSCP без модели делают matcher partial, а не all-traffic.

## 5. HP/H3C Comware

Текст `display current-configuration` и работа с сохранённой конфигурацией описаны H3C. В официальных ACL-руководствах порядок config основан на rule ID, auto использует depth-first и tie breakers; таблица зависит от типа ACL и платформы. Поэтому нельзя просто сортировать все auto ACL по ID или длине source prefix. [H3C configuration management](https://wwwsg.h3c.com/en/d_201301/772595_294551_0.htm), [H3C ACL order](https://www.h3c.com/en/d_202106/1416727_294551_0.htm).

Существующий 0.1.0 разбор полезен для инвентаря IPv4 basic/advanced rule, но warning явно исключает вычисление packet-filter и auto. Следующий результат должен закрыть применение, сохранив прежние unknown для неподтверждённых вариантов. Для этого паспорт фиксирует Comware 5/7, release, модель и тип ACL. Правило обнаружения version 5.20/7.1 пригодно как текущая эвристика, но новое покрытие release требует корпусной проверки, а не ослабления на любой `acl`.

Parser добавляет section-aware interface grammar и документированный packet-filter на выбранной версии. Не смешивает ACL как matcher QoS, security-policy и packet filtering: permit в ACL, используемой классификатором, нельзя автоматически интерпретировать как доступ по МЭ. Для basic ACL destination и service зависят от контракта назначения, а не от произвольного заполнения any. Непрерывные wildcard нормализуются как сегодня; произвольные bitmask требуют отдельного symbolic matcher либо unknown.

Resolver хранит time-range и группы как исходные сущности с типом, ссылки проверяются после чтения всего файла. Bindings включает default action только при подтверждённом profile и полном входе. SNMP management usage может сосуществовать с transit usage одной ACL: вывод должен сохранять оба назначения. Документированный H3C command reference также показывает различие rule counting и packet-filter hardware-count; эти источники нельзя считать взаимозаменяемыми. [H3C packet-filter/counters](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_CR-24948/10/202601/2739182_294551_0.htm).

Checks/map становятся доступны по областям с доказанным order. Для auto желательно два этапа: сначала импорт явно отображённого effective order из versioned display ACL, затем независимая реализация алгоритма сортировки и differential comparison. Если effective order неизвестен, проверки ширины адреса сохраняются, а shadowing/order conflict ограничиваются. Network: interfaces/VRF/configured routes→operational RIB→forwarding decisions; QoS, PBR и SecPath NAT требуют самостоятельных срезов.

Приёмка: shuffled текст с rule IDs не меняет config order; auto не получает config order; shared ACL transit+SNMP сохраняет два контекста; unmatched traffic оценивается только при известном default; удаление packet-filter из truncated входа даёт неизвестное применение, а не «ACL не используется».

## 6. UserGate NGFW

Для 7.5.0+ официально подтверждён native text export через SCP порт 2200, удалённый объект `sys_config`, metadata с product/version/created и шифрование чувствительных данных с USER_KEY. Это структурированный текст; статья не утверждает, что он JSON. Полный синтаксис всех политик и библиотек этой статьёй не подтверждён. [Официальный текстовый экспорт](https://docs.usergate.com/funkciya-eksporta-i-importa-konfiguracii_2315.html).

Первый полезный адаптер выбирает именно native text для фактической версии 7.5+. Перед написанием parser требуются образцы firewall rules, адресных списков, services/groups, zones, enabled, logging, schedules и одинаковых имён в разных namespaces. Образцы получают вручную или через отдельный согласованный collector; локальный импорт не должен требовать пароль устройства. Метаданные secret не выводятся в UI или golden fixtures. Timestamp без доказанного timezone не становится точным UTC capture.

Альтернатива — официальный converter export/import package. Документация описывает json-файлы разделов, различия NGFW и MC/templates, version-specific ограничения, изменения экспорта/порядка и исключённые секреты. Такой пакет — самостоятельный контракт, в котором дополнительно закрепляется версия converter. Он не равен legacy JSON проекта и не становится общей схемой всех NGFW. [Конвертеры UserGate](https://docs.usergate.com/722/). Открытая страница `github.com/usergate/export-import` при проверке показала empty repository; её нельзя использовать как подтверждённый доступный код экспортёра или schema. [Проверенный репозиторий](https://github.com/usergate/export-import).

Потенциал — богатый граф зависимостей policy→library objects→zones→interfaces и объяснение неполноты профилей приложения/идентификации. Parser сначала должен сохранять rule AST и все условия, даже не участвующие в проверках. Resolver поддерживает namespaces device/template/library, nested groups, отрицания и ссылки на встроенные объекты по каталогу версии. Внешняя обновляемая IP-list и FQDN сохраняются символически, пока нет отдельного timestamped contents snapshot.

Bindings отделяет локальную настройку от manager template и от подтверждённо применённой конфигурации узла. Порядок экспорта проверяется на двух overlapping allow/deny rules с известным ожидаемым результатом. Checks A и map включаются лишь для чистого L3/L4-среза либо при полном matcher для дополнительных условий. Schedule/identity/app-rule нельзя выдавать как постоянный allow. Network сначала получает interfaces/routes/VRF, затем отдельную проверенную NAT grammar и evaluation order, reverse flow и session semantics.

Приёмка: product не NGFW отвергается или выбирает отдельный adapter; неизвестный minor release остаётся экспериментальным; converter/native inputs не перехватывают друг друга; unresolved library member не заменяется any; manager rule, не привязанное к node, отображается как шаблон; обновление списка адресов меняет snapshot dependency и результаты сравнения.

## 7. Ideco NGFW

Официальный changelog ФСТЭК фиксирует CSV-выгрузку правил firewall/content filter для Ideco UTM 19.17.73 от 06.04.2026. Это конкретная ветка и версия; нельзя переносить утверждение на любой Novum/v22 без подтверждения. Официальный changelog Novum также содержит исправления NAT counters для локальных и Center правил — важный повод закреплять context и release в operational contract. [ФСТЭК changelog](https://ideco.ru/changelog-fstek), [Novum changelog](https://ideco.ru/changelog).

Документированные backup operations позволяют сохранять/восстанавливать данные, но это не описание открытой parser schema резервной копии. v22 documentation route открылся без извлекаемого текста; найденный официальный Center PDF подтверждает упоминание REST API сервиса, а не точные endpoints получения firewall inventory. **Unknown:** CSV columns выбранной версии, separator/encoding, object IDs, полнота groups/zones/order, API auth/schema/pagination/revision, backup contents. [Ideco backup](https://docs.ideco.ru/pdf/v21/ru-ngfw-settings-server-management-backup.pdf), [v22 documentation](https://docs.ideco.ru/v22/ru/), [Center PDF](https://docs.ideco.ru/cc-v21.pdf).

Первый срез рационально сделать read-only CSV inventory после получения образца именно нужной ветки. Parser сохраняет сырой header, column mapping и каждое значение; пустая ячейка трактуется согласно паспорту, никогда универсально как any/false. Локализованный caption не является enum action без versioned mapping. Если поле содержит имя группы без состава, resolver оставляет unresolved. Даже если CSV удобен для review и поиска, отсутствие библиотеки объектов не позволяет NEW-13 об использовании объектов или расчёт сетевого пути.

Потенциал полного адаптера — объединить rule inventory, object catalog, контекст обработки и deployed policy. API-snapshot — отдельная исследовательская задача после чтения vendor contract на выбранной версии. Collector должен сохранить raw responses всех страниц, terminal pagination marker и snapshot/revision сведения, если они предоставляются. Если атомарности нет, два чтения контрольной версии либо обнаружение изменений формируют inconsistent snapshot; последовательность отдельных успешных ответов не доказывает согласованность.

Bindings разделяет Center/local, device/context и доказанный порядок. Checks сначала включают подтверждённые ширину сетей/портов, metadata и enabled; логирование требует фактическое поле, не оценку по пустой CSV колонке. Map строит configured conditions даже при частичном каталоге, помечая unresolved узлы. Network не начинается с догадки о внутренних файлах backup: интерфейсы, маршруты и NAT получаются из подтверждённых источников каждого среза.

Приёмка: comma в quoted description и multiline cell не ломают строки; CSV с одними names показывает неизвестный состав; одинаковые rule IDs Center/local различаются; counter из исправленной и затронутой версии не объединяются; unsupported CSV branch даёт понятную диагностику. Изготовление adapter без подтверждённого образца не считается выполнением V02.

## 8. PT NGFW

Официальная обзорная страница в поисковой выдаче подтверждает централизованное управление и наличие REST API. При прямом открытии help portal получен 502; детали schema и export не проверены. Официальное обучение отдельно упоминает NAT, backup и API automation. Экспорт CSV журналов найден в документации 1.8, но журнал событий не является экспортом конфигурационных правил. [Обзор PT NGFW](https://help.ptsecurity.com/ru-RU/projects/ngfw/latest/help/10589080075), [Официальная программа обучения](https://edu.ptsecurity.com/kursy-po-ekspluatacii-productov-pt/pt-ngfw), [CSV журналов](https://help.ptsecurity.com/ru-RU/projects/ngfw/1.8/help/9392074507).

**Unknown:** пригодный policy export, extension/archive layout, API endpoints/auth/schema, ordering, UUID stability, templates/group placement, published/deployed revision и доступ к node network facts. Версия latest — переменная ссылка, её нужно заменить закреплённой release documentation перед реализацией. PT AF, MaxPatrol и другие продукты производителя не могут служить источником контрактов PT NGFW.

V03 начинается с обязательного паспорта и пакета обезличенных данных от лабораторного узла и менеджера. Структура пакета пока не предписывается вендору: принимается реальный подтверждённый формат. Минимальные поля, которые должен обеспечить адаптер: rule identity, name, order, enabled, action, address/service refs, zone/context, source provenance. Наличие поля проверяется на образце, не предполагается из названия REST.

Parser добавляется после этого; resolver выделяет независимые namespaces и встроенные объекты, bindings связывает desired policy с фактом placement и installed revision. Если получены только manager rules, UI должен говорить о политике управления, а не утверждать её работу на appliance. Checks и map следуют тому же capability gate, что для UserGate/Ideco. Network требует собственного policy/NAT pipeline и operational route profile; универсальная последовательность ASA не переносится.

Потенциал — сравнение «настроено в менеджере» и «применено на выбранном узле», поиск устаревших deployment и согласованный multisnapshot. Это самостоятельные будущие функции, требующие подтверждённых revisions, а не обязательное обещание текущего первого импорта. Приёмка исследовательской задачи — доступный source contract и документированная таблица unknown; приёмка parser — порядок и references без потери условий; приёмка integration — две политики на разных узлах не объединяются по имени. Недоступность help portal не исключает обязательное направление PT из roadmap.

## 9. Huawei VRP

Официальная Huawei grammar advanced IPv4 ACL включает config/auto order, source/destination wildcard, port operators eq/neq/gt/lt/range, flags, time-range и vpn-instance. Официальные материалы показывают `display current-configuration` в VRP. Эти факты подтверждают текстовую основу адаптера, но не идентичность Comware или единый синтаксис всех Huawei моделей. [Huawei ACL grammar](https://info.support.huawei.com/hedex/api/pages/EDOC1100277650/AZM1016J/05/resources/vrp/dc_vrp_acl4_cfg_0057.html), [Huawei configuration example](https://info.support.huawei.com/network/ptmngsys/Web/tsrev_wlan/cn/content/wlan/10_edesk_web_login_failure/edesk_web_login_failure_edesk002.html).

Первый срез — выбранная модель/release VRP и IPv4 ACL, отдельно от USG/другой ОС. Parser не выбирает Huawei по единственному `acl number`; нужен product/version контекст и отказ при противоречащих признаках. Лексер сохраняет # section boundary, view и line source. Named ports получают versioned таблицу; неизвестный alias не угадывается. Resolver добавляет time-range/address-pool только после подтверждения фактических конструкций. Bindings выясняет точный механизм применения ACL на этой модели; traffic classification не приравнивается packet filtering.

Checks/map сначала показывают rules и области с известной семантикой; при auto order известны ограничения до отдельной проверки. Network добавляет interfaces/vpn-instance/configured routes и operational RIB. Приёмка: Huawei input никогда не выбирает Comware; command не относящаяся к ACL не меняет её scope; neq-порт сохраняет два диапазона либо unsupported; vpn-instance не теряется; unsupported tail блокирует точное policy decision.

## 10. Juniper Junos и SRX

Официально доступны hierarchy и `show configuration | display set`; при недостаточных правах вывод может содержать ACCESS-DENIED. Stateless firewall filter допускает next term и не имеет универсальной простой first_match семантики; unmatched filter traffic implicitly discarded. SRX security policies управляют transit по zone pair и документируют отдельные operational detail/hit-count команды. [Junos configuration viewing](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/junos-configuration-viewing.html), [Filter evaluation](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-stateless-evaluate-packets.html), [SRX policies](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-policies.html).

Первый parser предпочтительно set format с полноценным lexer для quote/list и сборкой нескольких statements одного term. Затем hierarchy parser строит тот же AST; differential тест двух форматов выявляет расхождения. Term order берётся из подтверждённой последовательности экспорта, не алфавита имён. Inactive/deactivate, apply-groups, inheritance, исключения prefix-list и conditions сохраняются явно. Пока inheritance не разрешено, effective filter остаётся partial даже при успешно прочитанных set statements.

Set-first — предварительный инженерный выбор для упрощения первого лексического разбора, а не требование производителя. Окончательный стартовый формат определяется подтверждённым образцом нужной версии. Если доступен только пригодный hierarchy export, первым реализуется он; оба формата приводятся к общей AST с сохранением порядка и inheritance. Перестановка этапов не исключает поддержку второго формата из roadmap.

Resolver хранит prefix-lists, address-books, applications и namespaces logical-system/tenant. Bindings для stateless — interface unit/family/input/output/filter-list, для SRX — from-zone/to-zone/global/context. next term является control flow; count/log modifier не обязательно означает terminal permit. Все эти случаи требуют расширения policy semantics, а не насильного first_match в текущем `Rule`.

Потенциал — общий анализ конфигурации коммутатора/маршрутизатора и SRX с явным различием stateless и stateful. Checks/map first slice ограничены terms без неподдержанных conditions/control flow; затем добавляется term evaluator. SRX отдельным этапом получает zone policies, applications, schedule, NAT и обратную stateful модель. Network не переносит поведение filter на SRX zone-policy pipeline. Приёмка: ACCESS-DENIED уменьшает полноту; два statements одного term не создают два правила; next term не затеняет последующие как permit; hierarchy/set дают одинаковую IR; одинаковые object names двух address-books не смешиваются.

## 11. ArubaOS controllers

Официальная session ACL grammar включает first matching rule, implicit deny, alias/netdestination, netservice, user/userrole, application и дополнительные actions. Документация приводит связь user-role→session-acl; официальный developer portal описывает получение ACL Session через AOS8 JSON API с config_path. Это отдельная продуктовая семья от AOS-S/CX. [Session ACL grammar](https://arubanetworking.hpe.com/techdocs/ArubaOS/oxygen/AOS-8%20Command%20Line%20Interface%20Guide/GUID-32C0DCDE-CAA1-4E2D-A96F-F5667B69CD3B.html), [Role binding](https://arubanetworking.hpe.com/techdocs/Archived/AOS-8/ArubaOS_8.9.0_Web_Help/Content/arubaos-solutions/rap/conf-sess-acl-bri.htm), [AOS8 ACL API](https://developer.arubanetworks.com/aos8/reference/get_object-acl-sess).

Первый slice — текстовые session ACL конкретной версии, netdestination/netservice и role binding. Два существующих controller exports, отмеченных unsupported в specs, требуют законно доступных обезличенных fixtures; их нельзя восстановить по именам файлов. Parser сначала остаётся отдельным candidate adapter, чтобы прежний явный отказ не исчез раньше полезной поддержки. Resolver различает static alias, user address и dynamic role: user не превращается в any.

Bindings учитывает global/role ACL, managed node/config hierarchy, local overrides и порядок session-acl. API collector в следующем этапе фиксирует config_path; raw объект одного узла не доказывает effective inherited policy другого. При app condition без DPI/session state checks остаются конфигурационными; pre/post classification не заменяется destination port matcher. Map обозначает пользовательские роли символическими nodes. Network требует AP forwarding mode, controller/node context и NAT actions; guest ACL сама не доказывает Internet path.

Приёмка: AOS8 session input не выбирает switch parser; role отсутствует — known ACL inventory, unknown effective assignment; alias unresolved — unknown endpoint; app-rule не считается чистым L4 permit; global и role rules не сортируются между собой произвольно; сохранённые source anchors включают inherited origin при наличии данных.

## 12. Новые данные и безопасная обработка форматов

Предлагаемая IR расширяет текущие контракты версионированно. Нужны **SourceBundle** с manifest, SHA-256 каждого member, exporter/version, collection scope и capture interval; **PolicyContext** с device/node/tenant/template/VRF/policy kind; **ObjectDefinition/Reference** с namespace, type, unresolved reason и original membership; **MatchExpression** для AND/OR/NOT и typed dimensions; **RuleOrder** с effective rank, original sequence, order provenance; **PolicyBinding** с точным target/mode; **EvaluationProfile** с terminating/control-flow/default/stateful/NAT pipeline; **Observation** counters/RIB с временем и reset origin.

Эти названия — проект внутренних контрактов, не поля vendor schema. Их вводят ADR и migration/export schema version. На первом этапе L3/L4 rules могут иметь обратимо совместимую проекцию в текущий Rule. Если projection теряет condition, match_status остаётся partial/unknown, а evaluator новой IR получает полное дерево. Структурированные conditions важнее безразмерного массива строк warnings: по ним capability gate может объяснить, какая именно проверка блокируется.

Text reader сохраняет исходные bytes и line mapping после нормализации CRLF/BOM. UTF-8/UTF-8 BOM поддерживаются согласно паспорту; cp1251/UTF-16 добавляются только как явные профили, не безошибочная эвристика. Строки пагинации, ANSI escapes, wrapped output и command prompts распознаются с диагностикой. CLI command output и конфигурационный файл различаются. Неполный section нельзя делать полностью известным только потому, что file EOF корректен.

CSV parser использует реальные delimiter/quote/encoding/header профили, сохраняет номера record и физических строк. Duplicate column, malformed quotes, unexpected field count и missing required column блокируют соответствующий срез. Formula-like cell — строка данных; в будущих spreadsheet exports её экранируют. Archive reader не извлекает произвольные пути: проверяет относительные member names, запрет traversal/absolute/symlink, лимиты entries/uncompressed bytes/compression ratio и duplicate members. Nested archive не распаковывается без отдельного profile. Резервная копия неизвестного формата получает unknown format, а не попытку выполнить содержимое.

Provenance связывает сущность с hash bundle/member и line/object path/vendor ID. В UI доступны обезличенные snippets; secret fields не копируются в отчёт. Пересборка IR сохраняет исходный hash и parser version. Стабильная identity across snapshots отделена от UUID конкретной ревизии: vendor ID предпочтителен, но проверяется на повторное использование. Совпадение имени — кандидат сопоставления, неоднозначность остаётся видимой.

## 13. Как стремиться к ≥99.9% без фиктивного обещания

Требование следует измерять минимум тремя величинами: корректность нормализованных сущностей в заявленном slice; корректность определённых policy decisions относительно независимого oracle; доля входа/запросов, для которых вынесен определённый результат. Отдельно публикуются false allow и false deny. Возвращение unknown на все запросы не является успехом, даже если ошибочных allow нет. Coverage recognition ratio не подменяет ни одну из этих метрик.

Для каждого release фиксируется test population и допустимая экстраполяция. «Все модели всех версий» невалидный scope без такого корпуса. При независимых Bernoulli испытаниях и нуле ошибок односторонняя 95% верхняя граница вероятности ошибки равна `1 - 0.05^(1/n)`; n≥2995 даёт границу ниже 0.001. Это ориентир проверки статистического заявления, не доказательство для зависимых generated rules. Тысячи вариаций одного fixture не становятся независимыми конфигурациями. Нужны strata по платформе/release/grammar/context и отдельные результаты критичных семейств. На редких сложных конструкциях corpus мал — статус experimental и явные ограничения сохраняются.

Golden corpus получает вручную проверенные expected AST/IR/provenance/capabilities и основание vendor semantics. Ожидания не генерируются тем же parser, который проверяется. Contract tests проверяют неизменяемость, source anchors, no silent loss, unresolved propagation и deterministic output. Hypothesis создаёт valid/invalid ports, ranges, masks, groups, cycles и chunked input; metamorphic tests меняют whitespace/comments, порядок definitions и имена в пределах namespace. Changes term order не должны проходить как harmless transformation.

Differential testing сравнивает native/другой подтверждённый экспорт одной лабораторной конфигурации, independent matcher и, где доступно без изменения политики, vendor effective ACL/policy output. Два parser, скопированные из одной grammar implementation, слабые oracle. Operational command может иметь собственный scope и state, поэтому совпадение timestamp/version/context обязательно. Failure injection обрывает archive, CSV, API page и network facts; expected outcome — явная неполнота, а не исчезновение правил.

Release gate: нет известных ошибок в supported critical semantics; все unsupported constructs классифицированы; доли decisions/unknown и corpus distribution опубликованы; source_mapping проверен; версии exporter закреплены; false-allow counterexample блокирует выпуск slice до исправления. Ruff/mypy/pytest/Hypothesis проекта используются при будущей реализации. Документ не сообщает достигнутые 99.9%: на текущем исследовательском этапе нет измерений и независимого vendor oracle.

## 14. Задачи, зависимости и приёмка

| Задача | Работа и зависимость | Проверяемый результат |
|---|---|---|
| P01-A | Паспорта, capability matrix и source bundle; до новых adapters | Каждый input имеет scope/version/source, неизвестные поля явно перечислены |
| P01-B | MatchExpression/ObjectReference/Binding ADR; зависит P01-A | Unsupported condition не теряется в Rule projection; сохранение/экспорт версионированы |
| P02-A | Comware config order + packet-filter по selected release | Separate transit/SNMP, exact binding mode, golden anchors |
| P02-B | Comware auto order, effective output и comparator | Tie breakers проверены independently; неподтверждённый release остаётся unknown |
| P03-A | AOS-S/CX source ports/additional conditions и exact modes | Ширина/сравнение правил не используют усечённый matcher |
| P03-B | Switch interfaces/VLAN/VRF, затем route input | Configured/operational facts и freshness различаются |
| V01-A/B | UserGate native text passport→parser/resolver; converter отдельно | Versioned fixtures, namespaces, no legacy JSON promotion |
| V02-A/B | Ideco CSV contract→inventory; API passport→snapshot отдельно | Branch/version/header закреплены; missing objects/context видны |
| V03-A/B | PT official contract+sample→adapter, manager/node association | Unknown schema не заменена выдуманной; installed scope проверяется отдельно |
| V04 | Huawei selected VRP ACL+binding profile | Detection collision corpus с Comware; unsupported tail сохранён |
| V05-A/B | Junos set filter→hierarchy differential; SRX policy отдельно | Term control flow, inheritance, zones и address-books не смешаны |
| V06-A/B | ArubaOS session/role→effective hierarchy/API | Switch/controller separation, dynamic user/app boundaries |
| V-GATE | На каждый slice parser→resolver→bindings→checks→map | Выпускается фактическая ступень с опубликованной приёмкой |
| V-NET | Network facts/NAT/reverse flow для одного готового slice | Path result только при полных prerequisites; остальные платформы не блокируют выпуск |

UserGate, Ideco и PT готовят паспорта параллельно; отсрочка образца одного вендора не задерживает читаемый HP/Aruba/Comware map. Однако экспериментальный importer без объектов или deployed context не выдаётся за завершённую полную поддержку. Оценка первого roadmap 10–20 дней на adapter остаётся предварительной после фиксации формата; трудоёмкость всех дополнительных срезов оценивается отдельно по grammar inventory и доступности oracle.

FortiGate, Check Point, Palo Alto остаются возможными кандидатами при реальном парке, без обязательных задач этого исследования. Universal converter может ускорить получение материала, но меняет provenance и способен потерять vendor conditions; поэтому не заменяет native contract. API ускоряет регулярный capture, но добавляет auth/pagination/version/consistency; текст/CSV проще воспроизвести, но часто беднее по scope. Выбор делается по фактическому качеству входа, а не удобству заранее заданного JSON.

## 15. Реестр первичных источников и незакрытые вопросы

Все ссылки проверялись 14.10.2026. «Поиск» означает индексированный первичный источник, не успешное полное чтение страницы. Таблица фиксирует пределы доказательств.

| Источник | Доступ/что подтверждено | Чего не подтверждает |
|---|---|---|
| [UG text export](https://docs.usergate.com/funkciya-eksporta-i-importa-konfiguracii_2315.html) | Открыт; 7.5+, SCP/sys_config, metadata, secret encryption | Полную grammar всех разделов |
| [UG converters](https://docs.usergate.com/722/) | Поиск; json package и version-specific изменения/ограничения | Стабильную схему неизвестной версии converter |
| [UG GitHub](https://github.com/usergate/export-import) | Открыт; empty repository в данном ответе | Наличие доступного exporter implementation |
| [Ideco ФСТЭК changes](https://ideco.ru/changelog-fstek) | Поиск; CSV rules в 19.17.73 | Все Novum версии и полноту object catalog |
| [Ideco changes](https://ideco.ru/changelog) | Поиск; версии и counter/API changes | Rule retrieval endpoint/schema |
| [Ideco v21 backup](https://docs.ideco.ru/pdf/v21/ru-ngfw-settings-server-management-backup.pdf) | Поиск; file backup/restore | Читаемый parser format backup |
| [Ideco v22 docs](https://docs.ideco.ru/v22/ru/) | Открыт, извлекаемый текст отсутствует | Конкретный REST/CSV contract |
| [Ideco Center PDF](https://docs.ideco.ru/cc-v21.pdf) | Поиск; REST API service упомянут | Полный API inventory/pagination |
| [PT overview](https://help.ptsecurity.com/ru-RU/projects/ngfw/latest/help/10589080075) | Поиск подтверждает REST/manager; прямое открытие 502 | Рабочий schema/export contract |
| [PT 1.8 release](https://help.ptsecurity.com/en-US/projects/ngfw/1.8/help/9732345995) | Поиск; прямое открытие 502 | Совместимость parser с текущей latest |
| [PT logs](https://help.ptsecurity.com/ru-RU/projects/ngfw/1.8/help/9392074507) | Поиск; CSV logs | Export policy configuration |
| [PT training](https://edu.ptsecurity.com/kursy-po-ekspluatacii-productov-pt/pt-ngfw) | Поиск; API/NAT/backup направления | Syntax/fields API |
| [AOS-S 16.11 config](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/kb/sho-run-con129.htm) | Поиск; running-config example | Полный парк моделей и releases |
| [CX 10.13 ACL](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/acls_6300-6400-8100-8360/Content/Chp_ACLs/ACLs_cmds/sho-acc-lis.htm) | Поиск; command modes/targets | Hardware forwarding всех моделей |
| [H3C configuration](https://wwwsg.h3c.com/en/d_201301/772595_294551_0.htm) | Поиск; current/saved configuration handling | ACL semantics всех Comware |
| [H3C ACL](https://www.h3c.com/en/d_202106/1416727_294551_0.htm) | Поиск; config/auto ordering | Перенос tie breakers на любой release |
| [H3C packet-filter](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_CR-24948/10/202601/2739182_294551_0.htm) | Поиск; bindings/count distinctions | Полноту текущего adapter |
| [Huawei ACL](https://info.support.huawei.com/hedex/api/pages/EDOC1100277650/AZM1016J/05/resources/vrp/dc_vrp_acl4_cfg_0057.html) | Поиск; advanced rule grammar | Идентичность Comware/default enforcement |
| [Huawei current config](https://info.support.huawei.com/network/ptmngsys/Web/tsrev_wlan/cn/content/wlan/10_edesk_web_login_failure/edesk_web_login_failure_edesk002.html) | Поиск; VRP display current-configuration | Универсальный export bundle |
| [Junos viewing](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/junos-configuration-viewing.html) | Поиск; hierarchy/set, ACCESS-DENIED | Effective inherited config конкретного узла |
| [Junos filter](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-stateless-evaluate-packets.html) | Поиск; next term/default discard | SRX security-policy pipeline |
| [SRX policy command](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-policies.html) | Поиск; zone-context/detail/hit-count | NAT ordering/reverse session oracle |
| [ArubaOS ACL](https://arubanetworking.hpe.com/techdocs/ArubaOS/oxygen/AOS-8%20Command%20Line%20Interface%20Guide/GUID-32C0DCDE-CAA1-4E2D-A96F-F5667B69CD3B.html) | Поиск; session grammar, roles, dynamic/app terms | Полноту effective hierarchy выбранного node |
| [ArubaOS roles](https://arubanetworking.hpe.com/techdocs/Archived/AOS-8/ArubaOS_8.9.0_Web_Help/Content/arubaos-solutions/rap/conf-sess-acl-bri.htm) | Поиск; user-role/session-acl binding | Автоматическую роль конкретного пользователя |
| [ArubaOS API](https://developer.arubanetworks.com/aos8/reference/get_object-acl-sess) | Открыт/поиск; ACL Session и config_path | Поддержку всех AOS releases и snapshot atomicity |

Обязательные дальнейшие входы: фактический список моделей/releases парка; native UG text и/или закреплённый converter package; Ideco CSV и object export нужной ветки; PT versioned API/export reference и sample; effective order/placement для Comware auto и controller hierarchy; operational RIB/counters с reset/capture сведениям. Их отсутствие — конкретная незакрытая задача соответствующего slice, а не основание выдумывать формат или исключать производителя.
