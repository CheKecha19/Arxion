# Контекст пересылки одного Cisco ASA

Дополнение 08.11.2026: SwitchFacts/SwitchPolicies не расширяют область ASA
forwarding context. L2-связность и control-plane ограничения коммутаторов не
доказывают транзитную IP-достижимость. Требования — SWITCH_CONFIG_IMPORT.md.

Дата: 2026-10-11.
Статус: подготовка, ForwardingContext 0.1.0, конфигурационный ASA forwarding adapter, application binding и условный evaluator политик 0.1.0 реализованы. Оркестрация с маршрутом, effective NAT вход и итоговая достижимость ещё не реализованы.

## Назначение

Расширить локальные решения ADR-013 до объяснения применимых этапов одного устройства. Отдельная ACL не является полной политикой, а кандидат RIB не доказывает реальный egress. Документ определяет входную границу и реализованный условный срез по ADR-019. Прежние контракты сохранены; итоговые reachable/blocked запрещены.

Визуальный интерфейс, его зависимости и демонстрационные данные не изменяются. Ядро принимает данные в памяти и не выполняет сетевые обращения.

## Первый профиль

- Cisco ASA 9.16, single context, routed mode, физические L3-интерфейсы, IPv4 и единственная data/default таблица.
- Конкретный unicast transit-пакет нового соединения между двумя разными интерфейсами; не адрес самого ASA, не существующая сессия и не VPN. Допущения задаются явно, сохраняются и не выводятся из отсутствия команд. Hairpin/intra-interface, fragments, related ICMP errors, VTI и failover/cluster пока исключены; формат future flow должен различать необходимые TCP/ICMP характеристики, отсутствующие в старом query.
- Полностью нормализованные условия существующей модели: адреса/диапазоны и TCP/UDP destination ports либо ICMP без ограничений type/code. Source ports, identity/FQDN/SGT, time-range, application-aware и дополнительные условия требуют диагностики.
- Одна согласованная ревизия и доказательства времени по ADR-009. Порядок ACL и binding известны. Несколько равных egress-кандидатов не разрешаются выбором первого.
- Первая положительно разбираемая область контекста предполагает доказанно отсутствующие NAT и PBR; присутствующие NAT/PBR сохраняются как unsupported. Это не реализация их семантики.

## Необходимые факты

| Набор | Содержание | Если данных недостаточно |
|---|---|---|
| Применимость | Режим, context, семейство, transit/new/non-VPN и исключения | unknown или not_enough_evidence |
| Interface mapping | Физический ID, nameif, security-level, source mapping | Не угадывать label, уровень или направление |
| ACL inventory | Все ACL, порядок ACE, существование пустого списка отдельно от отсутствия | Нет implicit deny из отсутствующих rules |
| Bindings | Interface in/out и global, направление, positions, конфликты | Не сводить global к interface in |
| Межинтерфейсные ограничения | inter-interface/intra-interface permissions и значения уровней | Не угадывать defaults по отсутствию строк |
| NAT inventory | Configured object/manual NAT и effective NAT, включая системную Section 0 | Отсутствие пользовательских NAT не означает отсутствие влияния NAT |
| PBR inventory | policy-route, route-map и зависимые классификаторы | ACL deny классификатора не означает packet deny |
| Исключения | VPN bypass, control-plane, BVI/bridge, existing flow и inspection | Сохранить неподдержанную применимость |

Состояния фактов known/absent/unknown/unsupported сохраняют разные смыслы. Отсутствие ACL binding не является отсутствием всех механизмов фильтрации.

## Доказательство полноты

Новый входной профиль должен хранить UUID, исходные байты и SHA-256, точную команду, declared version и её происхождение, device/context, selection/extent, encoding, capture success, время получения и отдельное observation. Перечень feature scopes и основания полноты должны быть явными.

Претендующий на полноту источник для исследования: полный show running-config all. Это целевая команда, а не уже реализованная роль SourceDocument. Обычный export или selector может не показывать defaults/зависимые разделы; отсутствие строки тогда остаётся unknown. Full extent и хеш сами по себе не доказывают полноту или подлинность оборудования.

Статус absent для NAT/PBR/следующей ACL допустим только при доказанно полной релевантной области, успешном разборе всех влияющих конструкций и отсутствии конфликтов. Для NAT проверяются как верхний уровень, так и object network; для PBR - интерфейсы, route-map и зависимости. Нераспознанная потенциально влияющая строка исключает known absence. Adapter должен различать документированно не влияющие команды и неизвестные; blanket ignore неприемлем.

ASA 9.16(1) добавила системную NAT Section 0 с более высоким приоритетом. Поэтому configured_nat=absent и effective_nat=absent - разные утверждения. Полный running-config сам по себе не исключает системные правила; понадобится отдельная подтверждённая эффективная NAT-область. Show nat документирован, но его точный формат/полноту 9.16(x) нужно проверить до adapter. Пустой show xlate не доказывает отсутствие NAT. Show running-config object не показывает object NAT; нельзя считать этот selector полным NAT inventory. Во всех подготовленных excerpts системный NAT остаётся unknown.

Defaults допускаются в будущем только отдельными документированными правилами профиля с известной версией и доказанной областью входа. В первом срезе контекста неизвестные security-level/same-security не заполняются defaults. Заявление оператора или synthetic fixture остаётся заявлением своего происхождения, не аппаратным наблюдением.

## Цепочка решений

1. Проверить применимость, идентичность/время и обязательные feature inventories.
2. Подтвердить координаты packet ACL. Старый acl_input является условным заявлением вызывающей стороны; он не доказывает NAT-нормализацию.
3. Объяснить ingress interface ACL. Explicit deny завершает локальную ACL-проверку; no_match может продолжаться global ACL.
4. При необходимости применить global ACL; конец inbound chain и implicit deny требуют подтверждённого полного инвентаря. BVI/control-plane не входят в профиль.
5. Объяснить security-level/same-security как отдельные ограничения; interface permit их автоматически не отменяет. Нет применимой ACL не означает permit.
6. Проверить отсутствие либо unsupported наличие NAT/PBR перед привязкой RIB-кандидата к предполагаемому egress.
7. Объяснить применимую outbound ACL; ingress permit не отменяет её deny. Не объявлять маршрут реальным путём.
8. Сохранить все причины, trace и непроверенные этапы. Административное состояние не заменяет operational up, ARP, next-hop resolution, inspection и обратный путь.

Это последовательность объяснения поддержанного профиля, не утверждение полного физического packet-processing pipeline ASA. Runtime-зависимые исключения требуют отдельных входов и решений.

Same-security документирован как предварительное ограничение до ACL; расположение его объяснения в trace не должно менять приоритет решения. Для разных ingress/egress intra-interface неприменим при доказанной применимости профиля, а не отсутствует в конфигурации. Sysopt permit-vpn может быть включён, но для подтверждённого non-VPN потока bypass неприменим; значение настройки не доказывает происхождение потока.

## Официальные основания и команды

Источники сверены 2026-10-10; руководства описывают ветку, а не проверенный аппаратный захват конкретной сборки.

| Источник | Подтверждение и ограничение |
|---|---|
| [ASA 9.16 Access Rules](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/firewall/asa-916-firewall-config/access-rules.html) | Interface/global/implicit и out ACL, same-security; show running-config access-group |
| [ASA 9.16 ACL](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/firewall/asa-916-firewall-config/access-acls.html) | First-match/inactive; show running-config access-list и show access-list, выбор имени ограничивает область |
| [ASA 9.16 NAT](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/firewall/asa-916-firewall-config/nat-basics.html) | Object/manual NAT, Section 0; show running-config nat и show nat. Show xlate не является инвентарём правил |
| [ASA 9.16 PBR](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/route-policy-based.html) | Policy-route в interface; show policy-route и show run route-map. Classifier deny не является packet drop |
| [ASA 9.16 CLI](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/ref-cli.html) | Show running-config all включает defaults; selector ограничен связанными командами, runtime не входит в конфигурацию |
| [ASA 9.16 VPN parameters](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/vpn/asa-916-vpn-config/vpn-params.html) | VPN bypass и его условная применимость |
| [ASA sysopt reference](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/su-sz-commands.html) | Permit-vpn defaults и show run all sysopt; общий обновляемый справочник, точный 9.16(x) требует проверки |

Selectors interface/same-security-traffic соответствуют общей грамматике, но точный вывод должен быть проверен через CLI help выбранной сборки. Show running-config policy-route не считается подтверждённым источником: настройка вложена в interface. Ни одна из команд не выполнялась на устройстве в этой подготовке.

## Подготовленные сценарии

Каталог tests/fixtures/forwarding_asa содержит специально созданные фрагменты. В каждом manifest отмечаются declared version, происхождение, SHA-256, длина, команда и неполнота. Observed_at неизвестно; реальных клиентских данных и аппаратных захватов нет.

Сценарии проверяют постановку задачи: продолжение ingress no_match в global permit; ingress deny перед global; ingress permit с outbound deny; равные уровни с неизвестным разрешением и с явной inter-interface командой; object/manual NAT и PBR; обрезанный инвентарь. Ожидания в README условные и не являются golden results существующего evaluator.

## Реализованный вход adapter

CiscoAsaForwardingParser использует отдельный ForwardingFactsParser/ForwardingParseRequest, не ACL ParserRegistry. Документ передаётся в памяти с ForwardingSource, revision/configuration UUID и imported_at. Необязательный профиль без основания не принимается и не заполняется defaults. Detect без metadata отрицательный; metadata не удостоверяют производителя. Поддержаны точные show running-config/show running-config all и заголовок ASA 9.16, совместимый с заявленной веткой/сборкой. Ошибка SHA-256, имени, времени или observation отклоняется до разбора; неприменимая роль/профиль/кодировка возвращает ParseFailure.

Разбираются физические IPv4 interface/nameif/security-level, явные положительные/отрицательные same-security/sysopt настройки, определения extended ACL и remark, in/out/global bindings. Для условий ACE и object resolution используются существующие ASA ACL helpers, без изменения прежнего adapter 0.2.0. Неоднозначность не разрешается последней записью; отсутствующее определение binding сохраняется как UNKNOWN placeholder, не известный пустой ACL. Дополнительные условия binding и специальные интерфейсы получают диагностику.

NAT, policy-route/route-map и исключения сохраняются как unsupported с позициями. Unknown команды запрещают повышение полноты. Известная полнота отдельных inventories требует явных scopes, полного успешного show running-config all и observation; параметры интерфейсов/настроек также должны быть понятны и явно заданы. Все подготовленные excerpts остаются неполными, effective NAT всегда unknown для данного входа. Coverage отражает разбор конструкций, не полноту оборудования.

ForwardingParseResult 0.1.0 содержит отдельный контекст, parser version, warnings/errors, unsupported_constructs и source_map каждого факта/ACE/inventory. Результат является глубоким snapshot. Переданные UUID сами по себе не подтверждают совместимость с существующей DeviceRevision: для этого реализован отдельный application binding, описанный ниже. Условный evaluator реализован отдельно по ADR-019; полный путь остаётся следующей задачей. Роль из исторического fixture manifest не добавляется в старые ACL/network registries. Parser golden results проверяют только нормализацию synthetic excerpts, не packet-processing или аппаратную поддержку.

## Последовательность продолжения

1. Выполнено: нейтральный ForwardingContext 0.1.0, feature inventories с enumeration_complete/семантической complete, sources/scopes, ACL bindings и декларации применимости; повторная валидация и глубокие snapshots.
2. Выполнено: отдельный ASA adapter конфигурационного входа с source mapping и диагностикой покрытия; ACL ParserRegistry не расширен.
3. Выполнено: негативные tests unknown/unsupported/known absence и JSON golden results разбора; application binding к существующей ревизии. Далее эталоны evaluator semantics.
4. Выполнено: чистый условный evaluator цепочки поверх нейтральных фактов, не импортирующий vendor adapter или UI; восемь semantic golden results на собственных полных доменных fixtures.
5. Выполнено: прежние схемы и эталоны сохранены, ForwardingPolicyResult 0.1.0 утверждён ADR-019. Далее application-композиция с подтверждённым маршрутом и сбор доказательств effective NAT/PBR. Итоговые статусы запрещены до завершения всей необходимой цепочки.

## Критерий подготовки

Актуализация 2026-10-11: application binding и условный evaluator реализованы отдельными модулями. Реализация не завершает полный анализ пути.

ADR содержит первичные источники и ограничения, manifest контролирует байты и происхождение, сценарии не заявляют полноту экспорта. Реализация parser/evaluator, коммерческая поддержка и аппаратная валидация не засчитываются как выполненные этой подготовкой.

## Привязка к ревизии

`application/forwarding_binding.py: bind_forwarding_context(imported, parsed)` принимает NetworkImportResult и ForwardingParseResult в памяти. ForwardingBindingResult 0.1.0 содержит глубокие снимки обоих входов, mappings с отдельными forwarding/network interface IDs, UUID источников и позициями, status и reasons. Чтение JSON и model_copy повторно вычисляют проверку: произвольно указать consistent нельзя.

Профиль ограничен ASA 9.16, single/routed/IPv4/data/default и единственным конфигурационным источником. Его UUID, имя, SHA-256, captured_at и observation должны совпадать с Configuration источником ревизии. Связь разных конфигурационных захватов с разными хешами не поддержана. ACE сравниваются без зон и направления, назначаемых ACL adapter по bindings. Выбранные сетевые наборы сверяются с ревизией полностью.

Противоречащие идентификаторы, профили, правила, labels, security-level и сетевые факты отвергаются с ValueError. Неизвестные профиль/наблюдение или отсутствующие доказательства интерфейса дают not_enough_evidence с причинами, без defaults. Mapping сопоставляет физический ID, label, security-level и physical_l3; ForwardingInterface не содержит IP, поэтому равенство адресов между парсерами не заявляется. Consistent подтверждает только связь фактов, не полноту inventories, NAT/PBR или достижимость.

## Условный evaluator политик

`analysis/forwarding_policy.py: evaluate_forwarding_policy(context, *, ingress_interface_id, egress_interface_id)`
принимает физические ID из ForwardingContext и явно заданный условный egress, не
выбирает его из RIB. FlowApplicability обязателен: new/transit/non-VPN/non-fragment,
для TCP SYN=true, ACK=false, payload=0; для ICMP только echo type=8/code=0; UDP без
дополнительных признаков. Проверяются поддержанный профиль, observation и полные
inventories интерфейсов/ACL/bindings; configured/effective NAT, PBR и exceptions
должны быть доказанно absent. Нехватка доказательств не запускает ACL-решения.

При равных уровнях нужен полный known same_security inventory и явное эффективное
значение inter_interface: false завершает локальную проверку до ACL. Без применимой
inbound/global ACL известный высокий уровень допускает переход к низкому; обратное
направление даёт локальный deny. Наличие применимой ACL снимает этот неявный выбор:
используется first-match и доказанный конец цепочки. Ingress allow пропускает global,
no_match продолжает global, deny завершает цепочку. Затем применяется outbound ACL.
Подтверждённая полная пустая ACL допустима и приводит к implicit deny в конце цепочки.

ForwardingPolicyResult 0.1.0 хранит context snapshot, два ID, egress_basis=
caller_supplied_conditional, policy_status, восемь этапов trace и reasons. Верхний
status остаётся unknown/not_enough_evidence, runtime_pending присутствует всегда.
Policy_status - условное решение политики, не результат доставки пакета.
Чтение JSON и model_copy повторяют полный чистый расчёт и отвергают устаревший trace.
Доменный сервис не импортирует analysis, parsers, UI и не выполняет I/O.

Положительные эталоны используют собственные полные доменные fixtures, включая
условное доказательство effective NAT absence. Это не новый parser adapter, не
аппаратное подтверждение и не повышение полноты существующих excerpts. Все восемь
прежних forwarding excerpts остаются unknown/not_enough_evidence в интеграционных
проверках. Профиль версий согласован с forwarding parser: 9.16, 9.16(n) с допустимым
maintenance suffix и точечные формы ветки. Коммерческая поддержка не расширяется.
