# Расширенный каталог проверок: семантика, доказательства и развитие

Дата исследования: 14.10.2026. Статус: проект требований, не реализованные функции и не отчёт о security scan. Документ развивает раздел 5 и задачи P04/C01/C02/C03 первой версии [roadmap](../IMPROVEMENT_ROADMAP_2026-10.md). Все 25 идентификаторов NEW сохранены для трассировки. Предложенные технические имена FW-* новых проверок требуют регистрации; исторические семь идентификаторов уже существуют.

## 1. Что подтверждено исходниками и что необходимо построить

Изучены `analysis/policy_checks.py`, `analysis/firewall_assurance.py`, `analysis/policy_matching.py`, `domain/policy_matching.py`, `domain/assurance.py`, `domain/configuration.py`, `domain/network.py`, `domain/parse_result.py`, `domain/observation.py`. Это статическое исследование контрактов; тесты приложения в рамках документа не запускались.

Сегодня анализатор запускает семь независимых checks. Его контекст содержит ревизию, время, два флага обязательности metadata и `max_pair_rules=1000`. Доменный matcher умеет объединять адресные/портовые интервалы и проверять включение; полностью неизвестное условие возвращает `None`. FQDN и адресные зоны не вычисляются как адресные множества. Scope попарных проверок подтверждается только при известной зоне, policy ID, направлении и `first_match`. Для HP/Aruba ограничения могут блокировать отдельную ACL; для других платформ неполнота разбора блокирует попарный анализ значительно шире. Это сознательная граница текущего поведения, которую нельзя незаметно отменить ради большего числа результатов.

`RuleMatch` сегодня содержит адреса источника, назначения, сервис по протоколу и destination ports. Полей source ports, ICMP type/code, пользователя, приложения, расписания, negate, state, дополнительных NGFW-условий в этой алгебре нет. `Endpoint` хранит разрешённые значения, но не исходный граф вложенности; `ParseResult` не задаёт полный typed reference graph объектов для NAT/VPN/management. У `Rule` есть `owner`, но нет структурированного основания, временного срока или observation counters. Поэтому новые проверки не должны запускаться поверх упрощённой модели, если отброшенное измерение способно изменить вывод.

`CheckResult` разделяет `complete`, `partial`, `not_applicable`; отсутствие findings не означает чистую политику. Внутри finding сейчас выставляется `confidence=1.0`. Это значение не является результатом статистического измерения precision и не доказывает 99,9%. При расширении необходимо документировать его смысл либо заменить на тип доказательства и измеренную калибровку. Версия check, parser, профиля, resolver и входных snapshot должны составлять воспроизводимую идентичность результата.

## 2. Исследовательская основа и границы переноса

NIST рекомендует формулировать политику для входящего и исходящего трафика, разрешать необходимое и проверять настройку до и после изменений. Это основание для профиля организации, тестовых потоков и ревью доступа; оно не задаёт универсальный порог CIDR или число дней неиспользования. См. [NIST SP 800-41 Rev.1, разделы 4 и 5](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-41r1.pdf).

Классическое исследование Al-Shaer/Hamed рассматривает аномалии упорядоченных firewall-политик и различает отношения между правилами. Его подход используется как исследовательское основание NEW-09…11, но конкретные алгоритмы ниже — требования проекта, подлежащие самостоятельной проверке. [Discovery of Policy Anomalies in Distributed Firewalls, INFOCOM 2004, DOI](https://doi.org/10.1109/INFCOM.2004.1354680). Полный текст через открытие DOI и найденного PDF в этой сессии недоступен; нельзя утверждать, что все доказательства авторов проверены. Подтверждены библиографические данные и тема по доступному поисковому материалу самой публикации. До реализации алгоритмов получить полный текст и выполнить инженерную верификацию.

Вендорская практика также подтверждает пользу анализа shadow rules и сохранения их конфигурации перед изменениями. [Palo Alto Networks: Security Policy Rulebase Best Practices](https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rulebase-best-practices). Это пример зрелого процесса, не заявка на поддержку PAN-OS в проекте.

Counters требуют версии семантики: руководство PAN-OS 11.1 описывает reset, first/last hit, modified и отсутствие синхронизации статистики HA peers. Поэтому generic правило «ноль = ненужное» неприемлемо. [View Policy Rule Usage](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/view-policy-rule-usage). NAT тоже требует adapter-specific порядка: Cisco описывает отдельные NAT types и rule order, а пример ASA связывает translation с ACL. [ASA Information About NAT, версия 9.2](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/firewall/asa-firewall-cli/nat-overview.html), [ASA NAT and ACL example](https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/115904-asa-config-dmz-00.html). Это референс для контракта NEW-25; новый функционал Cisco остаётся отложенным по v1.

## 3. Общий контракт всех проверок

### Область, capability и четырёхзначное решение

Каждый паспорт проверяется в `device/context/VRF/policy/binding/direction/family/observation window`. Разные VRF, tenants, virtual systems, management и transit никогда не объединяются из-за совпадения имени или IP. Предлагается registry capability: `address_sets`, `service_sets`, `full_match`, `ordered_terminal_policy`, `binding_scope`, `object_catalog`, `reference_graph`, `schedule`, `rule_metadata`, `logging_config`, `ntp_config`, `management_acl`, `rule_counters`, `routing_snapshot`, `nat_pipeline`. Capability подтверждается для версии формата и конкретного среза, а не флагом «вендор поддержан».

На каждой единице оценки нужны четыре исхода: `violation`, `compliant`, `unknown`, `not_applicable`. Их не следует механически смешивать с существующим статусом выполнения всего check. `complete` означает, что все применимые единицы в заявленном scope оценены; `partial` — есть неизвестные/пропущенные единицы с причинами; `not_applicable` — доказанно отсутствуют применимые единицы либо проверка отключена утверждённым профилем. Отсутствие требуемого профиля — `unknown`, а не положительный результат и не фиктивная неприменимость.

Неизвестность локализовать по affected rules и dependencies. Если unsupported конструкция относится только к другому VRF, не блокировать весь прибор без причины; если привязать её к области нельзя, блокировать отрицательные выводы для потенциально затронутых областей. `unknown` не заменять `any`, пустая группа не равна unresolved, отсутствие строки в частичном экспорте не равно отсутствию настройки.

### Семантическая алгебра

Для полностью поддержанного правила `r` его matcher задаёт множество пакетов `M(r)`, включая все измерения, которые реально участвуют на платформе. Для действующей first-match политики эффективная часть `E(r)=M(r)\(∪ M(t))`, где `t` — более ранние активные терминальные правила той же области. Пересечения и разности вычисляются в пространстве полных tuples, а не отдельно по каждой оси с последующим неправильным объединением. Пример: union двух прямоугольников `A×X` и `B×Y` не равен `(A∪B)×(X∪Y)`; последнее добавляет лишние `A×Y` и `B×X`.

Для локальных проверок широты достаточно доказанного настроенного matcher, и finding должен называться «настроено разрешение». Для нарушения конкретного доступа по профилю нужны две явно разные ступени: intent finding на `M(r)` и effective policy finding на `E(r)`. Если порядок неизвестен, можно доказать intent нарушение по полным собственным условиям, но нельзя утверждать эффективный allow. Маршруты, NAT, reverse path, state и endpoint service существуют ещё одним уровнем. Даже вычисленный firewall path не доказывает работу сервиса на конечном хосте.

Алгебра должна поддержать intersection/difference/union, witness tuple, provenance покрывающих фрагментов, нормализацию интервалов без раскрытия каждого IP. Сначала точная реализация на небольших пространствах; затем decision diagrams/интервальные структуры только после сравнения с независимым oracle. Лимиты времени, памяти, фрагментов и cancel имеют воспроизводимые настройки. Достижение лимита выдаёт `unknown/partial`, количество обработанного и необработанного, без «успешно, нарушений нет».

### Evidence, severity и корреляция

У каждой находки: check ID/version, device/revision/source hash, индивидуальные rule IDs, source locations, scope, профиль/version, вычисленные множества или witness, preconditions, уровень утверждения и remediation. Для конфигурационной находки о NTP rule IDs могут быть пусты: нужен ID соответствующей сущности, а не выдуманное firewall-правило. Секреты заменять marker/hash, не переносить community/password в JSON/HTML/карточку.

Severity определяется отдельным объяснимым профилем: тип нарушения, категория источника, критичность назначения, широта и effective evidence. «Публичный IP» сам по себе не значит «Internet», TCP/443 не доказывает безопасный протокол, порт 5432 не доказывает PostgreSQL. Снижение severity исключением не изменяет вычисленное техническое условие. Связанные findings группировать в одну problem card с несколькими check IDs: duplicate/shadowing/conflict, any-any/broadness, parser missing-object/reference error. Подсчёт problem cards и findings хранить отдельно, чтобы не терять трассировку.

## 4. Потенциал существующих семи проверок

### FW-ANY-ANY — широкий matcher адресов

Текущее поведение: активный `ALLOW`, полный resolver, хотя бы одна общая IP family с универсальными source и destination. Код не требует универсального сервиса: существующий title «Разрешение между любыми адресами» соответствует реализации, но пользовательское имя any-any может ошибочно восприниматься как «любые порты». Не менять историю задним числом. Расширение: три подтипа — any-addresses с ограниченным сервисом, any-service с ограниченными адресами, universal всех осей. Сохранять family; IPv4 0.0.0.0/0 не эквивалентен IPv6 ::/0.

Польза — быстро найти наиболее широкие намерения, затем показать effective остаток и исключения до правила. Для админского сервиса high, для необходимого proxy egress с профильным ограничением contextual lower; generic порог не устраняет факт широты. Evidence: какие оси universal, конкретный matcher, policy placement, было ли вычислено `E`. Приёмка: allow/deny/disabled, обе families, any с unknown service, ограниченный TCP/443 и универсальный IP. NEW-04…06 могут дать подробности, но broadness у одной problem card не должен увеличивать счёт «опасных правил» втрое.

### FW-DUPLICATE — равенство matcher и эффекта

Сейчас сравниваются активные terminal rules одной доказанной области, совпадение `RuleMatch`, action и известного logging. Неизвестное logging препятствует утверждению полного duplicate. Расширение: эффект должен включать NGFW security profiles, log destination, schedule, identity, QoS и прочие поддержанные side effects. Предложить две категории: duplicate matcher для ревью и доказанно одинаковый весь эффект для кандидата удаления. Нельзя удалять правило только потому, что условия совпали: могут различаться владелец, lifecycle, change ticket или vendor-specific counters.

Evidence сохраняет обе индивидуальные позиции, поля equality и поля различий; canonical hash ускоряет shortlist, но равенство подтверждается сравнением. NEW-12 касается объектов, а не правил. Приёмка — различный logging, разный profile, schedule и namespace не превращаются в одинаковые правила; перестановка независимых объектов не меняет canonical equality; одинаковые names не создают совпадение. Remediation только draft change с повторным symbolic diff.

### FW-SHADOWED — полное покрытие одним предыдущим правилом

Сейчас это включение всех условий одного позднего matcher в более ранний terminal matcher. Полные одинаковые duplicates отделяются. Развитие: показывать две ситуации — одно действие (позднее не добавляет решение) и противоположное действие (позднее намерение не выполняется). Добавить nonterminal/log-only и user/app/time semantics, только когда adapter их доказал. Для schedule сравнивать временные множества; «первое правило активно сейчас» не означает затенение во все времена.

Польза — объяснить, почему изменение в позднем правиле не влияет на policy. Evidence: covering rule ID, covered rule ID, inclusion proof и witness исхода. Severity medium по умолчанию для ревью, high при доказанном скрытии запрещающего ограничения критичного сегмента. NEW-10 добавляет покрытие union, NEW-09 partial; NEW-11 связывает opposite actions. Приёмка: одно правило покрывает адреса, но не сервис — находки нет; разные VRF не сравниваются; неизвестное раннее правило не игнорируется; remove/reorder recommendation требует повторного решения policy.

### FW-MERGE-CANDIDATE — сжатие без расширения доступа

Текущий алгоритм рассматривает соседние rules с одинаковым эффектом, описанием и владельцем, ровно одной отличающейся осью; вложенные/затенённые кандидаты исключаются. Развитие — предложить точный union только изменяющейся оси и доказать `decision_before=decision_after` для всей поддержанной области. Несмежные rules нельзя объединять по простому совпадению action: intermediate deny и side effects могут изменить outcome. Разные profiles и deadlines запрещают автоматическое объединение.

Evidence: source IDs, proposed normalized rule, delta matcher, число сокращённых сущностей, proof/no-proof. Это info, не нарушение и не причина снижать compliance. Для NEW-04 union может пересечь организационный порог широты — вывести tradeoff и не рекомендовать изменение. Приёмка: после union нет дополнительных сочетаний source×destination; log/profile различия блокируют; hidden unsupported condition делает candidate unknown. Потенциал — безопасное планирование, export draft и сравнение, без записи на устройство.

### FW-LOGGING — регистрация событий по назначению

Сегодня флаг `require_logging` проверяет активные allow, известное `logging_enabled`; severity medium. Развитие: профиль выбирает allow/deny, start/end, traffic class, sampling, rate limit и обязательные destinations. Не требовать весь permit traffic без учёта нагрузки. Настройка «logging enabled» и delivery журналов — разные evidence. NEW-21 проверяет получателя; их связывает проблема наблюдаемости, но причины разные.

Evidence: policy requirement и фактический режим; запрещённая отсутствующая настройка отличается от unsupported logging syntax. Приёмка: disabled policy => not_applicable; logging unknown => partial; локальный журнал без внешнего receiver не считается успехом NEW-21; full-profile logging не заменяется булевым true. Operational ingestion/retention можно добавить позднее самостоятельными health checks и не заявлять его по configuration alone.

### FW-COMMENTS — описание намерения

Сегодня активное правило с `description_status` known/absent и пустым description создаёт low finding; неизвестный комментарий даёт limitation. Развитие: структурированный minimum template «цель, получатель, service purpose», lint placeholder («test», «tmp») как advisory, поиск ссылки на заявленный owner/ticket без автоматического превращения текста в подтверждённые metadata. Существующие чекбоксы сохраняются, профиль позволяет обязательность по scope.

NEW-19 проверяет owner/основание, NEW-17/18 lifecycle. Полезная карточка показывает четыре независимых поля и один checklist, чтобы одна пустая строка не выглядела четырьмя разными уязвимостями. Приёмка: unicode/whitespace, известное отсутствие и unsupported разбор различаются; непустой «owner=Ivan» не считается действительным владельцем без соглашения о формате. Польза — ускорить безопасный review и не потерять бизнес-назначение при cleanup.

### FW-DISABLED — lifecycle отключённых правил

Сейчас все disabled правила инвентаризируются как info. Правильно сохранить это поведение: disabled rule не даёт текущего разрешения. Развитие: disabled_since, reason, restore owner, retained evidence, ссылка на ticket, планируемое удаление после rollback window. Если duration неизвестна, не вычислять её из возраста файла. Сравнение ревизий показывает состояние включения без утверждения о дате фактического изменения на устройстве.

Связи: NEW-20 может предложить review активного правила, а после подтверждённого отключения FW-DISABLED отслеживает lifecycle. NEW-17 не должен считать disabled временное правило действующим просроченным доступом. Acceptance: отсутствуют active-risk findings для disabled; повторный импорт не сбрасывает manual note; сравнение rules со сменившимся ID показывает ambiguous mapping. Потенциал — восстановление и безопасная уборка с человеческим ревью, не массовое удаление.

## 5. Паспорта NEW-01…NEW-25

Во всех паспортах P/N/U — positive violation, negative compliant, unknown. Примеры synthetic; адреса служат иллюстрацией, не описывают сеть пользователя. Требования общего контракта применяются к каждому паспорту, поэтому указанные ниже edge cases дополняют общие, а не отменяют их.

### NEW-01 / B / FW-MANAGEMENT-UNTRUSTED — административное разрешение вне допустимого источника

**Смысл и польза.** Выявить настроенные пути к управлению устройством/системой, выходящие за approved admin networks. Разделить управление самим firewall и транзит к management endpoint: у них разные ACL/bindings, severity и remediation.

**Scope и входы.** Активный allow, полный matcher management service, registered target либо подтверждённый management listener, профиль admin sources по site/VRF, mapping зоны и binding. SSH/RDP/HTTPS-management задаются профилем; TCP/443 ко всем сайтам не считать управлением. Capability `management_acl` для local plane или `full_match/binding_scope` для transit.

**Предикат.** `V=M(r)∩AdminTargets∩AdminServices∩(SourceUniverse\AllowedAdminSources)` в соответствующей области. Непустой V — configured intent finding; наличие witness в `E(r)` — effective policy finding. Если admin list неполон/не утверждён, U. Зона Internet определяется authoritative mapping, не вычислением public IP.

**Severity/evidence/remediation.** High для critical management из недоверенной зоны, medium для избыточной trusted подсети; evidence сохраняет offending source fragment, target/service, rule ID, binding и profile clause. Предложить admin VPN/jump-host source scope, не советовать отключить единственный management path без альтернативы.

**P/N/U, ошибки.** P: guest zone→registered switch tcp/22 allow; N: только jump-host /32; U: HTTPS назначение неизвестно. FP при неверном inventory, FN при нестандартном management port или неразобранном локальном listener. DNAT, IPv6, inherited ACL и динамические VPN pools обязательны в corpus.

**Задачи/приёмка.** Typed admin profile, management inventory, interval difference, explain card. Проверить пересечение /24 с разрешённым /28: найти только остаток; earlier deny должен менять effective слой, сохраняя intent. Связать FW-ANY-ANY/FW-LOGGING с одной проблемой.

### NEW-02 / B / FW-DATABASE-EXPOSURE — доступ к зарегистрированной БД из запрещённой категории

**Смысл.** Проверять доступ к важным хранилищам по их владельцу и approved caller set, а не по известным номерам портов. Польза — различать необходимый application→DB traffic и широкий пользовательский/гостевой доступ.

**Входы/capability.** Инвентарь DB endpoints с service identities, ports/protocol, criticality, site/VRF, сроком свежести; профиль permitted sources; полные адресные/service условия. Если известен лишь tcp/3306, результат advisory «сервис по профилю портов», не «открыта БД». DNS/cluster endpoints требуют подтверждённого resolution snapshot.

**Алгоритм.** Для каждого зарегистрированного DB service `d`: `V=M(r)∩TuplesTo(d)\ApprovedDBTuples(d)`; объединить findings для одного rule/DB, сохранив отдельные witnesses и profile clauses. Effective stage использует E. Не смешивать destination port до/после DNAT; неизвестная stage => U для effective утверждения.

**Severity и действия.** High для запрещённой зоны к critical DB; medium для слишком широкого application tier. Evidence содержит ID инвентаря, несовпадающую категорию, rule ID, destination и service, свежесть. Remediation — выделить consumers, проверить backup/replication/monitoring, сузить правило, затем прогнать контрольные потоки.

**Примеры/риски.** P: guest→registered DB/5432; N: approved app /28; U: unmanaged asset либо stale DNS. FP при устаревшем DB inventory, FN при прокси/нестандартном service. Edge: clusters, failover addresses, shared NAT, replication, одинаковый IP в двух VRF.

**Приёмка.** Импорт inventory, comparison и per-service evidence. БД на 15432 находится, обычный web service на 5432 не маркируется БД. any-any связывается с FW-ANY-ANY, operational наличие процесса не утверждается.

### NEW-03 / A / FW-DISALLOWED-PROTOCOL — разрешение запрещённого профилем протокола

**Смысл.** Сократить legacy cleartext и исключить неоправданное использование сервиса. Название «незащищённый» применимо только к доказанному протоколу/назначению; L4 tuple сам по себе может быть только совпадением с профилем портов.

**Входы.** Полные TCP/UDP/protocol conditions активного allow и версионированный запрет с scope, назначением, исключениями. Пакет A может поставляться с явным baseline, но его активацию и границы нужно показать: Telnet/FTP, HTTP только для management target. Capability service sets; app-aware утверждения требуют application matcher.

**Предикат.** `M(r)∩ForbiddenServiceTuples(profile)≠∅`; фиксировать все нарушенные clauses, не весь диапазон как опасный. Для broad IP any показать, что совпадение включает forbidden service, без выдуманного обнаружения трафика. Intent/effective слои отдельно.

**Severity/evidence.** Medium по умолчанию, high при management из untrusted; evidence rule ID, service fragment, цель, профиль и exception state. Предложить защищённую альтернативу по назначению, endpoint readiness и постепенную миграцию. TLS на нестандартном порту либо FTP over TLS не распознавать по одному номеру.

**P/N/U и edge.** P: Telnet allow при active baseline-запрете, включая случай принятого временного исключения; во втором случае сохраняется `technical_outcome=violation`, а `disposition=accepted_until` снимает открытое действие только в точном scope и до срока. N: SSH либо сервис, разрешённый самой baseline-политикой; U: protocol OTHER либо HTTPS-management цель не установлена. Пользовательское принятие риска не превращает техническое нарушение в N и не меняет его эталонную метку precision/recall. FP — tunnel/encryption вне модели; FN — нестандартный порт без app inventory. ICMP нельзя трактовать как портовый диапазон.

**Задачи/приёмка.** Baseline clauses, пересечение, distinction protocol/port heuristic. Fixtures содержат broad range, named service и unknown. Дубликат any-any группируется, FW-LOGGING не считается заменой запрета.

### NEW-04 / A / FW-BROAD-SERVICE-RANGE — избыточное множество портов

**Смысл.** Выделить широкое настроенное разрешение для ревью минимально необходимых сервисов; число портов — показатель сложности/широты, не доказательство эксплуатации.

**Scope/входы.** TCP/UDP destination port intervals активного allow, profile thresholds по назначению/направлению и протоколу. Capability `service_sets`; source-port ограничения отдельно отражаются и не выдаются за destination диапазон. Для протокола IP any применять отдельный universal-service subtype, а не маскировать count 65536.

**Алгоритм.** Merge overlapping/adjacent intervals; `count=Σ(end-start+1)` по уникальному множеству и протоколу. Нарушение `count>threshold` или contiguous span превышает отдельный порог. Профиль может ограничивать множество разрешёнными service IDs, а не cardinality. Пороговые числа согласуются организацией; единого industry стандарта «100 портов опасно» нет.

**Severity/evidence/remediation.** Low/medium intent review, выше для critical destinations и untrusted sources. Evidence rule ID, canonical ranges, cardinality, threshold и category. Предложить список минимальных сервисов по owner specification; отсутствие traffic observations не позволяет автоматически убрать остальные.

**P/N/U и ошибки.** При демонстрационном threshold=100 P: 1000–1100 (101), N: 1000–1099, U: unresolved service group. Overlap 1000–1050 и 1040–1100 считать 101, не 112. FP — approved dynamic RPC/voice диапазон без exception; FN — множество маленьких rules, вместе дающих broad access (будущий aggregate view).

**Приёмка.** Interval boundaries, 1/65535, TCP versus UDP, duplicates, cancellation; cardinality invariant к порядку и разбиению диапазонов. Связи FW-ANY-ANY/FW-MERGE-CANDIDATE: сжатие может увеличивать визуальный span, но не должен изменять точное множество.

### NEW-05 / A / FW-BROAD-SOURCE — слишком широкое множество источников

**Смысл.** Найти разрешения, в которых источников существенно больше утверждённого потребителя. Польза — подсветить overscope без догадки о реальной активности каждого адреса.

**Входы.** Known source address set и профиль допустимой широты для service/destination/site/VRF/IP family. CIDR prefix может служить удобной подписью, но основной limit — cardinality/approved sources. Capability address sets; динамические группы и FQDN без закрытого snapshot => U для точного подсчёта.

**Алгоритм.** Объединить интервалы, определить count отдельно IPv4/IPv6 и difference с approved set. Проверять как cardinality threshold, так и фактический лишний fragment. Сумма двух /25 соответствует /24 по cardinality, а два далеко расположенных /32 не превращаются в широкий spanning диапазон. Не вычитать network/broadcast: ACL matcher сравнивает адреса, бизнес число «живых хостов» здесь не вычисляется.

**Severity/evidence.** Medium для критичного target, low для housekeeping; широкое management связывать с NEW-01. Evidence: rule ID, union, family, limit, exceeded fragment и witness. Предложить consumer group по inventory и approved profile. Нет наблюдений — нет автоматической рекомендации минимального рабочего source set.

**P/N/U/edge.** При лимите 256 P: /23; N: /24 ровно на границе; U: unresolved nested group. FP из-за неверного business threshold, FN при разделении broad grant на много rules. IPv6 /64 не оценивать по IPv4 /24-порогу; использовать назначенные policy sets. Any-any отображается существующей problem card с деталью NEW-05.

**Приёмка.** Profile validation, family split, exact union, adjacent/overlapping intervals, exclude/negate только при поддержке полного matcher. Threshold и outcome воспроизводимы при переупаковке CIDR.

### NEW-06 / A / FW-BROAD-DESTINATION — слишком широкое множество назначений

**Смысл.** Ограничить destinations необходимыми backend/asset groups и сделать видимым ошибочно заданный «весь subnet» вместо сервера.

**Scope/входы.** Known destination set активного allow, family-specific profile по источнику, service purpose и scope; approved destination inventory. До NAT анализирует только документированную match stage. Capability address sets; URL categories/application destinations нельзя заменять множеством IP без подтверждённой семантики.

**Предикат.** Тот же exact union cardinality и set difference, что NEW-05, по оси D. `V=D\ApprovedDestinations`, при доказанно полном business scope. Если порог есть, но inventory нет, выдавать threshold finding, не «доступ к посторонним серверам». Общий адресный span — только отображение, не исчисление union.

**Severity/evidence/remediation.** Medium при известной критичной zone/service, low для широкого profile review. Evidence rule ID, D, expected set, лишний fragment, stage, threshold. Remediation — выделить named target group, проверить failover/CDN/replication до narrowing; не строить список из текущих DNS answers как вечный whitelist.

**Примеры/ошибки.** P: app→вся server /16 при approved /28; N: две approved DB /32; U: dynamic FQDN group without authoritative time window. FP — legitimate elastic service без корректного профиля, FN — broad access через множество narrow rules. Edge: shared IP hosting, any v4 при ограниченном v6, destination negation, overlapping site ranges.

**Приёмка.** Не дублирует FW-ANY-ANY в summary, но сохраняет отдельный technical outcome. Доказать отрицательный результат на точном union с дырками; unsupported NAT не позволяет расширить утверждение до network reachability.

### NEW-07 / B / FW-UNRESTRICTED-EGRESS — все сервисы из доверенной в недоверенную область

**Смысл.** Выявить обход approved egress architecture, например прямое unrestricted разрешение вместо proxy/DNS/NTP gateways. Это организационное требование, не универсальный запрет Internet.

**Входы.** Trust classification зон/сетей, direction/binding, полные service sets, approved egress clauses, исключения. Capability full matcher и mapping; RFC1918 не заменяет classification. Trust не бинарная глобальная метка: филиал/vendor VPN/DMZ задаются явно.

**Алгоритм.** Пересечь активный allow с `TrustedSources×UntrustedDestinations`; доказать universal service по поддержанному protocol universe. `tcp any` — все TCP, но не все IP protocols; разные subtypes. Дополнительно определить forbidden egress difference по matrix; NEW-08 даёт конкретные запретные потоки. При ранее стоящих deny вычислить E для effective subtype.

**Severity/evidence.** Medium по умолчанию, high для critical production прямого egress в prohibited zone. Rule ID, direction, zone provenance, service universality и exception. Предложить approved gateways и необходимые сервисы; отсутствие logs нельзя использовать как доказательство ненужности egress.

**P/N/U/edge.** P: workstations→external IP any; N: approved proxy /32 tcp/3128; U: destination zone mapping неизвестен. FP — неверная trust label, FN — union множества service-specific rules (позднее aggregate). Proxy transparent routing, VPN, NAT and IPv6 требуют отдельного corpus.

**Приёмка.** Сам публичный destination не создаёт violation; tcp universal не маркируется universal-IP. Связать FW-ANY-ANY, FW-LOGGING, NEW-08 и NEW-25 по общей проблеме egress, сохраняя их разные доказательства.

### NEW-08 / B / FW-SEGMENTATION-MATRIX — пересечение с запрещённым потоком

**Смысл.** Превратить business segmentation в проверяемое условие и показать точный нарушающий tuple. Потенциал — контроль неизменности сегментации при каждом импорте и сравнение policy before/after.

**Входы.** Версионированная matrix зон/сетей/ролей, services, direction и exception deadlines; complete membership mapping. Explicit deny clauses и отсутствие allow в closed-world matrix должны различаться. Режим «не указан => запрещён» допустим только при утверждённой полноте матрицы.

**Алгоритм.** `V_raw=E(r)∩ForbiddenTuples` для effective technical violation; отдельно `M(r)∩ForbiddenTuples` для intent. Baseline matrix permissions определяют само ForbiddenTuples и не смешиваются с пользовательским принятием риска. Для действующих принятых исключений хранится отдельное `V_open=V_raw\AcceptedExceptionTuples(scope,time)`: это множество открытых действий, а не новый технический эталон. Исходные находка и V_raw сохраняются с disposition/accepted_until; precision/recall технической проверки не меняются при принятии риска. Противоречивые baseline clauses — ошибка профиля/U, не случайный выбор последнего. Наличие пересечения доказывается witness; отсутствие по всей политике требует полного matcher и coverage.

**Severity/evidence.** High для запрета критичного trust boundary; medium для остальных. Evidence rule IDs, matrix clause, source/target group provenance, service/time, witness и chosen winner. Remediation — пересмотреть правило или policy clause через approved change process, не скрывать организационную ошибку новым exception.

**P/N/U и ошибки.** P: guests→payroll DB; N: app→DB approved tcp/15432; U: host одновременно в несовместимых categories либо matrix incomplete. FN — неописанные новые segments; FP — stale inventory/roles. Multi-zone addresses и negate требуют exact membership semantics.

**Приёмка.** DSL/validator, explain solver, independent packet enumeration в small model. Более ранний deny устраняет effective violation, но показывает intent. FW-SHADOWED/NEW-11 связываются, не заменяют матричный результат.

### NEW-09 / A / FW-PARTIAL-SHADOW — непустая перекрытая и непустая остающаяся часть

**Смысл.** Объяснить, почему позднее правило работает лишь частично и какие адреса/сервисы реально до него доходят. Не всякое пересечение — дефект: whitelist exception перед general rule может быть намерением.

**Scope/входы.** Complete ordered terminal policy в одной binding области, все match dimensions включая schedule/identity при их наличии. Capability `ordered_terminal_policy/full_match`; одинаковые sequence либо неизвестное earlier condition => U для затронутой части.

**Алгоритм.** `C=M(r)∩∪M(t)` и `R=M(r)\∪M(t)`. Finding тогда и только тогда, когда C и R непусты. Сохранять покрывающие effective fragments и winning actions; если R пусто, маршрутизировать в FW-SHADOWED/NEW-10. Pair intersection достаточно для shortlist, но proof строится на union всех preceding terminal rules.

**Severity/evidence/remediation.** Medium при hidden intended deny, info/low при намеренном exception. Evidence rule ID, earlier IDs, witness в C и R, exact segments и active time. Remediation — уточнить поздние условия или описание; reorder только после diff поведения.

**P/N/U и риски.** P: earlier deny tcp/1–100, later allow tcp/50–150 => 50–100 shadowed, 101–150 remaining; N: disjoint либо full shadow subtype; U: раннее rule с application condition без поддержки. FP при игнорировании временного окна, FN при неверном union rectangle.

**Приёмка.** Реализовать intersection/difference/provenance; witness из R не совпадает ни с одним preceding rule; C∪R=M(r), C∩R=∅. Связь NEW-11 добавляет opposite action intent без второго счёта затенённого правила.

### NEW-10 / A / FW-UNION-SHADOW — полное покрытие несколькими предыдущими правилами

**Смысл.** Закрыть пробел single-rule shadowing: позднее правило может быть полностью недостижимым, хотя ни одно раннее правило не включает его целиком.

**Входы.** Те же capabilities и область, что NEW-09; полный ordered list, terminal semantics, exact match dimensions. Поддержать default rules как явные synthetic semantic entities только с adapter evidence; не смешивать implicit deny после r с предыдущими rules.

**Предикат.** `M(r)≠∅`, `M(r)\∪M(t)=∅`, и ни один t самостоятельно не покрывает M(r). Сформировать covering set. Минимальный covering set необязателен для первой версии; результат честно «достаточный набор», а greedy сокращение — улучшение UX, не доказательство математического минимума. Лимит фрагментов даёт U.

**Severity/evidence.** Medium для cleanup, high при полностью неработающем critical deny. Evidence individual rule IDs, union fragments, empty remainder proof, actions, completeness. Remediation — review intended policy, удалить только после reconciliation owners/tickets и decision equivalence для текущей и ожидаемой будущей конфигурации.

**Примеры/риски.** P: earlier tcp/1–50 плюс 51–100, later 1–100; N: gap=75 либо one earlier covers all (FW-SHADOWED); U: runtime budget exceeded. Особый negative: earlier A×X и B×Y не покрывают late (A∪B)×(X∪Y). FN/FP из axis-wise union полностью исключить тестовым oracle.

**Приёмка.** Exact-cover engine, overlap dedup, repeated IDs guard, IPv6 symbolic tests, limits/cancel. Все witnesses позднего matcher имеют winner earlier; NEW-09 не одновременно выводится как partial на той же единице.

### NEW-11 / A / FW-CONFLICTING-OVERLAP — противоположные действия на общих условиях

**Смысл.** Подсветить зависимость решения от порядка и ускорить review intent. Allow и deny exception часто намеренны; finding называется «пересечение с различающимся действием», не «ошибка доступа».

**Входы.** Полные matchers, одна ordered policy scope, documented action equivalence. Deny/drop/reject все блокируют доступ, но различаются ответом/log effects; для outcome противоположность allow versus blocking, для side-effect conflict отдельная категория.

**Алгоритм.** Для пары i<j определить `X=M(i)∩M(j)`. Рассмотреть `X\∪M(t<t_i)` — часть, где перестановка этой пары действительно может изменить outcome. Непустой X при пустой observable change — только intent relation; полное containment классифицировать shadow, partial relation связать NEW-09. При несоседних rules проверять intermediate winners для контрфактической перестановки.

**Severity/evidence.** Info/medium review, high только с подтверждённым matrix violation/hidden critical deny. Rule IDs, intersection witness, winner сейчас, simulated outcome after specified change, ограничения. Рекомендация — описать исключение либо уточнить диапазоны, не перемещать deny «наверх» автоматически.

**P/N/U и ошибки.** P: allow app /24→DB перед deny app /25; N: оба allow или disjoint; U: unknown order. FP — намеренный narrow allow exception без documented exception; FN — неучтённая app/time condition. Partial schedule overlap вычислять отдельно.

**Приёмка.** Action taxonomy, relation graph, контрфактический solver. Same deny/drop показывать effect difference, не allow/deny conflict. FW-SHADOWED/NEW-09/10 остаются техническими subclaims одной карточки.

### NEW-12 / A / FW-EQUIVALENT-OBJECTS — разные объекты с одинаковым значением

**Смысл.** Сократить объектный хаос, обеспечить устойчивые группы и уменьшить риск несогласованного изменения двух эквивалентных объектов.

**Входы.** Полный catalog одного namespace, object kind, resolved canonical value, raw members/provenance; capability object_catalog и resolver. Для групп сравнивать semantic value и отдельно structure. FQDN сравнивать literal canonical hostname, а не текущий IP: два разных домена с одинаковым DNS answer не эквивалентны навсегда.

**Алгоритм.** Canonical key `(namespace,type,family,normalized semantic set,all relevant qualifiers)`; shortlist hashing, затем exact equality. Group и host с одинаковым value — semantic candidate, не interchangeable тип автоматически. Учитывать dynamic predicates, negate и protocol qualifiers; unknown blocks proof.

**Severity/evidence/remediation.** Info/low, не vulnerability. Object IDs, source locations, canonical equality, список всех referencing entities и differing metadata. Предложить canonical объект, impact preview ссылок и сохранение алиасов до approved cleanup. Разные owners/lifecycle могут оправдать разные объекты.

**P/N/U и edge.** P: two /24 objects одинакового namespace; N: same name в другом VRF либо разные FQDN; U: partially resolved group. FP — потерянный namespace/type qualifier, FN — разные эквивалентные interval partitions без canonical merge. Семантически разные service names по application purpose не объединять автоматически.

**Приёмка.** Typed object identity, hash/equality, references impact. FW-DUPLICATE остаётся отдельным rule check; NEW-13 может обнаружить старый alias, но удаление требует общего proof graph.

### NEW-13 / A / FW-UNREFERENCED-OBJECT — нет поддержанных ссылок на объект

**Смысл.** Уменьшить размер configuration и burden review, сохраняя служебные объекты NAT/VPN/management. Заявление об «unused» требует полного графа всех потребителей, а не поиска имени в firewall rules.

**Входы.** Typed references с namespace/object ID, source owner, reference kind, section completeness. Root entities: active/disabled rules, NAT, VPN, management, schedules, external policy imports, templates и reserved vendor objects. Capability reference_graph задаёт именно поддержанные kinds. Неизвестная секция потенциального использования препятствует global deletion claim.

**Алгоритм.** Для прямого «нет ссылок» indegree=0 по полному графу. Отдельное улучшение — «не достижим от roots» (dead groups могут ссылаться друг на друга); название и доказательство другие. Disabled rule reference по-прежнему использование. При частичном graph вывод «нет ссылок в исследованном firewall срезе» advisory, не рекомендуем удалить.

**Severity/evidence/remediation.** Info, reference scope manifest, object ID, namespace, complete sections и any missing kinds. Предложить owner review/export backup; reserved/default objects исключаются validated vendor policy, не префиксом имени.

**P/N/U.** P: полный catalog и граф, orphan host; N: ссылка только в disabled NAT; U: NAT section unsupported. FP — внешнее templating и невидимые references; FN — учитывать только indegree и пропускать dead subgraph. Edge: include files, address/service names совпадают, cross-namespace references.

**Приёмка.** Graph builder, completeness gate, deletion preview. NEW-14/15 делают graph invalid и запрещают утверждать global unused, FW-DISABLED не обнуляет ссылки.

### NEW-14 / A / FW-MISSING-OBJECT-REFERENCE — ссылка без цели

**Смысл.** Превратить parser diagnostic в действие «исправить владельца ссылки», сохранив причину неполного анализа.

**Входы.** Полный catalog соответствующего namespace, raw typed reference и syntax semantics (object reference отличается от literal builtin service). Capability object_catalog/reference_graph. Forward reference допустима: резолвинг после чтения всех sections. Если dependent include/export part не получен, отсутствие объекта недоказано.

**Предикат.** Target ID отсутствует в полностью прочитанном разрешённом namespace после resolving allowed imports. В alternative namespace нельзя искать автоматически и считать исправление доказанным. Если vendor отвергает configuration с такой ссылкой, сообщить «источник содержит неразрешённую ссылку», не «на устройстве разрешён небезопасный доступ».

**Severity/evidence.** Medium data-quality, high workflow priority для blocked critical policy, но risk severity отдельно. Source rule ID либо owner entity ID, token/source location, expected target type, namespace, completeness. Remediation — получить missing include либо исправить reference/create intended object после просмотра impact.

**P/N/U/edge.** P: complete source с group member nonexistent; N: target объявлен ниже; U: partial catalog. FP — неверное распознавание builtins, case normalization или namespace inheritance; FN — silently placeholder object. Unicode/case-sensitive names и vendor implicit object definitions требуют fixtures.

**Приёмка.** Не создавать новый finding поверх того же parser error: одна карточка с parser issue ID и check ID. Matcher affected rules остаётся unknown; отсутствие object не расширяет allow до any.

### NEW-15 / A / FW-CYCLIC-GROUP — цикл вложенных групп

**Смысл.** Найти невозможность конечного полного раскрытия и показать краткую понятную цепочку ссылок вместо повторных generic errors.

**Входы.** Raw directed membership graph, identities/type/namespace, edge source locations; capability reference_graph. Resolved flattened endpoints недостаточны: после flattening происхождение цикла может быть потеряно. Dynamic group predicates анализируются отдельно, если это не явные membership edges.

**Алгоритм.** Tarjan/Kosaraju SCC: component size>1 либо self-loop. На SCC одна problem card; показать representative cycle и все affected groups/rules. Не пытаться перечислить все простые циклы экспоненциально. При частичном графе обнаруженный цикл доказуем, отсутствие циклов по всему catalog — нет.

**Severity/evidence/remediation.** Medium data/model issue; operational последствия определяет vendor validation. Object IDs, cycle edges и locations, dependent rule IDs, parser issue link. Предложить убрать неверный edge либо вынести shared members в acyclic group. Не заменять group пустым множеством и не угадывать desired values.

**P/N/U.** P: A→B→C→A или A→A; N: diamond A→B,C→D без back edge; U: unresolved external include для negative claim. FP — неверные identity collisions или обратные reference edges, FN — граф строится только из resolved portions. Edge: cross-type references, large depth, detached циклы без rules.

**Приёмка.** Iterative/stack-safe graph analysis, deterministic canonical cycle, cancellation, no secret leakage. NEW-14 missing edge отделяется, NEW-16 не считает cycle пустой группой. Parser и check показывают один source-backed actionable result.

### NEW-16 / A / FW-EMPTY-GROUP-IN-RULE — доказанно пустая группа в активном правиле

**Смысл.** Найти намерение, которое не имеет ожидаемых членов, и предупредить об опасной vendor semantics пустого selector.

**Scope/входы.** Explicit empty definition либо exact known empty resolution, active reference, object membership, vendor-specific meaning. Capability object_catalog/reference_graph/full_match. Поле пустого tuple с status UNKNOWN не является пустым object. Некоторые vendor representations используют отсутствие selector как any/default — это другой typed state.

**Алгоритм.** Построить proof empty leaf/group по complete graph, затем traversing active references. В зависимости от семантики: no-match => ineffective rule; wildcard-on-empty => broad unintended grant; vendor-rejected => source diagnostic. Без documented semantic behavior finding может доказать пустоту объекта, но effect U.

**Severity/evidence/remediation.** Low/medium ineffective intent, high только доказанному unintended allow по профилю. Object definition и IDs, referencing rule IDs, source fields, behavior basis, affected axis. Рекомендация — восстановить нужных members или убрать reference после проверки owner, не подставлять any.

**P/N/U/edge.** P: defined empty static group в active allow; N: known populated group или reference only disabled; U: missing members, cycle, dynamic group без inventory snapshot. FP — пустой dynamic group временно допустим, FN — неправильное сохранение состояния пустоты при нормализации. Negated empty group может означать universe, а не empty.

**Приёмка.** Добавить domain representation empty/absent/unresolved, vendor semantic fixtures. NEW-14/15 остаются unknown dependencies, FW-DISABLED reference не даёт active issue; доказательство пустоты сохраняется отдельно от доказательства воздействия.

### NEW-17 / B / FW-EXPIRED-TEMPORARY-PERMIT — срок истёк, разрешение ещё действует в настройках

**Смысл.** Контролировать жизненный цикл временного доступа и не оставлять incident/migration exceptions навсегда.

**Входы.** Active allow, explicit approved lifecycle metadata temporary + expires_at, aware analysis clock/timezone, schedule semantic state. Capability rule_metadata/schedule. Deadline from owner metadata и vendor enforcement schedule различать. Истёк metadata deadline при отключившем доступ vendor schedule — просроченный review artifact, но не действующее разрешение.

**Предикат.** `temporary ∧ enabled ∧ now≥expires_at` для административной просрочки; действующий permission subtype требует matcher-active-time и ненулевое effective или configured разрешение на now. Границу inclusive/exclusive документировать; без known timezone U. Repeat weekly schedule без overall deadline не считать expires_at.

**Severity/evidence.** Medium lifecycle, high critical untrusted permit, low если schedule уже блокирует. Rule ID, structured deadline provenance, timezone, evaluated_at, schedule state, profile clause. Предложить disable/extend с владельцем и основанием, затем подтвердить новой ревизией; отметка «исправлено» не подменяет configuration evidence.

**P/N/U.** P: expired metadata, active no schedule limit; N: future deadline; U: текст «до пятницы» или naive timestamp. DST ambiguous/nonexistent local times, leap-day, stale config и clock skew fixtures обязательны. FP — неверная extraction, FN — временное намерение не отмечено структурно (NEW-18 может тоже не знать).

**Приёмка.** Typed lifecycle, frozen clock tests, UTC conversion и chronology; FW-DISABLED исключает active subtype, NEW-19 связывает owner gaps. Metadata import не разрешает выдумать deadline из любого comment.

### NEW-18 / B / FW-TEMPORARY-PERMIT-WITHOUT-END — временное разрешение без конечного срока

**Смысл.** Предотвратить бесконечные временные exceptions ещё до просрочки, предоставить понятный backlog владельцам.

**Входы.** Explicit temporary marker/provenance, active allow, known completeness deadline metadata, organization maximum duration и optional starts_at. Capability rule_metadata. Prefix «temp» в name — suggestion на review, не authoritative lifecycle. Unknown deadline field и known absent deadline дают разные исходы.

**Алгоритм.** `temporary ∧ enabled ∧ expires_at_status=ABSENT` => violation. Дополнительный subtype `duration>profile.max` требует known start/end; бесконечное recurring schedule не заменяет end date. Если profile позволяет аварийное exception, оно должно иметь собственный finite review date; отсутствие данных не становится exception.

**Severity/evidence/remediation.** Low/medium process, high только связанное concrete access risk. Rule ID, marker source, required deadline clause, completeness, owner. Action — установить срок и ответственного, документировать business renewal condition; не автоматически назначать «30 дней» из шаблона.

**P/N/U/edge.** P: tag temporary=true, expires_at known absent; N: finite future end; U: parser не извлекает metadata или name=t-legacy. FP — structured tag используется как исторический label, FN — реальные temporary rules без marker. Disabled temporary objects — inventory/review, не active lifecycle violation.

**Приёмка.** Schema and profile validation, negative marker cases, null versus absent. FW-COMMENTS не заменяет эту проверку: непустое описание может не содержать срок; NEW-17 отвечает за существующий истёкший срок, не дублирует missing-end.

### NEW-19 / B / FW-MISSING-OWNER-CHANGE-BASIS — нет обязательного владельца или основания

**Смысл.** Обеспечить возможность безопасного изменения каждого разрешения и привязать responsibility к доступу. Это completeness business metadata, а не оценка личности владельца.

**Входы.** Structured owner ID/team, reason/change reference, профиль mandatory fields по active permit/deny, source completeness и optional owner registry. Capability rule_metadata; current `Rule.owner` можно использовать как raw field, но validation требует отдельного provenance/status. Не интерпретировать произвольный комментарий как owner и ticket.

**Предикат.** Для применимых rules list missing/invalid required fields. Known absent => violation; unknown parse => U. Owner departed/team nonexistent — отдельный stale-owner subtype с authoritative registry snapshot; не объявлять человека уволенным по пустой строке. Ticket existence без connected source не подтверждается regex.

**Severity/evidence/remediation.** Low/medium, повышение при critical access без responsible team. Rule ID, fields/status, expected profile и sanitized reference. Action — назначить team, бизнес-цель, change approval; сохранять imported facts и manual annotation раздельно, чтобы note не выдавалась за device metadata.

**P/N/U/edge.** P: required owner known absent, comment непустой; N: owner team + structured basis; U: unsupported annotation section. FP — неучтённое inherited owner, FN — бессмысленный placeholder прошёл validation. Shared policy owners и legacy emergency changes требуют явного профиля.

**Приёмка.** Metadata statuses, inheritance, typed import/manual overlay и экспорт provenance. FW-COMMENTS/NEW-17/18 объединяются в checklist, отдельные check outcomes сохраняются; никаких network запросов к ticket system без разрешённого workflow.

### NEW-20 / C / FW-RULE-NO-HITS-WINDOW — нет срабатываний за достаточное окно

**Смысл.** Предложить evidence-backed review active rules, которые могли стать obsolete, сохраняя редкие backup/DR/seasonal workflows. Нулевой counter — факт наблюдения, не доказательство неиспользования за всю историю.

**Входы.** Vendor/version counter semantics, enabled measurement, stable rule ID и matcher hash, per-node/HA observations, first/last hit, reset/created/modified, observation start/end, completeness и разрешённая длительность. Capability rule_counters и observation. Время импорта/mtime не заменяет начало наблюдения.

**Алгоритм.** Построить окно от max(requested start, reset, created, semantic modification, valid collection start). Подтвердить, что весь требуемый период покрыт и каждый релевантный active HA member наблюдён. Для monotone cumulative counter delta=0 при отсутствии reset/wrap; vendor-supported last_hit может давать дополнительное доказательство. Если окно короче требуемого, U. Counter aggregate без peer coverage не считается глобальным нулём.

**Severity/evidence/remediation.** Info/low candidate review. Rule ID, stable identity proof, window, counters/deltas, reset, gaps, peer coverage, caveat seasonal use. Action — owner review, planned observe window, disable with rollback, последующий review; не auto-delete.

**P/N/U и ошибки.** P: 90 approved days full zero observations; N: one hit within window; U: reset вчера/смена UUID/missing peer. FP — сезонность, outages, counting disabled; FN — другая shadow rule получает traffic. FW-SHADOWED помогает объяснить ноль, но не substitutes observation.

**Приёмка.** Counter snapshot model, identity mapping, timelines, HA/reboot/version fixtures и negative reset. Основание переносится из [PAN-OS 11.1 rule usage documentation](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/view-policy-rule-usage), конкретные adapter defaults проверяются отдельно.

### NEW-21 / B / FW-LOG-RECEIVER-MISSING — внешний получатель не соответствует профилю

**Смысл.** Проверить возможность централизованного аудита по configuration. Local logging и remote receiver выполняют разные роли, поэтому boolean rule logging недостаточен.

**Входы.** Полный logging configuration: receivers, enable state, facility/severity filters, source interface/VRF, protocol/port, category forwarding profiles, approved receiver set и requirements. Capability logging_config; разные operational collectors/profiles имеют отдельную identity. DNS receiver сравнивать как FQDN или с time-bound authoritative resolution.

**Алгоритм.** Для required category доказать хотя бы один enabled compatible target в approved set и соответствующие forwarding links. Нет ни одного при complete config => violation; wrong receiver/transport/filter — distinct subtypes. Если конфигурация хранится в management server, local export without inheritance даёт U. Настроенный receiver не доказывает delivery/retention.

**Severity/evidence/remediation.** Medium, high для critical audit requirement. Entity IDs, locations, approved receiver clause, effective category linkage, отсутствующая настройка как completeness evidence. Настроить approved target и filter; operational test ingestion по отдельному согласованному сценарию, без secret export.

**P/N/U/edge.** P: only local logs при remote required; N: required categories направлены approved SIEM; U: incomplete export. FP — централизованный inherited profile; FN — receiver существует, но filter исключает все relevant events. VRF/source interfaces, dual collectors и HA config требуют tests.

**Приёмка.** Configuration model + profile linkage, checked known absence; FW-LOGGING показывает отсутствующую генерацию событий, NEW-21 — route configured delivery. Их общая карточка не утверждает, что SIEM реально принимает журнал.

### NEW-22 / B / FW-NTP-PROFILE — нет approved time source в настройках

**Смысл.** Поддержать сопоставимость времени журналов, сроков и evidence. Это проверка выбранных источников времени, а не измерение drift или синхронизации.

**Входы.** Complete NTP/time settings нужного context: enable, servers/peers, VRF/source, optional authentication metadata (без secrets), profile allowed/required sources и vendor defaults/inheritance. Capability ntp_config. Устройства, получающие время иным approved механизмом, должны иметь явную альтернативную applicability.

**Алгоритм.** Сравнить configured enabled sources с profile: required отсутствуют либо forbidden set непуст => violation; documented approved alternatives => N/not_applicable по профилю. Если отсутствие строки может означать factory default или managed source, нужно resolver evidence, иначе U. DNS identity и IP identity не эквивалентны без утверждённого alias mapping.

**Severity/evidence/remediation.** Low/medium; повысить workflow priority при спорной chronology, не объявлять false timestamps фактом. Entity/source IDs, allowed clause, configured list, completeness, auth status. Remediation — approved source/VRF; затем отдельный operational sync observation. No route к NTP может выявляться NET query, но configuration наличие сервера не означает достижимость.

**P/N/U.** P: no servers при complete config и required profile; N: approved pair configured; U: partial export. FP — inherited management time, FN — имя approved сервера без доставки. Edge: timezone versus UTC time (timezone не NTP), peer mode, IPv6, auth unsupported.

**Приёмка.** Typed NTP configuration и tested vendor default resolution; никакого title «не синхронизирован» без operational. NEW-17 clock input и NEW-20 windows показывают dependency на доверие времени, не блокируют всё автоматически по generic NTP finding.

### NEW-23 / B / FW-SNMP-LEGACY-SCOPE — SNMP v1/v2c вне approved management set

**Смысл.** Выявить management exposure legacy SNMP с учётом локального listener и ACL, не считать любой transit UDP/161 настройкой SNMP на устройстве.

**Входы.** Enabled version/listeners, management bind/interface/VRF, permitted community scope как opaque identity, local ACL semantics, profile approved networks и legacy exceptions. Capability management_acl и SNMP configuration. Community/password полностью редактируются из evidence; field presence и sanitized identity достаточны.

**Предикат.** Для local v1/v2c configured accessible-source set S определить `V=S\ApprovedManagementSources`, с учётом listener binding и applicable ACL. Если source restrictions в полном config отсутствуют и vendor documented default universal, можно доказать S=universe; иначе U. v3 не означает автоматически безопасно: security level/auth/privacy требуют будущего отдельного check/profile.

**Severity/evidence/remediation.** Medium, high untrusted source к critical device; rule IDs relevant management ACL плюс listener entity ID, offending fragment, profile и version. Action — сузить scope/перейти на agreed v3 режим после совместимости monitoring; не выводить community и не советовать менять её в отчёте открытым текстом.

**P/N/U и edge.** P: v2c configured universal при approved /28; N: only approved collectors; U: unknown ACL binding. FP — транзитная ACL принята за management; FN — второй listener/IPv6/другая VRF. Trap receiver UDP/162 не равен inbound query listener UDP/161.

**Приёмка.** Local-plane resolver, all bindings, secret redaction tests; FW-LOGGING/FW-ANY-ANY связываются только при той же management scope. Unsupported SNMP ACL не подставляется any для finding.

### NEW-24 / C / FW-NO-ROUTE-CONTROL-FLOW — нет применимого маршрута к точному адресу

**Смысл.** Проверить заданные пользователем контрольные потоки и объяснить, почему network calculation не имеет выходного пути. Нельзя проверять «все адреса правила» одним lookup network prefix.

**Входы.** Exact query destination/source, family, ingress/VRF, coherent full routing snapshot, connected/interface state, PBR/route lookup semantics, time window и NAT stage если влияет на lookup. Capability routing_snapshot/forwarding resolver. Static configuration list не обязательно полная active RIB/FIB; определить claim layer явно.

**Алгоритм.** Выполнить platform lookup: applied PBR/VRF selection, longest-prefix match, next-hop recursive resolution и eligibility. Complete supported lookup возвращает no applicable route => violation для контрольного ожидания permitted flow. Blackhole/reject route — маршрут есть, но outcome block: другой subtype. ECMP и unresolved next-hop не равны route absence.

**Severity/evidence/remediation.** Medium availability expectation, high critical control flow; network failure не называть vulnerability. Query ID, device/VRF, exact tuple, source snapshot hashes/time, lookup trace, required expectation. Action — проверить маршрут/VRF/next-hop либо входные данные; service health не утверждать.

**P/N/U.** P: full empty eligible table для exact target без default; N: valid default route; U: partial RIB/PBR unsupported/downstream missing. FP — wrong VRF/NAT phase, FN — считать installed route working without neighbor. IPv6, connected routes, discard, ECMP, default and recursive loop обязательны.

**Приёмка.** Полные routing input contracts, query registry и negative default-route test. Ограниченность query set видна в отчёте: отсутствие findings не доказывает маршрутизацию всей сети. FW-* policy checks не заменяют routing.

### NEW-25 / C / FW-NAT-PROTECTED-SERVICE-PUBLICATION — запрещённая публикация через NAT

**Смысл.** Выявить скрытое внешнее намерение публикации защищаемого сервиса и объяснить translation plus policy, включая несовпадающие внешние/внутренние порты.

**Входы.** Verified version-specific NAT pipeline, active bindings/order, match and transform relations source/destination/port, pre/post tuple, policy stage, zone/VRF, protected inventory и prohibited publication profile. Capability nat_pipeline/full_match/binding_scope; no generic NAT assumption по имени vendor. Сначала поддержанный static DNAT с точной relation, затем pools/twice NAT/hairpin.

**Алгоритм.** Представить translation как relation `T(pre,post)`, а не простую map без domain. Найти pre tuples из forbidden zone, для которых selected T ведёт к protected service и applicable policy даёт allow на документированной stage. Разделить «NAT намерение публикации» и «NAT+policy разрешение». Network reachable subtype требует отдельно route/return/state; endpoint service operation не следует даже из него. Source NAT обычного egress не превращать в inbound publication.

**Severity/evidence/remediation.** High critical prohibited publication; medium reviewintent. NAT rule ID, firewall rule IDs, external/internal addresses and ports, translation stage, winner, profile clause, limitations. Предложить убрать/сузить DNAT или policy sources, проверить approved reverse-proxy/VPN вариант. Изменение NAT может затронуть другие flows: обязательный preview impact.

**P/N/U/edge.** P для NAT+policy permission: external tcp/15432→protected DB tcp/5432 с доказанным allow; N этого же слоя: source-only PAT outbound либо доказанный deny на applicable stage; U: unknown NAT order/conditional rule. Deny не отменяет отдельную находку слоя NAT intent, если baseline запрещает уже саму настройку публикации: её label и scope сохраняются отдельно. Принятое исключение добавляет disposition к технической находке, не делает её N. FP — перепутанные pre/post зоны, FN — port translation, alternate mappings и HA context. Identity NAT, overlapping pools, twice NAT, hairpin и reverse initiation semantics обязательны в последующих capability strata.

**Приёмка.** NAT relation and selection, independently verified pipeline fixtures, exact witnesses и all dependent source hashes. NEW-01/02/08 связываются по protected target; unknown NAT блокирует эффективный вывод, не скрывает честный intent finding. Источники семантики: [Cisco NAT order](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/firewall/asa-firewall-cli/nat-overview.html) и [NAT+ACL example](https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/115904-asa-config-dmz-00.html); перенос на новые NGFW только после их собственных подтверждённых документов.

## 6. Каталог профилей, порогов и исключений

### Предлагаемая структура профиля

`OrganizationPolicyProfile` содержит ID/version/hash, effective_from, author/approval reference, timezone, scope selector, provenance и completeness mode. Профиль хранится неизменяемыми версиями; rerun старого снимка с новым профилем создаёт новый evaluation, а не исправляет историю.

| Профиль | Поля и правила | Проверки |
|---|---|---|
| Management | Admin targets/services, allowed sources по site/VRF, local/transit distinction, jump-hosts, trust categories | NEW-01/23 |
| Protected services | Asset IDs, DB/critical services, owner, approved callers, inventory freshness, NAT stage | NEW-02/25 |
| Forbidden services | Protocol/application/port heuristic distinction, allowed context, scoped exceptions | NEW-03 |
| Breadth | Per-family/per-protocol cardinality, contiguous-span advisory, approved sets, intent/effective mode | NEW-04…06 |
| Egress | Trusted/untrusted mapping, gateways, universal-TCP versus universal-IP, required services | NEW-07 |
| Segmentation | Explicit allow/deny tuples, closed/open-world mode, precedence, membership, service/time clauses | NEW-08 |
| Object hygiene | Namespaces, reserved/system objects, full reference kinds, import/template roots, merge approval | NEW-12…16 |
| Lifecycle | Temporary marker semantics, deadline zone, maximum duration, emergency review, owner/basis requirements | NEW-17…19 |
| Usage | Observation duration, business cycle, resets, HA peers, stable identity, seasonal/DR exceptions | NEW-20 |
| Observability | Required event categories, logging mode/receiver/transport, approved time sources, inherited config | FW-LOGGING/NEW-21/22 |
| Control flows | Query ID, expected policy/network outcome, criticality, query frequency, required coherent inputs | NEW-24/25 и NET |

Первый пакет может включать объяснимые примеры профилей «только инвентаризация», «локальная policy hygiene», «утверждённая сегментация», «protected management», «operational review». Они являются шаблонами, а не автоматически обязательной политикой. Демо-порог 100 ports или 90 days нельзя показывать как отраслевое требование. Threshold должен иметь unit, scope и источник утверждения; negative/zero/неограниченные значения валидируются явно. Для IPv6 предпочтительно approved prefix/set matching; огромное число адресов обычного /64 не означает миллиарды реально доступных серверов.

### Исключения и remediation lifecycle

Exception содержит отдельный ID, check IDs, exact entity/scope predicate, основание, owner, approved_by/reference, begins_at/expires_at, review_at и immutable revision. Allow exception применяется только к заявленному subspace: нельзя исключением на DB/5432 suppress весь any-any. Исключение не убирает technical violation evidence, а добавляет disposition `accepted_until`; summary разделяет open и accepted. После истечения исключения автоматически восстанавливается открытое действие; техническая находка и её эталонная метка сохраняются непрерывно. Если entity mapping между ревизиями неоднозначен, exception не переносится молча.

Manual annotation («исправили») отличается от verified resolution: закрытие по новой ревизии возможно только при той же сопоставимой области, sufficient capabilities и unchanged check/profile semantics. Если следующая ревизия unsupported или профиль ослаблен, статус «не подтверждено», а не «устранено». Suppressed parser errors тоже не становятся complete. Comment и remediation ticket хранятся с автором/временем, но не требуют отправки внешних сообщений из приложения.

Изменения по предложению check выпускаются как draft: предполагаемые rules/objects, targeted problem, expected outcome, symbolic decision delta, unknown scope, rollback reference. Для broadness cleanup нужны положительные business control flows, для segmentation — положительные и запретные. Нельзя одновременно выводить «объединить правила» и «сузить доступ» без объяснения разных целей; decision diff должен показать, изменилось ли разрешённое множество.

## 7. Измеримое достижение качества 99,9%

### Что именно измеряется

Цель: precision и recall не ниже 0,999 на заранее объявленном поддержанном scope для конкретного check/adapter/version/profile. Это целевой gate, не достигнутый показатель документа. `precision=TP/(TP+FP)`, `recall=TP/(TP+FN)`. Общая accuracy по огромному числу отрицательных tuples непригодна: может скрыть пропуск всех редких нарушений. Для rule relations единица оценки — отношение/область по паспорту, для broadness — правило/family/protocol, для object checks — объект/reference/SCC, для counters — правило/окно/peer set, для routing — контрольный query. Их denominators нельзя складывать без объявления метрики.

Нужны два отчёта: quality среди definitive решений и end-to-end detection всех ground-truth positives внутри supported scope. Abstention на положительном кейсе снижает end-to-end recall/coverage, поэтому нельзя получить «99,9%» оставив все сложные cases unknown. Отдельно считать abstention rate, support coverage, false-complete rate (недоказанная полнота), witness validity и evidence traceability. Unsupported cases не включать скрыто в denominator; вести полный список и частоту таких входов в реальном парке.

Глобальное average не заменяет страты: отдельно каждой платформе/версии, v4/v6, ranges/groups, schedule/app conditions, binding, NAT stage, object graph и operational windows. Каталог может получить общий gate только если все обязательные страты прошли; провал редкой critical страты нельзя компенсировать простыми any-any cases. Для intent checks и effective checks independent labels, чтобы правильный finding о настройке не засчитывался как правильный вывод о фактическом пути.

### Корпус и независимость

1. Human-authored fixtures по каждому паспорту: P/N/U/not-applicable, edge и каждое declared limitation. Два review автора разметки с resolution disagreements; спорный business intent не превращать в ground truth без profile.
2. Малое конечное пространство пакетов с независимым exhaustive oracle: например несколько source/destination IP, protocols, port values и time slots. Oracle перечисляет tuples напрямую и применяет policy, не вызывает `RuleMatch.covers` или solver under test.
3. Hypothesis generator для interval normalization, set operations, ordering, object graphs. Metamorphic properties: splitting/merging interval не меняет множество; добавление disabled rule не меняет decision; renaming object preserving identity/values не меняет matcher; union shadow invariant к разбиению covering rules.
4. Golden versioned vendor cases по подтверждённым форматам, source mappings и namespaces. Исходные конфигурации anonymized/synthetic; privacy-preserving transformation не должна менять semantics. Сохранить paired original oracle только в authorized test environment, не в public fixtures.
5. Blind holdout: отдельные authors, unseen configurations и edge categories; не корректировать thresholds после просмотра holdout. Failures возвращаются в development corpus, новый holdout создаётся заново, предыдущий результат остаётся в журнале.
6. Differential validation при доступном независимом vendor emulator/lab или другом formal engine, с точным совпадением semantics. Различие результатов разбирается, не решается majority vote. Реальные probes проверяют наблюдение пути лишь в согласованном окне и не устанавливают универсальную truth для configuration.

### Статистический gate

Одна точечная оценка 99,9% на тысяче примеров не доказывает нижнюю доверительную границу 99,9%. При независимых Bernoulli испытаниях и нуле ошибок односторонняя exact 95% нижняя граница success probability равна `0.05^(1/n)`; для превышения 0,999 нужно как минимум 2995 соответствующих наблюдений. Это вывод из биномиальной модели, не гарантия для любой сети. Для precision и recall нужны соответствующие независимые denominators; тысячи correlated packets из одной configuration не дают тысячи independent cases. Если заявляется joint confidence либо много strata, требуется поправка multiplicity/объявленный family confidence и больший sample size.

При ненулевых ошибках вычислять exact bounds, а не правило «допустима одна ошибка на тысячу». При отсутствии positive labels recall не определён; при отсутствии emitted positives precision не определён. Детерминированное доказательство алгебры усиливает correctness supported model, но не доказывает parser accuracy или полноту business inventory. Поэтому весь pipeline оценивается отдельно: source→normalized model, model→check decision, decision→evidence/UI/export.

99,9% следует реализовать ступенчато: prototype correctness (small oracle), pilot quality на утверждённых scope, measured release gate на независимом corpus, field monitoring evidence disagreements. До gate UI указывает experimental/limited, а не численную гарантию. Рекомендуется сначала target 100% witness validity и zero false-complete на corpus, затем precision/recall; эти строгие invariants не заменяют statistical metric.

## 8. Декомпозиция реализации и завершение этапов

| Задача | Конкретный результат | Зависимости | Приёмка |
|---|---|---|---|
| CHECK-ARCH-01 | Versioned registry: check ID, claim layer, requirements, units, severity rules | P01/P04 | Все 32 паспорта имеют declarations; disabled/unsupported отчёт воспроизводим |
| CHECK-ARCH-02 | Scope/dependency resolver, field completeness, localized limitations | CHECK-ARCH-01, adapters | Unknown не any; неполный export не complete; unaffected scopes могут оцениваться |
| CHECK-ARCH-03 | Set algebra intersection/difference/union/witness/provenance | Domain matcher | Exhaustive oracle, Hypothesis identities, no axis-union enlargement |
| CHECK-ARCH-04 | Profile/exception validation, immutable versions and provenance | Organization context | Old run повторим, expiration корректна, ambiguous entity mapping не переносит exception |
| CHECK-A-01 | NEW-03…06 breadth/service checks | ARCH-02/04 | Все P/N/U/edge, exact counts и context |
| CHECK-A-02 | NEW-09…11 relation engine | ARCH-03/full policy | Partial/one-rule/union shadow различаются, counterfactual outcome доказуем |
| CHECK-A-03 | Typed graph + NEW-12…16 | Object adapters | NAT/VPN/reference scope явен, циклы и empty не unresolved |
| CHECK-B-01 | NEW-01/02/07/08 profile-based intent/effective | Inventory/matrix + ARCH | Profile clauses и witnesses; port не asset; public IP не trust |
| CHECK-B-02 | NEW-17…19 lifecycle metadata | Typed metadata/time | Frozen-clock and absence/unknown fixtures; source/manual fields различимы |
| CHECK-B-03 | NEW-21…23 device observability/management | Logging/NTP/SNMP adapters | Known config absence отдельно от operational claims; secrets redacted |
| CHECK-C-01 | Counters windows and NEW-20 | Operational inputs/identity | Resets/HA/gaps/version semantics; ноль без окна не unused |
| CHECK-C-02 | Control flows and NEW-24 | NET routing contracts | Exact address/VRF/family, full table gate, default/PBR/ECMP cases |
| CHECK-C-03 | NAT relation and NEW-25 | Verified adapter NET/NAT | Correct pre/post stage, independent witnesses, no generic fallback |
| CHECK-Q-01 | Independent labeled corpus/holdout, metric report | Each delivered slice | Precision/recall/coverage/CI по declared strata; недостигнутый gate явно указан |
| CHECK-UX-01 | Problem correlation and evidence cards Qt/HTML/JSON | U01…U05 | Individual IDs не потеряны; summary counts consistent; claim layer виден |

Разделение A/B/C из v1 сохранено: A — NEW-03…06,09…16; B — NEW-01/02/07/08/17…19/21…23; C — NEW-20/24/25. Сначала внедряются контракты, потом checks на одной доказанной платформе, затем capability расширяется независимо. Ни generic parser support, ни checkbox «включено» не означают, что конкретная проверка исполнена полностью.

Артефакт готов к реализации, когда каждому check назначены owner, supported adapter/version scope, corpus manifest и profile decisions. Выпуск готов только после actual implementation и проверки критериев соответствующего среза. Данный документ не считает эти условия выполненными.

## 9. Открытые решения, которые нельзя заполнить догадками

Потребуются утверждённые trust/zone mappings, DB и management inventory, matrix completeness mode, lifecycle timezone и deadlines, owner registry semantics, approved log/NTP/SNMP settings, breadth thresholds по family/service, business cycle counters, supported NAT export/version и coherent routing inputs. Эти решения не блокируют разработку generic контрактов и synthetic corpus, но ограничивают actionable business verdicts.

Для NEW-09…11 нужно выбрать initial exact representation и лимиты на измеренном объёме; доступ к полному исследованию Al-Shaer/Hamed остаётся исследовательским действием до реализации, а не скрыто выполненным чтением. Для 99,9% требуется согласовать единицы метрик, confidence level, required strata, coverage floor, стоимость FN/FP и размер независимого корпуса. Без этих решений число 99,9% остаётся целью, а не характеристикой продукта.
