# Оценка платформ для первого production-quality парсера

Дата оценки: 2026-10-09

## Правило оценки

Кандидат допускается к выбору, если документирован целевой формат, законно доступны минимум три сценария для создания обезличенных fixtures, а сценарии позволяют проверить правила, адреса, сервисы, блокирующее действие и диагностику неподдержанных конструкций. Наличие локальных fixture-файлов является обязательным quality gate до начала реализации адаптера, но не требуется для самого решения о приоритете формата.

| Кандидат | Данные / 40 | Формат / 20 | Достижимость / 20 | Спрос / 15 | Legacy / 5 | Итого | Решение |
|---|---:|---:|---:|---:|---:|---:|---|
| Cisco ASA 9.16 | 32 | 20 | 15 | 0 | 4 | 71 | Первый adapter реализован |
| Juniper Junos firewall filters | 28 | 18 | 12 | 0 | 3 | 61 | Резерв |
| HP Aruba AOS-CX 10.15 | 24 | 17 | 14 | 0 | 2 | 57 | Резерв |
| Huawei VRP ACL | 22 | 15 | 12 | 0 | 3 | 52 | Резерв |
| UserGate NGFW | 16 | 7 | 13 | 0 | 5 | 41 | Не выбран |

Баллы спроса равны нулю: на дату оценки нет подтверждённых интервью интеграторов или заказчиков. Это не отрицательная рыночная оценка, а отсутствие доказательств. Итог пересматривается при появлении таких данных.

## Доказательства по кандидатам

### Cisco ASA 9.16

- Целевой ввод: текстовый экспорт `show running-config`, содержащий `access-list`, `access-group`, `object network`, `object-group network`, `object service` и `object-group service`.
- Официальные источники: [Objects for Access Control](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/firewall/asa-916-firewall-config/access-objects.html), [Attribute-Based Access Control](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/firewall/asa-916-firewall-config/virtual-access-vm-attributes.html), [ASA 9.16 General Operations Guide](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config.pdf).
- Доступны открытые сценарии для правил permit/deny, объектов и групп, привязки ACL к интерфейсу, а также NAT. NAT служит тестом неподдержанной конструкции первой версии, а не частью первой реализации.
- Legacy содержит один обезличенный ACL fixture, но он не подтверждает синтаксис ASA 9.16 и используется только как ориентир общего ACL-поведения.

### Juniper Junos firewall filters

- Формат и порядок term хорошо документированы в [руководстве Juniper](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/task/firewall-filter-ocx-series-cli.html) и [guidelines](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-stateless-guidelines-for-configuring.html).
- В документации доступны сценарии accept, discard, reject, порядок term и привязка к интерфейсу.
- Нет локальных fixtures и подтверждённой границы между stateless firewall filters и полноценной firewall policy, поэтому кандидат остаётся резервным.

### Huawei VRP ACL

- Официальные сценарии ACL доступны в [документации Huawei](https://info.support.huawei.com/hedex/api/pages/EDOC1100331435/AEM10132/04/resources/dc/dc_cfg_ipsec_0159.html).
- Legacy поддерживает часть синтаксиса нумерованных и именованных ACL, но нет локального набора fixtures и зафиксированной версии VRP.
- До появления версии и набора выходных конфигураций кандидат не проходит порог воспроизводимости.

### HP Aruba AOS-CX 10.15

- Формат ACL, действия permit/deny, порядок ACE и применение ACL официально описаны в [AOS-CX ACL guide](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/acls_5420-6200/Content/Chp_ACLs/acc-con-lis-acl.htm) и [show access-list](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/acls_6300-6400-8100-8360/Content/Chp_ACLs/ACLs_cmds/sho-acc-lis.htm).
- Формат проще для первого среза, но legacy-реализация частична, а локальные fixtures отсутствуют.

### UserGate NGFW

- Официальная документация UserGate 7.x описывает [экспорт текстовой конфигурации](https://docs.usergate.com/eksport-i-import-konfiguracii-v-tekstovom-formate_2315.html) начиная с версии 7.5.0.
- Два legacy JSON fixture имеют контролируемое происхождение, однако их соответствие официальному экспортному формату и версии не доказано.
- Поэтому JSON нельзя объявлять production-форматом, а UserGate не выбирается до появления законного, версионированного набора реальных или специально созданных экспортов.

## Принятое ограниченное решение

Первым целевым форматом становится Cisco ASA 9.16 textual `show running-config` в границе ACL и объектов. Это выбор приоритета разработки, а не заявление о коммерческой поддержке Cisco ASA.

Quality gate закрыт 2026-10-09 в `TASK-005_CISCO_ASA_PARSER.md`:

1. Добавить минимум три локальных обезличенных fixture-сценария в каталог Cisco ASA.
2. Зафиксировать в manifest происхождение, SHA-256, версию, разрешённое использование и покрываемые конструкции каждого файла.
3. Подтвердить, что набор содержит permit, deny, IPv4 address/service objects, object groups, `access-group`, logging и один NAT-фрагмент как unsupported construct.
4. Утвердить ожидаемый source mapping и golden results для этих файлов.

Закрытие gate разрешило реализацию первого ограниченного adapter, но не является заявлением коммерческой поддержки Cisco ASA.
