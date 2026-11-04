# Собственные synthetic ACL HP/Aruba

Эти файлы созданы для контрактных тестов ограниченного `HpArubaParser`. Это не копии внешних
конфигураций, не данные заказчика, не аппаратные exports и не проверенные команды развёртывания.
Модель J0000A и версии в headers условны; fixtures не доказывают промышленную поддержку.
Адреса принадлежат TEST-NET. `ip17`, `ip#18`, `ip#23` и `ip#9` — намеренно неразрешённые
placeholder-объекты. Parser не заменяет их случайными адресами или `any`.

`aos_switch.cfg`: named standard/extended и numbered ACL, management authorized-managers,
несколько VLAN/портовых in/out/routed-in привязок, неподдержанный `established`.
`aos_cx.cfg`: named IPv4 ACL, routed-out и портовая in привязки, control-plane policy,
source-port и ICMP-type условия, для которых канонический Service недостаточен.

Management записи отделены policy/zone от transit ACL. Их destination и service/effective
match остаются unknown, а не превращаются в универсальное разрешение трафика через switch.
Полнота firewall, NAT, topology, hardware enforcement и operational state не доказываются.

Официальные первичные источники, сверенные при реализации:

- [Authorized managers AOS-S](https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/ASG/KB/content/asg%20kb/cnf-ip-aut-man-swi-cli.htm): отдельное управление устройством, privilege/access-method.
- [Numbered extended ACL AOS-S](https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/ASG/KB/content/asg%20kb/cre-add-ext-num-acl.htm): правила ACL, wildcard-маски и последовательность.
- [IPv4 ACL AOS-CX](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/HTML/acls_4100i-6000-6100/Content/Chp_ACLs/ACLs_cmds/acc-lis-ip.htm): CIDR, протоколы, ports, дополнительные условия.
- [VLAN routed binding AOS-CX](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/acls_8400/Content/Chp_ACLs/ACLs_cmds/app-acc-lis-to-int-vla.htm): отдельная application scope, не вычисленный путь.

Пределы adapter фиксируются предупреждениями и `UnsupportedConstruct`, неизвестность остаётся
в исходном `ParseResult`. ArubaOS controller session ACL/user-role распознаются отдельно,
но возвращают явный `ARUBAOS_CONTROLLER_UNSUPPORTED`; controller evaluator здесь отсутствует.
