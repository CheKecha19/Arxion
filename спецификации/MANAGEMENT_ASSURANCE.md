# Проверки управления устройствами

Реализовано 19.10.2026. Каталог с проверками управления: 1.2.0;
management parser и каждая MGMT-проверка: 1.0.0.
Это ограниченный анализ **настроенной конфигурации**, а не проверка доступности,
доставки журналов, синхронизации времени или успешного входа.

## Запуск

Desktop: «Настройки → Правила → Требования к управлению устройствами».
Укажите сети администраторов/SNMP, серверы syslog/NTP, тайм-аут и обязательные
настройки. Списки разделяются запятыми; пустое поле означает, что требования
не заданы, `[]` — что ни одно значение не разрешено. Сети задаются строгими CIDR:
`192.0.2.0/24`, адрес отдельного узла — `192.0.2.10/32`.
Существующий явный выбор семи старых проверок сохраняется: включите новые
MGMT-проверки в списке. В новых проектах они включены.

Флажок полноты относится только к следующему импорту всех выбранных файлов и
сбрасывается после запуска. При смешанном наборе полных экспортов и фрагментов
запускайте отдельные импорты. Полнота сохраняется в снимке и не меняется при
повторной проверке. Изменение профиля не меняет старые отчёты.

CLI:

```powershell
uv run firewall-compliance analyze switch.cfg --management-profile specifications/management-profile.example.json --complete-config
```

`--complete-config` — явное утверждение оператора о полноте экспорта. Без него
невозможно доказать отсутствие настройки. Формат файла или строка `return`
сами по себе не доказывают полноту. Профиль сохраняется в отчёте вместе с результатом.
Без файла профиля используются требования baseline, но разрешённые списки неизвестны.

## Каталог

| ID | Проверяемое условие |
|---|---|
| MGMT-TELNET | Явно включён Telnet-сервер |
| MGMT-HTTP | Явно включено управление по HTTP |
| MGMT-ADMIN-SOURCES | Настроенное множество источников управления выходит за разрешённое объединение сетей |
| MGMT-SNMP-LEGACY | Явно разрешены SNMPv1/v2c |
| MGMT-SNMP-WRITE | Настроен write-доступ через community, запрещённый профилем |
| MGMT-SNMP-SOURCES | Настроенные IPv4-источники SNMP выходят за разрешённое объединение сетей |
| MGMT-SYSLOG-MISSING | В полном экспорте нет поддержанной настройки внешнего syslog |
| MGMT-SYSLOG-UNAPPROVED | Настроен получатель syslog вне утверждённого списка |
| MGMT-NTP-MISSING | В полном экспорте нет поддержанной настройки источника NTP |
| MGMT-NTP-UNAPPROVED | Настроен источник NTP вне утверждённого списка |
| MGMT-IDLE-TIMEOUT | Явный тайм-аут равен нулю или превышает предел профиля |
| MGMT-BANNER | В полном экспорте нет баннера входа либо явно задан пустой баннер |

По умолчанию write запрещён, syslog/NTP/баннер обязательны, предел тайм-аута —
900 секунд. Это параметры baseline продукта, а не утверждение о соответствии
конкретному внешнему стандарту. Проверяется наличие текста баннера, не его
юридическая корректность. SNMPv3 RBAC, views и права пользователей не реализованы.

## Поддержанная грамматика и ограничения

Поддержка экспериментальная, проверена на synthetic-тестах. Семейство определяет
существующий каталог адаптеров; значения по умолчанию ОС не подставляются.
Полная поддержка любой версии семейства не заявляется.

| Область | AOS-Switch | Comware | AOS-CX |
|---|---|---|---|
| Telnet | `[no] telnet-server` | `[undo] telnet server enable` | unknown |
| HTTP | `[no] web-management plaintext` | `[undo] ip http enable` | unknown |
| Администраторы | `ip authorized-managers IPv4 [mask] [access manager/operator] [access-method …]` | inbound basic IPv4 ACL на `user-interface vty` / `line vty` | unknown |
| SNMP версии | community и `snmpv3 only` | `snmp-agent sys-info version v1/v2c/v3/all` | `[no] snmp-server snmpv3-only` |
| SNMP write | явный restricted/unrestricted у community | `snmp-agent community read/write … [acl N]` | unknown |
| Источники SNMP | authorized-managers с методом snmp/all | basic IPv4 ACL у community; без ACL — явно неограниченное множество IPv4 на уровне community при полном экспорте | unknown |
| Syslog | `logging IP/DNS` | `info-center loghost IP/DNS` | `logging IP/DNS` |
| NTP | `ntp server[-name] IP/DNS [iburst]` | `ntp-service unicast-server IP/DNS` | `ntp server IP/DNS [iburst]` |
| Тайм-аут | `console idle-timeout SECONDS` | `idle-timeout MINUTES [SECONDS]` внутри административной линии | `session-timeout MINUTES` |
| Баннер | `banner motd/exec DELIMITER…DELIMITER` | `header login DELIMITER…DELIMITER` | `banner motd/exec DELIMITER…DELIMITER` |

Баннеры поддерживают однобайтовый разделитель и несколько строк; содержимое
пропускается при разборе команд. Другие header/banner формы консервативно
останавливают дальнейший разбор, чтобы текст не стал командами.

Comware ACL: числовой basic ACL 2000–2999, явный sequence, permit/deny, source
IPv4 с непрерывной wildcard-маской либо any. Учитываются порядок и вычитание
ранних правил. Нужны полный экспорт и явное покрытие всего IPv4-пространства:
действие по умолчанию не предполагается. Budget — 4096 фрагментов.
Расписания, расширенные/named ACL, неизвестный порядок, неразрешённые ссылки,
IPv6 ACL, нестандартные суффиксы и другие ограничения дают partial.

Разрешение в VTY/community/authorized-managers означает настройку этой области,
а не доказанный доступ через все интерфейсы и межсетевые экраны. Без явных
ограничений источников по умолчанию не предполагается ни allow all, ни deny all.
Известный адрес вне профиля сопровождается конкретным адресом-свидетелем.

Неизвестная релевантная команда или противоречие блокирует окончательный вывод
по соответствующей области. Например, дополнительные опции syslog, NTP, выключение
подсистемы, SNMPv3-права и дополнительные ACL не игнорируются как безопасные.
При SNMPv3-only community write не объявляется работающим write-доступом.
Требования к IPv4 и IPv6 не смешиваются; серверы сравниваются как нормализованные
IP/DNS-значения, без DNS-запросов и без приравнивания имени к текущему IP.

## Данные и совместимость

`ParseResult.management` содержит нормализованные факты, источник, полноту и
диагностику. Без данных управления поле не сериализуется, поэтому старые
ASA/нейтральные JSON-эталоны сохраняются. Старые JSON читаются с management=None.
`FirewallAssuranceResult.management_profile` добавляется при запуске MGMT-проверок.
SQLite хранит эти дополнительные поля в существующих JSON payload; миграция SQL не нужна.
Старые версии приложения с extra=forbid не обязаны читать новые MGMT payload.

Каждая находка содержит строки-источники, нормализованное значение, профиль и
рекомендацию. Community strings, пароли и текст баннера не входят в management
inventory или findings. Для MGMT-находок сырые выдержки не сохраняются в SQLite;
ручной просмотр подключённого оригинала остаётся доступен пользователю.

## Основания синтаксиса

- [AOS-S: SNMPv3 only](https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/MCG/WC/content/common%20files/snm-acc-swi.htm)
- [AOS-S: примеры NTP и тайм-аутов](https://arubanetworking.hpe.com/techdocs/hpe-central/content/wired-switching/quick-start-onboarding-standalone-aos-s-switches.html)
- [AOS-S: единицы тайм-аута](https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/IPV6/WB/content/common%20files/vie-cur-inb-out-tel-con.htm)
- [AOS-CX: SNMP/MIB 10.11](https://www.arubanetworks.com/techdocs/AOS-CX/10.11/PDF/snmp_mib.pdf)
- [AOS-CX: Security Guide 10.07](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/PDF/5200-7884.pdf)
- [Comware: управление сессиями](https://www.h3c.com/en/d_201905/1188000_294551_0.htm)
- [Comware: ACL](https://www.h3c.com/en/d_202106/1419044_294551_0.htm)

Автоматическая проверка: `tests/integration/test_management_assurance.py` и
`tests/integration/test_management_settings.py`, включая 12 positive/negative
пар, неполноту, независимый Hypothesis oracle для объединения сетей, Qt,
CLI, SQLite, повторный анализ и отсутствие community strings в сохраняемых данных.
