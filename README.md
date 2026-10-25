# Firewall Compliance

Локальная Windows-ориентированная система анализа экспортированных конфигураций сетевого оборудования и межсетевых экранов.

## Статус

Добавлены 12 проверок управления устройствами (каталог 1.2.0) для ограниченных
форматов HP/Aruba и Comware: Telnet/HTTP, источники администрирования, SNMP,
syslog, NTP, тайм-ауты и баннер. Профиль настраивается в «Настройки → Правила»
или через CLI `--management-profile`; полнота импорта подтверждается отдельно.
Для этих адаптеров доступно 19 проверок, включая прежние семь firewall checks.
Грамматика, ограничения и пример запуска: [MANAGEMENT_ASSURANCE](specifications/MANAGEMENT_ASSURANCE.md).

Реализованы каноническая модель, ревизии устройства, ограниченные экспериментальные адаптеры Cisco ASA 9.16, HP/Aruba AOS-Switch/AOS-CX и HP/H3C Comware, а также семь проверок Firewall Assurance. CLI и desktop выбирают адаптер по содержимому файла через общий каталог. Исходный прототип сохранён отдельно как поведенческий ориентир. Границы анализа и поддержки платформ описаны в [SUPPORTED_PLATFORMS.md](specifications/SUPPORTED_PLATFORMS.md).

HP/Aruba и Comware предоставляют ограниченный IPv4 ACL/management-инвентарь с source mapping и диагностикой. `ip authorized-managers`, control-plane ACL и SNMP ACL относятся к управлению устройством; они не подтверждают транзитный доступ. ArubaOS controller session ACL/user-role, включая два предоставленных controller-экспорта (.14/.15), не поддержаны. Juniper в текущем этапе не подключён. Замаскированные значения `ipN`/`ip#N` остаются unknown: приложение не подставляет случайные адреса.

Шаг 8.0 подготовил достоверный контракт ревизии 2.0.0: глубокий snapshot, IP интерфейсов без потери хостовой части, явные полнота и наблюдение. Импорт маршрутов/интерфейсов реализован отдельным сетевым adapter; итоговая достижимость ещё не вычисляется. Файловое mtime не считается временем устройства. Совместимость старого JSON описана в specifications/SCHEMA_MIGRATIONS.md.

Network Assurance содержит `select_route`, предварительный `analyze_reachability`, сетевой импорт ASA 9.16 и локальные `evaluate_policy`/`evaluate_interface`/`analyze_device_decisions`. Application `analyze_imported_device` проверяет mapping label/interface по документам импорта. `bind_forwarding_context` связывает forwarding-факты с ревизией; `evaluate_forwarding_policy` объясняет условную цепочку ingress/global/outbound ACL и security-level при доказанном отсутствии NAT/PBR/exceptions. Egress задан условно вызывающей стороной. Результат 0.1.0 хранит policy_status отдельно от верхнего unknown/not_enough_evidence, context snapshot, trace и причины; чтение/копирование повторяет расчёт. Полный путь, effective NAT adapter, operational state, сетевой CLI и итоговые reachable/blocked не реализованы. Binding/evaluator требуют отдельного UI wiring; прежние API уже подключены отдельными сценариями.

Отдельный `CiscoAsaForwardingParser` получает `ForwardingParseRequest` с байтами и явными метаданными. Он формирует контекст интерфейсов, ACL и in/out/global bindings с диагностикой и source mapping, а не решение о прохождении пакета. Настройки не получают defaults; неполные выдержки не доказывают отсутствие NAT/PBR. Конфигурационный вход не подтверждает effective NAT. Контракт и границы: `specifications/FORWARDING_CONTEXT.md`; существующий CLI этим API не расширяется.

Добавлен backend карты заданных условий ACL для HP/Aruba и Comware:
`build_acl_map`, базовые фильтры и JSON/DOT. Каждое правило сохраняет действие,
условия, enabled, диагностику и источник. Карта не доказывает effective permissions
или достижимость. Контракт для подключения UI: [ACL_MAP.md](specifications/ACL_MAP.md).
Qt-карта и SQLite для этого результата ещё не подключены. Новое развитие Cisco
ASA/IOS/XE отложено в backlog; существующие реализации сохраняются.

## Требования

- Windows 10 или Windows 11 x64.
- Python 3.12 или новее.
- `uv` для управления окружением и зависимостями.

## Локальная установка для разработки

```powershell
uv sync --all-groups
```

## Проверки

```powershell
uv run ruff format --check src tests scripts
uv run ruff check src tests scripts
uv run mypy src
uv run pytest
```

## Локальный анализ

```powershell
uv run firewall-compliance analyze tests/fixtures/assurance/policy_quality.cfg
```

Команда выводит JSON с findings, Evidence, версиями и ограничениями анализа. Проверяются any-any, дубликаты, полное затенение одним правилом, кандидаты на объединение, логирование, описания и отключённые правила.

Логирование требуется для активных разрешений, описания - для активных правил. Эти требования можно отключить:

```powershell
uv run firewall-compliance analyze tests/fixtures/assurance/policy_quality.cfg --no-require-logging --no-require-comments
```

`partial` означает наличие непроверенных условий, `complete` - выполнение проверки в заданной границе. Отсутствие findings не является заключением о безопасности. Any-any относится к настроенным условиям правила для указанного сервиса; Network Assurance и влияние NAT ещё не вычисляются. Ошибка распознавания/парсинга возвращает JSON диагностику и код выхода 2; код 0 означает сформированный результат, включая partial и findings.

## Локальный desktop UI

Основной интерфейс — **PySide6 / Qt** с тёмной голубой/фиолетовой темой.
Cloud.ru настраивается в «Настройки → Интеграции → Cloud.ru» на отдельных вкладках
VMware, Advanced и Evolution.
Сбор ВМ, Edge Gateway, сетей и выбранных сетевых конфигураций запускается отдельно
в «Операции → Облачный сбор → Новый сбор». Поля подключения, API и границы поддержки описаны в
[руководстве Cloud.ru VMware](specifications/CLOUD_RU_VMWARE.md) и
[руководстве Advanced/Evolution](specifications/CLOUD_RU_PUBLIC.md).
Создайте проект, выберите папку конфигураций, проверьте предложенные устройства и
нажмите «Запустить проверку файлов» в «Операции → Файлы и проверки». Получите сводку, находки с доказательствами и общий
**HTML/JSON**. Ошибки и частичная поддержка отдельных файлов включаются в результат.

Из исходников: `Start-Desktop.cmd` или
`.\.venv\Scripts\python.exe -m firewall_compliance.interfaces.desktop`.
Portable: распакуйте `dist\FirewallCompliance-windows-x64.zip` и откройте `dist\FirewallCompliance\FirewallCompliance.exe`; переносите всю папку
с `_internal`. Для portable Python/uv не нужны. Сборка из исходников:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1
```

Проекты, история, настройки и пользовательские решения сохраняются в
`%LOCALAPPDATA%\FirewallCompliance\projects.sqlite3`. Полные конфигурации не
копируются; БД содержит нормализованный инвентарь и ограниченные выдержки.
После перезапуска для полного исходника/повторных проверок требуется файл с тем
же SHA-256. Иной hash создаёт новый анализ. БД и отчёты могут содержать чувствительные данные.

Поддержка оборудования и ограничения ядра прежние: ASA, HP/Aruba и Comware имеют
ограниченные адаптеры; Juniper и ArubaOS controllers не подключены. Дополнительные
ASA network/forwarding инструменты находятся в «Расширенном анализе»; окончательная
достижимость не вычисляется. Их документы/результаты живут в памяти и экспортируются отдельно.

Первый synthetic пример: `tests/fixtures/assurance/policy_quality.cfg` — семь checks
и 14 findings при стандартных настройках. Пошаговая работа:
[USER_GUIDE](specifications/USER_GUIDE.md), [сетевой гайд](specifications/NETWORK_UI_GUIDE.md).
Реализация: [DESKTOP_UI](specifications/DESKTOP_UI.md).
Подтверждённые проверки сборки и ограничения чистой Windows-матрицы:
[CURRENT_STATE](specifications/CURRENT_STATE.md).

## Документация

Требования, архитектурные решения и текущий статус находятся в каталоге `specifications/`.
Пользователю следует начать с [USER_GUIDE.md](specifications/USER_GUIDE.md),
разработчику — с [SPECIFICATION_INDEX.md](specifications/SPECIFICATION_INDEX.md).

Для работы над UI: `specifications/UI_BACKEND_INTEGRATION.md` содержит точки подключения, пример реального запуска, версии результатов и ограничения. Архитектура описывает текущие модули отдельно от планируемых. Оригиналы предоставленных и частично обезличенных конфигураций не копируются в проект или тестовые fixtures. Наличие такого файла не является обещанием полной поддержки семейства; контрактные проверки используют отдельно подготовленные synthetic данные.


