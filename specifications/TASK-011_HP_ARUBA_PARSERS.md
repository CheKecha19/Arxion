# TASK-011: HP/Aruba и Comware в реальном локальном импорте

Дата: 2026-10-10. Статус: Готово в ограниченной области.

## Цель

Получить достоверный ACL/management-инвентарь файлов HP/Aruba и Comware в текущем
desktop UI для подготовки демонстрации, без подключения legacy parser и вымышленных результатов.

## Контекст

PRODUCT_VISION, ARCHITECTURE, DEVELOPMENT_RULES, ROADMAP, SUPPORTED_PLATFORMS,
REQUIREMENT_STATUS FR-001/002/003/004/010/030/031, ADR-017. SR-005/006 сохраняются.
Первоначальное пожелание Juniper исключено пользователем после просмотра фактической папки.

## Область задачи

- HpArubaParser 0.1.0: AOS-Switch/AOS-CX, ограниченные IPv4 ACL, bindings,
  authorized-managers и отдельный control-plane scope.
- ComwareParser 0.1.0: IPv4 basic/advanced ACL, contiguous wildcard,
  destination-port eq/range, logging/comment, отдельное назначение SNMP ACL.
- Общая фабрика catalog.py для CLI/desktop. Существующие сессии, JSON и source preview.
- Понятный controller failure и ограничение сетевого экрана до ASA.
- Synthetic tests, оконная проверка, документация и read-only inventory всей внешней папки.

## Вне области задачи

- Juniper, ArubaOS controller session ACL/user-role evaluator, IPv6 и весь vendor config.
- Network Assurance/NAT/PBR/operational state для новых платформ.
- Коммерческая поддержка, аппаратная валидация или итоговый вердикт о безопасности.
- Механизм случайной замены данных в продукте; изменение исходных документов.

## Критерии приёмки

- Семейство определяется по содержимому, а не расширению, ID пользователя или отказу другого parser.
- Нормализованные правила содержат source mapping и ID соответствующей configuration.
- Management/SNMP/control-plane не превращаются в транзитные allow/any-any.
- Masked IP/ACL identifiers и неизвестные условия не получают ложного known состояния.
- Успешный импорт partial не скрывает ограничения checks; controller получает явный отказ.
- Результаты новых форматов открываются в UI и экспортируются исходной моделью.
- Сетевые ASA API не принимают новые vendor-базы через UI.

## Проверка

- Contract: 26 HP/Aruba и 12 Comware тестов.
- Integration: 6 tests/integration/test_multivendor_desktop.py, включая общий CLI catalog,
  original JSON roundtrip, IDs, source preview, повтор checks и явный controller failure.
- Полный pytest: 1208 passed. Ruff check/format: 143 файлов. Mypy: 60 source files.
- Оконный desktop_integration_smoke: synthetic AOS-Switch/AOS-CX/Comware импортируются
  через настоящую очередь/кнопки; показ правил, JSON и network guard проверены вместе
  с прежними ASA/network/repeat/diff сценариями и GC stress guard.
- Read-only проверка 79 masked TXT: 69 AOS-Switch и 1 AOS-CX partial, 7 Comware partial,
  2 controller failures, внутренних исключений нет. Сохранено 3139 нормализованных
  ACL/management records; это число инвентаря, а не число подтверждённых network decisions.
- Случайные синтетические адреса и masked ACL numbers подставлялись только в памяти
  для технической проверки по явному разрешению пользователя. Конкретные значения
  не сохранены; отношения оригинальных подсетей этой заменой не подтверждаются.

## Безопасность и обработка данных

Внешние оригиналы не копировались в проект/fixtures, не менялись и не печатались в outputs.
Тестовые конфигурации написаны отдельно. Локальный ignored `artifacts/local-parser-inventory`
содержит только имена файлов, семейства, счётчики и коды диагностики, без raw content,
учётных данных, hostname и адресов внутри конфигураций. Допустимая обработка реальных
конфигураций заказчика и коммерческий пилот остаются по SECURITY_BASELINE.

## Зависимости и риски

- Синтаксический импорт не заменяет подтверждение привязки и семантики оборудования.
- Экспериментальная область всегда сопровождается warning и partial checks.
- Маскирование номеров ACL под phone и адресов под ip скрывает исходный тип/отношения.
- Новые границы documented в SUPPORTED_PLATFORMS; controller support требует отдельной задачи.

## Запись о завершении

CLI/desktop используют общий каталог ASA, HP/Aruba и Comware. Juniper не подключён.
Обновлены пользовательские руководства, README, архитектура, текущий статус,
матрица требований, roadmap/backlog и ADR-017. Публичные схемы и версия приложения
не изменены; версии новых parsers 0.1.0. Нужные следующие задачи: расширение controller
формата и дальнейшие подтверждённые vendor-сценарии, без подстановки данных в приложении.
