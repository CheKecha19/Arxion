> История первоначального выбора платформ. Текущая поддержка — specifications/SUPPORTED_PLATFORMS.md; статус кандидата здесь не отменяет последующие реализации.

# Cisco ASA 9.16

Статус: quality gate закрыт для первого parser adapter.

Целевой формат: текстовый `show running-config` Cisco ASA 9.16. В первом срезе допустимы только строки `access-list`, `access-group`, `object network`, `object-group network`, `object service` и `object-group service`.

Разрешённые источники: официальные примеры Cisco ASA 9.16 и специально созданные на их основе обезличенные конфигурации. Первичные источники перечислены в `specifications/PLATFORM_EVALUATION.md`.

В `manifest.json` зафиксированы три локальных fixture, их SHA-256, версия, сценарии, происхождение и разрешённое использование. Все адреса относятся к диапазонам документации RFC 5737; данные заказчиков, учётные данные и реальные топологии отсутствуют.

Не входят в первый срез: NAT, IPv6, time-range, identity/user rules, FQDN, вложенные object groups и полный анализ маршрутизации.
