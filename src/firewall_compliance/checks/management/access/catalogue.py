"""Management access checks."""

from firewall_compliance.domain.management import ManagementKind

CHECKS: dict[str, tuple[ManagementKind, str, str]] = {
    "MGMT-TELNET": (
        "telnet",
        "Включён Telnet для управления",
        "Отключите Telnet и используйте SSH.",
    ),
    "MGMT-HTTP": ("http", "Включён HTTP для управления", "Отключите HTTP и используйте HTTPS."),
    "MGMT-ADMIN-SOURCES": (
        "admin_sources",
        "Источники управления вне разрешённых сетей",
        "Ограничьте настроенные источники управления утверждёнными сетями.",
    ),
    "MGMT-IDLE-TIMEOUT": (
        "timeout",
        "Небезопасный тайм-аут административной сессии",
        "Задайте ненулевой тайм-аут в пределах профиля.",
    ),
    "MGMT-BANNER": (
        "banner",
        "Отсутствует требуемый баннер входа",
        "Настройте непустой баннер входа с утверждённым текстом.",
    ),
}
