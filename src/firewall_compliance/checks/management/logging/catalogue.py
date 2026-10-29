"""Management logging checks."""

from firewall_compliance.domain.management import ManagementKind

CHECKS: dict[str, tuple[ManagementKind, str, str]] = {
    "MGMT-SYSLOG-MISSING": (
        "syslog",
        "Не настроен внешний получатель журналов",
        "Настройте внешний syslog и проверьте доставку отдельно.",
    ),
    "MGMT-SYSLOG-UNAPPROVED": (
        "syslog",
        "Получатель журналов не утверждён",
        "Используйте утверждённого получателя журналов.",
    ),
}
