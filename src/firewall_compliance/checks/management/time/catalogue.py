"""Management time checks."""

from firewall_compliance.domain.management import ManagementKind

CHECKS: dict[str, tuple[ManagementKind, str, str]] = {
    "MGMT-NTP-MISSING": (
        "ntp",
        "Не настроен источник NTP",
        "Настройте источник NTP и проверьте синхронизацию отдельно.",
    ),
    "MGMT-NTP-UNAPPROVED": (
        "ntp",
        "Источник NTP не утверждён",
        "Используйте утверждённый источник NTP.",
    ),
}
