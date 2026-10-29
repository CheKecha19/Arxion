"""Management snmp checks."""

from firewall_compliance.domain.management import ManagementKind

CHECKS: dict[str, tuple[ManagementKind, str, str]] = {
    "MGMT-SNMP-LEGACY": (
        "snmp_legacy",
        "Разрешён SNMPv1/v2c",
        "Используйте SNMPv3 с аутентификацией и шифрованием.",
    ),
    "MGMT-SNMP-WRITE": (
        "snmp_write",
        "SNMP write-доступ запрещён профилем",
        "Отключите write-доступ или согласуйте требование профиля.",
    ),
    "MGMT-SNMP-SOURCES": (
        "snmp_sources",
        "Источники SNMP вне разрешённых сетей",
        "Ограничьте источники SNMP утверждёнными сетями.",
    ),
}
