"""Перечисления канонической доменной модели."""

from enum import StrEnum


class DataStatus(StrEnum):
    """Степень достоверности отдельного поля конфигурации."""

    KNOWN = "known"
    ABSENT = "absent"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not_applicable"


class DataOrigin(StrEnum):
    """Происхождение нормализованного факта."""

    IMPORTED = "imported"
    MANUAL = "manual"


class SourceDocumentKind(StrEnum):
    """Назначение документа в составе ревизии устройства."""

    CONFIGURATION = "configuration"
    ROUTING_TABLE = "routing_table"
    TOPOLOGY = "topology"


class RevisionEntityKind(StrEnum):
    """Тип сущности, участвующей в сравнении ревизий."""

    CONFIGURATION = "configuration"
    INTERFACE = "interface"
    ROUTE = "route"
    NETWORK_SEGMENT = "network_segment"
    TOPOLOGY_LINK = "topology_link"


class RevisionChangeKind(StrEnum):
    """Вид изменения между двумя ревизиями."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class EndpointKind(StrEnum):
    """Тип сетевого объекта."""

    HOST = "host"
    SUBNET = "subnet"
    RANGE = "range"
    FQDN = "fqdn"
    OBJECT = "object"
    GROUP = "group"
    ZONE = "zone"
    ANY = "any"


class Protocol(StrEnum):
    """Протокол сетевого сервиса."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"
    OTHER = "other"


class RuleAction(StrEnum):
    """Нормализованное действие firewall-правила."""

    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    DROP = "drop"
    LOG = "log"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """Критичность finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(StrEnum):
    """Категория результата проверки."""

    SECURITY = "security"
    POLICY = "policy"
    COMPLIANCE = "compliance"
    PARSING = "parsing"
    CHANGE = "change"


class FindingStatus(StrEnum):
    """Жизненный цикл finding."""

    NEW = "new"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class ComplianceStatus(StrEnum):
    """Статус технического compliance-контроля."""

    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    NOT_ENOUGH_EVIDENCE = "not_enough_evidence"


class ParseIssueLevel(StrEnum):
    """Уровень диагностического сообщения парсера."""

    WARNING = "warning"
    ERROR = "error"
