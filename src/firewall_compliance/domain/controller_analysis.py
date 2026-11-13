"""Результаты анализа объявленных политик контроллера, отдельно от сетевого пути."""

from typing import Any, Literal

from pydantic import Field

from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.source import SourceLocation


class ControllerPolicyFinding(DomainModel):
    """Наблюдение по условиям правил, а не доказательство внешней доступности."""

    code: str
    severity: Literal["info", "low", "medium", "high"]
    title: str
    policy_id: str
    rule_ids: tuple[str, ...] = ()
    source_locations: tuple[SourceLocation, ...] = ()
    details: dict[str, Any] = Field(default_factory=dict)


class RolePolicySummary(DomainModel):
    """Полнота относится к статическому конфигурационному срезу роли."""

    role_name: str
    acl_names: tuple[str, ...] = ()
    rule_count: int = 0
    known_rules: int = 0
    complete: bool = False
    limitations: tuple[str, ...] = ()


class ControllerAnalysis(DomainModel):
    """Ограниченные результаты инвентаризации и анализа session ACL."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    findings: tuple[ControllerPolicyFinding, ...] = ()
    roles: tuple[RolePolicySummary, ...] = ()
    limitations: tuple[str, ...] = ()


class ControllerTrace(DomainModel):
    """Проверенная строка и причина совпадения/неизвестности запроса."""

    acl_name: str
    rule_id: str | None = None
    match: Literal["yes", "no", "unknown"]
    action: str | None = None
    reason: str
    source_locations: tuple[SourceLocation, ...] = ()


class ControllerRoleDecision(DomainModel):
    """Решение для заданного tuple в роли; не end-to-end и не runtime-сессия."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    role_name: str
    decision: Literal["allow", "deny", "unknown"] = "unknown"
    matched_rule_id: str | None = None
    trace: tuple[ControllerTrace, ...] = ()
    reasons: tuple[str, ...] = ()
    limitations: tuple[str, ...] = (
        "Оцениваются заданные условия роли, без маршрутизации, NAT и состояния сессии.",
        "Запрос не доказывает фактическое назначение роли активному клиенту.",
    )
