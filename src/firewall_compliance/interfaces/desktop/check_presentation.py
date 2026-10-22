"""Представление выполнения проверки без изменения сохранённого контракта."""

from typing import Any

CHECK_STATUS_LABELS = {
    "complete": "Выполнена в поддержанной области",
    "partial": "Выполнена частично",
    "not_applicable": "Не применима",
    "not_executed": "Не выполнена",
}


def check_execution_status(check: dict[str, Any]) -> str:
    """Отсутствие находок само по себе не означает, что проверка не запускалась."""
    if any(limit.get("code") == "CHECK_NOT_EXECUTED" for limit in check.get("limitations", [])):
        return "not_executed"
    return str(check["status"])


def check_status_label(check: dict[str, Any]) -> str:
    status = check_execution_status(check)
    return CHECK_STATUS_LABELS.get(status, status)


def check_reasons(check: dict[str, Any]) -> str:
    return "; ".join(
        f"{limit['code']}: {limit['message']}" for limit in check.get("limitations", [])
    )
