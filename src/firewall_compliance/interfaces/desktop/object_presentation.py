"""Pure human-readable projections of canonical objects; never infer missing facts."""

from collections.abc import Mapping, Sequence
from typing import Any, Literal

Record = Mapping[str, Any]

STATUS_LABELS = {
    "known": "Известно",
    "absent": "Отсутствует",
    "unknown": "Не определено",
    "unsupported": "Не поддержано",
    "not_applicable": "Не применимо",
}
ACTION_LABELS = {
    "allow": "Разрешить",
    "deny": "Запретить (deny)",
    "drop": "Отбросить (drop)",
    "reject": "Отклонить (reject)",
    "log": "Журналировать",
    "unknown": "Действие не определено",
}


def _status(value: Any) -> str:
    text = str(value or "unknown")
    return STATUS_LABELS.get(text, f"Неизвестный статус: {text}")


def _values(value: Record) -> list[str]:
    parts = [str(cidr) for cidr in value.get("cidrs", ())]
    parts.extend(f"{entry['start']}–{entry['end']}" for entry in value.get("ip_ranges", ()))
    if value.get("fqdn"):
        parts.append(str(value["fqdn"]))
    if value.get("zone"):
        parts.append(f"Зона: {value['zone']}")
    return parts


def _endpoint(value: Record, *, limit: int | None = None) -> str:
    status = value.get("resolution_status", "unknown")
    parts = _values(value)
    if value.get("kind") == "any" and status == "known":
        label = "Любой адрес"
    elif parts:
        shown = parts if limit is None else parts[:limit]
        label = ", ".join(shown)
        if limit is not None and len(parts) > limit:
            label += f" · ещё {len(parts) - limit}"
    else:
        label = str(value.get("name") or "Значение не извлечено")
    if status != "known":
        label += f" · {_status(status)}"
    elif not parts and value.get("kind") != "any":
        label += " · состав не извлечён"
    return label


def endpoint_summary(values: Sequence[Record]) -> str:
    """Describe extracted addresses without treating unresolved references as any."""
    return "; ".join(_endpoint(value, limit=3) for value in values) or "Не указано"


def _service(value: Record) -> str:
    status = value.get("resolution_status", "unknown")
    protocol = str(value.get("protocol") or "unknown")
    ports = ", ".join(
        str(entry["start"])
        if entry["start"] == entry["end"]
        else f"{entry['start']}–{entry['end']}"
        for entry in value.get("port_ranges", ())
    )
    if protocol == "ip" and status == "known":
        label = "Любой IP-протокол"
    elif protocol in {"tcp", "udp"}:
        label = (
            protocol.upper()
            + " · "
            + (ports or ("все порты" if status == "known" else "порт не извлечён"))
        )
    elif protocol == "icmp":
        label = "ICMP"
    else:
        label = str(value.get("name") or "Протокол не извлечён")
        label += " · протокол: " + protocol + " · порт не извлечён"
    if status != "known":
        label += f" · {_status(status)}"
    return label


def service_summary(values: Sequence[Record]) -> str:
    """Describe protocols and port ranges using only canonical extracted semantics."""
    return "; ".join(_service(value) for value in values) or "Не указано"


def object_summary(value: Record) -> str:
    """Return a short table preview; complete values remain in object_details."""
    return _service(value) if "service_id" in value else _endpoint(value, limit=3)


def object_details(value: Record) -> tuple[tuple[str, str], ...]:
    """Expose every current endpoint/service field without truncating values."""
    rows = [
        ("Имя", str(value.get("name") or "Не указано")),
        ("Идентификатор", str(value.get("endpoint_id") or value.get("service_id") or "Не указан")),
        ("Достоверность значения", _status(value.get("resolution_status"))),
    ]
    if "service_id" in value:
        rows.extend(
            [
                ("Условие сервиса", _service(value)),
                ("Протокол", str(value.get("protocol") or "Не извлечён")),
                (
                    "Диапазоны портов",
                    "; ".join(
                        f"{entry['start']}–{entry['end']}" for entry in value.get("port_ranges", ())
                    )
                    or "Не указаны",
                ),
            ]
        )
    else:
        rows.extend(
            [
                ("Тип", str(value.get("kind") or "Не указан")),
                ("Значение", _endpoint(value)),
                ("CIDR", "; ".join(str(entry) for entry in value.get("cidrs", ())) or "Не указаны"),
                (
                    "Диапазоны адресов",
                    "; ".join(
                        f"{entry['start']}–{entry['end']}" for entry in value.get("ip_ranges", ())
                    )
                    or "Не указаны",
                ),
                ("FQDN", str(value.get("fqdn") or "Не указан")),
                ("Зона", str(value.get("zone") or "Не указана")),
            ]
        )
    rows.append(("Описание", str(value.get("description") or "Не извлечено")))
    return tuple(rows)


def rule_scope_label(rule: Record) -> str:
    """Recognize explicit management markers; never infer transit from an ACL name."""
    policy = str(rule.get("policy_id") or "")
    if policy.startswith("management:"):
        return "Управление устройством"
    return "Область применения не подтверждена"


def _rule_qualification(rule: Record, status_field: str) -> str:
    field_status = rule.get(status_field, "unknown")
    match_status = rule.get("match_status", "unknown")
    return (
        f"полное условие не подтверждено (поле: {_status(field_status)}; "
        f"правило: {_status(match_status)})"
    )


def _rule_endpoint(
    rule: Record, field: Literal["sources", "destinations"], *, limit: int | None
) -> str:
    status_field = "source_status" if field == "sources" else "destination_status"
    confirmed = rule.get(status_field) == "known" and rule.get("match_status") == "known"
    labels = []
    for value in rule.get(field, ()):
        if not confirmed and value.get("kind") == "any":
            labels.append("Адресное условие не определено")
        else:
            labels.append(_endpoint(value, limit=limit))
    label = "; ".join(labels) or "Не указано"
    if not confirmed:
        return "Извлечённая часть: " + label + " · " + _rule_qualification(rule, status_field)
    return label


def rule_endpoint_summary(rule: Record, field: Literal["sources", "destinations"]) -> str:
    """Project a rule address condition using both field and aggregate certainty."""
    return _rule_endpoint(rule, field, limit=3)


def rule_service_summary(rule: Record) -> str:
    """Prevent placeholder service leaves from overriding unsupported rule predicates."""
    confirmed = rule.get("service_status") == "known" and rule.get("match_status") == "known"
    labels = []
    for value in rule.get("services", ()):
        if not confirmed and value.get("protocol") == "ip":
            labels.append("IP · ограничения не определены")
        elif (
            not confirmed
            and value.get("protocol") in {"tcp", "udp"}
            and not value.get("port_ranges")
        ):
            labels.append(str(value["protocol"]).upper() + " · порт не извлечён")
        else:
            labels.append(_service(value))
    label = "; ".join(labels) or "Не указано"
    if not confirmed:
        return "Извлечённая часть: " + label + " · " + _rule_qualification(rule, "service_status")
    return label


def rule_details(rule: Record) -> tuple[tuple[str, str], ...]:
    """Describe all current Rule fields while keeping unknown conditions visible."""
    location = rule.get("source_location") or {}
    source = str(location.get("source_name") or "Источник не указан")
    if location.get("line_start") is not None:
        end = location.get("line_end") or location["line_start"]
        source += f" · строки {location['line_start']}–{end}"
    for key, label in (("object_id", "ID объекта"), ("object_path", "путь")):
        if location.get(key):
            source += f" · {label}: {location[key]}"
    logging = rule.get("logging_enabled")
    enabled = rule.get("enabled")
    return (
        ("Правило", str(rule.get("name") or "Не указано")),
        ("Идентификатор правила", str(rule.get("rule_id") or "Не указан")),
        ("Конфигурация", str(rule.get("configuration_id") or "Не указана")),
        (
            "Состояние",
            "Включено" if enabled is True else "Отключено" if enabled is False else "Не определено",
        ),
        (
            "Действие",
            ACTION_LABELS.get(str(rule.get("action")), str(rule.get("action") or "Не определено")),
        ),
        ("Позиция в источнике", str(rule.get("sequence", "Не указана"))),
        (
            "Порядок применения",
            "Первое совпадение"
            if rule.get("policy_semantics") == "first_match"
            else "Не подтверждён",
        ),
        ("Политика", str(rule.get("policy_id") or "Не указана")),
        ("Область", rule_scope_label(rule)),
        (
            "Направление",
            {"in": "Входящее", "out": "Исходящее", "global": "Глобальное"}.get(
                str(rule.get("policy_direction")), "Не подтверждено"
            ),
        ),
        ("Откуда", _rule_endpoint(rule, "sources", limit=None)),
        ("Куда", _rule_endpoint(rule, "destinations", limit=None)),
        ("Сервис", rule_service_summary(rule)),
        ("Зона источника", str(rule.get("source_zone") or "Не указана")),
        ("Зона назначения", str(rule.get("destination_zone") or "Не указана")),
        ("Достоверность зон", _status(rule.get("zone_status"))),
        ("Достоверность условия", _status(rule.get("match_status"))),
        (
            "Журналирование",
            (
                "Включено"
                if logging is True
                else "Выключено"
                if logging is False
                else "Не определено"
            )
            + " · "
            + _status(rule.get("logging_status")),
        ),
        ("Описание", str(rule.get("description") or "Не извлечено")),
        ("Достоверность описания", _status(rule.get("description_status"))),
        ("Владелец", str(rule.get("owner") or "Не извлечён")),
        ("Расположение", source),
    )
