"""Rows for collected cloud rules, without claiming local analysis or resolving references."""

from __future__ import annotations

import json
from typing import Any

GROUPS = {
    "systemRules": "Системное",
    "userDefinedRules": "Пользовательское",
    "defaultRules": "По умолчанию",
    "nat": "NAT",
    "security_rules": "Группа безопасности",
}


def _text(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or value.get("id") or json.dumps(value, ensure_ascii=False))
    if isinstance(value, list):
        return ", ".join(_text(item) for item in value)
    return str(value) if value is not None else ""


def cloud_rule_values(record: dict[str, Any]) -> list[dict[str, Any]]:
    data = record.get("data", {})
    firewall = data.get("firewall")
    groups = (
        [(key, firewall.get(key)) for key in ("systemRules", "userDefinedRules", "defaultRules")]
        if isinstance(firewall, dict)
        else []
    )
    groups.extend((key, data.get(key)) for key in ("security_rules", "nat"))
    result = []
    for group, rules in groups:
        if not isinstance(rules, list):
            continue
        for sequence, raw in enumerate(rules, 1):
            if not isinstance(raw, dict):
                continue
            result.append(
                {
                    "cloud_rule": True,
                    "group": group,
                    "sequence": sequence,
                    "name": str(raw.get("name") or raw.get("id") or f"{GROUPS[group]} {sequence}"),
                    "raw": raw,
                }
            )
    return result


def _endpoints(raw: dict[str, Any], side: str) -> str:
    fields = (side + "FirewallIpAddresses", side + "FirewallGroups")
    if not any(key in raw for key in fields):
        return "Не указано API"
    parts = [_text(raw.get(fields[0]))]
    references = raw.get(fields[1])
    if references:
        parts.append("Группы: " + _text(references))
    return "; ".join(part for part in parts if part) or "Любой"


def cloud_rule_columns(value: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    raw, group = value["raw"], value["group"]
    action = str(raw.get("actionValue") or raw.get("action") or "Не указано API")
    if group == "nat":
        action = str(raw.get("type") or raw.get("ruleType") or "NAT")
        source = "Внутренние адреса: " + (_text(raw.get("internalAddresses")) or "Не указано API")
        destination = "Внешние адреса: " + (_text(raw.get("externalAddresses")) or "Не указано API")
        service = _text(raw.get("applicationPortProfile")) or "Не указано API"
    elif group == "security_rules":
        action = "Разрешение · " + str(raw.get("direction", "направление не указано"))
        source = "Удалённая сторона: " + (
            _text(raw.get("remote_ip_prefix") or raw.get("remote_group_id")) or "Не указано API"
        )
        destination = "Группа безопасности ресурса"
        service = (
            "; ".join(
                f"{key}: {_text(raw[key])}"
                for key in ("protocol", "port_range_min", "port_range_max")
                if raw.get(key) is not None
            )
            or "См. поля API"
        )
    else:
        source, destination = _endpoints(raw, "source"), _endpoints(raw, "destination")
        service_parts = []
        if raw.get("applicationPortProfiles"):
            service_parts.append("Профили: " + _text(raw["applicationPortProfiles"]))
        if raw.get("rawPortProtocols"):
            service_parts.append(json.dumps(raw["rawPortProtocols"], ensure_ascii=False))
        service = "; ".join(service_parts) or (
            "Любой"
            if "applicationPortProfiles" in raw or "rawPortProtocols" in raw
            else "Не указано API"
        )
    enabled = raw.get("active", raw.get("enabled"))
    if enabled is False:
        action += " · выключено"
    return (
        f"{GROUPS[group]} · {value['sequence']}",
        value["name"],
        action,
        source,
        destination,
        service,
    )


def cloud_rule_details(item: dict[str, Any], value: dict[str, Any]) -> list[tuple[str, str]]:
    columns = cloud_rule_columns(value)
    raw = value["raw"]
    return [
        ("Платформа", "Cloud.ru " + item["platform"].capitalize()),
        ("Ресурс", item["record"].get("name") or item["record"].get("id", "—")),
        ("Операция сбора", item["scan"]["id"]),
        ("Получено", item["scan"]["created_at"]),
        ("Раздел API", value["group"]),
        ("Порядок внутри раздела", str(value["sequence"])),
        ("ID правила", str(raw.get("id", "Не указан API"))),
        ("Название", value["name"]),
        ("Действие / тип", columns[2]),
        ("Источник / параметры NAT", columns[3]),
        ("Назначение / параметры NAT", columns[4]),
        ("Сервис", columns[5]),
        ("Направление", str(raw.get("direction", "Не указано API"))),
        ("Описание", str(raw.get("description") or "—")),
        ("Проверки", "Не выполнялись. Правило получено через API."),
        ("Ссылки на группы и профили", "Показаны имена/ID из API; состав по ссылкам не раскрыт."),
    ]
