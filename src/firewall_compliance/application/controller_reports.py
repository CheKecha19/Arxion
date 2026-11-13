"""Экспорт объектов, связей и ограниченного анализа ArubaOS Controller."""

import csv
import html
import io
import json
from collections import Counter
from collections.abc import Iterator, Mapping
from typing import Any

from firewall_compliance.domain.parse_result import ParseResult

CONTROLLER_REPORT_LIMITATION = (
    "Показаны декларации конфигурации и условный анализ политик. "
    "Они не доказывают назначение роли активному клиенту, установленную сессию, "
    "полную сквозную доступность или effective NAT/PBR/AppRF."
)


def controller_report_payload(parsed: ParseResult) -> dict[str, Any] | None:
    """Собрать versioned представление с источниками и неизвестными зависимостями."""
    inventory = parsed.controller_inventory
    if inventory is None:
        return None
    from firewall_compliance.analysis.controller_policy import analyze_controller

    analysis = analyze_controller(parsed)
    return {
        "schema_version": "1.0.0",
        "configuration": parsed.configuration.model_dump(mode="json"),
        "controller_inventory": inventory.model_dump(mode="json"),
        "controller_analysis": analysis.model_dump(mode="json"),
        "summary": {
            "objects_by_kind": dict(Counter(item.kind for item in inventory.objects)),
            "references": len(inventory.references),
            "references_by_status": dict(Counter(item.status for item in inventory.references)),
            "rules": len(parsed.rules),
            "issues": len(inventory.issues),
            "findings": len(analysis.findings),
        },
        "limitations": [CONTROLLER_REPORT_LIMITATION],
    }


def controller_report_records(payload: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    """Развернуть объекты и связи, сохранив отдельные типы сущностей."""
    yield {
        "section": "controller.summary",
        "entity_id": str(payload.get("configuration", {}).get("device_id", "")),
        "details": {
            "configuration": payload.get("configuration"),
            "summary": payload.get("summary"),
            "limitations": payload.get("limitations", [CONTROLLER_REPORT_LIMITATION]),
        },
    }
    for name in ("controller_inventory", "controller_analysis", "role_decision"):
        envelope = payload.get(name)
        if not isinstance(envelope, Mapping):
            continue
        for section, value in envelope.items():
            if isinstance(value, (tuple, list)):
                for index, entry in enumerate(value):
                    identifier = str(index + 1)
                    if isinstance(entry, Mapping):
                        identifier = str(
                            entry.get("object_id")
                            or entry.get("reference_id")
                            or entry.get("role_name")
                            or entry.get("code")
                            or identifier
                        )
                    yield {
                        "section": f"{name}.{section}",
                        "entity_id": identifier,
                        "details": entry,
                    }
            elif value is not None:
                yield {"section": f"{name}.{section}", "entity_id": section, "details": value}


def _safe_cell(value: str) -> str:
    if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r")):
        return "'" + value
    return value


def export_controller_csv(payload: Mapping[str, Any]) -> str:
    """Экспортировать сущности и evidence в CSV без формул из имён объектов."""
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=("section", "entity_id", "details_json"))
    writer.writeheader()
    for record in controller_report_records(payload):
        writer.writerow({
            "section": _safe_cell(record["section"]),
            "entity_id": _safe_cell(record["entity_id"]),
            "details_json": _safe_cell(json.dumps(record["details"], ensure_ascii=False)),
        })
    return stream.getvalue()


def controller_report_html_section(payload: Mapping[str, Any]) -> str:
    """Сформировать HTML из безопасной нормализованной модели, не из raw конфига."""
    parts = [
        "<section><h3>ArubaOS Controller: объекты, связи и политики</h3>",
        f"<p>{html.escape(CONTROLLER_REPORT_LIMITATION)}</p>",
    ]
    for record in controller_report_records(payload):
        parts.append(
            "<details><summary>"
            + html.escape(record["section"] + " · " + record["entity_id"])
            + "</summary><pre>"
            + html.escape(json.dumps(record["details"], ensure_ascii=False, indent=2))
            + "</pre></details>"
        )
    parts.append("</section>")
    return "".join(parts)


def export_controller_html(payload: Mapping[str, Any]) -> str:
    """Создать автономный HTML-отчёт без внешних ресурсов."""
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        "<title>ArubaOS Controller</title><style>"
        "body{font:15px sans-serif;max-width:1200px;margin:2em auto}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}details{margin:.6em 0}"
        "</style></head><body>"
        + controller_report_html_section(payload)
        + "</body></html>"
    )
