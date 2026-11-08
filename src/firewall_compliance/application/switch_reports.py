"""Экспорт настроенной структуры коммутатора без запуска сетевого анализа."""

import csv
import html
import io
import json
from collections.abc import Iterator, Mapping
from typing import Any

from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.switch_topology import SwitchTopology

SWITCH_REPORT_LIMITATION = (
    "Показаны настройки из файла. Они не подтверждают состояние каналов, "
    "фактическое применение маршрутов или сквозную доступность. "
    "Связи по описаниям портов являются предположениями."
)


def switch_report_payload(
    parsed: ParseResult, *, topology: SwitchTopology | None = None
) -> dict[str, Any] | None:
    """Собрать сведения из валидированного импорта, сохранив provenance."""
    facts = parsed.switch_facts
    policies = parsed.switch_policies
    if facts is None and policies is None:
        return None
    return {
        "schema_version": "1.0.0",
        "configuration": parsed.configuration.model_dump(mode="json"),
        "switch_facts": facts.model_dump(mode="json") if facts is not None else None,
        "switch_policies": policies.model_dump(mode="json") if policies is not None else None,
        "summary": policies.summary.model_dump(mode="json") if policies is not None else None,
        "limitations": [SWITCH_REPORT_LIMITATION],
        **({"switch_topology": topology.model_dump(mode="json")} if topology is not None else {}),
    }


def switch_report_records(payload: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    """Развернуть факты и применения ACL без умножения исходных ACE."""
    yield {
        "section": "summary",
        "entity_id": str(payload.get("configuration", {}).get("device_id", "")),
        "details": {
            "configuration": payload.get("configuration"),
            "summary": payload.get("summary"),
            "limitations": payload.get("limitations", [SWITCH_REPORT_LIMITATION]),
        },
    }
    for envelope_name in ("switch_policies", "switch_facts", "switch_topology"):
        envelope = payload.get(envelope_name)
        if not isinstance(envelope, Mapping):
            continue
        for section, value in envelope.items():
            if isinstance(value, list):
                for index, entry in enumerate(value):
                    identifier = str(index + 1)
                    if isinstance(entry, Mapping):
                        identifier = str(
                            entry.get("binding_id")
                            or entry.get("acl_id")
                            or entry.get("manager_id")
                            or entry.get("name")
                            or entry.get("code")
                            or identifier
                        )
                    yield {
                        "section": f"{envelope_name}.{section}",
                        "entity_id": identifier,
                        "details": entry,
                    }
            elif value is not None:
                yield {
                    "section": f"{envelope_name}.{section}",
                    "entity_id": section,
                    "details": value,
                }


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def _safe_cell(value: str) -> str:
    if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or value.startswith(
        ("\t", "\r")
    ):
        return "'" + value
    return value


def export_switch_csv(payload: Mapping[str, Any]) -> str:
    """Экспортировать категории, исходные факты и ограничения в CSV."""
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=("section", "entity_id", "details_json"))
    writer.writeheader()
    for record in switch_report_records(payload):
        writer.writerow(
            {
                "section": _safe_cell(record["section"]),
                "entity_id": _safe_cell(record["entity_id"]),
                "details_json": _safe_cell(_json(record["details"])),
            }
        )
    return stream.getvalue()


def switch_report_html_section(payload: Mapping[str, Any]) -> str:
    """Построить безопасный HTML-фрагмент с явными границами выводов."""
    escape = html.escape
    parts = [
        "<section><h3>Конфигурация коммутатора</h3>",
        f"<p>{escape(SWITCH_REPORT_LIMITATION)}</p>",
    ]
    summary = payload.get("summary")
    if isinstance(summary, Mapping):
        labels = {
            "acl_count": "ACL",
            "ace_count": "Исходных ACE",
            "binding_count": "Привязок",
            "manager_count": "Authorized managers",
            "transit_bindings": "Транзитных применений",
            "management_bindings": "Управляющих применений",
            "unbound_acls": "Непривязанных ACL",
            "unknown_bindings": "Неизвестных применений",
            "invalid_entries": "Некорректных записей",
            "invalid_managers": "Некорректных authorized managers",
        }
        parts.append("<dl>")
        for key, label in labels.items():
            if key in summary:
                parts.append(f"<dt>{escape(label)}</dt><dd>{escape(str(summary[key]))}</dd>")
        parts.append("</dl>")
        if summary.get("transit_bindings") == 0:
            parts.append("<p>Транзитные ACL в представленном файле не обнаружены.</p>")
    for record in switch_report_records(payload):
        parts.append(
            f"<details><summary>{escape(record['section'])} · "
            f"{escape(record['entity_id'])}</summary>"
            f"<pre>{escape(json.dumps(record['details'], ensure_ascii=False, indent=2))}</pre>"
            "</details>"
        )
    parts.append("</section>")
    return "".join(parts)


def export_switch_html(payload: Mapping[str, Any]) -> str:
    """Создать автономный HTML без внешних ресурсов."""
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        "<title>Конфигурация коммутатора</title><style>"
        "body{font:15px sans-serif;max-width:1200px;margin:2em auto}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}details{margin:.6em 0}"
        "</style></head><body>"
        + switch_report_html_section(payload)
        + "</body></html>"
    )


def export_switch_topology_json(topology: SwitchTopology) -> str:
    """Сохранить карту с доказательствами и разрывами, без пересчёта анализа."""
    return topology.model_dump_json(indent=2)


def export_switch_topology_csv(topology: SwitchTopology) -> str:
    """Экспортировать локальные узлы, связи и ограничения карты."""
    return export_switch_csv({"switch_topology": topology.model_dump(mode="json")})


def export_switch_topology_html(topology: SwitchTopology) -> str:
    """Создать автономный отчёт настроенной структуры и свидетельств."""
    return export_switch_html({"switch_topology": topology.model_dump(mode="json")})
