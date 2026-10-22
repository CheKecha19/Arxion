"""Автономные общие отчёты запуска с отдельными пользовательскими решениями."""

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from firewall_compliance.interfaces.desktop.check_presentation import (
    CHECK_STATUS_LABELS,
    check_execution_status,
    check_status_label,
)
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.result_presentation import (
    LimitationGroup,
    check_limitations,
    finding_limitations,
    group_details,
    group_summary,
    project_item_limitations,
)

DISCLAIMER = (
    "Ноль находок не означает безопасность устройства. Полнота ограничена поддержкой "
    "парсеров и реализованными проверками; итоговая сетевая достижимость не вычисляется."
)

LABELS = {
    "complete": "В границах проверки",
    "partial": "Частично",
    "not_applicable": "Неприменимо",
    "unsupported": "Формат не поддержан",
    "error": "Ошибка",
    "canceled": "Отменено",
    "running": "Выполняется",
    "completed": "Завершён",
    "cancelled": "Отменён",
    "interrupted": "Прерван",
    "critical": "Критическая",
    "high": "Высокая",
    "medium": "Средняя",
    "low": "Низкая",
    "info": "Информационная",
    "new": "Новая",
    "confirmed": "Подтверждена",
    "in_progress": "В работе",
    "accepted_risk": "Риск принят",
    "false_positive": "Ложное срабатывание",
    "resolved": "Отмечена устранённой пользователем",
    "FW-ANY-ANY": "Избыточно широкие разрешения",
    "FW-LOGGING": "Журналирование",
    "FW-COMMENTS": "Комментарии",
    "FW-DISABLED": "Отключённые правила",
    "FW-DUPLICATE": "Дублирующие правила",
    "FW-SHADOWED": "Перекрытые правила",
    "FW-MERGE-CANDIDATE": "Кандидаты на объединение",
}


def _label(value: str) -> str:
    return _escape(LABELS.get(value, value))


def _counts(values: dict[str, int]) -> str:
    return " · ".join(f"{_label(key)}: {count}" for key, count in values.items()) or "Нет"


def build_batch_report(
    store: ProjectStore, run_id: str, *, include_fragments: bool = True
) -> dict[str, Any]:
    """Собрать версионированный пакет без изменения отдельных backend-контрактов."""
    run = store.get_run(run_id)
    project = store.get_project(run["project_id"])
    items = []
    severity: Counter[str] = Counter()
    checks: Counter[str] = Counter()
    for item in run["items"]:
        items.append(
            {
                "item_id": item["id"],
                "source_name": item["source_name"],
                "content_sha256": item["content_sha256"],
                "status": item["status"],
                "device": {
                    key: item["parse_result"]["configuration"][key]
                    for key in ("device_id", "vendor", "platform")
                }
                if item.get("parse_result")
                else None,
                "diagnostics": item["diagnostics"],
                "result": item["report"],
                "excerpts": item["excerpts"] if include_fragments else [],
            }
        )
        if item["report"]:
            for check in item["report"]["checks"]:
                checks[check["status"]] += 1
                severity.update(finding["severity"] for finding in check["findings"])
    return {
        "package_type": "firewall-compliance.batch-report",
        "schema_version": "1.0.0",
        "project": {"id": project["id"], "name": project["name"]},
        "run": {key: run[key] for key in ("id", "created_at", "finished_at", "state", "settings")},
        "summary": {
            "files": len(items),
            "imports": dict(Counter(item["status"] for item in items)),
            "findings_by_severity": dict(severity),
            "checks_by_status": dict(checks),
        },
        "limitations": [DISCLAIMER],
        "fragments_included": include_fragments,
        "items": items,
        "user_decisions": run["marks"],
    }


def export_batch_json(
    store: ProjectStore, run_id: str, path: Path, *, include_fragments: bool = True
) -> None:
    """Экспортировать исходные результаты и пользовательские решения отдельными полями."""
    path.write_text(
        json.dumps(
            build_batch_report(store, run_id, include_fragments=include_fragments),
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _limitation_links(groups: tuple[LimitationGroup, ...]) -> str:
    """Link to the single reversible group projection rather than repeat raw lists."""
    return (
        "<ul>"
        + "".join(
            f'<li><a href="#{group.key}">{_escape(group.code)}: {_escape(group.message)}</a></li>'
            for group in groups
        )
        + "</ul>"
    )


def _limitation_section(groups: tuple[LimitationGroup, ...]) -> str:
    """Render shared group keys, explicit counts, and all raw occurrence references."""
    if not groups:
        return "<p>Ограничения в сохранённом результате не указаны.</p>"
    return "<h4>Ограничения и диагностика</h4>" + "".join(
        f'<div class="notice" id="{group.key}"><p>{_escape(group_summary(group))}</p>'
        f"<small>Происхождение: {_escape(group.origin)} · "
        f"Правила: {_escape(', '.join(group.rule_ids) or 'не указаны')} · "
        f"Проверки: {_escape(', '.join(group.check_ids) or 'не указаны')}</small>"
        "<details><summary>Все исходные записи и связи</summary>"
        f"<pre>{_escape(group_details(group))}</pre></details></div>"
        for group in groups
    )


def render_batch_html(package: dict[str, Any]) -> str:
    """HTML без JavaScript, сетевых ресурсов и интерпретации исходного текста как разметки."""
    summary = package["summary"]
    execution_counts = Counter(
        check_execution_status(check)
        for item in package["items"]
        for check in (item.get("result") or {}).get("checks", [])
    )
    execution_summary = (
        " · ".join(
            f"{_escape(CHECK_STATUS_LABELS.get(key, key))}: {count}"
            for key, count in execution_counts.items()
        )
        or "Нет"
    )
    sections = [
        f"<h1>{_escape(package['project']['name'])}</h1>",
        f"<p>Запуск: {_escape(package['run']['created_at'])} · "
        f"Состояние: {_label(package['run']['state'])}</p>",
        "<h2>Управленческая сводка</h2>",
        f"<p>Файлов: {summary['files']}. Находок: "
        f"{sum(summary['findings_by_severity'].values())}.</p>",
        f"<p>Импорты: {_counts(summary['imports'])}</p>",
        f"<p>Приоритеты: {_counts(summary['findings_by_severity'])}</p>",
        f"<p>Выполнение проверок: {execution_summary}</p>",
        '<div class="notice">' + "<br>".join(_escape(x) for x in package["limitations"]) + "</div>",
        "<h2>Устройства и охват</h2><table><thead><tr><th>Источник</th><th>Устройство</th>"
        "<th>Платформа</th><th>Результат импорта</th><th>Конструкции</th></tr></thead><tbody>",
    ]
    for item in package["items"]:
        report = item["result"]
        coverage = report["parse_coverage"] if report else None
        count = (
            f"{coverage['recognized_constructs']} / {coverage['discovered_constructs']}"
            if coverage
            else "—"
        )
        device = _escape(report["device_id"]) if report else "—"
        platform = _escape((item.get("device") or {}).get("platform", "—"))
        sections.append(
            f'<tr><td><a href="#item-{_escape(item["item_id"])}">'
            f"{_escape(item['source_name'])}</a></td><td>{device}</td>"
            f"<td>{platform}</td><td>{_label(item['status'])}</td><td>{count}</td></tr>"
        )
    sections.append("</tbody></table><h2>Находки и технические подробности</h2>")
    for item in package["items"]:
        sections.append(
            f'<section id="item-{_escape(item["item_id"])}"><h3>'
            f"{_escape(item['source_name'])} — {_label(item['status'])}</h3>"
        )
        sections.append(f"<p>SHA-256: <code>{_escape(item['content_sha256'])}</code></p>")
        item_groups = project_item_limitations(item)
        sections.append(_limitation_section(item_groups))
        result = item["result"]
        if result:
            sections.append(
                f"<p>Устройство: {_escape(result['device_id'])} · "
                f"Ревизия: {_escape(result['revision_id'])} · "
                f"Parser: {_escape(result['parser_version'])}</p>"
            )
            coverage = result["parse_coverage"]
            sections.append(
                f"<p>Распознано конструкций: {coverage['recognized_constructs']}; "
                f"обнаружено: {coverage['discovered_constructs']}; "
                f"неподдержанных: {coverage['unsupported_constructs']}.</p>"
            )
            for check in result["checks"]:
                sections.append(
                    f"<h4>{_label(check['check_id'])} — {_escape(check_status_label(check))}</h4>"
                    f"<small>{_escape(check['check_id'])}</small>"
                )
                groups = check_limitations(item, check, groups=item_groups)
                if groups:
                    sections.append(
                        f"<p>Групп ограничений проверки: {len(groups)}.</p>"
                        + _limitation_links(groups)
                    )
                for finding in check["findings"]:
                    mark = package["user_decisions"].get(finding["finding_id"], {})
                    affected = ", ".join(finding.get("affected_rule_ids", [])) or "не указаны"
                    sections.append(
                        f"<article><h5>{_label(finding['severity'])}: "
                        f"{_escape(finding['title'])}</h5>"
                        f"<p>{_escape(finding['description'])}</p>"
                        f"<p>Рекомендация: {_escape(finding['recommendation'])}</p>"
                        f"<p>Решение пользователя: {_label(mark.get('status', 'new'))}; "
                        f"комментарий: {_escape(mark.get('comment', ''))}</p>"
                        f"<h6>Доказательства</h6><p>{_escape(finding['evidence']['summary'])}</p>"
                        f"<p>Затронутые правила: "
                        f"{_escape(affected)}"
                        "</p>"
                        "<details><summary>Полные технические доказательства (JSON)</summary>"
                        "<pre>"
                        f"{_escape(json.dumps(finding['evidence'], ensure_ascii=False, indent=2))}"
                        "</pre></details>"
                    )
                    selection = finding_limitations(item, check, finding, groups=item_groups)
                    if selection.local:
                        sections.append(
                            "<p>Ограничения этой находки:</p>" + _limitation_links(selection.local)
                        )
                    if selection.common:
                        sections.append(
                            "<details><summary>Общие ограничения источника и проверки: "
                            f"{len(selection.common)} групп</summary>"
                            "<p>Точная привязка этих сообщений к правилам находки не указана.</p>"
                            + _limitation_links(selection.common)
                            + "</details>"
                        )
                    for location in finding["evidence"].get("source_locations", []):
                        start = location.get("line_start") or "не указаны"
                        end = location.get("line_end") or start
                        path = (
                            location.get("object_path") or location.get("object_id") or "не указан"
                        )
                        sections.append(
                            f"<p>Источник: {_escape(location.get('source_name', 'не указан'))}; "
                            f"строки: {_escape(start)}–{_escape(end)}; "
                            f"путь: {_escape(path)}</p>"
                        )
                    if package["fragments_included"]:
                        locations = finding["evidence"]["source_locations"]
                        for excerpt in item["excerpts"]:
                            if any(
                                location["source_name"] == excerpt["location"]["source_name"]
                                and location["line_start"] == excerpt["location"]["line_start"]
                                for location in locations
                            ):
                                sections.append(f"<pre>{_escape(excerpt['text'])}</pre>")
                    sections.append("</article>")
        if package["fragments_included"] and item["excerpts"]:
            sections.append("<h4>Сохранённые фрагменты исходника</h4>")
            sections.extend(
                f"<pre>{_escape(excerpt['text'])}</pre>" for excerpt in item["excerpts"]
            )
        sections.append("</section>")
    content = "\n".join(sections)
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Firewall Compliance — отчёт</title><style>
body{{font:16px/1.55 "Segoe UI",sans-serif;color:#203047;background:#f3f5f8;margin:0}}
main{{max-width:1100px;margin:auto;padding:32px}}section,article{{background:white;border:1px
solid #d5dcea;border-radius:12px;padding:20px;margin:18px 0}}h1,h2,h3{{color:#244d83}}
h5{{font-size:17px;margin:0}}.notice{{background:#fff3d7;border-left:4px solid #9b6b00;
padding:12px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf1f7;padding:12px}}
code{{overflow-wrap:anywhere}}table{{border-collapse:collapse;width:100%;background:white}}
td,th{{padding:10px;text-align:left;border:1px solid #d5dcea}}a{{color:#244d83}}
@media print{{body{{background:white;font-size:11pt}}main{{padding:0}}
section,article{{border-radius:0}}h3,h4,h5{{break-after:avoid}}pre{{font-size:9pt}}}}
</style></head><body><main>{content}</main></body></html>"""


def export_batch_html(
    store: ProjectStore, run_id: str, path: Path, *, include_fragments: bool = True
) -> None:
    """Сохранить автономный отчёт, включая фрагменты только при выбранной настройке."""
    path.write_text(
        render_batch_html(build_batch_report(store, run_id, include_fragments=include_fragments)),
        encoding="utf-8",
    )


def compare_run_findings(store: ProjectStore, before_id: str, after_id: str) -> dict[str, Any]:
    """Сравнить присутствие находок без автоматического объявления проблем устранёнными."""
    before, after = store.get_run(before_id), store.get_run(after_id)
    if before["project_id"] != after["project_id"]:
        raise ValueError("Сравнивать можно только запуски одного проекта")

    def identities(run: dict[str, Any]) -> set[tuple[str, str, tuple[str, ...]]]:
        return {
            (
                item["report"]["device_id"],
                finding["check_id"],
                tuple(sorted(finding["affected_rule_ids"])),
            )
            for item in run["items"]
            if item["report"]
            for check in item["report"]["checks"]
            for finding in check["findings"]
        }

    old, new = identities(before), identities(after)
    return {
        "before_run_id": before_id,
        "after_run_id": after_id,
        "appeared": sorted(new - old),
        "not_observed": sorted(old - new),
        "persisting": sorted(old & new),
        "limitations": [
            "Сопоставление по устройству, проверке и rule_id; изменение идентификаторов "
            "может выглядеть как новая находка. Отсутствие не доказывает устранение. "
            "Статусы и комментарии не переносятся автоматически."
        ],
    }
