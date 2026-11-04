"""Читаемые доказательства сохранённой сверки, без повторного вычисления доступа."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter
from io import StringIO

from firewall_compliance.application.matrix_artifact import MatrixAssessmentArtifact

MATRIX_STATE_LABELS = {
    "declared_match": "Покрывающее заданное условие найдено",
    "declared_conflict": "Противоположное заданное условие",
    "insufficient_evidence": "Недостаточно данных",
    "unregulated": "Не регламентировано",
    "requirement_conflict": "Конфликт требования",
    "not_applicable": "Другая область",
}


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def matrix_report_section(artifact: MatrixAssessmentArtifact) -> str:
    result = artifact.assessment
    groups = {group.group_id: group.name for group in artifact.matrix.groups}
    requirements = {row.requirement_id: row for row in artifact.matrix.requirements}
    requirement_counts = Counter(row.requirement_id for row in artifact.matrix.requirements)
    counts = Counter(row.state for row in result.requirements)
    configuration = artifact.revision.parse_result.configuration
    parts = [
        "<section><h2>Матрица доступа: заданные условия правил</h2>",
        "<p>Наличие условия allow не подтверждает сквозную доступность. "
        "Порядок применения, NAT и маршрутизация здесь не вычисляются.</p>",
        f"<p>Сверка: {_escape(artifact.artifact_id)}; выполнена: {_escape(artifact.created_at.isoformat())}<br>",
        f"Матрица: {_escape(artifact.matrix.matrix_id)} / v{_escape(artifact.matrix.version)}<br>",
        f"Ревизия: {_escape(result.revision_id)}; область: {_escape(result.scope_id)}<br>",
        f"Профиль: {_escape(result.profile_id)} / {_escape(result.profile_version)}; "
        f"приложение: {_escape(artifact.application_version)}</p>",
        f"<p>Источник: {_escape(configuration.source_name)}<br>"
        f"Получен: {_escape(configuration.captured_at.isoformat())}<br>"
        f"SHA-256: {_escape(configuration.content_sha256)}<br>"
        f"Запуск / элемент: {_escape(artifact.origin_run_id or 'не указан')} / "
        f"{_escape(artifact.origin_item_id or 'не указан')}</p>",
        "<p>" + "; ".join(
            f"{_escape(MATRIX_STATE_LABELS[key])}: {count}" for key, count in sorted(counts.items())
        ) + "</p>",
        "<h3>Полнота и ограничения</h3><ul>",
    ]
    parts.extend(f"<li>{_escape(value)}</li>" for value in result.limitations)
    if artifact.profile_settings_json is None:
        parts.append("<li>Параметры исходного профиля не сохранены; доступна только его ссылка.</li>")
    parts.append("</ul>")
    if result.diagnostics:
        parts.append("<h3>Диагностика матрицы</h3><ul>")
        parts.extend(
            f"<li>{_escape(issue.code)}: {_escape(issue.message)}; "
            f"группы {_escape(', '.join(issue.group_ids))}; "
            f"требования {_escape(', '.join(issue.requirement_ids))}</li>"
            for issue in result.diagnostics
        )
        parts.append("</ul>")
    parts.append(
        "<h3>Требования и результаты</h3><table><thead><tr><th>ID</th><th>Источник</th>"
        "<th>Назначение</th><th>Сервис</th><th>Требование</th><th>Результат и основание</th>"
        "</tr></thead><tbody>"
    )
    for row in result.requirements:
        if requirement_counts[row.requirement_id] != 1:
            cells = (
                row.requirement_id, "Неоднозначный ID", "Неоднозначный ID", "См. диагностику",
                "См. сохранённую матрицу", MATRIX_STATE_LABELS[row.state] + ": " + "; ".join(row.reasons),
            )
            parts.append("<tr>" + "".join(f"<td>{_escape(cell)}</td>" for cell in cells) + "</tr>")
            continue
        requirement = requirements[row.requirement_id]
        service = requirement.service
        ports = "любые порты" if service.any_ports else ", ".join(
            str(port.start) if port.start == port.end else f"{port.start}–{port.end}"
            for port in service.ports
        )
        cells = (
            row.requirement_id, groups.get(requirement.source_group, requirement.source_group),
            groups.get(requirement.destination_group, requirement.destination_group),
            f"{service.protocol} {ports}",
            {"permit": "Разрешить", "deny": "Запретить", "unregulated": "Не регламентировано"}[requirement.requirement],
            MATRIX_STATE_LABELS[row.state] + ": " + "; ".join(row.reasons),
        )
        parts.append("<tr>" + "".join(f"<td>{_escape(cell)}</td>" for cell in cells) + "</tr>")
    parts.append("</tbody></table><h3>Доказательства</h3>")
    for row in result.requirements:
        parts.append(f"<h4>{_escape(row.requirement_id)}</h4>")
        if requirement_counts[row.requirement_id] == 1:
            requirement = requirements[row.requirement_id]
            details = (
                ("Пользователь / группа", requirement.identity),
                ("Условие расписания", requirement.schedule),
                ("Основание требования", requirement.reason),
                ("Владелец", requirement.owner),
                ("Дата пересмотра", requirement.review_date),
                ("Политика", requirement.policy_id),
            )
            parts.extend(
                f"<p>{_escape(title)}: {_escape(value)}</p>"
                for title, value in details if value is not None
            )
        for evidence in row.evidence:
            parts.append(f"<p>{_escape(evidence.summary)}; правила: {_escape(', '.join(evidence.related_rule_ids))}</p>")
            for location in evidence.source_locations:
                parts.append(
                    f"<p>Источник: {_escape(location.source_name)}; строки "
                    f"{_escape(location.line_start)}–{_escape(location.line_end)}; "
                    f"путь: {_escape(location.object_path or location.object_id or 'не указан')}</p>"
                )
            parts.extend(f"<p>{_escape(value)}</p>" for value in evidence.limitations)
            if evidence.facts:
                parts.append("<pre>" + _escape(json.dumps(
                    dict(evidence.facts), ensure_ascii=False, indent=2,
                )) + "</pre>")
    parts.append("</section>")
    return "\n".join(parts)


def matrix_report_html(artifact: MatrixAssessmentArtifact) -> str:
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width"><title>Сверка матрицы доступа</title>'
        "<style>body{font:16px/1.5 'Segoe UI',sans-serif;margin:24px;color:#203047}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #b6c4d6;"
        "padding:8px;text-align:left;overflow-wrap:anywhere}p{overflow-wrap:anywhere}</style>"
        "</head><body>" + matrix_report_section(artifact) + "</body></html>"
    )


def matrix_report_csv(artifact: MatrixAssessmentArtifact) -> str:
    stream = StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow((
        "Сверка", "Матрица", "Версия", "Ревизия", "Область", "Режим", "Требование",
        "Результат", "Основания", "Правила", "Ограничения",
    ))
    for row in artifact.assessment.requirements:
        values = (
            str(artifact.artifact_id), artifact.matrix.matrix_id, artifact.matrix.version,
            str(artifact.revision.revision_id), artifact.assessment.scope_id, "Заданные условия правил",
            row.requirement_id, MATRIX_STATE_LABELS[row.state], "; ".join(row.reasons),
            ", ".join(dict.fromkeys(key for evidence in row.evidence for key in evidence.related_rule_ids)),
            "; ".join(artifact.assessment.limitations),
        )
        writer.writerow(tuple("'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value for value in values))
    return stream.getvalue()
