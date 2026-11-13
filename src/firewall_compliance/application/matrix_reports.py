"""Читаемые доказательства сохранённой сверки, без повторного вычисления доступа."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from io import StringIO
from itertools import islice
from uuid import UUID

from firewall_compliance.application.access_context import matrix_context_sources_by_digest
from firewall_compliance.application.matrix_artifact import MatrixAssessmentArtifact
from firewall_compliance.application.matrix_boundary_groups import (
    MatrixBoundaryGroupAssessment, evaluate_boundary_groups,
)
from firewall_compliance.application.matrix_comparison import (
    MatrixScopeChange, compare_matrix_assessments, compare_matrix_scope_assessments,
)
from firewall_compliance.application.matrix_policy import matrix_catalog_switch_policy_contexts
from firewall_compliance.application.matrix_scope_assessment import (
    HISTORICAL_BASELINE_NOTE, SOURCE_FALLBACK_NOTE, MatrixScopeAssessment,
    MatrixScopeRowAssessment, MatrixScopeSource, matrix_scope_checksum,
)
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixRequirementAssessment, MatrixService, MatrixZonePair
from firewall_compliance.domain.finding import Evidence

MATRIX_STATE_LABELS = {
    "declared_match": "Покрывающее заданное условие найдено",
    "declared_conflict": "Противоположное заданное условие",
    "insufficient_evidence": "Недостаточно данных",
    "unregulated": "Не регламентировано",
    "requirement_conflict": "Конфликт требования",
    "not_applicable": "Не требуется проверка",
    "partial_match": "Частичное покрытие",
    "excess_allow": "Лишнее разрешение",
}

MATRIX_MODE_LABELS = {
    "declared_rules": "Заданные условия правил",
    "local_policy": "Локальное решение политики",
    "mixed": "Заданные условия и локальные решения",
}

MATRIX_BOUNDARY_GROUP_LABELS = {
    "excess_allow": "Найдено лишнее разрешение",
    "declared_match": "Перечисленные точки проверены",
    "insufficient_evidence": "Охват перечисленных точек не подтверждён",
}

MATRIX_BOUNDARY_POINT_LABELS = {
    "excess_allow": "Лишнее разрешение",
    "confirmed": "Локальное ограничение подтверждено",
    "unverified": "Ограничение не подтверждено",
}

_STATUS_LABELS = {
    "complete": "Вычисление завершено",
    "partial": "Вычисление выполнено частично",
    "cancelled": "Вычисление отменено",
}

_REQUIREMENT_LABELS = {
    "permit": "Доступ необходим",
    "allow_optional": "Доступ допустим",
    "deny": "Запретить",
    "unregulated": "Не регламентировано",
}


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def matrix_service_label(service: MatrixService) -> str:
    ports = "любые порты" if service.any_ports else ", ".join(
        str(port.start) if port.start == port.end else f"{port.start}–{port.end}"
        for port in service.ports
    )
    return " ".join(value for value in (service.protocol, ports) if value)


def matrix_packet_detail(evidence: Evidence) -> str | None:
    fragment = evidence.facts.get("fragment")
    if not isinstance(fragment, dict):
        return None

    def interval(value: object, kind: type[str] | type[int]) -> str | None:
        if not isinstance(value, (tuple, list)) or len(value) != 2 or any(type(item) is not kind for item in value):
            return None
        first, last = value
        return str(first) if first == last else f"{first}–{last}"

    source = interval(fragment.get("source"), str)
    destination = interval(fragment.get("destination"), str)
    if source is None or destination is None:
        return None
    protocol = interval(fragment.get("protocol_numbers"), int)
    ports = interval(fragment.get("destination_ports"), int)
    service = {"1": "ICMP", "6": "TCP", "17": "UDP"}.get(protocol or "", f"IP {protocol}" if protocol else "IP")
    action = evidence.facts.get("action")
    sequence = evidence.facts.get("sequence")
    count = evidence.facts.get("fragment_count")
    parts = [f"{source} → {destination}", f"{service} {ports}" if ports else service]
    if action == "allow" or action in ("deny", "drop", "reject"):
        parts.insert(0, "Разрешение" if action == "allow" else "Запрет")
    if type(sequence) is int:
        parts.append(f"правило № {sequence}")
    if type(count) is int and count > 1:
        parts.append(f"фрагмент 1 из {count}")
    return " · ".join(parts)


def matrix_evidence_preview(evidence: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
    """Показать первые основания и по одному примеру других типов решения."""
    visible = evidence[:12]
    if len(visible) == len(evidence):
        return visible

    def category(item: Evidence) -> str:
        action = item.facts.get("action")
        if action == "allow":
            return "allow"
        if action in ("deny", "drop", "reject"):
            return "deny"
        return "other"

    missing = {"allow", "deny", "other"} - {category(item) for item in visible}
    extra = []
    for item in islice(evidence, len(visible), None):
        if not missing:
            break
        if (key := category(item)) in missing:
            extra.append(item)
            missing.remove(key)
    return (*visible, *extra)


def _group_label(group: str, zone: str | None) -> str:
    return group if zone is None else f"{group} · зона {zone}"


def _requirement_label(identifier: str, zones: MatrixZonePair | None) -> str:
    return identifier if zones is None else f"{identifier} · {zones.source_zone} → {zones.destination_zone}"


def _csv_values(values: Sequence[str]) -> tuple[str, ...]:
    return tuple("'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value for value in values)


def _report_rows(
    artifact: MatrixAssessmentArtifact, indices: Sequence[int] | None,
) -> Sequence[MatrixRequirementAssessment]:
    rows = artifact.assessment.requirements
    return rows if indices is None else [rows[index] for index in indices]


def matrix_report_section(
    artifact: MatrixAssessmentArtifact, indices: Sequence[int] | None = None, *,
    preview_limit: int | None = None,
) -> str:
    result = artifact.assessment
    selection = _report_rows(artifact, indices)
    rows = selection if preview_limit is None else selection[:preview_limit]
    groups = {group.group_id: group.name for group in artifact.matrix.groups}
    requirements = {row.requirement_id: row for row in artifact.matrix.requirements}
    requirement_counts = Counter(row.requirement_id for row in artifact.matrix.requirements)
    boundaries = {row.boundary_id: row for row in artifact.matrix.boundaries}
    boundary_counts = Counter(row.boundary_id for row in artifact.matrix.boundaries)
    counts = Counter(row.state for row in selection)
    configuration = artifact.revision.parse_result.configuration
    parts = [
        f"<section><h2>Матрица доступа — {_escape(MATRIX_MODE_LABELS[result.mode])}</h2>",
        f"<p>{_escape(_STATUS_LABELS[result.status])}. "
        f"Записей во всей сверке: {len(result.requirements)} из "
        f"{len(artifact.matrix.requirements) + len(artifact.matrix.boundaries)}.</p>",
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
    if indices is not None:
        parts.insert(2, f"<p>В выборке {len(selection)} из {len(result.requirements)} записей сверки.</p>")
    if len(rows) < len(selection):
        parts.insert(2, f"<p>В предпросмотре показано {len(rows)} из {len(selection)} записей выборки.</p>")
    if artifact.profile_settings_json is None:
        parts.append("<li>Параметры исходного профиля не сохранены; доступна только его ссылка.</li>")
    parts.append("</ul>")
    if artifact.cloud_selection is not None:
        cloud = artifact.cloud_selection
        heading = (
            f"<p>Облачный сбор {_escape(cloud.scan_id)} · интерфейс {_escape(cloud.interface_id)} · "
            f"{_escape(cloud.direction)} IPv{cloud.family}."
        )
        order = cloud.order_evidence
        if order is not None:
            heading += (f" Порядок групп Advanced: {_escape(' → '.join(order.group_ids))}. "
                        f"Запись {_escape(order.source_name)} / {_escape(order.source_reference)} "
                        f"от {_escape(order.observed_at.isoformat())}.")
        elif cloud.group_id:
            heading += f" Группа {_escape(cloud.group_id)}."
        else:
            heading += " Объявленные разрешения всех назначенных групп Evolution."
        parts.append(heading + "</p>")
    context_sources = matrix_context_sources_by_digest(artifact.context_inputs)
    context_origins = {}
    for digest, context in context_sources.items():
        snapshot = context.snapshot
        context_origins[digest] = {
            fact.evidence_id: fact.origin
            for facts in (snapshot.memberships, snapshot.devices, snapshot.sessions, snapshot.pools)
            for fact in facts
        }
        parts.append(
            f"<p>Сведения о сеансах: снимок {_escape(snapshot.captured_at.isoformat())}, "
            f"оценка на {_escape(context.evaluated_at.isoformat())}, контекст {_escape(snapshot.context_id)}. "
            "Адресная проверка относится к выбранным сеансам.</p>"
        )
    if artifact.matrix.set_assignments and preview_limit is None:
        versions = {version.revision_id: version for version in artifact.matrix.requirement_sets}
        parts.append("<details><summary>Закреплённые наборы требований</summary><ul>")
        for assignment in artifact.matrix.set_assignments:
            version = versions[assignment.revision_id]
            parts.append(
                f"<li>{_escape(version.name)} v{version.version} · {_escape(version.revision_id)} · "
                f"{_escape(assignment.axis)}: {_escape(', '.join(assignment.group_ids))}</li>"
            )
        parts.append("</ul></details>")
    if artifact.bindings and preview_limit is None:
        parts.append("<details><summary>Сохранённый состав ссылок каталога</summary><ul>")
        parts.extend(
            f"<li>{_escape(binding.value)}"
            + (f" · VRF {_escape(binding.vrf)}" if binding.vrf else "")
            + f" · {_escape(', '.join(binding.cidrs))}</li>"
            for binding in artifact.bindings
        )
        parts.append("</ul></details>")
    if result.diagnostics:
        parts.append("<h3>Диагностика всей матрицы</h3><ul>")
        diagnostics = result.diagnostics if preview_limit is None else result.diagnostics[:preview_limit]
        parts.extend(
            f"<li>{_escape(issue.code)}: {_escape(issue.message)}; "
            f"группы {_escape(', '.join(issue.group_ids))}; "
            f"требования {_escape(', '.join(issue.requirement_ids))}</li>"
            for issue in diagnostics
        )
        if len(diagnostics) < len(result.diagnostics):
            parts.append(f"<li>В полном HTML доступно сообщений: {len(result.diagnostics)}.</li>")
        parts.append("</ul>")
    parts.append(
        "<h3>Требования и результаты</h3><table><thead><tr><th>ID</th><th>Источник</th>"
        "<th>Назначение</th><th>Сервис</th><th>Требование</th><th>Результат и основание</th>"
        "</tr></thead><tbody>"
    )
    for row in rows:
        row_mode = MATRIX_MODE_LABELS[row.mode or result.mode]
        coverage = ", частичный охват" if row.coverage_complete is False else ""
        if row.attachment_limited:
            coverage += ", нужны данные о пути"
        outcome = f"{MATRIX_STATE_LABELS[row.state]} ({row_mode}{coverage}): " + "; ".join(row.reasons)
        if requirement_counts[row.requirement_id] + boundary_counts[row.requirement_id] != 1:
            cells = (
                row.requirement_id, "Неоднозначный ID", "Неоднозначный ID", "См. диагностику",
                "См. сохранённую матрицу", outcome,
            )
            parts.append("<tr>" + "".join(f"<td>{_escape(cell)}</td>" for cell in cells) + "</tr>")
            continue
        requirement = requirements.get(row.requirement_id)
        subject = requirement if requirement is not None else boundaries[row.requirement_id]
        zones = subject.zone_pair
        cells = (
            row.requirement_id,
            _group_label(groups.get(subject.source_group, subject.source_group), zones.source_zone if zones else None),
            _group_label(groups.get(subject.destination_group, subject.destination_group),
                         zones.destination_zone if zones else None),
            matrix_service_label(subject.service),
            _REQUIREMENT_LABELS[requirement.requirement] if requirement is not None else "Только перечисленный доступ",
            outcome,
        )
        parts.append("<tr>" + "".join(f"<td>{_escape(cell)}</td>" for cell in cells) + "</tr>")
    parts.append("</tbody></table><h3>Доказательства</h3>")
    for row in rows:
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
        if boundary_counts[row.requirement_id] == 1:
            boundary = boundaries[row.requirement_id]
            parts.append(
                f"<p>Допустимые требования: {_escape(', '.join(boundary.allowed_requirement_ids) or 'нет')}; "
                f"политика: {_escape(boundary.policy_id or 'не указана')}</p>"
            )
        if row.context_resolution is not None:
            context_result = row.context_resolution
            source = context_sources[context_result.snapshot_digest]
            parts.append(
                f"<p>{_escape(context_result.message)} · сеанс {_escape(context_result.session_id or 'не указан')} · "
                f"адрес {_escape(context_result.source_cidr or 'не подтверждён')} · "
                f"контекст {_escape(source.snapshot.context_id)} · "
                f"SHA-256 снимка {_escape(context_result.snapshot_digest)}.</p>"
            )
            for identifier in context_result.evidence_ids:
                origin = context_origins[context_result.snapshot_digest][identifier]
                parts.append(
                    f"<p>Свидетельство {_escape(identifier)} · {_escape(origin.source_name)} / "
                    f"{_escape(origin.record_id)} · {_escape(origin.observed_at.isoformat())}</p>"
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


def matrix_report_html(
    artifact: MatrixAssessmentArtifact, indices: Sequence[int] | None = None, *,
    preview_limit: int | None = None,
) -> str:
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width"><title>Сверка матрицы доступа</title>'
        "<style>body{font:16px/1.5 'Segoe UI',sans-serif;margin:24px;color:#203047}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #b6c4d6;"
        "padding:8px;text-align:left;overflow-wrap:anywhere}p{overflow-wrap:anywhere}</style>"
        "</head><body>" + matrix_report_section(artifact, indices, preview_limit=preview_limit) + "</body></html>"
    )


def matrix_report_csv(artifact: MatrixAssessmentArtifact, indices: Sequence[int] | None = None) -> str:
    stream = StringIO(newline="")
    writer = csv.writer(stream)
    headings: tuple[str, ...] = (
        "Сверка", "Матрица", "Версия", "Ревизия", "Область", "Режим", "Ход вычисления", "Требование",
        "Результат", "Основания", "Правила", "Ограничения", "Источник", "Назначение", "Сервис",
        "Ожидаемое условие", "Охват", "Применимость к пути", "Сеанс", "IP сеанса",
        "Зона источника", "Зона назначения",
    )
    policy_vrfs = matrix_catalog_switch_policy_contexts(artifact.revision)
    if policy_vrfs:
        headings += ("VRF политики",)
    multiple_contexts = bool(artifact.context_inputs and artifact.context_inputs.additional_contexts)
    context_sources = matrix_context_sources_by_digest(artifact.context_inputs) if multiple_contexts else {}
    if multiple_contexts:
        headings += ("Сетевой контекст снимка сеансов", "Время сеанса")
    writer.writerow(headings)
    groups = {group.group_id: group.name for group in artifact.matrix.groups}
    rows = {row.requirement_id: row for row in artifact.matrix.requirements}
    boundaries = {row.boundary_id: row for row in artifact.matrix.boundaries}
    counts = Counter(row.requirement_id for row in artifact.matrix.requirements)
    counts.update(row.boundary_id for row in artifact.matrix.boundaries)
    for row in _report_rows(artifact, indices):
        identifier = row.requirement_id
        requirement = rows.get(identifier)
        subject = (requirement or boundaries.get(identifier)) if counts[identifier] == 1 else None
        service = subject.service if subject is not None else None
        zones = subject.zone_pair if subject is not None else None
        context = row.context_resolution
        values: tuple[str, ...] = (
            str(artifact.artifact_id), artifact.matrix.matrix_id, artifact.matrix.version,
            str(artifact.revision.revision_id), artifact.assessment.scope_id,
            MATRIX_MODE_LABELS[row.mode or artifact.assessment.mode], _STATUS_LABELS[artifact.assessment.status],
            identifier, MATRIX_STATE_LABELS[row.state], "; ".join(row.reasons),
            ", ".join(dict.fromkeys(key for evidence in row.evidence for key in evidence.related_rule_ids)),
            "; ".join(artifact.assessment.limitations),
            groups.get(subject.source_group, subject.source_group) if subject is not None else "",
            groups.get(subject.destination_group, subject.destination_group) if subject is not None else "",
            matrix_service_label(service) if service is not None else "",
            (_REQUIREMENT_LABELS[requirement.requirement] if requirement is not None else "Только перечисленный доступ")
            if subject is not None else "",
            "Частичный" if row.coverage_complete is False else "Полный" if row.coverage_complete is True else "",
            "Нужны данные о пути" if row.attachment_limited else "",
            (context.session_id or "") if context else "", (context.source_cidr or "") if context else "",
            zones.source_zone if zones else "", zones.destination_zone if zones else "",
        )
        if policy_vrfs:
            values += (policy_vrfs.get(subject.policy_id or "", "") if subject is not None else "",)
        if multiple_contexts:
            source = context_sources.get(context.snapshot_digest) if context is not None else None
            values += (
                source.snapshot.context_id if source is not None else "",
                context.evaluated_at.isoformat() if context is not None and context.evaluated_at else "",
            )
        writer.writerow(_csv_values(values))
    return stream.getvalue()


def matrix_scope_source_notes(result: MatrixScopeAssessment) -> dict[str, tuple[str, ...]]:
    notes: dict[str, list[str]] = defaultdict(list)
    for diagnostic in result.diagnostics:
        if diagnostic.code.startswith("cloud_") or diagnostic.code == SOURCE_FALLBACK_NOTE:
            for identifier in diagnostic.requirement_ids:
                notes[identifier].append(diagnostic.message)
    return {identifier: tuple(dict.fromkeys(messages)) for identifier, messages in notes.items()}


def matrix_scope_report_section(
    artifact_id: str, result: MatrixScopeAssessment, matrix: AccessMatrix, *,
    run_id: str, preview_limit: int | None = None,
) -> str:
    relation = result.run_report_relation(run_id)
    if relation is None:
        raise ValueError("Сверка области не связана с запуском отчёта")
    origin = (
        "Этот запуск выбран для исторического среза."
        if relation == "historical_baseline" else "Ревизии из этого запуска использованы в оценке требований."
    )
    scope = f"Площадка {_escape(result.selected_site_id)}" if result.selected_site_id else "Область проекта"
    counts = Counter(row.assessment.state for row in result.requirements)
    group_counts = Counter(group.group_id for group in matrix.groups)
    groups = {group.group_id: group.name for group in matrix.groups if group_counts[group.group_id] == 1}
    requirements = [("requirement", row.requirement_id, row.service) for row in matrix.requirements
                    if row.scope_id == result.scope_id]
    requirements.extend(("boundary", row.boundary_id, row.service) for row in matrix.boundaries
                        if row.scope_id == result.scope_id)
    requirement_counts = Counter((kind, identifier) for kind, identifier, _ in requirements)
    services = {(kind, identifier): service for kind, identifier, service in requirements
                if requirement_counts[kind, identifier] == 1}
    sources = {source.revision_id: source for source in result.sources}
    rows = result.requirements
    if preview_limit is not None:
        def needs_attention(row: MatrixScopeRowAssessment) -> bool:
            return row.assessment.state not in {"declared_match", "not_applicable", "unregulated"} or (
                row.assessment.coverage_complete is False or row.assessment.attachment_limited
            )

        attention = tuple(islice((row for row in rows if needs_attention(row)), preview_limit))
        rows = attention + tuple(islice((row for row in rows if not needs_attention(row)), preview_limit - len(attention)))
    parts = [
        "<section><h3>Сверка области матрицы</h3>",
        f"<p>{scope} · {_escape(_STATUS_LABELS[result.status])} · {_escape(MATRIX_MODE_LABELS[result.mode])}<br>"
        f"{origin} Показан сохранённый результат всей области сверки.</p>",
        f"<p>Сверка {_escape(artifact_id)} от {_escape(result.created_at.isoformat())}<br>"
        f"Матрица {_escape(result.matrix_id)} / v{_escape(result.matrix_version)} · "
        f"профиль {_escape(result.profile_id)} / {_escape(result.profile_version)} · "
        f"приложение {_escape(result.application_version)}</p>",
        f"<p>Оценено {len(result.requirements)} из {result.total_requirements}. "
        + " · ".join(f"{_escape(MATRIX_STATE_LABELS[key])}: {count}" for key, count in counts.items()) + "</p>",
        "<h4>Полнота и ограничения</h4><ul>",
    ]
    parts.extend(f"<li>{_escape(value)}</li>" for value in result.limitations)
    parts.append("</ul>")
    if len(rows) < len(result.requirements):
        parts.append(f"<p>В предпросмотре показано {len(rows)} из {len(result.requirements)} строк. "
                     "В экспорт попадут все строки.</p>")
    parts.append("<table><thead><tr><th>Требование</th><th>Результат и основания</th>"
                 "<th>Источник оценки</th></tr></thead><tbody>")
    notes = matrix_scope_source_notes(result)
    for row in rows:
        assessment = row.assessment
        service = services.get((row.kind, row.requirement_id))
        source = sources.get(row.revision_id) if row.revision_id is not None else None
        requirement = (
            f"{_escape(row.requirement_id)}<br>{_escape(groups.get(row.source_group, row.source_group))} → "
            f"{_escape(groups.get(row.destination_group, row.destination_group))}"
        )
        if service is not None:
            requirement += f"<br>{_escape(matrix_service_label(service))}"
        if row.zone_pair is not None:
            requirement += f"<br>Зоны {_escape(row.zone_pair.source_zone)} → {_escape(row.zone_pair.destination_zone)}"
        decision = [_escape(MATRIX_STATE_LABELS[assessment.state])]
        if assessment.attachment_limited:
            decision.append("Нужны данные о пути")
        decision.extend(_escape(value) for value in dict.fromkeys((*assessment.reasons, *notes.get(row.requirement_id, ()))))
        evidence_rows = assessment.evidence if preview_limit is None else matrix_evidence_preview(assessment.evidence)
        for evidence in evidence_rows:
            fields = [evidence.summary, *evidence.related_rule_ids]
            if fragment := matrix_packet_detail(evidence):
                fields.append(fragment)
            fields.extend(
                f"{location.source_name} · {location.object_path or location.line_start or location.object_id or '—'}"
                for location in evidence.source_locations
            )
            decision.append(_escape(" · ".join(fields)))
        if len(evidence_rows) < len(assessment.evidence):
            decision.append(f"Ещё {len(assessment.evidence) - len(evidence_rows)} оснований в экспорте")
        provenance = [_escape(row.policy_id)] if row.policy_id else []
        if source is not None:
            cloud = source.cloud_selection or source.vmware_origin
            provenance.extend((_escape(source.device_label), f"Ревизия {_escape(source.revision_id)}"))
            if source.run_id is not None:
                provenance.append(f"Запуск {_escape(source.run_id)}")
            elif cloud is not None:
                provenance.append(f"Облачный сбор {_escape(cloud.scan_id)}")
        else:
            provenance.append("Снимок для оценки не назначен")
            if candidates := result.candidate_revisions(row):
                provenance.append(f"Подходящих снимков {len(candidates)}")
        if row.policy_vrf is not None:
            provenance.append(f"VRF {_escape(row.policy_vrf)}")
        parts.append(f"<tr><td>{requirement}</td><td>{'<br>'.join(decision)}</td>"
                     f"<td>{'<br>'.join(provenance)}</td></tr>")
    parts.append("</tbody></table></section>")
    return "\n".join(parts)


def matrix_scope_report_csv(
    result: MatrixScopeAssessment, indices: Sequence[int], *, matrix: AccessMatrix | None = None,
) -> str:
    stream = StringIO(newline="")
    writer = csv.writer(stream)
    headings: tuple[str, ...] = (
        "Матрица", "Версия", "Область", "Требование", "Группа источников", "Группа назначений",
        "Политика", "Устройство", "Контекст устройства", "Ревизия", "Запуск", "Облачный сбор",
        "Результат", "Режим", "Подходящих снимков", "Основания", "Правила",
        "Зона источника", "Зона назначения",
    )
    has_vrf = any(row.policy_vrf is not None for row in result.requirements)
    if has_vrf:
        headings += ("VRF политики",)
    if result.context_inputs is not None:
        headings += ("Сеанс", "Адрес сеанса", "Время сеанса", "Сетевой контекст снимка сеансов", "Свидетельства сеанса")
    boundary_groups = evaluate_boundary_groups(matrix, result) if matrix is not None and matrix.boundary_groups else ()
    grouped_points: dict[str, list[tuple[str, ...]]] = {}
    if boundary_groups:
        headings += (
            "ID общего ограничения", "Общее ограничение", "Вывод по общему ограничению",
            "Точка контроля", "Охват точки контроля",
        )
        for summary in boundary_groups:
            group = summary.group
            group_result = _boundary_group_result(summary)
            for point in summary.points:
                identifier = point.boundary.boundary_id
                point_name = group.point_names.get(identifier, identifier)
                point_result = MATRIX_BOUNDARY_POINT_LABELS[point.status]
                if point.gap:
                    point_result += f" · {point.gap}"
                grouped_points.setdefault(identifier, []).append((
                    group.group_id, group.name, group_result, point_name, point_result,
                ))
    writer.writerow(headings)
    context_sources = matrix_context_sources_by_digest(result.context_inputs)
    sources = {source.revision_id: source for source in result.sources}
    source_notes = matrix_scope_source_notes(result)
    for index in indices:
        row = result.requirements[index]
        assessment = row.assessment
        zones = row.zone_pair
        source = sources.get(row.revision_id) if row.revision_id is not None else None
        cloud = (source.cloud_selection or source.vmware_origin) if source is not None else None
        state = MATRIX_STATE_LABELS[assessment.state]
        if assessment.attachment_limited:
            state += " · Нужны данные о пути"
        candidates = len(result.candidate_revisions(row))
        values: tuple[str, ...] = (
            result.matrix_id, result.matrix_version, result.scope_id, row.requirement_id, row.source_group,
            row.destination_group, row.policy_id or "", source.device_label if source else "",
            (source.device_context or "") if source else "", str(source.revision_id) if source else "",
            (source.run_id or "") if source else "", cloud.scan_id if cloud else "", state,
            MATRIX_MODE_LABELS[assessment.mode or result.mode], str(candidates or int(source is not None)),
            "\n".join(dict.fromkeys((*assessment.reasons, *source_notes.get(row.requirement_id, ())))),
            ", ".join(dict.fromkeys(key for evidence in assessment.evidence for key in evidence.related_rule_ids)),
            zones.source_zone if zones else "", zones.destination_zone if zones else "",
        )
        if has_vrf:
            values += (row.policy_vrf or "",)
        if result.context_inputs is not None:
            context = assessment.context_resolution
            context_source = context_sources.get(context.snapshot_digest) if context is not None else None
            values += (
                context.session_id or "", context.source_cidr or "",
                context.evaluated_at.isoformat() if context.evaluated_at else "",
                context_source.snapshot.context_id if context_source is not None else "", ", ".join(context.evidence_ids),
            ) if context is not None else ("", "", "", "", "")
        if boundary_groups:
            points = grouped_points.get(row.requirement_id) if row.kind == "boundary" else None
            values += tuple("\n".join(field) for field in zip(*points, strict=True)) if points else ("",) * 5
        writer.writerow(_csv_values(values))
    return stream.getvalue()


def matrix_comparison_html(
    before: MatrixAssessmentArtifact, after: MatrixAssessmentArtifact, *, preview_limit: int | None = None,
) -> str:
    changes = compare_matrix_assessments(before, after)
    counts = Counter(change.state for change in changes)
    zones_by_id = {row.requirement_id: row.zone_pair for row in after.matrix.requirements}
    zones_by_id.update((row.boundary_id, row.zone_pair) for row in after.matrix.boundaries)
    parts = [
        '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Сравнение сверок</title><body>',
        '<h1>Изменения результатов сверки</h1>',
        f'<p>Матрица v{_escape(after.matrix.version)}; область {_escape(after.assessment.scope_id)}.</p>',
        f'<p>Было: {_escape(before.created_at.isoformat())}, {_escape(before.artifact_id)}<br>',
        f'Стало: {_escape(after.created_at.isoformat())}, {_escape(after.artifact_id)}</p>',
        f'<p>Изменился результат: {counts["changed"]}; изменились основания: {counts["evidence_changed"]}; '
        f'без видимых изменений: {counts["unchanged"]}; '
        f'недостаточно данных для сравнения: {counts["inconclusive"]}.</p>',
        '<p>Изменения описывают проверенные политики. Для вывода о пути нужны отдельные данные.</p>',
        '<table border="1" cellpadding="5"><thead><tr><th>ID</th><th>Было</th><th>Стало</th>'
        '<th>Сравнение</th></tr></thead><tbody>',
    ]
    visible = [change for change in changes if change.state != "unchanged"]
    if preview_limit is not None and len(visible) > preview_limit:
        parts.insert(-1, f"<p>В предпросмотре {preview_limit} из {len(visible)} строк сравнения.</p>")
    labels = {
        "changed": "Статус изменился", "evidence_changed": "Изменились основания или применимость",
        "inconclusive": "Недостаточно данных",
    }
    for change in visible[:preview_limit]:
        previous, current = change.before, change.after
        cells = (
            _requirement_label(change.requirement_id, zones_by_id.get(change.requirement_id)),
            (MATRIX_STATE_LABELS[previous.state] + (" · Нужны данные о пути" if previous.attachment_limited else ""))
            if previous else "Нет результата",
            (MATRIX_STATE_LABELS[current.state] + (" · Нужны данные о пути" if current.attachment_limited else ""))
            if current else "Нет результата",
            labels[change.state],
        )
        parts.append("<tr>" + "".join(f"<td>{_escape(cell)}</td>" for cell in cells) + "</tr>")
    parts.append("</tbody></table></body></html>")
    return "\n".join(parts)


def matrix_scope_comparison_html(
    before: MatrixScopeAssessment, after: MatrixScopeAssessment, *,
    preview_limit: int | None = None, matrix: AccessMatrix | None = None,
    changes: Sequence[MatrixScopeChange] | None = None,
) -> str:
    if matrix is not None and matrix_scope_checksum(matrix) != after.matrix_checksum:
        raise ValueError("Версия требований не совпадает с сохранённой сверкой")
    if (before.project_id, before.scope_id, before.selected_site_id, before.matrix_checksum) != (
        after.project_id, after.scope_id, after.selected_site_id, after.matrix_checksum,
    ):
        raise ValueError("Для отчёта нужны сверки одной области и утверждённой версии матрицы")
    if changes is None:
        changes = compare_matrix_scope_assessments(before, after, matrix=matrix)
    groups = {group.group_id: group.name for group in matrix.groups} if matrix is not None else {}
    services = {}
    if matrix is not None:
        services.update((("requirement", row.requirement_id), row.service) for row in matrix.requirements)
        services.update((("boundary", row.boundary_id), row.service) for row in matrix.boundaries)
    old_sources = {source.revision_id: source for source in before.sources}
    new_sources = {source.revision_id: source for source in after.sources}
    old_notes, new_notes = matrix_scope_source_notes(before), matrix_scope_source_notes(after)

    def details(
        row: MatrixScopeRowAssessment | None, sources: Mapping[UUID, MatrixScopeSource],
        notes: Mapping[str, Sequence[str]],
    ) -> str:
        if row is None:
            return "Нет строки"
        assessment = row.assessment
        lines = [_escape(MATRIX_STATE_LABELS[assessment.state])]
        source = sources.get(row.revision_id) if row.revision_id is not None else None
        if source is not None:
            lines.append(_escape(
                f"{source.device_label} · {source.captured_at.isoformat()}"
                + (f" · {source.device_context}" if source.device_context else "")
            ))
            lines.append(_escape(f"Ревизия · {source.revision_id}"))
            if source.cloud_selection is not None:
                cloud = source.cloud_selection
                lines.append(_escape(f"Сбор · {cloud.scan_id} · интерфейс {cloud.interface_id}"))
            if source.vmware_origin is not None:
                vmware = source.vmware_origin
                lines.append(_escape(f"Сбор VMware · {vmware.scan_id} · Edge Gateway {vmware.resource_id}"))
        if row.policy_vrf is not None:
            lines.append(_escape(f"VRF политики · {row.policy_vrf}"))
        if context := assessment.context_resolution:
            lines.append(_escape(context.message))
            if context.session_id:
                lines.append(_escape(f"Сеанс · {context.session_id}"))
            if context.source_cidr:
                lines.append(_escape(f"Адрес сеанса · {context.source_cidr}"))
        lines.extend(_escape(reason) for reason in dict.fromkeys((
            *assessment.reasons, *notes.get(row.requirement_id, ()),
        )))
        evidence = matrix_evidence_preview(assessment.evidence) if preview_limit is not None else assessment.evidence
        if evidence:
            facts = []
            for item in evidence:
                fields = [item.summary]
                if packet := matrix_packet_detail(item):
                    fields.append(packet)
                fields.extend(item.related_rule_ids)
                fields.extend(
                    f"{location.source_name}:{location.object_path or location.line_start or location.object_id or '—'}"
                    for location in item.source_locations
                )
                fields.extend(item.limitations)
                facts.append(f"<li>{_escape(' · '.join(fields))}</li>")
            lines.append("<ul>" + "".join(facts) + "</ul>")
        if len(evidence) < len(assessment.evidence):
            lines.append(f"Показано оснований: {len(evidence)} из {len(assessment.evidence)}.")
        return "<br>".join(lines)
    counts = Counter(change.state for change in changes)
    directions = Counter(change.direction for change in changes)
    visible = [change for change in changes if change.state != "unchanged"]
    parts = [
        '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Сравнение политик области</title><body>',
        '<h1>Сравнение политик области</h1>',
        f'<p>Матрица v{_escape(after.matrix_version)} · область {_escape(after.scope_id)}.</p>',
        f'<p>Было: {_escape(before.created_at.isoformat())}<br>Стало: {_escape(after.created_at.isoformat())}</p>',
        f'<p>Результат изменился: {counts["changed"]} · основания: {counts["evidence_changed"]} · '
        f'изменились источники: {counts["source_changed"]} · без изменений: {counts["unchanged"]} · '
        f'недостаточно данных: {counts["inconclusive"]}.</p>',
        f'<p>Улучшений: {directions["improved"]} · ухудшений: {directions["regressed"]}.</p>',
        '<p>Результаты относятся к сохранённым политикам. Изменение источника само по себе не подтверждает исправление.</p>',
    ]
    for label, result in (("Было", before), ("Стало", after)):
        for note in result.diagnostics:
            if note.code in {HISTORICAL_BASELINE_NOTE, SOURCE_FALLBACK_NOTE}:
                parts.append(f"<p>{label} · {_escape(note.message)}</p>")
    if matrix is not None and matrix.boundary_groups:
        parts.extend(_boundary_group_comparison_html(
            matrix, before, after, groups, {change.requirement_id: change.reason for change in changes},
            preview_limit,
        ))
    if preview_limit is not None and len(visible) > preview_limit:
        parts.append(f'<p>В предпросмотре {preview_limit} из {len(visible)} строк сравнения.</p>')

    def add_table(rows: Sequence[MatrixScopeChange]) -> None:
        if not rows:
            return
        parts.append('<table border="1" cellpadding="5"><thead><tr><th>Требование</th><th>Было</th>'
                     '<th>Стало</th><th>Основание сравнения</th></tr></thead><tbody>')
        for change in rows:
            subject = change.after or change.before
            title = _escape(_requirement_label(change.requirement_id, subject.zone_pair if subject else None))
            if subject is not None:
                source = groups.get(subject.source_group, subject.source_group)
                destination = groups.get(subject.destination_group, subject.destination_group)
                title += f"<br>{_escape(source)} → {_escape(destination)}"
                if subject.kind == "boundary":
                    title += "<br>Закрытая область"
                if service := services.get((subject.kind, change.requirement_id)):
                    title += f"<br>{_escape(matrix_service_label(service))}"
                if subject.policy_id:
                    title += f"<br>{_escape(subject.policy_id)}"
            direction = {"improved": "Устранено отклонение", "regressed": "Появилось отклонение"}.get(
                change.direction or "",
            )
            reason = f"{direction} · {change.reason}" if direction else change.reason
            parts.append(
                f"<tr><td>{title}</td><td>{details(change.before, old_sources, old_notes)}</td>"
                f"<td>{details(change.after, new_sources, new_notes)}</td><td>{_escape(reason)}</td></tr>"
            )
        parts.append("</tbody></table>")

    add_table(visible[:preview_limit])
    if preview_limit is None and counts["unchanged"]:
        parts.append(f'<details><summary>Строки без изменений ({counts["unchanged"]})</summary>')
        add_table([change for change in changes if change.state == "unchanged"])
        parts.append("</details>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _boundary_group_result(summary: MatrixBoundaryGroupAssessment) -> str:
    return (
        f"{MATRIX_BOUNDARY_GROUP_LABELS[summary.state]} · "
        f"точек с лишним разрешением: {summary.excess_count} · пробелов: {summary.gap_count}"
    )


def _boundary_group_comparison_html(
    matrix: AccessMatrix, before: MatrixScopeAssessment, after: MatrixScopeAssessment,
    groups: Mapping[str, str], comparison_reasons: Mapping[str, str],
    preview_limit: int | None,
) -> list[str]:
    old_groups = evaluate_boundary_groups(matrix, before)
    new_groups = evaluate_boundary_groups(matrix, after)
    if not new_groups:
        return []
    parts = [
        "<h2>Общие ограничения доступа</h2>",
        "<p>Сводка относится к перечисленным точкам контроля. Сквозная доступность оценивается отдельно.</p>",
    ]
    total = sum(len(summary.points) for summary in new_groups)
    remaining = total if preview_limit is None else min(total, preview_limit)
    if remaining < total:
        parts.append(f"<p>В предпросмотре {remaining} из {total} точек контроля.</p>")
    for old, new in zip(old_groups, new_groups, strict=True):
        if not remaining:
            break
        group = new.group
        boundary = new.points[0].boundary
        source_group = groups.get(boundary.source_group, boundary.source_group)
        destination_group = groups.get(boundary.destination_group, boundary.destination_group)
        parts.extend((
            f"<h3>{_escape(group.group_id)} · {_escape(group.name)}</h3>",
            f"<p>{_escape(source_group)} → {_escape(destination_group)} · "
            f"{_escape(matrix_service_label(boundary.service))}</p>",
            f"<p>Было · {_escape(_boundary_group_result(old))}<br>"
            f"Стало · {_escape(_boundary_group_result(new))}</p>",
            '<table border="1" cellpadding="5"><thead><tr><th>Точка контроля</th>'
            "<th>Было</th><th>Стало</th><th>Сопоставимость</th></tr></thead><tbody>",
        ))
        for left, right in islice(zip(old.points, new.points, strict=True), remaining):
            boundary = right.boundary
            identifier = boundary.boundary_id
            point_title = group.point_names.get(identifier)
            title = _escape(f"{point_title} · {identifier}" if point_title else identifier)
            if boundary.policy_id is not None:
                title += f"<br>{_escape(boundary.policy_id)}"
            states = []
            for point in (left, right):
                lines = [MATRIX_BOUNDARY_POINT_LABELS[point.status]]
                if point.status == "unverified" and point.row is not None and point.row.routing == "resolved":
                    lines.append(MATRIX_STATE_LABELS[point.row.assessment.state])
                if point.source is not None:
                    lines.append(f"{point.source.device_label} · {point.source.captured_at.isoformat()}")
                if point.gap:
                    lines.append(point.gap)
                states.append("<br>".join(map(_escape, lines)))
            reason = comparison_reasons.get(identifier, "В сохранённых результатах нет оценки точки.")
            parts.append(
                f"<tr><td>{title}</td><td>{states[0]}</td><td>{states[1]}</td><td>{_escape(reason)}</td></tr>"
            )
            remaining -= 1
        parts.append("</tbody></table>")
    return parts
