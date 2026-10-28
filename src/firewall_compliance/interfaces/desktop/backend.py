"""Согласованная сессия анализа и представление результатов для desktop UI."""

import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

from firewall_compliance import __version__
from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.analysis.management_checks import management_checks
from firewall_compliance.analysis.policy_checks import (
    AnyAnyCheck,
    CommentsCheck,
    DisabledRulesCheck,
    DuplicateRulesCheck,
    LoggingCheck,
    MergeCandidateCheck,
    PartialShadowedRulesCheck,
    PolicyCheck,
    ShadowedRulesCheck,
    UnionShadowedRulesCheck,
)
from firewall_compliance.analysis.policy_exposure import (
    DangerousServicesCheck,
    UntrustedAdministrativeAccessCheck,
)
from firewall_compliance.analysis.revision_diff import compare_device_revisions
from firewall_compliance.domain import Device, DeviceRevision, RevisionSource, SourceDocumentKind
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.configuration import Configuration, Rule
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.network import Endpoint, Service
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.domain.revision import DeviceRevisionDiff
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.interfaces.desktop.demo import (
    DemoWorkspace,
    DeviceView,
    FindingView,
    RuleRow,
    SeverityLabel,
)
from firewall_compliance.parsers import (
    ParseFailure,
    ParseRequest,
    SourceDocument,
)
from firewall_compliance.parsers.catalog import create_default_registry


@dataclass(frozen=True)
class AnalysisSession:
    """Исходный документ, снимок и отчёт одного фонового задания."""

    job_id: UUID
    path: Path
    source: SourceDocument
    parse_result: ParseResult
    revision: DeviceRevision
    report: FirewallAssuranceResult


def selected_checks(
    enabled_check_ids: tuple[str, ...] | None,
    management_profile: ManagementProfile | None = None,
    policy_exposure_profile: PolicyExposureProfile | None = None,
) -> tuple[PolicyCheck, ...] | None:
    """Проверить явный выбор проверок, сохранив прежний каталог по умолчанию."""
    if enabled_check_ids is None:
        return None
    catalog: tuple[PolicyCheck, ...] = (
        AnyAnyCheck(),
        DuplicateRulesCheck(),
        ShadowedRulesCheck(),
        MergeCandidateCheck(),
        LoggingCheck(),
        CommentsCheck(),
        DisabledRulesCheck(),
        PartialShadowedRulesCheck(),
        UnionShadowedRulesCheck(),
        DangerousServicesCheck(policy_exposure_profile),
        UntrustedAdministrativeAccessCheck(policy_exposure_profile),
        *management_checks(management_profile),
    )
    known = {check.check_id for check in catalog}
    if not enabled_check_ids or set(enabled_check_ids) - known:
        raise ValueError("Выберите хотя бы одну известную проверку")
    return tuple(check for check in catalog if check.check_id in enabled_check_ids)


def analyze_file(
    path: Path,
    *,
    job_id: UUID | None = None,
    device_id: str | None = None,
    require_logging: bool = True,
    require_comments: bool = True,
    enabled_check_ids: tuple[str, ...] | None = None,
    management_profile: ManagementProfile | None = None,
    configuration_complete: bool = False,
    policy_exposure_profile: PolicyExposureProfile | None = None,
) -> AnalysisSession | ParseFailure:
    """Прочитать и разобрать файл один раз; исключения обрабатывает граница задания."""
    source = FileSourceReader().read(path)
    source = SourceDocument.model_validate(
        {**source.model_dump(), "configuration_complete": configuration_complete}
    )
    imported_at = datetime.now(UTC)
    outcome = create_default_registry().parse(ParseRequest(source=source, imported_at=imported_at))
    if isinstance(outcome, ParseFailure):
        return outcome
    if device_id is not None:
        payload = outcome.configuration.model_dump()
        payload["device_id"] = device_id
        configuration = Configuration.model_validate(payload)
        outcome = ParseResult.model_validate(
            {**outcome.model_dump(), "configuration": configuration.model_dump()}
        )
    configuration = outcome.configuration
    revision = DeviceRevision(
        device=Device(
            device_id=configuration.device_id,
            vendor=configuration.vendor,
            platform=configuration.platform,
        ),
        parse_result=outcome,
        sources=(
            RevisionSource(
                source_name=source.source_name,
                content_sha256=source.content_sha256,
                captured_at=source.captured_at,
                file_modified_at=source.file_modified_at,
                observation=source.observation,
                kind=SourceDocumentKind.CONFIGURATION,
            ),
        ),
        application_version=__version__,
        observed_at=source.observation.observed_at if source.observation else None,
        imported_at=imported_at,
    )
    report = analyze_firewall(
        revision,
        require_logging=require_logging,
        require_comments=require_comments,
        checks=selected_checks(enabled_check_ids, management_profile, policy_exposure_profile),
        management_profile=management_profile,
    )
    return AnalysisSession(job_id or uuid4(), path.resolve(), source, outcome, revision, report)


def _endpoints(values: tuple[Endpoint, ...], status: str) -> str:
    if not values:
        return f"Нет значений · {status}"
    return (
        "; ".join(
            f"{item.name} [{item.kind.value}; {item.resolution_status.value}]"
            + (" · " + ", ".join(item.cidrs) if item.cidrs else "")
            + (
                " · " + ", ".join(f"{r.start}–{r.end}" for r in item.ip_ranges)
                if item.ip_ranges
                else ""
            )
            + (f" · {item.fqdn}" if item.fqdn else "")
            for item in values
        )
        + f" · {status}"
    )


def _services(values: tuple[Service, ...], status: str) -> str:
    if not values:
        return f"Нет значений · {status}"
    return (
        "; ".join(
            f"{item.name} [{item.protocol.value}; {item.resolution_status.value}]"
            + (
                " · " + ", ".join(f"{r.start}–{r.end}" for r in item.port_ranges)
                if item.port_ranges
                else ""
            )
            for item in values
        )
        + f" · {status}"
    )


def _rule_row(session: AnalysisSession, rule: Rule) -> RuleRow:
    action = {"allow": "Разрешить", "deny": "Запретить"}.get(rule.action.value, rule.action.value)
    return (
        session.report.device_id,
        str(session.report.revision_id),
        rule.sequence,
        f"{rule.name} · {rule.rule_id} · {rule.policy_id or 'область неизвестна'}",
        _endpoints(rule.sources, rule.source_status.value),
        _endpoints(rule.destinations, rule.destination_status.value),
        _services(rule.services, rule.service_status.value),
        action if rule.enabled else "Отключено",
        f"{rule.logging_enabled} · {rule.logging_status.value}",
    )


def view_workspace(sessions: tuple[AnalysisSession, ...]) -> DemoWorkspace:
    """Создать UI DTO без исходных строк и без подмены backend-контрактов."""
    devices: list[DeviceView] = []
    findings: list[FindingView] = []
    rules: list[RuleRow] = []
    severities = {
        "critical": "Критическая",
        "high": "Высокая",
        "medium": "Средняя",
        "low": "Низкая",
        "info": "Информационная",
    }
    for session in sessions:
        report = session.report
        parsed = session.parse_result
        completeness = (
            "Частичная"
            if parsed.errors
            or parsed.unsupported_constructs
            or any(check.status.value == "partial" for check in report.checks)
            or parsed.coverage.coverage_ratio < 1
            else "В границах проверок"
        )
        devices.append(
            DeviceView(
                report.device_id,
                parsed.configuration.platform,
                str(report.revision_id),
                "Время наблюдения неизвестно",
                completeness,
            )
        )
        rules.extend(_rule_row(session, rule) for rule in parsed.rules)
        rules_by_id = {rule.rule_id: rule for rule in parsed.rules}
        for check in report.checks:
            for finding in check.findings:
                related = [
                    rules_by_id[key] for key in finding.affected_rule_ids if key in rules_by_id
                ]
                evidence = {
                    "finding_id": str(finding.finding_id),
                    "check_id": check.check_id,
                    "check_version": check.check_version,
                    "check_status": check.status.value,
                    "check_limitations": [x.model_dump(mode="json") for x in check.limitations],
                    "revision_id": str(report.revision_id),
                    "configuration_id": str(report.configuration_id),
                    "device_id": report.device_id,
                    "status": finding.status.value,
                    "confidence": finding.confidence,
                    "evidence": finding.evidence.model_dump(mode="json"),
                }
                findings.append(
                    FindingView(
                        str(finding.finding_id),
                        report.device_id,
                        str(report.revision_id),
                        cast(SeverityLabel, severities[finding.severity.value]),
                        finding.title,
                        ", ".join(finding.affected_rule_ids) or "Правило не указано",
                        "; ".join(_endpoints(r.sources, r.source_status.value) for r in related)
                        or "Не указано",
                        "; ".join(
                            _endpoints(r.destinations, r.destination_status.value) for r in related
                        )
                        or "Не указано",
                        "; ".join(_services(r.services, r.service_status.value) for r in related)
                        or "Не указано",
                        finding.description,
                        json.dumps(evidence, ensure_ascii=False, indent=2),
                        f"Проверка: {check.status.value}. "
                        + " ".join(
                            (*finding.evidence.limitations, *(x.message for x in check.limitations))
                        )
                        + " Сетевые данные неизвестны; достижимость не вычисляется.",
                        finding.recommendation,
                    )
                )
    return DemoWorkspace(tuple(devices), tuple(findings), tuple(rules))


def diagnostic_lines(session: AnalysisSession) -> tuple[str, ...]:
    """Сохранить полноту проверок, версии и parser diagnostics в отображении."""
    report = session.report
    lines = [
        f"Источник: {session.source.source_name}",
        f"SHA-256: {session.source.content_sha256}",
        f"Ревизия: {report.revision_id}",
        f"Отчёт {report.schema_version}; parser {report.parser_version}; "
        f"каталог {report.check_catalog_version}",
        "Время наблюдения неизвестно; дата импорта не доказывает актуальность устройства.",
        "Интерфейсы, маршруты, NAT и итоговая достижимость: unknown.",
        "Покрытие: " + json.dumps(report.parse_coverage.model_dump(mode="json")),
    ]
    for check in report.checks:
        lines.append(
            f"{check.check_id} [{check.check_version}]: {check.status.value}; "
            f"находок {len(check.findings)}"
        )
        lines.extend(
            json.dumps(x.model_dump(mode="json"), ensure_ascii=False) for x in check.limitations
        )
    for issue in (*report.parse_warnings, *report.parse_errors, *report.unsupported_constructs):
        lines.append(json.dumps(issue.model_dump(mode="json"), ensure_ascii=False))
    lines.append("Ноль находок не означает успешный аудит или безопасность устройства.")
    return tuple(lines)


def source_preview(session: AnalysisSession, location: SourceLocation) -> str:
    """Показать только проверенный фрагмент сохранённого в памяти источника."""
    configuration = session.parse_result.configuration
    if (
        session.source.content_sha256 != configuration.content_sha256
        or session.source.source_name != configuration.source_name
        or location.source_name != session.source.source_name
    ):
        raise ValueError("Источник фрагмента не совпадает с проверенным документом")
    if location.line_start is None:
        raise ValueError("Позиция не содержит номеров строк")
    lines = session.source.content.decode("utf-8", errors="replace").splitlines()
    end = location.line_end or location.line_start
    if end > len(lines) or end - location.line_start + 1 > 200:
        raise ValueError("Границы фрагмента вне источника или превышают 200 строк")
    return "\n".join(
        f"{number}: {lines[number - 1]}" for number in range(location.line_start, end + 1)
    )


def export_report(session: AnalysisSession, path: Path) -> None:
    """Сохранить текущий backend-отчёт без исходного документа."""
    path.write_text(session.report.model_dump_json(indent=2), encoding="utf-8")


def reanalyze_session(
    session: AnalysisSession,
    *,
    require_logging: bool = True,
    require_comments: bool = True,
    enabled_check_ids: tuple[str, ...] | None = None,
    management_profile: ManagementProfile | None = None,
    policy_exposure_profile: PolicyExposureProfile | None = None,
) -> AnalysisSession:
    """Повторить проверки сохранённого снимка без чтения и создания новой ревизии."""
    if management_profile is None and session.report.management_profile is not None:
        management_profile = ManagementProfile.model_validate(session.report.management_profile)
    return replace(
        session,
        report=analyze_firewall(
            session.revision,
            require_logging=require_logging,
            require_comments=require_comments,
            checks=selected_checks(enabled_check_ids, management_profile, policy_exposure_profile),
            management_profile=management_profile,
        ),
    )


def compare_sessions(before: AnalysisSession, after: AnalysisSession) -> DeviceRevisionDiff:
    """Экспериментально сравнить снимки одного устройства без оценки доступа."""
    return compare_revisions(before.revision, after.revision)


def compare_revisions(before: DeviceRevision, after: DeviceRevision) -> DeviceRevisionDiff:
    """Сравнить policy или сетевые снимки, сохраняя все ограничения результата."""
    return compare_device_revisions(before, after)
