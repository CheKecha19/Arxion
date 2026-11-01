"""Pure project overview over explicit registry identities and saved analysis evidence."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from firewall_compliance.application.workspace_profile import analysis_settings
from firewall_compliance.interfaces.desktop.check_presentation import check_execution_status

SEVERITIES = ("critical", "high", "medium", "low", "info")
CATEGORIES = (("ngfw", "NGFW"), ("network", "Сетевое оборудование"), ("cloud", "Облако"))
_CONNECTION_FIELDS = (
    "platform",
    "site",
    "tenant",
    "project_id",
    "region",
    "ecs_endpoint",
    "vpc_endpoint",
)


@dataclass(frozen=True)
class CategorySummary:
    category: str
    label: str
    total: int = 0
    complete: int = 0
    partial: int = 0
    collected: int = 0
    unchecked: int = 0
    stale: int = 0

    @property
    def checked(self) -> int:
        """Actual current checks, including partial checks; collection is not analysis."""
        return self.complete + self.partial


@dataclass(frozen=True)
class OperationSummary:
    operation_id: str
    kind: str
    state: str
    created_at: str | None
    finished_at: str | None
    resources: int
    executed_checks: int = 0
    partial_checks: int = 0
    findings: int = 0
    not_executed_checks: int = 0


@dataclass(frozen=True)
class FindingTrendPoint:
    """Observed count, with explicit evidence required for a connecting segment."""

    run_id: str
    timestamp: str | None
    findings: int | None
    comparable_to_previous: bool
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class DashboardSnapshot:
    categories: tuple[CategorySummary, ...]
    active_resources: int
    archived_resources: int
    integrations: int
    virtual_machines: int
    analysis_runs: int
    completed_analysis_runs: int
    executed_checks: int
    partial_checks: int
    not_executed_checks: int
    last_check_at: str | None
    findings_by_severity: Mapping[str, int]
    open_findings_by_severity: Mapping[str, int]
    recent_checks: tuple[OperationSummary, ...]
    recent_operations: tuple[OperationSummary, ...]
    unmatched_report_devices: int = 0
    warnings: tuple[str, ...] = ()
    error_items: int = 0
    unsupported_items: int = 0
    collection_errors: int = 0
    finding_trend: tuple[FindingTrendPoint, ...] = ()
    source_health: tuple[Mapping[str, Any], ...] = ()

    @property
    def findings(self) -> int:
        return sum(self.findings_by_severity.values())

    @property
    def open_findings(self) -> int:
        return sum(self.open_findings_by_severity.values())


@dataclass(frozen=True)
class _Report:
    device_id: str
    item: Mapping[str, Any]
    report: Mapping[str, Any]
    run: Mapping[str, Any]
    executed: int
    partial: int
    not_executed: int
    timestamp: datetime | None


def finding_trend(runs: Sequence[Mapping[str, Any]]) -> tuple[FindingTrendPoint, ...]:
    """Compare recorded run coverage, never infer fixed findings from missing data."""
    ordered = sorted(
        (
            run for run in runs
            if run.get("finished_at") or run.get("state") in {"completed", "cancelled", "interrupted"}
        ),
        key=lambda run: _time(run.get("finished_at")) or datetime.min.replace(tzinfo=UTC),
    )
    points = []
    previous_signature: str | None = None
    previous_time: datetime | None = None
    for run in ordered:
        limitations = []
        if run.get("state") != "completed":
            limitations.append("Запуск отменён, прерван или завершён с ошибками")
        observed = _time(run.get("finished_at"))
        if observed is None:
            limitations.append("Нет достоверного времени завершения")
        items = run.get("items", [])
        reports = [item.get("report") for item in items if isinstance(item, dict)]
        if not items or len(reports) != len(items) or any(not report for report in reports):
            limitations.append("Не все входы имеют результаты")
        known_reports = [report for report in reports if isinstance(report, dict) and report]
        signatures = []
        device_ids = []
        for item in items:
            report = _mapping(item.get("report")) if isinstance(item, dict) else {}
            if not report:
                continue
            device_id = report.get("device_id")
            if isinstance(device_id, str) and device_id:
                device_ids.append(device_id)
            else:
                limitations.append("Неизвестен идентификатор устройства")
            checks = report.get("checks", [])
            if not isinstance(checks, (list, tuple)):
                checks = []
            if not device_id or not checks:
                limitations.append("Неизвестен состав устройств или проверок")
            coverage = _mapping(report.get("parse_coverage"))
            if (
                item.get("status") != "complete" or report.get("parse_errors")
                or report.get("unsupported_constructs")
                or type(coverage.get("discovered_constructs")) is not int
                or type(coverage.get("recognized_constructs")) is not int
                or coverage.get("discovered_constructs", -1) < 0
                or coverage.get("recognized_constructs") != coverage.get("discovered_constructs")
            ):
                limitations.append("Неполный разбор или результат")
            versions = {
                key: report.get(key)
                for key in ("application_version", "parser_version", "check_catalog_version")
            }
            if any(not value for value in versions.values()):
                limitations.append("Неизвестны версии анализа")
            if any(key not in report for key in ("require_logging", "require_comments", "max_pair_rules")):
                limitations.append("Неизвестны эффективные параметры проверки")
            check_signature = []
            for check in checks:
                if not isinstance(check, dict):
                    limitations.append("Неизвестен формат результата проверки")
                    continue
                status = check_execution_status(check)
                if status not in {"complete", "not_applicable"}:
                    limitations.append("Есть неполные или невыполненные проверки")
                if not check.get("check_version") or not check.get("check_id"):
                    limitations.append("Неизвестны версии или идентификаторы проверок")
                check_signature.append((check.get("check_id"), check.get("check_version"), status))
            signatures.append(
                {
                    "device": device_id,
                    "versions": versions,
                    "checks": sorted(check_signature, key=lambda value: str(value[0])),
                    "parameters": {
                        key: report.get(key)
                        for key in (
                            "require_logging", "require_comments", "max_pair_rules",
                            "management_profile", "policy_exposure_profile", "policy_scope_profile",
                        )
                    },
                }
            )
        if len(set(device_ids)) != len(device_ids):
            limitations.append("Несколько снимков одного устройства в запуске")
        settings = run.get("settings")
        if not isinstance(settings, dict):
            limitations.append("Нет сохранённых параметров запуска")
        settings = analysis_settings(settings) if isinstance(settings, dict) else {}
        if isinstance(settings.get("enabled_check_ids"), list):
            if all(isinstance(value, str) for value in settings["enabled_check_ids"]):
                settings["enabled_check_ids"] = sorted(settings["enabled_check_ids"])
            else:
                limitations.append("Неизвестен набор включённых проверок")
        signature = None
        if not limitations:
            try:
                signature = json.dumps(
                    {
                        "settings": settings,
                        "devices": sorted(signatures, key=lambda value: str(value["device"])),
                    },
                    sort_keys=True, ensure_ascii=False, allow_nan=False,
                )
            except (TypeError, ValueError):
                limitations.append("Параметры анализа не поддаются сравнению")
        comparable = (
            signature is not None and previous_signature == signature
            and previous_time is not None and observed is not None and observed > previous_time
        )
        if points and not comparable and not limitations:
            limitations.append("Изменились параметры, состав/версии проверок или предыдущий запуск неполон")
        count = sum(len(_findings(report)) for report in known_reports) if known_reports else None
        points.append(FindingTrendPoint(
            str(run.get("id", "")), _iso(observed), count, comparable,
            tuple(dict.fromkeys(limitations)),
        ))
        previous_signature, previous_time = signature, observed
    return tuple(points)


def _time(value: object) -> datetime | None:
    if not isinstance(value, (datetime, str)) or not value:
        return None
    try:
        parsed = (
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            if isinstance(value, str)
            else value
        )
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _iso(value: object) -> str | None:
    parsed = _time(value)
    return parsed.isoformat() if parsed else None


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _connection(value: Mapping[str, Any]) -> str:
    fields = {key: value.get(key) for key in _CONNECTION_FIELDS}
    fields["platform"] = fields["platform"] or "vmware"
    return json.dumps(fields, sort_keys=True, ensure_ascii=False)


def _cloud_key(value: Mapping[str, Any]) -> tuple[str, str] | None:
    connection = _mapping(value.get("connection"))
    resource_id = value.get("resource_id")
    if not connection or not isinstance(resource_id, str) or not resource_id:
        return None
    return _connection(connection), resource_id


def _resource_keys(resource: Mapping[str, Any]) -> tuple[set[str], set[tuple[str, str]]]:
    source = _mapping(resource.get("source"))
    devices: set[str] = set()
    clouds: set[tuple[str, str]] = set()
    identities = [resource.get("identity")]
    for aliases in (
        resource.get("identities"),
        resource.get("aliases"),
        source.get("aliases"),
    ):
        if isinstance(aliases, list):
            identities.extend(aliases)
    for identity in identities:
        if not isinstance(identity, str):
            continue
        if identity.startswith("device:"):
            devices.add(identity.removeprefix("device:"))
        elif identity.startswith("cloud:"):
            try:
                parts = json.loads(identity.removeprefix("cloud:"))
                if (
                    isinstance(parts, list)
                    and len(parts) == 3
                    and isinstance(parts[0], dict)
                    and isinstance(parts[2], str)
                ):
                    clouds.add((_connection(parts[0]), parts[2]))
            except ValueError:
                pass
    device_id = source.get("device_id")
    if isinstance(device_id, str) and device_id:
        devices.add(device_id)
    report_id = _mapping(source.get("report")).get("device_id")
    if isinstance(report_id, str) and report_id:
        devices.add(report_id)
    origin = _mapping(source.get("cloud_origin")) or source
    key = _cloud_key(origin)
    if key:
        clouds.add(key)
    scan, record = _mapping(source.get("scan")), _mapping(source.get("record"))
    key = _cloud_key({"connection": scan.get("config"), "resource_id": record.get("id")})
    if key:
        clouds.add(key)
    return devices, clouds


def _checks(report: Mapping[str, Any]) -> tuple[int, int, int]:
    executed = partial = not_executed = 0
    for check in report.get("checks", []):
        if not isinstance(check, dict):
            continue
        status = check_execution_status({"status": "unknown", **check})
        if status in {"complete", "partial"}:
            executed += 1
            partial += status == "partial"
        elif status != "not_applicable":
            not_executed += 1
    return executed, partial, not_executed


def _reports(runs: Sequence[Mapping[str, Any]]) -> list[_Report]:
    reports = []
    for run in runs:
        for item in run.get("items", []):
            if not isinstance(item, dict):
                continue
            report = _mapping(item.get("report"))
            device_id = report.get("device_id")
            if not isinstance(device_id, str) or not device_id:
                continue
            executed, partial, not_executed = _checks(report)
            reports.append(
                _Report(
                    device_id,
                    item,
                    report,
                    run,
                    executed,
                    partial,
                    not_executed,
                    _time(report.get("analyzed_at"))
                    or _time(run.get("finished_at"))
                    or _time(run.get("created_at")),
                )
            )
    return reports


def _findings(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        finding
        for check in report.get("checks", [])
        if isinstance(check, dict)
        and check_execution_status({"status": "unknown", **check}) in {"complete", "partial"}
        for finding in check.get("findings", [])
        if isinstance(finding, dict)
    ]


def _stale(resource: Mapping[str, Any], report: _Report) -> bool:
    source = _mapping(resource.get("source"))
    origin = _mapping(report.item.get("cloud_origin"))
    scan_id = source.get("scan_id") or _mapping(source.get("scan")).get("id")
    if scan_id and origin.get("scan_id") and scan_id != origin["scan_id"]:
        return True
    digest = source.get("content_sha256")
    return bool(
        digest and report.item.get("content_sha256") and digest != report.item["content_sha256"]
    )


def _operation(run: Mapping[str, Any], reports: Sequence[_Report]) -> OperationSummary:
    return OperationSummary(
        str(run.get("id", "")),
        "analysis",
        str(run.get("state", "unknown")),
        _iso(run.get("created_at")),
        _iso(run.get("finished_at")),
        len(run.get("items", [])),
        sum(report.executed for report in reports),
        sum(report.partial for report in reports),
        sum(len(_findings(report.report)) for report in reports),
        sum(report.not_executed for report in reports),
    )


def build_dashboard(
    resources: Sequence[Mapping[str, Any]],
    runs: Sequence[Mapping[str, Any]],
    scans: Sequence[Mapping[str, Any]],
    integrations: Sequence[Mapping[str, Any]],
    source_health: Sequence[Mapping[str, Any]] = (),
) -> DashboardSnapshot:
    """Project-scoped snapshot; no reads, writes, network calls, name matching or guessed dates.

    Supply get_run() payloads, not list_runs() summaries. Category membership is
    explicit registry metadata. Fully/partially checked means actual complete or
    partial check results, never a successful inventory collection. Resource
    last_check alone is not accepted as analysis evidence. Findings use only the
    latest executed report of each active matched device; historical operations
    and execution totals remain separate counters.
    """
    unique_resources = {
        str(resource.get("id") or resource.get("identity") or index): resource
        for index, resource in enumerate(resources)
    }
    active = [
        resource
        for resource in unique_resources.values()
        if resource.get("lifecycle", "active") != "archived"
    ]
    unique_runs = list(
        {str(run.get("id") or index): run for index, run in enumerate(runs)}.values()
    )
    reports = _reports(unique_runs)
    reports.sort(
        key=lambda report: report.timestamp or datetime.min.replace(tzinfo=UTC), reverse=True
    )
    latest: dict[str, _Report] = {}
    for report in reports:
        if report.executed:
            latest.setdefault(report.device_id, report)
    category_states: dict[str, Counter[str]] = {key: Counter() for key, _ in CATEGORIES}
    matched_devices: set[str] = set()
    for resource in active:
        category = str(resource.get("category", "unclassified"))
        if category not in dict(CATEGORIES):
            category = "unclassified"
        counts = category_states.setdefault(category, Counter())
        counts["total"] += 1
        device_ids, cloud_ids = _resource_keys(resource)
        candidates = [
            report
            for report in latest.values()
            if report.device_id in device_ids
            or (_cloud_key(_mapping(report.item.get("cloud_origin"))) in cloud_ids)
        ]
        candidate = candidates[0] if candidates else None
        if candidate is None:
            counts["collected" if _time(resource.get("last_scan")) else "unchecked"] += 1
            continue
        matched_devices.add(candidate.device_id)
        if _stale(resource, candidate):
            counts["stale"] += 1
        elif (
            candidate.partial or candidate.not_executed or candidate.item.get("status") == "partial"
        ):
            counts["partial"] += 1
        else:
            counts["complete"] += 1
    severities = Counter({severity: 0 for severity in SEVERITIES})
    open_severities = Counter({severity: 0 for severity in SEVERITIES})
    for device_id in matched_devices:
        report = latest[device_id]
        marks = _mapping(report.run.get("marks"))
        for finding in _findings(report.report):
            severity = finding.get("severity")
            if severity not in SEVERITIES:
                continue
            severities[str(severity)] += 1
            mark = _mapping(marks.get(str(finding.get("finding_id"))))
            status = mark.get("status") or finding.get("status", "new")
            if status not in {"resolved", "false_positive"}:
                open_severities[str(severity)] += 1
    operations = []
    for run in unique_runs:
        owned = [report for report in reports if report.run is run]
        operations.append(_operation(run, owned))
    operations.sort(
        key=lambda operation: _time(operation.created_at) or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    recent_checks = tuple(operations[:5])
    for scan in {str(scan.get("id") or index): scan for index, scan in enumerate(scans)}.values():
        result = _mapping(scan.get("result"))
        operations.append(
            OperationSummary(
                str(scan.get("id", "")),
                "collection",
                str(scan.get("state", "unknown")),
                _iso(scan.get("created_at")),
                _iso(scan.get("finished_at")),
                len(result.get("records", [])),
            )
        )
    operations.sort(
        key=lambda operation: _time(operation.created_at) or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    timestamps = [report.timestamp for report in reports if report.executed and report.timestamp]
    warnings = []
    unmatched = len(set(latest) - matched_devices)
    if unmatched:
        warnings.append(
            f"Проверенные снимки вне активного реестра: {unmatched}; их находки не включены."
        )
    if any(report.executed and report.timestamp is None for report in reports):
        warnings.append("У части результатов нет достоверной даты проверки.")
    if any(counts["stale"] for counts in category_states.values()):
        warnings.append(
            "Есть устаревшие результаты: находки относятся к предыдущему снимку ресурсов."
        )
    labels = (*CATEGORIES, ("unclassified", "Не классифицировано"))
    categories = tuple(
        CategorySummary(key, label, **category_states[key])
        for key, label in labels
        if key in category_states and (key != "unclassified" or category_states[key]["total"])
    )
    return DashboardSnapshot(
        categories,
        len(active),
        len(unique_resources) - len(active),
        len(
            {
                _connection(_mapping(integration.get("config")) or integration)
                + str(integration.get("provider", ""))
                for integration in integrations
            }
        ),
        sum(
            resource.get("category") == "cloud" and resource.get("resource_type") == "vms"
            for resource in active
        ),
        len(unique_runs),
        sum(
            operation.state == "completed" and operation.executed_checks > 0
            for operation in operations
            if operation.kind == "analysis"
        ),
        sum(report.executed for report in reports),
        sum(report.partial for report in reports),
        sum(report.not_executed for report in reports),
        max(timestamps).isoformat() if timestamps else None,
        dict(severities),
        dict(open_severities),
        recent_checks,
        tuple(operations[:5]),
        unmatched,
        tuple(warnings),
        sum(
            item.get("status") == "error"
            for run in unique_runs
            for item in run.get("items", [])
            if isinstance(item, dict)
        ),
        sum(
            item.get("status") == "unsupported"
            for run in unique_runs
            for item in run.get("items", [])
            if isinstance(item, dict)
        ),
        sum(
            len(_mapping(scan.get("result")).get("errors", []))
            for scan in {
                str(scan.get("id") or index): scan for index, scan in enumerate(scans)
            }.values()
        ),
        finding_trend(unique_runs),
        tuple(source_health),
    )
