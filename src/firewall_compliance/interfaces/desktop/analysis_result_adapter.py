"""Project-facing adapters preserve the exact saved analysis and query inputs."""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol, TypedDict, cast
from uuid import UUID

from pydantic import JsonValue

from firewall_compliance import __version__
from firewall_compliance.application.analysis_result import (
    AnalysisComponent,
    AnalysisResult,
    AttemptComponent,
    ComponentLimitation,
    DeviceDecisionComponent,
    FindingDecision,
    ForwardingComponent,
    InterfaceComponent,
    PolicyAnalysisOptions,
    PolicyComponent,
    PolicyDecisionComponent,
    ReachabilityComponent,
    RouteComponent,
    source_manifest,
)
from firewall_compliance.application.cloud_analysis import vmware_device_id
from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.enums import FindingStatus
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.policy_decision import (
    InterfaceDecisionResult,
    PolicyDecisionResult,
    SingleDeviceDecisionResult,
)
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.domain.policy_scope import PolicyScopeProfile
from firewall_compliance.domain.reachability import (
    AnalysisReason,
    ReachabilityResult,
    RouteSelectionResult,
)
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.jobs import JobError
from firewall_compliance.interfaces.desktop.network_backend import ForwardingQueryResult
from firewall_compliance.interfaces.desktop.workspace_models import cloud_resource_key

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.qt_network import NetworkQuerySnapshot


class RunStore(Protocol):
    def get_run(self, run_id: str) -> dict[str, Any]: ...

    def list_cloud_scans(self, project_id: str) -> list[dict[str, Any]]: ...


class _NetworkInputs(TypedDict):
    component_id: str
    revision: DeviceRevision
    imported: NetworkImportResult | None


def _date(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("В сохранённой операции отсутствует достоверная дата.")
    date = datetime.fromisoformat(value)
    if date.utcoffset() is None:
        raise ValueError("Дата сохранённой операции не содержит часовой пояс.")
    return date


def _stored_diagnostic(value: dict[str, Any]) -> ComponentLimitation:
    message = value["message"]
    if not isinstance(message, str):
        raise ValueError("Некорректное сохранённое сообщение диагностики.")
    details = {key: item for key, item in value.items() if key not in {"code", "message"}}
    if details:
        message += "\nДанные диагностики: " + json.dumps(
            details, ensure_ascii=False, sort_keys=True
        )
    return ComponentLimitation(code=value["code"], message=message)


def analysis_from_run(store: RunStore, project_id: str, run_id: str) -> AnalysisResult:
    """Wrap stored reports; never reread files or replace conclusions with new ones."""
    run = store.get_run(run_id)
    if run["project_id"] != project_id:
        raise ValueError("Запуск относится к другому проекту.")
    settings = run.get("settings") or {}
    components: list[AnalysisComponent] = []
    revisions: list[DeviceRevision] = []
    decisions: list[FindingDecision] = []
    records: dict[UUID, dict[str, JsonValue]] = {}
    scans: dict[str, dict[str, Any] | None] = {}
    read_scan = getattr(store, "get_cloud_scan", None)
    times = [_date(run["created_at"])]
    if run.get("finished_at"):
        times.append(_date(run["finished_at"]))
    run_state = run.get("state")
    if not run.get("items") and run_state in {
        "failed",
        "error",
        "interrupted",
        "cancelled",
        "canceled",
    }:
        components.append(
            AttemptComponent(
                component_id="operation",
                family="policy",
                operation="Проверка запуска",
                state="cancelled" if run_state in {"cancelled", "canceled"} else "failed",
                diagnostic=ComponentLimitation(
                    code="SAVED_RUN_" + str(run_state).upper(),
                    message="Запуск не завершил проверки; состояние: " + str(run_state) + ".",
                ),
            )
        )
    for item in run.get("items", []):
        component_id = "policy:" + str(item["id"])
        if not item.get("report"):
            cancelled = item.get("status") in {"cancelled", "canceled"}
            diagnostics = tuple(_stored_diagnostic(value) for value in item.get("diagnostics", []))
            components.append(
                AttemptComponent(
                    component_id=component_id,
                    family="policy",
                    operation=str(item.get("source_name") or "Импорт конфигурации"),
                    state="cancelled" if cancelled else "failed",
                    diagnostic=diagnostics[0]
                    if diagnostics
                    else ComponentLimitation(
                        code="SAVED_ANALYSIS_CANCELLED" if cancelled else "SAVED_ANALYSIS_FAILED",
                        message="Проверка отменена."
                        if cancelled
                        else "В сохранённой операции отсутствует выполненный отчёт; "
                        "исходная диагностика доступна в этой операции.",
                    ),
                    limitations=diagnostics,
                )
            )
            continue
        revision = DeviceRevision.model_validate(item.get("revision"))
        report = FirewallAssuranceResult.model_validate(item["report"])
        options = PolicyAnalysisOptions(
            check_ids=tuple(check.check_id for check in report.checks),
            require_logging=report.require_logging,
            require_comments=report.require_comments,
            max_pair_rules=report.max_pair_rules,
            management_profile=ManagementProfile.model_validate(
                report.management_profile or settings.get("management_profile") or {}
            ),
            exposure_profile=PolicyExposureProfile.model_validate(
                settings.get("policy_exposure_profile") or {}
            ),
            scope_profile=PolicyScopeProfile.model_validate(
                settings.get("policy_scope_profile") or {}
            )
            if any(
                check.check_id in {"FW-EXCESSIVE-ACCESS", "FW-ACL-ATTACHMENT"}
                for check in report.checks
            )
            else None,
        )
        components.append(
            PolicyComponent(
                component_id=component_id,
                revision=revision,
                options=options,
                result=report,
            )
        )
        revisions.append(revision)
        times.extend((revision.imported_at, report.analyzed_at))
        origin = item.get("cloud_origin")
        if origin:
            scan_id = str(origin["scan_id"])
            if scan_id not in scans:
                if callable(read_scan):
                    scans[scan_id] = read_scan(project_id, scan_id)
                else:
                    scans.update((str(scan["id"]), scan) for scan in store.list_cloud_scans(project_id))
                    scans.setdefault(scan_id, None)
            scan = scans[scan_id]
            index = origin.get("record_index")
            if scan is None or type(index) is not int or index < 0:
                raise ValueError("Исходный API-снимок облачного отчёта недоступен.")
            raw_records = scan.get("result", {}).get("records", [])
            if index >= len(raw_records) or not isinstance(raw_records[index], dict):
                raise ValueError("Исходная запись облачного отчёта недоступна.")
            record = raw_records[index]
            if str(record.get("id")) != str(origin["resource_id"]):
                raise ValueError("Исходный облачный ресурс не совпадает с отчётом.")
            if (
                scan.get("project_id", project_id) != project_id
                or cloud_resource_key(
                    {"id": scan["id"], "config": origin["connection"]}, record, index
                )
                != cloud_resource_key(scan, record, index)
                or report.device_id != vmware_device_id(scan["config"], str(record.get("id")))
            ):
                raise ValueError("Облачный источник не совпадает с подключением и проектом отчёта.")
            for source in revision.sources:
                records[source.source_document_id] = cast(dict[str, JsonValue], record)
        for check in report.checks:
            for finding in check.findings:
                mark = run.get("marks", {}).get(str(finding.finding_id))
                if mark is not None:
                    decisions.append(
                        FindingDecision(
                            component_id=component_id,
                            finding_id=finding.finding_id,
                            status=FindingStatus(mark["status"]),
                            comment=mark["comment"],
                            decided_at=_date(mark["updated_at"]),
                        )
                    )
    return AnalysisResult(
        application_version=__version__,
        project_reference=project_id,
        run_reference=run_id,
        started_at=min(times),
        finished_at=max(times),
        sources=source_manifest(tuple(revisions), api_records=records),
        components=tuple(components),
        decisions=tuple(decisions),
    )


def analysis_from_network(
    snapshot: NetworkQuerySnapshot,
    project_id: str,
    run_id: str | None = None,
) -> AnalysisResult:
    """Retain the original typed query, import documents and conditional result."""
    if snapshot.project_reference is not None and snapshot.project_reference != project_id:
        raise ValueError("Сетевой результат относится к другому проекту.")
    facts = snapshot.facts
    revision = facts.imported.revision if facts.imported is not None else facts.base_revision
    if (
        revision.device != facts.base_revision.device
        or revision.parse_result != facts.base_revision.parse_result
    ):
        raise ValueError("Базовая ревизия не совпадает с исходными данными сетевого импорта.")
    if snapshot.started_at is None or snapshot.finished_at is None:
        raise ValueError("Время выполнения запроса не сохранено; повторите сетевую проверку.")
    common: _NetworkInputs = {
        "component_id": "network",
        "revision": revision,
        "imported": facts.imported,
    }
    result = snapshot.result
    expected_query = (
        result.query
        if isinstance(result, (RouteSelectionResult, PolicyDecisionResult, ForwardingQueryResult))
        else result.route_selection.query
        if isinstance(result, (ReachabilityResult, SingleDeviceDecisionResult))
        else None
    )
    if expected_query is not None and snapshot.query != expected_query:
        raise ValueError("Исходный сетевой запрос не совпадает с сохранённым ответом.")
    if isinstance(result, InterfaceDecisionResult) and snapshot.query is not None:
        raise ValueError("Проверка интерфейса не содержит сетевого запроса.")
    if (
        isinstance(
            result,
            (
                RouteSelectionResult,
                ReachabilityResult,
                InterfaceDecisionResult,
                PolicyDecisionResult,
                SingleDeviceDecisionResult,
            ),
        )
        and snapshot.profile_id != "legacy"
    ):
        raise ValueError("Профиль запроса не совпадает с видом сетевой проверки.")
    if isinstance(result, ForwardingQueryResult) and snapshot.profile_id != result.profile_id:
        raise ValueError("Профиль forwarding не совпадает с исходным запросом.")
    component: AnalysisComponent
    if isinstance(result, RouteSelectionResult):
        component = RouteComponent(**common, query=result.query, result=result)
    elif isinstance(result, ReachabilityResult):
        component = ReachabilityComponent(
            **common, query=result.route_selection.query, result=result
        )
    elif isinstance(result, InterfaceDecisionResult):
        component = InterfaceComponent(**common, interface_id=result.interface_id, result=result)
    elif isinstance(result, PolicyDecisionResult):
        component = PolicyDecisionComponent(
            **common,
            query=result.query,
            binding=result.binding,
            result=result,
        )
    elif isinstance(result, SingleDeviceDecisionResult):
        component = DeviceDecisionComponent(
            **common,
            query=result.policy.query,
            binding=result.policy.binding,
            result=result,
        )
    elif isinstance(result, ForwardingQueryResult) and result.evaluation is not None:
        context = result.evaluation.context
        if context.flow is None or result.profile_id != "asa-9.16-single-routed-ipv4-data-default":
            raise ValueError("В результате отсутствуют исходные сведения о потоке и профиле.")
        component = ForwardingComponent(
            **common,
            query=result.query,
            profile_id="asa-9.16-single-routed-ipv4-data-default",
            flow=context.flow,
            context=context,
            parsed=facts.parsed,
            binding=result.binding,
            ingress_interface_id=result.evaluation.ingress_interface_id,
            egress_interface_id=result.evaluation.egress_interface_id,
            egress_basis=result.egress_basis,
            result=result.evaluation,
        )
    elif isinstance(result, (ForwardingQueryResult, AnalysisReason, JobError)):
        reasons = (
            result.reasons
            if isinstance(result, ForwardingQueryResult)
            else (result,)
            if isinstance(result, AnalysisReason)
            else ()
        )
        limitations = tuple(
            ComponentLimitation(code=reason.code, message=reason.message) for reason in reasons
        )
        diagnostic = (
            limitations[0]
            if limitations
            else ComponentLimitation(
                code="NETWORK_ANALYSIS_FAILED",
                message=result.message
                if isinstance(result, JobError)
                else "Сетевая проверка не выполнена.",
            )
        )
        attempt_context = (
            result.context if isinstance(result, ForwardingQueryResult) else facts.bound_context
        )
        component = AttemptComponent(
            **common,
            family="network",
            operation="Сетевой запрос",
            state="failed" if isinstance(result, JobError) else "not_executed",
            diagnostic=diagnostic,
            limitations=limitations,
            query=result.query if isinstance(result, ForwardingQueryResult) else snapshot.query,
            profile_id=snapshot.profile_id,
            forwarding_context=attempt_context,
            flow=attempt_context.flow if attempt_context else None,
        )
    else:
        raise ValueError("Этот вид результата ещё не имеет общего проверяемого контракта.")
    return AnalysisResult(
        application_version=__version__,
        project_reference=project_id,
        run_reference=run_id,
        started_at=snapshot.started_at,
        finished_at=snapshot.finished_at,
        sources=source_manifest((revision,)),
        components=(component,),
    )
