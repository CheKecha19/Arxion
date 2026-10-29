"""Оркестрация сетевых desktop-заданий без зависимости от Tkinter."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel

from firewall_compliance.analysis.device_decision import evaluate_interface
from firewall_compliance.analysis.forwarding_policy import evaluate_forwarding_policy
from firewall_compliance.analysis.policy_decision import evaluate_policy
from firewall_compliance.analysis.route_selection import analyze_reachability, select_route
from firewall_compliance.application.device_decision import analyze_imported_device
from firewall_compliance.application.forwarding_binding import (
    ForwardingBindingResult,
    bind_forwarding_context,
)
from firewall_compliance.application.network_import import (
    NetworkImportResult,
    import_network_documents,
)
from firewall_compliance.devices.ngfw.cisco.asa.forwarding import CiscoAsaForwardingParser
from firewall_compliance.domain.forwarding import (
    FlowApplicability,
    ForwardingContext,
    ForwardingSource,
)
from firewall_compliance.domain.forwarding_policy import ForwardingPolicyResult
from firewall_compliance.domain.observation import ObservationEvidence, ObservationWindow
from firewall_compliance.domain.policy_decision import PolicyBindingEvidence
from firewall_compliance.domain.reachability import AnalysisReason, ReachabilityQuery
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.interfaces.desktop.map_network_facts import MapNetworkFacts
from firewall_compliance.parsers.contracts import ParseFailure, SourceDocument
from firewall_compliance.parsers.forwarding_contracts import (
    ForwardingParseRequest,
    ForwardingParseResult,
)
from firewall_compliance.parsers.network_contracts import (
    NetworkDocumentMetadata,
    NetworkParseRequest,
)


@dataclass(frozen=True)
class NetworkDocumentDraft:
    """Явные заявления пользователя для одного выбранного документа."""

    path: Path
    metadata: Mapping[str, Any]
    observation: Mapping[str, Any] | None = None


SUPPORTED_FORWARDING_PROFILE = "asa-9.16-single-routed-ipv4-data-default"


@dataclass(frozen=True, slots=True)
class ForwardingProfileResolution:
    """Explicit dispatch eligibility, never a traffic or completeness verdict."""

    profile_id: str | None
    status: Literal["selected", "unknown", "not_enough_evidence"]
    binding: ForwardingBindingResult | None
    reasons: tuple[AnalysisReason, ...]
    context: ForwardingContext | None = None


def resolve_forwarding_profile(
    revision: DeviceRevision,
    profile_id: str | None,
    *,
    binding: ForwardingBindingResult | None = None,
    saved_facts: MapNetworkFacts | None = None,
) -> ForwardingProfileResolution:
    """Resolve one explicitly selected supported profile without vendor fallback.

    Facts come from an existing binding or anchor-checked saved map facts.
    The downstream evaluator still owns inventory/flow completeness, policy
    semantics and all conditional outcomes. Selection never asserts reachability.
    """
    reasons: list[AnalysisReason] = []

    def reason(
        code: str,
        category: Literal["missing_evidence", "unsupported", "contradiction"],
        message: str,
    ) -> None:
        reasons.append(AnalysisReason(code=code, category=category, message=message).as_snapshot())

    if profile_id is None:
        reason("profile_unknown", "missing_evidence", "Профиль forwarding явно не выбран.")
    elif profile_id != SUPPORTED_FORWARDING_PROFILE:
        reason("profile_unsupported", "unsupported", "Выбранный профиль не поддерживается.")
    elif (revision.device.vendor, revision.device.platform) != ("cisco", "asa-9.16"):
        reason("profile_device_mismatch", "unsupported", "Устройство вне выбранного профиля.")
    prepared = binding.as_snapshot() if binding is not None else None
    context = (
        prepared.forwarding.context
        if prepared is not None
        else (saved_facts.forwarding if saved_facts is not None else None)
    )
    bound_revision = (
        prepared.imported.revision
        if prepared is not None
        else (saved_facts.network_import.revision if saved_facts is not None else None)
    )
    if context is None:
        reason(
            "binding_missing", "missing_evidence", "Нет подтверждённой привязки forwarding-фактов."
        )
    elif bound_revision != revision:
        reason("binding_revision_mismatch", "contradiction", "Привязка относится к другой ревизии.")
    else:
        for field, expected in (
            ("context_mode", "single"),
            ("firewall_mode", "routed"),
            ("address_family", "ipv4"),
            ("table_role", "data"),
            ("table_id", "default"),
        ):
            value = getattr(context, field)
            if value is None:
                reason("profile_unknown", "missing_evidence", f"Не подтверждён профиль: {field}.")
            elif value != expected:
                reason("profile_unsupported", "unsupported", f"Вне выбранного профиля: {field}.")
        if prepared is not None and prepared.status != "consistent":
            reason(
                "binding_incomplete", "missing_evidence", "Привязка forwarding имеет ограничения."
            )
        if not context.sources or not context.interfaces:
            reason(
                "forwarding_facts_missing", "missing_evidence", "Нет исходных фактов интерфейсов."
            )
    status: Literal["selected", "unknown", "not_enough_evidence"] = (
        "unknown"
        if any(item.category in {"unsupported", "contradiction"} for item in reasons)
        else "not_enough_evidence"
        if reasons
        else "selected"
    )
    return ForwardingProfileResolution(
        profile_id,
        status,
        prepared if status == "selected" else None,
        tuple(reasons),
        context if status == "selected" else None,
    )


@dataclass(frozen=True, slots=True)
class ForwardingQueryResult:
    """Conditional policy trace for caller-supplied interfaces, never a path."""

    query: ReachabilityQuery
    profile_id: str | None
    ingress_interface_id: str | None
    egress_interface_id: str | None
    status: Literal["unknown", "not_enough_evidence"]
    binding: ForwardingBindingResult | None
    evaluation: ForwardingPolicyResult | None
    reasons: tuple[AnalysisReason, ...]
    egress_basis: Literal["caller_supplied_conditional"] = "caller_supplied_conditional"
    context: ForwardingContext | None = None


def run_forwarding_query(
    imported: NetworkImportResult,
    parsed: ForwardingParseResult | None,
    query: ReachabilityQuery,
    *,
    profile_id: str | None,
    ingress_interface_id: str | None = None,
    egress_interface_id: str | None = None,
    flow: FlowApplicability | None = None,
) -> ForwardingQueryResult:
    """Bind exact snapshots and evaluate an explicitly declared conditional pair.

    No route or first interface is selected. Flow applicability must be supplied
    explicitly here or already recorded in parsed.context.flow; its query must
    equal the caller's query. Existing evaluators retain all eligibility gates,
    evidence and runtime uncertainty. The saved source files are never reread.
    """
    query = query.as_snapshot()
    binding: ForwardingBindingResult | None = None
    reasons: list[AnalysisReason] = []

    def reason(
        code: str,
        category: Literal["missing_evidence", "contradiction"],
        message: str,
    ) -> None:
        reasons.append(AnalysisReason(code=code, category=category, message=message).as_snapshot())

    revision = imported.revision
    if (
        query.revision_id != revision.revision_id
        or query.device_id != revision.device.device_id
        or query.device_context != revision.device.context
    ):
        reason("query_revision_mismatch", "contradiction", "Запрос относится к другой ревизии.")
    ingress = ingress_interface_id.strip() if ingress_interface_id is not None else None
    egress = egress_interface_id.strip() if egress_interface_id is not None else None
    if not ingress or not egress:
        reason("interface_pair_missing", "missing_evidence", "Явная пара ingress/egress не задана.")
    if ingress and ingress != query.ingress_interface_id:
        reason("query_ingress_mismatch", "contradiction", "Ingress не совпадает с запросом.")
    if parsed is not None:
        declared_flow = flow if flow is not None else parsed.context.flow
        if declared_flow is None:
            reason("flow_missing", "missing_evidence", "Нет явной декларации применимости потока.")
        elif declared_flow.query != query:
            reason(
                "flow_query_mismatch", "contradiction", "Декларация потока содержит другой запрос."
            )
        try:
            prepared = parsed
            if flow is not None:
                context = parsed.context.model_copy(update={"flow": flow})
                prepared = parsed.model_copy(update={"context": context})
            binding = bind_forwarding_context(imported, prepared)
        except ValueError:
            reason("binding_invalid", "contradiction", "Привязка исходных фактов не подтверждена.")
    resolution = resolve_forwarding_profile(revision, profile_id, binding=binding)
    reasons.extend(resolution.reasons)
    evaluation: ForwardingPolicyResult | None = None
    if not reasons and resolution.binding is not None and ingress and egress:
        evaluation = evaluate_forwarding_policy(
            resolution.binding.forwarding.context,
            ingress_interface_id=ingress,
            egress_interface_id=egress,
        )
        reasons.extend(evaluation.reasons)
    status: Literal["unknown", "not_enough_evidence"] = (
        evaluation.status
        if evaluation is not None
        else "unknown"
        if any(item.category in {"unsupported", "contradiction"} for item in reasons)
        else "not_enough_evidence"
    )
    return ForwardingQueryResult(
        query,
        profile_id,
        ingress,
        egress,
        status,
        resolution.binding or binding,
        evaluation,
        tuple(reasons),
    )


def run_bound_forwarding_query(
    imported: NetworkImportResult,
    context: ForwardingContext | None,
    query: ReachabilityQuery,
    *,
    profile_id: str | None,
    ingress_interface_id: str | None = None,
    egress_interface_id: str | None = None,
    flow: FlowApplicability | None = None,
) -> ForwardingQueryResult:
    """Re-evaluate saved facts with explicit new flow and conditional interfaces.

    No parsed result is reconstructed. Saved context.flow is never implicitly
    reused. A derived validated context preserves the original source anchors;
    it replaces only the explicitly supplied flow. Egress is caller-supplied,
    not selected from a routing table, and overall delivery remains unresolved.
    """
    query = query.as_snapshot()
    reasons: list[AnalysisReason] = []

    def reason(
        code: str,
        category: Literal["missing_evidence", "contradiction"],
        message: str,
    ) -> None:
        reasons.append(AnalysisReason(code=code, category=category, message=message).as_snapshot())

    revision = imported.revision
    ingress = ingress_interface_id.strip() if ingress_interface_id is not None else None
    egress = egress_interface_id.strip() if egress_interface_id is not None else None
    if (
        query.revision_id != revision.revision_id
        or query.device_id != revision.device.device_id
        or query.device_context != revision.device.context
    ):
        reason("query_revision_mismatch", "contradiction", "Запрос относится к другой ревизии.")
    if not ingress or not egress:
        reason("interface_pair_missing", "missing_evidence", "Явная пара ingress/egress не задана.")
    if ingress and ingress != query.ingress_interface_id:
        reason("query_ingress_mismatch", "contradiction", "Ingress не совпадает с запросом.")
    if flow is None:
        reason("flow_missing", "missing_evidence", "Новый запрос требует явной декларации потока.")
    elif flow.query != query:
        reason("flow_query_mismatch", "contradiction", "Декларация потока содержит другой запрос.")
    saved: MapNetworkFacts | None = None
    derived: ForwardingContext | None = None
    if context is not None:
        try:
            saved = MapNetworkFacts(imported, context)
            excluded = {"source_zone", "destination_zone", "policy_direction", "zone_status"}
            expected = {
                rule.rule_id: rule.model_dump(mode="python", exclude=excluded)
                for rule in revision.parse_result.rules
            }
            actual = {
                rule.rule_id: rule.model_dump(mode="python", exclude=excluded)
                for acl in context.acls
                for rule in acl.rules
            }
            if (
                expected != actual
                or len(expected) != len(revision.parse_result.rules)
                or len(actual) != sum(len(acl.rules) for acl in context.acls)
            ):
                reason(
                    "binding_rules_mismatch",
                    "contradiction",
                    "ACL не совпадают с исходной ревизией.",
                )
            if context.table_id is not None and query.table_id != context.table_id:
                reason(
                    "query_table_mismatch", "contradiction", "Запрос относится к другой таблице."
                )
            if flow is not None and flow.query == query:
                derived = context.model_copy(update={"flow": flow})
                saved = MapNetworkFacts(imported, derived)
        except ValueError:
            saved = None
            derived = None
            reason(
                "binding_invalid", "contradiction", "Привязки сохранённых фактов не подтверждены."
            )
    resolution = resolve_forwarding_profile(revision, profile_id, saved_facts=saved)
    reasons.extend(resolution.reasons)
    evaluation: ForwardingPolicyResult | None = None
    if not reasons and resolution.context is not None and ingress and egress:
        evaluation = evaluate_forwarding_policy(
            resolution.context,
            ingress_interface_id=ingress,
            egress_interface_id=egress,
        )
        reasons.extend(evaluation.reasons)
    status: Literal["unknown", "not_enough_evidence"] = (
        evaluation.status
        if evaluation is not None
        else "unknown"
        if any(item.category in {"unsupported", "contradiction"} for item in reasons)
        else "not_enough_evidence"
    )
    return ForwardingQueryResult(
        query,
        profile_id,
        ingress,
        egress,
        status,
        None,
        evaluation,
        tuple(reasons),
        context=derived,
    )


def _read(draft: NetworkDocumentDraft) -> SourceDocument:
    source = FileSourceReader().read(draft.path)
    if draft.observation is not None:
        payload = source.model_dump(mode="python")
        payload["observation"] = ObservationEvidence.model_validate(draft.observation)
        source = SourceDocument.model_validate(payload)
    return source


def import_documents(
    base: DeviceRevision,
    drafts: tuple[NetworkDocumentDraft, ...],
    *,
    baseline_observation: Mapping[str, Any] | None = None,
    observation_window: Mapping[str, Any] | None = None,
) -> NetworkImportResult | ParseFailure:
    """Импортировать роли совместно, сохранив исходный snapshot и документы."""
    if not drafts:
        raise ValueError("Выберите хотя бы один сетевой документ.")
    sources = tuple(_read(draft) for draft in drafts)
    imported_at = datetime.now(UTC)
    payload = base.model_dump(mode="python")
    payload["imported_at"] = imported_at
    payload["parse_result"]["configuration"]["imported_at"] = imported_at
    if baseline_observation is not None:
        observation = ObservationEvidence.model_validate(baseline_observation)
        payload["observed_at"] = observation.observed_at
        config = base.parse_result.configuration
        for source in payload["sources"]:
            if (source["source_name"], source["content_sha256"]) == (
                config.source_name,
                config.content_sha256,
            ):
                source["observation"] = observation
    if observation_window is not None:
        payload["observation_window"] = ObservationWindow.model_validate(observation_window)
    baseline = DeviceRevision.model_validate(payload)
    requests = []
    for draft, source in zip(drafts, sources, strict=True):
        metadata = dict(draft.metadata)
        metadata.update(
            source_document_id=uuid4(),
            device_id=base.device.device_id,
            content_sha256=source.content_sha256,
        )
        requests.append(
            NetworkParseRequest(
                source=source,
                metadata=NetworkDocumentMetadata.model_validate(metadata),
                imported_at=imported_at,
            )
        )
    return import_network_documents(baseline, tuple(requests), revision_id=uuid4())


def run_network_query(
    revision: DeviceRevision,
    operation: Literal["route", "reachability", "interface", "policy", "device"],
    values: Mapping[str, Any],
    *,
    binding_values: Mapping[str, Any] | None = None,
    imported: NetworkImportResult | None = None,
) -> BaseModel:
    """Вызвать один оригинальный API и вернуть его типизированный контракт."""
    if operation == "interface":
        return evaluate_interface(revision, str(values["ingress_interface_id"]))
    payload = dict(values)
    payload.update(
        revision_id=revision.revision_id,
        device_id=revision.device.device_id,
        device_context=revision.device.context,
    )
    query = ReachabilityQuery.model_validate(payload)
    if operation == "route":
        return select_route(revision, query)
    if operation == "reachability":
        return analyze_reachability(revision, query)
    if binding_values is None:
        raise ValueError("Нужна явная декларация PolicyBindingEvidence с source mapping.")
    binding = PolicyBindingEvidence.model_validate(binding_values)
    if operation == "policy":
        return evaluate_policy(revision, query, binding)
    if imported is None or imported.revision.revision_id != revision.revision_id:
        raise ValueError("Локальная композиция требует сохранённый NetworkImportResult.")
    return analyze_imported_device(imported, query, binding)


def parse_forwarding(
    base: DeviceRevision,
    draft: NetworkDocumentDraft,
    profile: Mapping[str, Any],
) -> BaseModel:
    """Разобрать отдельный forwarding-контекст без заявления application binding."""
    allowed_profile_keys = {
        "context_mode",
        "firewall_mode",
        "address_family",
        "table_role",
        "table_id",
        "profile_reference",
    }
    if set(profile) - allowed_profile_keys:
        raise ValueError(
            "Профиль forwarding содержит недопустимые поля; идентичность задаёт сессия."
        )
    source = _read(draft)
    metadata = dict(draft.metadata)
    metadata.update(
        source_document_id=uuid4(),
        source_name=source.source_name,
        content_sha256=source.content_sha256,
        device_id=base.device.device_id,
        device_context=base.device.context,
        captured_at=source.captured_at,
        observation=source.observation,
    )
    request = ForwardingParseRequest.model_validate(
        {
            "source": source,
            "metadata": ForwardingSource.model_validate(metadata),
            "revision_id": base.revision_id,
            "configuration_id": base.parse_result.configuration.configuration_id,
            "imported_at": datetime.now(UTC),
            **profile,
        }
    )
    return CiscoAsaForwardingParser().parse(request)
