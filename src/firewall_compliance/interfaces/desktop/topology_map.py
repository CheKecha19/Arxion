"""Presentation of recorded interface facts, without topology inference."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.forwarding import (
    ForwardingContext,
    ForwardingInterface,
    ForwardingSource,
)
from firewall_compliance.domain.forwarding_policy import STAGE_ORDER, ForwardingPolicyStage
from firewall_compliance.domain.reachability import AnalysisReason, ReachabilityQuery
from firewall_compliance.domain.revision import DeviceRevision, Interface, RevisionSource
from firewall_compliance.interfaces.desktop.network_backend import (
    SUPPORTED_FORWARDING_PROFILE,
    ForwardingQueryResult,
)
from firewall_compliance.parsers.network_contracts import NetworkParseResult


@dataclass(frozen=True, slots=True)
class ConfiguredSubnetAttachment:
    """An explicit interface prefix, never a cable or an effective route."""

    cidr: str
    address_status: DataStatus
    relationship: Literal["configured_subnet"] = "configured_subnet"


@dataclass(frozen=True, slots=True)
class TopologyInterface:
    """One original interface fact with its exact provenance and scope."""

    interface_id: str
    label: str
    fact: Interface | ForwardingInterface
    source: RevisionSource | ForwardingSource | None
    document: NetworkParseResult | None
    table_id: str | None
    attachments: tuple[ConfiguredSubnetAttachment, ...] = ()
    vrf_id: None = None
    operational_state: Literal["unknown"] = "unknown"


@dataclass(frozen=True, slots=True)
class TopologyProjection:
    """Revision-scoped presentation; retained snapshots carry completeness."""

    status: Literal["missing", "unknown", "recorded"]
    revision: DeviceRevision | None
    forwarding: ForwardingContext | None
    interfaces: tuple[TopologyInterface, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TopologyTraceProjection:
    """Ordered conditional-policy cards and associated interfaces, not hops."""

    status: Literal["conditional_policy", "unavailable", "unsupported"]
    query: ReachabilityQuery | None
    profile_id: str | None
    overall_status: Literal["unknown", "not_enough_evidence"] | None
    policy_status: str | None
    stages: tuple[ForwardingPolicyStage, ...]
    ingress: ForwardingInterface | None
    egress: ForwardingInterface | None
    context: ForwardingContext | None
    reasons: tuple[AnalysisReason, ...]
    unknown_boundaries: tuple[str, ...]
    claim_layer: Literal["conditional_policy"] = "conditional_policy"
    quantifier: None = None
    physical_transitions: tuple[()] = ()


def _supported_trace_result(value: object) -> ForwardingQueryResult | None:
    """Validate dynamic UI input while retaining the typed public trace contract."""
    return value if isinstance(value, ForwardingQueryResult) else None


def build_topology_trace(
    result: ForwardingQueryResult,
    projection: TopologyProjection,
) -> TopologyTraceProjection:
    """Project an existing supported trace without invoking any evaluator.

    Cards retain their original order, rule trace and source locations. A query
    and its immutable context must match the displayed revision and forwarding
    facts; only explicit flow may differ from the displayed saved context.
    Mismatch clears all overlay references. No physical transition or route is
    present in this contract, even when conditional policy_status is allow.
    """
    boundaries = ("route_selection_unknown", "physical_transition_unknown", "delivery_unknown")
    supported_result = _supported_trace_result(result)

    def unavailable(
        code: str,
        message: str,
        *,
        unsupported: bool = True,
    ) -> TopologyTraceProjection:
        reason = AnalysisReason(
            code=code,
            category="unsupported" if unsupported else "missing_evidence",
            message=message,
        )
        return TopologyTraceProjection(
            "unsupported" if unsupported else "unavailable",
            supported_result.query if supported_result is not None else None,
            supported_result.profile_id if supported_result is not None else None,
            supported_result.status if supported_result is not None else None,
            None,
            (),
            None,
            None,
            None,
            (*supported_result.reasons, reason) if supported_result is not None else (reason,),
            boundaries,
        )

    if supported_result is None:
        return unavailable(
            "trace_contract_unsupported", "Тип результата не содержит поддержанный trace."
        )
    query, revision = result.query, projection.revision
    if revision is None or (
        query.revision_id != revision.revision_id
        or query.device_id != revision.device.device_id
        or query.device_context != revision.device.context
    ):
        return unavailable(
            "trace_revision_mismatch", "Trace относится к другой ревизии или устройству."
        )
    evaluation = result.evaluation
    if evaluation is None:
        return unavailable("trace_unavailable", "Условный trace не построен.", unsupported=False)
    context, displayed = evaluation.context, projection.forwarding
    if (
        result.profile_id != SUPPORTED_FORWARDING_PROFILE
        or displayed is None
        or context.revision_id != revision.revision_id
        or context.configuration_id != revision.parse_result.configuration.configuration_id
        or context.device_id != revision.device.device_id
        or context.device_context != revision.device.context
        or context.table_id != query.table_id
        or context.flow is None
        or context.flow.query != query
        or context.model_dump(mode="python", exclude={"flow"})
        != displayed.model_dump(mode="python", exclude={"flow"})
        or (result.context is not None and result.context != context)
        or result.ingress_interface_id != evaluation.ingress_interface_id
        or result.egress_interface_id != evaluation.egress_interface_id
        or query.ingress_interface_id != evaluation.ingress_interface_id
        or result.status != evaluation.status
        or result.egress_basis != evaluation.egress_basis
        or tuple(stage.stage for stage in evaluation.trace) != STAGE_ORDER
    ):
        return unavailable(
            "trace_scope_mismatch", "Trace не совпадает с текущими forwarding-фактами и scope."
        )
    sources = {source.source_document_id: source for source in revision.sources}
    for source in context.sources:
        original = sources.get(source.source_document_id)
        if original is None or (
            source.source_name,
            source.content_sha256,
            source.captured_at,
            source.observation,
        ) != (
            original.source_name,
            original.content_sha256,
            original.captured_at,
            original.observation,
        ):
            return unavailable(
                "trace_source_mismatch", "Source anchors trace не совпадают с текущей ревизией."
            )
    interfaces = {interface.interface_id: interface for interface in context.interfaces}
    ingress = interfaces.get(evaluation.ingress_interface_id)
    egress = interfaces.get(evaluation.egress_interface_id)
    # Missing interface facts remain missing; never substitute a label/name match.
    unknown = tuple(
        stage.stage
        for stage in evaluation.trace
        if stage.outcome in {"unknown", "not_enough_evidence"}
    )
    reasons = tuple(dict.fromkeys((*result.reasons, *evaluation.reasons)))
    return TopologyTraceProjection(
        "conditional_policy",
        query,
        result.profile_id,
        result.status,
        evaluation.policy_status,
        evaluation.trace,
        ingress,
        egress,
        context,
        reasons,
        (*boundaries, *unknown),
    )


def build_topology_projection(
    facts: NetworkImportResult | DeviceRevision | None,
    *,
    forwarding: ForwardingContext | None = None,
) -> TopologyProjection:
    """Project existing snapshots without reading source files or creating IDs.

    The device is the exact ``revision.device`` and every interface retains its
    original fact/source anchor. Network documents retain table/context scope,
    diagnostics and collection evidence. Forwarding facts remain separate;
    matching labels never establish identity between the two inventories.
    """
    limitations = (
        "Привязки подсетей показывают заданные префиксы интерфейсов.",
        "Кабели, соседство, эффективные маршруты и достижимость не вычисляются.",
        "Операционное состояние неизвестно; enabled не означает up.",
        "VRF не задана этими моделями; table_id сохраняется отдельно без подмены VRF.",
    )
    if facts is None:
        return TopologyProjection("missing", None, None, (), limitations)
    if isinstance(facts, NetworkImportResult):
        imported = facts.as_snapshot()
        revision = imported.revision.as_snapshot()
    else:
        imported = None
        revision = facts.as_snapshot()
    context = forwarding.as_snapshot() if forwarding is not None else None
    if context is not None and (
        context.revision_id != revision.revision_id
        or context.configuration_id != revision.parse_result.configuration.configuration_id
        or context.device_id != revision.device.device_id
        or context.device_context != revision.device.context
    ):
        raise ValueError("Forwarding facts belong to another revision or device scope")
    documents = {
        document.source.source_document_id: document
        for document in (imported.documents if imported else ())
        if document.scope == "interfaces"
    }
    for network_document in documents.values():
        if (
            network_document.metadata.device_id != revision.device.device_id
            or network_document.metadata.context != revision.device.context
        ):
            raise ValueError("Network document belongs to another device scope")
    sources = {source.source_document_id: source for source in revision.sources}
    interfaces: list[TopologyInterface] = []
    for interface in revision.interfaces:
        source_id = interface.source_document_id
        document = documents.get(source_id) if source_id is not None else None
        interfaces.append(
            TopologyInterface(
                interface_id=interface.interface_id,
                label=interface.name,
                fact=interface,
                source=sources.get(source_id) if source_id is not None else None,
                document=document,
                table_id=document.metadata.table_id if document else None,
                attachments=tuple(
                    ConfiguredSubnetAttachment(cidr, interface.addresses_status)
                    for cidr in interface.networks
                ),
            )
        )
    if context is not None:
        forwarding_sources = {source.source_document_id: source for source in context.sources}
        interfaces.extend(
            TopologyInterface(
                interface_id=interface.interface_id,
                label=interface.label,
                fact=interface,
                source=forwarding_sources.get(interface.location.source_document_id),
                document=None,
                table_id=context.table_id,
            )
            for interface in context.interfaces
        )
    return TopologyProjection(
        "recorded" if interfaces else "unknown",
        revision,
        context,
        tuple(interfaces),
        limitations,
    )
