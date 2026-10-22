"""Сопоставление локальных этапов без утверждения конечной достижимости."""

from typing import Literal

from firewall_compliance.analysis.policy_decision import evaluate_policy
from firewall_compliance.analysis.route_selection import select_route
from firewall_compliance.domain import DataStatus, DeviceRevision, Evidence, ReachabilityQuery
from firewall_compliance.domain.policy_decision import (
    InterfaceDecisionResult,
    PolicyBindingEvidence,
    SingleDeviceDecisionResult,
)
from firewall_compliance.domain.reachability import AnalysisReason


def evaluate_interface(revision: DeviceRevision, interface_id: str) -> InterfaceDecisionResult:
    """Проверить только подтверждённую административную настройку интерфейса."""
    revision = DeviceRevision.model_validate(revision.model_dump(mode="python"))
    interface = next(
        (item for item in revision.interfaces if item.interface_id == interface_id), None
    )
    reasons: list[AnalysisReason] = []
    if (
        revision.interfaces_status != DataStatus.KNOWN
        or revision.observed_at is None
        or interface is None
        or interface.data_status != DataStatus.KNOWN
        or interface.enabled is None
    ):
        reasons.append(
            AnalysisReason(
                code="interface_state_unresolved",
                category="missing_evidence",
                message="Нет согласованного известного факта административного состояния.",
            )
        )
    status: Literal["unknown", "administratively_enabled", "administratively_disabled"] = (
        "unknown"
        if reasons
        else "administratively_enabled"
        if interface is not None and interface.enabled
        else "administratively_disabled"
    )
    return InterfaceDecisionResult(
        interface_id=interface_id,
        status=status,
        interface=interface,
        reasons=tuple(reasons),
        evidence=Evidence(
            summary="Административная настройка, не подтверждение operational state.",
            source_locations=(interface.source_location,)
            if interface is not None and interface.source_location is not None
            else (),
            facts={
                "revision_id": str(revision.revision_id),
                "interfaces_status": revision.interfaces_status.value,
                "observed_at": revision.observed_at.isoformat() if revision.observed_at else None,
                "collection_evidence": revision.interfaces_evidence.model_dump(mode="json")
                if revision.interfaces_evidence
                else None,
                "interface": interface.model_dump(mode="json") if interface else None,
            },
            limitations=("Operational state, link, ARP и фактическая передача не проверены.",),
        ),
    )


def analyze_device_decisions(
    revision: DeviceRevision, query: ReachabilityQuery, binding: PolicyBindingEvidence
) -> SingleDeviceDecisionResult:
    """Объяснить кандидата RIB, настройку интерфейсов и одну явно указанную ACL."""
    revision = DeviceRevision.model_validate(revision.model_dump(mode="python"))
    query = ReachabilityQuery.model_validate(query.model_dump(mode="python"))
    binding = PolicyBindingEvidence.model_validate(binding.model_dump(mode="python"))
    selection = select_route(revision, query)
    policy = evaluate_policy(revision, query, binding)
    identifiers = [query.ingress_interface_id]
    for hop in selection.hops:
        if hop.outgoing_interface_id is not None and hop.outgoing_interface_id not in identifiers:
            identifiers.append(hop.outgoing_interface_id)
    if binding.interface_id not in identifiers:
        identifiers.append(binding.interface_id)
    interfaces = tuple(evaluate_interface(revision, identifier) for identifier in identifiers)
    reasons = [*selection.reasons, *policy.reasons]
    reasons.extend(reason for item in interfaces for reason in item.reasons)
    reasons.append(
        AnalysisReason(
            code="forward_chain_pending",
            category="pending",
            message="Одна ACL и кандидат RIB не доказывают цепочку: NAT/PBR, global/egress ACL, "
            "security-level, operational state, inspection и обратный путь не проверены. "
            "Tuple явно задан для ACL, а не восстановлен из NAT.",
        )
    )
    if binding.direction == "out" and (
        selection.status != "selected"
        or selection.hops[0].outgoing_interface_id != binding.interface_id
    ):
        reasons.append(
            AnalysisReason(
                code="egress_binding_not_selected",
                category="contradiction",
                message="Указанная outbound ACL не привязана к единственному кандидату RIB; "
                "её локальное решение не считается этапом выбранного пути.",
            )
        )
    return SingleDeviceDecisionResult(
        status="not_enough_evidence"
        if any(reason.category == "missing_evidence" for reason in reasons)
        and not any(reason.category in {"contradiction", "unsupported"} for reason in reasons)
        else "unknown",
        route_selection=selection,
        interfaces=interfaces,
        policy=policy,
        reasons=tuple(reasons),
    )
