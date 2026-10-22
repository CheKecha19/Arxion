"""Чистые доменные правила условной цепочки и повторной проверки её результата."""

import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Literal

from firewall_compliance.domain.enums import DataStatus, Protocol
from firewall_compliance.domain.forwarding import (
    FeatureInventory,
    ForwardingBinding,
    ForwardingContext,
)
from firewall_compliance.domain.forwarding_policy import (
    STAGE_ORDER,
    ForwardingPolicyStage,
    ForwardingPolicyStatus,
    ForwardingStageName,
)
from firewall_compliance.domain.policy_decision import PolicyTraceEntry
from firewall_compliance.domain.policy_matching import matches_query, resolve_rule
from firewall_compliance.domain.reachability import AnalysisReason, ReachabilityQuery

_POLICY_OUTCOMES: dict[str, ForwardingPolicyStatus] = {
    "allow": "allow",
    "deny": "deny",
    "drop": "drop",
    "reject": "reject",
    "implicit_deny": "implicit_deny",
    "unknown": "unknown",
    "not_enough_evidence": "not_enough_evidence",
}
_ACTIONS: dict[str, Literal["allow", "deny", "drop", "reject"]] = {
    "allow": "allow",
    "deny": "deny",
    "drop": "drop",
    "reject": "reject",
}


@dataclass(frozen=True)
class ForwardingPolicyCalculation:
    status: Literal["unknown", "not_enough_evidence"]
    policy_status: ForwardingPolicyStatus
    trace: tuple[ForwardingPolicyStage, ...]
    reasons: tuple[AnalysisReason, ...]


def _reason(
    code: str,
    category: Literal["missing_evidence", "unsupported", "contradiction", "pending"],
    message: str,
) -> AnalysisReason:
    return AnalysisReason(code=code, category=category, message=message)


def _uncertainty(reasons: list[AnalysisReason]) -> Literal["unknown", "not_enough_evidence"]:
    return (
        "unknown"
        if any(r.category in {"unsupported", "contradiction"} for r in reasons)
        else "not_enough_evidence"
    )


def _acl_stage(
    context: ForwardingContext,
    query: ReachabilityQuery,
    binding: ForwardingBinding | None,
    name: ForwardingStageName,
) -> ForwardingPolicyStage:
    if binding is None:
        return ForwardingPolicyStage(stage=name, outcome="not_applicable")
    acl = next(item for item in context.acls if item.policy_id == binding.policy_id)
    trace: list[PolicyTraceEntry] = []
    reasons: list[AnalysisReason] = []
    outcome: Literal["allow", "deny", "drop", "reject", "no_match", "unknown"] = "no_match"
    matched: str | None = None
    if acl.status != DataStatus.KNOWN or not acl.complete:
        reasons.append(
            _reason("acl_incomplete", "missing_evidence", "ACL не имеет подтверждённой полноты.")
        )
        return ForwardingPolicyStage(
            stage=name,
            outcome="not_enough_evidence",
            policy_id=acl.policy_id,
            locations=(binding.location, acl.location),
            reasons=tuple(reasons),
        )
    for rule in acl.rules:
        resolved = resolve_rule(rule) if rule.enabled is not False else None
        if rule.enabled is False:
            entry_outcome: Literal["disabled", "no_match", "match", "unknown"] = "disabled"
        elif (
            rule.enabled is None
            or resolved is None
            or rule.action.value not in {"allow", "deny", "drop", "reject"}
        ):
            entry_outcome = "unknown"
            outcome = "unknown"
            reasons.append(
                _reason(
                    "ace_unknown",
                    "unsupported",
                    "Неизвестный активный ACE исключает продолжение цепочки.",
                )
            )
        elif matches_query(resolved, query):
            entry_outcome = "match"
            matched = rule.rule_id
            outcome = _ACTIONS[rule.action.value]
        else:
            entry_outcome = "no_match"
        trace.append(
            PolicyTraceEntry(
                rule_id=rule.rule_id,
                sequence=rule.sequence,
                outcome=entry_outcome,
                source_location=rule.source_location,
            )
        )
        if entry_outcome in {"match", "unknown"}:
            break
    return ForwardingPolicyStage(
        stage=name,
        outcome=outcome,
        policy_id=acl.policy_id,
        matched_rule_id=matched,
        rule_trace=tuple(trace),
        locations=(binding.location, acl.location),
        reasons=tuple(reasons),
    )


def derive_forwarding_policy(
    context: ForwardingContext,
    *,
    ingress_interface_id: str,
    egress_interface_id: str,
) -> ForwardingPolicyCalculation:
    """Проверить политику для явно заданной пары интерфейсов, не выбирать egress из RIB."""
    context = ForwardingContext.model_validate(context.model_dump(mode="python"))
    ingress_interface_id, egress_interface_id = (
        ingress_interface_id.strip(),
        egress_interface_id.strip(),
    )
    if not ingress_interface_id or not egress_interface_id:
        raise ValueError("идентификаторы интерфейсов не должны быть пустыми")
    stages: dict[ForwardingStageName, ForwardingPolicyStage] = {}
    reasons: list[AnalysisReason] = []
    applicability: list[AnalysisReason] = []
    coordinates: list[AnalysisReason] = []

    def missing(code: str, message: str) -> None:
        applicability.append(_reason(code, "missing_evidence", message))

    for field, expected in (
        ("context_mode", "single"),
        ("firewall_mode", "routed"),
        ("address_family", "ipv4"),
        ("table_role", "data"),
        ("table_id", "default"),
    ):
        value = getattr(context, field)
        if value is None:
            missing("profile_unknown", f"Нет подтверждённого профиля: {field}.")
        elif value != expected:
            applicability.append(
                _reason("profile_unsupported", "unsupported", f"Неподдержанный профиль: {field}.")
            )
    if context.observed_at is None:
        missing("observation_missing", "Нет подтверждённого времени наблюдения.")
    for source in context.sources:
        if (
            re.fullmatch(r"9\.16(?:\([0-9]+\)[0-9]*|(?:\.[0-9]+)+)?", source.declared_version)
            is None
        ):
            applicability.append(
                _reason(
                    "version_unsupported", "unsupported", "Версия источника вне профиля ASA 9.16."
                )
            )
    interfaces = {item.interface_id: item for item in context.interfaces}
    ingress, egress = interfaces.get(ingress_interface_id), interfaces.get(egress_interface_id)
    for interface in (ingress, egress):
        if interface is None:
            missing("interface_missing", "Заданный физический интерфейс отсутствует в контексте.")
        elif interface.physical_l3 is None:
            missing("interface_unknown", "Не подтверждён тип интерфейса.")
        elif interface.physical_l3 is not True:
            applicability.append(
                _reason(
                    "interface_unsupported",
                    "unsupported",
                    "Не подтверждён физический L3 интерфейс.",
                )
            )
        elif interface.security_status != DataStatus.KNOWN:
            missing("security_level_unknown", "Не подтверждён security-level интерфейса.")
    if ingress_interface_id == egress_interface_id:
        applicability.append(
            _reason(
                "hairpin_unsupported", "unsupported", "Intra-interface поток не входит в профиль."
            )
        )
    flow = context.flow
    if flow is None:
        missing("flow_missing", "Нет декларации применимости потока.")
    else:
        query = flow.query
        if query.ingress_interface_id != ingress_interface_id:
            applicability.append(
                _reason(
                    "ingress_mismatch",
                    "contradiction",
                    "Ingress запроса не совпадает с заданным интерфейсом.",
                )
            )
        if ip_address(query.source_ip).version != 4 or query.table_id != "default":
            applicability.append(
                _reason("query_unsupported", "unsupported", "Запрос вне IPv4/default профиля.")
            )
        for field in ("new_connection", "transit", "non_vpn", "non_fragment"):
            value = getattr(flow, field)
            if value is None:
                missing("flow_unknown", f"Не подтверждена применимость: {field}.")
            elif value is not True:
                applicability.append(
                    _reason(
                        "flow_unsupported", "unsupported", f"Неподдержанная применимость: {field}."
                    )
                )
        details = (
            (("tcp_syn", True), ("tcp_ack", False), ("tcp_payload_length", 0))
            if query.protocol == Protocol.TCP
            else ((("icmp_type", 8), ("icmp_code", 0)) if query.protocol == Protocol.ICMP else ())
        )
        for field, packet_expected in details:
            value = getattr(flow, field)
            if value is None:
                missing("flow_details_missing", f"Не задан признак пакета: {field}.")
            elif value != packet_expected:
                applicability.append(
                    _reason(
                        "flow_details_unsupported", "unsupported", f"Неподдержанный пакет: {field}."
                    )
                )
    inventories: dict[str, FeatureInventory] = {item.feature: item for item in context.inventories}
    for feature in ("interfaces", "acl_definitions", "acl_bindings"):
        inventory = inventories.get(feature)
        if inventory is not None and inventory.status == DataStatus.UNSUPPORTED:
            applicability.append(
                _reason(
                    "inventory_unsupported", "unsupported", f"Неподдержанный инвентарь: {feature}."
                )
            )
        elif inventory is None or not inventory.complete or inventory.status == DataStatus.UNKNOWN:
            missing("inventory_incomplete", f"Нет полного инвентаря: {feature}.")
    for feature in ("configured_nat", "effective_nat", "pbr", "exceptions"):
        inventory = inventories.get(feature)
        if inventory is not None and inventory.status in {DataStatus.KNOWN, DataStatus.UNSUPPORTED}:
            coordinates.append(
                _reason(
                    "coordinates_unsupported",
                    "unsupported",
                    f"Присутствующая область не поддержана: {feature}.",
                )
            )
        elif inventory is None or not inventory.complete or inventory.status != DataStatus.ABSENT:
            coordinates.append(
                _reason(
                    "coordinates_missing",
                    "missing_evidence",
                    f"Не доказано отсутствие влияния: {feature}.",
                )
            )
    stages["applicability"] = ForwardingPolicyStage(
        stage="applicability",
        outcome=_uncertainty(applicability) if applicability else "passed",
        reasons=tuple(applicability),
    )
    stages["coordinates"] = ForwardingPolicyStage(
        stage="coordinates",
        outcome=_uncertainty(coordinates) if coordinates else "passed",
        reasons=tuple(coordinates),
        locations=tuple(
            location
            for feature in ("configured_nat", "effective_nat", "pbr", "exceptions")
            if feature in inventories
            for location in inventories[feature].locations
        ),
    )
    reasons.extend(applicability)
    reasons.extend(coordinates)
    policy: ForwardingPolicyStatus = _uncertainty(reasons) if reasons else "allow"
    if not reasons:
        assert ingress is not None and egress is not None and flow is not None
        assert ingress.security_level is not None and egress.security_level is not None
        equal = ingress.security_level == egress.security_level
        toggle = next((item for item in context.toggles if item.name == "inter_interface"), None)
        same_reasons: list[AnalysisReason] = []
        same_inventory = inventories.get("same_security")
        if equal and (
            toggle is None
            or toggle.status != DataStatus.KNOWN
            or same_inventory is None
            or not same_inventory.complete
            or same_inventory.status != DataStatus.KNOWN
        ):
            same_reasons.append(
                _reason(
                    "same_security_unknown",
                    "unsupported"
                    if toggle and toggle.status == DataStatus.UNSUPPORTED
                    else "missing_evidence",
                    "Нет явного эффективного inter-interface разрешения.",
                )
            )
            policy = _uncertainty(same_reasons)
        elif equal and toggle is not None and toggle.value is False:
            policy = "deny"
        stages["same_security"] = ForwardingPolicyStage(
            stage="same_security",
            outcome=policy if policy != "allow" else "passed",
            reasons=tuple(same_reasons),
            locations=(ingress.location, egress.location)
            + ((toggle.location,) if equal and toggle and toggle.location else ()),
        )
        reasons.extend(same_reasons)
        if policy == "allow":
            inbound = next(
                (
                    b
                    for b in context.bindings
                    if b.direction == "in" and b.interface_id == ingress_interface_id
                ),
                None,
            )
            global_binding = next((b for b in context.bindings if b.direction == "global"), None)
            stages["ingress_acl"] = _acl_stage(context, flow.query, inbound, "ingress_acl")
            current = stages["ingress_acl"].outcome
            if current in {"no_match", "not_applicable"}:
                stages["global_acl"] = _acl_stage(context, flow.query, global_binding, "global_acl")
                current = stages["global_acl"].outcome
                if current in {"no_match", "not_applicable"}:
                    default: Literal["allow", "deny", "implicit_deny"] = (
                        "implicit_deny"
                        if inbound or global_binding
                        else (
                            "allow" if ingress.security_level >= egress.security_level else "deny"
                        )
                    )
                    stages["inbound_default"] = ForwardingPolicyStage(
                        stage="inbound_default",
                        outcome=default,
                        locations=(ingress.location, egress.location),
                    )
                    current = default
            policy = _POLICY_OUTCOMES.get(current, "unknown")
            if policy == "allow":
                outbound = next(
                    (
                        b
                        for b in context.bindings
                        if b.direction == "out" and b.interface_id == egress_interface_id
                    ),
                    None,
                )
                stages["egress_acl"] = _acl_stage(context, flow.query, outbound, "egress_acl")
                out = stages["egress_acl"].outcome
                if out == "no_match":
                    stages["egress_acl"] = stages["egress_acl"].model_copy(
                        update={"outcome": "implicit_deny"}
                    )
                    policy = "implicit_deny"
                elif out != "not_applicable":
                    policy = _POLICY_OUTCOMES.get(out, "unknown")
    for stage in stages.values():
        if stage.stage not in {"applicability", "coordinates", "same_security"}:
            reasons.extend(stage.reasons)
    runtime = _reason(
        "runtime_pending",
        "pending",
        "Условный egress задан вызывающей стороной; RIB, operational state, "
        "next-hop, inspection и обратный путь не проверены.",
    )
    reasons.append(runtime)
    stages["runtime"] = ForwardingPolicyStage(
        stage="runtime", outcome="unknown", reasons=(runtime,)
    )
    return ForwardingPolicyCalculation(
        policy_status=policy,
        status="not_enough_evidence" if policy == "not_enough_evidence" else "unknown",
        trace=tuple(
            stages.get(name, ForwardingPolicyStage(stage=name, outcome="skipped"))
            for name in STAGE_ORDER
        ),
        reasons=tuple(reasons),
    )
