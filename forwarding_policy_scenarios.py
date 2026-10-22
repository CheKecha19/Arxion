"""Эталонные условные сценарии с полными собственными доменными доказательствами."""

from firewall_compliance.analysis.forwarding_policy import evaluate_forwarding_policy
from firewall_compliance.domain.forwarding_policy import ForwardingPolicyResult
from tests.forwarding_fixtures import forwarding_location, forwarding_rule
from tests.forwarding_policy_fixtures import (
    EGRESS_ID,
    INGRESS_ID,
    incomplete_feature,
    policy_context,
    policy_payload,
)

POLICY_SCENARIOS = (
    "ingress_allow",
    "global_allow",
    "ingress_deny",
    "outbound_deny",
    "same_security_deny",
    "inbound_implicit_deny",
    "empty_outbound_deny",
    "nat_unknown",
)


def policy_scenario(name: str) -> ForwardingPolicyResult:
    """Создать повторяемые факты, не повышая полноту parser excerpts."""
    if name not in POLICY_SCENARIOS:
        raise ValueError("неизвестный эталонный сценарий политики")
    values = policy_payload()
    if name in {"global_allow", "inbound_implicit_deny"}:
        values["acls"][0]["rules"] = []
    if name == "global_allow":
        values["acls"][1]["rules"] = [
            forwarding_rule(20, policy_id="GLOBAL").model_dump(mode="python")
        ]
    if name == "ingress_deny":
        values["acls"][0]["rules"][0]["action"] = "deny"
    if name in {"outbound_deny", "empty_outbound_deny"}:
        values["bindings"][1].update(
            direction="out",
            interface_id=EGRESS_ID,
            location=forwarding_location(30).model_dump(mode="python"),
        )
        if name == "outbound_deny":
            values["acls"][1]["rules"] = [
                forwarding_rule(20, policy_id="GLOBAL", action="deny").model_dump(mode="python")
            ]
    if name == "same_security_deny":
        values["interfaces"][1]["security_level"] = 100
        values["toggles"][0]["value"] = False
    if name == "nat_unknown":
        incomplete_feature(values, "effective_nat")
    return evaluate_forwarding_policy(
        policy_context(values), ingress_interface_id=INGRESS_ID, egress_interface_id=EGRESS_ID
    )
