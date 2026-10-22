"""Публичный API условной цепочки политик, без выбора реального egress."""

from firewall_compliance.domain.forwarding import ForwardingContext
from firewall_compliance.domain.forwarding_policy import ForwardingPolicyResult
from firewall_compliance.domain.forwarding_policy_evaluation import derive_forwarding_policy


def evaluate_forwarding_policy(
    context: ForwardingContext,
    *,
    ingress_interface_id: str,
    egress_interface_id: str,
) -> ForwardingPolicyResult:
    """Оценить заданную пару физических интерфейсов и сохранить проверяемый снимок."""
    context = ForwardingContext.model_validate(context.model_dump(mode="python"))
    ingress_interface_id, egress_interface_id = (
        ingress_interface_id.strip(),
        egress_interface_id.strip(),
    )
    calculated = derive_forwarding_policy(
        context, ingress_interface_id=ingress_interface_id, egress_interface_id=egress_interface_id
    )
    return ForwardingPolicyResult(
        context=context,
        ingress_interface_id=ingress_interface_id,
        egress_interface_id=egress_interface_id,
        status=calculated.status,
        policy_status=calculated.policy_status,
        trace=calculated.trace,
        reasons=calculated.reasons,
    )
