"""Сквозной контур parser snapshots не получает синтетическую полноту evaluator."""

import pytest
from tests.asa_forwarding_fixtures import SCENARIOS
from tests.forwarding_binding_fixtures import make_binding_inputs
from tests.golden.test_asa_forwarding_golden import parse_forwarding_scenario

from firewall_compliance.analysis.forwarding_policy import evaluate_forwarding_policy
from firewall_compliance.application.forwarding_binding import bind_forwarding_context
from firewall_compliance.domain.enums import DataStatus


def test_parser_binding_evaluator_does_not_promote_configured_context() -> None:
    imported, parsed = make_binding_inputs()
    bound = bind_forwarding_context(imported, parsed)
    before = bound.model_dump_json()
    assert bound.status == "consistent"
    result = evaluate_forwarding_policy(
        bound.forwarding.context,
        ingress_interface_id="GigabitEthernet0/1",
        egress_interface_id="GigabitEthernet0/0",
    )
    assert result.policy_status == "not_enough_evidence"
    assert result.context == parsed.context
    assert bound.model_dump_json() == before
    assert result.context.flow is None
    assert (
        next(i for i in result.context.inventories if i.feature == "effective_nat").status
        == DataStatus.UNKNOWN
    )
    assert all(not stage.rule_trace and stage.matched_rule_id is None for stage in result.trace)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_existing_parser_excerpt_never_becomes_complete_policy(scenario: str) -> None:
    parsed = parse_forwarding_scenario(scenario)
    before = parsed.model_dump_json()
    result = evaluate_forwarding_policy(
        parsed.context,
        ingress_interface_id="GigabitEthernet0/1",
        egress_interface_id="GigabitEthernet0/0",
    )
    assert result.policy_status in {"unknown", "not_enough_evidence"}
    assert parsed.model_dump_json() == before
    assert result.context == parsed.context
    assert all(not stage.rule_trace and stage.matched_rule_id is None for stage in result.trace)
