"""Нельзя повысить достоверность результата через непроверенные вложенные модели."""

import pytest
from pydantic import ValidationError
from tests.network_fixtures import make_network_request

from firewall_compliance.domain import SourceDocumentKind
from firewall_compliance.parsers import CiscoAsaNetworkParser, NetworkParseResult


def parsed_route() -> NetworkParseResult:
    result = CiscoAsaNetworkParser().parse(
        make_network_request(
            "route outside 0.0.0.0 0.0.0.0 192.0.2.1 1\n", "asa_running_config_static_routes"
        )
    )
    assert isinstance(result, NetworkParseResult)
    return result


@pytest.mark.parametrize(
    "updates", [{"metric": -1}, {"administrative_distance": 999}, {"next_hop": "not-ip"}]
)
def test_copied_route_does_not_bypass_nested_validation(updates: dict) -> None:
    result = parsed_route()
    payload = result.model_dump(mode="python")
    payload["routes"] = (result.routes[0].model_copy(update=updates),)
    with pytest.raises(ValidationError):
        NetworkParseResult.model_validate(payload)


def test_source_kind_cannot_be_swapped_between_config_and_rib() -> None:
    result = parsed_route()
    payload = result.model_dump(mode="python")
    payload["source"] = result.source.model_copy(update={"kind": SourceDocumentKind.ROUTING_TABLE})
    with pytest.raises(ValidationError):
        NetworkParseResult.model_validate(payload)


def test_direct_copied_result_is_revalidated() -> None:
    result = parsed_route()
    bad = result.model_copy(
        update={"routes": (result.routes[0].model_copy(update={"metric": -1}),)}
    )
    with pytest.raises(ValidationError):
        NetworkParseResult.model_validate(bad)
