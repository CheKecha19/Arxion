"""Вход forwarding adapter связывает байты с отдельными метаданными."""

import pytest
from pydantic import ValidationError
from tests.asa_forwarding_fixtures import forwarding_request
from tests.forwarding_fixtures import make_forwarding_context

from firewall_compliance.domain.parse_result import ParseCoverage
from firewall_compliance.parsers.forwarding_contracts import (
    ForwardingParseRequest,
    ForwardingParseResult,
)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("metadata", "content_sha256", "0" * 64),
        ("metadata", "source_name", "other.cfg"),
        ("metadata", "device_context", "other"),
        ("source", "content", b"changed bytes"),
    ],
)
def test_request_revalidates_document_identity(section: str, field: str, value: object) -> None:
    payload = forwarding_request("ingress_no_match_global_permit").model_dump(mode="python")
    payload[section][field] = value
    with pytest.raises(ValidationError):
        ForwardingParseRequest.model_validate(payload)


def test_request_revalidates_unchecked_source_copy() -> None:
    request = forwarding_request("ingress_no_match_global_permit")
    payload = request.model_dump(mode="python")
    payload["source"] = request.source.model_copy(update={"content": b"unverified"})
    with pytest.raises(ValidationError):
        ForwardingParseRequest.model_validate(payload)


def test_profile_claim_requires_reference() -> None:
    payload = forwarding_request("ingress_no_match_global_permit").model_dump(mode="python")
    payload["profile_reference"] = None
    with pytest.raises(ValidationError):
        ForwardingParseRequest.model_validate(payload)


def test_request_json_round_trip() -> None:
    request = forwarding_request("ingress_no_match_global_permit")
    assert ForwardingParseRequest.model_validate_json(request.model_dump_json()) == request


def result_with_mapping() -> ForwardingParseResult:
    context = make_forwarding_context()
    mapping = {
        f"inventory:{inventory.feature}:{number}": anchor.location
        for inventory in context.inventories
        for number, anchor in enumerate(inventory.locations)
    }
    mapping.update(
        {rule.rule_id: rule.source_location for acl in context.acls for rule in acl.rules}
    )
    return ForwardingParseResult(
        context=context,
        coverage=ParseCoverage(
            discovered_constructs=0, recognized_constructs=0, unsupported_constructs=0
        ),
        source_map=mapping,
    )


def test_result_requires_mapping_for_facts() -> None:
    result = result_with_mapping()
    with pytest.raises(ValidationError):
        result.model_copy(update={"source_map": {}})


def test_result_requires_mapping_for_each_ace() -> None:
    result = result_with_mapping()
    mapping = dict(result.source_map)
    for acl in result.context.acls:
        for rule in acl.rules:
            mapping.pop(rule.rule_id)
    with pytest.raises(ValidationError):
        result.model_copy(update={"source_map": mapping})


def test_result_is_deep_snapshot_with_json_round_trip() -> None:
    result = result_with_mapping()
    assert ForwardingParseResult.model_validate_json(result.model_dump_json()) == result
    with pytest.raises(TypeError):
        result.source_map.clear()
    with pytest.raises((TypeError, ValidationError)):
        result.coverage.discovered_constructs = 1
