"""Проверки роли, полноты и трассировки сетевого адаптера ASA."""

from typing import Any

import pytest
from pydantic import ValidationError
from tests.network_fixtures import make_network_request

from firewall_compliance.devices.ngfw.cisco.asa.network import CiscoAsaNetworkParser
from firewall_compliance.domain import DataOrigin, DataStatus, ParseIssueLevel, SourceDocumentKind
from firewall_compliance.parsers.contracts import ParseFailure
from firewall_compliance.parsers.network_contracts import NetworkParseResult, NetworkSourceKind

_INTERFACE = (
    "interface GigabitEthernet0/0\n nameif outside\n security-level 0\n"
    " ip address 192.0.2.2 255.255.255.0\n!\n"
)
_RIB = (
    "C 192.0.2.0 255.255.255.0 is directly connected, outside\n"
    "S 198.51.100.0 255.255.255.0 [1/0] via 192.0.2.1, outside\n"
)
_ROUTE = "route outside 198.51.100.0 255.255.255.0 192.0.2.1 1\n"


@pytest.mark.parametrize(
    "payload,filename",
    [
        (_INTERFACE, "asa_running_config_interfaces.cfg"),
        (_RIB, "asa_ipv4_rib.txt"),
        (_ROUTE, "asa_running_config_static_routes.cfg"),
        ("", "show-route-9.16.txt"),
    ],
)
def test_detection_requires_metadata_even_for_named_recognizable_payloads(
    payload: str,
    filename: str,
) -> None:
    source = make_network_request(payload).source.model_copy(update={"source_name": filename})
    detection = CiscoAsaNetworkParser().detect(source)
    assert not detection.is_match
    assert detection.confidence == 0
    assert detection.reasons


def test_explicit_detection_uses_metadata_without_inferring_payload_role() -> None:
    parser = CiscoAsaNetworkParser()
    request = make_network_request(_RIB)
    detection = parser.detect(request.source, request.metadata)
    assert detection.is_match
    outcome = parser.parse(request)
    assert isinstance(outcome, NetworkParseResult)
    assert outcome.scope == "interfaces"
    assert outcome.status == DataStatus.UNKNOWN
    assert not outcome.routes and not outcome.collection_evidence.complete
    assert outcome.unsupported_constructs


def test_detection_rejects_hash_mismatch() -> None:
    request = make_network_request("")
    metadata = request.metadata.model_copy(update={"content_sha256": "0" * 64})
    detection = CiscoAsaNetworkParser().detect(request.source, metadata)
    assert not detection.is_match and detection.confidence == 0


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"command": "show running-config"}, "network_command_mismatch"),
        ({"command": "show route"}, "network_command_mismatch"),
        ({"command": "show running-config interface | include nameif"}, "network_command_mismatch"),
        ({"declared_version": "9.18"}, "network_version_unsupported"),
        ({"declared_version": "9.16(1)junk"}, "network_version_unsupported"),
        ({"address_family": "ipv6"}, "network_scope_unsupported"),
        ({"table_role": "management"}, "network_scope_unsupported"),
        ({"table_id": "other"}, "network_scope_unsupported"),
        ({"context_mode": "multiple", "context": "tenant"}, "network_mode_unsupported"),
        ({"firewall_mode": "transparent"}, "network_mode_unsupported"),
    ],
)
def test_unsupported_metadata_returns_failure_before_creating_facts(
    changes: dict[str, Any],
    code: str,
) -> None:
    request = make_network_request(_INTERFACE, **changes)
    parser = CiscoAsaNetworkParser()
    assert not parser.detect(request.source, request.metadata).is_match
    outcome = parser.parse(request)
    assert isinstance(outcome, ParseFailure)
    assert code in {issue.code for issue in outcome.errors}
    assert all(issue.level == ParseIssueLevel.ERROR for issue in outcome.errors)
    assert outcome.content_sha256 == request.source.content_sha256
    assert outcome.source_name == request.source.source_name


@pytest.mark.parametrize("encoding,payload", [("ascii", b"\xff"), ("utf-8", b"\xc3(")])
def test_invalid_encoding_returns_explicit_failure(encoding: str, payload: bytes) -> None:
    request = make_network_request(payload, encoding=encoding)
    outcome = CiscoAsaNetworkParser().parse(request)
    assert isinstance(outcome, ParseFailure)
    assert [issue.code for issue in outcome.errors] == ["network_encoding_invalid"]
    assert outcome.content_sha256 == request.source.content_sha256


@pytest.mark.parametrize(
    "kind",
    [
        "asa_running_config_interfaces",
        "asa_running_config_static_routes",
        "asa_ipv4_rib",
    ],
)
@pytest.mark.parametrize(
    "observed,complete,expected",
    [
        (True, True, DataStatus.ABSENT),
        (False, True, DataStatus.UNKNOWN),
        (True, False, DataStatus.UNKNOWN),
        (False, False, DataStatus.UNKNOWN),
    ],
)
def test_empty_set_requires_full_capture_and_observation(
    kind: NetworkSourceKind,
    observed: bool,
    complete: bool,
    expected: DataStatus,
) -> None:
    request = make_network_request("", kind, observed=observed, complete=complete)
    outcome = CiscoAsaNetworkParser().parse(request)
    assert isinstance(outcome, NetworkParseResult)
    assert outcome.status == expected
    assert outcome.collection_evidence.complete == (expected == DataStatus.ABSENT)
    assert not outcome.interfaces and not outcome.routes
    codes = {issue.code for issue in outcome.warnings}
    assert ("network_observation_missing" in codes) == (not observed)
    assert ("network_capture_partial" in codes) == (not complete)


@pytest.mark.parametrize(
    "text,kind,count",
    [
        (_INTERFACE, "asa_running_config_interfaces", 1),
        (_RIB, "asa_ipv4_rib", 2),
        (_ROUTE, "asa_running_config_static_routes", 1),
    ],
)
def test_clean_observed_full_capture_is_known_with_imported_provenance(
    text: str,
    kind: NetworkSourceKind,
    count: int,
) -> None:
    request = make_network_request(text, kind, declared_version="9.16(4)")
    outcome = CiscoAsaNetworkParser().parse(request)
    assert isinstance(outcome, NetworkParseResult)
    assert outcome.status == DataStatus.KNOWN
    assert outcome.collection_evidence.complete
    assert not outcome.errors and not outcome.warnings and not outcome.unsupported_constructs
    assert outcome.source.observation == request.source.observation
    assert outcome.source.content_sha256 == request.source.content_sha256
    assert outcome.source.source_document_id == request.metadata.source_document_id
    assert outcome.collection_evidence.source_document_ids == (request.metadata.source_document_id,)
    assert outcome.source.kind == (
        SourceDocumentKind.ROUTING_TABLE
        if kind == "asa_ipv4_rib"
        else SourceDocumentKind.CONFIGURATION
    )
    facts = (*outcome.interfaces, *outcome.routes)
    assert len(facts) == count
    identifiers = tuple(item.interface_id for item in outcome.interfaces) + tuple(
        item.route_id for item in outcome.routes
    )
    for identifier, fact in zip(identifiers, facts, strict=True):
        assert fact.origin == DataOrigin.IMPORTED
        assert fact.source_document_id == request.metadata.source_document_id
        assert fact.device_id == request.metadata.device_id
        assert fact.source_location is not None
        assert fact.source_location.source_name == request.source.source_name
        assert outcome.source_map[identifier] == fact.source_location
    if outcome.interfaces:
        assert outcome.interfaces[0].enabled is None
        assert outcome.interfaces[0].zone is None
        assert outcome.interfaces[0].source_location is not None
        assert outcome.interfaces[0].source_location.line_start == 1
        assert outcome.interfaces[0].source_location.line_end == 4
        assert [loc.line_start for loc in outcome.interface_settings[0].source_locations] == [2, 3]
        assert not outcome.routes
    else:
        assert [loc.line_start for loc in outcome.source_map.values()] == list(range(1, count + 1))


@pytest.mark.parametrize(
    "text,diagnostic",
    [
        ("interface Ethernet0/0\n management-only\n", "unsupported_constructs"),
        ("interface Ethernet0/0\n security-level 999\n", "errors"),
    ],
)
def test_diagnostics_override_full_metadata_claim(text: str, diagnostic: str) -> None:
    request = make_network_request(text)
    outcome = CiscoAsaNetworkParser().parse(request)
    assert isinstance(outcome, NetworkParseResult)
    assert outcome.metadata.complete
    assert getattr(outcome, diagnostic)
    assert outcome.status == DataStatus.UNKNOWN
    assert not outcome.collection_evidence.complete


def test_failed_capture_cannot_claim_absent() -> None:
    request = make_network_request("", complete=False, capture_success=False)
    outcome = CiscoAsaNetworkParser().parse(request)
    assert isinstance(outcome, NetworkParseResult)
    assert outcome.status == DataStatus.UNKNOWN
    assert "network_capture_failed" in {issue.code for issue in outcome.warnings}


def test_parser_revalidates_copied_requests_before_processing() -> None:
    request = make_network_request(_INTERFACE)
    invalid_metadata = request.metadata.model_copy(update={"content_sha256": "0" * 64})
    with pytest.raises(ValidationError):
        CiscoAsaNetworkParser().parse(request.model_copy(update={"metadata": invalid_metadata}))


def test_result_and_json_roundtrip_are_deeply_frozen_and_independent() -> None:
    request = make_network_request(_INTERFACE)
    original_json = request.model_dump_json()
    result = CiscoAsaNetworkParser().parse(request)
    assert isinstance(result, NetworkParseResult)
    restored = NetworkParseResult.model_validate_json(result.model_dump_json())
    assert restored == result
    assert request.model_dump_json() == original_json
    for outcome in (result, restored):
        with pytest.raises(TypeError):
            outcome.status = DataStatus.UNKNOWN
        with pytest.raises(TypeError):
            outcome.metadata.complete = False
        with pytest.raises(TypeError):
            outcome.interface_labels["outside"] = "tampered"
        with pytest.raises(TypeError):
            outcome.source_map.clear()
        with pytest.raises(TypeError):
            outcome.interfaces[0].addresses = ()
        with pytest.raises(TypeError):
            outcome.interface_settings[0].security_level = 100
        with pytest.raises(TypeError):
            outcome.interface_settings[0].source_locations[0].line_start = 999
        with pytest.raises(TypeError):
            outcome.source_map[outcome.interfaces[0].interface_id].line_start = 999
        assert outcome.source.observation is not None
        with pytest.raises(TypeError):
            outcome.source.observation.reference = "tampered"
        with pytest.raises(TypeError):
            outcome.collection_evidence.complete = False


def test_result_observation_is_detached_from_frozen_source_evidence() -> None:
    request = make_network_request(_INTERFACE)
    result = CiscoAsaNetworkParser().parse(request)
    assert isinstance(result, NetworkParseResult)
    saved_json = result.model_dump_json()
    assert request.source.observation is not None
    assert result.source.observation is not request.source.observation
    with pytest.raises(ValidationError):
        request.source.observation.reference = "Changed by caller after parsing"
    assert result.model_dump_json() == saved_json
