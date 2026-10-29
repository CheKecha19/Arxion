"""Инварианты метаданных, bindings и неизменяемых сетевых результатов."""

from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.network_fixtures import make_network_request

from firewall_compliance.devices.ngfw.cisco.asa.network import CiscoAsaNetworkParser
from firewall_compliance.domain import DataStatus, Interface, ParseIssue, ParseIssueLevel
from firewall_compliance.parsers.network_contracts import (
    NetworkDocumentMetadata,
    NetworkInterfaceBinding,
    NetworkParseRequest,
    NetworkParseResult,
)


@pytest.mark.parametrize(
    "changes",
    [
        {"selection": "authored_excerpt"},
        {"selection": "partial"},
        {"selection": "filtered"},
        {"selection": "single_interface"},
        {"extent": "excerpt"},
        {"extent": "truncated"},
        {"capture_success": False},
        {"completeness_reference": None},
        {"completeness_reference": "   "},
    ],
)
def test_full_claim_requires_every_completeness_condition(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_network_request("", **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"selection": "filtered"},
        {"extent": "truncated"},
        {"capture_success": False},
        {"completeness_reference": None},
    ],
)
def test_partial_metadata_can_preserve_capture_limitations(changes: dict[str, Any]) -> None:
    request = make_network_request("", complete=False, **changes)
    assert not request.metadata.complete


@pytest.mark.parametrize(
    "field",
    [
        "source_kind",
        "command",
        "device_id",
        "source_document_id",
        "declared_version",
        "version_provenance",
        "version_reference",
        "origin",
        "origin_reference",
        "context_mode",
        "firewall_mode",
        "address_family",
        "table_role",
        "table_id",
        "content_sha256",
        "encoding",
        "selection",
        "extent",
        "capture_success",
    ],
)
def test_explicit_metadata_fields_cannot_be_inferred(field: str) -> None:
    data = make_network_request("").metadata.model_dump(mode="python")
    del data[field]
    with pytest.raises(ValidationError):
        NetworkDocumentMetadata.model_validate(data)


def test_unknown_role_and_extra_metadata_are_rejected() -> None:
    data = make_network_request("").metadata.model_dump(mode="python")
    with pytest.raises(ValidationError):
        NetworkDocumentMetadata.model_validate({**data, "source_kind": "full_running_config"})
    with pytest.raises(ValidationError):
        NetworkDocumentMetadata.model_validate({**data, "inferred_complete": True})
    with pytest.raises(ValidationError):
        make_network_request("", context="unexpected-single-context")


def test_hash_identity_is_verified_and_hex_case_is_accepted() -> None:
    with pytest.raises(ValidationError, match="SHA-256"):
        make_network_request("", content_sha256="0" * 64)
    request = make_network_request("")
    metadata = request.metadata.model_copy(
        update={
            "content_sha256": request.source.content_sha256.upper(),
        }
    )
    checked = NetworkParseRequest.model_validate(request.model_copy(update={"metadata": metadata}))
    assert checked.metadata.content_sha256.lower() == checked.source.content_sha256


@pytest.mark.parametrize("naive", [True, False])
def test_import_time_is_aware_and_not_before_capture(naive: bool) -> None:
    request = make_network_request("")
    imported_at = (
        request.imported_at.replace(tzinfo=None)
        if naive
        else request.source.captured_at - timedelta(seconds=1)
    )
    with pytest.raises(ValidationError):
        NetworkParseRequest.model_validate(request.model_copy(update={"imported_at": imported_at}))


def test_case_insensitive_duplicate_binding_and_multiple_labels_are_rejected() -> None:
    request = make_network_request("")
    first = request.interfaces[0]
    second = first.model_copy(
        update={"interface_id": "interface:Ethernet0/1", "name": "Ethernet0/1"}
    )
    with pytest.raises(ValidationError, match="labels"):
        make_network_request(
            "",
            interfaces=(first, second),
            bindings=(
                NetworkInterfaceBinding(label="outside", interface_id=first.interface_id),
                NetworkInterfaceBinding(label="OUTSIDE", interface_id=second.interface_id),
            ),
        )
    with pytest.raises(ValidationError, match="несколько labels"):
        make_network_request(
            "",
            bindings=(
                NetworkInterfaceBinding(label="outside", interface_id=first.interface_id),
                NetworkInterfaceBinding(label="inside", interface_id=first.interface_id),
            ),
        )


@pytest.mark.parametrize("problem", ["missing", "unknown", "wrong_device", "duplicate"])
def test_bindings_require_unique_known_interfaces_of_same_device(problem: str) -> None:
    request = make_network_request("")
    interface = request.interfaces[0]
    interfaces = request.interfaces
    if problem == "missing":
        interfaces = ()
    elif problem == "unknown":
        interfaces = (interface.model_copy(update={"data_status": DataStatus.UNKNOWN}),)
    elif problem == "wrong_device":
        interfaces = (interface.model_copy(update={"device_id": "another-device"}),)
    else:
        interfaces = (interface, interface)
    with pytest.raises(ValidationError):
        make_network_request("", interfaces=interfaces, bindings=request.bindings)


def test_request_revalidates_metadata_and_interface_instances() -> None:
    request = make_network_request("")
    invalid_metadata = request.metadata.model_copy(update={"extent": "excerpt"})
    with pytest.raises(ValidationError):
        NetworkParseRequest.model_validate(
            request.model_copy(update={"metadata": invalid_metadata})
        )
    invalid_interface = request.interfaces[0].model_copy(update={"addresses": ("bad-address",)})
    with pytest.raises(ValidationError):
        NetworkParseRequest.model_validate(
            request.model_copy(update={"interfaces": (invalid_interface,)})
        )


def test_request_freezes_nested_interfaces_and_returns_binding_copy() -> None:
    request = make_network_request("")
    binding = NetworkInterfaceBinding(
        label="OUTSIDE", interface_id=request.interfaces[0].interface_id
    )
    request = make_network_request("", interfaces=request.interfaces, bindings=(binding,))
    labels = request.interface_labels
    labels["outside"] = "tampered"
    labels.clear()
    assert request.interface_labels == {"outside": request.interfaces[0].interface_id}
    with pytest.raises(ValidationError):
        request.bindings = ()
    with pytest.raises(ValidationError):
        request.bindings[0].label = "inside"
    with pytest.raises(TypeError):
        request.interfaces[0].name = "tampered"
    assert request.interfaces[0].source_location is not None
    with pytest.raises(TypeError):
        request.interfaces[0].source_location.line_start = 99
    restored = NetworkParseRequest.model_validate_json(request.model_dump_json())
    assert restored == request
    with pytest.raises(TypeError):
        restored.interfaces[0].source_location = None


def test_request_snapshot_is_detached_from_caller_interface_location() -> None:
    template = make_network_request("")
    interface = Interface.model_validate(template.interfaces[0].model_dump(mode="python"))
    request = make_network_request("", interfaces=(interface,), bindings=template.bindings)
    assert interface.source_location is not None
    interface.source_location.line_start = 99
    assert request.interfaces[0].source_location is not None
    assert request.interfaces[0].source_location.line_start == 1


@pytest.mark.parametrize(
    "problem",
    [
        "source_id",
        "hash",
        "device",
        "fact_source",
        "location",
        "missing_map",
        "wrong_map",
        "binding",
        "scope",
        "evidence_source",
        "warning",
        "unknown_fact",
        "absent_with_facts",
    ],
)
def test_result_rejects_inconsistent_provenance_and_false_known_status(problem: str) -> None:
    text = "interface Ethernet0/0\n nameif inside\n ip address 192.0.2.1 255.255.255.0\n"
    result = CiscoAsaNetworkParser().parse(make_network_request(text))
    assert isinstance(result, NetworkParseResult)
    data = result.model_dump(mode="python")
    other_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    if problem == "source_id":
        data["source"]["source_document_id"] = other_id
    elif problem == "hash":
        data["source"]["content_sha256"] = "0" * 64
    elif problem == "device":
        data["interfaces"][0]["device_id"] = "another-device"
    elif problem == "fact_source":
        data["interfaces"][0]["source_document_id"] = other_id
    elif problem == "location":
        data["interfaces"][0]["source_location"]["source_name"] = "another.txt"
    elif problem == "missing_map":
        data["source_map"] = {}
    elif problem == "wrong_map":
        data["source_map"][result.interfaces[0].interface_id]["line_start"] = 2
    elif problem == "binding":
        data["interface_labels"] = {"inside": "missing"}
    elif problem == "scope":
        data["collection_evidence"]["scope"] = "routing_table"
    elif problem == "evidence_source":
        data["collection_evidence"]["source_document_ids"] = (other_id,)
    elif problem == "warning":
        data["warnings"] = (
            ParseIssue(
                code="unproven",
                level=ParseIssueLevel.WARNING,
                message="Не доказано",
            ),
        )
    elif problem == "unknown_fact":
        data["interfaces"][0]["data_status"] = DataStatus.UNKNOWN
    else:
        data["status"] = DataStatus.ABSENT
    with pytest.raises(ValidationError):
        NetworkParseResult.model_validate(data)
