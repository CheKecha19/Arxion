"""Проверки безопасного разбора фактов пересылки ASA."""

from typing import Any

import pytest
from pydantic import ValidationError
from tests.forwarding_fixtures import (
    CAPTURED_AT,
    CONFIG_SOURCE_ID,
    CONFIGURATION_ID,
    DEVICE_ID,
    IMPORTED_AT,
    REVISION_ID,
)

from firewall_compliance.devices.ngfw.cisco.asa.forwarding import CiscoAsaForwardingParser
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.forwarding import FEATURE_SCOPES, ForwardingSource
from firewall_compliance.domain.observation import ObservationEvidence
from firewall_compliance.parsers.contracts import ParseFailure, SourceDocument
from firewall_compliance.parsers.forwarding_contracts import (
    ForwardingParseRequest,
    ForwardingParseResult,
)

BASE = (
    b"ASA Version 9.16(4)\n"
    b"interface GigabitEthernet0/0\n"
    b" nameif inside\n"
    b" security-level 100\n"
    b" ip address 192.0.2.1 255.255.255.0\n"
    b"!\n"
    b"access-list FIRST extended permit ip any any\n"
    b"access-list SECOND extended deny ip any any\n"
)
FULL_CONFIGURATION = (
    BASE
    + b"access-group FIRST in interface inside\n"
    + b"no same-security-traffic permit inter-interface\n"
    + b"no same-security-traffic permit intra-interface\n"
    + b"no sysopt connection permit-vpn\n"
)


def forwarding_request(
    content: bytes = BASE,
    *,
    source_name: str = "synthetic-asa.cfg",
    metadata_changes: dict[str, Any] | None = None,
    **changes: Any,
) -> ForwardingParseRequest:
    observation = (metadata_changes or {}).get("observation")
    source = SourceDocument(
        source_name=source_name,
        content=content,
        captured_at=CAPTURED_AT,
        observation=observation,
    )
    metadata = ForwardingSource.model_validate(
        {
            "source_document_id": CONFIG_SOURCE_ID,
            "source_name": source.source_name,
            "content_sha256": source.content_sha256,
            "purpose": "configuration",
            "device_id": DEVICE_ID,
            "command": "show running-config",
            "declared_version": "9.16",
            "version_provenance": "documentation",
            "version_reference": "Synthetic ASA 9.16 declaration",
            "origin": "synthetic",
            "origin_reference": "Authored test excerpt",
            "captured_at": CAPTURED_AT,
            "selection": "authored_excerpt",
            "extent": "excerpt",
            "encoding": "ascii",
            "capture_success": True,
            **(metadata_changes or {}),
        }
    )
    return ForwardingParseRequest(
        source=source,
        metadata=metadata,
        revision_id=REVISION_ID,
        configuration_id=CONFIGURATION_ID,
        imported_at=IMPORTED_AT,
        **changes,
    )


def parse_success(request: ForwardingParseRequest) -> ForwardingParseResult:
    result = CiscoAsaForwardingParser().parse(request)
    assert isinstance(result, ForwardingParseResult), result
    assert result.context.revision_id == request.revision_id
    assert result.context.configuration_id == request.configuration_id
    return result


def full_forwarding_request(content: bytes = FULL_CONFIGURATION) -> ForwardingParseRequest:
    scopes = tuple(sorted(set().union(*FEATURE_SCOPES.values()) - {"effective_nat"}))
    return forwarding_request(
        content,
        metadata_changes={
            "command": "show running-config all",
            "selection": "all",
            "extent": "full",
            "complete_scopes": scopes,
            "completeness_reference": "Synthetic exhaustive configuration declaration",
            "observation": ObservationEvidence(
                observed_at=CAPTURED_AT,
                method="synthetic",
                reference="Synthetic full capture observation",
            ),
        },
        context_mode="single",
        firewall_mode="routed",
        address_family="ipv4",
        table_role="data",
        table_id="default",
        profile_reference="Synthetic profile declaration",
    )


def test_detection_requires_metadata() -> None:
    parser = CiscoAsaForwardingParser()
    request = forwarding_request()
    assert parser.detect(request.source, request.metadata).is_match
    detection = parser.detect(request.source, None)
    assert not detection.is_match
    assert detection.confidence == 0


def test_mismatched_hash_is_rejected_by_request_validation() -> None:
    with pytest.raises(ValidationError):
        forwarding_request(metadata_changes={"content_sha256": "0" * 64})


@pytest.mark.parametrize(
    "content,metadata_changes",
    [
        (BASE + b"hostname \xff\n", {}),
        (BASE + b"hostname \xff\n", {"encoding": "utf-8"}),
        (BASE, {"command": "show access-list"}),
        (BASE, {"declared_version": "8.4"}),
        (BASE.replace(b"9.16(4)", b"8.4(1)"), {}),
        (BASE.replace(b"ASA Version", b"IOS Version"), {}),
        (BASE.split(b"\n", 1)[1], {}),
        (BASE + b"ASA Version 9.16(4)\n", {}),
        (BASE + b"ASA Version 9.16(3)\n", {"declared_version": "9.16"}),
    ],
    ids=[
        "ascii",
        "utf8",
        "command",
        "metadata-version",
        "header-version",
        "ios",
        "no-header",
        "repeated-header",
        "second-header-other-build",
    ],
)
def test_invalid_source_is_not_detected_and_returns_failure(
    content: bytes, metadata_changes: dict[str, Any]
) -> None:
    parser = CiscoAsaForwardingParser()
    request = forwarding_request(content, metadata_changes=metadata_changes)
    detection = parser.detect(request.source, request.metadata)
    assert not detection.is_match
    assert detection.confidence == 0
    result = parser.parse(request)
    assert isinstance(result, ParseFailure)
    assert result.errors
    assert result.source_name == request.source.source_name
    assert result.content_sha256 == request.source.content_sha256


def test_undeclared_profile_and_toggles_remain_unknown() -> None:
    result = parse_success(forwarding_request())
    context = result.context
    assert context.observed_at is None
    assert context.flow is None
    assert all(
        getattr(context, field) is None
        for field in (
            "context_mode",
            "firewall_mode",
            "address_family",
            "table_role",
            "table_id",
            "profile_reference",
        )
    )
    toggles = {item.name: item for item in context.toggles}
    assert set(toggles) == {"inter_interface", "intra_interface", "permit_vpn"}
    assert all(t.status == DataStatus.UNKNOWN and t.value is None for t in toggles.values())
    assert {i.feature for i in context.inventories} == set(FEATURE_SCOPES)
    assert all(i.status == DataStatus.UNKNOWN and not i.complete for i in context.inventories)


def test_explicit_profile_is_preserved() -> None:
    profile = {
        "context_mode": "single",
        "firewall_mode": "routed",
        "address_family": "ipv4",
        "table_role": "data",
        "table_id": "default",
        "profile_reference": "Synthetic profile declaration",
    }
    context = parse_success(forwarding_request(**profile)).context
    assert all(getattr(context, field) == value for field, value in profile.items())


@pytest.mark.parametrize(
    "line",
    [
        b"access-group FIRST\n",
        b"access-group FIRST sideways interface inside\n",
        b"access-group FIRST in interface\n",
        b"access-group FIRST global interface inside\n",
        b"access-group FIRST in interface missing\n",
    ],
)
def test_malformed_binding_never_becomes_a_known_binding(line: bytes) -> None:
    result = CiscoAsaForwardingParser().parse(forwarding_request(BASE + line))
    if isinstance(result, ParseFailure):
        assert result.errors
        return
    assert result.errors or result.warnings or result.unsupported_constructs
    assert not result.context.bindings
    inventory = next(i for i in result.context.inventories if i.feature == "acl_bindings")
    assert inventory.status in {DataStatus.UNKNOWN, DataStatus.UNSUPPORTED}
    assert not inventory.complete


@pytest.mark.parametrize(
    "first,second",
    [
        (b"FIRST in interface inside", b"SECOND in interface inside"),
        (b"SECOND in interface inside", b"FIRST in interface inside"),
        (b"FIRST global", b"SECOND global"),
        (b"SECOND global", b"FIRST global"),
    ],
)
def test_conflicting_bindings_do_not_use_last_wins(first: bytes, second: bytes) -> None:
    content = BASE + b"access-group " + first + b"\naccess-group " + second + b"\n"
    result = CiscoAsaForwardingParser().parse(forwarding_request(content))
    if isinstance(result, ParseFailure):
        assert result.errors
        return
    assert result.errors or result.warnings or result.unsupported_constructs
    assert not result.context.bindings
    assert not next(i for i in result.context.inventories if i.feature == "acl_bindings").complete


@pytest.mark.parametrize(
    "extra",
    [
        b" security-level 0\n",
        b" nameif outside\n",
        b" security-level invalid\n",
        b" ip address invalid\n",
    ],
)
def test_interface_conflicts_do_not_create_known_physical_l3(extra: bytes) -> None:
    content = BASE.replace(b"!\n", extra + b"!\n", 1)
    result = CiscoAsaForwardingParser().parse(forwarding_request(content))
    if isinstance(result, ParseFailure):
        assert result.errors
        return
    assert result.errors or result.warnings or result.unsupported_constructs
    assert not next(i for i in result.context.inventories if i.feature == "interfaces").complete
    assert all(
        i.physical_l3 is not True or i.security_status == DataStatus.UNKNOWN
        for i in result.context.interfaces
    )


@pytest.mark.parametrize("interface", [b"Management0/0", b"BVI1", b"GigabitEthernet0/0.10"])
def test_special_interfaces_are_not_assumed_physical_l3(interface: bytes) -> None:
    content = BASE.replace(b"GigabitEthernet0/0", interface)
    result = CiscoAsaForwardingParser().parse(forwarding_request(content))
    if isinstance(result, ParseFailure):
        assert result.errors
        return
    assert all(i.physical_l3 is not True for i in result.context.interfaces)


def test_name_and_security_level_alone_do_not_prove_physical_l3() -> None:
    content = BASE.replace(b" ip address 192.0.2.1 255.255.255.0\n", b"")
    result = parse_success(forwarding_request(content))
    assert all(i.physical_l3 is not True for i in result.context.interfaces)


@pytest.mark.parametrize(
    "commands",
    [
        b"same-security-traffic permit unknown-direction\n",
        b"same-security-traffic permit inter-interface\n"
        b"no same-security-traffic permit inter-interface\n",
        b"no same-security-traffic permit inter-interface\n"
        b"same-security-traffic permit inter-interface\n",
        b"sysopt connection permit-vpn\nno sysopt connection permit-vpn\n",
        b"no sysopt connection permit-vpn\nsysopt connection permit-vpn\n",
    ],
)
def test_unknown_or_conflicting_toggles_do_not_become_effective_false(commands: bytes) -> None:
    result = CiscoAsaForwardingParser().parse(forwarding_request(BASE + commands))
    if isinstance(result, ParseFailure):
        assert result.errors
        return
    assert result.errors or result.warnings or result.unsupported_constructs
    name = "permit_vpn" if b"sysopt" in commands else "inter_interface"
    toggle = next(t for t in result.context.toggles if t.name == name)
    assert toggle.status in {DataStatus.UNKNOWN, DataStatus.UNSUPPORTED}
    assert toggle.value is None


def test_unknown_line_invalidates_even_declared_full_absence() -> None:
    content = FULL_CONFIGURATION + b"unrecognized-forwarding-command enable\n"
    request = full_forwarding_request(content)
    result = CiscoAsaForwardingParser().parse(request)
    if isinstance(result, ParseFailure):
        assert result.errors
        return
    assert result.errors or result.warnings or result.unsupported_constructs
    assert all(i.status != DataStatus.ABSENT for i in result.context.inventories)
    assert all(not i.complete for i in result.context.inventories)
    effective = next(i for i in result.context.inventories if i.feature == "effective_nat")
    assert effective.status == DataStatus.UNKNOWN


def test_full_observed_source_proves_only_explicitly_enumerated_features() -> None:
    request = full_forwarding_request()
    result = parse_success(request)
    assert not result.errors and not result.unsupported_constructs
    inventories = {item.feature: item for item in result.context.inventories}
    for feature in ("configured_nat", "pbr", "exceptions"):
        item = inventories[feature]
        assert item.status == DataStatus.ABSENT
        assert item.complete and item.enumeration_complete
        assert item.item_count == 0 and item.locations == ()
    for feature in ("interfaces", "acl_definitions", "acl_bindings", "same_security", "vpn_bypass"):
        item = inventories[feature]
        assert item.status == DataStatus.KNOWN
        assert item.complete and item.enumeration_complete
        assert item.source_document_ids == (CONFIG_SOURCE_ID,)
    effective = inventories["effective_nat"]
    assert effective.status == DataStatus.UNKNOWN
    assert not effective.complete and not effective.enumeration_complete
    assert result.context.observed_at == CAPTURED_AT
    assert all(acl.complete and acl.status == DataStatus.KNOWN for acl in result.context.acls)
    assert all(t.status == DataStatus.KNOWN and t.value is False for t in result.context.toggles)


def test_full_source_unresolved_network_object_keeps_acl_unknown() -> None:
    content = FULL_CONFIGURATION.replace(
        b"access-list FIRST extended permit ip any any",
        b"access-list FIRST extended permit ip object MISSING any",
    )
    result = parse_success(full_forwarding_request(content))
    acl = next(acl for acl in result.context.acls if acl.policy_id == "FIRST")
    assert acl.status == DataStatus.UNKNOWN and not acl.complete
    assert result.errors or result.warnings or result.unsupported_constructs
    inventory = next(i for i in result.context.inventories if i.feature == "acl_definitions")
    assert inventory.status == DataStatus.UNKNOWN and not inventory.complete


@pytest.mark.parametrize(
    "child",
    [
        b" host 192.0.2.10 unexpected\n",
        b" subnet 192.0.2.0 255.255.255.0 unexpected\n",
        b" range 192.0.2.10 192.0.2.20 unexpected\n",
    ],
    ids=["host", "subnet", "range"],
)
def test_malformed_network_object_child_cannot_prove_known_complete_acl(child: bytes) -> None:
    content = FULL_CONFIGURATION.replace(
        b"access-list FIRST extended permit ip any any",
        b"object network LOCAL\n"
        + child
        + b"!\naccess-list FIRST extended permit ip object LOCAL any",
    )
    result = parse_success(full_forwarding_request(content))
    acl = next(acl for acl in result.context.acls if acl.policy_id == "FIRST")
    assert acl.status == DataStatus.UNKNOWN and not acl.complete
    assert result.errors or result.warnings or result.unsupported_constructs
    inventory = next(i for i in result.context.inventories if i.feature == "acl_definitions")
    assert inventory.status == DataStatus.UNKNOWN and not inventory.complete


@pytest.mark.parametrize("address", [b"0.0.0.0", b"224.0.0.1", b"255.255.255.255"])
def test_invalid_unicast_interface_address_does_not_prove_physical_l3(address: bytes) -> None:
    content = FULL_CONFIGURATION.replace(b"192.0.2.1 255.255.255.0", address + b" 255.255.255.0")
    result = parse_success(full_forwarding_request(content))
    assert result.context.interfaces
    assert all(interface.physical_l3 is not True for interface in result.context.interfaces)


def test_parse_revalidates_request_copy_with_tampered_source_content() -> None:
    request = full_forwarding_request()
    source = request.source.model_copy(update={"content": request.source.content + b"! tampered\n"})
    tampered = request.model_copy(update={"source": source})
    assert tampered.metadata.content_sha256 != tampered.source.content_sha256
    result = CiscoAsaForwardingParser().parse(tampered)
    assert isinstance(result, ParseFailure)
    assert result.errors
    assert result.content_sha256 == source.content_sha256
