"""Синтетические проверки узкой грамматики интерфейсов ASA."""

import pytest
from tests.network_fixtures import make_network_request

from firewall_compliance.domain import DataOrigin, DataStatus
from firewall_compliance.parsers.asa_network_interfaces import parse_interfaces


def test_explicit_facts_preserve_host_and_body_locations() -> None:
    text = (
        "!\ninterface GigabitEthernet0/0\n nameif OutSIDE\n security-level 0\n"
        " ip address 192.0.2.129 255.255.255.0\n no shutdown\n!\n"
    )
    request = make_network_request(text)
    facts = parse_interfaces(request, text)
    (interface,) = facts.interfaces
    assert interface.interface_id == "interface:GigabitEthernet0/0"
    assert interface.name == "GigabitEthernet0/0"
    assert interface.device_id == request.metadata.device_id
    assert interface.origin == DataOrigin.IMPORTED
    assert interface.source_document_id == request.metadata.source_document_id
    assert interface.addresses == ("192.0.2.129/24",)
    assert interface.networks == ("192.0.2.0/24",)
    assert interface.addresses_status == DataStatus.KNOWN
    assert interface.enabled is True
    assert interface.zone is None
    assert interface.source_location is not None
    assert interface.source_location.source_name == request.source.source_name
    assert (interface.source_location.line_start, interface.source_location.line_end) == (2, 6)
    assert facts.interface_labels == {"outside": interface.interface_id}
    (setting,) = facts.interface_settings
    assert setting.label == "OutSIDE"
    assert setting.security_level == 0
    assert [location.line_start for location in setting.source_locations] == [3, 4]
    assert facts.coverage.discovered_constructs == 5
    assert facts.coverage.recognized_constructs == 5
    assert facts.coverage.unsupported_constructs == 0
    assert not facts.errors and not facts.warnings and not facts.routes


@pytest.mark.parametrize("command,enabled", [("", None), (" shutdown", False)])
def test_no_implicit_address_or_admin_state(command: str, enabled: bool | None) -> None:
    text = f"interface Ethernet1/2\n{command}\n!\n"
    facts = parse_interfaces(make_network_request(text), text)
    (interface,) = facts.interfaces
    assert interface.enabled is enabled
    assert interface.addresses == ()
    assert interface.addresses_status == DataStatus.UNKNOWN
    assert facts.interface_settings[0].security_level is None
    assert facts.interface_settings[0].source_locations == ()
    assert facts.interface_labels == {}


def test_explicit_no_ip_address_means_absent() -> None:
    text = "interface Ethernet0/0\n no ip address\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert facts.interfaces[0].addresses_status == DataStatus.ABSENT
    assert facts.interfaces[0].addresses == ()
    assert facts.interfaces[0].enabled is None


@pytest.mark.parametrize(
    "mask,prefix",
    [
        ("0.0.0.0", 0),
        ("255.255.255.255", 32),
        ("255.255.255.254", 31),
    ],
)
def test_contiguous_mask_boundaries(mask: str, prefix: int) -> None:
    text = f"interface Ethernet0/0\n ip address 192.0.2.9 {mask}\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert facts.interfaces[0].addresses == (f"192.0.2.9/{prefix}",)
    assert not facts.errors


@pytest.mark.parametrize(
    "command",
    [
        "ip address 192.0.2.1 255.0.255.0",
        "ip address 192.0.2.1 0.0.0.255",
        "ip address 192.0.2.1 24",
        "ip address 999.0.0.1 255.255.255.0",
        "ip address 192.0.2.1 255.255.255.0 junk",
        "no ip address junk",
        "security-level 101",
        "security-level -1",
        "security-level 50 junk",
        "nameif outside junk",
        "nameif " + "x" * 49,
        "shutdown junk",
        "no shutdown junk",
    ],
)
def test_malformed_attributes_leave_unrecognized_remainder(command: str) -> None:
    text = f"interface Ethernet0/0\n {command}\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert len(facts.errors) == 1
    assert facts.errors[0].source_location is not None
    assert facts.errors[0].source_location.line_start == 2
    assert facts.interfaces[0].data_status == DataStatus.UNKNOWN
    assert facts.interfaces[0].enabled is None
    assert facts.interfaces[0].addresses_status == DataStatus.UNKNOWN
    assert facts.interface_labels == {}
    assert facts.coverage.discovered_constructs == 2
    assert facts.coverage.recognized_constructs == 1
    assert facts.coverage.unsupported_constructs == 0


@pytest.mark.parametrize(
    "command",
    [
        "ip address dhcp",
        "ip address pppoe",
        "ipv6 address 2001:db8::1/64",
        "bridge-group 1",
        "management-only",
        "channel-group 1 mode active",
        "description authored",
        "mystery command",
    ],
)
def test_unsupported_attributes_are_located_and_prevent_valid_binding(command: str) -> None:
    text = f"interface Ethernet0/0\n nameif inside\n {command}\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert facts.interfaces[0].data_status == DataStatus.UNSUPPORTED
    assert facts.interfaces[0].enabled is None
    assert facts.interface_labels == {}
    assert facts.coverage.discovered_constructs == 3
    assert facts.coverage.recognized_constructs == 2
    assert facts.coverage.unsupported_constructs == 1
    assert len(facts.unsupported_constructs) == len(facts.warnings) == 1
    assert facts.unsupported_constructs[0].source_location.line_start == 3
    assert command in facts.unsupported_constructs[0].message
    expected = (
        DataStatus.UNSUPPORTED if command.startswith(("ip address", "ipv6")) else DataStatus.UNKNOWN
    )
    assert facts.interfaces[0].addresses_status == expected


@pytest.mark.parametrize(
    "physical",
    [
        "GigabitEthernet0/0.1",
        "BVI1",
        "Port-channel1",
        "Management0/0",
        "Vlan1",
        "GigabitEthernet0/0 junk",
    ],
)
def test_unsupported_blocks_never_fabricate_interfaces(physical: str) -> None:
    text = f"interface {physical}\n nameif inside\n ip address 192.0.2.1 255.255.255.0\n!\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert not facts.interfaces and not facts.interface_settings and not facts.interface_labels
    assert facts.coverage.discovered_constructs == facts.coverage.unsupported_constructs == 3
    assert facts.coverage.recognized_constructs == 0


def test_case_insensitive_duplicate_labels_have_no_winner() -> None:
    text = "interface Ethernet0/0\n nameif inside\n!\ninterface Ethernet0/1\n nameif INSIDE\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert len(facts.interfaces) == 2
    assert facts.interface_labels == {}
    assert all(interface.data_status == DataStatus.UNKNOWN for interface in facts.interfaces)
    assert [setting.label for setting in facts.interface_settings] == ["inside", "INSIDE"]
    assert [error.code for error in facts.errors] == ["ASA_INTERFACE_DUPLICATE_LABEL"] * 2


def test_duplicate_physical_ids_have_no_winner() -> None:
    text = "interface Ethernet0/0\n nameif inside\ninterface Ethernet0/0\n nameif outside\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert not facts.interfaces and not facts.interface_labels and not facts.interface_settings
    assert [error.code for error in facts.errors] == ["ASA_INTERFACE_DUPLICATE_ID"] * 2


@pytest.mark.parametrize(
    "first,second,attribute",
    [
        ("nameif inside", "nameif outside", "label"),
        ("security-level 10", "security-level 20", "security_level"),
        ("shutdown", "no shutdown", "enabled"),
        ("ip address 192.0.2.1 255.255.255.0", "no ip address", "addresses"),
    ],
)
def test_duplicate_attributes_do_not_use_last_value(
    first: str,
    second: str,
    attribute: str,
) -> None:
    text = f"interface Ethernet0/0\n {first}\n {second}\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert facts.errors[0].code == "ASA_INTERFACE_DUPLICATE_ATTRIBUTE"
    assert facts.coverage.discovered_constructs == 3
    assert facts.coverage.recognized_constructs == 2
    owner = (
        facts.interface_settings[0]
        if attribute in {"label", "security_level"}
        else facts.interfaces[0]
    )
    assert getattr(owner, attribute) == (() if attribute == "addresses" else None)
    assert not facts.interface_labels


def test_unsupported_block_label_cannot_resolve_to_supported_interface() -> None:
    text = "interface Ethernet0/0\n nameif Inside\n!\ninterface BVI1\n nameif inside\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert facts.interface_labels == {}
    assert any(error.code == "ASA_INTERFACE_DUPLICATE_LABEL" for error in facts.errors)


def test_empty_comments_and_orphan_commands_are_accounted() -> None:
    text = "! comment\n\n nameif outside\ninterface Ethernet0/0\n!\n shutdown\n"
    facts = parse_interfaces(make_network_request(text), text)
    assert facts.coverage.discovered_constructs == 3
    assert facts.coverage.recognized_constructs == 1
    assert facts.coverage.unsupported_constructs == 2
    assert facts.interfaces[0].enabled is None
    assert facts.interfaces[0].source_location is not None
    assert facts.interfaces[0].source_location.line_end == 4
    assert not facts.interface_labels
