"""Проверки строгих форм маршрутов ASA и сохранения неизвестности."""

from pathlib import Path
from uuid import UUID

import pytest
from tests.network_fixtures import make_network_request

from firewall_compliance.devices.ngfw.cisco.asa.routes import parse_routes
from firewall_compliance.domain import DataOrigin, DataStatus, ParseIssueLevel
from firewall_compliance.parsers.network_contracts import NetworkInterfaceBinding, NetworkSourceKind

CONFIG: NetworkSourceKind = "asa_running_config_static_routes"
RIB: NetworkSourceKind = "asa_ipv4_rib"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "network_asa"


def test_config_provenance_priorities_and_casefold_binding() -> None:
    text = "!\n\n route OUTSIDE 198.51.100.0 255.255.255.0 192.0.2.1 254\n"
    source_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    request = make_network_request(text, CONFIG, source_document_id=source_id)
    facts = parse_routes(request, text)
    (route,) = facts.routes
    assert route.route_id == f"route:{CONFIG}:{source_id}:3"
    assert route.source_document_id == source_id
    assert route.device_id == request.metadata.device_id
    assert route.origin == DataOrigin.IMPORTED
    assert route.source_location is not None
    assert route.source_location.source_name == request.source.source_name
    assert route.source_location.line_start == route.source_location.line_end == 3
    assert route.destination == "198.51.100.0/24"
    assert route.next_hop == "192.0.2.1"
    assert route.outgoing_interface_id == request.interface_labels["outside"]
    assert route.administrative_distance == 254
    assert route.metric is None
    assert route.route_kind == "static"
    assert route.data_status == DataStatus.KNOWN
    assert not route.is_blackhole
    assert not facts.interfaces and not facts.interface_labels and not facts.interface_settings
    assert not facts.warnings and not facts.errors and not facts.unsupported_constructs
    assert parse_routes(request, text).routes == facts.routes


def test_null0_preserves_absent_target_and_priorities() -> None:
    text = "route NuLl0 203.0.113.96 255.255.255.240"
    facts = parse_routes(make_network_request(text, CONFIG), text)
    (route,) = facts.routes
    assert route.is_blackhole
    assert route.destination == "203.0.113.96/28"
    assert route.next_hop is None and route.outgoing_interface_id is None
    assert route.administrative_distance is None and route.metric is None
    assert route.route_kind == "static" and route.data_status == DataStatus.KNOWN


def test_connected_route_uses_explicit_inside_binding() -> None:
    text = "C 10.20.0.0 255.255.255.0 is directly connected, InSiDe"
    outside = make_network_request(text, RIB).interfaces[0]
    inside = outside.model_copy(
        update={
            "interface_id": "interface:GigabitEthernet0/1",
            "name": "GigabitEthernet0/1",
            "addresses": ("10.20.0.2/24",),
        }
    )
    request = make_network_request(
        text,
        RIB,
        interfaces=(outside, inside),
        bindings=(
            NetworkInterfaceBinding(label="outside", interface_id=outside.interface_id),
            NetworkInterfaceBinding(label="inside", interface_id=inside.interface_id),
        ),
    )
    facts = parse_routes(request, text)
    assert facts.routes[0].outgoing_interface_id == inside.interface_id
    assert facts.routes[0].data_status == DataStatus.KNOWN
    assert not facts.warnings


@pytest.mark.parametrize(
    "network,mask,expected",
    [
        ("0.0.0.0", "0.0.0.0", "0.0.0.0/0"),
        ("198.51.100.25", "255.255.255.255", "198.51.100.25/32"),
    ],
)
def test_mask_boundaries(network: str, mask: str, expected: str) -> None:
    text = f"route outside {network} {mask} 192.0.2.1 1"
    facts = parse_routes(make_network_request(text, CONFIG), text)
    assert facts.routes[0].destination == expected


@pytest.mark.parametrize("gateway", ["999.1.1.1", "0.0.0.0", "224.0.0.1"])
def test_header_invalid_gateway_is_an_error(gateway: str) -> None:
    text = f"Gateway of last resort is {gateway} to network 0.0.0.0"
    facts = parse_routes(make_network_request(text, RIB), text)
    assert not facts.routes and not facts.unsupported_constructs
    assert facts.errors[0].code == "ASA_INVALID_ROUTE"
    assert facts.coverage.recognized_constructs == 0


@pytest.mark.parametrize(
    "text,next_hop",
    [
        ("route missing 198.51.100.0 255.255.255.0 192.0.2.1 1", "192.0.2.1"),
        ("C 198.51.100.0 255.255.255.0 is directly connected, missing", None),
        ("S 198.51.100.0 255.255.255.0 [1/0] via 192.0.2.1, missing", "192.0.2.1"),
    ],
)
def test_unknown_label_does_not_invent_interface(text: str, next_hop: str | None) -> None:
    kind = CONFIG if text.startswith("route") else RIB
    facts = parse_routes(make_network_request(text, kind), text)
    (route,) = facts.routes
    assert route.data_status == DataStatus.UNKNOWN
    assert route.outgoing_interface_id is None
    assert route.next_hop == next_hop
    assert [issue.code for issue in facts.warnings] == ["ASA_UNKNOWN_INTERFACE_LABEL"]
    assert facts.warnings[0].source_location == route.source_location
    assert facts.coverage.recognized_constructs == 1
    assert not facts.errors and not facts.unsupported_constructs


def test_supported_rib_forms_and_metadata_header() -> None:
    text = "\n".join(
        [
            "Gateway of last resort is 192.0.2.1 to network 0.0.0.0",
            "!",
            "C 192.0.2.0 255.255.255.0 is directly connected, OUTSIDE",
            "S 198.51.100.0 255.255.255.0 [0/999] via 192.0.2.1, outside",
            "S* 0.0.0.0 0.0.0.0 [254/0] via 192.0.2.1, outside",
        ]
    )
    request = make_network_request(text, RIB)
    facts = parse_routes(request, text)
    connected, static, default = facts.routes
    assert connected.route_kind == "connected"
    assert connected.next_hop is None
    assert connected.outgoing_interface_id == request.interface_labels["outside"]
    assert connected.administrative_distance is None and connected.metric is None
    assert static.administrative_distance == 0 and static.metric == 999
    assert default.destination == "0.0.0.0/0"
    assert default.administrative_distance == 254 and default.metric == 0
    assert all(route.data_status == DataStatus.KNOWN for route in facts.routes)
    assert facts.coverage.discovered_constructs == facts.coverage.recognized_constructs == 4
    assert not facts.errors and not facts.warnings


@pytest.mark.parametrize(
    "kind,text",
    [
        (CONFIG, "route outside 198.51.100.1 255.255.255.0 192.0.2.1 1"),
        (CONFIG, "route outside 198.51.100.0 0.0.0.255 192.0.2.1 1"),
        (CONFIG, "route outside 198.51.100.0 255.0.255.0 192.0.2.1 1"),
        (CONFIG, "route outside 999.1.1.1 255.255.255.0 192.0.2.1 1"),
        (CONFIG, "route outside 198.51.100.0 24 192.0.2.1 1"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 192.0.2.999 1"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 224.0.0.1 1"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 0.0.0.0 1"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 255.255.255.255 1"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 192.0.2.1 0"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 192.0.2.1 255"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 192.0.2.1 -1"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 192.0.2.1 x"),
        (CONFIG, "route null0 203.0.113.97 255.255.255.240"),
        (RIB, "C 192.0.2.1 255.255.255.0 is directly connected, outside"),
        (RIB, "S* 198.51.100.0 255.255.255.0 [1/0] via 192.0.2.1, outside"),
        (RIB, "S 198.51.100.0 255.255.255.0 [255/0] via 192.0.2.1, outside"),
        (RIB, "S 198.51.100.0 255.255.255.0 [-1/0] via 192.0.2.1, outside"),
        (RIB, "S 198.51.100.0 255.255.255.0 [1/-1] via 192.0.2.1, outside"),
        (RIB, "S 198.51.100.0 255.255.255.0 [x/0] via 192.0.2.1, outside"),
        (RIB, "S 198.51.100.0 255.255.255.0 [1/x] via 192.0.2.1, outside"),
        (RIB, "S 198.51.100.0 255.255.255.0 [1/0] via 0.0.0.0, outside"),
    ],
)
def test_invalid_values_are_errors(kind: NetworkSourceKind, text: str) -> None:
    facts = parse_routes(make_network_request(text, kind), text)
    assert not facts.routes and not facts.unsupported_constructs
    (error,) = facts.errors
    assert error.code == "ASA_INVALID_ROUTE" and error.level == ParseIssueLevel.ERROR
    assert error.source_location is not None and error.source_location.line_start == 1
    assert facts.coverage.discovered_constructs == 1
    assert facts.coverage.recognized_constructs == facts.coverage.unsupported_constructs == 0


@pytest.mark.parametrize(
    "kind,text",
    [
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 192.0.2.1"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 192.0.2.1 1 track 6"),
        (CONFIG, "route outside 198.51.100.0 255.255.255.0 192.0.2.1 1 garbage"),
        (CONFIG, "route null0 198.51.100.0 255.255.255.0 1"),
        (CONFIG, "prefix route outside 198.51.100.0 255.255.255.0 192.0.2.1 1"),
        (CONFIG, "interface GigabitEthernet0/0"),
        (CONFIG, "route outside 2001:db8:: ffff:ffff:: 2001:db8::1 1"),
        (RIB, "C 192.0.2.0 255.255.255.0 is directly connected, outside tail"),
        (RIB, "S 198.51.100.0 255.255.255.0 [1/0] via 192.0.2.1, outside tail"),
        (RIB, "S* 0.0.0.0 0.0.0.0 [1/0] via"),
        (RIB, "L 192.0.2.2 255.255.255.255 is directly connected, outside"),
        (RIB, "O 198.51.100.0 255.255.255.0 [110/2] via 192.0.2.1, outside"),
        (RIB, "[1/0] via 192.0.2.3, outside"),
        (RIB, "S 198.51.100.0 255.255.255.0 [1/0] via 192.0.2.1, Null0"),
        (RIB, "C 198.51.100.0 255.255.255.0 is directly connected, Null0"),
        (RIB, "S 198.51.100.0 255.255.255.0 is directly connected, Null0"),
        (RIB, "Codes: C - connected, S - static, L - local, O - OSPF"),
        (RIB, "Gateway of last resort is not set trailing"),
        (RIB, "Gateway of last resort is 192.0.2.1 to network 0.0.0.0 trailing"),
        (RIB, "Gateway of last resort is 192.0.2.1 to network 198.51.100.0"),
        (RIB, "unknown"),
    ],
)
def test_unsupported_forms_have_no_partial_route(kind: NetworkSourceKind, text: str) -> None:
    facts = parse_routes(make_network_request(text, kind), text)
    assert not facts.routes and not facts.errors
    (construct,) = facts.unsupported_constructs
    assert construct.construct_type == "ASA_UNSUPPORTED_ROUTE"
    assert construct.source_location.line_start == construct.source_location.line_end == 1
    assert facts.warnings[0].level == ParseIssueLevel.WARNING
    assert facts.coverage.discovered_constructs == facts.coverage.unsupported_constructs == 1
    assert facts.coverage.recognized_constructs == 0


@pytest.mark.parametrize("text", ["", "\n!\n   ! comment\n\n"])
@pytest.mark.parametrize("kind", [CONFIG, RIB])
def test_empty_document_does_not_synthesize_routes(text: str, kind: NetworkSourceKind) -> None:
    facts = parse_routes(make_network_request(text, kind), text)
    assert not facts.routes
    assert facts.coverage.discovered_constructs == 0


def test_not_set_header_is_metadata_only() -> None:
    text = "Gateway of last resort is not set"
    facts = parse_routes(make_network_request(text, RIB), text)
    assert not facts.routes and not facts.warnings and not facts.errors
    assert facts.coverage.recognized_constructs == 1


def test_mixed_coverage_and_exact_diagnostic_lines() -> None:
    text = "\n".join(
        [
            "!",
            "route outside 0.0.0.0 0.0.0.0 192.0.2.1 1",
            "",
            "route outside 198.51.100.0 255.255.255.0 192.0.2.1 x",
            "route outside 198.51.100.0 255.255.255.0 192.0.2.1 1 track 6",
        ]
    )
    facts = parse_routes(make_network_request(text, CONFIG), text)
    assert len(facts.routes) == 1
    assert facts.coverage.discovered_constructs == 3
    assert facts.coverage.recognized_constructs == facts.coverage.unsupported_constructs == 1
    assert facts.errors[0].source_location is not None
    assert facts.errors[0].source_location.line_start == 4
    assert facts.unsupported_constructs[0].source_location.line_start == 5


@pytest.mark.parametrize(
    "scenario,filename,kind,count,unsupported",
    [
        ("connected_static_default", "static_routes.cfg", CONFIG, 2, 0),
        ("connected_static_default", "show_route.txt", RIB, 4, 0),
        ("narrower_null0", "static_routes.cfg", CONFIG, 4, 0),
        ("partial_unsupported", "static_routes.cfg", CONFIG, 0, 1),
        ("partial_unsupported", "show_route.txt", RIB, 1, 1),
    ],
)
def test_existing_payloads_read_only(
    scenario: str, filename: str, kind: NetworkSourceKind, count: int, unsupported: int
) -> None:
    text = (FIXTURES / scenario / filename).read_text(encoding="ascii")
    facts = parse_routes(make_network_request(text, kind), text)
    assert len(facts.routes) == count
    assert len(facts.unsupported_constructs) == unsupported
    assert not facts.errors
    if kind == RIB:
        assert not any(route.is_blackhole for route in facts.routes)
