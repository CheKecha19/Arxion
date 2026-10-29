"""Project inventory, address scopes and ACL evidence are kept distinct."""

from __future__ import annotations

from typing import Any

from tests.revision_fixtures import make_revision

from firewall_compliance.domain.enums import DataStatus, EndpointKind
from firewall_compliance.domain.network import Endpoint
from firewall_compliance.interfaces.desktop.project_map import (
    CONTOUR,
    build_project_map,
    resource_addresses,
    subnet_zone,
)


def device_item(device_id: str = "fw") -> dict[str, Any]:
    revision = make_revision(device_id=device_id)
    revision = revision.model_copy(
        update={
            "device": revision.device.model_copy(
                update={"hostname": device_id + ".cfg"},
            )
        }
    )
    rule = revision.parse_result.rules[0]
    source = Endpoint(
        endpoint_id="src", name="10.1.1.10", kind=EndpointKind.HOST, cidrs=("10.1.1.10/32",)
    )
    destination = Endpoint(
        endpoint_id="dst", name="10.2.2.20", kind=EndpointKind.HOST, cidrs=("10.2.2.20/32",)
    )
    rule = rule.model_copy(
        update={
            "sources": (source,),
            "destinations": (destination,),
            "match_status": DataStatus.KNOWN,
        }
    )
    parsed = revision.parse_result.model_copy(update={"rules": (rule,)})
    revision = revision.model_copy(update={"parse_result": parsed})
    return {
        "id": device_id,
        "source_name": device_id + ".cfg",
        "revision": revision.model_dump(mode="json"),
    }


def cloud_item(identifier: str, address: str, project: str = "cloud-a") -> dict[str, Any]:
    return {
        "id": identifier,
        "scan": {
            "id": "scan-" + project,
            "config": {"platform": "evolution", "project_id": project},
        },
        "record": {
            "id": identifier,
            "name": identifier,
            "type": "vms",
            "inventory": {"ip_address": address},
            "data": {},
        },
    }


def test_devices_from_entire_inventory_and_direct_acl_evidence() -> None:
    graph = build_project_map("project", [device_item("fw-a"), device_item("fw-b")], [])
    assert len([node for node in graph.nodes if node.kind == "router"]) == 2
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert len(edge.rules) == 2
    by_key = {node.key: node for node in graph.nodes}
    assert by_key[edge.source].label == "10.1.1.10"
    assert by_key[edge.target].label == "10.2.2.20"
    assert by_key[edge.source].zone == "10.1.1.0/24"
    assert by_key[edge.target].zone == "10.2.2.0/24"
    assert {rule.device for rule in edge.rules} == {"fw-a.cfg", "fw-b.cfg"}


def test_unique_cloud_ip_is_matched_but_overlapping_addresses_are_not() -> None:
    item = device_item()
    graph = build_project_map("p", [item], [cloud_item("vm", "10.2.2.20")])
    assert graph.edges[0].target == "vm"
    assert next(node for node in graph.nodes if node.key == "vm").area != CONTOUR
    graph = build_project_map(
        "p", [item], [cloud_item("vm", "10.2.2.20"), cloud_item("vm2", "10.2.2.20", "cloud-b")]
    )
    assert graph.edges[0].target not in {"vm", "vm2"}
    assert len({node.area for node in graph.nodes if node.kind == "cloud"}) == 2


def test_connections_without_collections_and_devices_without_revision_stay_visible() -> None:
    graph = build_project_map(
        "p",
        [{"id": "legacy", "source_name": "old.cfg"}],
        [],
        [{"provider": "cloud_ru_evolution", "config": {"project_id": "a"}}],
    )
    assert {node.kind for node in graph.nodes} == {"router", "cloud"}
    assert graph.warnings
    assert not graph.edges


def test_any_is_one_condition_without_fanout_to_inventory() -> None:
    revision = make_revision()
    graph = build_project_map("p", [{"id": "fw", "revision": revision.model_dump(mode="json")}], [])
    assert len([node for node in graph.nodes if node.kind == "globe"]) == 1
    assert all(not edge.source.startswith("device:") for edge in graph.edges)


def test_cloud_links_require_explicit_ids_and_same_connection() -> None:
    vm = cloud_item("vm", "10.2.2.20")
    vm["record"]["inventory"]["subnet_id"] = "subnet"
    subnet = cloud_item("subnet", "10.2.2.1")
    subnet["record"]["type"] = "subnets"
    other = cloud_item("subnet-elsewhere", "10.2.2.1", "other")
    other["record"]["id"] = "subnet"
    graph = build_project_map("p", [], [vm, subnet, other])
    assert len(graph.edges) == 1
    assert graph.edges[0].target == "subnet"
    assert graph.edges[0].kind == "attachment"


def test_security_rule_remote_cidr_does_not_become_vm_address() -> None:
    record = {
        "inventory": {"ip_address": "10.0.0.5"},
        "data": {"security_rules": [{"ip_address": "198.51.100.1"}]},
    }
    assert resource_addresses(record) == ("10.0.0.5",)
    assert subnet_zone("192.168.23.2") == "192.168.23.0/24"
    assert subnet_zone("10.0.0.0/8") == "10.0.0.0/8"
    assert subnet_zone("2001:db8::5") == "2001:db8::/64"


def test_cloud_sg_keeps_direction_and_condition_owner() -> None:
    group = cloud_item("sg", "10.2.2.20")
    group["record"]["inventory"] = {}
    group["record"]["type"] = "security_groups"
    group["record"]["data"] = {
        "security_rules": [
            {
                "id": "https",
                "direction": "ingress",
                "remote_ip_prefix": "192.0.2.0/24",
                "protocol": "tcp",
                "port_range_min": 443,
                "port_range_max": 443,
            }
        ]
    }
    graph = build_project_map("p", [], [group])
    assert len(graph.edges) == 1
    assert graph.edges[0].target == "sg"
    assert "443" in graph.edges[0].rules[0].services[0]
    group["record"]["data"]["security_rules"][0]["direction"] = "egress"
    outgoing = build_project_map("p", [], [group]).edges[0]
    assert outgoing.source == "sg"
    assert outgoing.rules[0].source == "sg"
    assert outgoing.rules[0].destination == "192.0.2.0/24"


def test_contexts_are_not_merged_by_address() -> None:
    first, second = device_item("a"), device_item("b")
    second["revision"]["device"]["context"] = "separate-vrf"
    graph = build_project_map("p", [first, second], [])
    assert len(graph.edges) == 2
    assert len({edge.source for edge in graph.edges}) == 2


def test_cloud_subnet_cidr_selects_zone_without_inventing_hosts() -> None:
    subnet = cloud_item("subnet", "10.2.2.1")
    subnet["record"]["type"] = "subnets"
    subnet["record"]["inventory"] = {"cidr": "10.2.2.0/24"}
    graph = build_project_map("p", [], [subnet])
    node = next(node for node in graph.nodes if node.key == "subnet")
    assert node.zone == "10.2.2.0/24"
    assert node.addresses == ("10.2.2.0/24",)
    assert not graph.edges
