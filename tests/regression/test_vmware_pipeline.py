"""Synthetic end-to-end contracts for saved VMware policy analysis and map wiring."""

import json
import time
from copy import deepcopy
from pathlib import Path
from threading import Event
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from PySide6.QtWidgets import QApplication

from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.application.cloud_analysis import vmware_revision
from firewall_compliance.devices.cloud.cloud_ru.vmware.client import (
    CloudError,
    ScanResult,
    VMwareClient,
    VMwareConfig,
)
from firewall_compliance.domain.enums import DataStatus, RuleAction
from firewall_compliance.interfaces.desktop.cloud_analysis import analyze_saved_vmware
from firewall_compliance.interfaces.desktop.project_map import build_project_map
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow
from firewall_compliance.interfaces.desktop.workspace_models import cloud_resources

VDC = "11111111-2222-3333-4444-555555555555"
GROUP = "urn:vcloud:firewallGroup:22222222-2222-3333-4444-555555555555"
PROFILE = "urn:vcloud:applicationPortProfile:33333333-2222-3333-4444-555555555555"
QT_APP = None


def rule(**changes):
    return {
        "id": "rule-1",
        "name": "Synthetic rule",
        "actionValue": "ALLOW",
        "active": True,
        "direction": "IN_OUT",
        "ipProtocol": "IPV4",
        "sourceFirewallGroups": None,
        "sourceFirewallIpAddresses": None,
        "destinationFirewallGroups": None,
        "destinationFirewallIpAddresses": None,
        "applicationPortProfiles": None,
        "rawPortProtocols": None,
        "logging": False,
        "description": "",
        **changes,
    }


def scan(*rules):
    return {
        "id": "synthetic-scan",
        "created_at": "2026-10-26T00:00:00+00:00",
        "state": "completed",
        "config": {"platform": "vmware", "site": "https://vcd01-01.cloud.ru", "tenant": "test"},
        "result": {
            "state": "completed",
            "errors": [],
            "requests": [],
            "records": [
                {
                    "id": "urn:vcloud:gateway:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "type": "edges",
                    "name": "Synthetic Edge",
                    "collected_at": "2026-10-26T00:00:00+00:00",
                    "inventory": {"ownerRef": {"id": "urn:vcloud:vdc:" + VDC}},
                    "data": {
                        "firewall": {
                            "systemRules": None,
                            "userDefinedRules": list(rules),
                            "defaultRules": [],
                        }
                    },
                }
            ],
        },
    }


def database():
    root = Path("artifacts/vmware-pipeline-tests")
    root.mkdir(parents=True, exist_ok=True)
    return ProjectStore(root / f"{uuid4()}.sqlite3")


def test_existing_seven_checks_receive_real_rules():
    original = scan(
        rule(),
        rule(id="duplicate"),
        rule(id="disabled", active=False),
        rule(
            id="narrow",
            sourceFirewallIpAddresses=["10.0.0.1"],
            destinationFirewallIpAddresses=["10.0.0.2"],
        ),
    )
    saved = deepcopy(original)
    revision = vmware_revision(original, 0)
    report = analyze_firewall(revision)
    results = {check.check_id: check for check in report.checks}
    assert len(results) == 7
    for key in (
        "FW-ANY-ANY",
        "FW-DUPLICATE",
        "FW-SHADOWED",
        "FW-LOGGING",
        "FW-COMMENTS",
        "FW-DISABLED",
    ):
        assert results[key].findings, key
    assert original == saved
    assert revision.parse_result.rules[0].action == RuleAction.ALLOW
    assert (
        "/data/firewall/userDefinedRules/0"
        in revision.parse_result.rules[0].source_location.object_path
    )


def test_reference_resolution_preserves_ports_and_ip_sets():
    source = scan(
        rule(sourceFirewallGroups=[{"id": GROUP}], applicationPortProfiles=[{"id": PROFILE}])
    )
    data = source["result"]["records"][0]["data"]
    data["firewall_groups"] = {
        GROUP: {"id": GROUP, "typeValue": "IP_SET", "ipAddresses": ["10.1.2.0/24"]}
    }
    data["application_port_profiles"] = {
        PROFILE: {
            "id": PROFILE,
            "applicationPorts": [{"protocol": "TCP", "destinationPorts": ["443", "8000-8010"]}],
        }
    }
    parsed = vmware_revision(source, 0).parse_result
    assert parsed.rules[0].match_status == DataStatus.KNOWN
    assert parsed.rules[0].sources[0].cidrs == ("10.1.2.0/24",)
    assert [(p.start, p.end) for p in parsed.rules[0].services[0].port_ranges] == [
        (443, 443),
        (8000, 8010),
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"sourceFirewallGroups": [{"id": GROUP, "name": "Missing group"}]},
        {"applicationPortProfiles": [{"id": PROFILE}]},
        {"sourceFirewallIpAddresses": ["example.invalid"]},
        {"sourceFirewallIpAddresses": "ANY"},
        {"networkContextProfiles": [{"id": "l7-profile"}]},
        {"sourceGroupsExcluded": True},
        {"direction": "UNKNOWN"},
        {"active": None},
        {"rawPortProtocols": [{"layer4Item": {"protocol": "TCP", "sourcePorts": ["1024-65535"]}}]},
    ],
)
def test_incomplete_rules_never_turn_into_known_any(changes):
    source = scan(rule(**changes))
    revision = vmware_revision(source, 0)
    assert revision.parse_result.rules[0].match_status != DataStatus.KNOWN
    report = analyze_firewall(revision)
    assert not next(c for c in report.checks if c.check_id == "FW-ANY-ANY").findings
    assert all(check.status.value == "partial" for check in report.checks)
    graph = build_project_map("p", [], cloud_resources([source]))
    assert any(edge.status == "unknown" for edge in graph.edges if edge.kind == "acl")


def test_nat_is_not_an_allow_rule():
    source = scan(rule(actionValue="DROP"))
    source["result"]["records"][0]["data"]["nat"] = [{"id": "nat", "type": "DNAT"}]
    revision = vmware_revision(source, 0)
    assert len(revision.parse_result.rules) == 1
    assert revision.parse_result.rules[0].action == RuleAction.DROP


def test_family_direction_and_precedence():
    source = scan(rule(ipProtocol="IPV6", direction="OUT"))
    source["result"]["records"][0]["data"]["firewall"]["systemRules"] = [
        rule(id="system", ipProtocol="IPV6", direction="OUT")
    ]
    revision = vmware_revision(source, 0)
    assert [r.source_location.object_id for r in revision.parse_result.rules] == [
        "system",
        "rule-1",
    ]
    assert revision.parse_result.rules[0].sources[0].cidrs == ("::/0",)
    assert revision.parse_result.rules[0].policy_direction == "out"


def test_projects_and_connections_are_not_merged_by_name():
    one, two = scan(rule()), scan(rule())
    two["id"] = "another-scan"
    two["config"]["tenant"] = "other-tenant"
    assert vmware_revision(one, 0).device.device_id != vmware_revision(two, 0).device.device_id
    graph = build_project_map("p", [], cloud_resources([one, two]))
    assert len({rule.rule_id for edge in graph.edges for rule in edge.rules}) == 2


def test_persisted_runs_keep_source_and_settings():
    store = database()
    project = store.create_project("Synthetic")
    source = scan(rule())
    scan_id = store.create_cloud_scan(project, {}, source["config"])
    store.finish_cloud_scan(scan_id, source["result"])
    source = store.list_cloud_scans(project)[0]
    settings = {"enabled_check_ids": ["FW-LOGGING"], "require_logging": False}
    payloads = analyze_saved_vmware(source, settings, Event())
    run_id = store.save_cloud_analysis(scan_id, payloads, settings)
    restored = store.get_run(run_id)
    assert restored["settings"]["cloud_scan_id"] == scan_id
    assert len(restored["items"][0]["report"]["checks"]) == 1
    assert (
        restored["items"][0]["cloud_origin"]["resource_id"] == source["result"]["records"][0]["id"]
    )
    assert store.list_cloud_scans(project)[0] == source
    assert store.cloud_analysis_runs(scan_id, project) == [run_id]
    assert not store.cloud_analysis_runs(scan_id, store.create_project("Other"))


def test_cancel_has_no_persistent_side_effects():
    stop = Event()
    stop.set()
    with pytest.raises(ValueError, match="отменена"):
        analyze_saved_vmware(scan(rule()), {}, stop)


def test_collector_reads_each_reference_once_and_preserves_failures():
    calls = []

    def transport(request, timeout):
        path = urlsplit(request.full_url).path
        calls.append(path)
        if "/firewallGroups/" in path:
            return json.dumps(
                {"id": GROUP, "typeValue": "IP_SET", "ipAddresses": ["10.0.0.0/24"]}
            ).encode()
        raise CloudError("HTTP 403: Недостаточно прав.")

    client = VMwareClient(
        VMwareConfig("https://vcd01-01.cloud.ru", "test", "39.1"), "SYNTHETIC", transport=transport
    )
    policy = {
        "userDefinedRules": [
            rule(
                sourceFirewallGroups=[{"id": GROUP}],
                destinationFirewallGroups=[{"id": GROUP}],
                applicationPortProfiles=[{"id": PROFILE}],
            )
        ]
    }
    objects, errors = client._firewall_objects(policy)
    assert GROUP in objects["firewall_groups"]
    assert not objects["application_port_profiles"] and errors
    assert len(calls) == 2
    client._firewall_objects(policy)
    assert len(calls) == 2


def test_qt_saved_scan_analysis_findings_map_and_reopen():
    global QT_APP
    QT_APP = QApplication.instance() or QApplication([])
    window = MainWindow(store=database())
    try:
        project = window.create_project("Synthetic pipeline")
        source = scan(rule())
        scan_id = window.store.create_cloud_scan(project, {}, source["config"])
        window.store.finish_cloud_scan(scan_id, source["result"])
        panel = window.cloud_panel
        panel._refresh_history(scan_id)
        assert panel.analyze_button.isEnabled()
        panel.analyze_saved_scan()
        deadline = time.monotonic() + 10
        while panel.busy and time.monotonic() < deadline:
            QT_APP.processEvents()
            time.sleep(0.01)
        assert not panel.busy and "находок:" in panel.analysis_status.text(), (
            panel.analysis_status.text()
        )
        runs = window.store.cloud_analysis_runs(scan_id, project)
        assert len(runs) == 1
        window._open_cloud_analysis(runs[0])
        assert window.finding_model.rowCount() > 0
        window._refresh_project_map()
        edges = [edge for edge in window.project_map_widget.graph.edges if edge.kind == "acl"]
        assert edges and edges[0].rules[0].services
        window._open_project_map_rules(tuple(rule.rule_id for edge in edges for rule in edge.rules))
        assert window.rules_table.selectionModel().selectedRows()
        window.load_run(runs[0])
        assert window._items()[0]["cloud_origin"]["scan_id"] == scan_id
        assert window.store.list_cloud_scans(project)[0]["result"] == source["result"]
    finally:
        window.close()


def test_merge_candidates_use_existing_check():
    source = scan(
        rule(sourceFirewallIpAddresses=["10.0.0.1"], destinationFirewallIpAddresses=["10.0.1.5"]),
        rule(
            id="second",
            sourceFirewallIpAddresses=["10.0.0.2"],
            destinationFirewallIpAddresses=["10.0.1.5"],
        ),
    )
    report = analyze_firewall(vmware_revision(source, 0))
    assert next(check for check in report.checks if check.check_id == "FW-MERGE-CANDIDATE").findings


def test_same_address_in_other_vdc_is_not_attached():
    source = scan(
        rule(sourceFirewallIpAddresses=["10.0.0.5"], destinationFirewallIpAddresses=["10.0.0.8"])
    )
    for suffix, vdc in (("own", VDC), ("other", "99999999-2222-3333-4444-555555555555")):
        source["result"]["records"].append(
            {
                "type": "vms",
                "id": suffix,
                "name": suffix,
                "inventory": {
                    "ipAddress": "10.0.0.5",
                    "vdc": "https://vcd01-01.cloud.ru/api/vdc/" + vdc + "/",
                },
                "data": {},
            }
        )
    inventory = cloud_resources([source])
    graph = build_project_map("p", [], inventory)
    own = next(item["id"] for item in inventory if item["record"]["id"] == "own")
    other = next(item["id"] for item in inventory if item["record"]["id"] == "other")
    acl = [edge for edge in graph.edges if edge.kind == "acl"]
    assert acl and acl[0].source == own
    assert all(other not in (edge.source, edge.target) for edge in acl)


def test_auto_analysis_after_collection_and_project_isolation():
    global QT_APP
    QT_APP = QApplication.instance() or QApplication([])
    store = database()
    window = MainWindow(store=store)
    try:
        project = window.create_project("Auto-check")
        source = scan(rule())

        class Client:
            def __init__(self, *_args, cancel=None):
                self.cancel = cancel or Event()

            def scan(self, _selection):
                return ScanResult("completed", records=source["result"]["records"])

        panel = window.cloud_panel
        panel.site.setText("https://vcd01-01.cloud.ru")
        panel.tenant.setText("test")
        panel.token.setText("SYNTHETIC")
        panel.save()
        panel.client_factory = Client
        panel.start_scan()
        deadline = time.monotonic() + 10
        while panel.busy and time.monotonic() < deadline:
            QT_APP.processEvents()
            time.sleep(0.01)
        assert not panel.busy
        scans = store.list_cloud_scans(project)
        assert store.cloud_analysis_runs(scans[0]["id"], project)
        assert len(window.device_model.payloads) == 1
        assert window.device_model.payloads[0].get("report")
        assert (
            len([node for node in window.project_map_widget.graph.nodes if node.kind == "router"])
            == 1
        )
        panel._refresh_history(scans[0]["id"])
        panel.analyze_button.click()
        other = window.create_project("Other during check")
        deadline = time.monotonic() + 10
        while panel.busy and time.monotonic() < deadline:
            QT_APP.processEvents()
            time.sleep(0.01)
        assert len(store.cloud_analysis_runs(scans[0]["id"], project)) == 2
        assert not store.list_runs(other)
    finally:
        window.close()
