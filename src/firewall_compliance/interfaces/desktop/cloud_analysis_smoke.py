"""Synthetic portable-executable verification of the VMware analysis workflow."""

from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication

from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow


def run_cloud_analysis_smoke(output: Path) -> None:
    app = QApplication.instance()
    assert isinstance(app, QApplication)
    window = MainWindow(store=ProjectStore(output / "cloud-analysis.sqlite3"))
    try:
        project = window.create_project("Synthetic VMware analysis")
        config = {"platform": "vmware", "site": "https://vcd01-01.cloud.ru", "tenant": "synthetic"}
        scan_id = window.store.create_cloud_scan(
            project, {"resources": ["edges"], "data": ["firewall"]}, config
        )
        raw = {
            "id": "synthetic-rule",
            "name": "Synthetic broad HTTPS",
            "active": True,
            "actionValue": "ALLOW",
            "ipProtocol": "IPV4",
            "direction": "IN_OUT",
            "sourceFirewallGroups": None,
            "destinationFirewallGroups": None,
            "sourceFirewallIpAddresses": None,
            "destinationFirewallIpAddresses": None,
            "applicationPortProfiles": [],
            "rawPortProtocols": [
                {"layer4Item": {"protocol": "TCP", "destinationPorts": ["443"], "sourcePorts": []}}
            ],
            "logging": False,
            "description": "",
        }
        window.store.finish_cloud_scan(
            scan_id,
            {
                "state": "completed",
                "records": [
                    {
                        "type": "edges",
                        "id": "urn:vcloud:gateway:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                        "name": "Synthetic Edge",
                        "inventory": {},
                        "data": {
                            "firewall": {
                                "systemRules": None,
                                "userDefinedRules": [raw],
                                "defaultRules": [],
                            }
                        },
                    }
                ],
                "errors": [],
                "requests": [],
            },
        )
        panel = window.cloud_panel
        panel._refresh_history(scan_id)
        panel.analyze_button.click()
        deadline = time.monotonic() + 30
        while panel.busy and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        assert not panel.busy
        runs = window.store.cloud_analysis_runs(scan_id, project)
        assert runs, panel.analysis_status.text()
        window._open_cloud_analysis(runs[0])
        assert window.finding_model.rowCount() >= 3
        assert len(window._items()[0]["report"]["checks"]) == 7
        window._refresh_project_map()
        edges = [edge for edge in window.project_map_widget.graph.edges if edge.kind == "acl"]
        assert edges and "443" in str(edges[0].rules[0].services)
        window._open_project_map_rules(tuple(rule.rule_id for edge in edges for rule in edge.rules))
        assert window.rules_table.selectionModel().selectedRows()
        item = window._items()[0]
        evidence = window.resource_details._rule_evidence(item, item["parse_result"]["rules"][0])
        assert "synthetic-rule" in evidence and "Исходные поля правила API" in evidence
        reopened = ProjectStore(window.store.path).get_run(runs[0])
        assert reopened["items"][0]["cloud_origin"]["scan_id"] == scan_id
    finally:
        window.close()
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()
