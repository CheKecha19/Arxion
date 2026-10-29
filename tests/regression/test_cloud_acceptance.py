"""Synthetic VMware acceptance cases for incomplete evidence and project isolation."""

from copy import deepcopy
from threading import Event

import pytest
from PySide6.QtWidgets import QApplication, QWidget

from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.application.cloud_analysis import vmware_revision
from firewall_compliance.devices.cloud.cloud_ru.vmware.client import ScanResult
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.interfaces.desktop import cloud_analysis
from firewall_compliance.interfaces.desktop.cloud_analysis import analyze_saved_vmware
from firewall_compliance.interfaces.desktop.cloud_panel import CloudPanel
from firewall_compliance.interfaces.desktop.project_map import build_project_map
from firewall_compliance.interfaces.desktop.workspace_models import cloud_resources
from tests.regression.test_vmware_pipeline import database, rule, scan

QT_APP = None


class CapturedRunner:
    """Deliver background results deterministically across GUI state changes."""

    def __init__(self):
        self.jobs = []

    def submit(self, work, completed):
        self.jobs.append((work, completed))

    def poll(self):
        return ()

    def shutdown(self):
        pass


@pytest.mark.parametrize("malformed", [None, "not-a-rule", 123, []])
def test_malformed_rule_is_visible_unknown_with_original_pointer(malformed):
    source = scan(rule(), malformed, rule(id="last"))
    parsed = vmware_revision(source, 0).parse_result
    assert len(parsed.rules) == 3
    unknown = parsed.rules[1]
    assert unknown.match_status == DataStatus.UNKNOWN
    assert unknown.sources and unknown.destinations and unknown.services
    assert unknown.source_location.object_path.endswith("userDefinedRules/1")
    assert parsed.coverage.unsupported_constructs == 1
    graph = build_project_map("p", [], cloud_resources([source]))
    evidence = [item for edge in graph.edges for item in edge.rules]
    assert len(evidence) == 3
    assert next(item for item in evidence if item.rule_id == unknown.rule_id).status == "unknown"


def test_malformed_section_preserves_other_sections_and_section_pointer():
    source = scan(rule())
    source["result"]["records"][0]["data"]["firewall"]["systemRules"] = {"unexpected": True}
    parsed = vmware_revision(source, 0).parse_result
    assert len(parsed.rules) == 2
    assert parsed.rules[0].source_location.object_path.endswith("/systemRules")
    assert parsed.rules[0].match_status == DataStatus.UNKNOWN
    assert parsed.rules[1].match_status == DataStatus.KNOWN


def test_duplicate_api_ids_keep_distinct_evidence():
    parsed = vmware_revision(scan(rule(), rule()), 0).parse_result
    assert len({item.rule_id for item in parsed.rules}) == 2
    assert len(parsed.source_map) == 2
    assert parsed.rules[0].source_location != parsed.rules[1].source_location
    assert parsed.warnings


@pytest.mark.parametrize(
    "changes",
    [
        {"sourceFirewallGroups": [{}]},
        {"rawPortProtocols": "unexpected"},
        {"rawPortProtocols": [{"layer4Item": {"protocol": "ICMP", "icmpType": 8}}]},
        {
            "rawPortProtocols": [
                {"layer4Item": {"protocol": "TCP", "destinationPorts": ["ANY", "bad"]}}
            ]
        },
        {"rawPortProtocols": [{"layer4Item": {"protocol": "TCP"}, "layer7Item": {"id": "l7"}}]},
    ],
)
def test_unknown_conditions_never_become_unrestricted_allow(changes):
    revision = vmware_revision(scan(rule(**changes)), 0)
    assert revision.parse_result.rules[0].match_status == DataStatus.UNKNOWN
    assert not next(
        item for item in analyze_firewall(revision).checks if item.check_id == "FW-ANY-ANY"
    ).findings


def test_mismatched_cached_reference_ids_are_unknown():
    source = scan(
        rule(sourceFirewallGroups=[{"id": "group"}], applicationPortProfiles=[{"id": "app"}])
    )
    data = source["result"]["records"][0]["data"]
    data["firewall_groups"] = {
        "group": {"id": "other", "typeValue": "IP_SET", "ipAddresses": ["0.0.0.0/0"]}
    }
    data["application_port_profiles"] = {
        "app": {"id": "other", "applicationPorts": [{"protocol": "TCP"}]}
    }
    parsed = vmware_revision(source, 0).parse_result
    assert parsed.rules[0].source_status == DataStatus.UNKNOWN
    assert parsed.rules[0].service_status == DataStatus.UNKNOWN


def test_malformed_comment_is_unknown_and_not_missing_comment_finding():
    revision = vmware_revision(scan(rule(comments={"text": "unrecognized"})), 0)
    assert revision.parse_result.rules[0].description_status == DataStatus.UNKNOWN
    result = next(
        item for item in analyze_firewall(revision).checks if item.check_id == "FW-COMMENTS"
    )
    assert not result.findings
    assert result.limitations


def test_services_have_stable_distinct_semantic_ids():
    parsed = vmware_revision(
        scan(
            *(
                rule(
                    id=str(port),
                    rawPortProtocols=[
                        {"layer4Item": {"protocol": "TCP", "destinationPorts": [str(port)]}}
                    ],
                )
                for port in [80, 443]
            )
        ),
        0,
    ).parse_result
    assert len({service.service_id for service in parsed.services}) == 2


def test_bad_gateway_does_not_discard_good_gateway_and_failure_survives_reopen():
    source = scan(rule())
    broken = deepcopy(source["result"]["records"][0])
    broken["id"] = "broken-edge"
    broken["collected_at"] = "2026-10-26T00:00:00"  # Unknown timezone is not assumed UTC.
    source["result"]["records"].append(broken)
    store = database()
    project = store.create_project("Synthetic acceptance")
    scan_id = store.create_cloud_scan(project, {}, source["config"])
    store.finish_cloud_scan(scan_id, source["result"])
    source = store.list_cloud_scans(project)[0]
    items = analyze_saved_vmware(source, {}, Event())
    assert items[0]["report"]["checks"]
    assert items[1]["status"] == "error" and items[1]["report"] is None
    assert items[1]["cloud_origin"]["resource_id"] == "broken-edge"
    run_id = store.save_cloud_analysis(scan_id, items, {})
    assert store.get_run(run_id)["items"][1]["report"] is None
    assert store.list_runs(project)[0]["item_count"] == 2


def test_disabled_requirement_is_not_incomplete_analysis():
    items = analyze_saved_vmware(
        scan(rule()), {"enabled_check_ids": ["FW-LOGGING"], "require_logging": False}, Event()
    )
    assert items[0]["status"] == "complete"
    assert items[0]["report"]["checks"][0]["status"] == "not_applicable"


def test_cancel_during_last_check_prevents_returning_persistable_result(monkeypatch):
    cancelled = Event()
    original = cloud_analysis.analyze_firewall

    def check(*args, **kwargs):
        result = original(*args, **kwargs)
        cancelled.set()
        return result

    monkeypatch.setattr(cloud_analysis, "analyze_firewall", check)
    with pytest.raises(ValueError, match="отменена"):
        analyze_saved_vmware(scan(rule()), {}, cancelled)


@pytest.mark.parametrize("cancelled", [False, True])
def test_auto_analysis_uses_original_project_after_switch(cancelled):
    global QT_APP
    QT_APP = QApplication.instance() or QApplication([])
    parent = QWidget()
    store = database()
    original = store.create_project("Original")
    other = store.create_project("Other")
    panel = CloudPanel(store, parent)
    panel.runner.shutdown()

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def scan(self, _selection):
            return ScanResult("completed", records=scan(rule())["result"]["records"])

    runner = CapturedRunner()
    panel.runner = runner
    try:
        panel.set_project(original)
        panel.site.setText("https://vcd01-01.cloud.ru")
        panel.tenant.setText("test")
        panel.token.setText("SYNTHETIC")
        panel.save()
        panel.client_factory = Client
        panel.start_scan()
        work, completed = runner.jobs.pop()
        if cancelled:
            panel.cancel.set()
        panel.set_project(other)
        completed(work())
        assert len(runner.jobs) == (0 if cancelled else 1)
        if runner.jobs:
            work, completed = runner.jobs.pop()
            completed(work())
            assert store.list_runs(original)
        else:
            assert not store.list_runs(original)
        assert not store.list_runs(other)
        assert not panel.busy
    finally:
        panel.close()
        parent.close()


@pytest.mark.parametrize("persistence_failed", [False, True])
def test_panel_handles_failed_gateway_and_persistence_error(monkeypatch, persistence_failed):
    global QT_APP
    QT_APP = QApplication.instance() or QApplication([])
    parent = QWidget()
    store = database()
    project = store.create_project("Synthetic acceptance")
    source = scan(rule())
    broken = deepcopy(source["result"]["records"][0])
    broken["id"] = "broken-edge"
    broken["collected_at"] = "not-a-timestamp"
    source["result"]["records"].append(broken)
    scan_id = store.create_cloud_scan(project, {}, source["config"])
    store.finish_cloud_scan(scan_id, source["result"])
    panel = CloudPanel(store, parent)
    panel.runner.shutdown()
    runner = CapturedRunner()
    panel.runner = runner
    try:
        panel.set_project(project)
        panel._refresh_history(scan_id)
        if persistence_failed:

            def fail_save(*_args):
                raise OSError("SYNTHETIC PRIVATE FAILURE")

            monkeypatch.setattr(store, "save_cloud_analysis", fail_save)
        panel.analyze_saved_scan()
        work, completed = runner.jobs.pop()
        completed(work())
        assert not panel.busy
        assert "SYNTHETIC PRIVATE FAILURE" not in panel.analysis_status.text()
        if persistence_failed:
            assert "Не удалось сохранить" in panel.analysis_status.text()
            assert not store.list_runs(project)
        else:
            assert "ошибок: 1" in panel.analysis_status.text()
            assert len(store.list_runs(project)) == 1
        assert store.list_cloud_scans(project)
    finally:
        panel.close()
        parent.close()
