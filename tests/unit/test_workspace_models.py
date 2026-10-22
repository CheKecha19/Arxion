"""Resource identity and partial cloud observations in the desktop projection."""

from copy import deepcopy
from typing import Any

from firewall_compliance.interfaces.desktop.workspace_models import cloud_resources


def _scan(identifier: str, date: str, platform: str = "vmware") -> dict[str, Any]:
    return {
        "id": identifier,
        "created_at": date,
        "config": {"platform": platform, "site": "https://synthetic.invalid", "tenant": "one"},
        "state": "completed",
        "result": {"records": [{"id": "vm-1", "type": "vms", "name": "same name"}]},
    }


def test_partial_observation_keeps_missing_resource_with_original_time() -> None:
    old = _scan("old", "2026-10-01")
    new = _scan("new", "2026-10-02")
    new["state"] = "partial"
    new["result"]["records"] = [{"id": "vm-2", "type": "vms", "name": "same name"}]
    before = deepcopy([old, new])
    items = cloud_resources([old, new])
    assert len(items) == 2
    assert {item["scan"]["created_at"] for item in items} == {"2026-10-01", "2026-10-02"}
    assert [old, new] == before


def test_identity_uses_connection_and_provider_id_not_name() -> None:
    scans = [_scan("one", "2026-10-01"), _scan("two", "2026-10-02")]
    scans[1]["result"]["records"][0]["name"] = "renamed"
    assert len(cloud_resources(scans)) == 1
    assert cloud_resources(scans)[0]["record"]["name"] == "renamed"
    scans[1]["config"]["tenant"] = "another"
    assert len(cloud_resources(scans)) == 2
    scans[1]["config"]["tenant"] = "one"
    scans[1]["config"]["platform"] = "evolution"
    assert len(cloud_resources(scans)) == 2


def test_missing_ids_are_not_merged_across_scans() -> None:
    scans = [_scan("one", "2026-10-01"), _scan("two", "2026-10-02")]
    for scan in scans:
        scan["result"]["records"][0]["id"] = ""
    assert len(cloud_resources(scans)) == 2


def test_rule_evidence_excludes_other_rules_and_other_sources() -> None:
    from firewall_compliance.interfaces.desktop.resource_details import rule_evidence_text

    location = {"source_name": "synthetic.cfg", "line_start": 10, "line_end": 11}
    item = {
        "source_name": "synthetic.cfg",
        "content_sha256": "a" * 64,
        "excerpts": [
            {"location": location, "text": "selected rule"},
            {"location": {**location, "line_start": 25, "line_end": 25}, "text": "other rule"},
            {"location": {**location, "source_name": "another.cfg"}, "text": "other file"},
        ],
    }
    text = rule_evidence_text(item, {"source_location": location})
    assert "selected rule" in text
    assert "other rule" not in text and "other file" not in text
    assert "SHA-256" in text
    assert "selected rule" not in rule_evidence_text(item, {})
