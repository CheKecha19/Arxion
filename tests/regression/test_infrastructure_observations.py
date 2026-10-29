"""Synthetic registry projection: evidence dates, stable identities and safe provenance."""

import json
from copy import deepcopy
from datetime import datetime

import pytest

from firewall_compliance.interfaces.desktop.dashboard import build_dashboard
from firewall_compliance.interfaces.desktop.infrastructure_observations import project_observations
from firewall_compliance.interfaces.desktop.workspace_models import cloud_resource_key


def collection(scan_id, date, *, name="Edge", resource_id="edge", config=None, **record_fields):
    return {
        "id": scan_id,
        "created_at": date,
        "config": config
        or {"platform": "vmware", "site": "https://vcd00-00.cloud.ru", "tenant": "test"},
        "result": {
            "records": [
                {
                    "id": resource_id,
                    "name": name,
                    "type": "edges",
                    "collected_at": date,
                    "inventory": {"ownerRef": {"id": "vdc-test", "name": "VDC test"}},
                    **record_fields,
                }
            ]
        },
    }


def analysis(run_id, date, *, scan=None, captured=None, checks=None, **item_fields):
    item = {
        "id": run_id + "-item",
        "status": "complete",
        "report": {
            "device_id": "device-test",
            "analyzed_at": date,
            "checks": [{"status": "complete", "findings": [], "limitations": []}]
            if checks is None
            else checks,
        },
        "parse_result": {
            "configuration": {
                "platform": "aos-cx",
                "vendor": "hp-aruba",
                "device_id": "device-test",
                "captured_at": captured,
                "imported_at": date,
                "content_sha256": run_id,
            }
        },
        "revision": {"device": {"hostname": run_id + " host"}},
        **item_fields,
    }
    if scan:
        record = scan["result"]["records"][0]
        item["cloud_origin"] = {
            "scan_id": scan["id"],
            "connection": scan["config"],
            "resource_id": record["id"],
            "resource_type": record["type"],
            "record_index": 0,
        }
        item["parse_result"]["configuration"]["captured_at"] = captured or record["collected_at"]
    return {
        "id": run_id,
        "created_at": date,
        "finished_at": date,
        "state": "completed",
        "items": [item],
    }


def instant(value):
    return datetime.fromisoformat(value) if value else None


def test_accumulates_resources_without_duplicates_or_name_matching():
    old = collection("old", "2026-10-20T00:00:00Z", name="Old name")
    new = collection("new", "2026-10-21T00:00:00Z", name="New name")
    omitted = collection("later", "2026-10-22T00:00:00Z", name="New name", resource_id="other")
    rows = project_observations([], [new, omitted, old, old])
    assert len(rows) == 2
    edge = next(row for row in rows if row["source"]["resource_id"] == "edge")
    assert edge["name"] == "New name"
    assert edge["source"]["scan_id"] == "new"
    assert instant(edge["first_seen"]) == instant(old["created_at"])
    assert instant(edge["last_scan"]) == instant(new["created_at"])
    assert edge["last_check"] is None


def test_old_snapshot_reanalysis_keeps_newer_collection_metadata_and_marks_stale():
    old = collection("old", "2026-10-20T00:00:00Z", name="Old name")
    new = collection("new", "2026-10-21T00:00:00Z", name="Current name")
    checked = analysis("recheck-old", "2026-10-25T00:00:00Z", scan=old)
    checked["finished_at"] = "2026-10-26T00:00:00Z"
    rows = project_observations([checked], [old, new])
    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == "Current name" and row["vdc"] == "VDC test"
    assert row["source"]["scan_id"] == "new"
    assert row["source"]["analysis_scan_id"] == "old"
    assert row["source"]["run_id"] == "recheck-old"
    assert instant(row["last_scan"]) == instant(new["created_at"])
    assert instant(row["last_check"]) == instant(checked["items"][0]["report"]["analyzed_at"])
    snapshot = build_dashboard(rows, [checked], [old, new], [])
    assert snapshot.categories[2].stale == 1


def test_failed_attempt_preserves_successful_check_date_and_device_identity():
    source = collection("source", "2026-10-20T00:00:00Z")
    checked = analysis("ok", "2026-10-21T00:00:00Z", scan=source)
    failed = analysis("failed", "2026-10-22T00:00:00Z", scan=source, report=None, status="error")
    rows = project_observations([failed, checked], [source])
    assert len(rows) == 1
    assert instant(rows[0]["last_check"]) == instant(checked["created_at"])
    assert rows[0]["source"]["device_id"] == "device-test"
    assert rows[0]["source"]["run_id"] == "failed"


@pytest.mark.parametrize(
    "checks",
    [
        [],
        [{"status": "not_applicable"}],
        [{}],
        [None],
        [{"status": "partial", "limitations": [{"code": "CHECK_NOT_EXECUTED"}]}],
        [{"status": "complete", "limitations": None}],
    ],
)
def test_missing_or_unexecuted_checks_do_not_create_last_check_date(checks):
    rows = project_observations([analysis("attempt", "2026-10-21T00:00:00Z", checks=checks)], [])
    assert len(rows) == 1 and rows[0]["last_check"] is None


@pytest.mark.parametrize(
    "date", [None, "not-a-date", "2026-10-21T00:00:00", "0001-01-01T00:00:00+14:00"]
)
def test_unknown_or_invalid_dates_remain_empty(date):
    rows = project_observations([], [collection("unknown", date)])
    assert rows[0]["first_seen"] is None and rows[0]["last_scan"] is None
    assert rows[0]["last_check"] is None


def test_fractional_seconds_and_timezones_are_compared_as_instants():
    old = collection("old", "2026-10-20T03:00:00+03:00", name="Old")
    new = collection("new", "2026-10-20T00:00:00.100000Z", name="New")
    rows = project_observations([], [new, old])
    assert rows[0]["name"] == "New"
    assert instant(rows[0]["first_seen"]) == instant(old["created_at"])
    assert instant(rows[0]["last_scan"]) == instant(new["created_at"])


def test_safe_connection_preserves_identity_and_does_not_copy_credentials_or_inputs():
    config = {
        "platform": "advanced",
        "project_id": "project-test",
        "region": "region-test",
        "ecs_endpoint": "https://ecs.test.cloud.ru",
        "vpc_endpoint": "https://vpc.test.cloud.ru",
        "api_key": "SYNTHETIC-API-SECRET",
        "secret_key": "SYNTHETIC-SECRET",
        "headers": {"Authorization": "SYNTHETIC-BEARER"},
        "timeout": 30,
        "credentials": {"password": "SYNTHETIC-PASSWORD"},
    }
    source = collection("safe", "2026-10-20T00:00:00Z", config=config)
    checked = analysis("checked", "2026-10-21T00:00:00Z", scan=source)
    original = deepcopy([source, checked])
    rows = project_observations([checked], [source])
    assert len(rows) == 1
    assert rows[0]["identity"] == "cloud:" + cloud_resource_key(
        source, source["result"]["records"][0], 0
    )
    serialized = json.dumps(rows)
    assert "SYNTHETIC-" not in serialized and "Authorization" not in serialized
    assert set(rows[0]["source"]["connection"]) == {
        "platform",
        "site",
        "tenant",
        "project_id",
        "region",
        "ecs_endpoint",
        "vpc_endpoint",
    }
    assert [source, checked] == original
    snapshot = build_dashboard(rows, [checked], [source], [])
    assert snapshot.categories[2].complete == 1 and not snapshot.unmatched_report_devices


@pytest.mark.parametrize(
    "field,value",
    [
        ("site", "https://other.cloud.ru"),
        ("tenant", "other"),
        ("project_id", "other"),
        ("region", "other"),
        ("platform", "advanced"),
    ],
)
def test_equal_resource_ids_in_different_connections_never_merge(field, value):
    one = collection("one", "2026-10-20T00:00:00Z")
    two = deepcopy(one)
    two["id"] = "two"
    two["config"][field] = value
    assert len(project_observations([], [one, two])) == 2


def test_local_identity_dedup_and_collection_digest_are_separate_from_old_reanalysis():
    old = analysis("old", "2026-10-20T00:00:00Z")
    new = analysis("new", "2026-10-21T00:00:00Z")
    recheck = deepcopy(old)
    recheck["id"] = "recheck"
    recheck["created_at"] = recheck["finished_at"] = "2026-10-25T00:00:00Z"
    recheck["items"][0]["report"]["analyzed_at"] = recheck["created_at"]
    rows = project_observations([old, new, recheck, old], [])
    assert len(rows) == 1
    row = rows[0]
    assert row["identity"] == "device:device-test" and row["category"] == "network"
    assert row["name"] == "new host"
    assert row["source"]["content_sha256"] == "new" and row["source"]["run_id"] == "recheck"
    assert instant(row["first_seen"]) == instant(old["created_at"])
    assert instant(row["last_scan"]) == instant(new["created_at"])
    assert instant(row["last_check"]) == instant(recheck["created_at"])
    # An old revision alone still proves its earlier import; reanalysis is not discovery.
    assert instant(project_observations([recheck], [])[0]["first_seen"]) == instant(
        old["created_at"]
    )


@pytest.mark.parametrize(
    "vendor,platform,category",
    [
        ("Cisco", "asa-9.16", "ngfw"),
        ("", "UserGate", "ngfw"),
        ("", "ideco-ngfw", "ngfw"),
        ("hp-aruba", "aos-cx", "network"),
        ("hp-h3c", "comware", "network"),
        ("unknown", "unknown", "unclassified"),
    ],
)
def test_category_follows_supported_vendor_and_platform(vendor, platform, category):
    run = analysis("category", "2026-10-20T00:00:00Z")
    run["items"][0]["parse_result"]["configuration"].update(vendor=vendor, platform=platform)
    assert project_observations([run], [])[0]["category"] == category


def test_templates_do_not_become_running_vms_and_vdc_reference_can_be_object():
    source = collection(
        "template",
        "2026-10-20T00:00:00Z",
        type="vms",
        inventory={
            "isVAppTemplate": True,
            "vdc": {"id": "vdc-id", "name": "VDC object"},
        },
    )
    rows = project_observations([], [source])
    assert rows[0]["resource_type"] == "vm_templates" and rows[0]["vdc"] == "VDC object"
    assert not build_dashboard(rows, [], [source], []).virtual_machines


def test_anonymous_resources_keep_collection_index_identity():
    source = collection("anonymous", "2026-10-20T00:00:00Z", resource_id=None)
    source["result"]["records"].append(deepcopy(source["result"]["records"][0]))
    checked = analysis("checked", "2026-10-21T00:00:00Z", scan=source)
    checked["items"][0]["cloud_origin"]["record_index"] = 1
    rows = project_observations([checked], [source])
    assert len(rows) == 2
    assert next(row for row in rows if row["last_check"])["source"]["record_index"] == 1
