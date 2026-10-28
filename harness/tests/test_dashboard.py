"""Synthetic dashboard counters, identity isolation and compact Qt presentation."""

from copy import deepcopy
from typing import Any

from hypothesis import given
from hypothesis import strategies as st
from PySide6.QtWidgets import QApplication

from firewall_compliance.interfaces.desktop.dashboard import build_dashboard
from firewall_compliance.interfaces.desktop.qt_dashboard import ProjectDashboard

QT_APP: QApplication | None = None


def resource(identity: str, category: str = "network", **fields: Any) -> dict[str, Any]:
    return {
        "id": identity,
        "identity": "device:" + identity,
        "category": category,
        "lifecycle": "active",
        "resource_type": "device",
        **fields,
    }


def run(
    device: str,
    date: str,
    *,
    state: str = "completed",
    status: str = "complete",
    run_id: str = "run",
    count: int = 1,
    severity: str = "high",
    **item_fields: Any,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "state": state,
        "created_at": date,
        "finished_at": date,
        "marks": {},
        "items": [
            {
                "status": status,
                "report": {
                    "device_id": device,
                    "analyzed_at": date,
                    "checks": [
                        {
                            "check_id": "FW-TEST",
                            "status": status,
                            "findings": [
                                {"finding_id": f"finding-{index}", "severity": severity}
                                for index in range(count)
                            ],
                            "limitations": [],
                        }
                    ],
                },
                **item_fields,
            }
        ],
    }


def test_empty_dashboard_has_three_categories_and_five_severities():
    snapshot = build_dashboard([], [], [], [])
    assert [category.category for category in snapshot.categories] == ["ngfw", "network", "cloud"]
    assert not snapshot.active_resources and not snapshot.analysis_runs
    assert snapshot.last_check_at is None
    assert len(snapshot.findings_by_severity) == 5
    assert not snapshot.findings and not snapshot.recent_checks


def test_manual_and_collection_are_not_mistaken_for_analysis():
    resources = [
        resource("manual", origin="manual"),
        resource("vm", "cloud", resource_type="vms", last_scan="2026-10-26T00:00:00+00:00"),
        resource("fake-date", last_check="2026-10-26T00:00:00+00:00"),
    ]
    snapshot = build_dashboard(
        resources, [], [], [{"provider": "cloud_ru_vmware", "config": {"tenant": "one"}}]
    )
    network = next(category for category in snapshot.categories if category.category == "network")
    cloud = next(category for category in snapshot.categories if category.category == "cloud")
    assert network.unchecked == 2 and not network.checked
    assert cloud.collected == 1 and not cloud.checked
    assert snapshot.virtual_machines == 1 and snapshot.integrations == 1
    assert snapshot.last_check_at is None


def test_latest_findings_do_not_accumulate_repeated_checks():
    older = run("router", "2026-10-25T00:00:00+00:00", run_id="old", count=8)
    newer = run("router", "2026-10-26T00:00:00+00:00", run_id="new", count=2)
    original = deepcopy([older, newer])
    snapshot = build_dashboard([resource("router")], [older, newer, newer], [], [])
    assert snapshot.findings == 2
    assert snapshot.analysis_runs == 2 and snapshot.executed_checks == 2
    assert snapshot.categories[1].complete == 1
    assert snapshot.last_check_at == "2026-10-26T00:00:00+00:00"
    assert [older, newer] == original


def test_partial_and_unexecuted_checks_are_explicit():
    checked = run("router", "2026-10-26T00:00:00+00:00", status="partial")
    checked["items"][0]["report"]["checks"].append(
        {
            "status": "partial",
            "limitations": [{"code": "CHECK_NOT_EXECUTED"}],
            "findings": [{"finding_id": "not-valid", "severity": "critical"}],
        }
    )
    snapshot = build_dashboard([resource("router")], [checked], [], [])
    assert snapshot.executed_checks == 1 and snapshot.partial_checks == 1
    assert snapshot.not_executed_checks == 1
    assert snapshot.findings == 1 and snapshot.findings_by_severity["critical"] == 0
    assert snapshot.categories[1].partial == 1
    assert snapshot.recent_checks[0].not_executed_checks == 1
    assert "неполно" in ProjectDashboard._operation_state(snapshot.recent_checks[0])


def test_no_check_results_do_not_set_last_check_time():
    attempt = run("router", "2026-10-26T00:00:00+00:00", count=0)
    attempt["items"][0]["report"]["checks"][0]["limitations"] = [{"code": "CHECK_NOT_EXECUTED"}]
    snapshot = build_dashboard([resource("router")], [attempt], [], [])
    assert snapshot.last_check_at is None
    assert not snapshot.executed_checks and snapshot.categories[1].unchecked == 1
    assert snapshot.analysis_runs == 1 and snapshot.completed_analysis_runs == 0


def test_cloud_old_scan_reanalysis_stays_stale_after_new_collection():
    current = resource(
        "edge",
        "cloud",
        source={"device_id": "hashed-edge", "scan_id": "new-collection"},
        last_scan="2026-10-26T00:00:00+00:00",
    )
    analysis = run(
        "hashed-edge", "2026-10-27T00:00:00+00:00", cloud_origin={"scan_id": "old-collection"}
    )
    snapshot = build_dashboard([current], [analysis], [], [])
    cloud = snapshot.categories[2]
    assert cloud.stale == 1 and not cloud.checked
    assert snapshot.findings == 1


def test_cloud_connections_never_match_only_by_resource_name_or_id():
    current = resource(
        "edge",
        "cloud",
        source={
            "resource_id": "same-id",
            "scan_id": "scan-a",
            "connection": {"site": "https://one.cloud.ru", "tenant": "a"},
        },
    )
    analysis = run(
        "same-name",
        "2026-10-26T00:00:00+00:00",
        cloud_origin={
            "resource_id": "same-id",
            "scan_id": "scan-b",
            "connection": {"site": "https://one.cloud.ru", "tenant": "b"},
        },
    )
    snapshot = build_dashboard([current], [analysis], [], [])
    assert snapshot.categories[2].unchecked == 1
    assert not snapshot.findings and snapshot.unmatched_report_devices == 1


def test_archives_excluded_and_unknown_category_never_guessed():
    snapshot = build_dashboard(
        [resource("old", lifecycle="archived"), resource("UserGate-looking", "unknown")],
        [run("old", "2026-10-26T00:00:00+00:00")],
        [],
        [],
    )
    assert snapshot.active_resources == 1 and snapshot.archived_resources == 1
    assert snapshot.categories[0].total == 0
    assert snapshot.categories[-1].category == "unclassified"
    assert not snapshot.findings


def test_linked_manual_resource_uses_explicit_registry_identities():
    linked = resource("manual", identities=["manual:manual", "device:router"])
    snapshot = build_dashboard([linked], [run("router", "2026-10-26T00:00:00+00:00")], [], [])
    assert snapshot.active_resources == 1
    assert snapshot.categories[1].complete == 1
    assert snapshot.findings == 1 and not snapshot.unmatched_report_devices


def test_review_decisions_have_all_and_open_counters():
    analysis = run("router", "2026-10-26T00:00:00+00:00", count=3)
    analysis["marks"] = {
        "finding-0": {"status": "false_positive"},
        "finding-1": {"status": "resolved"},
        "finding-2": {"status": "accepted_risk"},
    }
    snapshot = build_dashboard([resource("router")], [analysis], [], [])
    assert snapshot.findings == 3 and snapshot.open_findings == 1


def test_recent_operations_are_chronological_and_limited_to_five():
    runs = [
        run("r", f"2026-10-{day:02d}T00:00:00+00:00", run_id=f"r{day}") for day in range(10, 17)
    ]
    scans = [
        {
            "id": "latest",
            "created_at": "2026-10-26T04:00:00+03:00",
            "state": "failed",
            "result": {"records": []},
        }
    ]
    snapshot = build_dashboard([resource("r")], runs, scans, [])
    assert len(snapshot.recent_checks) == 5 and len(snapshot.recent_operations) == 5
    assert snapshot.recent_checks[0].operation_id == "r16"
    assert snapshot.recent_operations[0].kind == "collection"
    assert snapshot.recent_operations[0].state == "failed"


def test_reportless_failed_item_does_not_count_as_checked():
    attempt = {
        "id": "failure",
        "state": "completed",
        "created_at": "2026-10-26T00:00:00+00:00",
        "items": [{"status": "error", "report": None}],
    }
    snapshot = build_dashboard([resource("router")], [attempt], [], [])
    assert not snapshot.executed_checks and not snapshot.completed_analysis_runs
    assert snapshot.categories[1].unchecked == 1
    assert snapshot.recent_checks[0].resources == 1
    assert "не выполнены" in ProjectDashboard._operation_state(snapshot.recent_checks[0])


@given(st.lists(st.sampled_from(["ngfw", "network", "cloud", "unknown"]), max_size=30))
def test_resource_state_partition_has_no_hidden_or_duplicate_counts(categories):
    rows = [
        resource(str(index), category, last_scan="2026-10-26T00:00:00+00:00" if index % 2 else None)
        for index, category in enumerate(categories)
    ]
    snapshot = build_dashboard(rows, [], [], [])
    assert snapshot.active_resources == len(rows)
    assert sum(category.total for category in snapshot.categories) == len(rows)
    assert all(
        category.total
        == category.complete
        + category.partial
        + category.collected
        + category.unchecked
        + category.stale
        for category in snapshot.categories
    )


def test_qt_dashboard_replaces_contents_and_emits_navigation():
    global QT_APP
    QT_APP = QApplication.instance() or QApplication([])
    widget = ProjectDashboard()
    try:
        navigation = []
        widget.navigation_requested.connect(navigation.append)
        widget.refresh(
            build_dashboard(
                [resource("router")], [run("router", "2026-10-26T00:00:00+00:00")], [], []
            )
        )
        assert widget.category_table.rowCount() == 3
        assert widget.findings_table.rowCount() == 5
        assert widget.checks_table.rowCount() == 1
        assert "26.10.2026" in widget.last_check_label.text()
        widget.navigation_buttons["findings"].click()
        assert navigation == ["findings"]
        widget.refresh(build_dashboard([], [], [], []))
        assert widget.checks_table.rowCount() == 0
        assert "ещё не выполнялась" in widget.last_check_label.text()
    finally:
        widget.close()
