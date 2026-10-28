"""Optional policy checks keep explicit profiles across real CLI, Qt and cloud paths."""

import json
import os
import subprocess
import sys
import time
from copy import deepcopy
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QWidget

from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.interfaces.desktop.backend import (
    AnalysisSession,
    analyze_file,
    reanalyze_session,
    selected_checks,
)
from firewall_compliance.interfaces.desktop.check_presentation import check_execution_status
from firewall_compliance.interfaces.desktop.cloud_analysis import analyze_saved_vmware
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow

APP = None
EXPOSURE_IDS = ("FW-DANGEROUS-SERVICES", "FW-ADMIN-UNTRUSTED")
EXTENDED_IDS = {*EXPOSURE_IDS, "FW-PARTIAL-SHADOWED", "FW-UNION-SHADOWED"}
LEGACY_IDS = (
    "FW-ANY-ANY",
    "FW-DUPLICATE",
    "FW-SHADOWED",
    "FW-MERGE-CANDIDATE",
    "FW-LOGGING",
    "FW-COMMENTS",
    "FW-DISABLED",
)


@pytest.fixture
def directory():
    path = Path("artifacts/extended-policy-integration") / str(uuid4())
    path.mkdir(parents=True)
    return path.resolve()


@pytest.fixture
def source(directory):
    path = directory / "synthetic.cfg"
    path.write_text(
        "hostname SYNTHETIC-EXPOSURE\n"
        "access-list OUTSIDE extended permit tcp any host 192.0.2.10 eq 22\n"
        "access-group OUTSIDE in interface outside\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def window(directory):
    global APP
    APP = QApplication.instance() or QApplication([])
    widget = MainWindow(
        store=ProjectStore(directory / "projects.sqlite3"),
        advanced_widget_factory=lambda _sessions, _runner: QWidget(),
    )
    try:
        yield widget
    finally:
        widget.close()
        widget.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        APP.processEvents()


def profile(port=22, *, targets=("192.0.2.10/32",), trusted=("10.0.0.0/8",)):
    selector = {
        "selector_id": "explicit-organization-service",
        "name": "Organization service",
        "protocol": "tcp",
        "port_ranges": [{"start": port, "end": port}],
    }
    return PolicyExposureProfile.model_validate(
        {
            "profile_id": "synthetic-exposure",
            "version": "7",
            "dangerous_services": [selector],
            "administrative_services": [selector],
            "administrative_targets": targets,
            "trusted_admin_networks": trusted,
        }
    )


def checks(report):
    return {check.check_id: check for check in report.checks}


def wait(window, predicate):
    deadline = time.monotonic() + 20
    while not predicate():
        APP.processEvents()
        window.poll_jobs()
        if time.monotonic() > deadline:
            raise AssertionError("Synthetic Qt job did not finish")
        time.sleep(0.005)
    APP.processEvents()


def configure(window, policy, enabled=EXPOSURE_IDS):
    window.policy_exposure_settings.load_profile(policy.model_dump(mode="json"))
    for identifier, checkbox in window.check_boxes.items():
        checkbox.setChecked(identifier in enabled)
    window._save_analysis_settings()


def test_local_selection_preserves_default_catalog_and_uses_explicit_profile(source):
    original = source.read_bytes()
    default = analyze_file(source)
    assert isinstance(default, AnalysisSession)
    assert not EXTENDED_IDS.intersection(checks(default.report))
    assert set(LEGACY_IDS) <= set(checks(default.report))
    legacy = analyze_file(source, enabled_check_ids=LEGACY_IDS, policy_exposure_profile=profile())
    assert isinstance(legacy, AnalysisSession)
    assert set(checks(legacy.report)) == set(LEGACY_IDS)
    assert legacy.report.check_catalog_version != "1.3.0"
    session = analyze_file(
        source, enabled_check_ids=EXPOSURE_IDS, policy_exposure_profile=profile()
    )
    assert isinstance(session, AnalysisSession)
    assert set(checks(session.report)) == set(EXPOSURE_IDS)
    assert session.report.check_catalog_version == "1.3.0"
    assert all(check.findings for check in session.report.checks)
    assert source.read_bytes() == original


@pytest.mark.parametrize("targets,trusted", [(None, ("10.0.0.0/8",)), (("192.0.2.10/32",), None)])
def test_missing_explicit_admin_targets_or_trust_stays_not_executed(source, targets, trusted):
    session = analyze_file(
        source,
        enabled_check_ids=EXPOSURE_IDS,
        policy_exposure_profile=profile(targets=targets, trusted=trusted),
    )
    assert isinstance(session, AnalysisSession)
    result = checks(session.report)
    assert result["FW-DANGEROUS-SERVICES"].findings
    admin = result["FW-ADMIN-UNTRUSTED"]
    assert not admin.findings
    assert check_execution_status(admin.model_dump(mode="json")) == "not_executed"
    assert any(item.code == "CHECK_NOT_EXECUTED" for item in admin.limitations)


def test_unknown_profile_and_explicit_catalog_selection_are_distinct(source):
    selected = selected_checks(EXPOSURE_IDS)
    assert selected and {check.check_id for check in selected} == set(EXPOSURE_IDS)
    session = analyze_file(source, enabled_check_ids=EXPOSURE_IDS)
    assert isinstance(session, AnalysisSession)
    assert all(not check.findings for check in session.report.checks)
    assert all(
        check_execution_status(check.model_dump(mode="json")) == "not_executed"
        for check in session.report.checks
    )


def test_real_cli_profile_enables_extended_checks_and_invalid_profile_is_safe(source, directory):
    policy_path = directory / "profile.json"
    policy_path.write_text(profile().model_dump_json(), encoding="utf-8")
    environment = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    command = [sys.executable, "-m", "firewall_compliance", "analyze", str(source)]
    baseline = subprocess.run(command, capture_output=True, encoding="utf-8", env=environment)
    assert baseline.returncode == 0, baseline.stderr
    old = json.loads(baseline.stdout)
    assert not EXTENDED_IDS.intersection(check["check_id"] for check in old["checks"])
    enabled_unknown = subprocess.run(
        command + ["--extended-policy-checks"],
        capture_output=True,
        encoding="utf-8",
        env=environment,
    )
    assert enabled_unknown.returncode == 0, enabled_unknown.stderr
    unknown = json.loads(enabled_unknown.stdout)
    assert unknown["check_catalog_version"] == "1.3.0"
    unknown_checks = {check["check_id"]: check for check in unknown["checks"]}
    assert all(
        check_execution_status(unknown_checks[identifier]) == "not_executed"
        and not unknown_checks[identifier]["findings"]
        for identifier in EXPOSURE_IDS
    )
    result = subprocess.run(
        command + ["--policy-exposure-profile", str(policy_path)],
        capture_output=True,
        encoding="utf-8",
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    results = {check["check_id"]: check for check in payload["checks"]}
    assert results.keys() >= EXTENDED_IDS and payload["check_catalog_version"] == "1.3.0"
    assert all(results[identifier]["findings"] for identifier in EXPOSURE_IDS)
    policy_path.write_text('{"dangerous_services":"synthetic-secret-do-not-log"}', encoding="utf-8")
    rejected = subprocess.run(
        command + ["--policy-exposure-profile", str(policy_path)],
        capture_output=True,
        encoding="utf-8",
        env=environment,
    )
    assert rejected.returncode == 2 and not rejected.stdout.strip()
    assert "synthetic-secret-do-not-log" not in rejected.stderr


def test_saved_cloud_analysis_uses_selected_profile_without_mutating_scan(directory):
    store = ProjectStore(directory / "cloud.sqlite3")
    project = store.create_project("Synthetic cloud exposure")
    config = {"platform": "vmware", "site": "https://synthetic.invalid", "tenant": "synthetic"}
    scan_id = store.create_cloud_scan(project, {}, config)
    store.finish_cloud_scan(
        scan_id,
        {
            "state": "completed",
            "errors": [],
            "records": [
                {
                    "type": "edges",
                    "id": "urn:vcloud:gateway:synthetic-exposure",
                    "name": "Synthetic Edge",
                    "data": {
                        "firewall": {
                            "systemRules": [],
                            "defaultRules": [],
                            "userDefinedRules": [
                                {
                                    "id": "rule-1",
                                    "name": "Organization service",
                                    "actionValue": "ALLOW",
                                    "active": True,
                                    "direction": "IN_OUT",
                                    "ipProtocol": "IPV4",
                                    "sourceFirewallGroups": None,
                                    "sourceFirewallIpAddresses": None,
                                    "destinationFirewallGroups": None,
                                    "destinationFirewallIpAddresses": ["192.0.2.10"],
                                    "applicationPortProfiles": None,
                                    "rawPortProtocols": [
                                        {
                                            "layer4Item": {
                                                "protocol": "TCP",
                                                "destinationPorts": ["22"],
                                            }
                                        }
                                    ],
                                    "logging": False,
                                    "description": "Synthetic explicit exposure",
                                }
                            ],
                        }
                    },
                }
            ],
        },
    )
    scan = store.list_cloud_scans(project)[0]
    original = deepcopy(scan)
    settings = {
        "enabled_check_ids": list(EXPOSURE_IDS),
        "policy_exposure_profile": profile().model_dump(mode="json"),
    }
    payloads = analyze_saved_vmware(scan, settings, Event())
    report = payloads[0]["report"]
    assert report["check_catalog_version"] == "1.3.0"
    assert {check["check_id"] for check in report["checks"]} == set(EXPOSURE_IDS)
    assert all(check["findings"] for check in report["checks"])
    run_id = store.save_cloud_analysis(scan_id, payloads, settings)
    reopened = ProjectStore(store.path)
    assert (
        reopened.get_run(run_id)["settings"]["policy_exposure_profile"]
        == settings["policy_exposure_profile"]
    )
    assert scan == original and reopened.list_cloud_scans(project)[0] == original


def test_project_profile_isolation_legacy_check_selection_and_reopen(window):
    first = window.create_project("Synthetic profile project")
    configure(window, profile(), LEGACY_IDS)
    first_settings = window.store.get_project(first)["settings"]
    second = window.create_project("Synthetic unknown-profile project")
    assert window.policy_exposure_settings.profile().administrative_targets is None
    configure(window, PolicyExposureProfile(), LEGACY_IDS)
    window.refresh_projects(first)
    assert window.policy_exposure_settings.profile() == profile()
    assert {key for key, box in window.check_boxes.items() if box.isChecked()} == set(LEGACY_IDS)
    assert window.store.get_project(first)["settings"] == first_settings
    restored = ProjectStore(window.store.path)
    assert (
        restored.get_project(second)["settings"]["policy_exposure_profile"][
            "administrative_targets"
        ]
        is None
    )
    assert restored.get_project(first)["settings"][
        "policy_exposure_profile"
    ] == profile().model_dump(mode="json")


def test_qt_start_and_repeat_capture_new_profile_but_reuse_saved_source_snapshot(window, source):
    project = window.create_project("Synthetic repeat exposure")
    configure(window, profile(23))
    window.stage_paths([source])
    wait(window, lambda: not window._preflight_jobs)
    assert window.run_button.isEnabled()
    window.start_analysis()
    wait(window, lambda: not window._batch_active)
    first_run = window.run_id
    first = window.store.get_run(first_run)
    assert first["settings"]["policy_exposure_profile"] == profile(23).model_dump(mode="json")
    assert all(not check["findings"] for check in first["items"][0]["report"]["checks"])
    revision = deepcopy(first["items"][0]["revision"])
    source.write_text("Changed synthetic source must not be reread", encoding="utf-8")
    configure(window, profile(22))
    row = next(
        index for index, item in enumerate(window.device_model.payloads) if item.get("report")
    )
    window.device_table.selectRow(
        window.device_proxy.mapFromSource(window.device_model.index(row, 0)).row()
    )
    window.repeat_selected()
    wait(window, lambda: not window._restore_busy)
    assert window.run_id != first_run
    repeated = window.store.get_run(window.run_id)
    assert repeated["settings"]["policy_exposure_profile"] == profile(22).model_dump(mode="json")
    assert all(check["findings"] for check in repeated["items"][0]["report"]["checks"])
    assert repeated["items"][0]["revision"] == revision
    assert window.store.get_run(first_run) == first
    assert ProjectStore(window.store.path).get_project(project)["settings"][
        "policy_exposure_profile"
    ] == profile(22).model_dump(mode="json")


def test_reanalyze_api_applies_new_profile_without_rebuilding_revision(source):
    session = analyze_file(
        source, enabled_check_ids=EXPOSURE_IDS, policy_exposure_profile=profile(23)
    )
    assert isinstance(session, AnalysisSession)
    revision = session.revision.model_dump(mode="json")
    repeated = reanalyze_session(
        session, enabled_check_ids=EXPOSURE_IDS, policy_exposure_profile=profile()
    )
    assert repeated.revision.model_dump(mode="json") == revision
    assert all(check.findings for check in repeated.report.checks)
    assert all(not check.findings for check in session.report.checks)
