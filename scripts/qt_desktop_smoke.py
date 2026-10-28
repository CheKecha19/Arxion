"""Оконная Qt-проверка на synthetic данных, с временной БД и исходниками."""

from __future__ import annotations

import gc
import json
import os
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from time import monotonic, sleep
from uuid import uuid4

if "--visible" not in sys.argv:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.reachability import RouteSelectionResult
from firewall_compliance.interfaces.desktop.backend import AnalysisSession
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow
from firewall_compliance.interfaces.desktop.qt_theme import apply_theme

ROOT = Path(__file__).resolve().parents[1]
LEGACY_CHECKS = frozenset(
    {
        "FW-ANY-ANY",
        "FW-DUPLICATE",
        "FW-SHADOWED",
        "FW-MERGE-CANDIDATE",
        "FW-LOGGING",
        "FW-COMMENTS",
        "FW-DISABLED",
    }
)
EXTENDED_CHECKS = frozenset(
    {
        "FW-PARTIAL-SHADOWED",
        "FW-UNION-SHADOWED",
        "FW-DANGEROUS-SERVICES",
        "FW-ADMIN-UNTRUSTED",
    }
)


def pump(app: QApplication, predicate: Callable[[], bool], timeout: float = 45) -> None:
    deadline = monotonic() + timeout
    while not predicate():
        app.processEvents()
        if monotonic() >= deadline:
            raise AssertionError("Истекло ожидание Qt результата")
        sleep(0.005)
    app.processEvents()


@contextmanager
def workspace_smoke_directory() -> Iterator[Path]:
    """Retain synthetic evidence without tempfile's restrictive Windows ACLs."""
    directory = (ROOT / "artifacts" / "qt-smoke-runs" / uuid4().hex).resolve()
    assert directory.is_relative_to(ROOT)
    directory.mkdir(parents=True)
    yield directory


def extended_policy_smoke(app: QApplication, directory: Path) -> None:
    """Exercise the four added checks through the actual Qt/settings/worker path."""
    source = directory / "extended-policy.cfg"
    source.write_text(
        "hostname QA-EXTENDED\n"
        "access-list ADMIN extended permit tcp host 192.0.2.0 host 203.0.113.10 eq 22\n"
        "access-list ADMIN extended permit tcp host 192.0.2.1 host 203.0.113.10 eq 22\n"
        "access-list ADMIN extended permit tcp 192.0.2.0 255.255.255.254 "
        "host 203.0.113.10 eq 22\n"
        "access-list ADMIN extended permit tcp 192.0.2.0 255.255.255.252 "
        "host 203.0.113.10 eq 22\n"
        "access-group ADMIN in interface outside\n",
        encoding="utf-8",
    )
    window = MainWindow(ProjectStore(directory / "extended.sqlite3"))
    try:
        project = window.create_project("Расширенные synthetic проверки")
        selector = {
            "selector_id": "explicit-review-service",
            "name": "Synthetic organization service",
            "protocol": "tcp",
            "port_ranges": [{"start": 22, "end": 22}],
        }
        window.policy_exposure_settings.load_profile(
            {
                "profile_id": "synthetic-smoke",
                "version": "1",
                "dangerous_services": [selector],
                "administrative_services": [selector],
                "administrative_targets": ["203.0.113.10/32"],
                "trusted_admin_networks": ["10.0.0.0/8"],
            }
        )
        selected = LEGACY_CHECKS | EXTENDED_CHECKS
        for check_id, checkbox in window.check_boxes.items():
            checkbox.setChecked(check_id in selected)
        window._save_analysis_settings()
        window.stage_paths([source])
        pump(app, lambda: not window._preflight_jobs)
        assert window.run_button.isEnabled()
        window.start_analysis()
        pump(app, lambda: not window._batch_active)
        assert window.run is not None and len(window.run["items"]) == 1
        report = window.run["items"][0]["report"]
        assert report["check_catalog_version"] == "1.3.0"
        checks = {check["check_id"]: check for check in report["checks"]}
        assert set(checks) == selected
        assert checks["FW-PARTIAL-SHADOWED"]["findings"]
        assert checks["FW-UNION-SHADOWED"]["findings"]
        assert len(checks["FW-DANGEROUS-SERVICES"]["findings"]) == 4
        assert len(checks["FW-ADMIN-UNTRUSTED"]["findings"]) == 4
        assert all(
            finding["evidence"]["source_locations"]
            for check_id in EXTENDED_CHECKS
            for finding in checks[check_id]["findings"]
        )
        assert (
            window.store.get_project(project)["settings"]["policy_exposure_profile"]["profile_id"]
            == "synthetic-smoke"
        )
    finally:
        window.close()
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()


def main() -> None:
    sys.path.insert(0, str(ROOT))
    from tests.network_import_fixtures import INTERFACES, RIB, make_document

    app = QApplication.instance() or QApplication([])
    apply_theme(app)
    with workspace_smoke_directory() as directory:
        store = ProjectStore(directory / "projects.sqlite3")
        window = MainWindow(store)
        window.show()
        project_id = window.create_project("Синтетический QA проект")
        # Keep the original seven-check scenario and its exact known outcome.
        # New checks have a separate, explicitly configured scenario below.
        for check_id, checkbox in window.check_boxes.items():
            checkbox.setChecked(check_id in LEGACY_CHECKS)
        fixture = ROOT / "tests/fixtures/assurance/policy_quality.cfg"
        text = fixture.read_text(encoding="utf-8")
        paths = []
        for index in range(76):
            path = directory / f"qa-asa-{index:02}.cfg"
            path.write_text(
                text.replace("hostname ASA-ASSURANCE", f"hostname QA-ASA-{index:02}"),
                encoding="utf-8",
            )
            paths.append(path)
        paths.extend(
            [
                ROOT / "tests/fixtures/hp_aruba/aos_switch.cfg",
                ROOT / "tests/fixtures/hp_aruba/aos_cx.cfg",
            ]
        )
        comware = directory / "qa-comware.cfg"
        comware.write_text(
            "version 7.1.045\nsysname QA-COMWARE\nacl number 2000\n"
            " rule 0 permit source 192.0.2.10 0\n#\n",
            encoding="utf-8",
        )
        unsupported = directory / "qa-unsupported.txt"
        unsupported.write_text("not a network configuration", encoding="utf-8")
        paths.extend([comware, unsupported])
        window.stage_paths(paths)
        ticks = []
        heartbeat = QTimer()
        heartbeat.timeout.connect(lambda: ticks.append(monotonic()))
        heartbeat.start(10)
        pump(app, lambda window=window: not window._preflight_jobs)
        assert len(window.staged) == 80
        assert window.run_button.isEnabled()
        window.navigate("findings")
        window.start_analysis()
        pump(app, lambda window=window: not window._batch_active, timeout=90)
        heartbeat.stop()
        assert len(ticks) > 1
        assert window.run and len(window.run["items"]) == 80
        assert sum(bool(item["report"]) for item in window.run["items"]) == 79
        assert any(item["status"] == "unsupported" for item in window.run["items"])
        asa_reports = [
            item["report"]
            for item in window.run["items"]
            if Path(item["path"]).name.startswith("qa-asa-")
        ]
        assert len(asa_reports) == 76
        assert all(
            {check["check_id"] for check in report["checks"]} == LEGACY_CHECKS
            and sum(len(check["findings"]) for check in report["checks"]) == 14
            for report in asa_reports
        )
        assert window.finding_model.rowCount() >= 76 * 14
        assert all(item["warning"] not in {"Выполняется", "В очереди"} for item in window.staged)
        assert window.current_section_id == "findings"
        assert window.notification_label.isVisible()
        assert window.notification_button.isVisible()
        panel = window.advanced_panel
        panel.refresh_sessions()
        base = panel.base().revision
        for content, kind in ((INTERFACES, "asa_running_config_interfaces"), (RIB, "asa_ipv4_rib")):
            request = make_document(base, content, kind)
            path = directory / f"{kind}.txt"
            path.write_text(content, encoding="utf-8")
            metadata = request.metadata.model_dump(mode="json")
            for key in ("source_document_id", "device_id", "content_sha256"):
                metadata.pop(key)
            panel.network_path.setText(str(path))
            panel.metadata.setPlainText(json.dumps(metadata))
            panel.stage()
        assert len(panel.drafts[base.revision_id]) == 2
        panel.import_network()
        pump(app, lambda panel=panel: isinstance(panel.current_result, NetworkImportResult))
        assert len(panel.current_result.documents) == 2
        assert len(panel.current_result.revision.interfaces) == 2
        panel.query_fields["source_ip"].setText("10.20.0.10")
        panel.query_fields["destination_ip"].setText("198.51.100.25")
        panel.query_fields["ingress_interface_id"].setText("interface:GigabitEthernet0/1")
        panel.query_fields["destination_port"].setText("443")
        panel.query("route")
        pump(app, lambda panel=panel: isinstance(panel.current_result, RouteSelectionResult))
        assert panel.current_result.status == "not_enough_evidence"
        run_id = window.run_id
        assert run_id is not None
        for size in ((1920, 1080), (1280, 800)):
            window.resize(*size)
            for page, section in enumerate(
                (
                    "home",
                    "findings",
                    "devices",
                    "rules",
                    "history",
                    "reports",
                    "advanced",
                    "map",
                    "settings",
                    "scans",
                    "staging",
                )
            ):
                window.navigate(section)
                app.processEvents()
                assert window.pages.currentIndex() == page, (
                    section,
                    page,
                    window.pages.currentIndex(),
                    window.current_section_id,
                )
        window.navigate("findings")
        window.finding_search.setFocus()
        QTest.keyClicks(window.finding_search, "QA-ASA-00")
        assert window.finding_proxy.rowCount() == 14
        window.finding_table.selectRow(0)
        app.processEvents()
        assert window.finding_detail.toPlainText()
        if "--screenshot" in sys.argv:
            destination = ROOT / "artifacts" / "qt-window-smoke"
            destination.mkdir(parents=True, exist_ok=True)
            scale = os.environ.get("QT_SCALE_FACTOR", "1").replace(".", "-")
            assert window.grab().save(str(destination / "findings.png"))
            window.resize(1920, 1080)
            for section in ("home", "devices", "settings"):
                window.navigate(section)
                app.processEvents()
                assert window.grab().save(str(destination / f"{section}-scale-{scale}.png"))
            window.navigate("findings")
            window.resize(1280, 720)
            app.processEvents()
            assert window.grab().save(str(destination / "findings-150-percent-layout.png"))
            for section in ("home", "devices", "history", "reports", "staging", "scans"):
                window.navigate(section)
                if section == "devices":
                    window.device_table.selectRow(0)
                app.processEvents()
                # Windows ограничивает клиентскую область рамкой на экране при 150%.
                assert 1000 <= window.width() <= 1280 and 650 <= window.height() <= 720, (
                    section,
                    window.size(),
                    window.minimumSizeHint(),
                )
                assert window.grab().save(str(destination / f"workspace-{section}-{scale}.png"))
            window.navigate("findings")
        window.mark_combo.setCurrentIndex(window.mark_combo.findData("confirmed"))
        window.comment_edit.setPlainText("Проверено в synthetic smoke <script>")
        window.save_marks()
        assert store.get_run(run_id)["marks"]
        window.finding_search.clear()
        window.export_batch("html", directory / "report.html")
        window.export_batch("json", directory / "report.json")
        pump(
            app,
            lambda: (directory / "report.html").exists() and (directory / "report.json").exists(),
        )
        package = json.loads((directory / "report.json").read_text(encoding="utf-8"))
        assert package["summary"]["files"] == 80
        assert package["user_decisions"]
        document = (directory / "report.html").read_text(encoding="utf-8")
        assert "&lt;script&gt;" in document and "<script>" not in document
        assert "https://" not in document
        snapshot = next(item for item in window.run["items"] if item["report"])
        window.close()
        app.processEvents()
        restored = MainWindow(ProjectStore(directory / "projects.sqlite3"))
        restored.show()
        restored.load_run(run_id)
        assert restored.project_id == project_id
        assert restored.run and restored.run["marks"]
        assert not restored.sessions
        restored.attach_source(snapshot["id"], Path(snapshot["path"]))
        pump(app, lambda restored=restored: not restored._restore_busy)
        assert isinstance(restored.sessions[snapshot["id"]], AnalysisSession)
        restored.navigate("devices")
        source_row = next(
            index
            for index, item in enumerate(restored.device_model.payloads)
            if item["id"] == snapshot["id"]
        )
        restored.device_table.selectRow(
            restored.device_proxy.mapFromSource(restored.device_model.index(source_row, 0)).row()
        )
        restored.line_start.setValue(1)
        restored.line_end.setValue(3)
        restored.preview_selected_source()
        assert "hostname QA-ASA-00" in restored.device_detail.toPlainText()
        changed = directory / "changed.cfg"
        changed.write_text("changed content", encoding="utf-8")
        try:
            store.attach_source(snapshot["id"], changed)
        except ValueError:
            pass
        else:
            raise AssertionError("Изменённый исходник принят")
        old_session = restored.sessions[snapshot["id"]]
        restored.attach_source(snapshot["id"], changed)
        pump(
            app,
            lambda restored=restored: not restored._restore_busy and not restored._preflight_jobs,
        )
        assert any(item["path"] == changed for item in restored.staged)
        assert restored.sessions[snapshot["id"]] is old_session
        staged_count = len(restored.staged)
        restored.attach_source(snapshot["id"], directory / "missing.cfg")
        pump(app, lambda restored=restored: not restored._restore_busy)
        assert len(restored.staged) == staged_count
        assert restored.sessions[snapshot["id"]] is old_session
        started, release = Event(), Event()
        restored.runner.submit(lambda: (started.set(), release.wait(2)), lambda _result: None)
        pump(app, started.is_set)
        before_close = monotonic()
        restored.close()
        assert monotonic() - before_close < 1
        release.set()
        app.processEvents()
        window.deleteLater()
        restored.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        del window, restored
        gc.collect()
        extended_policy_smoke(app, directory)
        print(
            "Qt smoke passed: 80 files, legacy seven checks/14 findings, extended four checks, "
            "navigation, keyboard, history, reports, hash, close."
        )


if __name__ == "__main__":
    main()
