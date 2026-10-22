"""Самопроверка собранного приложения на собственных синтетических данных."""

import gc
import json
import sys
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request

from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QPlainTextEdit, QPushButton

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.infrastructure.cloud_public import AdvancedClient, EvolutionClient
from firewall_compliance.infrastructure.cloud_vmware import VMwareClient
from firewall_compliance.interfaces.desktop.batch_reports import (
    export_batch_html,
    export_batch_json,
)
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_app import MainWindow
from firewall_compliance.interfaces.desktop.qt_theme import apply_theme


def run_packaged_smoke(output_dir: Path) -> None:
    """Проверить Qt, анализ, SQLite и отчёты без внешнего Python-процесса."""
    output_dir.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    assert isinstance(app, QApplication)
    apply_theme(app)
    source = output_dir / "synthetic-device.txt"
    source.write_text(
        "hostname SYNTHETIC-PACKAGE-SMOKE\n"
        "interface GigabitEthernet0/0\n"
        " nameif outside\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        "!\n"
        "interface GigabitEthernet0/1\n"
        " nameif inside\n"
        " ip address 10.0.0.1 255.255.255.0\n"
        "!\n"
        "! PRIVATE-SOURCE-MARKER-MUST-NOT-PERSIST\n"
        "access-list OUTSIDE extended permit ip any any\n"
        "access-list OUTSIDE extended permit tcp host 10.10.1.10 host 10.10.2.20 eq 443\n"
        "access-list OUTSIDE extended permit tcp host 10.10.1.11 host 10.10.2.21 eq 22\n"
        "access-list OUTSIDE extended permit tcp host 10.10.2.20 host 10.10.3.30 eq 443\n"
        "access-list OUTSIDE extended deny tcp host 10.10.3.30 host 10.10.1.10 eq 22\n"
        "access-group OUTSIDE in interface outside\n"
        "nat (inside,outside) source dynamic any interface\n",
        encoding="utf-8",
    )
    unknown = output_dir / "unsupported.txt"
    unknown.write_text("unsupported synthetic format\n", encoding="utf-8")
    store = ProjectStore(output_dir / "projects.sqlite3")
    window = MainWindow(store=store)
    window.show()

    def until(predicate: Callable[[], bool]) -> None:
        deadline = time.monotonic() + 30
        while not predicate():
            app.processEvents()
            if time.monotonic() > deadline:
                raise TimeoutError("Самопроверка не завершилась вовремя")
            time.sleep(0.01)
        app.processEvents()

    project_id = window.create_project("Синтетическая проверка Windows-сборки")
    cloud = window.cloud_panel
    cloud.site.setText("https://vcd01-01.cloud.ru")
    cloud.tenant.setText("synthetic-tenant")
    cloud.token.setText("SYNTHETIC-CLOUD-API-TOKEN")
    cloud.save()
    assert store.get_vmware_token(project_id) == "SYNTHETIC-CLOUD-API-TOKEN"

    def cloud_transport(request: Request, _timeout: int) -> bytes:
        if request.get_method() == "POST":
            return b'{"access_token":"SYNTHETIC-ACCESS-TOKEN"}'
        assert "/api/query?" in request.full_url
        return (
            b'<QueryResultRecords total="1"><VMRecord name="SYNTHETIC-CLOUD-VM" '
            b'href="https://vcd01-01.cloud.ru/api/vApp/vm-abcd" '
            b'ipAddress="10.10.3.30"/></QueryResultRecords>'
        )

    cloud.client_factory = partial(VMwareClient, transport=cloud_transport)
    cloud.resource_checks["edges"].setChecked(False)
    cloud.resource_checks["networks"].setChecked(False)
    cloud.data_checks["vm_networks"].setChecked(False)
    cloud.start_scan()
    until(lambda: not cloud.busy)
    scan = store.list_cloud_scans(project_id)[0]
    assert scan["state"] == "completed"
    assert len(scan["result"]["records"]) == 1
    assert "SYNTHETIC-CLOUD-API-TOKEN" not in json.dumps(scan)
    assert "SYNTHETIC-ACCESS-TOKEN" not in json.dumps(scan)
    window._configure_cloud()
    app.processEvents()
    window.grab().save(str(output_dir / "qt-cloud-settings.png"))
    window.navigate("scans")
    app.processEvents()
    window.grab().save(str(output_dir / "qt-cloud-scans.png"))
    public_project = "01234567-89ab-cdef-0123-456789abcdef"
    public_item = "11111111-2222-3333-4444-555555555555"

    def public_transport(request: Request, _timeout: int) -> bytes:
        if request.get_method() == "POST":
            return b'{"access_token":"SYNTHETIC-PUBLIC-ACCESS"}'
        path = urlsplit(request.full_url).path
        if "compute.api.cloud.ru" in request.full_url:
            payload = {"items": [{"id": public_item, "name": "SYNTHETIC-EVOLUTION"}], "total": 1}
        else:
            authorization = request.get_header("Authorization")
            assert authorization and authorization.startswith("SDK-HMAC-SHA256")
            if path.endswith(public_item):
                payload = {"security_group": {"security_group_rules": [{"direction": "ingress"}]}}
            else:
                payload = {
                    "security_groups": []
                    if "marker=" in request.full_url
                    else [{"id": public_item, "name": "SYNTHETIC-ADVANCED"}]
                }
        return json.dumps(payload).encode()

    cloud.public_factories = {
        "advanced": partial(AdvancedClient, transport=public_transport),
        "evolution": partial(EvolutionClient, transport=public_transport),
    }
    for index, platform in ((1, "advanced"), (2, "evolution")):
        form = cloud.public_forms[platform]
        form.project.setText(public_project.replace("-", "") if index == 1 else public_project)
        form.access_key.setText("SYNTHETIC-PUBLIC-AK")
        form.secret_key.setText("SYNTHETIC-PUBLIC-SK")
        form.save()
        cloud.source.setCurrentIndex(index)
        for key, check in cloud.resource_checks.items():
            check.setChecked(key == "security_groups")
        cloud.start_scan()
        until(lambda: not cloud.busy)
        public_scan = store.list_cloud_scans(project_id)[0]
        assert public_scan["config"]["platform"] == platform
        assert public_scan["state"] == "completed"
        assert len(public_scan["result"]["records"]) == 1
        assert "SYNTHETIC-PUBLIC-AK" not in json.dumps(public_scan)
        assert "SYNTHETIC-PUBLIC-SK" not in json.dumps(public_scan)
        assert "SYNTHETIC-PUBLIC-ACCESS" not in json.dumps(public_scan)
        window._configure_cloud()
        app.processEvents()
        window.grab().save(str(output_dir / f"qt-{platform}-settings.png"))
        window.navigate("scans")
        app.processEvents()
        window.grab().save(str(output_dir / f"qt-{platform}-scans.png"))
    window.stage_paths([source, unknown])
    until(window.run_button.isEnabled)
    window.start_analysis()

    def finished(candidate: MainWindow = window) -> bool:
        return not candidate._batch_active

    until(finished)
    run_id = window.run_id
    assert run_id is not None
    run = store.get_run(run_id)
    assert len(run["items"]) == 2
    successful = [item for item in run["items"] if item["report"]]
    assert len(successful) == 1
    assert {check["check_id"] for check in successful[0]["report"]["checks"]} == {
        key for key, box in window.check_boxes.items() if box.isChecked()
    }
    finding = next(f for c in successful[0]["report"]["checks"] for f in c["findings"])
    store.set_finding_mark(run_id, finding["finding_id"], "confirmed", "Проверка сохранения")
    export_batch_html(store, run_id, output_dir / "report.html")
    export_batch_json(store, run_id, output_dir / "report.json")
    package = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert package["schema_version"] == "1.0.0"
    assert package["items"][0]["result"] == run["items"][0]["report"]
    assert "INCOMPLETE_PARSE" in (output_dir / "report.html").read_text(encoding="utf-8")
    window.navigate("settings")
    window.settings_nav_buttons["integrations"].click()
    for key in ("usergate", "pt", "ideco"):
        window.integration_pages.setCurrentIndex(0)
        app.processEvents()
        card = window.integration_buttons[key]
        assert card.isEnabled() and card.isVisible()
        assert "Запланировано" in card.text()
        card.click()
        app.processEvents()
        assert window.integration_pages.currentIndex() == window.integration_detail_indices[key]
        detail_page = window.integration_pages.currentWidget()
        assert detail_page is not None
        labels = "\n".join(label.text() for label in detail_page.findChildren(QLabel))
        assert "не реализован" in labels
        assert "недоступны" in labels
        actions = detail_page.findChildren(QPushButton)
        assert len(actions) == 1 and "Все интеграции" in actions[0].text()
    window.navigate("findings")
    window.finding_table.selectRow(0)
    assert window.navigation.topLevelItemCount() == 6
    panel = window.advanced_panel
    panel.refresh_sessions()
    network_source = output_dir / "synthetic-interfaces.txt"
    network_source.write_text(
        "interface GigabitEthernet0/0\n nameif outside\n security-level 0\n"
        " ip address 192.0.2.1 255.255.255.0\n no shutdown\n!\n"
        "interface GigabitEthernet0/1\n nameif inside\n security-level 100\n"
        " ip address 10.0.0.1 255.255.255.0\n no shutdown\n!\n",
        encoding="utf-8",
    )
    panel.network_path.setText(str(network_source.resolve()))
    panel.metadata.setPlainText(
        json.dumps(
            {
                "source_kind": "asa_running_config_interfaces",
                "context_mode": "single",
                "firewall_mode": "routed",
                "declared_version": "9.16(4)",
                "version_provenance": "operator_declared",
                "version_reference": "synthetic smoke",
                "origin": "synthetic",
                "origin_reference": "generated smoke fixture",
                "address_family": "ipv4",
                "table_role": "data",
                "table_id": "default",
                "command": "show running-config interface",
                "encoding": "utf-8",
                "selection": "all",
                "extent": "full",
                "capture_success": True,
                "complete": True,
                "completeness_reference": "generated smoke fixture",
            }
        )
    )
    panel.stage()
    panel.import_network()
    until(lambda: isinstance(panel.current_result, NetworkImportResult))
    window.navigate("map")
    window.map_result_selector.setCurrentIndex(
        window.map_result_selector.findData(str(successful[0]["id"])),
    )
    window.map_attach_network_button.click()
    app.processEvents()
    selected_section = window.navigation.currentItem()
    assert selected_section is not None and selected_section.text(0) == "Сетевая карта"
    assert window.map_mode_selector.currentData() == "project"
    assert window.map_mode_stack.currentWidget() is window.project_map_widget
    project_map = window.project_map_widget
    assert len(project_map.graph.areas) >= 5
    assert len([node for node in project_map.graph.nodes if node.kind == "cloud"]) == 3
    assert all(icon.icon.isValid() for icon in project_map.node_items.values())
    window.resize(1500, 1000)
    app.processEvents()
    project_map.view.fit_map()
    assert window.grab().save(str(output_dir / "qt-project-network-map.png"))
    window.map_mode_selector.setCurrentIndex(1)
    assert window.map_mode_stack.currentWidget() is window.topology_map_widget
    assert not window.map_sources_panel.isVisible()
    topology = window.topology_map_widget
    assert topology.scene.interface_items
    assert topology.scene.attachment_items
    topology.view.fit_map()
    assert window.grab().save(str(output_dir / "qt-network-map.png"))
    topology.search.setText("192.0.2")
    assert len(topology.scene.interface_items) == 1
    topology.search.clear()
    topology.element_selector.setCurrentIndex(2)
    app.processEvents()
    assert topology.details_panel.isVisible()
    assert window.grab().save(str(output_dir / "qt-network-map-properties.png"))
    window.navigate("findings")
    window.navigate("devices")
    assert window.device_model.rowCount() == 4
    assert {
        item.get("platform") for item in window.device_model.payloads if item.get("kind") == "cloud"
    } == {
        "vmware",
        "advanced",
        "evolution",
    }
    assert len(window.history_model.payloads) == 4
    assert window.report_run.currentData() == run_id
    window.resource_kind.setCurrentIndex(window.resource_kind.findData("device"))
    window.device_table.selectRow(0)
    app.processEvents()
    assert window.device_model.columnCount() == 4
    assert "Всего групп:" in window.device_detail.toPlainText()
    assert "Ноль находок не доказывает безопасность" in window.device_detail.toPlainText()
    assert window.import_errors_button.isEnabled()
    assert len(window._import_error_items) == 1
    inspected_text: list[str] = []
    dialog_screenshots: list[bool] = []

    def inspect_limitations_dialog() -> None:
        dialog = app.activeModalWidget()
        if isinstance(dialog, QDialog):
            inspected_text.extend(
                editor.toPlainText() for editor in dialog.findChildren(QPlainTextEdit)
            )
            dialog_screenshots.append(
                dialog.grab().save(str(output_dir / "qt-r1-full-limitations.png"))
            )
            dialog.reject()

    QTimer.singleShot(0, inspect_limitations_dialog)
    window.resource_details.show_item_limitations(successful[0])
    assert len(inspected_text) == 1
    assert dialog_screenshots == [True]
    assert "INCOMPLETE_PARSE" in inspected_text[0]
    assert "raw_records" in inspected_text[0]
    assert "source_location" in inspected_text[0]
    window.grab().save(str(output_dir / "qt-r1-device-details.png"))
    window.resource_details.open_findings()
    assert window.current_section_id == "findings"
    window.workspace_history.back()
    assert window.current_section_id == "devices"
    window.navigate("findings")
    window.finding_table.selectRow(0)
    app.processEvents()
    window.grab().save(str(output_dir / "qt-findings.png"))
    window.close()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()
    restored = ProjectStore(output_dir / "projects.sqlite3")
    restored_run = restored.get_run(run_id)
    assert restored_run["marks"][finding["finding_id"]]["status"] == "confirmed"
    assert "PRIVATE-SOURCE-MARKER" not in json.dumps(restored_run, ensure_ascii=False)
    assert (
        restored.attach_source(successful[0]["id"], source).report.model_dump(mode="json")
        == successful[0]["report"]
    )
    source.write_text(source.read_text(encoding="utf-8") + "! changed\n", encoding="utf-8")
    try:
        restored.attach_source(successful[0]["id"], source)
    except ValueError:
        pass
    else:
        raise AssertionError("Изменённый исходник был принят")
    reopened = MainWindow(store=restored)
    assert reopened.project_id == project_id
    assert reopened.run_id == run_id
    reopened.close()
    reopened.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    del reopened, window
    gc.collect()
    app.processEvents()
    (output_dir / "smoke-result.json").write_text(
        json.dumps(
            {
                "passed": True,
                "frozen": bool(getattr(sys, "frozen", False)),
                "executable": sys.executable,
                "files": 2,
                "checks": len(successful[0]["report"]["checks"]),
                "history_restored": True,
                "modified_source_rejected": True,
                "cloud_vmware_synthetic_scan": True,
                "cloud_credentials_protected": True,
                "cloud_advanced_synthetic_scan": True,
                "cloud_evolution_synthetic_scan": True,
                "workspace_six_sections": True,
                "network_map_topology_search_properties": True,
                "project_map_icons_regions_acl": True,
                "workspace_mixed_inventory": True,
                "workspace_linked_navigation": True,
                "r1_grouped_device_details_and_full_provenance": True,
                "r1_json_schema_unchanged": True,
                "r1_failed_import_record_retained": True,
                "r1_ngfw_visible_and_honestly_planned": True,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
