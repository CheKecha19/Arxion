"""Real Qt settings and project persistence for management requirements."""

import os
from pathlib import Path

import pytest


def test_management_settings_roundtrip_and_validation(tmp_path: Path) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QApplication, QWidget

    from firewall_compliance.interfaces.desktop.project_store import ProjectStore
    from firewall_compliance.interfaces.desktop.qt_app import MainWindow

    app = QApplication.instance() or QApplication([])
    store = ProjectStore(tmp_path / "settings.sqlite3")
    window = MainWindow(store, advanced_widget_factory=lambda _sessions, _runner: QWidget())
    try:
        project = window.create_project("Management requirements")
        settings = window.management_settings
        settings.fields["approved_admin_networks"].setText("192.0.2.0/24, 2001:db8::/32")
        settings.fields["approved_snmp_networks"].setText("[]")
        settings.fields["approved_ntp_servers"].setText("NTP.EXAMPLE.")
        settings.timeout.setValue(600)
        settings.complete.setChecked(True)
        window._save_analysis_settings()
        saved = store.get_project(project)["settings"]["management_profile"]
        assert saved["approved_admin_networks"] == ["192.0.2.0/24", "2001:db8::/32"]
        assert saved["approved_snmp_networks"] == []
        assert saved["approved_ntp_servers"] == ["ntp.example"]
        assert len(window.check_boxes) == 25
        assert {"FW-EXCESSIVE-ACCESS", "FW-ACL-ATTACHMENT"} <= window.check_boxes.keys()
        assert {key for key in window.check_boxes if key.startswith("FW-")} == {
            "FW-ANY-ANY",
            "FW-DUPLICATE",
            "FW-SHADOWED",
            "FW-MERGE-CANDIDATE",
            "FW-LOGGING",
            "FW-COMMENTS",
            "FW-DISABLED",
            "FW-PARTIAL-SHADOWED",
            "FW-UNION-SHADOWED",
            "FW-DANGEROUS-SERVICES",
            "FW-ADMIN-UNTRUSTED",
            "FW-EXCESSIVE-ACCESS",
            "FW-ACL-ATTACHMENT",
        }
        assert len([key for key in window.check_boxes if key.startswith("MGMT-")]) == 12
        assert set(store.get_project(project)["settings"]["enabled_check_ids"]) == {
            key for key, checkbox in window.check_boxes.items() if checkbox.isChecked()
        }
        assert not window.check_boxes["FW-EXCESSIVE-ACCESS"].isChecked()
        assert not window.check_boxes["FW-ACL-ATTACHMENT"].isChecked()
        settings.load_profile(saved)
        assert settings.profile().model_dump(mode="json") == saved
        assert not settings.complete.isChecked()
        settings.fields["approved_admin_networks"].setText("192.0.2.9/24")
        with pytest.raises(ValueError):
            settings.profile()
        window._save_analysis_settings()
        assert store.get_project(project)["settings"]["management_profile"] == saved
        assert settings.error.text()
    finally:
        window.close()
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()
