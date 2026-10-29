"""Native exposure policy preserves explicit unknown/empty and stable selector IDs."""

from copy import deepcopy

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QSignalSpy
from PySide6.QtWidgets import QApplication

from firewall_compliance.interfaces.desktop.policy_exposure_settings import PolicyExposureSettings

APP = None


@pytest.fixture
def settings():
    global APP
    APP = QApplication.instance() or QApplication([])
    widget = PolicyExposureSettings()
    try:
        yield widget
    finally:
        widget.close()


def service(catalogue, *, name="Organization SSH", protocol="tcp", ports="22"):
    catalogue.declared.setChecked(True)
    catalogue.add_service()
    row = catalogue.table.rowCount() - 1
    catalogue.table.item(row, 0).setText(name)
    combo = catalogue.table.cellWidget(row, 1)
    combo.setCurrentIndex(combo.findData(protocol))
    catalogue.table.item(row, 2).setText(ports)
    return catalogue.table.item(row, 0).data(Qt.ItemDataRole.UserRole)


def test_unknown_defaults_and_explicit_empty_have_distinct_payloads(settings):
    profile = settings.profile()
    assert profile.dangerous_services is None
    assert profile.administrative_services is None
    assert profile.administrative_targets is None
    assert profile.trusted_admin_networks is None
    for catalogue in settings.catalogues.values():
        catalogue.declared.setChecked(True)
    for field in settings.fields.values():
        field.setText("[]")
    profile = settings.profile()
    assert profile.dangerous_services == () and profile.administrative_services == ()
    assert profile.administrative_targets == () and profile.trusted_admin_networks == ()
    settings.load_profile(profile.model_dump(mode="json"))
    assert settings.profile() == profile


def test_catalogue_roundtrip_keeps_ids_name_ports_and_normalized_networks(settings):
    dangerous = settings.catalogues["dangerous_services"]
    original_id = service(dangerous, name="Organization custom TCP", ports="23, 8000-8010")
    service(
        settings.catalogues["administrative_services"],
        name="Ping policy",
        protocol="icmp",
        ports="",
    )
    settings.fields["administrative_targets"].setText("192.0.2.12/24, 2001:db8::1/64")
    settings.fields["trusted_admin_networks"].setText("10.0.0.1/24, 10.0.0.2/24")
    profile = settings.profile()
    payload = profile.model_dump(mode="json")
    assert profile.dangerous_services[0].selector_id == original_id
    assert profile.dangerous_services[0].port_ranges[1].end == 8010
    assert profile.administrative_targets == ("192.0.2.0/24", "2001:db8::/64")
    assert profile.trusted_admin_networks == ("10.0.0.0/24",)
    original = deepcopy(payload)
    settings.load_profile(payload)
    assert payload == original and settings.profile() == profile
    dangerous.table.item(0, 0).setText("Renamed")
    assert settings.profile().dangerous_services[0].selector_id == original_id


@pytest.mark.parametrize(
    "protocol,ports",
    [
        ("tcp", ""),
        ("icmp", "22"),
        ("udp", "65536"),
        ("tcp", "90-20"),
        ("tcp", "22,,23"),
        ("tcp", "not-a-port"),
    ],
)
def test_bad_ports_protocol_show_row_error_without_saving(settings, protocol, ports):
    service(settings.catalogues["dangerous_services"], protocol=protocol, ports=ports)
    with pytest.raises(ValueError, match="строка 1"):
        settings.profile()
    assert "строка 1" in settings.error.text()


def test_no_blank_names_or_unselected_protocol(settings):
    catalogue = settings.catalogues["dangerous_services"]
    service(catalogue, name="")
    with pytest.raises(ValueError):
        settings.profile()
    catalogue.table.item(0, 0).setText("Valid")
    catalogue.table.cellWidget(0, 1).setCurrentIndex(0)
    with pytest.raises(ValueError):
        settings.profile()


def test_unknown_catalogue_ignores_disabled_draft_but_keeps_it_for_editing(settings):
    catalogue = settings.catalogues["dangerous_services"]
    selector_id = service(catalogue)
    catalogue.declared.setChecked(False)
    assert settings.profile().dangerous_services is None
    catalogue.declared.setChecked(True)
    assert settings.profile().dangerous_services[0].selector_id == selector_id
    catalogue.table.selectRow(0)
    catalogue.remove_selected()
    assert settings.profile().dangerous_services == ()


def test_load_is_silent_and_preserves_organization_profile_identity(settings):
    changed = QSignalSpy(settings.changed)
    settings.load_profile(
        {
            "profile_id": "organization-specific",
            "version": "2026-10",
            "dangerous_services": [
                {
                    "selector_id": "permanent-id",
                    "name": "Legacy SSH",
                    "protocol": "tcp",
                    "port_ranges": [{"start": 22, "end": 22}],
                }
            ],
            "trusted_admin_networks": [],
        }
    )
    assert changed.count() == 0
    profile = settings.profile()
    assert profile.profile_id == "organization-specific" and profile.version == "2026-10"
    assert profile.dangerous_services[0].selector_id == "permanent-id"
    catalogue = settings.catalogues["dangerous_services"]
    catalogue.table.item(0, 0).setText("New name")
    assert changed.count() > 0
    settings.load_profile(None)
    assert settings.profile().dangerous_services is None
    assert settings.profile().trusted_admin_networks is None


def test_invalid_cidr_keeps_input_and_reports_error(settings):
    settings.fields["administrative_targets"].setText("synthetic-invalid-cidr")
    with pytest.raises(ValueError, match="CIDR"):
        settings.profile()
    assert settings.fields["administrative_targets"].text() == "synthetic-invalid-cidr"
