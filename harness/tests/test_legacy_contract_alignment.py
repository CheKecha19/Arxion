"""Settings changes reach persistence handlers for typed Qt control signals."""

import pytest
from PySide6.QtTest import QSignalSpy
from PySide6.QtWidgets import QApplication

from firewall_compliance.interfaces.desktop.management_settings import ManagementSettings

APP = None


@pytest.mark.parametrize("control", ["timeout", "allow_snmp_write", "require_ntp"])
def test_management_control_changes_emit_parameterless_settings_notification(control):
    global APP
    APP = QApplication.instance() or QApplication([])
    widget = ManagementSettings()
    changed = QSignalSpy(widget.changed)
    try:
        if control == "timeout":
            widget.timeout.setValue(widget.timeout.value() + 1)
        else:
            widget.options[control].toggle()

        assert changed.count() == 1
    finally:
        widget.close()
