"""Synthetic native forms preserve explicit evidence and original backend contracts."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from PySide6.QtTest import QSignalSpy
from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QLineEdit

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.forwarding import ForwardingSource
from firewall_compliance.domain.observation import ObservationEvidence, ObservationWindow
from firewall_compliance.domain.policy_decision import PolicyBindingEvidence
from firewall_compliance.interfaces.desktop.jobs import JobRunner
from firewall_compliance.interfaces.desktop.network_backend import (
    NetworkDocumentDraft,
    import_documents,
    parse_forwarding,
)
from firewall_compliance.interfaces.desktop.qt_network import NetworkWidget
from firewall_compliance.interfaces.desktop.qt_network_forms import NetworkContractForm
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseResult
from tests.regression.synthetic_network_inputs import INTERFACES, make_document, make_network_base

APP = None


@pytest.fixture(autouse=True)
def app():
    global APP
    APP = QApplication.instance() or QApplication([])
    return APP


def fill(form, **values):
    for key, value in values.items():
        field = form.fields[key]
        if isinstance(field, QCheckBox):
            field.setChecked(value)
        elif isinstance(field, QComboBox):
            index = field.findData(value)
            assert index >= 0, (key, value)
            field.setCurrentIndex(index)
        else:
            assert isinstance(field, QLineEdit)
            field.setText(str(value) if value is not None else "")


def metadata():
    base = make_network_base(observed=False)
    request = make_document(base, INTERFACES, "asa_running_config_interfaces", complete=False)
    value = request.metadata.model_dump(mode="json")
    for key in ("source_document_id", "content_sha256", "device_id"):
        value.pop(key)
    value.update(
        selection="authored_excerpt",
        extent="excerpt",
        capture_success=False,
        complete=False,
        completeness_reference=None,
    )
    return value


def test_unknown_observation_and_interval_have_no_default_time():
    for kind in ("observation", "window", "profile"):
        form = NetworkContractForm(kind)
        assert form.values() == {}
        assert not form.form_widget.isEnabled()
        for key in ("observed_at", "start", "end"):
            if key in form.fields:
                assert form.fields[key].text() == ""


def test_observation_requires_explicit_timezone_and_reference_and_preserves_dto():
    form = NetworkContractForm("observation")
    changed = QSignalSpy(form.textChanged)
    form.declared.setChecked(True)
    fill(
        form, observed_at="2026-10-01T10:00:00", method="synthetic", reference="Author declaration"
    )
    with pytest.raises(ValueError, match="часовой пояс"):
        form.values()
    assert "часовой пояс" in form.error.text()
    fill(form, observed_at="2026-10-01T10:00:00+03:00")
    value = form.values()
    assert (
        ObservationEvidence.model_validate(value).observed_at.utcoffset().total_seconds() == 10800
    )
    assert changed.count() > 0
    form.declared.setChecked(False)
    assert form.values() == {}


def test_window_rejects_reversed_interval():
    form = NetworkContractForm("window")
    form.declared.setChecked(True)
    fill(form, start="2026-10-02T00:00:00Z", end="2026-10-01T00:00:00Z", reason="Synthetic")
    with pytest.raises(ValueError, match="порядок"):
        form.values()
    fill(form, end="2026-10-03T00:00:00Z")
    assert ObservationWindow.model_validate(form.values()).reason == "Synthetic"


def test_typed_metadata_roundtrip_import_preserves_unknown_completeness_and_time():
    form = NetworkContractForm("metadata", metadata())
    assert "source_document_id" not in form.fields
    assert "content_sha256" not in form.fields
    root = Path("artifacts/network-forms-tests")
    root.mkdir(parents=True, exist_ok=True)
    source = root / f"{uuid4()}.cfg"
    source.write_text(INTERFACES, encoding="utf-8")
    base = make_network_base(observed=False)
    before = base.model_dump(mode="json")
    result = import_documents(base, (NetworkDocumentDraft(source, form.values()),))
    assert isinstance(result, NetworkImportResult)
    assert len(result.documents) == 1 and len(result.revision.interfaces) == 2
    assert result.documents[0].status == DataStatus.UNKNOWN
    assert result.documents[0].source.observation is None
    assert result.revision.observed_at is None
    assert base.model_dump(mode="json") == before


def test_completeness_and_command_are_operator_actions():
    form = NetworkContractForm("metadata", metadata())
    fill(form, command="", complete=True)
    with pytest.raises(ValueError):
        form.values()
    form._command()
    assert form.fields["command"].text() == "show running-config interface"
    with pytest.raises(ValueError, match="Полнота требует"):
        form.values()
    fill(form, complete=False)
    assert form.values()["capture_success"] is False
    fill(form, context="not-single")
    with pytest.raises(ValueError, match="single"):
        form.values()


def test_binding_form_keeps_source_mapping_and_conservative_defaults():
    form = NetworkContractForm(
        "binding",
        {
            "direction": "in",
            "declaration_origin": "synthetic",
            "implicit_action": "unknown",
            "coordinate_space": "acl_input",
            "complete": False,
            "terminal": False,
        },
    )
    fill(
        form,
        policy_id="INSIDE",
        interface_id="interface:Gi0/1",
        interface_label="inside",
        interface_mapping_reference="Synthetic nameif",
        source_document_id=str(uuid4()),
    )
    fill(
        form,
        **{"binding_location.source_name": "synthetic.cfg", "binding_location.line_start": "12"},
    )
    value = form.values()
    binding = PolicyBindingEvidence.model_validate(value)
    assert binding.binding_location.line_start == 12
    assert not binding.complete and not binding.terminal and binding.implicit_action == "unknown"
    fill(form, terminal=True)
    with pytest.raises(ValueError, match="основания"):
        form.values()
    fill(form, terminal_reference="Synthetic terminal claim")
    assert form.values()["terminal"] is True
    fill(form, **{"binding_location.line_start": "none"})
    with pytest.raises(ValueError, match="целое число"):
        form.values()


def test_raw_fallback_roundtrip_signal_and_invalid_json_do_not_discard_edits():
    form = NetworkContractForm("metadata", metadata())
    changed = QSignalSpy(form.textChanged)
    payload = {**metadata(), "origin_reference": "Edited through JSON"}
    form.setPlainText(json.dumps(payload))
    assert form.values() == payload and changed.count() > 0
    form.raw_group.setChecked(False)
    assert form.values() == payload
    assert form.fields["origin_reference"].text() == "Edited through JSON"
    form.setPlainText("{")
    with pytest.raises(ValueError, match="JSON"):
        form.values()
    form.raw_group.setChecked(False)
    assert form.raw_group.isChecked() and form.toPlainText() == "{"


def test_network_widget_uses_native_forms_and_keeps_invalidation_hook():
    runner = JobRunner()
    widget = NetworkWidget(lambda: (), runner)
    try:
        assert isinstance(widget.metadata, NetworkContractForm)
        assert isinstance(widget.binding, NetworkContractForm)
        assert isinstance(widget.forward_metadata, NetworkContractForm)
        assert widget.observation.values() == {}
        generation = widget._query_generation
        fill(widget.binding, policy_id="Changed")
        assert widget._query_generation > generation
    finally:
        widget.close()
        runner.shutdown()


def test_forwarding_profile_unknown_then_explicit_and_missing_reason():
    form = NetworkContractForm("profile")
    assert form.values() == {}
    form.declared.setChecked(True)
    fill(
        form,
        context_mode="single",
        firewall_mode="routed",
        address_family="ipv4",
        table_role="data",
        table_id="default",
    )
    with pytest.raises(ValueError, match="основание"):
        form.values()
    fill(form, profile_reference="Synthetic declared profile")
    assert form.values()["context_mode"] == "single"


def test_typed_forwarding_metadata_roundtrip_retains_unknown_observation():
    defaults = {
        key: value for key, value in metadata().items() if key in ForwardingSource.model_fields
    }
    defaults.update(purpose="configuration", command="show running-config", complete_scopes=[])
    form = NetworkContractForm("forward_metadata", defaults)
    assert "source_document_id" not in form.fields
    root = Path("artifacts/network-forms-tests")
    root.mkdir(parents=True, exist_ok=True)
    source = root / f"{uuid4()}.cfg"
    source.write_text("ASA Version 9.16(4)\n" + INTERFACES, encoding="utf-8")
    result = parse_forwarding(
        make_network_base(observed=False), NetworkDocumentDraft(source, form.values()), {}
    )
    assert isinstance(result, ForwardingParseResult)
    assert result.context.sources[0].observation is None
    assert not result.context.sources[0].complete_scopes
    form.scope_checks["interfaces"].setChecked(True)
    with pytest.raises(ValueError, match="Полнота требует"):
        form.values()


def test_empty_raw_metadata_can_return_to_editable_native_fields():
    form = NetworkContractForm("metadata", metadata())
    form.setPlainText("{}")
    form.raw_group.setChecked(False)
    assert form.form_widget.isEnabled()
    fill(form, origin_reference="Operator can correct an empty raw input")
    assert form.fields["origin_reference"].text() == "Operator can correct an empty raw input"
