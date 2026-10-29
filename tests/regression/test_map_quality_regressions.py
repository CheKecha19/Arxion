"""Synthetic regressions for strict map adapters and optional Qt scene state."""

from datetime import UTC, datetime

import pytest
from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication

from firewall_compliance.domain.configuration import Configuration, Device, Rule
from firewall_compliance.domain.enums import DataOrigin, DataStatus, RuleAction, SourceDocumentKind
from firewall_compliance.domain.parse_result import ParseCoverage, ParseResult
from firewall_compliance.domain.reachability import ReachabilityQuery
from firewall_compliance.domain.revision import DeviceRevision, Interface, RevisionSource
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.interfaces.desktop.network_backend import ForwardingQueryResult
from firewall_compliance.interfaces.desktop.qt_acl_map import (
    AclMapScene,
    AclMapView,
    build_map_state,
)
from firewall_compliance.interfaces.desktop.topology_map import (
    build_topology_projection,
    build_topology_trace,
)

NOW = datetime(2026, 10, 26, tzinfo=UTC)
QT_APP: QApplication | None = None


@pytest.fixture
def revision():
    configuration = Configuration(
        source_name="synthetic.cfg",
        device_id="synthetic-map-device",
        vendor="synthetic",
        platform="synthetic",
        parser_version="1.0.0",
        content_sha256="a" * 64,
        captured_at=NOW,
        imported_at=NOW,
    )
    rules = tuple(
        Rule(
            rule_id=f"rule-{index}",
            configuration_id=configuration.configuration_id,
            name=f"Synthetic {direction}",
            sequence=index,
            action=RuleAction.UNKNOWN if index == 0 else RuleAction.DENY,
            enabled=index != 2,
            policy_id="synthetic-policy",
            policy_direction=direction,
            source_status=DataStatus.UNKNOWN,
            destination_status=DataStatus.UNKNOWN,
            service_status=DataStatus.UNKNOWN,
            source_location=SourceLocation(source_name="synthetic.cfg", line_start=index + 1),
        )
        for index, direction in enumerate((None, "in", "out"))
    )
    return DeviceRevision(
        device=Device(device_id=configuration.device_id, vendor="synthetic", platform="synthetic"),
        parse_result=ParseResult(
            configuration=configuration,
            rules=rules,
            coverage=ParseCoverage(
                discovered_constructs=3, recognized_constructs=3, unsupported_constructs=0
            ),
            source_map={rule.rule_id: rule.source_location for rule in rules},
        ),
        sources=(
            RevisionSource(
                source_name=configuration.source_name,
                content_sha256=configuration.content_sha256,
                kind=SourceDocumentKind.CONFIGURATION,
                captured_at=NOW,
            ),
        ),
        application_version="0.3.0",
        imported_at=NOW,
        interfaces=(
            Interface(
                device_id=configuration.device_id,
                interface_id="manual-interface",
                name="Synthetic interface",
                origin=DataOrigin.MANUAL,
                data_status=DataStatus.UNKNOWN,
                addresses=("192.0.2.1/24",),
                addresses_status=DataStatus.UNKNOWN,
                manual_reason="Synthetic operator statement",
                recorded_at=NOW,
            ),
        ),
    )


@pytest.mark.parametrize(
    ("payload", "status"),
    [
        ({"report": {"device_id": "synthetic"}}, "unsupported"),
        ({"revision": {"schema_version": "future"}}, "unsupported"),
        ({"revision": {"revision_id": "not-a-durable-id"}}, "invalid"),
    ],
)
def test_saved_map_never_substitutes_report_or_invents_revision(payload, status):
    result = build_map_state(payload, built_at=NOW)
    assert result.status == status
    assert result.graph is None and result.revision is None


def test_saved_partial_map_preserves_original_identity_and_unknown_rules(revision):
    current = build_map_state(revision, built_at=NOW)
    saved = build_map_state({"revision": revision.model_dump(mode="json")}, built_at=NOW)
    assert current.status == saved.status == "partial"
    assert current.graph == saved.graph
    assert saved.revision.revision_id == revision.revision_id
    assert saved.revision.sources == revision.sources
    assert [relation.rule.enabled for relation in saved.graph.relations] == [True, True, False]
    assert saved.graph.relations[0].rule.action == RuleAction.UNKNOWN
    assert all(relation.condition_status == "unknown" for relation in saved.graph.relations)


def test_topology_interface_without_document_remains_explicitly_unknown(revision):
    projection = build_topology_projection(revision)
    interface = projection.interfaces[0]
    assert interface.document is None and interface.source is None
    assert interface.table_id is None and interface.vrf_id is None
    assert interface.operational_state == "unknown"
    assert interface.attachments[0].cidr == "192.0.2.0/24"
    assert interface.attachments[0].address_status == DataStatus.UNKNOWN
    assert interface.fact.interface_id == revision.interfaces[0].interface_id


def test_dynamic_unsupported_trace_clears_every_overlay_reference(revision):
    projection = build_topology_projection(revision)
    trace = build_topology_trace(object(), projection)
    assert trace.status == "unsupported"
    assert trace.query is None and trace.context is None
    assert trace.ingress is None and trace.egress is None and not trace.stages
    assert trace.reasons[0].code == "trace_contract_unsupported"
    assert "physical_transition_unknown" in trace.unknown_boundaries


def test_missing_evaluation_stays_unavailable_without_invented_path(revision):
    query = ReachabilityQuery(
        revision_id=revision.revision_id,
        device_id=revision.device.device_id,
        ingress_interface_id="manual-interface",
        source_ip="192.0.2.1",
        destination_ip="198.51.100.1",
        protocol="tcp",
        destination_port=443,
    )
    result = ForwardingQueryResult(
        query=query,
        profile_id=None,
        ingress_interface_id=None,
        egress_interface_id=None,
        status="not_enough_evidence",
        binding=None,
        evaluation=None,
        reasons=(),
    )
    trace = build_topology_trace(result, build_topology_projection(revision))
    assert trace.status == "unavailable" and trace.query == query
    assert trace.overall_status == "not_enough_evidence"
    assert trace.reasons[0].code == "trace_unavailable"
    assert not trace.stages and not trace.physical_transitions


def test_qt_lanes_and_canvas_gestures_preserve_unknown_partial_state(revision):
    global QT_APP
    QT_APP = QApplication.instance() or QApplication([])
    scene = AclMapScene()
    view = AclMapView(scene)
    try:
        state = build_map_state(revision, built_at=NOW)
        scene.set_map_state(state)
        assert scene.render_status == "partial"
        assert len(scene.relation_items) == 3
        assert len(scene.node_items) == 9
        before = view.transform()
        view.keyPressEvent(
            QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Plus, Qt.KeyboardModifier.ControlModifier)
        )
        assert view.transform() == before
        view.keyPressEvent(
            QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Plus, Qt.KeyboardModifier.ShiftModifier)
        )
        assert view.transform().m11() > before.m11()
        view.setScene(None)
        before = view.transform()
        view.fit_map()
        assert view.transform() == before
        assert state.revision == revision
    finally:
        view.close()
