"""Topology presentation, filtering and viewport retention."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any

import pytest
from tests.revision_fixtures import make_revision


@pytest.fixture
def topology_widget() -> Any:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from firewall_compliance.interfaces.desktop.qt_topology_map import TopologyMapWidget
    from firewall_compliance.interfaces.desktop.topology_map import build_topology_projection

    app = QApplication.instance() or QApplication([])
    widget = TopologyMapWidget()
    widget.resize(1200, 720)
    widget.show()
    widget.set_projection(build_topology_projection(make_revision()))
    app.processEvents()
    yield widget
    widget.close()
    widget.deleteLater()
    app.processEvents()


def test_interfaces_belong_to_device_and_links_follow_container(topology_widget: Any) -> None:
    widget = topology_widget
    device = widget.scene.device_item
    interface = next(iter(widget.scene.interface_items.values()))
    link = widget.scene.attachment_items[0]
    assert interface.parentItem() is device
    assert device.card_rect.contains(interface.mapRectToParent(interface.boundingRect()))
    start = link._path.pointAtPercent(0)
    device.setPos(90, 40)
    moved = link._path.pointAtPercent(0)
    assert moved.x() == pytest.approx(start.x() + 90)
    assert moved.y() == pytest.approx(start.y() + 40)


def test_filter_keeps_full_facts_and_properties_available(topology_widget: Any) -> None:
    widget = topology_widget
    projection = widget.projection
    entries = widget.element_selector.count()
    widget.search.setText("no-such-interface")
    assert not widget.scene.interface_items
    assert widget.projection is projection
    assert widget.element_selector.count() == entries
    widget.search.clear()
    assert widget.scene.interface_items
    widget.interface_filter.setCurrentIndex(2)
    assert not widget.scene.interface_items
    widget.interface_filter.setCurrentIndex(1)
    assert widget.scene.interface_items
    assert not widget.details_panel.isVisible()
    widget.element_selector.setCurrentIndex(2)
    assert widget.details_panel.isVisible()
    assert "Interface ID:" in widget.details.toPlainText()


def test_same_projection_retains_zoom_and_layout(topology_widget: Any) -> None:
    widget = topology_widget
    device = widget.scene.device_item
    device.setPos(90, 40)
    widget.view.zoom_in()
    transform = widget.view.transform()
    widget.set_projection(replace(widget.projection))
    assert widget.scene.device_item is device
    assert widget.view.transform() == transform
    assert device.pos().x() == 90


def test_search_can_narrow_projection_over_render_limit(topology_widget: Any) -> None:
    widget = topology_widget
    interface = widget.projection.interfaces[0]
    interfaces = tuple(
        replace(interface, interface_id=f"port:{i}", label=f"port:{i}", attachments=())
        for i in range(1201)
    )
    widget.set_projection(replace(widget.projection, interfaces=interfaces))
    assert widget.scene.render_status == "limited"
    widget.search.setText("port:1200")
    assert widget.scene.render_status == "recorded"
    assert len(widget.scene.interface_items) == 1
    assert len(widget.projection.interfaces) == 1201
