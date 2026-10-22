"""Interaction tests for icons, crossings, zones and scoped presentation state."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any

import pytest

from firewall_compliance.interfaces.desktop.project_map import (
    ProjectMap,
    ProjectMapEdge,
    ProjectMapNode,
)


@pytest.fixture
def project_widget() -> Any:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from firewall_compliance.interfaces.desktop.qt_project_map import ProjectMapWidget

    app = QApplication.instance() or QApplication([])
    widget = ProjectMapWidget()
    widget.resize(1100, 750)
    nodes = tuple(
        ProjectMapNode(str(i), f"Host {i}", "monitor", "contour", "10.0.1.0/24") for i in range(4)
    )
    graph = ProjectMap(
        "p",
        nodes,
        (ProjectMapEdge("0", "3", "acl", "allow"), ProjectMapEdge("1", "2", "acl", "allow")),
        {"contour": "Внутренний контур"},
    )
    widget.set_graph(graph, {})
    widget.show()
    app.processEvents()
    yield widget, app
    widget.close()
    widget.deleteLater()
    app.processEvents()


def test_icons_and_bridge_are_rendered_and_edge_selection_shows_properties(
    project_widget: Any,
) -> None:
    widget, app = project_widget
    assert all(icon.icon.isValid() for icon in widget.node_items.values())
    assert len(widget.edge_items) == 2
    assert widget.edge_items[0].path().elementCount() == 2
    assert widget.edge_items[1].path().elementCount() > 2
    widget.edge_items[1].setSelected(True)
    app.processEvents()
    assert widget.details.isVisible()
    assert "Связь по условиям ACL" in widget.details.toPlainText()
    widget.scene.clearSelection()
    assert all(item.opacity() == 1 for item in widget.node_items.values())


def test_zone_double_click_collapses_without_losing_graph(project_widget: Any) -> None:
    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtTest import QTest

    widget, app = project_widget
    key = next(iter(widget.zone_items))
    region = widget.zone_items[key]
    position = widget.view.mapFromScene(region.rect.topLeft() + QPointF(30, 18))
    QTest.mouseDClick(widget.view.viewport(), Qt.MouseButton.LeftButton, pos=position)
    app.processEvents()
    assert key in widget.collapsed
    assert len(widget.node_items) == 1
    assert len(widget.graph.nodes) == 4
    widget._toggle_zone(key)
    assert len(widget.node_items) == 4


def test_renaming_and_project_switch_keep_labels_scoped(project_widget: Any) -> None:
    widget, _app = project_widget
    key = next(iter(widget.zone_items))
    saved = []
    widget.labels_changed.connect(saved.append)
    widget.rename_zone(key, "Серверы приложений")
    assert saved == [{key: "Серверы приложений"}]
    assert "Серверы приложений" in widget.zone_items[key].title
    widget.search.setText("Серверы приложений")
    assert len(widget.node_items) == 4
    widget.set_graph(replace(widget.graph, project_id="another"), {})
    assert not widget.zone_labels
    assert not widget.search.text()
    assert "Серверы приложений" not in widget.zone_items[key].title


def test_opposing_actions_share_one_line_without_losing_rule_information(
    project_widget: Any,
) -> None:
    widget, _app = project_widget
    graph = replace(
        widget.graph,
        edges=(ProjectMapEdge("0", "3", "acl", "allow"), ProjectMapEdge("0", "3", "acl", "deny")),
    )
    widget.set_graph(graph, {})
    assert len(widget.edge_items) == 1
    assert widget.edge_items[0].edge.action == "mixed"
    widget.edge_filter.setCurrentIndex(1)
    assert len(widget.edge_items) == 1
    assert widget.edge_items[0].edge.action == "allow"


def test_unchanged_graph_preserves_zoom(project_widget: Any) -> None:
    widget, _app = project_widget
    widget.view.zoom_in()
    transform = widget.view.transform()
    widget.set_graph(replace(widget.graph), dict(widget.zone_labels))
    assert widget.view.transform() == transform


def test_display_budget_keeps_full_graph_and_reports_limit(project_widget: Any) -> None:
    widget, _app = project_widget
    widget.MAX_DISPLAY_EDGES = 1
    widget._render()
    assert len(widget.edge_items) == 1
    assert len(widget.graph.edges) == 2
    assert "Лимит линий: 1/2" in widget.status.text()
