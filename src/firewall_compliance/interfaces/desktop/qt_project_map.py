"""Icon-based project map with nested regions, named zones and line bridges."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from math import ceil, hypot, sqrt
from pathlib import Path

from PySide6.QtCore import QByteArray, QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPainterPathStroker, QPen, QPolygonF
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsSceneMouseEvent,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStyleOptionGraphicsItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.map_geometry import bridge_positions
from firewall_compliance.interfaces.desktop.project_map import (
    CONTOUR,
    EXTERNAL,
    ProjectMap,
    ProjectMapEdge,
    ProjectMapNode,
    identity,
)
from firewall_compliance.interfaces.desktop.qt_acl_map import AclMapView
from firewall_compliance.interfaces.desktop.qt_theme import COLORS

ICON_DIR = Path(__file__).parent / "assets" / "map_icons"
ZONE_COLORS = ("#7DD3FC", "#C4B5FD", "#5EEAD4", "#FCD34D", "#FDA4AF", "#A5B4FC")


class MapRegionItem(QGraphicsObject):
    activated = Signal(str)

    def __init__(self, key: str, rect: QRectF, title: str, color: str, *, zone: bool) -> None:
        super().__init__()
        self.key, self.rect, self.title, self.color, self.zone = key, rect, title, color, zone
        self.setZValue(-3 if zone else -5)
        self.setToolTip(title + ("\nДвойной щелчок: свернуть / развернуть зону" if zone else ""))

    def boundingRect(self) -> QRectF:
        return self.rect.adjusted(-2, -2, 2, 2)

    def paint(
        self, painter: QPainter, option: QStyleOptionGraphicsItem, widget: QWidget | None = None
    ) -> None:
        color = QColor(self.color)
        painter.setPen(
            QPen(color, 1.3, Qt.PenStyle.DashLine if self.zone else Qt.PenStyle.SolidLine)
        )
        fill = QColor(self.color)
        fill.setAlpha(10 if self.zone else 7)
        painter.setBrush(fill)
        painter.drawRoundedRect(self.rect, 16, 16)
        painter.setPen(color)
        font = painter.font()
        font.setPointSize(12 if self.zone else 14)
        font.setBold(True)
        painter.setFont(font)
        text = painter.fontMetrics().elidedText(
            self.title, Qt.TextElideMode.ElideRight, int(self.rect.width()) - 32
        )
        painter.drawText(self.rect.adjusted(16, 10, -16, 0), Qt.AlignmentFlag.AlignTop, text)

    def mouseDoubleClickEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        if self.zone:
            self.activated.emit(self.key)
            event.accept()
        else:
            super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        if self.zone:
            event.accept()
        else:
            super().mousePressEvent(event)


class ProjectIconItem(QGraphicsObject):
    def __init__(self, node: ProjectMapNode, color: str) -> None:
        super().__init__()
        self.node, self.color = node, color
        data = (ICON_DIR / f"{node.kind}.svg").read_bytes().replace(b"currentColor", color.encode())
        self.icon = QSvgRenderer(QByteArray(data), self)
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemIsFocusable
        )
        self.setZValue(3)
        self.setToolTip("\n".join((node.label, *node.addresses, *node.details)))

    def boundingRect(self) -> QRectF:
        return QRectF(-55, -30, 110, 102)

    def paint(
        self, painter: QPainter, option: QStyleOptionGraphicsItem, widget: QWidget | None = None
    ) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(
            QPen(
                QColor(COLORS["purple"] if self.isSelected() else self.color),
                2.5 if self.isSelected() else 1.1,
            )
        )
        painter.setBrush(QColor(COLORS["raised"] if self.isSelected() else COLORS["panel"]))
        painter.drawEllipse(QRectF(-27, -27, 54, 54))
        self.icon.render(painter, QRectF(-18, -18, 36, 36))
        painter.setPen(QColor(COLORS["text"]))
        font = painter.font()
        font.setPointSize(11)
        painter.setFont(font)
        label = painter.fontMetrics().elidedText(self.node.label, Qt.TextElideMode.ElideRight, 108)
        painter.fillRect(QRectF(-55, 32, 110, 34), QColor(COLORS["background"]))
        painter.drawText(QRectF(-55, 32, 110, 18), Qt.AlignmentFlag.AlignCenter, label)
        if self.node.addresses and self.node.addresses[0] != self.node.label:
            painter.setPen(QColor(COLORS["muted"]))
            address = painter.fontMetrics().elidedText(
                self.node.addresses[0], Qt.TextElideMode.ElideRight, 108
            )
            painter.drawText(QRectF(-55, 50, 110, 18), Qt.AlignmentFlag.AlignCenter, address)


class ProjectEdgeItem(QGraphicsPathItem):
    def __init__(
        self, edge: ProjectMapEdge, path: QPainterPath, end: QPointF, direction: QPointF
    ) -> None:
        super().__init__(path)
        self.edge, self.end, self.direction = edge, end, direction
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setZValue(0)
        self.color = "#FB7185" if edge.action in {"deny", "drop", "reject"} else "#79B8FF"
        if edge.kind == "attachment":
            self.color = "#A8B3C7"
        elif edge.action not in {"allow", "deny", "drop", "reject"}:
            self.color = "#FCD34D"
        if not edge.enabled:
            self.color = "#64748B"
        self.setToolTip(
            f"{'ACL' if edge.kind == 'acl' else 'Подключение'} · "
            f"{edge.action} · правил: {len(edge.rules)} · включено: {edge.enabled}"
        )

    def shape(self) -> QPainterPath:
        stroker = QPainterPathStroker()
        stroker.setWidth(12)
        return stroker.createStroke(self.path())

    def boundingRect(self) -> QRectF:
        return super().boundingRect().adjusted(-9, -9, 9, 9)

    def paint(
        self, painter: QPainter, option: QStyleOptionGraphicsItem, widget: QWidget | None = None
    ) -> None:
        # The dark underlay removes the lower line beneath each bridge.
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor(COLORS["background"]), 7))
        painter.drawPath(self.path())
        pen = QPen(
            QColor(COLORS["purple"] if self.isSelected() else self.color),
            2.8 if self.isSelected() else 1.35,
        )
        if self.edge.status != "known" or not self.edge.enabled or self.edge.kind == "attachment":
            pen.setStyle(Qt.PenStyle.DashLine)
        painter.setPen(pen)
        painter.drawPath(self.path())
        if self.edge.kind == "acl":
            d = self.direction
            normal = QPointF(-d.y(), d.x())
            arrow = QPolygonF(
                [self.end, self.end - d * 9 + normal * 4, self.end - d * 9 - normal * 4]
            )
            painter.setBrush(pen.color())
            painter.drawPolygon(arrow)


class ProjectMapWidget(QWidget):
    labels_changed = Signal(object)
    MAX_DISPLAY_EDGES = 1500

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.graph = ProjectMap("")
        self.zone_labels: dict[str, str] = {}
        self.collapsed: set[str] = set()
        self.node_items: dict[str, ProjectIconItem] = {}
        self.edge_items: list[ProjectEdgeItem] = []
        self.zone_items: dict[str, MapRegionItem] = {}
        self._building = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        toolbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Найти устройство, IP или зону…")
        self.search.setAccessibleName("Поиск на карте проекта")
        toolbar.addWidget(self.search, 1)
        self.zone_selector = QComboBox()
        self.zone_selector.setMaximumWidth(210)
        self.zone_selector.setAccessibleName("Зона карты проекта")
        toolbar.addWidget(self.zone_selector)
        self.rename_button = QPushButton("Название зоны…")
        self.rename_button.clicked.connect(self._rename_zone)
        toolbar.addWidget(self.rename_button)
        layout.addLayout(toolbar)
        tools = QHBoxLayout()
        self.edge_filter = QComboBox()
        for title, value in (
            ("Все связи", "all"),
            ("Разрешения ACL", "allow"),
            ("Запреты ACL", "deny"),
            ("Облачные подключения", "attachment"),
        ):
            self.edge_filter.addItem(title, value)
        tools.addWidget(self.edge_filter)
        self.neighbors = QCheckBox("Соседние узлы")
        self.neighbors.setChecked(True)
        tools.addWidget(self.neighbors)
        tools.addStretch()
        self.scene = QGraphicsScene(self)
        self.view = AclMapView(self.scene, self)
        self._fit_timer = QTimer(self)
        self._fit_timer.setSingleShot(True)
        self._fit_timer.timeout.connect(self.view.fit_map)
        self.view.setMinimumSize(280, 120)
        self.view.setAccessibleName("Общая сетевая карта проекта")
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        for label, callback in (
            ("+", self.view.zoom_in),
            ("−", self.view.zoom_out),
            ("Вписать", self.view.fit_map),
        ):
            button = QPushButton(label)
            button.clicked.connect(callback)
            tools.addWidget(button)
        self.properties_button = QPushButton("Свойства")
        self.properties_button.setCheckable(True)
        tools.addWidget(self.properties_button)
        layout.addLayout(tools)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumWidth(240)
        self.details.setMaximumWidth(420)
        self.details.setAccessibleName("Устройство и правила выбранной связи")
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.view)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 1)
        splitter.setSizes([900, 320])
        self.details.hide()
        self.properties_button.toggled.connect(self.details.setVisible)
        layout.addWidget(splitter, 1)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        legend = QLabel(
            "→ ACL: синий — разрешение, красный — запрет · "
            "жёлтый — разные действия · серый пунктир — подключение · доступность не проверяется"
        )
        legend.setWordWrap(True)
        layout.addWidget(legend)
        self.scene.selectionChanged.connect(self._selected)
        self.search.textChanged.connect(self._render)
        self.zone_selector.currentIndexChanged.connect(self._render)
        self.edge_filter.currentIndexChanged.connect(self._render)
        self.neighbors.toggled.connect(self._render)
        self.set_graph(self.graph, {})

    @staticmethod
    def zone_key(node: ProjectMapNode) -> str:
        return node.area + "|" + node.scope + "|" + node.zone

    @staticmethod
    def zone_title(node: ProjectMapNode) -> str:
        suffix = (
            node.scope
            if node.scope and node.scope != "default" and not node.scope.startswith("cloud:")
            else ""
        )
        return node.zone + (" · " + suffix if suffix else "")

    def set_graph(self, graph: ProjectMap, labels: dict[str, str]) -> None:
        if graph == self.graph and labels == self.zone_labels and self.zone_selector.count():
            return
        changed_project = graph.project_id != self.graph.project_id
        self.graph, self.zone_labels = graph, dict(labels)
        if changed_project:
            self.collapsed.clear()
            self.search.blockSignals(True)
            self.search.clear()
            self.search.blockSignals(False)
            self.properties_button.setChecked(False)
        previous = None if changed_project else self.zone_selector.currentData()
        self.zone_selector.blockSignals(True)
        self.zone_selector.clear()
        self.zone_selector.addItem("Все зоны", None)
        zones = {self.zone_key(node): node for node in graph.nodes}
        for key, node in sorted(zones.items()):
            label = labels.get(key, self.zone_title(node))
            self.zone_selector.addItem(label + " · " + graph.areas.get(node.area, ""), key)
        self.zone_selector.setCurrentIndex(max(0, self.zone_selector.findData(previous)))
        self.zone_selector.blockSignals(False)
        self._render()

    def rename_zone(self, key: str, label: str) -> None:
        if not label.strip() or len(label.strip()) > 120:
            return
        labels = {**self.zone_labels, key: label.strip()}
        self.set_graph(self.graph, labels)
        self.labels_changed.emit(dict(labels))

    def _rename_zone(self) -> None:
        key = self.zone_selector.currentData()
        if not isinstance(key, str):
            return
        node = next(node for node in self.graph.nodes if self.zone_key(node) == key)
        value, accepted = QInputDialog.getText(
            self,
            "Название зоны",
            "Название:",
            text=self.zone_labels.get(key, self.zone_title(node)),
        )
        if accepted:
            self.rename_zone(key, value)

    def _toggle_zone(self, key: str) -> None:
        self.collapsed.symmetric_difference_update({key})
        self._render()

    def _render(self) -> None:
        if self._building:
            return
        self._building = True
        try:
            self.scene.clear()
            self.node_items.clear()
            self.edge_items.clear()
            self.zone_items.clear()
            query = self.search.text().strip().casefold()
            zone = self.zone_selector.currentData()
            self.rename_button.setEnabled(isinstance(zone, str))
            mode = self.edge_filter.currentData()
            edges = [
                edge
                for edge in self.graph.edges
                if mode == "all"
                or (mode == "allow" and edge.action == "allow" and edge.enabled)
                or (mode == "deny" and edge.action in {"deny", "drop", "reject"})
                or (mode == "attachment" and edge.kind == "attachment")
            ]
            visible = {
                node.key
                for node in self.graph.nodes
                if (zone is None or self.zone_key(node) == zone)
                and (
                    not query
                    or query
                    in " ".join(
                        (
                            node.label,
                            *node.addresses,
                            node.zone,
                            node.scope,
                            self.graph.areas.get(node.area, ""),
                            self.zone_labels.get(self.zone_key(node), ""),
                        )
                    ).casefold()
                )
            }
            if (query or zone) and self.neighbors.isChecked():
                matches = frozenset(visible)
                visible.update(
                    key
                    for edge in edges
                    if edge.source in matches or edge.target in matches
                    for key in (edge.source, edge.target)
                )
            by_area: dict[str, dict[str, list[ProjectMapNode]]] = defaultdict(
                lambda: defaultdict(list)
            )
            for node in self.graph.nodes:
                if node.key in visible:
                    by_area[node.area][self.zone_key(node)].append(node)
            positions: dict[str, QPointF] = {}
            representatives: dict[str, str] = {}
            x, area_top, row_height = 50.0, 50.0, 0.0
            area_columns = max(1, min(3, ceil(sqrt(len(by_area) * 1.5))))
            for area_index, area in enumerate(
                sorted(by_area, key=lambda value: (value != CONTOUR, value == EXTERNAL, value))
            ):
                if area_index and area_index % area_columns == 0:
                    x = 50.0
                    area_top += row_height + 50
                    row_height = 0.0
                zones = by_area[area]
                area_x, y = x, area_top + 50
                width = 210.0
                zone_columns = 2 if len(zones) >= 3 else 1
                zone_row_height, zone_offset = 0.0, 0.0
                for zone_index, (key, values) in enumerate(sorted(zones.items())):
                    if zone_index and zone_index % zone_columns == 0:
                        y += zone_row_height + 28
                        zone_row_height, zone_offset = 0.0, 0.0
                    values.sort(key=lambda node: (node.kind != "router", node.label))
                    color = ZONE_COLORS[zone_index % len(ZONE_COLORS)]
                    collapsed = key in self.collapsed
                    columns = max(1, min(8, ceil(sqrt(len(values)))))
                    rows = ceil(len(values) / columns)
                    zone_width = max(160, columns * 128 + 32)
                    zone_height = 170 if collapsed else rows * 112 + 64
                    title = self.zone_labels.get(key, self.zone_title(values[0]))
                    subnet = values[0].zone
                    title += (f" · {subnet}" if title != subnet else "") + f" · {len(values)}"
                    title = ("▸ " if collapsed else "▾ ") + title
                    region = MapRegionItem(
                        key,
                        QRectF(x + zone_offset + 20, y, zone_width, zone_height),
                        title,
                        color,
                        zone=True,
                    )
                    region.activated.connect(self._toggle_zone)
                    self.scene.addItem(region)
                    self.zone_items[key] = region
                    if collapsed:
                        summary = replace(
                            values[0],
                            key="zone:" + identity(key),
                            label=title,
                            kind="network",
                            addresses=(),
                            details=tuple(node.label for node in values),
                        )
                        values_to_draw = [summary]
                        for node in values:
                            representatives[node.key] = summary.key
                    else:
                        values_to_draw = values
                    for index, node in enumerate(values_to_draw):
                        pos = QPointF(
                            x + zone_offset + 20 + 80 + (index % columns) * 128,
                            y + 80 + (index // columns) * 112,
                        )
                        icon = ProjectIconItem(node, color)
                        icon.setPos(pos)
                        self.scene.addItem(icon)
                        self.node_items[node.key] = icon
                        positions[node.key] = pos
                        representatives.setdefault(node.key, node.key)
                    zone_row_height = max(zone_row_height, zone_height)
                    zone_offset += zone_width + 24
                    width = max(width, zone_offset + 16)
                y += zone_row_height + 28
                region = MapRegionItem(
                    area,
                    QRectF(area_x, area_top, width, max(170, y - area_top + 10)),
                    self.graph.areas.get(area, area),
                    "#94A3B8",
                    zone=False,
                )
                self.scene.addItem(region)
                x += width + 60
                row_height = max(row_height, region.rect.height())
            outer = self.scene.itemsBoundingRect().adjusted(-28, -52, 28, 28)
            if outer.isEmpty() or not self.node_items:
                outer = QRectF(0, 0, 800, 300)
                message = self.scene.addText(
                    "Добавьте устройства и интеграции в проект."
                    if not self.graph.nodes
                    else "Нет узлов по фильтру."
                )
                message.setDefaultTextColor(QColor(COLORS["muted"]))
                message.setPos(30, 70)
            internet = MapRegionItem(
                "internet", outer, "ИНТЕРНЕТ · сеть проекта", "#94A3B8", zone=False
            )
            internet.setZValue(-10)
            self.scene.addItem(internet)
            drawable: list[tuple[ProjectMapEdge, QPointF, QPointF]] = []
            bundles: dict[tuple[str, str, str], list[ProjectMapEdge]] = defaultdict(list)
            for edge in edges:
                source = representatives.get(edge.source)
                target = representatives.get(edge.target)
                if source not in positions or target not in positions:
                    continue
                bundles[source, target, edge.kind].append(edge)
            for (source, target, kind), group in bundles.items():
                actions = {edge.action for edge in group}
                edge = ProjectMapEdge(
                    source,
                    target,
                    kind,
                    next(iter(actions)) if len(actions) == 1 else "mixed",
                    all(edge.enabled for edge in group),
                    "known" if all(edge.status == "known" for edge in group) else "unknown",
                    tuple(dict.fromkeys(rule for edge in group for rule in edge.rules)),
                    tuple(dict.fromkeys(line for edge in group for line in edge.details)),
                )
                start, end = positions[source], positions[target]
                if source != target:
                    dx, dy = end.x() - start.x(), end.y() - start.y()
                    length = hypot(dx, dy)
                    direction = QPointF(dx / length, dy / length)
                    if (target, source, kind) in bundles:
                        offset = QPointF(-direction.y(), direction.x()) * 5
                        start, end = start + offset, end + offset
                    start, end = start + direction * 29, end - direction * 29
                drawable.append((edge, start, end))
            total_lines = len(drawable)
            drawable = drawable[: self.MAX_DISPLAY_EDGES]
            segments = [((a.x(), a.y()), (b.x(), b.y())) for _, a, b in drawable]
            bridges = bridge_positions(segments)
            for index, (edge, start, end) in enumerate(drawable):
                delta = end - start
                length = hypot(delta.x(), delta.y())
                if length < 1:
                    path = QPainterPath(start + QPointF(0, -28))
                    path.cubicTo(
                        start + QPointF(70, -85), start + QPointF(85, 40), start + QPointF(27, 0)
                    )
                    end, direction = start + QPointF(27, 0), QPointF(-1, 0)
                else:
                    direction = delta / length
                    normal = QPointF(-direction.y(), direction.x())
                    path = QPainterPath(start)
                    for position in bridges.get(index, ()):
                        middle = start + delta * position
                        path.lineTo(middle - direction * 8)
                        path.cubicTo(
                            middle - direction * 4 + normal * 11,
                            middle + direction * 4 + normal * 11,
                            middle + direction * 8,
                        )
                    path.lineTo(end)
                item = ProjectEdgeItem(edge, path, end, direction)
                self.scene.addItem(item)
                self.edge_items.append(item)
            self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-24, -24, 24, 24))
            self.status.setText(
                f"Объектов: {len(visible)} / {len(self.graph.nodes)} · "
                f"Связей: {len(drawable)} / {len(self.graph.edges)} · "
                f"Зон: {len(self.zone_items)}"
                + (f" · Замечаний: {len(self.graph.warnings)}" if self.graph.warnings else "")
                + (
                    f" · Лимит линий: {len(drawable)}/{total_lines}; выберите узел или зону"
                    if total_lines > len(drawable)
                    else ""
                )
            )
            self.status.setToolTip("\n".join(self.graph.warnings))
            self.details.setPlainText(
                "Выберите устройство или линию связи.\n\n"
                "Зоны /24 — визуальная группировка по первым трём октетам.\n"
                "Двойной щелчок по зоне сворачивает её.\n\n" + "\n".join(self.graph.warnings)
            )
        finally:
            self._building = False
        # Fit after Qt has laid out the active page, not the previous mode.
        self._fit_timer.start(0)

    def _selected(self) -> None:
        if self._building:
            return
        selected = self.scene.selectedItems()
        if not selected:
            for icon in self.node_items.values():
                icon.setOpacity(1)
            for line in self.edge_items:
                line.setOpacity(1)
            return
        item = selected[0]
        if isinstance(item, ProjectIconItem):
            node = item.node
            lines = [node.label, *node.addresses, "", *node.details]
            active_nodes = {node.key}
            if node.kind == "cloud":
                active_nodes.update(
                    value.key for value in self.graph.nodes if value.area == node.area
                )
            connected = [
                edge
                for edge in self.graph.edges
                if edge.source in active_nodes
                or edge.target in active_nodes
                or any(rule.owner_id == node.key for rule in edge.rules)
            ]
            lines.append(f"\nСвязей: {len(connected)}")
            for edge in connected:
                active_nodes.update((edge.source, edge.target))
                for rule in edge.rules:
                    lines.append(f"{rule.name}: {rule.source} → {rule.destination} · {rule.action}")
            for icon in self.node_items.values():
                icon.setOpacity(1 if icon.node.key in active_nodes else 0.25)
            for line in self.edge_items:
                line.setOpacity(
                    1
                    if line.edge.source in active_nodes and line.edge.target in active_nodes
                    else 0.12
                )
        elif isinstance(item, ProjectEdgeItem):
            edge = item.edge
            lines = [
                "Связь по условиям ACL" if edge.kind == "acl" else "Облачное подключение",
                f"Действие: {edge.action or '—'}",
                f"Правил: {len(edge.rules)}",
                *edge.details,
            ]
            for rule in edge.rules:
                lines.extend(
                    (
                        "",
                        f"{rule.device} · {rule.name}",
                        f"ID: {rule.rule_id}",
                        f"{rule.source} → {rule.destination}",
                        f"Сервисы: {', '.join(rule.services) or 'неизвестны'}",
                        f"Действие: {rule.action} · включено: {rule.enabled}",
                        f"Условия: {rule.status} · {rule.location}",
                    )
                )
            for line in self.edge_items:
                line.setOpacity(1 if line is item else 0.15)
            for icon in self.node_items.values():
                icon.setOpacity(
                    1
                    if icon.node.key in (edge.source, edge.target)
                    or any(rule.owner_id == icon.node.key for rule in edge.rules)
                    else 0.25
                )
        else:
            return
        self.details.setPlainText("\n".join(lines))
        self.properties_button.setChecked(True)
