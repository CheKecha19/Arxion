"""Icon-based project map with nested regions, named zones and line bridges."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from math import ceil, hypot, sqrt
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel, QByteArray, QModelIndex, QPointF, QRectF, Qt, QTimer, Signal,
)
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPainterPathStroker, QPen, QPolygonF, QTransform
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QAbstractItemView,
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
    QSpinBox,
    QStyleOptionGraphicsItem,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.map_geometry import bridge_positions
from firewall_compliance.interfaces.desktop.project_map_layout import ProjectMapLayouts
from firewall_compliance.interfaces.desktop.project_map_projection import bounded_project_map
from firewall_compliance.interfaces.desktop.project_map import (
    CONTOUR,
    EXTERNAL,
    ProjectMap,
    ProjectMapEdge,
    ProjectMapNode,
    identity,
)
from firewall_compliance.interfaces.desktop.qt_acl_map import AclMapView
from firewall_compliance.interfaces.desktop.qt_rule_query import RuleQueryWidget
from firewall_compliance.interfaces.desktop.qt_theme import COLORS

ICON_DIR = Path(__file__).parent / "assets" / "map_icons"
ZONE_COLORS = ("#7DD3FC", "#C4B5FD", "#5EEAD4", "#FCD34D", "#FDA4AF", "#A5B4FC")
EMPTY_INDEX = QModelIndex()


class InteractionRows(QAbstractTableModel):
    """All filtered aggregates remain accessible even beyond the line budget."""

    HEADERS = ("Источник", "Назначение", "Действие", "Сервисы", "Правил", "Условия", "Контекст")

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.edges: tuple[ProjectMapEdge, ...] = ()
        self.labels: dict[str, str] = {}
        self.contexts: dict[str, str] = {}

    def replace(
        self, edges: list[ProjectMapEdge], labels: dict[str, str], contexts: dict[str, str],
    ) -> None:
        self.beginResetModel()
        self.edges, self.labels = tuple(edges), labels
        self.contexts = contexts
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.edges)

    def columnCount(self, parent: QModelIndex = EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal and 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if not index.isValid() or not 0 <= index.row() < len(self.edges) or not 0 <= index.column() < len(self.HEADERS) or role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        edge = self.edges[index.row()]
        services = tuple(dict.fromkeys(value for rule in edge.rules for value in rule.services))
        return (
            self.labels.get(edge.source, edge.source),
            self.labels.get(edge.target, edge.target),
            edge.action or "не указано",
            (("Несколько сервисов: " if len(services) > 1 else "") + ", ".join(services))
            or "неизвестны / неприменимы",
            str(len({(rule.owner_id, rule.rule_id) for rule in edge.rules})),
            edge.status + (" · отключено" if not edge.enabled else "")
            + (" · фильтр неизвестен" if "Условия фильтра неизвестны" in edge.details else ""),
            self.contexts.get(edge.source, "неизвестен") + " → "
            + self.contexts.get(edge.target, "неизвестен"),
        )[index.column()]


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
        if edge.kind != "acl":
            self.color = "#A8B3C7"
        elif edge.action not in {"allow", "deny", "drop", "reject"}:
            self.color = "#FCD34D"
        if not edge.enabled:
            self.color = "#64748B"
        self.setToolTip(
            f"{'ACL' if edge.kind == 'acl' else 'Структура / принадлежность'} · "
            f"{edge.action} · правил: {len(edge.rules)} · включено: {edge.enabled} · "
            f"условия: {edge.status}"
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
        if self.edge.status != "known" or not self.edge.enabled or self.edge.kind != "acl":
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
    rules_requested = Signal(object)
    view_settings_changed = Signal(object)
    MAX_DISPLAY_EDGES = 200

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.graph = ProjectMap("")
        self.zone_labels: dict[str, str] = {}
        self.collapsed: set[str] = set()
        self.node_items: dict[str, ProjectIconItem] = {}
        self.edge_items: list[ProjectEdgeItem] = []
        self.zone_items: dict[str, MapRegionItem] = {}
        self._building = False
        self._selecting = False
        self._edge_offset = 0
        self._relations: list[ProjectMapEdge] = []
        self._base_status = ""
        self._focus_node: str | None = None
        self._focus_history: list[tuple[str | None, str]] = []
        self._cameras: dict[tuple[object, ...], tuple[QTransform, QPointF]] = {}
        self._last_view_key: tuple[object, ...] | None = None
        self._layouts = ProjectMapLayouts()
        self._drill_members: frozenset[str] | None = None
        self._drill_history: list[tuple[frozenset[str] | None, str | None]] = []
        self._render_members: dict[str, tuple[str, ...]] = {}
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
        self.presentation = QComboBox()
        self.presentation.addItem("Структура сети", "structure")
        self.presentation.addItem("Условия правил", "access")
        self.presentation.setAccessibleName("Представление карты проекта")
        tools.addWidget(self.presentation)
        self.edge_filter = QComboBox()
        for title, value in (
            ("Все связи", "all"),
            ("Разрешения ACL", "allow"),
            ("Запреты ACL", "deny"),
            ("Связи структуры", "attachment"),
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
        self._fit_timer.timeout.connect(self._restore_camera)
        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.timeout.connect(self._render)
        self.view.setMinimumSize(280, 120)
        self.view.setAccessibleName("Общая сетевая карта проекта")
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        navigation = QHBoxLayout()
        for label, callback in (
            ("+", self.view.zoom_in),
            ("−", self.view.zoom_out),
            ("Вписать", self.view.fit_map),
        ):
            button = QPushButton(label)
            button.clicked.connect(callback)
            navigation.addWidget(button)
        self.properties_button = QPushButton("Свойства")
        self.properties_button.setCheckable(True)
        tools.addWidget(self.properties_button)
        self.open_rules_button = QPushButton("Правила выбранной связи")
        self.open_rules_button.clicked.connect(self._open_selected_rules)
        tools.addWidget(self.open_rules_button)
        self.access_button = QPushButton("Показать доступ")
        self.access_button.clicked.connect(self._show_access)
        tools.addWidget(self.access_button)
        reset = QPushButton("Вся карта")
        reset.clicked.connect(self._clear_focus)
        navigation.addWidget(reset)
        back = QPushButton("Назад")
        back.clicked.connect(self._back_focus)
        navigation.addWidget(back)
        drill = QPushButton("Раскрыть группу")
        drill.clicked.connect(self._drill_selected)
        navigation.addWidget(drill)
        previous = QPushButton("← Линии")
        previous.clicked.connect(lambda: self._page_edges(-1))
        navigation.addWidget(previous)
        following = QPushButton("Линии →")
        following.clicked.connect(lambda: self._page_edges(1))
        navigation.addWidget(following)
        layout.addLayout(tools)
        layout.addLayout(navigation)
        self.conditions = RuleQueryWidget(self)
        self.conditions.changed.connect(self._filters_changed)
        layout.addWidget(self.conditions)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumWidth(240)
        self.details.setMaximumWidth(420)
        self.details.setAccessibleName("Устройство и правила выбранной связи")
        self.interaction_model = InteractionRows(self)
        self.interactions = QTableView()
        self.interactions.setModel(self.interaction_model)
        self.interactions.setAccessibleName("Все взаимодействия текущей выборки карты")
        self.interactions.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.interactions.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.interactions.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.interactions.clicked.connect(self._interaction_clicked)
        side = QSplitter(Qt.Orientation.Vertical)
        limits = QWidget()
        limit_layout = QHBoxLayout(limits)
        self.node_limit = QSpinBox()
        self.node_limit.setRange(3, 500)
        self.node_limit.setValue(100)
        self.node_limit.setAccessibleName("Максимум узлов в представлении карты")
        self.line_limit = QSpinBox()
        self.line_limit.setRange(1, 1000)
        self.line_limit.setValue(self.MAX_DISPLAY_EDGES)
        self.line_limit.setAccessibleName("Максимум линий на странице карты")
        for title, widget in (("Узлы", self.node_limit), ("Линии", self.line_limit)):
            limit_layout.addWidget(QLabel(title))
            limit_layout.addWidget(widget)
            widget.valueChanged.connect(self._limits_changed)
        limits.setMaximumHeight(65)
        side.addWidget(limits)
        side.addWidget(self.interactions)
        side.addWidget(self.details)
        side.setMinimumWidth(280)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.view)
        splitter.addWidget(side)
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
            "жёлтый — неизвестное действие · серый — подключение · "
            "пунктир — неполные условия, выключенное правило или подключение. "
            "Группы представления не доказывают общую сеть; доступность не проверяется."
        )
        legend.setWordWrap(True)
        layout.addWidget(legend)
        self.scene.selectionChanged.connect(self._selected)
        self.search.textChanged.connect(self._filters_changed)
        self.zone_selector.currentIndexChanged.connect(self._filters_changed)
        self.edge_filter.currentIndexChanged.connect(self._filters_changed)
        self.neighbors.toggled.connect(self._filters_changed)
        self.presentation.currentIndexChanged.connect(self._filters_changed)
        self.set_graph(self.graph, {})

    @staticmethod
    def zone_key(node: ProjectMapNode) -> str:
        return node.area + "|" + node.scope + "|" + node.zone

    def zone_title(self, node: ProjectMapNode) -> str:
        if node.scope.startswith("view:"):
            return node.zone
        if node.scope.startswith("local:"):
            owner = next(
                (value for value in self.graph.nodes if value.scope == node.scope and value.kind == "router"),
                None,
            )
            return node.zone + " · " + (owner.label if owner else "отдельный контекст")
        suffix = (
            node.scope
            if node.scope and node.scope != "default" and not node.scope.startswith("cloud:")
            else ""
        )
        return node.zone + (" · " + suffix if suffix else "")

    def set_graph(
        self, graph: ProjectMap, labels: dict[str, str],
        view_settings: object = None,
    ) -> None:
        changed_project = graph.project_id != self.graph.project_id
        if changed_project:
            self._layouts = ProjectMapLayouts.load(
                view_settings.get("layouts") if isinstance(view_settings, dict) else None
            )
        limits_changed = False
        if isinstance(view_settings, dict):
            for name, control in (("node_limit", self.node_limit), ("line_limit", self.line_limit)):
                value = view_settings.get(name, (100 if name == "node_limit" else 200) if changed_project else None)
                if type(value) is int and control.minimum() <= value <= control.maximum():
                    limits_changed = limits_changed or control.value() != value
                    control.blockSignals(True)
                    control.setValue(value)
                    control.blockSignals(False)
        if (
            graph == self.graph and labels == self.zone_labels
            and self.zone_selector.count() and not limits_changed
        ):
            return
        self.graph, self.zone_labels = graph, dict(labels)
        if changed_project:
            self._cameras.clear()
            self._last_view_key = None
            self._drill_members = None
            self._drill_history.clear()
            self._focus_node = None
            self._focus_history.clear()
            self._edge_offset = 0
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
        choices = tuple(dict.fromkeys((self.zone_labels.get(key, self.zone_title(node)), *self.zone_labels.values())))
        value, accepted = QInputDialog.getItem(
            self,
            "Название зоны",
            "Название (можно выбрать ранее сохранённую подпись):",
            choices, 0, True,
        )
        if accepted:
            self.rename_zone(key, value)

    def _toggle_zone(self, key: str) -> None:
        self.collapsed.symmetric_difference_update({key})
        self._render()

    def _clear_focus(self) -> None:
        self._focus_node = None
        self._drill_members = None
        self._drill_history.clear()
        self._focus_history.clear()
        self._edge_offset = 0
        self._render()

    def _back_focus(self) -> None:
        if self._focus_history:
            self._focus_node, presentation = self._focus_history.pop()
            self.presentation.blockSignals(True)
            self.presentation.setCurrentIndex(self.presentation.findData(presentation))
            self.presentation.blockSignals(False)
            self._edge_offset = 0
            self._render()
        elif self._drill_history:
            self._drill_members, self._focus_node = self._drill_history.pop()
            self._edge_offset = 0
            self._render()

    def _drill_selected(self) -> None:
        selected = self.scene.selectedItems()
        node = next((item.node for item in selected if isinstance(item, ProjectIconItem)), None)
        members = self._render_members.get(node.key, ()) if node is not None else ()
        if len(members) < 2:
            self.status.setText("Выберите сводную группу для раскрытия.")
            return
        self._drill_history.append((self._drill_members, self._focus_node))
        self._drill_members = frozenset(members)
        self._focus_node = None
        self._focus_history.clear()
        self._edge_offset = 0
        self._render()

    def _limits_changed(self) -> None:
        self._edge_offset = 0
        self._render()
        self.view_settings_changed.emit(self._view_settings())

    def _view_settings(self) -> dict[str, object]:
        return {
            "node_limit": self.node_limit.value(), "line_limit": self.line_limit.value(),
            "layouts": self._layouts.to_json(),
        }

    def _filters_changed(self, *_: object) -> None:
        self._clear_focus()

    def _show_access(self) -> None:
        node = next((item.node for item in self.scene.selectedItems() if isinstance(item, ProjectIconItem)), None)
        if node is None:
            self.status.setText("Выберите устройство или ресурс структуры.")
            return
        if len(self._render_members.get(node.key, ())) > 1:
            self.status.setText("Сначала раскройте группу и выберите устройство или ресурс.")
            return
        owner = next((edge.source for edge in self.graph.edges if edge.kind == "membership" and edge.target == node.key), node.key)
        self.presentation.blockSignals(True)
        self.presentation.setCurrentIndex(self.presentation.findData("access"))
        self.presentation.blockSignals(False)
        self.edge_filter.blockSignals(True)
        self.edge_filter.setCurrentIndex(0)
        self.edge_filter.blockSignals(False)
        self._focus_history.append((self._focus_node, "structure"))
        self._focus_node = owner
        self._drill_members = None
        self._edge_offset = 0
        self._render()

    def _restore_camera(self) -> None:
        camera = self._cameras.get(self._last_view_key) if self._last_view_key else None
        if camera is None:
            self.view.fit_map()
        else:
            transform, center = camera
            self.view.setTransform(transform)
            self.view.centerOn(center)

    def _page_edges(self, direction: int) -> None:
        if not self._relations:
            return
        limit = self.line_limit.value()
        last = (len(self._relations) - 1) // limit * limit
        self._edge_offset = max(0, min(last, self._edge_offset + direction * limit))
        self._render()

    def _interaction_clicked(self, index: QModelIndex) -> None:
        if not index.isValid() or not 0 <= index.row() < len(self.interaction_model.edges):
            return
        edge = self.interaction_model.edges[index.row()]
        position = self._relations.index(edge)
        limit = self.line_limit.value()
        offset = position // limit * limit
        if offset != self._edge_offset:
            self._edge_offset = offset
            self._render()
        for line in self.edge_items:
            if line.edge == edge:
                self._selecting = True
                try:
                    self.scene.clearSelection()
                    line.setSelected(True)
                finally:
                    self._selecting = False
                self._selected()
                self.view.centerOn(line)
                break

    def _render(self) -> None:
        if self._building:
            return
        if self._last_view_key is not None:
            self._cameras[self._last_view_key] = (
                QTransform(self.view.transform()),
                self.view.mapToScene(self.view.viewport().rect().center()),
            )
            if len(self._cameras) > 100:
                self._cameras.pop(next(iter(self._cameras)))
        self._building = True
        try:
            self.scene.clear()
            self.node_items.clear()
            self.edge_items.clear()
            self.zone_items.clear()
            self._render_members.clear()
            query = self.search.text().strip().casefold()
            zone = self.zone_selector.currentData()
            self.rename_button.setEnabled(isinstance(zone, str))
            structure = self.presentation.currentData() == "structure"
            mode = "all" if structure else self.edge_filter.currentData()
            self.edge_filter.setVisible(not structure)
            self.access_button.setVisible(structure)
            self.open_rules_button.setVisible(not structure)
            self.conditions.setVisible(not structure)
            edges = [
                edge
                for edge in self.graph.edges
                if (edge.kind not in {"acl", "condition"} if structure else edge.kind in {"acl", "condition"})
                and (mode == "all"
                or (mode == "allow" and edge.action == "allow" and edge.enabled)
                or (mode == "deny" and edge.action in {"deny", "drop", "reject"})
                or (mode == "attachment" and edge.kind not in {"acl", "condition"}))
            ]
            if not structure and self.conditions.query.active:
                matching = {
                    key: self.conditions.query.matches(rule) for key, rule in self.graph.rule_inputs.items()
                }
                filtered = []
                for edge in edges:
                    rules = tuple(
                        rule for rule in edge.rules
                        if self.conditions.accepts(matching.get((rule.owner_id, rule.rule_id)))
                    )
                    if rules:
                        unknown = any(matching.get((rule.owner_id, rule.rule_id)) is None for rule in rules)
                        filtered.append(replace(
                            edge, rules=rules,
                            details=(*edge.details, "Условия фильтра неизвестны") if unknown else edge.details,
                        ))
                edges = filtered
            access_nodes = {
                key for edge in edges for key in (
                    edge.source, edge.target, *(rule.owner_id for rule in edge.rules),
                )
            }
            visible = {
                node.key
                for node in self.graph.nodes
                if (
                    not node.key.startswith(("endpoint:", "group:")) if structure
                    else node.key in access_nodes
                )
                and (zone is None or self.zone_key(node) == zone)
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
            original = {node.key: node for node in self.graph.nodes}
            anchor = self._focus_node if self._focus_node in original else None
            if self._drill_members is not None and anchor is None:
                visible.intersection_update(self._drill_members)
                if self.neighbors.isChecked():
                    members = frozenset(visible)
                    visible.update(
                        key for edge in edges
                        if edge.source in members or edge.target in members
                        or any(rule.owner_id in members for rule in edge.rules)
                        for key in (edge.source, edge.target)
                    )
            if anchor is not None and self.neighbors.isChecked():
                visible = {anchor}
                for edge in edges:
                    if anchor in (edge.source, edge.target) or any(rule.owner_id == anchor for rule in edge.rules):
                        visible.update((edge.source, edge.target))
            projection = bounded_project_map(
                self.graph, visible, tuple(edges), node_budget=self.node_limit.value(),
                detail=self._drill_members is not None and anchor is None, anchor=anchor,
                detail_members=self._drill_members,
            )
            view_graph = projection.graph
            self._render_members.update(projection.members)
            renamed = []
            for node in view_graph.nodes:
                members = projection.members[node.key]
                source_zones = {self.zone_key(original[key]) for key in members}
                label = self.zone_labels.get(next(iter(source_zones))) if len(source_zones) == 1 else None
                renamed.append(
                    replace(node, label=f"{label} · {len(members)} объектов")
                    if len(members) > 1 and label else node
                )
            view_graph = replace(view_graph, nodes=tuple(renamed))
            by_area: dict[str, dict[str, list[ProjectMapNode]]] = defaultdict(
                lambda: defaultdict(list)
            )
            for node in view_graph.nodes:
                by_area[node.area][self.zone_key(node)].append(node)
            layout_key = identity(
                structure, query, zone, mode, self._focus_node,
                tuple(sorted(self._drill_members)) if self._drill_members is not None else None,
                self.node_limit.value(), self.conditions.query,
            )
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
                    slots = self._layouts.zone(
                        layout_key, key, tuple(node.key for node in values), columns,
                    )
                    columns = slots.columns
                    rows = max(slots.slots.values(), default=0) // columns + 1
                    zone_width = max(160, columns * 128 + 32)
                    zone_height = 170 if collapsed else rows * 112 + 64
                    title = self.zone_labels.get(key, self.zone_title(values[0]))
                    subnet = values[0].zone
                    title += (f" · {subnet}" if title != subnet else "")
                    title += f" · {sum(len(projection.members[node.key]) for node in values)} объектов"
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
                        self._render_members[summary.key] = tuple(
                            member for value in values
                            for member in projection.members.get(value.key, (value.key,))
                        )
                        for node in values:
                            representatives[node.key] = summary.key
                    else:
                        values_to_draw = values
                    for index, node in enumerate(values_to_draw):
                        index = 0 if collapsed else slots.slots[node.key]
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
                    view_graph.areas.get(area, area),
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
                "overview", outer, "ОБЛАСТЬ ПРЕДСТАВЛЕНИЯ · не физическая граница", "#94A3B8", zone=False
            )
            internet.setZValue(-10)
            self.scene.addItem(internet)
            drawable: list[tuple[ProjectMapEdge, QPointF, QPointF]] = []
            bundles: dict[tuple[str, str, str, str, bool, str], list[ProjectMapEdge]] = defaultdict(list)
            if self._focus_node is not None and self._focus_node not in self.node_items:
                self._focus_node = None
            for edge in view_graph.edges:
                source = representatives.get(edge.source)
                target = representatives.get(edge.target)
                if source not in positions or target not in positions:
                    continue
                bundles[source, target, edge.kind, edge.action, edge.enabled, edge.status].append(edge)
            pair_lanes: dict[tuple[str, str], list[tuple[str, str, str, str, bool, str]]] = defaultdict(list)
            for key in sorted(bundles):
                pair_lanes[min(key[0], key[1]), max(key[0], key[1])].append(key)
            for bundle_key, group in sorted(bundles.items()):
                source, target, kind, action, enabled, status = bundle_key
                edge = ProjectMapEdge(
                    source,
                    target,
                    kind,
                    action,
                    enabled,
                    status,
                    tuple(dict.fromkeys(rule for edge in group for rule in edge.rules)),
                    tuple(dict.fromkeys(line for edge in group for line in edge.details)),
                )
                start, end = positions[source], positions[target]
                lanes = pair_lanes[min(source, target), max(source, target)]
                lane = (lanes.index(bundle_key) - (len(lanes) - 1) / 2) * 10
                if source != target:
                    dx, dy = end.x() - start.x(), end.y() - start.y()
                    length = hypot(dx, dy)
                    direction = QPointF(dx / length, dy / length)
                    offset = QPointF(-direction.y(), direction.x()) * lane * (1 if source < target else -1)
                    start, end = start + offset, end + offset
                    start, end = start + direction * 29, end - direction * 29
                else:
                    start, end = start + QPointF(lane, lane), end + QPointF(lane, lane)
                drawable.append((edge, start, end))
            if self._focus_node is not None:
                focused_members = self._render_members.get(self._focus_node, (self._focus_node,))
                drawable = [
                    value for value in drawable
                    if self._focus_node in (value[0].source, value[0].target)
                    or any(
                        rule.owner_id in focused_members
                        for rule in value[0].rules
                    )
                ]
            total_lines = len(drawable)
            self._relations = [edge for edge, _, _ in drawable]
            if self._edge_offset >= total_lines:
                self._edge_offset = 0
            drawable = drawable[self._edge_offset:self._edge_offset + self.line_limit.value()]
            self.interaction_model.replace(
                self._relations,
                {
                    key: item.node.label + (" · " + ", ".join(item.node.addresses) if item.node.addresses else "")
                    for key, item in self.node_items.items()
                },
                {
                    key: view_graph.areas.get(item.node.area, item.node.area) + " · " + self.zone_title(item.node)
                    for key, item in self.node_items.items()
                },
            )
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
            self._base_status = (
                ("Структура сети" if structure else "Условия правил")
                + (
                    " › " + self.node_items[self._focus_node].node.label
                    if self._focus_node is not None and self._focus_node in self.node_items else " › Обзор"
                )
                + (f" › Раскрыто объектов: {len(self._drill_members)}" if self._drill_members else "")
                + " · "
                f"Узлов вида: {len(self.node_items)} / {projection.source_nodes} исходных · "
                f"Линий: {len(drawable)} / {len(self._relations)} агрегированных · "
                f"Исходных связей: {projection.source_edges} · "
                f"Зон: {len(self.zone_items)}"
                + (f" · Замечаний: {len(self.graph.warnings)}" if self.graph.warnings else "")
                + (
                    f" · Линии {self._edge_offset + 1}–{self._edge_offset + len(drawable)}"
                    f" из {total_lines}; все доступны в списке справа"
                    if total_lines > len(drawable)
                    else ""
                )
            )
            self.status.setText(self._base_status)
            self.status.setToolTip("\n".join(self.graph.warnings))
            current_keys = {self.zone_key(node) for node in self.graph.nodes}
            unused = {key: value for key, value in self.zone_labels.items() if key not in current_keys}
            if unused:
                self._base_status += f" · Подписей прежней группировки: {len(unused)}"
                self.status.setText(self._base_status)
                self.status.setToolTip(
                    self.status.toolTip() + "\nРанее сохранённые подписи:\n"
                    + "\n".join(f"{key}: {value}" for key, value in unused.items())
                )
            self.details.setPlainText(
                "Выберите устройство или линию связи.\n\n"
                "Группы адресов /24 и /64 — представление, не доказательство VLAN или общей сети.\n"
                "Двойной щелчок по зоне сворачивает её.\n\n" + "\n".join(self.graph.warnings)
            )
        finally:
            self._building = False
        self._last_view_key = (
            self.graph.project_id, self.presentation.currentData(), self.search.text(),
            self.zone_selector.currentData(), self.edge_filter.currentData(),
            self._focus_node, self._drill_members, frozenset(self.collapsed),
            self.node_limit.value(), self.line_limit.value(), self._edge_offset,
            self.conditions.query, self.conditions.include_unknown,
        )
        if self._layouts.changed and self.graph.project_id:
            self._layouts.changed = False
            self.view_settings_changed.emit(self._view_settings())
        if self._focus_node is not None and self._focus_node in self.node_items:
            self.node_items[self._focus_node].setSelected(True)
        # Fit after Qt has laid out the active page, not the previous mode.
        self._fit_timer.start(0)

    def _selected(self) -> None:
        if self._building or self._selecting:
            return
        selected = self.scene.selectedItems()
        if not selected:
            focused = self.node_items.get(self._focus_node) if self._focus_node else None
            if focused is not None:
                focused.setSelected(True)
                return
            for icon in self.node_items.values():
                icon.setOpacity(1)
                icon.setVisible(True)
            for line in self.edge_items:
                line.setOpacity(1)
                line.setVisible(True)
            for region in self.scene.items():
                if isinstance(region, MapRegionItem):
                    region.setVisible(True)
            return
        item = selected[0]
        if isinstance(item, ProjectIconItem):
            node = item.node
            if self._focus_node != node.key:
                self._focus_history.append((self._focus_node, str(self.presentation.currentData())))
                self._focus_node = node.key
                self._edge_offset = 0
                self._render_timer.start(0)
                return
            lines = [node.label, *node.addresses, "", *node.details]
            active_nodes = {node.key}
            active_members = set(self._render_members.get(node.key, (node.key,)))
            connected = [
                edge
                for edge in self._relations
                if edge.source in active_nodes
                or edge.target in active_nodes
                or any(rule.owner_id in active_members for rule in edge.rules)
            ]
            lines.append(f"\nСвязей: {len(connected)}")
            for edge in connected:
                active_nodes.update((edge.source, edge.target))
                for rule in edge.rules:
                    lines.append(f"{rule.name}: {rule.source} → {rule.destination} · {rule.action}")
            for icon in self.node_items.values():
                icon.setVisible(icon.node.key in active_nodes)
            for line in self.edge_items:
                line.setVisible(line.edge in connected)
        elif isinstance(item, ProjectEdgeItem):
            edge = item.edge
            if edge in self.interaction_model.edges:
                self.interactions.selectRow(self.interaction_model.edges.index(edge))
            lines = [
                "Связь по условиям ACL" if edge.kind == "acl"
                else "Неразобранные условия правила" if edge.kind == "condition"
                else "Структура / принадлежность",
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
                        f"Направление: {rule.direction or 'не указано'}",
                        f"Условия: {rule.status} · {rule.location}",
                        *rule.details,
                    )
                )
            for line in self.edge_items:
                line.setVisible(line is item)
            for icon in self.node_items.values():
                icon.setVisible(
                    icon.node.key in (edge.source, edge.target)
                    or any(rule.owner_id == icon.node.key for rule in edge.rules)
                )
        else:
            return
        self.details.setPlainText("\n".join(lines))
        for region in self.scene.items():
            if isinstance(region, MapRegionItem):
                region.setVisible(False)
        bounds = QRectF()
        for graphic in (*self.node_items.values(), *self.edge_items):
            if graphic.isVisible():
                bounds = bounds.united(graphic.sceneBoundingRect())
        if not bounds.isNull():
            self.scene.setSceneRect(bounds.adjusted(-30, -30, 30, 30))
        self.properties_button.setChecked(True)

    def _open_selected_rules(self) -> None:
        selected = self.scene.selectedItems()
        rules: list[str] = []
        for item in selected:
            if isinstance(item, ProjectEdgeItem):
                rules.extend(rule.rule_id for rule in item.edge.rules)
            elif isinstance(item, ProjectIconItem):
                rules.extend(
                    rule.rule_id
                    for edge in self.graph.edges
                    for rule in edge.rules
                    if rule.owner_id == item.node.key
                )
        if rules:
            self.rules_requested.emit(tuple(dict.fromkeys(rules)))
