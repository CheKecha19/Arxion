"""Desktop adapter for the existing revision-scoped ACL map projection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from math import ceil, hypot, isfinite
from pathlib import Path
from typing import Literal

from PySide6.QtCore import (
    QByteArray,
    QIODevice,
    QObject,
    QPoint,
    QPointF,
    QRectF,
    QSaveFile,
    QTimer,
    Qt,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QImage,
    QImageWriter,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPainterPathStroker,
    QPen,
    QPolygonF,
    QWheelEvent,
)
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStyleOptionGraphicsItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.analysis.acl_map import AclMapFilter, build_acl_map, filter_acl_relations
from firewall_compliance.application.acl_map import export_acl_map_html
from firewall_compliance.domain.acl_map import AclMap, AclMapNode, AclMapRelation
from firewall_compliance.domain.enums import RuleAction
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.backend import AnalysisSession
from firewall_compliance.interfaces.desktop.qt_theme import COLORS

CONFIGURED_POLICY_LABEL = "Заданные условия ACL (configured policy)"


class AclMapNodeItem(QGraphicsObject):
    """Movable presentation of one declared condition with its original identity.

    Moving or selecting this item changes presentation only. Its domain node is
    immutable; no policy evaluation or reachability is performed here.
    """

    geometry_changed = Signal()

    def __init__(
        self,
        node: AclMapNode,
        parent: QGraphicsItem | None = None,
    ) -> None:
        if not isinstance(node, AclMapNode):
            raise TypeError("ACL map item requires an AclMapNode")
        super().__init__(parent)
        self._node = node
        if node.endpoint is not None:
            self._label = node.endpoint.name
            self._type_label = f"Адресный объект · {node.endpoint.kind.value}"
            detail = f"Статус данных: {node.endpoint.resolution_status.value}"
        elif node.service is not None:
            self._label = node.service.name
            self._type_label = f"Сервис · {node.service.protocol.value}"
            detail = f"Статус данных: {node.service.resolution_status.value}"
        else:
            dimension = {
                "source": "источник",
                "destination": "назначение",
                "service": "сервис",
            }.get(node.unknown_dimension or "", "условие")
            self._label = f"Неизвестно: {dimension}"
            self._type_label = "Неизвестное условие"
            detail = "Значение условия недоступно"
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemIsMovable
            | QGraphicsItem.GraphicsItemFlag.ItemIsFocusable
            | QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
            | QGraphicsItem.GraphicsItemFlag.ItemSendsScenePositionChanges
        )
        self.setData(int(Qt.ItemDataRole.UserRole), node.node_id)
        # Explicit rich-text escaping preserves literal names, including '<'.
        self.setToolTip(
            "<qt>"
            + "<br/>".join(
                escape(line)
                for line in (
                    self._label,
                    self._type_label,
                    detail,
                    f"ID: {node.node_id}",
                    CONFIGURED_POLICY_LABEL,
                    "Узел условия правила; достижимость не вычисляется.",
                )
            )
            + "</qt>"
        )

    @property
    def node(self) -> AclMapNode:
        """The unchanged domain node, including its durable node_id."""
        return self._node

    @property
    def node_id(self) -> str:
        return self._node.node_id

    @property
    def label(self) -> str:
        return self._label

    def boundingRect(self) -> QRectF:
        return QRectF(-2.0, -2.0, 244.0, 88.0)

    def itemChange(
        self,
        change: QGraphicsItem.GraphicsItemChange,
        value: object,
    ) -> object:
        result = super().itemChange(change, value)
        if change == QGraphicsItem.GraphicsItemChange.ItemScenePositionHasChanged:
            self.geometry_changed.emit()
        return result

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionGraphicsItem,
        widget: QWidget | None = None,
    ) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        border = QPen(QColor(COLORS["blue" if self.isSelected() else "muted"]))
        border.setWidthF(2.0 if self.isSelected() else 1.0)
        if self.hasFocus():
            border.setStyle(Qt.PenStyle.DashLine)
        painter.setPen(border)
        painter.setBrush(QColor(COLORS["raised" if self.isSelected() else "panel"]))
        painter.drawRoundedRect(QRectF(0.0, 0.0, 240.0, 84.0), 10.0, 10.0)
        painter.setPen(QColor(COLORS["text"]))
        label = painter.fontMetrics().elidedText(self._label, Qt.TextElideMode.ElideRight, 216)
        painter.drawText(QRectF(12.0, 10.0, 216.0, 30.0), Qt.AlignmentFlag.AlignVCenter, label)
        painter.setPen(QColor(COLORS["muted"]))
        kind = painter.fontMetrics().elidedText(
            self._type_label,
            Qt.TextElideMode.ElideRight,
            216,
        )
        painter.drawText(QRectF(12.0, 43.0, 216.0, 28.0), Qt.AlignmentFlag.AlignVCenter, kind)
        painter.restore()


class AclMapRelationJunctionItem(QGraphicsObject):
    """Presentation-only rule junction, never a fabricated domain/network node."""

    geometry_changed = Signal()

    def __init__(self, relation: AclMapRelation) -> None:
        super().__init__()
        self._relation = relation
        rule = relation.rule
        enabled = "включено" if rule.enabled else "× ОТКЛЮЧЕНО"
        action = rule.action.value.upper() + (" ?" if rule.action == RuleAction.UNKNOWN else "")
        condition = relation.condition_status + (
            " ?" if relation.condition_status != "known" else ""
        )
        self._lines = (
            f"Узел правила ACL: {rule.name}",
            f"{action} · {enabled} · {condition}",
            f"Ист. {len(relation.source_node_ids)} · назн. "
            f"{len(relation.destination_node_ids)} · серв. {len(relation.service_node_ids)}",
        )
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemIsMovable
            | QGraphicsItem.GraphicsItemFlag.ItemIsFocusable
            | QGraphicsItem.GraphicsItemFlag.ItemSendsScenePositionChanges
        )
        self.setData(int(Qt.ItemDataRole.UserRole), relation.relation_id)
        self.setData(int(Qt.ItemDataRole.UserRole) + 1, rule.rule_id)
        self.setData(int(Qt.ItemDataRole.UserRole) + 2, str(rule.configuration_id))
        self.setData(
            int(Qt.ItemDataRole.UserRole) + 3, rule.source_location.model_dump(mode="json")
        )
        self.setData(
            int(Qt.ItemDataRole.UserRole) + 4,
            {
                "source_node_ids": list(relation.source_node_ids),
                "destination_node_ids": list(relation.destination_node_ids),
                "service_node_ids": list(relation.service_node_ids),
            },
        )
        self.setToolTip(
            "<qt>"
            + "<br/>".join(
                escape(line)
                for line in (
                    CONFIGURED_POLICY_LABEL,
                    *self._lines,
                    "Визуальное объединение условий правила; не сетевое устройство.",
                    f"Relation ID: {relation.relation_id}",
                    f"Rule ID: {rule.rule_id}; configuration ID: {rule.configuration_id}",
                    f"Source: {rule.source_location.model_dump_json()}",
                    f"Source nodes: {', '.join(relation.source_node_ids)}",
                    f"Destination nodes: {', '.join(relation.destination_node_ids)}",
                    f"Service nodes: {', '.join(relation.service_node_ids)}",
                    f"Policy: {rule.policy_id}; direction: {rule.policy_direction}",
                    f"Zones: {rule.source_zone} → {rule.destination_zone}",
                )
            )
            + "</qt>"
        )

    @property
    def relation(self) -> AclMapRelation:
        return self._relation

    @property
    def relation_id(self) -> str:
        return self._relation.relation_id

    def boundingRect(self) -> QRectF:
        return QRectF(-2.0, -2.0, 354.0, 88.0)

    def itemChange(
        self,
        change: QGraphicsItem.GraphicsItemChange,
        value: object,
    ) -> object:
        result = super().itemChange(change, value)
        if change == QGraphicsItem.GraphicsItemChange.ItemScenePositionHasChanged:
            self.geometry_changed.emit()
        return result

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionGraphicsItem,
        widget: QWidget | None = None,
    ) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor(COLORS["purple"]), 2.0))
        painter.setBrush(QColor(COLORS["raised" if self.isSelected() else "panel"]))
        painter.drawRoundedRect(QRectF(0.0, 0.0, 350.0, 84.0), 18.0, 18.0)
        painter.setPen(QColor(COLORS["text"]))
        for index, line in enumerate(self._lines):
            label = painter.fontMetrics().elidedText(line, Qt.TextElideMode.ElideRight, 326)
            painter.drawText(
                QRectF(12.0, 6.0 + index * 24.0, 326.0, 24.0),
                Qt.AlignmentFlag.AlignVCenter,
                label,
            )
        painter.restore()


class AclMapEdgeItem(QGraphicsObject):
    """One visual segment of a declared-rule relation, retaining the hyperedge.

    A segment connects participating condition nodes, never an inferred network
    hop. All source, destination and service memberships remain on the relation.
    Multiple segments may deliberately share the same durable relation_id.
    """

    def __init__(
        self,
        relation: AclMapRelation,
        source: AclMapNodeItem | AclMapRelationJunctionItem,
        destination: AclMapNodeItem | AclMapRelationJunctionItem,
        parent: QGraphicsItem | None = None,
        *,
        show_label: bool = True,
    ) -> None:
        if not isinstance(relation, AclMapRelation):
            raise TypeError("ACL map edge requires an AclMapRelation")
        members = (
            *relation.source_node_ids,
            *relation.destination_node_ids,
            *relation.service_node_ids,
        )
        for item in (source, destination):
            if isinstance(item, AclMapNodeItem):
                if item.node_id not in members:
                    raise ValueError("ACL map edge endpoints must belong to its relation")
            elif isinstance(item, AclMapRelationJunctionItem):
                if item.relation != relation:
                    raise ValueError("ACL map junction must represent the same relation")
            else:
                raise TypeError("ACL map edge requires a condition node or rule junction")
        super().__init__(parent)
        self._relation = relation
        self.source_item = source
        self.destination_item = destination
        self._show_label = show_label
        rule = relation.rule
        status = "включено" if rule.enabled else "× ОТКЛЮЧЕНО"
        action = rule.action.value.upper() + (" ?" if rule.action == RuleAction.UNKNOWN else "")
        condition = relation.condition_status + (
            " ?" if relation.condition_status != "known" else ""
        )
        self._label = f"{action} · {status} · {condition}"
        self._conditions_label = (
            f"Условия: ист. {len(relation.source_node_ids)} · "
            f"назн. {len(relation.destination_node_ids)} · "
            f"серв. {len(relation.service_node_ids)}"
        )
        self._color = QColor(COLORS["blue"])
        self._line_style = Qt.PenStyle.SolidLine
        if rule.action in {RuleAction.DENY, RuleAction.REJECT, RuleAction.DROP}:
            self._color = QColor("#F28B82")
        if rule.action == RuleAction.UNKNOWN or relation.condition_status != "known":
            self._color = QColor("#F2C66D")
            self._line_style = Qt.PenStyle.DotLine
        if not rule.enabled:
            self._color = QColor(COLORS["muted"])
            self._line_style = Qt.PenStyle.DashLine
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemIsFocusable
        )
        self.setZValue(-1.0)
        role = int(Qt.ItemDataRole.UserRole)
        self.setData(role, relation.relation_id)
        self.setData(role + 1, rule.rule_id)
        self.setData(role + 2, str(rule.configuration_id))
        self.setData(role + 3, rule.source_location.model_dump(mode="json"))
        self.setData(
            role + 4,
            {
                "source_node_ids": list(relation.source_node_ids),
                "destination_node_ids": list(relation.destination_node_ids),
                "service_node_ids": list(relation.service_node_ids),
            },
        )
        self.setToolTip(
            "<qt>"
            + "<br/>".join(
                escape(line)
                for line in (
                    CONFIGURED_POLICY_LABEL,
                    rule.name,
                    self._label,
                    self._conditions_label,
                    f"Relation ID: {relation.relation_id}",
                    f"Rule ID: {rule.rule_id}",
                    f"Configuration ID: {rule.configuration_id}",
                    f"Source: {rule.source_location.model_dump_json()}",
                    f"Source nodes: {', '.join(relation.source_node_ids)}",
                    f"Destination nodes: {', '.join(relation.destination_node_ids)}",
                    f"Service nodes: {', '.join(relation.service_node_ids)}",
                    f"Policy: {rule.policy_id}; direction: {rule.policy_direction}",
                    f"Zones: {rule.source_zone} → {rule.destination_zone}",
                    "Стрелка связывает условия правила; маршрут и достижимость не вычисляются.",
                )
            )
            + "</qt>"
        )
        self._path = QPainterPath()
        self._arrow = QPolygonF()
        self._label_rect = QRectF()
        self._hit_shape = QPainterPath()
        source.geometry_changed.connect(self.update_geometry)
        if destination is not source:
            destination.geometry_changed.connect(self.update_geometry)
        self.update_geometry()

    @property
    def relation(self) -> AclMapRelation:
        return self._relation

    @property
    def relation_id(self) -> str:
        return self._relation.relation_id

    def update_geometry(self) -> None:
        """Rebuild local geometry from current scene positions, presentation only."""
        source_rect = self.source_item.sceneBoundingRect()
        destination_rect = self.destination_item.sceneBoundingRect()
        source = source_rect.center()
        destination = destination_rect.center()
        delta = destination - source
        source_extent = max(
            abs(delta.x()) / (source_rect.width() / 2.0),
            abs(delta.y()) / (source_rect.height() / 2.0),
        )
        destination_extent = max(
            abs(delta.x()) / (destination_rect.width() / 2.0),
            abs(delta.y()) / (destination_rect.height() / 2.0),
        )
        path = QPainterPath()
        if (
            self.source_item is self.destination_item
            or min(source_extent, destination_extent) < 2.0
        ):
            # A visible loop also avoids undefined tangents for coincident nodes.
            start = self.mapFromScene(QPointF(source_rect.right(), source.y()))
            end = self.mapFromScene(QPointF(destination.x(), destination_rect.top()))
            path.moveTo(start)
            path.cubicTo(start + QPointF(100.0, -120.0), end + QPointF(0.0, -120.0), end)
        else:
            start = self.mapFromScene(source + delta / source_extent)
            end = self.mapFromScene(destination - delta / destination_extent)
            bend = max(40.0, abs(end.x() - start.x()) / 2.0)
            sign = 1.0 if end.x() >= start.x() else -1.0
            path.moveTo(start)
            path.cubicTo(start + QPointF(sign * bend, 0.0), end - QPointF(sign * bend, 0.0), end)
        tangent = end - path.pointAtPercent(0.97)
        length = hypot(tangent.x(), tangent.y())
        direction = tangent / length if length > 0.001 else QPointF(1.0, 0.0)
        normal = QPointF(-direction.y(), direction.x())
        arrow = QPolygonF(
            [
                end,
                end - direction * 12.0 + normal * 6.0,
                end - direction * 12.0 - normal * 6.0,
            ]
        )
        middle = path.pointAtPercent(0.5)
        label_rect = (
            QRectF(middle.x() - 175.0, middle.y() - 27.0, 350.0, 54.0)
            if self._show_label
            else QRectF()
        )
        stroker = QPainterPathStroker()
        stroker.setWidth(16.0)
        hit_shape = stroker.createStroke(path)
        arrow_shape = QPainterPath()
        arrow_shape.addPolygon(arrow)
        label_shape = QPainterPath()
        if self._show_label:
            label_shape.addRect(label_rect)
        hit_shape = hit_shape.united(arrow_shape).united(label_shape)
        self.prepareGeometryChange()
        self._path = path
        self._arrow = arrow
        self._label_rect = label_rect
        self._hit_shape = hit_shape.simplified()
        self.update()

    def boundingRect(self) -> QRectF:
        return self._hit_shape.boundingRect().adjusted(-3.0, -3.0, 3.0, 3.0)

    def shape(self) -> QPainterPath:
        return self._hit_shape

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionGraphicsItem,
        widget: QWidget | None = None,
    ) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.isSelected() or self.hasFocus():
            painter.setPen(QPen(QColor(COLORS["purple"]), 7.0))
            painter.drawPath(self._path)
        pen = QPen(self._color, 2.0)
        pen.setStyle(self._line_style)
        painter.setPen(pen)
        painter.drawPath(self._path)
        painter.setBrush(self._color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPolygon(self._arrow)
        if not self._show_label:
            painter.restore()
            return
        painter.setPen(QPen(self._color, 1.0))
        painter.setBrush(QColor(COLORS["panel"]))
        painter.drawRoundedRect(self._label_rect, 6.0, 6.0)
        painter.setPen(QColor(COLORS["text"]))
        for offset, text in ((4.0, self._label), (27.0, self._conditions_label)):
            line_rect = QRectF(
                self._label_rect.x() + 8.0,
                self._label_rect.y() + offset,
                334.0,
                23.0,
            )
            label = painter.fontMetrics().elidedText(text, Qt.TextElideMode.ElideRight, 334)
            painter.drawText(line_rect, Qt.AlignmentFlag.AlignCenter, label)
        painter.restore()


@dataclass(frozen=True, slots=True)
class AclMapState:
    """Map snapshot and safe display state without effective-path claims."""

    status: Literal["empty", "ready", "partial", "unsupported", "invalid"]
    graph: AclMap | None
    message: str
    label: str = CONFIGURED_POLICY_LABEL
    revision: DeviceRevision | None = None


class AclMapScene(QGraphicsScene):
    """Bounded, deterministic presentation of the existing ACL projection.

    Hyperedges use source/service → rule junction → destination spokes: O(total
    memberships), with no Cartesian pairs or invented physical network links.
    The full input state stays available even when rendering is budget-limited.
    """

    MAX_NODES = 500
    MAX_RELATIONS = 300
    MAX_SEGMENTS = 1500

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.state: AclMapState | None = None
        self.render_status: Literal[
            "empty",
            "ready",
            "partial",
            "unsupported",
            "invalid",
            "limited",
        ] = "empty"
        self.diagnostic = ""
        self.node_items: dict[str, AclMapNodeItem] = {}
        self.relation_items: dict[str, AclMapRelationJunctionItem] = {}
        self.edge_items: list[AclMapEdgeItem] = []

    def _show_message(self, message: str) -> None:
        item = self.addText(message)
        item.setDefaultTextColor(QColor(COLORS["text"]))
        item.setTextWidth(960.0)
        self.setSceneRect(self.itemsBoundingRect().adjusted(-32.0, -32.0, 32.0, 32.0))

    def set_map_state(
        self, state: AclMapState, *, filters: AclMapFilter | None = None,
        relation_ids: frozenset[str] | None = None,
    ) -> None:
        """Replace the entire presentation; never retain an earlier graph."""
        if not isinstance(state, AclMapState):
            raise TypeError("ACL map scene requires an AclMapState")
        # Delete segments before their endpoints so connected slots cannot see
        # an already-deleted C++ graphics item during scene teardown.
        for edge in self.edge_items:
            edge.source_item.geometry_changed.disconnect(edge.update_geometry)
            if edge.destination_item is not edge.source_item:
                edge.destination_item.geometry_changed.disconnect(edge.update_geometry)
        self.edge_items.clear()
        self.node_items.clear()
        self.relation_items.clear()
        self.clear()
        self.setSceneRect(QRectF())
        self.state = state
        self.render_status = state.status
        self.diagnostic = state.message
        graph = state.graph
        if state.status in {"empty", "invalid", "unsupported"} or graph is None:
            if state.status in {"ready", "partial"}:
                self.render_status = "invalid"
                self.diagnostic = "Данные карты недоступны; карта не построена."
            self._show_message(f"{state.label}\n{self.diagnostic}")
            return
        selected_relations = (
            filter_acl_relations(graph, filters) if filters is not None else graph.relations
        )
        if relation_ids is not None:
            selected_relations = tuple(
                relation for relation in selected_relations if relation.relation_id in relation_ids
            )
        referenced_ids = {
            node_id
            for relation in selected_relations
            for node_id in (
                *relation.source_node_ids,
                *relation.destination_node_ids,
                *relation.service_node_ids,
            )
        }
        selected_nodes = (
            tuple(node for node in graph.nodes if node.node_id in referenced_ids)
            if filters is not None or relation_ids is not None
            else graph.nodes
        )
        segment_count = sum(
            len(set(relation.source_node_ids))
            + len(set(relation.destination_node_ids))
            + len(set(relation.service_node_ids))
            for relation in selected_relations
        )
        if (
            len(selected_nodes) > self.MAX_NODES
            or len(selected_relations) > self.MAX_RELATIONS
            or segment_count > self.MAX_SEGMENTS
        ):
            self.render_status = "limited"
            self.diagnostic = (
                "Отображение ограничено бюджетом: "
                f"узлов {len(selected_nodes)}/{self.MAX_NODES}, "
                f"правил {len(selected_relations)}/{self.MAX_RELATIONS}, "
                f"сегментов {segment_count}/{self.MAX_SEGMENTS}. "
                "Граф не отрисован; полные условия сохранены в данных карты. "
                "Это не свидетельствует об отсутствии правил или достижимости."
            )
            self._show_message(f"{state.label}\n{self.diagnostic}\n{state.message}")
            return
        node_ids = {node.node_id for node in graph.nodes}
        if len(node_ids) != len(graph.nodes) or any(
            node_id not in node_ids
            for relation in graph.relations
            for node_id in (
                *relation.source_node_ids,
                *relation.destination_node_ids,
                *relation.service_node_ids,
            )
        ):
            self.render_status = "invalid"
            self.diagnostic = "Идентификаторы условий карты несогласованы; карта не построена."
            self._show_message(f"{state.label}\n{self.diagnostic}")
            return
        banner = self.addText(
            "\n".join(
                (
                    "Связи по правилам",
                    state.label,
                    state.message,
                    f"Ревизия: {graph.revision.revision_id}; "
                    f"устройство: {graph.revision.device.device_id}",
                    f"Источник: {graph.revision.parse_result.configuration.source_name}; "
                    f"SHA-256: {graph.revision.parse_result.configuration.content_sha256}",
                    f"Выбрано правил: {len(selected_relations)} из {len(graph.relations)}",
                    "Фокус на части правил; полный набор доступен в списке и HTML."
                    if relation_ids is not None else "Полный вид с учётом фильтров.",
                    *(
                        ("Фильтры: " + filters.model_dump_json(exclude_none=True),)
                        if filters is not None
                        else ()
                    ),
                    "Узел правила ACL объединяет условия, а не обозначает устройство. "
                    "Стрелки: источник/сервис → правило → назначение.",
                    *graph.limitations,
                )
            )
        )
        banner.setDefaultTextColor(QColor(COLORS["text"]))
        banner.setTextWidth(1160.0)
        top = banner.boundingRect().height() + 48.0
        relations = sorted(selected_relations, key=lambda item: item.relation_id)
        lanes: dict[tuple[str, str, str, str], list[AclMapRelation]] = {}
        for relation in relations:
            rule = relation.rule
            lane: tuple[str, str, str, str] = (
                rule.policy_id or "",
                rule.policy_direction or "",
                rule.source_zone or "",
                rule.destination_zone or "",
            )
            lanes.setdefault(lane, []).append(relation)
        node_lanes: dict[str, tuple[str, str, str, str]] = {}
        source_ids: set[str] = set()
        service_ids: set[str] = set()
        for lane in sorted(lanes):
            for relation in lanes[lane]:
                source_ids.update(relation.source_node_ids)
                service_ids.update(relation.service_node_ids)
                for node_id in (
                    *relation.source_node_ids,
                    *relation.destination_node_ids,
                    *relation.service_node_ids,
                ):
                    node_lanes.setdefault(node_id, lane)
        # Preserve every domain node, including an unconnected condition should
        # a future projection carry one. This lane is presentation only.
        orphan_lane = ("Условия без связей", "", "", "")
        if any(node.node_id not in node_lanes for node in selected_nodes):
            lanes.setdefault(orphan_lane, [])
        nodes_by_id = {node.node_id: node for node in selected_nodes}
        for lane in sorted(lanes):
            lane_nodes = sorted(
                node_id for node_id in nodes_by_id if node_lanes.get(node_id, orphan_lane) == lane
            )
            left_nodes = [node_id for node_id in lane_nodes if node_id in source_ids | service_ids]
            right_nodes = [
                node_id for node_id in lane_nodes if node_id not in source_ids | service_ids
            ]
            heading = self.addText(
                f"Политика: {lane[0] or 'не задана'} · "
                f"направление: {lane[1] or 'неизвестно'} · "
                f"зоны: {lane[2] or '?'} → {lane[3] or '?'}"
            )
            heading.setDefaultTextColor(QColor(COLORS["muted"]))
            heading.setTextWidth(1400.0)
            heading.setPos(0.0, top)
            top += heading.boundingRect().height() + 24.0
            for x, node_group in ((0.0, left_nodes), (1120.0, right_nodes)):
                for index, node_id in enumerate(node_group):
                    node_item = AclMapNodeItem(nodes_by_id[node_id])
                    self.addItem(node_item)
                    node_item.setPos(x, top + float(index) * 140.0)
                    self.node_items[node_id] = node_item
            for index, relation in enumerate(lanes[lane]):
                junction = AclMapRelationJunctionItem(relation)
                self.addItem(junction)
                junction.setPos(520.0, top + float(index) * 140.0)
                self.relation_items[relation.relation_id] = junction
            top += float(max(len(left_nodes), len(right_nodes), len(lanes[lane]), 1)) * 140.0 + 48.0
        for relation in relations:
            junction = self.relation_items[relation.relation_id]
            for dimension, members in (
                ("source", relation.source_node_ids),
                ("service", relation.service_node_ids),
                ("destination", relation.destination_node_ids),
            ):
                for node_id in sorted(set(members)):
                    node_item = self.node_items[node_id]
                    source, destination = (
                        (junction, node_item)
                        if dimension == "destination"
                        else (node_item, junction)
                    )
                    edge = AclMapEdgeItem(relation, source, destination, show_label=False)
                    edge.setData(int(Qt.ItemDataRole.UserRole) + 5, dimension)
                    edge.setToolTip(
                        edge.toolTip().replace("</qt>", f"<br/>Измерение: {dimension}</qt>")
                    )
                    self.addItem(edge)
                    self.edge_items.append(edge)
        self.setSceneRect(self.itemsBoundingRect().adjusted(-48.0, -48.0, 48.0, 48.0))


class AclMapView(QGraphicsView):
    """Local canvas gestures; text-input keyboard handling stays untouched."""

    MIN_ZOOM = 0.08
    MAX_ZOOM = 4.0
    ZOOM_STEP = 1.2

    def __init__(self, scene: QGraphicsScene, parent: QWidget | None = None) -> None:
        super().__init__(scene, parent)
        self._pan_position: QPoint | None = None
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        # Zoom is anchored explicitly at a wheel event's position, avoiding
        # dependence on the last hover event or toolbar focus.
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.NoAnchor)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setAccessibleDescription(
            "Колесо — масштаб под указателем; средняя кнопка — перемещение. "
            "При фокусе карты: + приблизить, - отдалить, 0 вписать."
        )

    def _zoom(self, factor: float, anchor: QPoint | None = None) -> None:
        current = self.transform().m11()
        if current <= 0.0:
            return
        target = min(self.MAX_ZOOM, max(self.MIN_ZOOM, current * factor))
        point = anchor if anchor is not None else self.viewport().rect().center()
        before = self.mapToScene(point)
        self.scale(target / current, target / current)
        after = self.mapToScene(point)
        delta = after - before
        self.translate(delta.x(), delta.y())

    def zoom_in(self) -> None:
        self._zoom(self.ZOOM_STEP)

    def zoom_out(self) -> None:
        self._zoom(1.0 / self.ZOOM_STEP)

    def fit_map(self) -> None:
        self._fit_scene(self.scene())

    def _fit_scene(self, scene: QGraphicsScene | None) -> None:
        # Qt permits setScene(None), although its scene() stub omits nullability.
        if scene is None:
            return
        bounds = QRectF()
        for item in scene.items():
            if item.isVisible():
                bounds = bounds.united(item.sceneBoundingRect())
        bounds = bounds.adjusted(-32.0, -32.0, 32.0, 32.0)
        if bounds.isEmpty():
            return
        self.resetTransform()
        self.fitInView(bounds, Qt.AspectRatioMode.KeepAspectRatio)
        # A huge scene still respects the same readable zoom limits. Scrollbars
        # provide access to the remainder if fitting would exceed the minimum.
        self._zoom(1.0)
        self.centerOn(bounds.center())

    def wheelEvent(self, event: QWheelEvent) -> None:
        if event.modifiers() != Qt.KeyboardModifier.NoModifier:
            super().wheelEvent(event)
            return
        delta = event.angleDelta().y() or event.pixelDelta().y()
        if delta == 0:
            super().wheelEvent(event)
            return
        steps = min(4.0, max(-4.0, delta / 120.0))
        self._zoom(self.ZOOM_STEP**steps, event.position().toPoint())
        event.accept()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if (
            event.button() == Qt.MouseButton.MiddleButton
            and event.modifiers() == Qt.KeyboardModifier.NoModifier
        ):
            self._pan_position = event.position().toPoint()
            self.viewport().setCursor(Qt.CursorShape.ClosedHandCursor)
            self.setFocus(Qt.FocusReason.MouseFocusReason)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._pan_position is not None:
            if not event.buttons() & Qt.MouseButton.MiddleButton:
                self._pan_position = None
                self.viewport().unsetCursor()
                super().mouseMoveEvent(event)
                return
            position = event.position().toPoint()
            delta = position - self._pan_position
            self._pan_position = position
            horizontal = self.horizontalScrollBar()
            vertical = self.verticalScrollBar()
            horizontal.setValue(horizontal.value() - delta.x())
            vertical.setValue(vertical.value() - delta.y())
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.MiddleButton and self._pan_position is not None:
            self._pan_position = None
            self.viewport().unsetCursor()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        # This handler belongs only to the canvas; no window-wide shortcuts
        # consume typing in searches, selectors or the details panel.
        modifiers = event.modifiers()
        if (
            modifiers in {Qt.KeyboardModifier.NoModifier, Qt.KeyboardModifier.ShiftModifier}
            and event.key() == Qt.Key.Key_Plus
        ):
            self.zoom_in()
            event.accept()
            return
        if modifiers == Qt.KeyboardModifier.NoModifier:
            if event.key() == Qt.Key.Key_Minus:
                self.zoom_out()
                event.accept()
                return
            if event.key() == Qt.Key.Key_0:
                self.fit_map()
                event.accept()
                return
        super().keyPressEvent(event)


class AclMapWidget(QWidget):
    """Configured-policy canvas and plain-text, canonical selection details."""

    MAX_PNG_PIXELS = 16_000_000
    MAX_PNG_DIMENSION = 16_384

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state: AclMapState | None = None
        self._graph: AclMap | None = None
        self._nodes: dict[str, AclMapNode] = {}
        self._relations: dict[str, AclMapRelation] = {}
        self._node_references: dict[str, list[tuple[AclMapRelation, str]]] = {}
        self._updating = False
        self.filters: AclMapFilter | None = None
        self._focused_relations: frozenset[str] | None = None
        self._focus_history: list[frozenset[str] | None] = []
        self._pending_focus: frozenset[str] | None = None
        self._focus_timer = QTimer(self)
        self._focus_timer.setSingleShot(True)
        self._focus_timer.timeout.connect(self._apply_pending_focus)
        layout = QVBoxLayout(self)
        self.mode_label = QLabel("Связи по правилам", self)
        self.mode_label.setTextFormat(Qt.TextFormat.PlainText)
        self.mode_label.setAccessibleName("Режим карты: связи по правилам")
        layout.addWidget(self.mode_label)
        self.status_label = QLabel(self)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.status_label)
        filter_row = QHBoxLayout()
        self.source_filter = QLineEdit(self)
        self.source_filter.setPlaceholderText("Источник: IP / CIDR")
        self.source_filter.setAccessibleName("Фильтр источника IP или CIDR")
        self.destination_filter = QLineEdit(self)
        self.destination_filter.setPlaceholderText("Назначение: IP / CIDR")
        self.destination_filter.setAccessibleName("Фильтр назначения IP или CIDR")
        self.protocol_filter = QComboBox(self)
        self.protocol_filter.setAccessibleName("Фильтр протокола")
        self.protocol_filter.addItem("Любой протокол", None)
        for protocol in ("tcp", "udp", "icmp", "ip"):
            self.protocol_filter.addItem(protocol.upper(), protocol)
        self.port_filter = QLineEdit(self)
        self.port_filter.setPlaceholderText("Порт 1–65535")
        self.port_filter.setMaximumWidth(140)
        self.port_filter.setAccessibleName("Фильтр порта назначения")
        for control in (
            self.source_filter,
            self.destination_filter,
            self.protocol_filter,
            self.port_filter,
        ):
            filter_row.addWidget(control)
        layout.addLayout(filter_row)
        filter_actions = QHBoxLayout()
        self.unknown_filter = QCheckBox("Показывать неизвестные условия", self)
        self.unknown_filter.setChecked(True)
        layout.addWidget(self.unknown_filter)
        self.apply_filters_button = QPushButton("Применить фильтры", self)
        self.reset_filters_button = QPushButton("Сбросить", self)
        self.html_export_button = QPushButton("Экспорт HTML", self)
        self.png_export_button = QPushButton("Экспорт PNG", self)
        self.apply_filters_button.clicked.connect(self._apply_filter_controls)
        self.reset_filters_button.clicked.connect(self.reset_filters)
        self.html_export_button.clicked.connect(lambda: self._export_dialog("html"))
        self.png_export_button.clicked.connect(lambda: self._export_dialog("png"))
        for action_control in (
            self.apply_filters_button,
            self.reset_filters_button,
            self.html_export_button,
            self.png_export_button,
        ):
            filter_actions.addWidget(action_control)
        filter_actions.addStretch(1)
        layout.addLayout(filter_actions)
        self.scene = AclMapScene(self)
        self.view = AclMapView(self.scene, self)
        self.view.setAccessibleName("Карта заданных условий ACL")
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.view.setMinimumSize(360, 260)
        toolbar = QHBoxLayout()
        self.zoom_in_button = QPushButton("Приблизить", self)
        self.zoom_in_button.setAccessibleName("Приблизить карту")
        self.zoom_in_button.setToolTip("Приблизить (+ при фокусе карты)")
        self.zoom_in_button.clicked.connect(self.view.zoom_in)
        self.zoom_out_button = QPushButton("Отдалить", self)
        self.zoom_out_button.setAccessibleName("Отдалить карту")
        self.zoom_out_button.setToolTip("Отдалить (- при фокусе карты)")
        self.zoom_out_button.clicked.connect(self.view.zoom_out)
        self.fit_button = QPushButton("Вписать", self)
        self.fit_button.setAccessibleName("Вписать карту в область просмотра")
        self.fit_button.setToolTip("Вписать (0 при фокусе карты); масштаб 8–400%")
        self.fit_button.clicked.connect(self.view.fit_map)
        toolbar.addWidget(self.zoom_in_button)
        toolbar.addWidget(self.zoom_out_button)
        toolbar.addWidget(self.fit_button)
        self.back_focus_button = QPushButton("Назад", self)
        self.back_focus_button.clicked.connect(self._back_focus)
        self.all_rules_button = QPushButton("Все правила", self)
        self.all_rules_button.clicked.connect(self._clear_focus)
        toolbar.addWidget(self.back_focus_button)
        toolbar.addWidget(self.all_rules_button)
        gesture_hint = QLabel("Колесо: масштаб · средняя кнопка: перемещение · + / − / 0", self)
        gesture_hint.setTextFormat(Qt.TextFormat.PlainText)
        gesture_hint.setWordWrap(True)
        toolbar.addWidget(gesture_hint, 1)
        layout.addLayout(toolbar)
        self.details = QPlainTextEdit(self)
        self.details.setReadOnly(True)
        self.details.setAccessibleName("Подробности выбранного условия или правила ACL")
        self.details.setMinimumWidth(300)
        self.relation_selector = QComboBox(self)
        self.relation_selector.setEditable(True)
        self.relation_selector.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.relation_selector.setAccessibleName("Все правила карты, включая не отрисованные")
        selector_label = QLabel("Правило из полного набора:", self)
        selector_label.setBuddy(self.relation_selector)
        side_panel = QWidget(self)
        side_layout = QVBoxLayout(side_panel)
        side_layout.addWidget(selector_label)
        side_layout.addWidget(self.relation_selector)
        side_layout.addWidget(self.details, 1)
        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(self.view)
        splitter.addWidget(side_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        self.scene.selectionChanged.connect(self._selection_changed)
        self.relation_selector.currentIndexChanged.connect(self._relation_selected)
        self.set_map_state(AclMapState("empty", None, "Выберите результат анализа."))

    def set_map_state(self, state: AclMapState) -> None:
        """Refresh scene and full-state details without reading source files."""
        if not isinstance(state, AclMapState):
            raise TypeError("ACL map widget requires an AclMapState")
        self._updating = True
        previous_block = self.relation_selector.blockSignals(True)
        try:
            self.state = state
            self._focus_timer.stop()
            self._pending_focus = None
            self._focused_relations = None
            self._focus_history.clear()
            self.back_focus_button.setEnabled(False)
            self._graph = None
            self._nodes.clear()
            self._relations.clear()
            self._node_references.clear()
            self.relation_selector.clear()
            self.relation_selector.addItem("Выберите правило", None)
            self.details.clear()
            self.scene.set_map_state(state, filters=self.filters)
            if self.scene.render_status in {"ready", "partial", "limited"}:
                self._graph = state.graph
            statuses = {
                "empty": "Нет отображаемых правил",
                "ready": "Проекция заданных правил доступна",
                "partial": "Неполные данные карты",
                "unsupported": "Данные не поддерживаются",
                "invalid": "Данные карты не подтверждены",
                "limited": "Отображение ограничено бюджетом; доступен полный набор правил",
            }
            lines = [state.label, statuses[self.scene.render_status], self.scene.diagnostic]
            graph = self._graph
            if graph is not None:
                lines.extend(graph.limitations)
                self._nodes = {node.node_id: node for node in graph.nodes}
                selected = (
                    filter_acl_relations(graph, self.filters)
                    if self.filters is not None
                    else graph.relations
                )
                lines.append(f"Выбрано правил: {len(selected)} из {len(graph.relations)}")
                for relation in sorted(
                    selected,
                    key=lambda item: (item.rule.sequence, item.rule.rule_id),
                ):
                    self._relations[relation.relation_id] = relation
                    rule = relation.rule
                    enabled = "включено" if rule.enabled else "× отключено"
                    self.relation_selector.addItem(
                        f"{rule.sequence}: {rule.name} — {rule.action.value} / "
                        f"{enabled} / {relation.condition_status}",
                        relation.relation_id,
                    )
                    for dimension, members in (
                        ("источник", relation.source_node_ids),
                        ("назначение", relation.destination_node_ids),
                        ("сервис", relation.service_node_ids),
                    ):
                        for node_id in dict.fromkeys(members):
                            self._node_references.setdefault(node_id, []).append(
                                (relation, dimension)
                            )
            self.status_label.setText("\n".join(dict.fromkeys(lines)))
            self.html_export_button.setEnabled(graph is not None)
            self.png_export_button.setEnabled(
                graph is not None and self.scene.render_status != "limited"
            )
            self.relation_selector.setEnabled(bool(self._relations))
            self.details.setPlainText(
                "\n".join(self._context_lines())
                + "\n\nВыберите условие или правило на карте либо правило из полного набора."
            )
            # At native scale, the first lane is visible immediately; explicit
            # navigation and zoom controls are a separate presentation step.
            self.view.resetTransform()
            self.view.horizontalScrollBar().setValue(self.view.horizontalScrollBar().minimum())
            self.view.verticalScrollBar().setValue(self.view.verticalScrollBar().minimum())
        finally:
            self.relation_selector.blockSignals(previous_block)
            self._updating = False

    def set_filters(self, filters: AclMapFilter | None) -> None:
        """Change only the presentation selection; the saved graph stays complete."""
        validated = (
            AclMapFilter.model_validate(filters.model_dump(mode="python"))
            if filters is not None
            else None
        )
        self.filters = validated
        controls = validated or AclMapFilter()
        self.source_filter.setText(controls.source_cidr or "")
        self.destination_filter.setText(controls.destination_cidr or "")
        self.protocol_filter.setCurrentIndex(
            max(
                0,
                self.protocol_filter.findData(
                    controls.protocol.value if controls.protocol is not None else None
                ),
            )
        )
        self.port_filter.setText(
            str(controls.destination_port) if controls.destination_port is not None else ""
        )
        self.unknown_filter.setChecked(controls.include_unknown)
        if self.state is not None:
            self.set_map_state(self.state)

    def reset_filters(self) -> None:
        self.set_filters(None)

    def _apply_filter_controls(self) -> None:
        try:
            self.set_filters(
                AclMapFilter(
                    source_cidr=self.source_filter.text().strip() or None,
                    destination_cidr=self.destination_filter.text().strip() or None,
                    protocol=self.protocol_filter.currentData(),
                    destination_port=(
                        int(self.port_filter.text().strip())
                        if self.port_filter.text().strip()
                        else None
                    ),
                    include_unknown=self.unknown_filter.isChecked(),
                )
            )
        except ValueError:
            self.status_label.setText(
                "Некорректный фильтр: проверьте IP/CIDR, протокол и порт 1–65535. "
                "Предыдущий вид карты сохранён."
            )

    def _export_target(self, path: Path) -> QSaveFile:
        if self._graph is None:
            raise ValueError("Нет подтверждённой карты для экспорта.")
        source = Path(self._graph.revision.parse_result.configuration.source_name)
        if source.exists() and (
            source.resolve() == path.resolve() or (path.exists() and path.samefile(source))
        ):
            raise ValueError("Экспорт не может перезаписать исходный документ.")
        stream = QSaveFile(str(path))
        if not stream.open(QIODevice.OpenModeFlag.WriteOnly):
            raise OSError("Не удалось открыть файл экспорта.")
        return stream

    def export_html(self, path: Path) -> None:
        """Write the current selection with full original provenance and limits."""
        if self._graph is None:
            raise ValueError("Нет подтверждённой карты для экспорта.")
        data = export_acl_map_html(self._graph, filters=self.filters).encode("utf-8")
        stream = self._export_target(path)
        if stream.write(data) != len(data):
            stream.cancelWriting()
            raise OSError("Не удалось записать HTML.")
        if not stream.commit():
            raise OSError("Не удалось сохранить HTML.")

    def export_png(self, path: Path) -> None:
        """Export the current scene at native scale, refusing unreadable huge images."""
        if self._graph is None or self.scene.render_status in {"limited", "invalid"}:
            raise ValueError("Карта не отрисована; уточните фильтры перед экспортом PNG.")
        bounds = self.scene.itemsBoundingRect().adjusted(-24, -24, 24, 24)
        if not all(isfinite(value) for value in (bounds.width(), bounds.height())):
            raise ValueError("Некорректный размер карты.")
        width, height = ceil(bounds.width()), ceil(bounds.height())
        if (
            width <= 0
            or height <= 0
            or max(width, height) > self.MAX_PNG_DIMENSION
            or width * height > self.MAX_PNG_PIXELS
        ):
            raise ValueError("PNG превышает бюджет размера; уточните фильтры карты.")
        image = QImage(width, height, QImage.Format.Format_ARGB32)
        if image.isNull():
            raise OSError("Недостаточно памяти для PNG.")
        image.fill(QColor(COLORS["background"]))
        painter = QPainter(image)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            self.scene.render(painter, QRectF(0, 0, width, height), bounds)
        finally:
            painter.end()
        stream = self._export_target(path)
        writer = QImageWriter(stream, QByteArray(b"png"))
        if not writer.write(image):
            stream.cancelWriting()
            raise OSError("Не удалось записать PNG.")
        if not stream.commit():
            raise OSError("Не удалось сохранить PNG.")

    def _export_dialog(self, format_name: Literal["html", "png"]) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт текущего вида ACL",
            f"acl-map.{format_name}",
            f"{format_name.upper()} (*.{format_name})",
        )
        if not path:
            return
        try:
            if format_name == "html":
                self.export_html(Path(path))
            else:
                self.export_png(Path(path))
        except (OSError, ValueError) as error:
            QMessageBox.warning(self, "Экспорт карты", str(error))

    def _context_lines(self) -> list[str]:
        lines = ["Связи по правилам", CONFIGURED_POLICY_LABEL, self.scene.diagnostic]
        graph = self._graph
        if graph is None:
            return lines
        revision = graph.revision
        lines.extend(
            (
                f"Ревизия: {revision.revision_id}",
                f"Устройство: {revision.device.hostname or revision.device.device_id}",
                f"Device ID: {revision.device.device_id}",
                f"Импортировано: {revision.imported_at.isoformat()}",
                "Ограничения:",
                *graph.limitations,
            )
        )
        return lines

    @staticmethod
    def _node_lines(node: AclMapNode) -> list[str]:
        """Canonical content, without inventing absent resolution or provenance."""
        lines = [f"Node ID: {node.node_id}", f"Тип узла: {node.kind}"]
        if node.endpoint is not None:
            endpoint = node.endpoint
            lines.extend(
                (
                    f"Название: {endpoint.name}",
                    f"Object ID: {endpoint.endpoint_id}",
                    f"Тип объекта: {endpoint.kind.value}",
                    f"Статус разрешения данных: {endpoint.resolution_status.value}",
                    "CIDR: " + (", ".join(endpoint.cidrs) or "не указаны"),
                    "Диапазоны IP: "
                    + (
                        ", ".join(f"{value.start}–{value.end}" for value in endpoint.ip_ranges)
                        or "не указаны"
                    ),
                    f"FQDN: {endpoint.fqdn or 'не указан'}",
                    f"Зона: {endpoint.zone or 'не указана'}",
                    f"Описание: {endpoint.description or 'не указано'}",
                )
            )
        elif node.service is not None:
            service = node.service
            lines.extend(
                (
                    f"Название: {service.name}",
                    f"Service ID: {service.service_id}",
                    f"Протокол: {service.protocol.value}",
                    f"Статус разрешения данных: {service.resolution_status.value}",
                    "Диапазоны портов: "
                    + (
                        ", ".join(f"{value.start}–{value.end}" for value in service.port_ranges)
                        or "не указаны (это не означает any)"
                    ),
                    f"Описание: {service.description or 'не указано'}",
                )
            )
        else:
            lines.extend(
                (
                    "? Значение условия неизвестно",
                    f"Измерение: {node.unknown_dimension}",
                    "Неизвестное условие не означает any или разрешение.",
                )
            )
        return lines

    @staticmethod
    def _rule_reference_lines(relation: AclMapRelation) -> list[str]:
        rule = relation.rule
        source = rule.source_location
        return [
            f"Relation ID: {relation.relation_id}",
            f"Rule ID: {rule.rule_id}",
            f"Configuration ID: {rule.configuration_id}",
            f"Источник правила: {source.source_name}",
            f"Строки: {source.line_start or 'не указаны'}–"
            f"{source.line_end or source.line_start or 'не указаны'}",
            f"Путь объекта: {source.object_path or 'не указан'}",
            f"ID объекта в источнике: {source.object_id or 'не указан'}",
        ]

    def _source_document_lines(self) -> list[str]:
        if self._graph is None:
            return []
        lines = ["Документы ревизии (не отдельная привязка происхождения каждого объекта):"]
        for source in self._graph.revision.sources:
            lines.extend(
                (
                    f"  {source.source_name} · {source.kind.value}",
                    f"  Source document ID: {source.source_document_id}",
                    f"  Получен: {source.captured_at.isoformat()}",
                )
            )
        return lines

    def _show_node(self, node: AclMapNode) -> None:
        lines = [*self._context_lines(), "", "Условие правила", *self._node_lines(node)]
        lines.extend(
            (
                "",
                "Происхождение: условие канонической проекции правил выбранной ревизии.",
                "Отдельная трассировка определения объекта моделью узла не предоставлена.",
                "Ссылки на использующие правила:",
            )
        )
        references = self._node_references.get(node.node_id, [])
        if not references:
            lines.append("Ссылающиеся правила отсутствуют в проекции.")
        for relation, dimension in references:
            lines.extend(
                (
                    "",
                    f"Роль условия: {dimension}",
                    f"Правило: {relation.rule.name}; условия: {relation.condition_status}",
                    *self._rule_reference_lines(relation),
                )
            )
        lines.extend(("", *self._source_document_lines()))
        self.details.setPlainText("\n".join(lines))

    def _show_relation(self, relation: AclMapRelation, dimension: str | None = None) -> None:
        rule = relation.rule
        lines = [*self._context_lines(), "", f"Правило: {rule.name}"]
        if dimension is not None:
            lines.append(f"Выбран сегмент условия: {dimension}")
        lines.extend(
            (
                f"Заданное действие: {rule.action.value}",
                "Включено: " + ("да" if rule.enabled else "нет · × отключено"),
                f"Статус условий: {relation.condition_status}",
                f"Позиция правила: {rule.sequence}",
                f"Политика: {rule.policy_id or 'не указана'}",
                f"Направление политики: {rule.policy_direction or 'неизвестно'}",
                f"Семантика политики: {rule.policy_semantics or 'неизвестна'}",
                f"Зоны: {rule.source_zone or '?'} → {rule.destination_zone or '?'}",
                f"Статусы source / destination / service: {rule.source_status.value} / "
                f"{rule.destination_status.value} / {rule.service_status.value}",
                f"Статусы match / zone: {rule.match_status.value} / {rule.zone_status.value}",
                f"Описание: {rule.description or 'не указано'}",
                "",
                *self._rule_reference_lines(relation),
            )
        )
        for title, members in (
            ("Источники", relation.source_node_ids),
            ("Назначения", relation.destination_node_ids),
            ("Сервисы", relation.service_node_ids),
        ):
            lines.extend(("", f"{title} — все условия ({len(members)}):"))
            for index, node_id in enumerate(members, start=1):
                node = self._nodes.get(node_id)
                lines.append(f"  Условие {index}:")
                if node is not None:
                    lines.extend(f"    {line}" for line in self._node_lines(node))
                else:
                    lines.append(f"    ? Данные условия недоступны; Node ID: {node_id}")
        lines.extend(("", *self._source_document_lines()))
        self.details.setPlainText("\n".join(lines))

    def _selection_changed(self) -> None:
        if self._updating:
            return
        selected = self.scene.selectedItems()
        if not selected:
            self.details.setPlainText("\n".join(self._context_lines()))
            return
        item = selected[0]
        if isinstance(item, AclMapNodeItem):
            previous_block = self.relation_selector.blockSignals(True)
            self.relation_selector.setCurrentIndex(0)
            self.relation_selector.blockSignals(previous_block)
            self._show_node(item.node)
            related = frozenset(
                relation.relation_id for relation, _ in self._node_references.get(item.node.node_id, ())
            )
            if self._focused_relations is not None:
                related = related.intersection(self._focused_relations)
            if related:
                self._queue_focus(related)
        elif isinstance(item, (AclMapEdgeItem, AclMapRelationJunctionItem)):
            previous_block = self.relation_selector.blockSignals(True)
            self.relation_selector.setCurrentIndex(
                self.relation_selector.findData(item.relation_id),
            )
            self.relation_selector.blockSignals(previous_block)
            dimension = item.data(int(Qt.ItemDataRole.UserRole) + 5)
            self._show_relation(item.relation, dimension if isinstance(dimension, str) else None)
            self._queue_focus(frozenset((item.relation_id,)))

    def _queue_focus(self, relation_ids: frozenset[str]) -> None:
        self._pending_focus = relation_ids
        self._focus_timer.start(0)

    def _apply_pending_focus(self) -> None:
        if self._pending_focus is not None:
            pending, self._pending_focus = self._pending_focus, None
            self._focus_relations(pending)

    def _focus_relations(self, relation_ids: frozenset[str] | None, *, remember: bool = True) -> None:
        if self.state is None or relation_ids == self._focused_relations:
            return
        if remember:
            self._focus_history.append(self._focused_relations)
        self._focused_relations = relation_ids
        self._updating = True
        try:
            self.scene.set_map_state(self.state, filters=self.filters, relation_ids=relation_ids)
        finally:
            self._updating = False
        self.back_focus_button.setEnabled(bool(self._focus_history))
        self.png_export_button.setEnabled(
            self._graph is not None and self.scene.render_status != "limited"
        )
        self.status_label.setText(
            f"{self.state.label}\n"
            + (f"Фокус: {len(relation_ids)} правил из {len(self._relations)}. " if relation_ids is not None else "Все выбранные правила. ")
            + self.scene.diagnostic
        )
        self.view.fit_map()

    def _clear_focus(self) -> None:
        self._focus_relations(None)

    def _back_focus(self) -> None:
        if self._focus_history:
            self._focus_relations(self._focus_history.pop(), remember=False)

    def _relation_selected(self, index: int) -> None:
        if self._updating:
            return
        relation_id = self.relation_selector.itemData(index)
        relation = self._relations.get(relation_id) if isinstance(relation_id, str) else None
        if relation is not None:
            self._focus_relations(frozenset((relation.relation_id,)))
        self._updating = True
        try:
            self.scene.clearSelection()
            if relation is not None:
                junction = self.scene.relation_items.get(relation.relation_id)
                if junction is not None:
                    junction.setSelected(True)
        finally:
            self._updating = False
        if relation is not None:
            self._show_relation(relation)
        else:
            self.details.setPlainText("\n".join(self._context_lines()))


def _saved_revision(item: Mapping[str, object]) -> DeviceRevision | None:
    """Read only an embedded revision, requiring its original durable IDs."""
    payload = item.get("revision")
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise ValueError("Saved revision must be an object")
    if not payload.get("revision_id"):
        raise ValueError("Saved revision identity is unavailable")
    sources = payload.get("sources")
    if not isinstance(sources, (list, tuple)) or not sources:
        raise ValueError("Saved source identities are unavailable")
    for source in sources:
        if not isinstance(source, Mapping) or not source.get("source_document_id"):
            raise ValueError("Saved source identity is unavailable")
    return DeviceRevision.model_validate(dict(payload))


def build_map_state(
    analysis: AnalysisSession | DeviceRevision | Mapping[str, object] | None,
    *,
    built_at: datetime | None = None,
) -> AclMapState:
    """Adapt current analysis or a saved item without rereading its source.

    Saved items must carry their original revision and source document IDs;
    this boundary never synthesizes a revision from a report or parse result.
    Domain projection retains deny, disabled, unknown and unsupported rules.
    Empty or incomplete maps never imply permission or absence of policy.
    Model validation failures produce a safe state without source payloads.
    Successful states share the graph's prepared immutable revision directly,
    including valid snapshots with no ACL rules, without another validation.
    """
    if analysis is None:
        return AclMapState("empty", None, "Выберите результат анализа или сохранённую ревизию.")
    try:
        if isinstance(analysis, AnalysisSession):
            revision = analysis.revision
        elif isinstance(analysis, DeviceRevision):
            revision = analysis
        else:
            payload = analysis.get("revision")
            if isinstance(payload, Mapping) and payload.get("schema_version") not in {
                None,
                "1.0.0",
                "2.0.0",
            }:
                return AclMapState(
                    "unsupported", None, "Версия сохранённой ревизии не поддерживается."
                )
            saved_revision = _saved_revision(analysis)
            if saved_revision is None:
                return AclMapState(
                    "unsupported",
                    None,
                    "Сохранённая ревизия недоступна; карта не построена.",
                )
            revision = saved_revision
        graph = build_acl_map(revision, built_at=built_at or datetime.now(UTC))
    except (ValueError, TypeError):
        return AclMapState(
            "invalid",
            None,
            "Не удалось подтвердить ревизию и происхождение данных карты.",
        )
    if not graph.relations:
        return AclMapState(
            "empty",
            graph,
            "Нет разобранных правил; это не доказывает отсутствие политики.",
            revision=graph.revision,
        )
    # The domain owns completeness and condition semantics; do not infer paths.
    status: Literal["ready", "partial"] = "partial" if len(graph.limitations) > 2 else "ready"
    return AclMapState(
        status,
        graph,
        "Карта показывает заданные условия правил. "
        "Эффективные разрешения, маршруты, NAT и сквозная достижимость не вычисляются.",
        revision=graph.revision,
    )
