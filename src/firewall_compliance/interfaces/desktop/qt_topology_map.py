"""Qt presentation of recorded topology facts, without network inference."""

from __future__ import annotations

from dataclasses import dataclass, replace
from html import escape
from typing import Literal

from PySide6.QtCore import QObject, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPainterPathStroker, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsScene,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStyleOptionGraphicsItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.domain.configuration import Device
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.revision import Interface
from firewall_compliance.interfaces.desktop.qt_acl_map import AclMapView
from firewall_compliance.interfaces.desktop.qt_theme import COLORS
from firewall_compliance.interfaces.desktop.topology_map import (
    ConfiguredSubnetAttachment,
    TopologyInterface,
    TopologyProjection,
    build_topology_projection,
)

TOPOLOGY_MODE_LABEL = "Записанные интерфейсы и заданные привязки подсетей"
TopologyInventory = Literal["revision", "forwarding"]


def _inventory(interface: TopologyInterface) -> TopologyInventory:
    return "revision" if isinstance(interface.fact, Interface) else "forwarding"


def _completeness(interface: TopologyInterface, projection: TopologyProjection) -> str:
    if interface.document is not None:
        complete = interface.document.collection_evidence.complete
        return "полнота документа: " + ("заявлена" if complete else "не подтверждена")
    if isinstance(interface.fact, Interface) and projection.revision is not None:
        evidence = projection.revision.interfaces_evidence
        return "полнота перечня: " + (
            "заявлена" if evidence is not None and evidence.complete else "не подтверждена"
        )
    return "полнота перечня forwarding: не установлена проекцией"


def _interface_lines(
    interface: TopologyInterface,
    projection: TopologyProjection,
) -> tuple[str, ...]:
    fact = interface.fact
    lines = [
        f"Interface ID: {interface.interface_id}",
        f"Inventory: {_inventory(interface)} (одинаковые названия не объединяются)",
        f"Table ID: {interface.table_id or 'не задана'}; VRF: не задана",
        f"Операционное состояние: {interface.operational_state}",
        _completeness(interface, projection),
    ]
    if isinstance(fact, Interface):
        lines.extend(
            (
                f"Device ID: {fact.device_id}",
                f"Статус факта: {fact.data_status.value}",
                f"Статус адресов: {fact.addresses_status.value}",
                f"Enabled: {fact.enabled}; это не означает operational up",
                "Адреса: " + (", ".join(fact.addresses) or "не заданы"),
                f"Происхождение: {fact.origin.value}",
            )
        )
        location = fact.source_location
    else:
        lines.append(f"Статус security-level: {fact.security_status.value}")
        location = fact.location.location
    if interface.source is not None:
        lines.extend(
            (
                f"Документ: {interface.source.source_name}",
                f"Source document ID: {interface.source.source_document_id}",
            )
        )
    else:
        lines.append("Документ происхождения недоступен в проекции")
    if location is not None:
        lines.extend(
            (
                f"Источник позиции: {location.source_name}",
                f"Строки: {location.line_start}–{location.line_end or location.line_start}",
                f"Путь объекта: {location.object_path or 'не задан'}",
                f"Object ID: {location.object_id or 'не задан'}",
            )
        )
    if interface.document is not None:
        document = interface.document
        lines.extend(
            (
                f"Статус документа: {document.status.value}",
                f"Диагностика: warnings {len(document.warnings)}, errors {len(document.errors)}, "
                f"unsupported {len(document.unsupported_constructs)}",
                *document.limitations,
            )
        )
    return tuple(lines)


class TopologyNodeItem(QGraphicsObject):
    """A movable rendering of an original fact or an explicit prefix value."""

    geometry_changed = Signal()

    def __init__(
        self,
        kind: Literal["device", "interface", "subnet"],
        identity: str,
        label: str,
        lines: tuple[str, ...],
        payload: Device | TopologyInterface | ConfiguredSubnetAttachment,
        *,
        status: DataStatus = DataStatus.UNKNOWN,
    ) -> None:
        super().__init__()
        self.kind = kind
        self.identity = identity
        self.payload = payload
        self.status = status
        self.card_rect = QRectF(0.0, 0.0, 260.0, 88.0)
        kind_label = {"device": "Устройство", "interface": "Интерфейс", "subnet": "Подсеть"}[kind]
        status_label = (
            "данные известны" if status == DataStatus.KNOWN else f"данные: {status.value}"
        )
        self._lines = (label, f"{kind_label} · {status_label}", *lines)
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemIsMovable
            | QGraphicsItem.GraphicsItemFlag.ItemIsFocusable
            | QGraphicsItem.GraphicsItemFlag.ItemSendsScenePositionChanges
        )
        role = int(Qt.ItemDataRole.UserRole)
        self.setData(role, identity)
        self.setData(role + 1, kind)
        self.setToolTip(
            "<qt>"
            + "<br/>".join(escape(line) for line in (TOPOLOGY_MODE_LABEL, *self._lines))
            + "</qt>"
        )

    def boundingRect(self) -> QRectF:
        return self.card_rect.adjusted(-3.0, -3.0, 3.0, 3.0)

    def set_container_height(self, height: float) -> None:
        self.prepareGeometryChange()
        self.card_rect = QRectF(0.0, 0.0, 308.0, height)
        self.update()

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
        color = COLORS["purple" if self.isSelected() else "blue"]
        pen = QPen(QColor(color), 2.0)
        if self.status != DataStatus.KNOWN:
            pen.setStyle(Qt.PenStyle.DashLine)
        if self.hasFocus():
            pen.setWidthF(3.0)
        painter.setPen(pen)
        painter.setBrush(QColor(COLORS["raised" if self.isSelected() else "panel"]))
        painter.drawRoundedRect(self.card_rect, 10.0, 10.0)
        painter.setPen(QColor(COLORS["text"]))
        lines = self._lines[:3]
        if self.kind == "device":
            lines = (self._lines[0], "Устройство · интерфейсы внутри")
        for index, line in enumerate(lines):
            text = painter.fontMetrics().elidedText(line, Qt.TextElideMode.ElideRight, 236)
            painter.drawText(
                QRectF(12.0, 6.0 + index * 24.0, 236.0, 24.0),
                Qt.AlignmentFlag.AlignVCenter,
                text,
            )
        painter.restore()


class TopologyAttachmentItem(QGraphicsObject):
    """Configured prefix attachment, with no cable, direction or up assertion."""

    def __init__(
        self,
        interface: TopologyInterface,
        attachment: ConfiguredSubnetAttachment,
        interface_item: TopologyNodeItem,
        subnet_item: TopologyNodeItem,
        projection: TopologyProjection,
    ) -> None:
        if attachment not in interface.attachments:
            raise ValueError("Topology attachment must belong to its projected interface")
        if interface_item.payload is not interface or subnet_item.payload is not attachment:
            raise ValueError("Topology attachment endpoints must retain the original facts")
        super().__init__()
        self.interface = interface
        self.attachment = attachment
        self.interface_item = interface_item
        self.subnet_item = subnet_item
        self.relationship = attachment.relationship
        self._lines = (
            f"configured_attachment · {attachment.relationship}",
            f"Адреса: {attachment.address_status.value}",
            _completeness(interface, projection),
        )
        self._path = QPainterPath()
        self._label_rect = QRectF()
        self._hit_shape = QPainterPath()
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemIsFocusable
        )
        self.setZValue(-1.0)
        role = int(Qt.ItemDataRole.UserRole)
        # No relation ID exists in the DTO: retain its literal identifying
        # values rather than manufacturing a domain link identity.
        self.setData(role, interface.interface_id)
        self.setData(role + 1, attachment.relationship)
        self.setData(role + 2, attachment.cidr)
        self.setData(role + 3, _inventory(interface))
        self.setData(role + 4, interface.table_id)
        self.setToolTip(
            "<qt>"
            + "<br/>".join(
                escape(line)
                for line in (
                    *self._lines,
                    f"CIDR: {attachment.cidr}",
                    *_interface_lines(interface, projection),
                    "Это заданный префикс интерфейса; кабель и достижимость не установлены.",
                )
            )
            + "</qt>"
        )
        interface_item.geometry_changed.connect(self.update_geometry)
        subnet_item.geometry_changed.connect(self.update_geometry)
        self.update_geometry()

    def update_geometry(self) -> None:
        start_rect = self.interface_item.sceneBoundingRect()
        end_rect = self.subnet_item.sceneBoundingRect()
        start = self.mapFromScene(QPointF(start_rect.right(), start_rect.center().y()))
        end = self.mapFromScene(QPointF(end_rect.left(), end_rect.center().y()))
        path = QPainterPath(start)
        bend = max(60.0, abs(end.x() - start.x()) / 2.0)
        path.cubicTo(start + QPointF(bend, 0.0), end - QPointF(bend, 0.0), end)
        middle = path.pointAtPercent(0.5)
        label_rect = QRectF(middle.x() - 160.0, middle.y() - 36.0, 320.0, 72.0)
        stroker = QPainterPathStroker()
        stroker.setWidth(16.0)
        label_path = QPainterPath()
        label_path.addRect(label_rect)
        hit_shape = stroker.createStroke(path).united(label_path)
        self.prepareGeometryChange()
        self._path = path
        self._label_rect = label_rect
        self._hit_shape = hit_shape
        self.update()

    def boundingRect(self) -> QRectF:
        return self._hit_shape.boundingRect().adjusted(-4.0, -4.0, 4.0, 4.0)

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
        pen = QPen(QColor(COLORS["muted"]), 2.0)
        pen.setStyle(
            Qt.PenStyle.DashLine
            if self.attachment.address_status == DataStatus.KNOWN
            else Qt.PenStyle.DotLine
        )
        painter.setPen(pen)
        painter.drawPath(self._path)
        if not (self.isSelected() or self.hasFocus()):
            painter.restore()
            return
        painter.setBrush(QColor(COLORS["panel"]))
        painter.drawRoundedRect(self._label_rect, 6.0, 6.0)
        painter.setPen(QColor(COLORS["text"]))
        for index, line in enumerate(self._lines):
            text = painter.fontMetrics().elidedText(line, Qt.TextElideMode.ElideRight, 304)
            painter.drawText(
                QRectF(
                    self._label_rect.x() + 8.0, self._label_rect.y() + index * 24.0, 304.0, 24.0
                ),
                Qt.AlignmentFlag.AlignCenter,
                text,
            )
        painter.restore()


class TopologyMapScene(QGraphicsScene):
    """Deterministic bounded renderer; retains the complete input projection."""

    MAX_ITEMS = 1200
    MAX_ATTACHMENTS = 700

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.projection: TopologyProjection | None = None
        self.render_status: Literal["missing", "unknown", "recorded", "limited", "invalid"] = (
            "missing"
        )
        self.diagnostic = ""
        self.device_item: TopologyNodeItem | None = None
        self.interface_items: dict[tuple[TopologyInventory, str], TopologyNodeItem] = {}
        self.subnet_items: dict[tuple[TopologyInventory, str, str], TopologyNodeItem] = {}
        self.attachment_items: list[TopologyAttachmentItem] = []

    def _message(self, text: str) -> None:
        item = self.addText(text)
        item.setDefaultTextColor(QColor(COLORS["text"]))
        item.setTextWidth(1280.0)
        self.setSceneRect(self.itemsBoundingRect().adjusted(-32.0, -32.0, 32.0, 32.0))

    def set_projection(self, projection: TopologyProjection) -> None:
        if not isinstance(projection, TopologyProjection):
            raise TypeError("Topology scene requires a TopologyProjection")
        for item in self.attachment_items:
            item.interface_item.geometry_changed.disconnect(item.update_geometry)
            item.subnet_item.geometry_changed.disconnect(item.update_geometry)
        self.attachment_items.clear()
        self.interface_items.clear()
        self.subnet_items.clear()
        self.device_item = None
        self.clear()
        self.setSceneRect(QRectF())
        self.projection = projection
        self.render_status = projection.status
        self.diagnostic = ""
        if projection.status == "missing" or projection.revision is None:
            self.diagnostic = "Ревизия интерфейсов недоступна; связи не построены."
            self._message(
                "\n".join((TOPOLOGY_MODE_LABEL, self.diagnostic, *projection.limitations))
            )
            return
        count = sum(len(interface.attachments) for interface in projection.interfaces)
        total = 1 + len(projection.interfaces) + count
        if total > self.MAX_ITEMS or count > self.MAX_ATTACHMENTS:
            self.render_status = "limited"
            self.diagnostic = (
                f"Бюджет отображения превышен: узлов {total}/{self.MAX_ITEMS}, "
                f"привязок {count}/{self.MAX_ATTACHMENTS}. Граф целиком не отрисован. "
                "Полная проекция сохранена; отсутствие рисунка не означает отсутствие фактов."
            )
            self._message(
                "\n".join((TOPOLOGY_MODE_LABEL, self.diagnostic, *projection.limitations))
            )
            return
        keys = [
            (_inventory(interface), interface.interface_id) for interface in projection.interfaces
        ]
        if len(set(keys)) != len(keys) or any(
            len({attachment.cidr for attachment in interface.attachments})
            != len(interface.attachments)
            for interface in projection.interfaces
        ):
            self.render_status = "invalid"
            self.diagnostic = (
                "Неоднозначные идентификаторы интерфейсов/привязок; граф не отрисован."
            )
            self._message(
                "\n".join((TOPOLOGY_MODE_LABEL, self.diagnostic, *projection.limitations))
            )
            return
        revision = projection.revision
        self.diagnostic = (
            f"Интерфейсов: {len(projection.interfaces)}; заданных привязок: {count}. "
            f"Статус перечня ревизии: {revision.interfaces_status.value}. "
            "Полнота и операционное состояние не выводятся из наличия узлов."
        )
        top = 0.0
        device = revision.device
        self.device_item = TopologyNodeItem(
            "device",
            device.device_id,
            device.hostname or device.device_id,
            (
                f"Device ID: {device.device_id}",
                f"Ревизия: {revision.revision_id}",
                f"Контекст: {device.context or 'не задан'}",
                "Операционное состояние: unknown",
            ),
            device,
        )
        self.addItem(self.device_item)
        self.device_item.setPos(0.0, top)
        row = 0
        for interface in sorted(
            projection.interfaces,
            key=lambda value: (_inventory(value), value.interface_id),
        ):
            inventory = _inventory(interface)
            completeness = _completeness(interface, projection)
            status = (
                interface.fact.data_status
                if isinstance(interface.fact, Interface)
                else DataStatus.UNKNOWN
            )
            node = TopologyNodeItem(
                "interface",
                interface.interface_id,
                interface.label,
                (
                    (", ".join(interface.fact.addresses) or "Адреса не заданы")
                    if isinstance(interface.fact, Interface)
                    else f"Таблица: {interface.table_id or '—'}",
                    *_interface_lines(interface, projection),
                ),
                interface,
                status=status,
            )
            node.setData(int(Qt.ItemDataRole.UserRole) + 2, inventory)
            node.setData(int(Qt.ItemDataRole.UserRole) + 3, interface.table_id)
            node.setParentItem(self.device_item)
            node.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, False)
            node.setPos(24.0, 80.0 + row * 116.0)
            self.interface_items[(inventory, interface.interface_id)] = node
            for offset, attachment in enumerate(
                sorted(interface.attachments, key=lambda value: value.cidr)
            ):
                subnet = TopologyNodeItem(
                    "subnet",
                    attachment.cidr,
                    attachment.cidr,
                    (
                        "Префикс интерфейса",
                        completeness,
                        f"Interface ID: {interface.interface_id}",
                        *_interface_lines(interface, projection),
                    ),
                    attachment,
                    status=attachment.address_status,
                )
                subnet.setData(int(Qt.ItemDataRole.UserRole) + 2, inventory)
                subnet.setData(int(Qt.ItemDataRole.UserRole) + 3, interface.interface_id)
                self.addItem(subnet)
                subnet.setPos(700.0, top + 80.0 + (row + offset) * 116.0)
                self.subnet_items[(inventory, interface.interface_id, attachment.cidr)] = subnet
                link = TopologyAttachmentItem(interface, attachment, node, subnet, projection)
                self.addItem(link)
                self.attachment_items.append(link)
            row += max(1, len(interface.attachments))
        self.device_item.set_container_height(92.0 + max(1, row) * 116.0)
        self.setSceneRect(self.itemsBoundingRect().adjusted(-48.0, -48.0, 48.0, 48.0))


@dataclass(frozen=True, slots=True)
class _TopologySelection:
    """A UI selector entry retaining original projection values."""

    kind: Literal["device", "interface", "subnet", "attachment"]
    interface: TopologyInterface | None = None
    attachment: ConfiguredSubnetAttachment | None = None


class TopologyMapWidget(QWidget):
    """Recorded-facts canvas with full-projection, plain-text details."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.projection: TopologyProjection | None = None
        self._entries: list[_TopologySelection] = []
        self._updating = False
        layout = QVBoxLayout(self)
        self.mode_label = QLabel("Топология конфигурации", self)
        self.mode_label.setTextFormat(Qt.TextFormat.PlainText)
        self.mode_label.setAccessibleName("Режим карты: топология конфигурации")
        self.mode_label.hide()
        self.legend_label = QLabel(
            "Штрихи: заданная привязка configured_subnet с известным статусом адресов. "
            "Точки: привязка с неизвестными/неподдержанными данными. "
            "Operational: unknown для всех элементов; enabled не означает up. "
            "Линии не обозначают кабели, соседство или достижимость.",
            self,
        )
        self.legend_label.setTextFormat(Qt.TextFormat.PlainText)
        self.legend_label.setWordWrap(True)
        self.legend_label.hide()
        self.status_label = QLabel(self)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.scene = TopologyMapScene(self)
        self.view = AclMapView(self.scene, self)
        self.view.setAccessibleName("Карта записанных интерфейсов и заданных подсетей")
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setMinimumSize(280, 120)
        toolbar = QHBoxLayout()
        self.search = QLineEdit(self)
        self.search.setPlaceholderText("Найти интерфейс, адрес или подсеть…")
        self.search.setAccessibleName("Поиск по топологии")
        toolbar.addWidget(self.search, 1)
        self.interface_filter = QComboBox(self)
        self.interface_filter.setAccessibleName("Фильтр интерфейсов")
        self.interface_filter.addItem("Все интерфейсы", "all")
        self.interface_filter.addItem("С подсетями", "addressed")
        self.interface_filter.addItem("Без привязок подсетей", "unaddressed")
        toolbar.addWidget(self.interface_filter)
        self.zoom_in_button = QPushButton("+", self)
        self.zoom_out_button = QPushButton("−", self)
        self.fit_button = QPushButton("Вписать", self)
        for button, name, hint, callback in (
            (self.zoom_in_button, "Приблизить топологию", "+ при фокусе карты", self.view.zoom_in),
            (self.zoom_out_button, "Отдалить топологию", "- при фокусе карты", self.view.zoom_out),
            (self.fit_button, "Вписать топологию", "0 при фокусе карты", self.view.fit_map),
        ):
            button.setAccessibleName(name)
            button.setToolTip(hint)
            button.clicked.connect(callback)
            toolbar.addWidget(button)
        self.details_button = QPushButton("Свойства", self)
        self.details_button.setCheckable(True)
        toolbar.addWidget(self.details_button)
        layout.addLayout(toolbar)
        self.element_selector = QComboBox(self)
        self.element_selector.setAccessibleName("Элементы полной проекции топологии")
        selector_label = QLabel("Элемент из полной проекции:", self)
        selector_label.setBuddy(self.element_selector)
        self.details = QPlainTextEdit(self)
        self.details.setReadOnly(True)
        self.details.setAccessibleName("Подробности выбранного элемента топологии")
        self.details.setMinimumWidth(240)
        panel = self.details_panel = QWidget(self)
        panel.setMinimumWidth(260)
        panel.setMaximumWidth(420)
        panel_layout = QVBoxLayout(panel)
        panel_layout.addWidget(selector_label)
        panel_layout.addWidget(self.element_selector)
        panel_layout.addWidget(self.details, 1)
        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(self.view)
        splitter.addWidget(panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 0)
        splitter.setSizes([900, 300])
        panel.hide()
        self.details_button.toggled.connect(panel.setVisible)
        layout.addWidget(splitter, 1)
        legend = QLabel("Линии: привязки подсетей · состояние сети неизвестно", self)
        legend.setToolTip(self.legend_label.text())
        layout.addWidget(legend)
        layout.addWidget(self.status_label)
        self.scene.selectionChanged.connect(self._selection_changed)
        self.element_selector.currentIndexChanged.connect(self._element_selected)
        self.search.textChanged.connect(self._filter_projection)
        self.interface_filter.currentIndexChanged.connect(self._filter_projection)
        self.set_projection(build_topology_projection(None))

    def _add_entry(self, label: str, entry: _TopologySelection) -> None:
        self.element_selector.addItem(label, len(self._entries))
        self._entries.append(entry)

    def set_projection(self, projection: TopologyProjection) -> None:
        """Replace all visible state; full selector survives render limits."""
        if not isinstance(projection, TopologyProjection):
            raise TypeError("Topology widget requires a TopologyProjection")
        if projection == self.projection:
            return
        self._updating = True
        previous_block = self.element_selector.blockSignals(True)
        try:
            self.projection = projection
            self._entries.clear()
            self.element_selector.clear()
            self.element_selector.addItem("Выберите элемент", -1)
            self._filter_projection()
            if (
                self.scene.render_status not in {"missing", "invalid"}
                and projection.revision is not None
            ):
                device = projection.revision.device
                self._add_entry(
                    f"Устройство: {device.hostname or device.device_id}",
                    _TopologySelection("device"),
                )
                for interface in sorted(
                    projection.interfaces,
                    key=lambda value: (_inventory(value), value.interface_id),
                ):
                    scope = f"{_inventory(interface)} · {interface.interface_id}"
                    self._add_entry(
                        f"Интерфейс: {interface.label} · {scope}",
                        _TopologySelection("interface", interface),
                    )
                    for attachment in sorted(interface.attachments, key=lambda value: value.cidr):
                        self._add_entry(
                            f"Подсеть: {attachment.cidr} · {scope}",
                            _TopologySelection("subnet", interface, attachment),
                        )
                        self._add_entry(
                            f"Привязка: {interface.label} — {attachment.cidr} · {scope}",
                            _TopologySelection("attachment", interface, attachment),
                        )
            self.element_selector.setEnabled(bool(self._entries))
            self.details.setPlainText(
                "\n".join(self._context_lines()) + "\n\nВыберите элемент карты или полного набора."
            )
        finally:
            self.element_selector.blockSignals(previous_block)
            self._updating = False

    def _filter_projection(self) -> None:
        projection = self.projection
        if projection is None:
            return
        query = self.search.text().strip().casefold()
        mode = self.interface_filter.currentData()
        interfaces = []
        for interface in projection.interfaces:
            if mode == "addressed" and not interface.attachments:
                continue
            if mode == "unaddressed" and interface.attachments:
                continue
            terms = [interface.label, interface.interface_id, interface.table_id or ""]
            terms.extend(attachment.cidr for attachment in interface.attachments)
            if isinstance(interface.fact, Interface):
                terms.extend(interface.fact.addresses)
                terms.append(interface.fact.zone or "")
            if query and not any(query in term.casefold() for term in terms):
                continue
            interfaces.append(interface)
        self.scene.set_projection(replace(projection, interfaces=tuple(interfaces)))
        count = sum(len(interface.attachments) for interface in interfaces)
        status = f"Интерфейсы: {len(interfaces)} / {len(projection.interfaces)} · Подсети: {count}"
        if self.scene.render_status == "limited":
            status += " · Уточните поиск или фильтр для отображения карты"
        elif self.scene.render_status in {"missing", "invalid", "unknown"}:
            status += " · " + self.scene.diagnostic
        self.status_label.setText(status)
        self.status_label.setToolTip("\n".join((self.scene.diagnostic, *projection.limitations)))
        self.view.fit_map()

    def _context_lines(self) -> list[str]:
        lines = [
            "Топология конфигурации",
            self.scene.diagnostic,
            "Operational: unknown; VRF: unknown (table_id не подменяет VRF).",
        ]
        projection = self.projection
        if projection is None:
            return lines
        lines.extend(projection.limitations)
        revision = projection.revision
        if revision is not None:
            lines.extend(
                (
                    f"Ревизия: {revision.revision_id}",
                    f"Device ID: {revision.device.device_id}",
                    f"Контекст устройства: {revision.device.context or 'не задан'}",
                    f"Импортировано: {revision.imported_at.isoformat()}",
                    f"Статус перечня интерфейсов: {revision.interfaces_status.value}",
                )
            )
            evidence = revision.interfaces_evidence
            lines.append(
                "Полнота перечня ревизии: "
                + ("заявлена" if evidence is not None and evidence.complete else "не подтверждена")
            )
            if evidence is not None:
                lines.extend(
                    (
                        "Документы основания полноты: "
                        + (
                            ", ".join(str(value) for value in evidence.source_document_ids)
                            or "не заданы"
                        ),
                        f"Ручное основание: {evidence.manual_reason or 'не задано'}",
                    )
                )
        return lines

    def _show_entry(self, entry: _TopologySelection) -> None:
        projection = self.projection
        if projection is None:
            return
        self.details_button.setChecked(True)
        lines = self._context_lines() + ["", f"Элемент: {entry.kind}"]
        if entry.kind == "device" and projection.revision is not None:
            device = projection.revision.device
            lines.extend(
                (
                    f"Имя: {device.hostname or 'не задано'}",
                    f"Device ID: {device.device_id}",
                    f"Поставщик: {device.vendor}; платформа: {device.platform}",
                    f"Management IP: {device.management_ip or 'не задан'}",
                    "Документы ревизии (не доказательство кабельных связей):",
                )
            )
            for source in projection.revision.sources:
                lines.extend(
                    (
                        f"  {source.source_name} · {source.kind.value}",
                        f"  Source document ID: {source.source_document_id}",
                        f"  Получен: {source.captured_at.isoformat()}",
                    )
                )
        if entry.interface is not None:
            interface = entry.interface
            lines.extend(
                (f"Имя интерфейса: {interface.label}", *_interface_lines(interface, projection))
            )
            if isinstance(interface.fact, Interface):
                lines.append(
                    f"Ручное основание факта: {interface.fact.manual_reason or 'не задано'}"
                )
            if interface.document is not None:
                evidence = interface.document.collection_evidence
                lines.append(
                    "Документы основания полноты документа: "
                    + (
                        ", ".join(str(value) for value in evidence.source_document_ids)
                        or "не заданы"
                    )
                )
            if interface.source is not None:
                lines.append(f"Документ получен: {interface.source.captured_at.isoformat()}")
            lines.append("Все заданные привязки этого интерфейса:")
            lines.extend(
                f"  {value.cidr} · {value.relationship} · адреса {value.address_status.value}"
                for value in interface.attachments
            )
            if not interface.attachments:
                lines.append("  Привязки не представлены; это не доказывает отсутствие адресов.")
        if entry.attachment is not None:
            attachment = entry.attachment
            lines.extend(
                (
                    "",
                    f"CIDR: {attachment.cidr}",
                    f"Вид привязки: configured_attachment / {attachment.relationship}",
                    f"Статус адресных данных: {attachment.address_status.value}",
                    "Самостоятельный subnet/link ID модель не предоставляет.",
                    "Привязка наследует ссылку исходного интерфейса; это не кабель и не маршрут.",
                )
            )
        self.details.setPlainText("\n".join(lines))

    def _selection_changed(self) -> None:
        if self._updating:
            return
        selected = self.scene.selectedItems()
        entry_index = -1
        if selected:
            item = selected[0]
            for index, entry in enumerate(self._entries):
                if isinstance(item, TopologyAttachmentItem):
                    match = (
                        entry.kind == "attachment"
                        and entry.interface is item.interface
                        and entry.attachment is item.attachment
                    )
                elif isinstance(item, TopologyNodeItem):
                    match = entry.kind == item.kind and (
                        (item.kind == "device")
                        or (item.kind == "interface" and entry.interface is item.payload)
                        or (
                            item.kind == "subnet"
                            and entry.attachment is item.payload
                            and entry.interface is not None
                            and entry.interface.interface_id
                            == item.data(int(Qt.ItemDataRole.UserRole) + 3)
                            and _inventory(entry.interface)
                            == item.data(int(Qt.ItemDataRole.UserRole) + 2)
                        )
                    )
                else:
                    match = False
                if match:
                    entry_index = index
                    break
        previous_block = self.element_selector.blockSignals(True)
        self.element_selector.setCurrentIndex(self.element_selector.findData(entry_index))
        self.element_selector.blockSignals(previous_block)
        if entry_index >= 0:
            self._show_entry(self._entries[entry_index])
        else:
            self.details.setPlainText("\n".join(self._context_lines()))

    def _element_selected(self, index: int) -> None:
        if self._updating:
            return
        entry_index = self.element_selector.itemData(index)
        entry = (
            self._entries[entry_index]
            if isinstance(entry_index, int) and 0 <= entry_index < len(self._entries)
            else None
        )
        self._updating = True
        try:
            self.scene.clearSelection()
            if entry is not None:
                item: QGraphicsItem | None = None
                if entry.kind == "device":
                    item = self.scene.device_item
                elif entry.interface is not None:
                    key = (_inventory(entry.interface), entry.interface.interface_id)
                    if entry.kind == "interface":
                        item = self.scene.interface_items.get(key)
                    elif entry.attachment is not None:
                        if entry.kind == "subnet":
                            item = self.scene.subnet_items.get((*key, entry.attachment.cidr))
                        else:
                            item = next(
                                (
                                    link
                                    for link in self.scene.attachment_items
                                    if link.interface is entry.interface
                                    and link.attachment is entry.attachment
                                ),
                                None,
                            )
                if item is not None:
                    item.setSelected(True)
                    self.view.ensureVisible(item)
        finally:
            self._updating = False
        if entry is not None:
            self._show_entry(entry)
        else:
            self.details.setPlainText("\n".join(self._context_lines()))
