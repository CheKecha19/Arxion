"""Явно применяемый фильтр без повторного чтения конфигураций."""

from __future__ import annotations

from collections.abc import Mapping

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QVBoxLayout, QWidget,
)

from firewall_compliance.application.rule_query import RuleQuery, parse_port_ranges
from firewall_compliance.domain.configuration import Rule


class RuleQueryWidget(QWidget):
    changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.query = RuleQuery()
        self.include_unknown = True
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.source = QLineEdit()
        self.source.setPlaceholderText("Источник IP/CIDR")
        self.source.setAccessibleName("Пересечение условий источника с IP или CIDR")
        self.destination = QLineEdit()
        self.destination.setPlaceholderText("Назначение IP/CIDR")
        self.destination.setAccessibleName("Пересечение условий назначения с IP или CIDR")
        self.protocol = QComboBox()
        self.protocol.setAccessibleName("Протокол фильтра правил")
        self.protocol.addItem("Любой протокол", "")
        for protocol in ("tcp", "udp", "icmp", "icmpv6", "ip"):
            self.protocol.addItem(protocol.upper(), protocol)
        self.ports = QLineEdit()
        self.ports.setPlaceholderText("Порты назначения: 443,1000-2000")
        self.ports.setAccessibleName("Порты назначения или диапазоны через запятую")
        for widget in (self.source, self.destination, self.protocol, self.ports):
            row.addWidget(widget)
        layout.addLayout(row)
        actions = QHBoxLayout()
        self.unknown = QCheckBox("Сохранять неизвестные условия")
        self.unknown.setChecked(True)
        actions.addWidget(self.unknown)
        apply = QPushButton("Применить условия")
        apply.clicked.connect(self._apply)
        reset = QPushButton("Сбросить условия")
        reset.clicked.connect(self._reset)
        actions.addWidget(apply)
        actions.addWidget(reset)
        actions.addStretch(1)
        layout.addLayout(actions)
        self.summary = QLabel("Условия не заданы. CIDR означает пересечение; порты применяются с TCP/UDP.")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)

    def _apply(self) -> None:
        try:
            query = RuleQuery(
                self.source.text().strip(), self.destination.text().strip(),
                str(self.protocol.currentData()), parse_port_ranges(self.ports.text()),
            )
        except ValueError as error:
            QMessageBox.warning(self, "Условия фильтра", str(error))
            return
        self.query, self.include_unknown = query, self.unknown.isChecked()
        self.summary.setText(
            f"Применено: {query.source or 'любой источник'} → {query.destination or 'любое назначение'}; "
            f"{query.protocol or 'любой протокол'}; порты {self.ports.text().strip() or 'любые'}. "
            "Пересечение заданных условий; неизвестные выделены отдельно. Сквозной доступ не вычисляется."
            if query.active else "Условия не заданы. CIDR означает пересечение; порты применяются с TCP/UDP."
        )
        self.changed.emit()

    def _reset(self) -> None:
        self.source.clear()
        self.destination.clear()
        self.protocol.setCurrentIndex(0)
        self.ports.clear()
        self.unknown.setChecked(True)
        self._apply()

    def match(self, value: Mapping[str, object] | None) -> bool | None:
        if not self.query.active:
            return True
        try:
            rule = Rule.model_validate(value)
        except (TypeError, ValueError):
            return None
        return self.query.matches(rule)

    def accepts(self, result: bool | None) -> bool:
        return result is True or (result is None and self.include_unknown)
