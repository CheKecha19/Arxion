"""Compact project overview; all numbers come from the explicit dashboard snapshot."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QKeyEvent, QMouseEvent, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.dashboard import (
    SEVERITIES,
    DashboardSnapshot,
    FindingTrendPoint,
    OperationSummary,
    build_dashboard,
)

_SEVERITY_LABELS = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "info": "Информационный",
}
_STATES = {
    "completed": "Завершено",
    "partial": "Частично",
    "running": "Выполняется",
    "cancelled": "Отменено",
    "canceled": "Отменено",
    "failed": "Ошибка",
    "interrupted": "Прервано",
    "error": "Ошибка",
    "unknown": "Неизвестно",
}

_BAR_COLORS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#facc15",
    "low": "#60a5fa",
    "info": "#94a3b8",
}


class SeverityBars(QWidget):
    """One common linear scale, with total and open counts always visible."""

    activated = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._totals: dict[str, int] = {}
        self._open: dict[str, int] = {}
        self._selected = 0
        self.setMinimumSize(300, 190)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAccessibleName("Находки по критичности: всего и открыто")
        self.setToolTip(
            "Длина серой полосы — все находки; цветная часть — открытые. "
            "Числа справа: всего / открыто. Нажмите строку, чтобы открыть находки. "
            "Клавиатура: стрелки вверх/вниз и Enter."
        )

    def set_counts(self, totals: Mapping[str, int], opened: Mapping[str, int]) -> None:
        self._totals = {key: max(0, totals.get(key, 0)) for key in SEVERITIES}
        self._open = {key: max(0, opened.get(key, 0)) for key in SEVERITIES}
        self.setAccessibleDescription(
            "; ".join(
                f"{_SEVERITY_LABELS[key]}: всего {self._totals[key]}, открыто {self._open[key]}"
                for key in SEVERITIES
            )
        )
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        row_height = self.height() / len(SEVERITIES)
        label_width = min(150, self.width() * 0.38)
        count_width = 85
        bar_width = max(1.0, self.width() - label_width - count_width - 16)
        maximum = max((1, *self._totals.values()))
        for row, severity in enumerate(SEVERITIES):
            y = row * row_height
            total = self._totals.get(severity, 0)
            opened = self._open.get(severity, 0)
            painter.setPen(self.palette().text().color())
            label = painter.fontMetrics().elidedText(
                _SEVERITY_LABELS[severity], Qt.TextElideMode.ElideRight, int(label_width - 8)
            )
            painter.drawText(
                QRectF(0, y, label_width - 8, row_height),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                label,
            )
            top = y + row_height / 2 - 7
            painter.fillRect(QRectF(label_width, top, bar_width, 14), QColor("#263244"))
            painter.fillRect(
                QRectF(label_width, top, bar_width * total / maximum, 14), QColor("#64748b")
            )
            painter.fillRect(
                QRectF(label_width, top, bar_width * min(opened, total) / maximum, 14),
                QColor(_BAR_COLORS[severity]),
            )
            painter.drawText(
                QRectF(label_width + bar_width + 8, y, count_width, row_height),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                f"{total} / {opened}",
            )
            if self.hasFocus() and self._selected == row:
                painter.setPen(QPen(self.palette().highlight().color(), 1))
                painter.drawRect(QRectF(1, y + 1, self.width() - 2, row_height - 2))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            row = int(event.position().y() * len(SEVERITIES) / max(1, self.height()))
            if 0 <= row < len(SEVERITIES):
                self._selected = row
                self.setFocus()
                self.update()
                self.activated.emit(SEVERITIES[row])
                return
        super().mousePressEvent(event)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in (Qt.Key.Key_Up, Qt.Key.Key_Down):
            step = -1 if event.key() == Qt.Key.Key_Up else 1
            self._selected = (self._selected + step) % len(SEVERITIES)
            self.update()
            return
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            self.activated.emit(SEVERITIES[self._selected])
            return
        super().keyPressEvent(event)


class FindingTrendChart(QWidget):
    """Plot observed counts; only explicitly comparable neighbors are connected."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.points: tuple[FindingTrendPoint, ...] = ()
        self.setMinimumHeight(180)
        self.setAccessibleName("Число находок по завершённым запускам")

    def set_points(self, points: tuple[FindingTrendPoint, ...]) -> None:
        self.points = points[-12:]
        descriptions = [
            f"{_date(point.timestamp)}: "
            f"{point.findings if point.findings is not None else 'нет результата'}; "
            + ("; ".join(point.limitations) or "в проверенной области")
            for point in self.points
        ]
        self.setAccessibleDescription("\n".join(descriptions))
        self.setToolTip("\n".join(descriptions) or "Завершённых запусков пока нет")
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        foreground = self.palette().text().color()
        painter.setPen(foreground)
        if not self.points:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Нет завершённых запусков")
            return
        left, top, bottom = 36.0, 28.0, self.height() - 38.0
        width = max(1.0, self.width() - left - 30)
        maximum = max((1, *(point.findings or 0 for point in self.points)))
        painter.setPen(QPen(QColor("#64748b"), 1))
        painter.drawLine(QPointF(left, bottom), QPointF(left + width, bottom))
        painter.drawText(QRectF(0, bottom - 10, 30, 20), Qt.AlignmentFlag.AlignRight, "0")
        previous: QPointF | None = None
        for index, point in enumerate(self.points):
            x = left + width * index / max(1, len(self.points) - 1)
            if point.findings is None:
                painter.setPen(foreground)
                painter.drawText(QRectF(x - 10, bottom - 22, 20, 20), Qt.AlignmentFlag.AlignCenter, "?")
                previous = None
                continue
            y = bottom - (bottom - top) * point.findings / maximum
            current = QPointF(x, y)
            painter.setPen(QPen(QColor("#60a5fa"), 2))
            if point.comparable_to_previous and previous is not None:
                painter.drawLine(previous, current)
            painter.setBrush(QColor("#fbbf24" if point.limitations else "#60a5fa"))
            painter.drawEllipse(current, 4, 4)
            painter.setPen(foreground)
            painter.drawText(
                QRectF(x - 25, y - 24, 50, 20), Qt.AlignmentFlag.AlignCenter, str(point.findings)
            )
            if index in (0, len(self.points) - 1):
                date = _date(point.timestamp)
                painter.drawText(
                    QRectF(max(0.0, min(x - 45, self.width() - 100.0)), bottom + 8, 100, 24),
                    Qt.AlignmentFlag.AlignCenter, date,
                )
            previous = current


def _label(text: str, name: str = "") -> QLabel:
    widget = QLabel(text)
    widget.setWordWrap(True)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    if name:
        widget.setObjectName(name)
    return widget


def _date(value: str | None) -> str:
    if not value:
        return "Не указана"
    parsed = datetime.fromisoformat(value)
    return parsed.astimezone().strftime("%d.%m.%Y %H:%M")


def _table(headers: tuple[str, ...], name: str) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setObjectName(name)
    table.setAccessibleName(name)
    table.setHorizontalHeaderLabels(headers)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.verticalHeader().hide()
    table.verticalHeader().setDefaultSectionSize(29)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setMinimumSectionSize(45)
    table.setAlternatingRowColors(True)
    table.setWordWrap(False)
    return table


def _fill(
    table: QTableWidget, rows: list[tuple[str, ...]], tooltips: list[str] | None = None
) -> None:
    table.setRowCount(len(rows))
    for row_index, row in enumerate(rows):
        for column, text in enumerate(row):
            item = QTableWidgetItem(text)
            item.setToolTip(tooltips[row_index] if tooltips else text)
            table.setItem(row_index, column, item)
    table.setMinimumHeight(58 + max(1, len(rows)) * 29)
    table.setMaximumHeight(66 + max(1, len(rows)) * 29)


class ProjectDashboard(QWidget):
    navigation_requested = Signal(str)
    severity_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.snapshot = build_dashboard([], [], [], [])
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        root.addWidget(scroll)
        content = QWidget()
        content.setMaximumWidth(1560)
        scroll.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        layout = QGridLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(16)
        columns: list[QVBoxLayout] = []
        for index in range(3):
            panel = QFrame()
            panel.setObjectName("dashboardColumn")
            panel.setMinimumWidth(320)
            column = QVBoxLayout(panel)
            column.setContentsMargins(12, 12, 12, 12)
            column.setSpacing(12)
            layout.addWidget(panel, 0, index)
            layout.setColumnStretch(index, 1)
            columns.append(column)
        resources, findings, activity = columns
        scroll.setWidget(content)
        resources.addWidget(_label("Инфраструктура", "heading"))
        self.last_check_label = _label("Последняя проверка: ещё не выполнялась")
        resources.addWidget(self.last_check_label)
        metrics = QGridLayout()
        self.summary_labels: dict[str, QLabel] = {}
        for index, (key, title) in enumerate(
            (
                ("integrations", "Облачных подключений"),
                ("virtual_machines", "ВМ в облаке"),
                ("analysis_runs", "Запусков анализа"),
                ("executed_checks", "Выполнено проверок"),
            )
        ):
            card = QFrame()
            card.setObjectName("hero")
            card_layout = QVBoxLayout(card)
            card_layout.addWidget(_label(title))
            value = _label("0")
            value.setStyleSheet("font-size: 24px; font-weight: 600;")
            value.setAccessibleName(title)
            card_layout.addWidget(value)
            self.summary_labels[key] = value
            metrics.addWidget(card, index // 2, index % 2)
        resources.addLayout(metrics)
        self.execution_summary = _label("", "muted")
        activity.addWidget(self.execution_summary)
        self.finding_summary = _label("Находки последних проверенных снимков", "heading")
        findings.addWidget(self.finding_summary)
        self.severity_chart = SeverityBars()
        self.severity_chart.activated.connect(self._open_severity)
        findings.addWidget(self.severity_chart)
        activity.insertWidget(0, _label("Динамика находок", "heading"))
        self.trend_chart = FindingTrendChart()
        activity.insertWidget(1, self.trend_chart)
        self.trend_note = _label("", "muted")
        activity.insertWidget(2, self.trend_note)
        resources.addWidget(_label("Источники", "heading"))
        self.source_table = _table(
            ("Источник", "Сбор", "Анализ", "Последняя попытка", "Успешный сбор", "Ошибок", "Предупр."),
            "dashboardSources",
        )
        resources.addWidget(self.source_table)
        resources.addWidget(_label("Полнота данных", "heading"))
        self.category_table = _table(
            (
                "Категория",
                "Всего",
                "Полностью",
                "Частично",
                "Только сбор",
                "Нет проверки",
                "Устарело",
            ),
            "dashboardCategories",
        )
        self.category_table.setToolTip(
            "Полностью и частично — ресурсы с реальными результатами проверок. "
            "Получение инвентаря не считается проверкой. Архив исключён."
        )
        resources.addWidget(self.category_table)
        for table in (self.source_table, self.category_table):
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            table.horizontalHeader().setDefaultSectionSize(105)
            table.setColumnWidth(0, 150)
            table.setMinimumWidth(0)
        activity.addWidget(_label("Последние проверки", "heading"))
        self.checks_table = _table(("Дата", "Состояние", "Ресурсы", "Проверки"), "dashboardChecks")
        self.checks_table.cellDoubleClicked.connect(
            lambda *_: self.navigation_requested.emit("history")
        )
        activity.addWidget(self.checks_table)
        self.findings_table = _table(("Приоритет", "Всего", "Открыто"), "dashboardFindings")
        self.findings_table.cellDoubleClicked.connect(
            lambda *_: self.navigation_requested.emit("findings")
        )
        findings.addWidget(self.findings_table)
        activity.addWidget(_label("Последние операции", "heading"))
        self.operations_table = _table(
            ("Дата", "Операция", "Состояние", "Ресурсы"), "dashboardOperations"
        )
        self.operations_table.cellDoubleClicked.connect(self._open_operation)
        activity.addWidget(self.operations_table)
        self.coverage_label = _label("", "muted")
        resources.addWidget(self.coverage_label)
        self.navigation_buttons: dict[str, QPushButton] = {}
        for page, text in (
            ("devices", "Инфраструктура"),
            ("findings", "Проблемы"),
            ("history", "Изменения и запуски"),
            ("scans", "Облачный сбор"),
        ):
            button = QPushButton(text)
            button.clicked.connect(
                lambda _checked=False, page=page: self.navigation_requested.emit(page)
            )
            target = (
                resources if page in {"devices", "scans"}
                else findings if page == "findings"
                else activity
            )
            target.addWidget(button, alignment=Qt.AlignmentFlag.AlignLeft)
            self.navigation_buttons[page] = button
        for column in columns:
            column.addStretch()
        self.refresh(self.snapshot)

    def refresh(self, snapshot: DashboardSnapshot) -> None:
        self.snapshot = snapshot
        states = {
            **_STATES, "never": "Сбор ещё не выполнялся",
            "configuration_changed": "Настройки изменены после сбора",
            "invalid": "Некорректные настройки",
            "not_executed": "Не выполнялся", "not_supported": "Не поддержан",
        }
        _fill(self.source_table, [
            (str(source["label"]), states.get(source["state"], source["state"]),
             states.get(source["analysis_state"], source["analysis_state"]),
             _date(source["last_attempt"]), _date(source["last_success"]), str(source["errors"]), str(source.get("warnings", 0)))
            for source in snapshot.source_health
        ])
        self.source_table.setToolTip(
            "Результат последней операции не подтверждает текущую связность. "
            "Даты сбора не заменяют время наблюдения конфигурации. Источники показаны по проекту."
        )
        self.last_check_label.setText(
            "Последняя выполненная проверка: " + _date(snapshot.last_check_at)
            if snapshot.last_check_at
            else "Последняя проверка: ещё не выполнялась"
        )
        self.last_check_label.setToolTip(
            "Местное время компьютера; только реально выполненные проверки."
        )
        for key, label in self.summary_labels.items():
            label.setText(str(getattr(snapshot, key)))
        self.execution_summary.setText(
            f"Проверок за всю историю: {snapshot.executed_checks}; "
            f"частичных: {snapshot.partial_checks}; "
            f"не выполнено: {snapshot.not_executed_checks}.\n"
            f"Ошибок файлов: {snapshot.error_items}; "
            f"неподдержанных входов: {snapshot.unsupported_items}; "
            f"ошибок сбора: {snapshot.collection_errors}."
        )
        self.finding_summary.setText(
            f"Находки последних проверенных снимков: {snapshot.findings} "
            f"· открыто {snapshot.open_findings}"
        )
        self.severity_chart.set_counts(
            snapshot.findings_by_severity, snapshot.open_findings_by_severity
        )
        self.trend_chart.set_points(snapshot.finding_trend)
        limited = sum(bool(point.limitations) for point in snapshot.finding_trend[-12:])
        self.trend_note.setText(
            f"Запусков с ограничениями сравнения: {limited}" if limited else ""
        )
        self.trend_note.setVisible(bool(limited))
        self.trend_chart.setAccessibleDescription(
            self.trend_chart.accessibleDescription()
            + "\nЛинии соединяют сопоставимые запуски; жёлтые точки означают ограничения. "
            "Снижение числа находок не доказывает исправление или безопасность."
        )
        self.trend_chart.setToolTip(
            self.trend_chart.toolTip()
            + "\nПоследние 12 запусков; линии соединяют сопоставимые результаты. "
            "Жёлтые точки означают ограничения сравнения. "
            "Снижение числа находок не доказывает исправление или безопасность."
        )
        _fill(
            self.category_table,
            [
                (
                    category.label,
                    str(category.total),
                    str(category.complete),
                    str(category.partial),
                    str(category.collected),
                    str(category.unchecked),
                    str(category.stale),
                )
                for category in snapshot.categories
            ],
        )
        _fill(
            self.findings_table,
            [
                (
                    _SEVERITY_LABELS[severity],
                    str(snapshot.findings_by_severity[severity]),
                    str(snapshot.open_findings_by_severity[severity]),
                )
                for severity in SEVERITIES
            ],
        )
        _fill(
            self.checks_table,
            [
                (
                    _date(operation.created_at),
                    self._operation_state(operation),
                    str(operation.resources),
                    str(operation.executed_checks),
                )
                for operation in snapshot.recent_checks
            ],
            [self._operation_tooltip(operation) for operation in snapshot.recent_checks],
        )
        _fill(
            self.operations_table,
            [
                (
                    _date(operation.created_at),
                    "Проверка" if operation.kind == "analysis" else "Сбор данных",
                    self._operation_state(operation),
                    str(operation.resources),
                )
                for operation in snapshot.recent_operations
            ],
            [self._operation_tooltip(operation) for operation in snapshot.recent_operations],
        )
        notes = [
            f"В активном реестре: {snapshot.active_resources}; "
            f"в архиве: {snapshot.archived_resources}.",
            *snapshot.warnings,
        ]
        self.coverage_label.setText("\n".join(notes))
        self.finding_summary.setToolTip(
            "Находки по последним проверенным снимкам активных ресурсов. "
            "Открытые исключают resolved/false_positive; принятый риск учтён. "
            "Ноль находок не доказывает безопасность."
        )

    def _open_severity(self, severity: str) -> None:
        self.navigation_requested.emit("findings")
        self.severity_requested.emit(severity)

    @staticmethod
    def _operation_state(operation: OperationSummary) -> str:
        state = _STATES.get(operation.state, operation.state)
        if operation.kind == "analysis" and operation.state == "completed":
            if not operation.executed_checks:
                return state + " · проверки не выполнены"
            if operation.partial_checks or operation.not_executed_checks:
                return state + " · неполно"
        return state

    @staticmethod
    def _operation_tooltip(operation: OperationSummary) -> str:
        return (
            f"ID: {operation.operation_id}\n"
            f"Начато: {_date(operation.created_at)}\n"
            f"Завершено: {_date(operation.finished_at)}\n"
            f"Выполнено проверок: {operation.executed_checks}; "
            f"частично: {operation.partial_checks}; "
            f"не выполнено: {operation.not_executed_checks}\n"
            f"Находок в операции: {operation.findings}"
        )

    def _open_operation(self, row: int, _column: int) -> None:
        if 0 <= row < len(self.snapshot.recent_operations):
            operation = self.snapshot.recent_operations[row]
            self.navigation_requested.emit("history" if operation.kind == "analysis" else "scans")
