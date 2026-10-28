"""Compact project overview; all numbers come from the explicit dashboard snapshot."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
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

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.snapshot = build_dashboard([], [], [], [])
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        root.addWidget(scroll)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 8, 12, 12)
        scroll.setWidget(content)
        layout.addWidget(_label("Обзор проекта", "heading"))
        self.last_check_label = _label("Последняя проверка: ещё не выполнялась")
        layout.addWidget(self.last_check_label)
        metrics = QHBoxLayout()
        self.summary_labels: dict[str, QLabel] = {}
        for key, title in (
            ("integrations", "Облачных подключений"),
            ("virtual_machines", "ВМ в облаке"),
            ("analysis_runs", "Запусков анализа"),
            ("executed_checks", "Выполнено проверок"),
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
            metrics.addWidget(card, 1)
        layout.addLayout(metrics)
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
        self.category_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        layout.addWidget(self.category_table)
        middle = QGridLayout()
        check_panel = QWidget()
        check_layout = QVBoxLayout(check_panel)
        check_layout.setContentsMargins(0, 0, 0, 0)
        check_layout.addWidget(_label("Пять последних запусков проверки"))
        self.checks_table = _table(("Дата", "Состояние", "Ресурсы", "Проверки"), "dashboardChecks")
        self.checks_table.cellDoubleClicked.connect(
            lambda *_: self.navigation_requested.emit("history")
        )
        check_layout.addWidget(self.checks_table)
        check_layout.addStretch()
        middle.addWidget(check_panel, 0, 0)
        finding_panel = QWidget()
        finding_layout = QVBoxLayout(finding_panel)
        finding_layout.setContentsMargins(0, 0, 0, 0)
        finding_layout.addWidget(_label("Находки последних проверенных снимков"))
        self.findings_table = _table(("Приоритет", "Всего", "Открыто"), "dashboardFindings")
        self.findings_table.cellDoubleClicked.connect(
            lambda *_: self.navigation_requested.emit("findings")
        )
        finding_layout.addWidget(self.findings_table)
        finding_layout.addStretch()
        middle.addWidget(finding_panel, 0, 1)
        middle.setColumnStretch(0, 1)
        middle.setColumnStretch(1, 1)
        layout.addLayout(middle)
        layout.addWidget(_label("Последние операции"))
        self.operations_table = _table(
            ("Дата", "Операция", "Состояние", "Ресурсы"), "dashboardOperations"
        )
        self.operations_table.cellDoubleClicked.connect(self._open_operation)
        layout.addWidget(self.operations_table)
        self.coverage_label = _label("", "muted")
        layout.addWidget(self.coverage_label)
        actions = QHBoxLayout()
        self.navigation_buttons: dict[str, QPushButton] = {}
        for page, text in (
            ("devices", "Инфраструктура"),
            ("findings", "Проблемы"),
            ("history", "История"),
            ("scans", "Облачный сбор"),
        ):
            button = QPushButton(text)
            button.clicked.connect(
                lambda _checked=False, page=page: self.navigation_requested.emit(page)
            )
            actions.addWidget(button)
            self.navigation_buttons[page] = button
        layout.addLayout(actions)
        layout.addStretch()
        self.refresh(self.snapshot)

    def refresh(self, snapshot: DashboardSnapshot) -> None:
        self.snapshot = snapshot
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
            f"в архиве: {snapshot.archived_resources}. "
            f"Частичных проверок за всю историю: {snapshot.partial_checks}; "
            f"не выполненных: {snapshot.not_executed_checks}.",
            "Один запуск анализа может выполнять несколько проверок.",
            "Находки — по последним проверенным снимкам активных ресурсов. "
            "«Открыто» исключает resolved/false_positive; принятый риск остаётся учтённым. "
            "Ноль находок не доказывает безопасность.",
            *snapshot.warnings,
        ]
        self.coverage_label.setText("\n".join(notes))

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
