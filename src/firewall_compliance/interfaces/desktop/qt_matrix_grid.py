"""Сетка явно заданных пар групп с раскрытием всех требований ячейки."""

from __future__ import annotations

import html
from collections import Counter, defaultdict
from collections.abc import Mapping

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.application.access_matrix import matrix_diagnostics
from firewall_compliance.application.rule_query import parse_port_ranges
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixRequirement
from firewall_compliance.interfaces.desktop.qt_models import RowsModel

_EMPTY_INDEX = QModelIndex()
_ACTIONS = {"permit": "Разрешить", "deny": "Запретить", "unregulated": "Не регламентировано"}
type RequirementEntry = tuple[int, MatrixRequirement]


def _service_label(row: MatrixRequirement) -> str:
    service = row.service
    if service.protocol == "ip":
        return "IP: все IP-протоколы (явное условие)"
    if service.protocol == "icmp":
        return "ICMP: порты неприменимы"
    if service.any_ports:
        return service.protocol.upper() + ": любые порты (задано явно)"
    ports = ", ".join(
        str(port.start) if port.start == port.end else f"{port.start}–{port.end}"
        for port in service.ports
    )
    return service.protocol.upper() + ": " + ports


class MatrixGridModel(QAbstractTableModel):
    """Виртуальная сетка: ячейки не создаются как отдельные Qt-виджеты."""

    def __init__(self, matrix: AccessMatrix, parent: QWidget) -> None:
        super().__init__(parent)
        names: dict[str, list[str]] = defaultdict(list)
        for group in matrix.groups:
            names[group.group_id].append(group.name)
        identifiers = set(names)
        for row in matrix.requirements:
            identifiers.update((row.source_group, row.destination_group))
        self.axes = tuple(sorted(identifiers))
        self.labels = {
            identifier: (
                f"{names[identifier][0]} · {identifier}" if len(names[identifier]) == 1
                else f"{identifier} · конфликт ID группы" if names[identifier]
                else f"{identifier} · группа не определена"
            )
            for identifier in self.axes
        }
        original: dict[tuple[str, str], list[RequirementEntry]] = defaultdict(list)
        for index, row in enumerate(matrix.requirements):
            original[row.source_group, row.destination_group].append((index, row))
        self.original = {key: tuple(values) for key, values in original.items()}
        self.entries: dict[tuple[str, str], tuple[RequirementEntry, ...]] = dict(self.original)

    def replace(self, entries: Mapping[tuple[str, str], tuple[RequirementEntry, ...]]) -> None:
        self.beginResetModel()
        self.entries = dict(entries)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.axes)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.axes)

    def pair(self, index: QModelIndex | QPersistentModelIndex) -> tuple[str, str] | None:
        if (
            not index.isValid() or not 0 <= index.row() < len(self.axes)
            or not 0 <= index.column() < len(self.axes)
        ):
            return None
        return self.axes[index.row()], self.axes[index.column()]

    def headerData(
        self, section: int, orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if not 0 <= section < len(self.axes):
            return None
        label = self.labels[self.axes[section]]
        if role == Qt.ItemDataRole.DisplayRole:
            return label
        if role == Qt.ItemDataRole.ToolTipRole:
            prefix = "Источник" if orientation == Qt.Orientation.Vertical else "Назначение"
            return "<qt>" + html.escape(prefix + ": " + label) + "</qt>"
        return None

    def data(
        self, index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        pair = self.pair(index)
        if pair is None:
            return None
        values = self.entries.get(pair, ())
        counts = Counter(row.requirement for _, row in values)
        if role == Qt.ItemDataRole.DisplayRole:
            if not values:
                return "Нет строк в выборке" if pair in self.original else "Нет явной строки"
            return "\n".join(f"{_ACTIONS[key]}: {counts[key]}" for key in _ACTIONS if counts[key])
        if role == Qt.ItemDataRole.BackgroundRole and len(counts) > 1:
            return QColor("#544724")
        if role == Qt.ItemDataRole.ToolTipRole:
            lines = [self.labels[pair[0]] + " → " + self.labels[pair[1]]]
            if not values:
                lines.append(
                    "Есть строки этой пары, исключённые фильтром."
                    if pair in self.original else "Для этих ID явная строка не задана."
                )
                lines.append("Пересечение и вложенность групп не вычисляются этой сеткой.")
            else:
                lines.append(f"Строк в выборке: {len(values)}. Все доступны в таблице ниже.")
                for position, row in values[:12]:
                    lines.append(
                        f"Строка {position + 1}: {row.requirement_id}; {_ACTIONS[row.requirement]}; "
                        f"{_service_label(row)}; identity: {row.identity or 'без условия'}; "
                        f"область: {row.scope_id}"
                    )
                if len(values) > 12:
                    lines.append("В подсказке показаны первые 12 строк, без ограничения полного списка.")
                if len(counts) > 1:
                    lines.append("Разные требования не объединяются в одно разрешение или запрет.")
            return "<qt>" + "<br>".join(html.escape(line) for line in lines) + "</qt>"
        return None


class MatrixGridDialog(QDialog):
    """Сетка неизменяемого черновика; открытие не сохраняет и не оценивает матрицу."""

    requirement_requested = Signal(int)

    def __init__(
        self, matrix: AccessMatrix, parent: QWidget | None = None, *, scope_id: str | None = None,
    ) -> None:
        super().__init__(parent)
        self._matrix = matrix
        self._diagnostics = matrix_diagnostics(matrix)
        self._current_entries: tuple[RequirementEntry, ...] = ()
        self.setWindowTitle("Матрица: явно заданные пары групп")
        self.resize(1250, 850)
        root = QVBoxLayout(self)
        note = QLabel(
            "Строка — группа источника, столбец — группа назначения. Ячейка раскрывает все "
            "подходящие требования. Сетка не разрешает состав групп и не вычисляет доступность.\n"
            "Identity — точное условие строки; также показываются строки без identity-ограничения. "
            "Членство пользователей в AD не выводится из названия."
        )
        note.setWordWrap(True)
        root.addWidget(note)
        controls = QHBoxLayout()
        self.scope = QComboBox()
        self.scope.setAccessibleName("Область требований в сетке")
        self.scope.addItem("Все области", None)
        for value in sorted({row.scope_id for row in matrix.requirements}):
            self.scope.addItem(value, value)
        if scope_id is not None:
            self.scope.setCurrentIndex(max(0, self.scope.findData(scope_id)))
        controls.addWidget(self.scope)
        self.protocol = QComboBox()
        self.protocol.setAccessibleName("Протокол фильтра сетки")
        self.protocol.addItem("Все протоколы", None)
        for value in ("tcp", "udp", "icmp"):
            self.protocol.addItem(value.upper(), value)
        controls.addWidget(self.protocol)
        self.ports = QLineEdit()
        self.ports.setPlaceholderText("Порты назначения: 443,1000-2000")
        self.ports.setAccessibleName("Порты или диапазоны для пересечения условий сервиса")
        controls.addWidget(self.ports, 1)
        self.identity = QComboBox()
        self.identity.setAccessibleName("Объявленное identity-условие")
        self.identity.addItem("Все identity-условия", None)
        self.identity.addItem("Только без identity-условия", "")
        for value in sorted({row.identity for row in matrix.requirements if row.identity is not None}):
            self.identity.addItem(value, value)
        controls.addWidget(self.identity)
        apply = QPushButton("Применить фильтры")
        apply.clicked.connect(self._apply_filters)
        controls.addWidget(apply)
        reset = QPushButton("Сбросить")
        reset.clicked.connect(self._reset_filters)
        controls.addWidget(reset)
        root.addLayout(controls)
        self.filter_note = QLabel()
        self.filter_note.setTextFormat(Qt.TextFormat.PlainText)
        self.filter_note.setWordWrap(True)
        root.addWidget(self.filter_note)
        diagnostics = QHBoxLayout()
        diagnostics.addWidget(QLabel(f"Диагностических сообщений матрицы: {len(self._diagnostics)}."))
        show_diagnostics = QPushButton("Показать диагностику")
        show_diagnostics.clicked.connect(self._show_diagnostics)
        diagnostics.addWidget(show_diagnostics)
        diagnostics.addStretch(1)
        root.addLayout(diagnostics)
        split = QSplitter(Qt.Orientation.Vertical)
        self.model = MatrixGridModel(matrix, self)
        self.grid = QTableView()
        self.grid.setModel(self.model)
        self.grid.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.grid.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.grid.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.grid.setWordWrap(True)
        self.grid.horizontalHeader().setDefaultSectionSize(190)
        self.grid.verticalHeader().setDefaultSectionSize(88)
        self.grid.setAccessibleName("Сетка явных требований источник × назначение")
        self.grid.selectionModel().currentChanged.connect(self._cell_selected)
        split.addWidget(self.grid)
        lower = QWidget()
        lower_layout = QVBoxLayout(lower)
        self.cell_heading = QLabel("Выберите ячейку сетки.")
        self.cell_heading.setTextFormat(Qt.TextFormat.PlainText)
        self.cell_heading.setWordWrap(True)
        lower_layout.addWidget(self.cell_heading)
        self.rows_model = RowsModel((
            "ID", "Требование", "Сервис", "Identity", "Расписание", "Область", "Политика",
        ))
        self.rows = QTableView()
        self.rows.setModel(self.rows_model)
        self.rows.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rows.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.rows.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.rows.horizontalHeader().setStretchLastSection(True)
        self.rows.setAccessibleName("Все строки выбранной ячейки с отдельными сервисами")
        self.rows.selectionModel().selectionChanged.connect(self._requirement_selected)
        lower_layout.addWidget(self.rows)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setAccessibleName("Полный состав требования или диагностика матрицы")
        self.details.setMaximumHeight(150)
        lower_layout.addWidget(self.details)
        self.open_card = QPushButton("Открыть карточку выбранной строки")
        self.open_card.setEnabled(False)
        self.open_card.clicked.connect(self._open_card)
        lower_layout.addWidget(self.open_card)
        split.addWidget(lower)
        split.setSizes((380, 350))
        root.addWidget(split, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self.protocol.currentIndexChanged.connect(self._pending_filters)
        self.scope.currentIndexChanged.connect(self._pending_filters)
        self.identity.currentIndexChanged.connect(self._pending_filters)
        self.ports.textChanged.connect(self._pending_filters)
        self._apply_filters()

    def _pending_filters(self, *_: object) -> None:
        self.filter_note.setText("Изменения фильтров ещё не применены к сетке.")

    def _reset_filters(self) -> None:
        self.protocol.setCurrentIndex(0)
        self.scope.setCurrentIndex(0)
        self.identity.setCurrentIndex(0)
        self.ports.clear()
        self._apply_filters()

    def _apply_filters(self) -> None:
        protocol, scope, identity = (
            self.protocol.currentData(), self.scope.currentData(), self.identity.currentData(),
        )
        try:
            ports = parse_port_ranges(self.ports.text())
            if self.ports.text().strip() and not ports:
                raise ValueError("Не задано ни одного порта.")
            if ports and protocol not in {"tcp", "udp"}:
                raise ValueError("Для фильтра портов выберите TCP или UDP.")
        except ValueError:
            self.filter_note.setText(
                "Фильтр не применён: порты задаются как 443,1000-2000 в пределах 1–65535; "
                "для них нужен TCP или UDP. Предыдущая выборка сохранена."
            )
            return
        pairs: dict[tuple[str, str], tuple[RequirementEntry, ...]] = {}
        for pair, entries in self.model.original.items():
            matching = []
            for entry in entries:
                row = entry[1]
                if scope is not None and row.scope_id != scope:
                    continue
                if identity == "" and row.identity is not None:
                    continue
                if identity not in {None, ""} and row.identity not in {None, identity}:
                    continue
                if protocol is not None and row.service.protocol not in {"ip", protocol}:
                    continue
                if ports and row.service.protocol != "ip" and not row.service.any_ports:
                    if not any(
                        start <= value.end and end >= value.start
                        for start, end in ports for value in row.service.ports
                    ):
                        continue
                matching.append(entry)
            if matching:
                pairs[pair] = tuple(matching)
        previous = self.grid.currentIndex()
        position = (previous.row(), previous.column()) if previous.isValid() else None
        self.model.replace(pairs)
        count = sum(len(entries) for entries in pairs.values())
        identity_label = "все условия" if identity is None else identity or "только без условия"
        self.filter_note.setText(
            f"Строк: {count} из {len(self._matrix.requirements)}; "
            f"область: {scope or 'все'}; протокол: {protocol or 'все'}; "
            f"порты: {self.ports.text().strip() or 'без отбора'}; identity: {identity_label}. "
            "Порты фильтруются по пересечению; разные требования/сервисы остаются отдельными строками."
        )
        if position is not None:
            self.grid.setCurrentIndex(self.model.index(*position))
            self._cell_selected(self.grid.currentIndex())
        else:
            self._cell_selected(QModelIndex())

    def _cell_selected(self, index: QModelIndex, *_: object) -> None:
        pair = self.model.pair(index)
        self._current_entries = self.model.entries.get(pair, ()) if pair is not None else ()
        self.rows_model.replace([
            (
                row.requirement_id, _ACTIONS[row.requirement], _service_label(row),
                row.identity or "без условия", row.schedule or "без условия",
                row.scope_id, row.policy_id or "не указана",
            )
            for _, row in self._current_entries
        ])
        self.details.clear()
        self.open_card.setEnabled(False)
        self.cell_heading.setText(
            self.model.labels[pair[0]] + " → " + self.model.labels[pair[1]]
            + f" · все строки выборки: {len(self._current_entries)}"
            if pair is not None else "Выберите ячейку сетки."
        )

    def _requirement_selected(self, *_: object) -> None:
        selected = self.rows.selectionModel().selectedRows()
        valid = len(selected) == 1 and 0 <= selected[0].row() < len(self._current_entries)
        self.open_card.setEnabled(valid)
        if not valid:
            return
        position, row = self._current_entries[selected[0].row()]
        self.details.setPlainText("\n".join((
            f"Строка матрицы: {position + 1}; ID: {row.requirement_id}",
            f"{row.source_group} → {row.destination_group}",
            f"Требование: {_ACTIONS[row.requirement]}; сервис: {_service_label(row)}",
            f"Identity: {row.identity or 'без условия'}; расписание: {row.schedule or 'без условия'}",
            f"Область: {row.scope_id}; политика: {row.policy_id or 'не указана'}",
            f"Владелец: {row.owner or 'не указан'}; пересмотр: {row.review_date or 'не задан'}",
            f"Основание: {row.reason or 'не задано'}",
        )))

    def _open_card(self) -> None:
        selected = self.rows.selectionModel().selectedRows()
        if len(selected) == 1 and 0 <= selected[0].row() < len(self._current_entries):
            self.requirement_requested.emit(self._current_entries[selected[0].row()][0])
            self.accept()

    def _show_diagnostics(self) -> None:
        self.rows.clearSelection()
        self.open_card.setEnabled(False)
        self.details.setPlainText("\n\n".join(
            f"{issue.code}: {issue.message}\nГруппы: {', '.join(issue.group_ids) or '—'}\n"
            f"Требования: {', '.join(issue.requirement_ids) or '—'}"
            for issue in self._diagnostics
        ) or "Структурных противоречий не обнаружено. Сверка доступа не выполнялась.")
