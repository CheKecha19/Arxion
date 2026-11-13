"""Сетка явно заданных требований и закрытых областей по парам групп."""

from __future__ import annotations

import html
from collections import Counter, defaultdict
from collections.abc import Mapping

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, QSignalBlocker, QTimer, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.application.access_matrix import matrix_diagnostics
from firewall_compliance.application.rule_query import parse_port_ranges
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixBoundary, MatrixRequirement
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable
from firewall_compliance.interfaces.desktop.qt_matrix_zones import zone_pair_caption

_EMPTY_INDEX = QModelIndex()
_ACTIONS = {
    "permit": "Доступ необходим", "allow_optional": "Доступ допустим",
    "deny": "Запретить", "unregulated": "Не регламентировано",
}
_AXIS_PAGE_SIZE = 20
_BOUNDARY_LABEL = "Закрытая область"
type GridEntry = tuple[int, MatrixRequirement | MatrixBoundary]
type GroupPair = tuple[str, str]
type PairCounts = tuple[Counter[str], int]


def _entry_id(row: MatrixRequirement | MatrixBoundary) -> str:
    return row.boundary_id if isinstance(row, MatrixBoundary) else row.requirement_id


def _matching_groups(labels: Mapping[str, str], query: str) -> set[str]:
    terms = query.casefold().split()
    return {key for key, value in labels.items() if all(term in value for term in terms)}


def _service_label(row: MatrixRequirement | MatrixBoundary) -> str:
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


def _policy_label(row: MatrixRequirement | MatrixBoundary) -> str:
    zones = zone_pair_caption(row.zone_pair)
    policy = row.policy_id or "не указана"
    return f"{policy} · {zones}" if zones else policy


class MatrixGridModel(QAbstractTableModel):
    """Виртуальная сетка: ячейки не создаются как отдельные Qt-виджеты."""

    def __init__(self, matrix: AccessMatrix, parent: QWidget) -> None:
        super().__init__(parent)
        names: dict[str, list[str]] = defaultdict(list)
        for group in matrix.groups:
            names[group.group_id].append(group.name)
        self.defined_groups = {identifier for identifier, labels in names.items() if len(labels) == 1}
        identifiers = set(names)
        original: dict[tuple[str, str], list[GridEntry]] = defaultdict(list)
        for rows in (matrix.requirements, matrix.boundaries):
            for index, row in enumerate(rows):
                identifiers.update((row.source_group, row.destination_group))
                original[row.source_group, row.destination_group].append((index, row))
        self.labels = {
            identifier: (
                f"{names[identifier][0]} · {identifier}" if len(names[identifier]) == 1
                else f"{identifier} · конфликт ID группы" if names[identifier]
                else f"{identifier} · группа не определена"
            )
            for identifier in identifiers
        }
        self.search_labels = {identifier: label.casefold() for identifier, label in self.labels.items()}
        self.entry_search = {
            (isinstance(row, MatrixBoundary), index): _entry_id(row).casefold()
            for values in original.values() for index, row in values
        }
        self.original = {
            key: tuple(original[key])
            for key in sorted(original, key=lambda pair: (
                self.search_labels[pair[0]], self.search_labels[pair[1]], pair,
            ))
        }
        self.sources: tuple[str, ...] = ()
        self.destinations: tuple[str, ...] = ()
        self.entries: dict[tuple[str, str], tuple[GridEntry, ...]] = {}
        self._counts: dict[GroupPair, PairCounts] = {}

    def replace(
        self, entries: Mapping[GroupPair, tuple[GridEntry, ...]], counts: Mapping[GroupPair, PairCounts],
        sources: tuple[str, ...], destinations: tuple[str, ...],
    ) -> None:
        self.beginResetModel()
        self.sources, self.destinations = sources, destinations
        self.entries = {
            pair: entries[pair] for source in sources for destination in destinations
            if (pair := (source, destination)) in entries
        }
        self._counts = {pair: counts[pair] for pair in self.entries}
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.sources)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self.destinations)

    def pair(self, index: QModelIndex | QPersistentModelIndex) -> tuple[str, str] | None:
        if (
            not index.isValid() or not 0 <= index.row() < len(self.sources)
            or not 0 <= index.column() < len(self.destinations)
        ):
            return None
        return self.sources[index.row()], self.destinations[index.column()]

    def headerData(
        self, section: int, orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        axis = self.sources if orientation == Qt.Orientation.Vertical else self.destinations
        if not 0 <= section < len(axis):
            return None
        label = self.labels[axis[section]]
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
        statistics = self._counts.get(pair)
        if role == Qt.ItemDataRole.DisplayRole:
            if statistics is None:
                return "Нет строк в выборке" if pair in self.original else "Нет явной строки"
            counts, boundaries = statistics
            lines = [f"Закрытых областей: {boundaries}"] if boundaries else []
            lines.extend(f"{_ACTIONS[key]}: {counts[key]}" for key in _ACTIONS if counts[key])
            return "\n".join(lines)
        if role == Qt.ItemDataRole.BackgroundRole and statistics is not None and len(statistics[0]) > 1:
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
                for _, row in values[:12]:
                    if isinstance(row, MatrixBoundary):
                        title = f"{_BOUNDARY_LABEL} {row.boundary_id} · исключений: {len(row.allowed_requirement_ids)}"
                    else:
                        title = f"{row.requirement_id} · {_ACTIONS[row.requirement]} · identity: {row.identity or 'без условия'}"
                    lines.append(
                        f"{title} · {_service_label(row)} · область: {row.scope_id} · политика: {_policy_label(row)}"
                    )
                if len(values) > 12:
                    lines.append("В подсказке показаны первые 12 строк, без ограничения полного списка.")
                if statistics is not None and len(statistics[0]) > 1:
                    lines.append("Разные требования не объединяются в одно разрешение или запрет.")
            return "<qt>" + "<br>".join(html.escape(line) for line in lines) + "</qt>"
        return None


class _PairListModel(QAbstractTableModel):
    """Одна строка на занятую пару, без пустых пересечений групп."""

    _headers = ("Откуда", "Куда", "Требования", "Закрытые области")

    def __init__(self, labels: Mapping[str, str], parent: QWidget) -> None:
        super().__init__(parent)
        self._labels = labels
        self._pairs: tuple[GroupPair, ...] = ()
        self._positions: dict[GroupPair, int] = {}
        self._counts: dict[GroupPair, PairCounts] = {}

    def replace(self, counts: dict[GroupPair, PairCounts]) -> None:
        self.beginResetModel()
        self._counts = counts
        self._pairs = tuple(counts)
        self._positions = {pair: row for row, pair in enumerate(self._pairs)}
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self._pairs)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = _EMPTY_INDEX) -> int:
        return 0 if parent.isValid() else len(self._headers)

    def index_for_pair(self, pair: GroupPair | None) -> QModelIndex:
        position = self._positions.get(pair) if pair is not None else None
        return self.index(position, 0) if position is not None else QModelIndex()

    def pair(self, index: QModelIndex | QPersistentModelIndex) -> GroupPair | None:
        return self._pairs[index.row()] if index.isValid() and 0 <= index.row() < len(self._pairs) else None

    def headerData(
        self, section: int, orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section] if 0 <= section < len(self._headers) else None
        return None

    def data(
        self, index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        pair = self.pair(index)
        if pair is None:
            return None
        column = index.column()
        if role == Qt.ItemDataRole.TextAlignmentRole and column >= 2:
            return Qt.AlignmentFlag.AlignCenter
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        if column < 2:
            label = self._labels[pair[column]]
            return "<qt>" + html.escape(label) + "</qt>" if role == Qt.ItemDataRole.ToolTipRole else label
        requirements, boundaries = self._counts[pair]
        return str(requirements.total() if column == 2 else boundaries)


class MatrixGridDialog(QDialog):
    """Просмотр заданных пар групп и строк неизменяемого черновика."""

    requirement_requested = Signal(int)
    boundary_requested = Signal(int)
    new_requirements_requested = Signal(str, str)

    def __init__(
        self, matrix: AccessMatrix, parent: QWidget | None = None, *, scope_id: str | None = None,
    ) -> None:
        super().__init__(parent)
        self._matrix = matrix
        self._editing_scope_id = scope_id
        self._diagnostics = None
        self._current_entries: tuple[GridEntry, ...] = ()
        self._selected_pair: GroupPair | None = None
        self._pairs: dict[GroupPair, tuple[GridEntry, ...]] = {}
        self._counts: dict[GroupPair, PairCounts] = {}
        self._sources: tuple[str, ...] = ()
        self._destinations: tuple[str, ...] = ()
        self._source_positions: dict[str, int] = {}
        self._destination_positions: dict[str, int] = {}
        self.setWindowTitle("Пары групп в матрице")
        self.resize(1250, 850)
        root = QVBoxLayout(self)
        note = QLabel(
            "Выберите пару групп, чтобы открыть её требования и закрытые области. "
            "Сетка также показывает пустые пересечения. Доступ определяется при сверке."
        )
        note.setWordWrap(True)
        root.addWidget(note)
        controls = QHBoxLayout()
        self.scope = QComboBox()
        self.scope.setAccessibleName("Область требований")
        self.scope.addItem("Все области", None)
        rows = (*matrix.requirements, *matrix.boundaries)
        for value in sorted({row.scope_id for row in rows}):
            self.scope.addItem(value, value)
        if scope_id is not None:
            self.scope.setCurrentIndex(max(0, self.scope.findData(scope_id)))
        controls.addWidget(self.scope)
        self.policy = QComboBox()
        self.policy.setAccessibleName("Политика требований и закрытых областей")
        self.policy.addItem("Все политики", None)
        self.policy.addItem("Без указанной политики", "")
        for value in sorted({row.policy_id for row in rows if row.policy_id is not None}):
            self.policy.addItem(value, value)
        controls.addWidget(self.policy)
        self.protocol = QComboBox()
        self.protocol.setAccessibleName("Протокол")
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
        self.identity.setToolTip("При выборе условия также видны требования без identity и закрытые области.")
        for value in sorted({row.identity for row in matrix.requirements if row.identity is not None}):
            self.identity.addItem(value, value)
        controls.addWidget(self.identity)
        for selector in (self.scope, self.policy, self.identity):
            selector.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
            selector.setMinimumContentsLength(13)
            selector.setMaxVisibleItems(12)
        reset = QPushButton("Сбросить фильтры")
        reset.clicked.connect(self._reset_filters)
        controls.addWidget(reset)
        root.addLayout(controls)
        axes = QHBoxLayout()
        self.source_filter = QLineEdit()
        self.source_filter.setPlaceholderText("Откуда · имя или ID группы")
        self.source_filter.setAccessibleName("Поиск группы источника")
        self.destination_filter = QLineEdit()
        self.destination_filter.setPlaceholderText("Куда · имя или ID группы")
        self.destination_filter.setAccessibleName("Поиск группы назначения")
        self.entry_filter = QLineEdit()
        self.entry_filter.setPlaceholderText("ID требования или закрытой области")
        self.entry_filter.setAccessibleName("Поиск ID требования или закрытой области")
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(150)
        self._search_timer.timeout.connect(self._apply_filters)
        for field in (self.source_filter, self.destination_filter, self.entry_filter):
            field.setClearButtonEnabled(True)
            axes.addWidget(field, 1)
        root.addLayout(axes)
        for field in (self.source_filter, self.destination_filter, self.entry_filter, self.ports):
            field.textChanged.connect(lambda _text: self._search_timer.start())
        for field in (self.source_filter, self.destination_filter, self.ports):
            field.returnPressed.connect(self._apply_filters)
        self.entry_filter.returnPressed.connect(self._select_entry_by_id)
        self.entry_filter.setToolTip("Enter выбирает строку с точным ID, если она одна в выборке.")
        self.filter_note = QLabel()
        self.filter_note.setTextFormat(Qt.TextFormat.PlainText)
        self.filter_note.setWordWrap(True)
        root.addWidget(self.filter_note)
        diagnostics = QHBoxLayout()
        show_diagnostics = QPushButton("Показать диагностику")
        show_diagnostics.clicked.connect(self._show_diagnostics)
        diagnostics.addWidget(show_diagnostics)
        diagnostics.addStretch(1)
        root.addLayout(diagnostics)
        split = QSplitter(Qt.Orientation.Vertical)
        self.model = MatrixGridModel(matrix, self)
        self.views = QTabWidget()
        self.pair_model = _PairListModel(self.model.labels, self)
        self.pair_list = QTableView()
        self.pair_list.setModel(self.pair_model)
        self.pair_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.pair_list.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.pair_list.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.pair_list.setAccessibleName("Явно заданные пары источников и назначений")
        self.pair_list.setToolTip("Двойной щелчок или Enter открывает единственную строку либо переводит к её списку.")
        self.pair_list.verticalHeader().hide()
        pair_header = self.pair_list.horizontalHeader()
        for column in (0, 1):
            pair_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        self.pair_list.setColumnWidth(2, 116)
        self.pair_list.setColumnWidth(3, 160)
        self.pair_list.selectionModel().currentChanged.connect(self._pair_selected)
        self.pair_list.activated.connect(self._activate_pair)
        self.views.addTab(self.pair_list, "Заданные пары")

        grid_page = QWidget()
        grid_layout = QVBoxLayout(grid_page)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        pages = QHBoxLayout()
        self.source_page = QSpinBox()
        self.destination_page = QSpinBox()
        for title, page in (
            ("Страница источников", self.source_page), ("Страница назначений", self.destination_page),
        ):
            label = QLabel(title)
            label.setBuddy(page)
            pages.addWidget(label)
            page.setAccessibleName(title)
            page.setRange(1, 1)
            page.valueChanged.connect(self._show_page)
            pages.addWidget(page)
        pages.addStretch()
        grid_layout.addLayout(pages)
        self.grid = QTableView()
        self.grid.setModel(self.model)
        self.grid.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.grid.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.grid.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.grid.setWordWrap(True)
        self.grid.horizontalHeader().setDefaultSectionSize(190)
        self.grid.verticalHeader().setDefaultSectionSize(88)
        self.grid.setAccessibleName("Сетка требований и закрытых областей источник × назначение")
        self.grid.selectionModel().currentChanged.connect(self._cell_selected)
        grid_layout.addWidget(self.grid)
        self.views.addTab(grid_page, "Сетка")
        split.addWidget(self.views)
        lower = QWidget()
        lower_layout = QVBoxLayout(lower)
        self.cell_heading = QLabel("Выберите пару групп.")
        self.cell_heading.setTextFormat(Qt.TextFormat.PlainText)
        self.cell_heading.setWordWrap(True)
        lower_layout.addWidget(self.cell_heading)
        self.rows = MatrixTable((
            "ID", "Требование / область", "Сервис", "Identity", "Расписание", "Область", "Политика",
        ))
        self.rows.horizontalHeader().setStretchLastSection(True)
        self.rows.setAccessibleName("Требования и закрытые области выбранной пары")
        self.rows.itemSelectionChanged.connect(self._entry_selected)
        self.rows.itemActivated.connect(self._open_card)
        lower_layout.addWidget(self.rows)
        lower_layout.addLayout(self.rows.navigation())
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setAccessibleName("Полный состав требования или диагностика матрицы")
        self.details.setMaximumHeight(150)
        lower_layout.addWidget(self.details)
        self.open_card = QPushButton("Открыть карточку выбранной строки")
        self.open_card.setAutoDefault(False)
        self.open_card.setEnabled(False)
        self.open_card.clicked.connect(self._open_card)
        self.add_requirements = QPushButton("Добавить требования к паре…")
        self.add_requirements.setAutoDefault(False)
        self.add_requirements.setEnabled(False)
        self.add_requirements.clicked.connect(self._request_new_requirements)
        pair_actions = QHBoxLayout()
        pair_actions.addWidget(self.open_card)
        pair_actions.addWidget(self.add_requirements)
        pair_actions.addStretch()
        lower_layout.addLayout(pair_actions)
        split.addWidget(lower)
        split.setSizes((380, 350))
        root.addWidget(split, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setAutoDefault(False)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        for selector in (self.protocol, self.scope, self.policy, self.identity):
            selector.currentIndexChanged.connect(lambda _index: self._search_timer.start())
        self.views.currentChanged.connect(self._view_changed)
        self._apply_filters()
        self.source_filter.setFocus()

    def _reset_filters(self) -> None:
        self.protocol.setCurrentIndex(0)
        self.scope.setCurrentIndex(0)
        self.policy.setCurrentIndex(0)
        self.identity.setCurrentIndex(0)
        self.ports.clear()
        self.source_filter.clear()
        self.destination_filter.clear()
        self.entry_filter.clear()
        self._apply_filters()

    def _apply_filters(self) -> bool:
        self._search_timer.stop()
        protocol, scope, policy, identity = (
            self.protocol.currentData(), self.scope.currentData(), self.policy.currentData(),
            self.identity.currentData(),
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
            return False
        pairs: dict[GroupPair, tuple[GridEntry, ...]] = {}
        counts: dict[GroupPair, PairCounts] = {}
        requirement_count = boundary_count = 0
        source_filter = self.source_filter.text().strip()
        destination_filter = self.destination_filter.text().strip()
        entry_filter = self.entry_filter.text().strip().casefold()
        sources = _matching_groups(self.model.search_labels, source_filter)
        destinations = _matching_groups(self.model.search_labels, destination_filter)
        for pair, entries in self.model.original.items():
            if pair[0] not in sources or pair[1] not in destinations:
                continue
            matching = []
            for entry in entries:
                index, row = entry
                is_boundary = isinstance(row, MatrixBoundary)
                if entry_filter and entry_filter not in self.model.entry_search[is_boundary, index]:
                    continue
                if scope is not None and row.scope_id != scope:
                    continue
                if policy is not None and (row.policy_id or "") != policy:
                    continue
                if isinstance(row, MatrixRequirement):
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
                requirements = Counter(row.requirement for _, row in matching if isinstance(row, MatrixRequirement))
                total_requirements = requirements.total()
                boundaries = len(matching) - total_requirements
                counts[pair] = requirements, boundaries
                requirement_count += total_requirements
                boundary_count += boundaries
        self._pairs = pairs
        self._counts = counts
        show_empty_intersections = bool(source_filter and destination_filter) or not pairs
        if show_empty_intersections:
            self._sources = self._ordered_axis(sources)
            self._destinations = self._ordered_axis(destinations)
        else:
            self._sources = self._ordered_axis({source for source, _ in pairs})
            self._destinations = self._ordered_axis({destination for _, destination in pairs})
        self._source_positions = {identifier: position for position, identifier in enumerate(self._sources)}
        self._destination_positions = {identifier: position for position, identifier in enumerate(self._destinations)}
        with QSignalBlocker(self.pair_list.selectionModel()):
            self.pair_model.replace(counts)
        self._set_page_ranges()
        self._select_in_active_view(self._selected_pair)
        self.filter_note.setText(
            f"Пар: {len(pairs)} · требований: {requirement_count} · закрытых областей: {boundary_count}"
        )
        return True

    def _select_entry_by_id(self) -> None:
        query = self.entry_filter.text().strip().casefold()
        if not self._apply_filters() or not query:
            return
        match = None
        for pair, entries in self._pairs.items():
            for position, (original, row) in enumerate(entries):
                if self.model.entry_search[isinstance(row, MatrixBoundary), original] == query:
                    if match is not None:
                        return
                    match = pair, position
        if match is not None:
            pair, position = match
            self._select_in_active_view(pair)
            self.rows.show_index(position)

    def _ordered_axis(self, identifiers: set[str]) -> tuple[str, ...]:
        return tuple(sorted(identifiers, key=lambda key: (self.model.search_labels[key], key)))

    def _set_page_ranges(self) -> None:
        for values, page in ((self._sources, self.source_page), (self._destinations, self.destination_page)):
            with QSignalBlocker(page):
                page.setRange(1, max(1, (len(values) + _AXIS_PAGE_SIZE - 1) // _AXIS_PAGE_SIZE))

    def _view_changed(self, *_: object) -> None:
        self._select_in_active_view(self._selected_pair)

    def _select_in_active_view(self, pair: GroupPair | None) -> None:
        if self.views.currentWidget() is self.pair_list:
            index = self.pair_model.index_for_pair(pair)
            if not index.isValid() and len(self._pairs) == 1:
                index = self.pair_model.index(0, 0)
            with QSignalBlocker(self.pair_list.selectionModel()):
                self.pair_list.setCurrentIndex(index)
            if index.isValid():
                self.pair_list.scrollTo(index)
            self._show_pair(self.pair_model.pair(index))
            return
        if pair is None and len(self._pairs) == 1:
            pair = next(iter(self._pairs))
        if pair is not None and pair[0] in self._source_positions and pair[1] in self._destination_positions:
            for position, page in (
                (self._source_positions[pair[0]], self.source_page),
                (self._destination_positions[pair[1]], self.destination_page),
            ):
                with QSignalBlocker(page):
                    page.setValue(position // _AXIS_PAGE_SIZE + 1)
        self._show_grid_page(pair)

    def _show_page(self, *_: object) -> None:
        self._show_grid_page(self._selected_pair)

    def _show_grid_page(self, pair: GroupPair | None) -> None:
        source = (self.source_page.value() - 1) * _AXIS_PAGE_SIZE
        destination = (self.destination_page.value() - 1) * _AXIS_PAGE_SIZE
        sources = self._sources[source:source + _AXIS_PAGE_SIZE]
        destinations = self._destinations[destination:destination + _AXIS_PAGE_SIZE]
        if pair is None and len(self._pairs) == 1:
            pair = next(iter(self._pairs))
        with QSignalBlocker(self.grid.selectionModel()):
            self.model.replace(self._pairs, self._counts, sources, destinations)
            index = (
                self.model.index(sources.index(pair[0]), destinations.index(pair[1]))
                if pair is not None and pair[0] in sources and pair[1] in destinations else QModelIndex()
            )
            self.grid.setCurrentIndex(index)
        self._show_pair(self.model.pair(index))

    def _cell_selected(self, index: QModelIndex, *_: object) -> None:
        self._show_pair(self.model.pair(index))

    def _pair_selected(self, index: QModelIndex, *_: object) -> None:
        self._show_pair(self.pair_model.pair(index))

    def _activate_pair(self, index: QModelIndex) -> None:
        pair = self.pair_model.pair(index)
        if pair is None:
            return
        if self._search_timer.isActive() and not self._apply_filters():
            return
        if pair not in self._pairs:
            return
        self._show_pair(pair)
        if len(self._current_entries) == 1:
            self._open_card()
        else:
            if self.rows.selected_index() is None:
                self.rows.show_index(0)
            self.rows.setFocus()

    def _show_pair(self, pair: GroupPair | None) -> None:
        entries = self._pairs.get(pair, ()) if pair is not None else ()
        if pair is None:
            caption = "Выберите пару групп."
            if self.views.currentWidget() is self.pair_list and not self._pairs:
                caption = "Нет заданных пар по этим фильтрам. Откройте «Сетка», чтобы выбрать пустое пересечение."
        else:
            source, destination = (self.model.labels[key] for key in pair)
            caption = f"{source} → {destination} · строк в выборке: {len(entries)}"
        self.cell_heading.setText(caption)
        scope_matches = self._can_add_to_scope()
        groups_match = pair is not None and all(key in self.model.defined_groups for key in pair)
        self.add_requirements.setEnabled(groups_match and scope_matches)
        scope_hint = f"Область редактора · {self._editing_scope_id}" if self._editing_scope_id else ""
        if not scope_matches:
            scope_hint = "Выберите область редактора или «Все области»."
        elif pair is not None and not groups_match:
            scope_hint = "Для добавления требований обе группы должны быть определены однозначно."
        self.add_requirements.setToolTip(scope_hint)
        if pair == self._selected_pair and entries is self._current_entries:
            return
        previous = self.rows.selected_index()
        selected = (
            self._current_entries[previous] if pair == self._selected_pair and previous is not None else None
        )
        self._selected_pair = pair
        self._current_entries = entries

        def values(position: int) -> tuple[str, ...]:
            row = entries[position][1]
            if isinstance(row, MatrixBoundary):
                return (
                    row.boundary_id, _BOUNDARY_LABEL, _service_label(row),
                    "—", "—", row.scope_id, _policy_label(row),
                )
            return (
                row.requirement_id, _ACTIONS[row.requirement], _service_label(row),
                row.identity or "без условия", row.schedule or "без условия",
                row.scope_id, _policy_label(row),
            )

        self.rows.set_rows(range(len(entries)), values, reset=True)
        if len(entries) == 1:
            self.rows.show_index(0)
        elif selected is not None:
            for position, entry in enumerate(entries):
                if entry is selected:
                    self.rows.show_index(position)
                    break

    def _entry_selected(self) -> None:
        selected = self.rows.selected_index()
        self.open_card.setEnabled(selected is not None)
        if selected is None:
            self.details.clear()
            return
        position, row = self._current_entries[selected]
        if isinstance(row, MatrixBoundary):
            self.details.setPlainText("\n".join((
                f"{_BOUNDARY_LABEL} · ID: {row.boundary_id}",
                f"{row.source_group} → {row.destination_group}",
                f"Сервис: {_service_label(row)} · область: {row.scope_id} · политика: {_policy_label(row)}",
                f"Разрешённых требований: {len(row.allowed_requirement_ids)}.",
                "Запрет относится к остатку указанной области после вычета перечисленных требований.",
            )))
            return
        self.details.setPlainText("\n".join((
            f"Строка матрицы: {position + 1}; ID: {row.requirement_id}",
            f"{row.source_group} → {row.destination_group}",
            f"Требование: {_ACTIONS[row.requirement]}; сервис: {_service_label(row)}",
            f"Identity: {row.identity or 'без условия'}; расписание: {row.schedule or 'без условия'}",
            f"Область: {row.scope_id}; политика: {_policy_label(row)}",
            f"Владелец: {row.owner or 'не указан'}; пересмотр: {row.review_date or 'не задан'}",
            f"Основание: {row.reason or 'не задано'}",
        )))

    def _open_card(self) -> None:
        if self._search_timer.isActive() and not self._apply_filters():
            return
        selected = self.rows.selected_index()
        if selected is not None:
            position, row = self._current_entries[selected]
            self.accept()
            if isinstance(row, MatrixBoundary):
                self.boundary_requested.emit(position)
            else:
                self.requirement_requested.emit(position)

    def _can_add_to_scope(self) -> bool:
        return self._editing_scope_id is None or self.scope.currentData() in {None, self._editing_scope_id}

    def _request_new_requirements(self) -> None:
        pair = self._selected_pair
        if self._search_timer.isActive() and not self._apply_filters():
            return
        if pair is not None and pair == self._selected_pair and self.add_requirements.isEnabled():
            self.accept()
            self.new_requirements_requested.emit(*pair)

    def _show_diagnostics(self) -> None:
        if self._diagnostics is None:
            self._diagnostics = matrix_diagnostics(self._matrix)
        self.rows.clearSelection()
        self.open_card.setEnabled(False)
        self.details.setPlainText("\n\n".join(
            f"{issue.code}: {issue.message}\nГруппы: {', '.join(issue.group_ids) or '—'}\n"
            f"Требования: {', '.join(issue.requirement_ids) or '—'}"
            for issue in self._diagnostics
        ) or "Структурных противоречий не обнаружено. Сверка доступа не выполнялась.")
