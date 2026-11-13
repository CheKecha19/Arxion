"""Находки и полнота проверок в выбранной паре сохранённых снимков."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QComboBox, QHeaderView, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
    QSplitter, QVBoxLayout, QWidget,
)

from firewall_compliance.interfaces.desktop.check_presentation import check_status_label
from firewall_compliance.interfaces.desktop.qt_matrix_inputs import select_matrix_input
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable

_FINDINGS = "Находки"
_COVERAGE = "Полнота проверок"
_FIRST = (
    "Появилась в результатах", "Более не обнаружена", "Отсутствие не подтверждено",
    "Есть во втором результате", "Сопоставление правил не подтверждено", "Неоднозначная сигнатура",
)
_MISSING_FINDING = "Эта находка отсутствует в сохранённом результате."


@dataclass(frozen=True, slots=True)
class MatrixFindingComparisonRow:
    columns: tuple[str, str, str]
    channel: str
    search: str
    before: tuple[str, str]
    after: tuple[str, str]
    reason: str

    @property
    def needs_attention(self) -> bool:
        return self.channel == _COVERAGE or self.columns[2] in _FIRST


def _strings(items: Sequence[object]) -> tuple[str, ...]:
    return tuple(item for item in items if isinstance(item, str) and item)


def _source(location: Mapping[str, Any]) -> str:
    start, end = location.get("line_start"), location.get("line_end")
    anchor = f"строка {start}" if start is not None else None
    if end is not None and end != start:
        anchor = f"строки {start}–{end}"
    return " · ".join(_strings((
        location.get("source_name"), anchor, location.get("object_path"), location.get("object_id"),
    )))


def _check_summary(check: dict[str, Any] | None) -> str:
    if not check or not check.get("status"):
        return "Сохранённых сведений о выполнении проверки нет."
    if check.get("limitations") is None:
        check = {**check, "limitations": ()}
    lines = [check_status_label(check)]
    if version := check.get("check_version"):
        lines.append(f"Версия проверки · {version}")
    for item in check.get("limitations") or ():
        rules = _strings(item.get("rule_ids") or ())
        lines.append(" · ".join(_strings((
            item.get("message"), item.get("code"), f"Правила {', '.join(rules)}" if rules else None,
        ))))
    return "\n".join(lines)


def _finding_summary(finding: Mapping[str, Any]) -> tuple[str, tuple[str, ...]]:
    evidence = finding.get("evidence") or {}
    rules = tuple(dict.fromkeys(_strings((
        *(finding.get("affected_rule_ids") or ()), *(evidence.get("related_rule_ids") or ()),
    ))))
    lines = list(dict.fromkeys(_strings((finding.get("title"), finding.get("description"), evidence.get("summary")))))
    if rules:
        lines.append("Правила · " + ", ".join(rules))
    locations = tuple(filter(None, (_source(item) for item in evidence.get("source_locations") or ())))
    lines.extend(locations)
    lines.extend(_strings(evidence.get("limitations") or ()))
    return "\n".join(lines), (*rules, *locations)


def _finding_side(findings: Sequence[Mapping[str, Any]]) -> tuple[str, tuple[str, ...]]:
    values = tuple(map(_finding_summary, findings))
    return (
        "\n\n".join(text for text, _ in values) if values else _MISSING_FINDING,
        tuple(term for _, terms in values for term in terms),
    )


def prepare_matrix_finding_rows(rows: Sequence[Mapping[str, Any]]) -> tuple[MatrixFindingComparisonRow, ...]:
    """Подготовить поиск и короткие основания в фоновом задании."""
    result = []
    checks: dict[str, tuple[str, str]] = {}
    for row in rows:
        channel = row["channel"]
        if channel not in {_FINDINGS, _COVERAGE}:
            continue
        entity, change, details = row["entity"], row["change"], row["details"]
        check_id, _, title = entity.partition(" · ")
        reasons = tuple(dict.fromkeys(_strings((details.get("limitation"), *(details.get("reasons") or ())))))
        if channel == _FINDINGS:
            if check_id not in checks:
                checks[check_id] = _check_summary(details.get("before_check")), _check_summary(details.get("after_check"))
            old_check, new_check = checks[check_id]
            old_finding, old_terms = _finding_side(details.get("before") or ())
            new_finding, new_terms = _finding_side(details.get("after") or ())
            before, after = (old_check, old_finding), (new_check, new_finding)
            terms = (*old_terms, *new_terms)
        else:
            old_check, new_check = _check_summary(details.get("before")), _check_summary(details.get("after"))
            before, after = (old_check, ""), (new_check, "")
            terms = (old_check, new_check, *reasons)
        columns = check_id, title or "Полнота проверки", change
        search = " ".join((*columns, *terms, channel)).casefold()
        result.append(MatrixFindingComparisonRow(columns, channel, search, before, after, "\n".join(reasons)))
    return tuple(sorted(result, key=lambda row: (
        not row.needs_attention, row.channel == _COVERAGE, row.columns[0], row.columns[1],
    )))


class MatrixComparisonFindings(QWidget):
    requested = Signal(str)

    def __init__(
        self, sources: Sequence[tuple[str, str]], overview: Sequence[str], parent: QWidget,
    ) -> None:
        super().__init__(parent)
        self._sources = dict(sources)
        self._source_id = next(iter(self._sources), None)
        self._pending_id: str | None = None
        self._result_id: str | None = None
        self._error_id: str | None = None
        self._started = False
        self._automatic_category = True
        self._rows: tuple[MatrixFindingComparisonRow, ...] = ()
        root = QVBoxLayout(self)
        intro = QLabel("Находки относятся ко всему выбранному устройству в двух сохранённых снимках.")
        intro.setWordWrap(True)
        root.addWidget(intro)
        if overview:
            note = QLabel("\n".join(overview))
            note.setTextFormat(Qt.TextFormat.PlainText)
            note.setWordWrap(True)
            root.addWidget(note)

        source_row = QHBoxLayout()
        self._source = QLabel()
        self._source.setTextFormat(Qt.TextFormat.PlainText)
        self._source.setWordWrap(True)
        self._source.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        source_row.addWidget(self._source, 1)
        choose = QPushButton("Выбрать устройство…")
        choose.setAutoDefault(False)
        choose.clicked.connect(self._choose)
        choose.setVisible(len(self._sources) > 1)
        source_row.addWidget(choose)
        root.addLayout(source_row)

        status_row = QHBoxLayout()
        self._status = QLabel()
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        self._status.setWordWrap(True)
        status_row.addWidget(self._status, 1)
        self._retry = QPushButton("Повторить")
        self._retry.setAutoDefault(False)
        self._retry.clicked.connect(self._retry_current)
        self._retry.hide()
        status_row.addWidget(self._retry)
        root.addLayout(status_row)

        self._results = QWidget()
        results = QVBoxLayout(self._results)
        results.setContentsMargins(0, 0, 0, 0)
        filters = QHBoxLayout()
        self._query = QLineEdit()
        self._query.setPlaceholderText("Проверка, находка, правило или исходный файл")
        self._query.setAccessibleName("Поиск по находкам выбранного устройства")
        self._query.setClearButtonEnabled(True)
        filters.addWidget(self._query, 1)
        self._category = QComboBox()
        self._category.setAccessibleName("Фильтр находок и полноты проверок")
        self._category.addItem("Изменения и пробелы", "attention")
        self._category.addItem("Все результаты", "all")
        for channel in (_FINDINGS, _COVERAGE):
            self._category.addItem(channel, channel)
        filters.addWidget(self._category)
        results.addLayout(filters)
        vertical = QSplitter(Qt.Orientation.Vertical)
        table_panel = QWidget()
        table_layout = QVBoxLayout(table_panel)
        table_layout.setContentsMargins(0, 0, 0, 0)
        self._table = MatrixTable(("Проверка", "Находка", "Результат сравнения"))
        self._table.setAccessibleName("Сравнение сохранённых находок устройства")
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(0, 180)
        self._table.setColumnWidth(2, 285)
        self._table.verticalHeader().setDefaultSectionSize(48)
        for button in (self._table.previous, self._table.next):
            button.setAutoDefault(False)
            button.clicked.connect(lambda: self._table.selectRow(0))
        table_layout.addWidget(self._table, 1)
        table_layout.addLayout(self._table.navigation())
        vertical.addWidget(table_panel)
        details = QWidget()
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(0, 0, 0, 0)
        self._reason = QLabel()
        self._reason.setTextFormat(Qt.TextFormat.PlainText)
        self._reason.setWordWrap(True)
        details_layout.addWidget(self._reason)
        horizontal = QSplitter(Qt.Orientation.Horizontal)
        self._before = self._side(horizontal, "Было")
        self._after = self._side(horizontal, "Стало")
        horizontal.setSizes((520, 520))
        details_layout.addWidget(horizontal, 1)
        vertical.addWidget(details)
        vertical.setSizes((260, 250))
        results.addWidget(vertical, 1)
        root.addWidget(self._results, 1)
        self._results.hide()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._filter)
        self._query.textChanged.connect(lambda _: self._timer.start())
        self._query.returnPressed.connect(self._filter)
        self._category.currentIndexChanged.connect(self._filter)
        self._category.activated.connect(self._use_selected_category)
        self._table.itemSelectionChanged.connect(self._show_row)
        if self._source_id is None:
            self._source.hide()
            self._status.setText("В двух сверках нет пары снимков устройства с сохранёнными результатами проверок.")
        else:
            self._source.setText(self._sources[self._source_id])
            self._status.setText("Результаты загружаются при открытии вкладки.")

    @staticmethod
    def _side(parent: QSplitter, title: str) -> QPlainTextEdit:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QLabel(title))
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setAccessibleName(f"{title} · находки и полнота сохранённой проверки")
        layout.addWidget(text, 1)
        parent.addWidget(panel)
        return text

    def start(self) -> None:
        self._started = True
        self._request_current()

    def select_source(self, source_id: str) -> bool:
        if source_id not in self._sources:
            return False
        if source_id != self._source_id:
            self._source_id = source_id
            self._source.setText(self._sources[source_id])
            self._rows = ()
            self._result_id = self._error_id = None
            self._results.hide()
            self._retry.hide()
            self._filter()
            self._status.setText("Готовим сравнение проверок выбранных снимков…")
        self._request_current()
        return True

    def _choose(self) -> None:
        choices = tuple(self._sources.items())
        index = select_matrix_input(
            self, [label for _, label in choices], title="Устройство для сравнения находок",
            placeholder="Имя устройства, платформа, контекст или дата",
        )
        if index is not None:
            self.select_source(choices[index][0])

    def _retry_current(self) -> None:
        self._error_id = None
        self._request_current()

    def _use_selected_category(self, _: int) -> None:
        self._automatic_category = False

    def _request_current(self) -> None:
        source_id = self._source_id
        if not self._started or source_id is None or self._pending_id is not None:
            return
        if source_id in (self._result_id, self._error_id):
            return
        self._retry.hide()
        self._pending_id = source_id
        self._status.setText("Читаем сохранённые результаты проверок…")
        self.requested.emit(source_id)

    def _finish_request(self, source_id: str) -> bool:
        if source_id != self._pending_id:
            return False
        self._pending_id = None
        if source_id != self._source_id:
            self._request_current()
            return False
        return True

    def set_result(
        self, source_id: str, rows: Sequence[MatrixFindingComparisonRow], diagnostics: Sequence[str],
    ) -> None:
        if not self._finish_request(source_id):
            return
        self._rows = tuple(rows)
        self._result_id = source_id
        self._results.setVisible(bool(rows))
        if self._automatic_category:
            category = "attention" if any(row.needs_attention for row in rows) else "all"
            self._category.setCurrentIndex(self._category.findData(category))
        findings = sum(row.channel == _FINDINGS for row in rows)
        gaps = len(rows) - findings
        summary = f"Находки · {findings}   Сведения о полноте · {gaps}" if rows else (
            "В сохранённых результатах этой пары нет находок или ограничений для отображения."
        )
        self._status.setText("\n".join((summary, *diagnostics)))
        self._filter()

    def set_error(self, source_id: str, message: str) -> None:
        if not self._finish_request(source_id):
            return
        self._error_id = source_id
        self._status.setText(message)
        self._retry.show()

    def _filter(self, *_: object) -> None:
        self._timer.stop()
        terms = self._query.text().casefold().split()
        channel = self._category.currentData()
        selected = self._table.selected_index()
        indices = [
            index for index, row in enumerate(self._rows)
            if (channel == "all" or row.channel == channel or (channel == "attention" and row.needs_attention))
            and all(term in row.search for term in terms)
        ]
        if indices != self._table.filtered_indices():
            self._table.set_rows(indices, lambda index: self._rows[index].columns, reset=True)
        elif selected is not None:
            return
        page = indices[:self._table.PAGE_SIZE]
        if page:
            self._table.selectRow(page.index(selected) if selected is not None and selected in page else 0)

    def _show_row(self) -> None:
        index = self._table.selected_index()
        if index is None:
            self._reason.clear()
            self._before.clear()
            self._after.clear()
            return
        row = self._rows[index]
        self._reason.setText(row.reason)
        self._before.setPlainText("\n\n".join(filter(None, row.before)))
        self._after.setPlainText("\n\n".join(filter(None, row.after)))
