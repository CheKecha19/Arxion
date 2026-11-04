"""Таблица различий сохранённых запусков и карточка было/стало."""

from __future__ import annotations

import html
import json
import sqlite3
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QSortFilterProxyModel, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.qt_batch_report import write_report_file
from firewall_compliance.interfaces.desktop.qt_models import RowsModel
from firewall_compliance.interfaces.desktop.run_comparison import compare_saved_runs
from firewall_compliance.interfaces.desktop.run_comparison_store import RunComparisonStore
from firewall_compliance.interfaces.desktop.run_comparison_store import RunComparisonSummary
from firewall_compliance.application.run_comparison_artifact import RunComparisonArtifact


class RunComparisonDialog(QDialog):
    def __init__(
        self, before: dict[str, Any], after: dict[str, Any], runner: JobRunner,
        parent: QWidget | None = None, *, context_valid: Callable[[], bool] | None = None,
        load_runs: Callable[[], tuple[dict[str, Any], dict[str, Any]]] | None = None,
        selection_basis: str = "Два запуска выбраны вручную.",
        comparison_store: RunComparisonStore | None = None,
        load_comparison: Callable[[], RunComparisonArtifact] | None = None,
    ) -> None:
        super().__init__(parent)
        self._runner = runner
        self._context_valid = context_valid or (lambda: True)
        self._closed = False
        self._package: dict[str, Any] | None = None
        self._rows: list[dict[str, Any]] = []
        self._selection_basis = selection_basis
        self.setWindowTitle("Сравнение сохранённых запусков")
        self.resize(1250, 800)
        root = QVBoxLayout(self)
        self.context = QLabel(
            f"Было: {before.get('created_at')} · {before['id']}\n"
            f"Стало: {after.get('created_at')} · {after['id']}"
        )
        self.context.setWordWrap(True)
        root.addWidget(self.context)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        root.addWidget(self.progress)
        filters = QHBoxLayout()
        self.channel = QComboBox()
        self.channel.addItem("Все каналы", None)
        self.channel.currentIndexChanged.connect(self._filter)
        filters.addWidget(self.channel)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Устройство, ID, вид изменения…")
        self.search.textChanged.connect(self._filter)
        filters.addWidget(self.search, 1)
        root.addLayout(filters)
        split = QSplitter(Qt.Orientation.Vertical)
        self.model = RowsModel(("Устройство", "Канал", "Изменение", "Объект"))
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.selectionModel().selectionChanged.connect(self._selected)
        self.table.setAccessibleName("Различия запусков по независимым каналам")
        split.addWidget(self.table)
        detail = QSplitter(Qt.Orientation.Horizontal)
        self.before = self._detail("Было: значения сохранённого снимка")
        self.after = self._detail("Стало: значения сохранённого снимка")
        self.evidence = self._detail("Основание и ограничения различия")
        for panel in (self.before, self.after, self.evidence):
            detail.addWidget(panel)
        split.addWidget(detail)
        split.setSizes((450, 260))
        root.addWidget(split, 1)
        self.status = QLabel("Сравниваем сохранённые ревизии…")
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        actions = QHBoxLayout()
        self.exports = []
        for kind in ("html", "json"):
            button = QPushButton("Сохранить " + kind.upper())
            button.setEnabled(False)
            button.clicked.connect(lambda _checked=False, kind=kind: self._export(kind))
            actions.addWidget(button)
            self.exports.append(button)
        root.addLayout(actions)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self.finished.connect(self._finish)

        def work() -> dict[str, Any]:
            if load_comparison is not None:
                artifact = load_comparison()
                package = artifact.model_dump(mode="json")["package"]
                package["saved_comparison_id"] = str(artifact.comparison_id)
                package["saved_at"] = artifact.saved_at.isoformat()
                return package
            if load_runs is not None:
                first, second = load_runs()
            else:
                first = json.loads(json.dumps(before, ensure_ascii=False))
                second = json.loads(json.dumps(after, ensure_ascii=False))
            result = compare_saved_runs(first, second)
            result["selection_basis"] = selection_basis
            if comparison_store is not None:
                try:
                    comparison_store.initialize()
                    artifact = comparison_store.save(result["project_id"], result)
                    result["saved_comparison_id"] = str(artifact.comparison_id)
                    result["saved_at"] = artifact.saved_at.isoformat()
                except (ValueError, TypeError, OSError, sqlite3.Error):
                    result["persistence_warning"] = "Результат вычислен, но сохранить его в историю не удалось. Доступен экспорт."
            return result

        self._runner.submit(work, self._complete)

    @staticmethod
    def _detail(name: str) -> QPlainTextEdit:
        panel = QPlainTextEdit()
        panel.setReadOnly(True)
        panel.setAccessibleName(name)
        panel.setPlaceholderText(name)
        return panel

    def _finish(self, _result: int) -> None:
        self._closed = True

    def _complete(self, value: object) -> None:
        if self._closed:
            return
        if not self._context_valid():
            self.reject()
            return
        self.progress.hide()
        if isinstance(value, JobError):
            self.status.setText("Сравнение не завершено: " + value.message)
            return
        if not isinstance(value, dict):
            self.status.setText("Результат сравнения недоступен.")
            return
        self._package = value
        self.context.setText(
            f"Было: {value['before_created_at']} · {value['before_run_id']}\n"
            f"Стало: {value['after_created_at']} · {value['after_run_id']}\nСопоставимость профилей: "
            + ("подтверждена" if value["profiles"]["comparable"] else "не подтверждена")
            + " · Область входов: "
            + ("сопоставима" if value["input_scopes"]["comparable"] else "сопоставимость не подтверждена")
            + "\n" + value.get("selection_basis", self._selection_basis)
            + (
                "\nСохранённое сравнение: " + value["saved_comparison_id"]
                if value.get("saved_comparison_id") else ""
            )
        )
        self._rows = value["rows"]
        self.channel.blockSignals(True)
        for name in sorted({row["channel"] for row in self._rows}):
            self.channel.addItem(name, name)
        self.channel.blockSignals(False)
        counts = Counter(row["channel"] for row in self._rows)
        self.status.setText(
            " · ".join(f"{key}: {count}" for key, count in sorted(counts.items()))
            + "\n" + "\n".join(value["limitations"])
            + ("\n" + value["persistence_warning"] if value.get("persistence_warning") else "")
        )
        self.evidence.setPlainText(json.dumps({
            "profiles": value["profiles"], "unresolved_before": value["unresolved_before"],
            "unresolved_after": value["unresolved_after"],
        }, ensure_ascii=False, indent=2))
        self._filter()
        for button in self.exports:
            button.setEnabled(True)

    def _filter(self, *_: object) -> None:
        query = self.search.text().strip().casefold()
        channel = self.channel.currentData()
        selected = [
            row for row in self._rows
            if (channel is None or row["channel"] == channel)
            and (not query or query in " ".join(
                str(row[key]) for key in ("device", "channel", "change", "entity")
            ).casefold())
        ]
        self.model.replace(
            [(row["device"], row["channel"], row["change"], row["entity"]) for row in selected], selected,
        )
        self.before.clear()
        self.after.clear()
        if self._package is not None:
            self.evidence.setPlainText(json.dumps({
                "profiles": self._package["profiles"],
                "input_scopes": self._package["input_scopes"],
                "unresolved_before": self._package["unresolved_before"],
                "unresolved_after": self._package["unresolved_after"],
            }, ensure_ascii=False, indent=2))

    def _selected(self, *_: object) -> None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return
        row = self.model.payloads[self.proxy.mapToSource(selected[0]).row()]
        details = row["details"]
        first = details.get("before_value", details.get("before")) if isinstance(details, dict) else None
        second = details.get("after_value", details.get("after")) if isinstance(details, dict) else None
        if isinstance(details, dict) and first is None and second is None:
            facts = (details.get("evidence") or {}).get("facts") or {}
            first, second = facts.get("before"), facts.get("after")
        self.before.setPlainText(
            json.dumps(first, ensure_ascii=False, indent=2) if first is not None
            else "Для этой стороны сохранённое значение отсутствует."
        )
        self.after.setPlainText(
            json.dumps(second, ensure_ascii=False, indent=2) if second is not None
            else "Для этой стороны сохранённое значение отсутствует."
        )
        self.evidence.setPlainText(json.dumps(details, ensure_ascii=False, indent=2))

    def _export(self, kind: str) -> None:
        package = self._package
        if package is None:
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Сохранить сравнение", f"comparison.{kind}", f"{kind.upper()} (*.{kind})",
        )
        if not filename:
            return
        destination = Path(filename)
        rows = tuple(self.model.payloads)
        for button in self.exports:
            button.setEnabled(False)
        self.progress.show()

        def work() -> str:
            selection = {"mode": "view" if channel is not None or query else "full_comparison", "channel": channel, "query": query}
            if kind == "json":
                exported = {**package, "selection": selection, "rows": rows}
                if selection["mode"] == "view":
                    device_ids = {row["device"] for row in rows}
                    exported["devices"] = [{
                        "device_id": device["device_id"], "state": device["state"],
                        "before_item_ids": device["before_item_ids"],
                        "after_item_ids": device["after_item_ids"],
                        "before_revision_id": (device.get("before_revision") or {}).get("revision_id"),
                        "after_revision_id": (device.get("after_revision") or {}).get("revision_id"),
                    } for device in package["devices"] if device["device_id"] in device_ids]
                    exported["unresolved_before"] = []
                    exported["unresolved_after"] = []
                    selection["description"] = "Выборка строк; полные ревизии и неидентифицированные входы не включены."
                text = json.dumps(exported, ensure_ascii=False, indent=2)
            else:
                def escape(value: object) -> str:
                    return html.escape(str(value), quote=True)
                sections = [
                    '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Сравнение запусков</title><body>',
                    "<h1>Сравнение сохранённых запусков</h1>",
                    f"<p>Было: {escape(package['before_run_id'])}; стало: {escape(package['after_run_id'])}</p>",
                    f"<p>Выборка: {escape(channel or 'все каналы')}; поиск: {escape(query or 'не задан')}</p>",
                    f"<p>Сформировано: {escape(package['generated_at'])}; "
                    f"профили сопоставимы: {escape(package['profiles']['comparable'])}</p>",
                    "<ul>" + "".join(f"<li>{escape(value)}</li>" for value in package["limitations"]) + "</ul>",
                ]
                for row in rows:
                    sections.append(f"<h2>{escape(row['device'])} · {escape(row['channel'])} · {escape(row['change'])}</h2>")
                    sections.append("<pre>" + escape(json.dumps(row["details"], ensure_ascii=False, indent=2)) + "</pre>")
                text = "\n".join((*sections, "</body></html>"))
            write_report_file(destination, text)
            return destination.name

        channel, query = self.channel.currentData(), self.search.text().strip()

        def done(value: object) -> None:
            if self._closed or not self._context_valid():
                return
            self.progress.hide()
            for button in self.exports:
                button.setEnabled(True)
            self.status.setText(
                "Экспорт не завершён: " + value.message if isinstance(value, JobError)
                else "Сравнение сохранено: " + str(value)
            )

        self._runner.submit(work, done)


class ComparisonHistoryDialog(QDialog):
    def __init__(
        self, store: RunComparisonStore, runner: JobRunner, project_id: str,
        parent: QWidget | None = None, *, site_id: str | None = None,
        context_valid: Callable[[], bool] | None = None,
    ) -> None:
        super().__init__(parent)
        self._store, self._runner, self._project_id = store, runner, project_id
        self._site_id = site_id
        self._context_valid = context_valid or (lambda: True)
        self._closed = False
        self._offset = 0
        self._values: tuple[RunComparisonSummary, ...] = ()
        self._count = 0
        self.setWindowTitle("История сравнений")
        self.resize(950, 300)
        root = QVBoxLayout(self)
        note = QLabel("Сохранённые сравнения читаются с проверкой целостности, без повторного анализа.")
        note.setWordWrap(True)
        root.addWidget(note)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        root.addWidget(self.progress)
        self.selector = QComboBox()
        self.selector.setAccessibleName("Сохранённые сравнения текущей области")
        root.addWidget(self.selector)
        actions = QHBoxLayout()
        self.open_button = QPushButton("Открыть сравнение")
        self.open_button.clicked.connect(self._open)
        self.previous = QPushButton("← Новее")
        self.previous.clicked.connect(lambda: self._page(-1))
        self.next = QPushButton("Старее →")
        self.next.clicked.connect(lambda: self._page(1))
        for button in (self.open_button, self.previous, self.next):
            actions.addWidget(button)
        root.addLayout(actions)
        self.status = QLabel()
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self.finished.connect(self._finish)
        self._reload()

    def _finish(self, _result: int) -> None:
        self._closed = True

    def _page(self, direction: int) -> None:
        self._offset = max(0, self._offset + direction * 100)
        self._reload()

    def _reload(self) -> None:
        offset = self._offset
        self.progress.show()
        for widget in (self.selector, self.open_button, self.previous, self.next):
            widget.setEnabled(False)

        def work() -> object:
            return self._store.history(self._project_id, site_id=self._site_id, offset=offset)

        def done(value: object) -> None:
            if self._closed:
                return
            if not self._context_valid():
                self.reject()
                return
            self.progress.hide()
            if isinstance(value, JobError):
                self.status.setText("История недоступна: " + value.message)
                return
            if not isinstance(value, tuple):
                self.status.setText("Не удалось прочитать историю сравнений.")
                return
            self._values, self._count = value
            self.selector.clear()
            for record in self._values:
                self.selector.addItem(
                    f"{record.saved_at} · {record.before_run_id} → {record.after_run_id}"
                    + (f" · площадка {record.site_id}" if record.site_id is not None else " · все площадки"),
                    record.comparison_id,
                )
            self.selector.setEnabled(bool(self._values))
            self.open_button.setEnabled(bool(self._values))
            self.previous.setEnabled(offset > 0)
            self.next.setEnabled(offset + len(self._values) < self._count)
            self.status.setText(
                f"Записи {offset + 1}–{offset + len(self._values)} из {self._count}."
                if self._values else "Сохранённых сравнений в этой области нет."
            )

        self._runner.submit(work, done)

    def _open(self) -> None:
        index = self.selector.currentIndex()
        if not 0 <= index < len(self._values):
            return
        record = self._values[index]
        dialog = RunComparisonDialog(
            {"id": record.before_run_id}, {"id": record.after_run_id}, self._runner, self,
            context_valid=lambda: not self._closed and self._context_valid(),
            load_comparison=lambda: self._store.get(self._project_id, record.comparison_id),
        )
        dialog.exec()
        dialog.deleteLater()
