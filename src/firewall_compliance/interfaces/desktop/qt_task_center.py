"""Read-only task center over the existing run and scan history."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.project_store import ProjectStore

STATES = {
    "running": "Выполняется",
    "completed": "Завершено",
    "partial": "Частично",
    "failed": "Ошибка",
    "error": "Ошибка",
    "interrupted": "Прервано / частичный результат",
    "cancelled": "Отменено",
    "canceled": "Отменено",
    "queued": "В очереди",
}


class TaskCenterDialog(QDialog):
    open_run = Signal(str)
    open_scan = Signal(str)
    retry_requested = Signal(str, str)

    def __init__(
        self,
        store: ProjectStore,
        project_id: str,
        active: Callable[[], list[dict[str, Any]]],
        context_valid: Callable[[], bool],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Задачи и история операций")
        self.resize(940, 560)
        self._store, self._project_id = store, project_id
        self._active, self._valid = active, context_valid
        self._runner = JobRunner()
        self._closed = False
        self._loading = False
        self._rows: list[dict[str, Any]] = []
        self._saved: list[dict[str, Any]] = []
        layout = QVBoxLayout(self)
        self.status = QLabel("Чтение истории…")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ("Тип", "Состояние", "Начало (UTC)", "Завершение (UTC)", "Элементов", "Ошибок", "Ограничения")
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAccessibleName("Операции выбранного проекта")
        self.table.itemDoubleClicked.connect(lambda *_: self._open())
        layout.addWidget(self.table, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self.open_button = QPushButton("Открыть результат")
        self.open_button.clicked.connect(self._open)
        buttons.addButton(self.open_button, QDialogButtonBox.ButtonRole.ActionRole)
        retry = QPushButton("Повторить неуспешные элементы")
        retry.clicked.connect(self._retry)
        buttons.addButton(retry, QDialogButtonBox.ButtonRole.ActionRole)
        refresh = QPushButton("Обновить")
        refresh.clicked.connect(self._reload)
        buttons.addButton(refresh, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.finished.connect(self._finish)
        self._poll = QTimer(self)
        self._poll.timeout.connect(self._tick)
        self._poll.start(150)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._reload)
        self._refresh_timer.start(3000)
        self._reload()

    def _finish(self, _result: int) -> None:
        self._closed = True
        self._poll.stop()
        self._refresh_timer.stop()
        self._runner.shutdown()

    def _tick(self) -> None:
        if not self._valid():
            self.reject()
            return
        self._runner.poll()
        self._render()

    def _reload(self) -> None:
        if self._closed or self._loading or not self._valid():
            return
        self._loading = True

        def work() -> list[dict[str, Any]]:
            rows = []
            for run in self._store.project_history(self._project_id, compact=True):
                items = run["items"]
                rows.append({
                    "kind": "run", "id": run["id"], "state": run["state"],
                    "created_at": run["created_at"], "finished_at": run.get("finished_at"),
                    "count": len(items),
                    "errors": sum(
                        item.get("status") in {"error", "failed", "unsupported"} for item in items
                    ),
                    "limitations": (
                        f"Частичных: {sum(item.get('status') == 'partial' for item in items)}; "
                        f"предупреждений о составе: {sum(len(item.get('collection_warnings', ())) for item in items)}"
                    ),
                })
            for scan in self._store.project_cloud_scan_summaries(
                self._project_id, include_inventory=False,
            ):
                result = scan.get("result") or {}
                rows.append({
                    "kind": "scan", "id": scan["id"], "state": scan["state"],
                    "created_at": scan["created_at"], "finished_at": scan.get("finished_at"),
                    "count": scan.get("record_count", len(result.get("records", ()))),
                    "errors": len(result.get("errors", ())),
                    "limitations": (
                        "Сбор инвентаря не подтверждает проверку правил; "
                        f"предупреждений о составе: {len(result.get('integrity_warnings', ()))}"
                    ),
                })
            return sorted(rows, key=lambda row: row["created_at"], reverse=True)

        def done(value: object) -> None:
            if self._closed or not self._valid():
                return
            self._loading = False
            if isinstance(value, JobError):
                self.status.setText("История не обновлена: " + value.message)
                return
            if not isinstance(value, list):
                self.status.setText("Не удалось прочитать историю операций.")
                return
            self._saved = value
            self.status.setText(
                "История исходного проекта; даты операций не заменяют время наблюдения конфигураций."
            )
            self._render()

        self._runner.submit(work, done)

    def _render(self) -> None:
        active = self._active()
        active_keys = {(row["kind"], row.get("id")) for row in active}
        rows = [*active, *(row for row in self._saved if (row["kind"], row["id"]) not in active_keys)]
        if rows == self._rows:
            return
        selected = self.table.currentRow()
        selected_key = (
            (self._rows[selected]["kind"], self._rows[selected].get("id"))
            if 0 <= selected < len(self._rows) else None
        )
        self._rows = rows
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = (
                {"run": "Проверка", "scan": "Облачный сбор", "cycle": "Полный цикл"}[row["kind"]],
                STATES.get(row["state"], row["state"]),
                row.get("created_at") or "—", row.get("finished_at") or "—",
                str(row.get("count", "—")), str(row.get("errors", "—")),
                row.get("limitations", ""),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(index, column, item)
            if (row["kind"], row.get("id")) == selected_key:
                self.table.selectRow(index)
        self.table.resizeColumnsToContents()

    def _open(self) -> None:
        index = self.table.currentRow()
        if not 0 <= index < len(self._rows) or not self._valid():
            return
        row = self._rows[index]
        if not row.get("id") or row["state"] in {"running", "queued"}:
            self.status.setText("Операция ещё выполняется; завершённый результат пока недоступен.")
            return
        self.accept()
        (self.open_run if row["kind"] == "run" else self.open_scan).emit(row["id"])

    def _retry(self) -> None:
        index = self.table.currentRow()
        if not 0 <= index < len(self._rows) or not self._valid():
            return
        row = self._rows[index]
        if not row.get("id") or row["state"] in {"running", "queued"} or row["kind"] not in {"run", "scan"}:
            self.status.setText("Выберите завершённую операцию с ошибками или ограничениями.")
            return
        self.accept()
        self.retry_requested.emit(row["kind"], row["id"])
