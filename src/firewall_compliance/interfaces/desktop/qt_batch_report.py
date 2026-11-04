"""Предпросмотр и экспорт одного зафиксированного пакета отчёта в фоне."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QIODevice, QSaveFile
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.batch_reports import build_batch_report, render_batch_html
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.project_store import ProjectStore


def write_report_file(path: Path, content: str) -> None:
    """QSaveFile публикует файл целиком после успешной записи."""
    data = content.encode("utf-8")
    stream = QSaveFile(str(path))
    if not stream.open(QIODevice.OpenModeFlag.WriteOnly):
        raise OSError("Cannot open report destination")
    if stream.write(data) != len(data):
        stream.cancelWriting()
        raise OSError("Cannot write report")
    if not stream.commit():
        raise OSError("Cannot commit report")


class BatchReportDialog(QDialog):
    def __init__(
        self, store: ProjectStore, runner: JobRunner, project_id: str, run_id: str,
        parent: QWidget | None = None, *, include_fragments: bool = True,
        context_valid: Callable[[], bool] | None = None,
        target: tuple[str, Path] | None = None,
    ) -> None:
        super().__init__(parent)
        self._runner = runner
        self._context_valid = context_valid or (lambda: True)
        self._package: dict[str, Any] | None = None
        self._html = ""
        self._closed = False
        self._ticket: object | None = None
        self.saved_path: Path | None = None
        self.setWindowTitle("Отчёт сохранённого запуска")
        self.resize(1100, 780)
        layout = QVBoxLayout(self)
        self.status = QLabel("Готовим отчёт по сохранённым результатам…")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        layout.addWidget(self.progress)
        self.browser = QTextBrowser()
        self.browser.setOpenLinks(False)
        self.browser.setOpenExternalLinks(False)
        layout.addWidget(self.browser, 1)
        actions = QHBoxLayout()
        self.exports: list[QPushButton] = []
        for kind in ("html", "json"):
            button = QPushButton("Сохранить " + kind.upper())
            button.clicked.connect(lambda _checked=False, kind=kind: self._choose_export(kind))
            actions.addWidget(button)
            self.exports.append(button)
        layout.addLayout(actions)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.finished.connect(self._finish)

        def work() -> tuple[dict[str, Any], str]:
            package = build_batch_report(store, run_id, include_fragments=include_fragments)
            if package["project"]["id"] != project_id:
                raise ValueError("Report run belongs to another project")
            content = render_batch_html(package)
            if target is not None:
                kind, path = target
                if kind not in {"html", "json"}:
                    raise ValueError("Unsupported report format")
                text = content if kind == "html" else json.dumps(package, ensure_ascii=False, indent=2)
                write_report_file(path, text)
            return package, content

        def done(value: Any) -> None:
            self._package, self._html = value
            self.browser.setHtml(self._html)
            self.status.setText(
                f"Запуск: {run_id}; сформировано: {self._package['generated_at']}. "
                "HTML и JSON будут сохранены из этого пакета. "
                + self._package["selection"]["description"]
            )
            if target is not None:
                self.saved_path = target[1]
                self.accept()

        self._job(work, done)

    def _finish(self, _result: int) -> None:
        self._closed = True
        self._ticket = None

    def _job(self, work: Callable[[], object], done: Callable[[Any], None]) -> None:
        if self._closed or not self._context_valid():
            self.reject()
            return
        ticket = object()
        self._ticket = ticket
        self.progress.show()
        for button in self.exports:
            button.setEnabled(False)

        def complete(value: object) -> None:
            if self._closed or ticket is not self._ticket:
                return
            if not self._context_valid():
                self.reject()
                return
            self.progress.hide()
            if isinstance(value, JobError):
                self.status.setText("Отчёт не подготовлен: " + value.message)
                return
            done(value)
            for button in self.exports:
                button.setEnabled(self._package is not None)

        self._runner.submit(work, complete)

    def _choose_export(self, kind: str) -> None:
        package = self._package
        if package is None:
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Сохранить показанный отчёт", f"analysis-{package['run']['id']}.{kind}",
            f"{kind.upper()} (*.{kind})",
        )
        if not filename:
            return
        destination = Path(filename)
        content = self._html

        def work() -> None:
            text = content if kind == "html" else json.dumps(package, ensure_ascii=False, indent=2)
            write_report_file(destination, text)

        self._job(
            work,
            lambda _value: self.status.setText("Отчёт сохранён: " + destination.name),
        )
