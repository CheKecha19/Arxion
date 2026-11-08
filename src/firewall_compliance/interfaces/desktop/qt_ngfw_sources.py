"""Explicit saved NGFW connection editor and read-only collection command."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from threading import Event

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QLabel,
    QLineEdit, QPushButton, QSpinBox, QWidget,
)

from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.ngfw_sources import NgfwSource, SavedNgfwSources
from firewall_compliance.interfaces.desktop.project_store import ProjectStore


class _SourceEditor(QDialog):
    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape and not self.isWindow():
            event.accept()
            return
        super().keyPressEvent(event)


def edit_ngfw_source(
    parent: QWidget, runner: JobRunner, store: ProjectStore, project_id: str,
    provider: str, on_saved: Callable[[Path], None],
) -> None:
    dialog = create_ngfw_source_editor(parent, runner, store, project_id, provider, on_saved)
    dialog.setWindowFlags(Qt.WindowType.Dialog)
    dialog.resize(650, 540)
    dialog.exec()


def create_ngfw_source_editor(
    parent: QWidget, runner: JobRunner, store: ProjectStore, project_id: str,
    provider: str, on_saved: Callable[[Path], None],
    on_changed: Callable[[], None] = lambda: None,
) -> QDialog:
    """Build the same saved-source form for embedding in an integration page."""
    dialog = _SourceEditor(parent)
    dialog.setWindowFlags(Qt.WindowType.Widget)
    dialog.setWindowTitle(f"{provider.title()} — источники данных")
    form = QFormLayout(dialog)
    sources = QComboBox()
    sources.addItem("Новое подключение", None)
    form.addRow("Сохранённый источник", sources)
    fields = {key: QLineEdit() for key in ("label", "host", "username", "password", "ca_file")}
    fields["username"].setText("Admin")
    fields["password"].setEchoMode(QLineEdit.EchoMode.Password)
    for key, title in (("label", "Название"), ("host", "Адрес узла"),
                       ("username", "Пользователь"), ("password", "Пароль"), ("ca_file", "PEM CA")):
        form.addRow(title, fields[key])
    family = QComboBox()
    family.addItems(("UserGate 6 · TCP/HTTP", "UserGate 7 · TCP/HTTP", "UserGate 7.3.3+ · HTTPS"))
    family.setCurrentIndex(2)
    family.setVisible(provider == "usergate")
    if provider == "usergate":
        form.addRow("Профиль", family)
    port = QSpinBox()
    port.setRange(0, 65535)
    port.setSpecialValueText("По умолчанию")
    form.addRow("Порт", port)
    timeout = QSpinBox()
    timeout.setRange(1, 300)
    timeout.setValue(30)
    form.addRow("Таймаут, с", timeout)
    consent = QCheckBox("Сохранить подключение и защищённый пароль для повторных проверок")
    form.addRow(consent)
    status = QLabel()
    status.setWordWrap(True)
    form.addRow(status)
    save = QPushButton("Сохранить подключение")
    collect = QPushButton("Прочитать конфигурацию")
    form.addRow(save)
    form.addRow(collect)
    saved = SavedNgfwSources(store)
    closed = False
    stop = Event()

    def finish(_result: int) -> None:
        nonlocal closed
        closed = True
        stop.set()
        fields["password"].clear()

    dialog.finished.connect(finish)

    def busy(value: bool) -> None:
        dialog.setProperty("operationActive", value)
        for widget in (*fields.values(), sources, family, port, timeout, consent, save, collect):
            widget.setEnabled(not value)

    def selected(_index: int = 0) -> None:
        source = sources.currentData()
        fields["password"].clear()
        consent.setChecked(False)
        if source is None:
            return
        for key in ("label", "host", "username", "ca_file"):
            fields[key].setText(getattr(source, key) or "")
        family.setCurrentIndex(0 if source.family == "6" else 2 if source.transport == "https" else 1)
        port.setValue(source.port or 0)
        timeout.setValue(int(source.timeout))

    sources.currentIndexChanged.connect(selected)

    def loaded(value: object) -> None:
        if closed:
            return
        busy(False)
        if isinstance(value, JobError):
            status.setText("Не удалось прочитать подключения: " + value.message)
            return
        for source in value:
            sources.addItem(source.label, source)

    busy(True)
    runner.submit(lambda: saved.list(project_id, provider), loaded)

    def command(collect_now: bool) -> None:
        if getattr(parent, "_batch_active", False) or getattr(parent, "_restore_busy", False):
            status.setText("Дождитесь завершения текущей операции.")
            return
        old = sources.currentData()
        try:
            config = {
                "provider": provider, "label": fields["label"].text().strip(),
                "host": fields["host"].text().strip(), "username": fields["username"].text().strip(),
                "family": "6" if family.currentIndex() == 0 else "7",
                "transport": "https" if provider == "ideco" or family.currentIndex() == 2 else "tcp",
                "ca_file": fields["ca_file"].text().strip() or None,
                "port": port.value() or None, "timeout": timeout.value(),
            }
            if old is not None:
                config["source_id"] = old.source_id
            source = NgfwSource.model_validate(config)
        except ValueError:
            status.setText("Проверьте название, узел, профиль и параметры соединения.")
            return
        persist = consent.isChecked()
        secret = fields["password"].text()
        if not collect_now and not persist:
            status.setText("Подтвердите сохранение защищённых учётных данных.")
            return
        if (persist or old != source) and not secret:
            status.setText("Для нового или изменённого подключения введите пароль.")
            return
        destination = None
        if collect_now:
            filename, _ = QFileDialog.getSaveFileName(dialog, "Снимок конфигурации", f"{provider}.json", "JSON (*.json)")
            if not filename:
                return
            destination = Path(filename)
            if destination.exists():
                status.setText("Выберите новое имя файла: снимки не перезаписываются.")
                return
        fields["password"].clear()
        busy(True)
        status.setText("Сохранение и чтение…" if collect_now else "Сохранение…")

        def work() -> Path | NgfwSource:
            import json

            if persist:
                saved.save(project_id, source, secret)
            if destination is None:
                return source
            if stop.is_set():
                raise InterruptedError()
            password = secret or saved.password(project_id, source)
            snapshot = source.reader().collect(source.username, password)
            if stop.is_set():
                raise InterruptedError()
            with destination.open("x", encoding="utf-8") as stream:
                json.dump(snapshot, stream, ensure_ascii=False, indent=2, allow_nan=False)
            return destination

        def done(value: object) -> None:
            if closed:
                return
            busy(False)
            if persist and not isinstance(value, JobError):
                on_changed()
            if isinstance(value, JobError):
                status.setText("Операция не завершена. Проверьте соединение, права и файл CA.")
            elif isinstance(value, Path):
                status.setText("Снимок сохранён и передан для анализа.")
                on_saved(value)
            else:
                index = next((i for i in range(1, sources.count()) if sources.itemData(i).source_id == source.source_id), -1)
                if index < 0:
                    sources.addItem(source.label, source)
                    index = sources.count() - 1
                else:
                    sources.setItemData(index, source)
                    sources.setItemText(index, source.label)
                sources.setCurrentIndex(index)
                status.setText("Подключение сохранено. Оно доступно общей команде проверки.")

        runner.submit(work, done)

    save.clicked.connect(lambda: command(False))
    collect.clicked.connect(lambda: command(True))
    return dialog
