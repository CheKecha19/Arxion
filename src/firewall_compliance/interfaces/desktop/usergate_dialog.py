"""UserGate read-only collection dialog using the desktop background queue."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QWidget,
)

from firewall_compliance.infrastructure.usergate import UserGateReader
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.project_store import ProjectStore


def collect_usergate(
    parent: QWidget, runner: JobRunner, on_saved: Callable[[Path], None],
    *, store: ProjectStore | None = None, project_id: str | None = None,
) -> None:
    if store is not None and project_id is not None:
        from firewall_compliance.interfaces.desktop.qt_ngfw_sources import edit_ngfw_source

        edit_ngfw_source(parent, runner, store, project_id, "usergate", on_saved)
        return
    dialog = QDialog(parent)
    dialog.setWindowTitle("UserGate — чтение конфигурации")
    form = QFormLayout(dialog)
    form.addRow(QLabel("Доступ только для чтения. Изменение конфигурации запрещено."))
    profile = QComboBox()
    profile.addItems(["6.1.5+ · TCP/HTTP", "7.x · TCP/HTTP", "7.3.3+ · HTTPS"])
    host = QLineEdit()
    username = QLineEdit("Admin")
    password = QLineEdit()
    password.setEchoMode(QLineEdit.EchoMode.Password)
    ca = QLineEdit()
    ca.setPlaceholderText("Необязательно: путь к PEM доверенного CA")
    form.addRow("Версия и соединение", profile)
    form.addRow("Адрес NGFW", host)
    form.addRow("Пользователь", username)
    form.addRow("Пароль", password)
    form.addRow("CA для HTTPS", ca)
    status = QLabel("Для TCP/HTTP используйте защищённую сеть управления.")
    status.setWordWrap(True)
    form.addRow(status)
    button = QPushButton("Прочитать и сохранить снимок")
    form.addRow(button)

    def start() -> None:
        try:
            reader = UserGateReader(
                host.text().strip(),
                family="6" if profile.currentIndex() == 0 else "7",
                transport="https" if profile.currentIndex() == 2 else "tcp",
                ca_file=ca.text().strip() or None,
            )
        except (ValueError, OSError):
            status.setText("Проверьте адрес NGFW и файл CA.")
            return
        filename, _ = QFileDialog.getSaveFileName(
            dialog, "Сохранить снимок", "usergate.json", "JSON (*.json)"
        )
        if not filename:
            return
        target = Path(filename)
        if target.exists():
            status.setText("Выберите новое имя файла: перезапись снимка запрещена.")
            return
        login, secret = username.text(), password.text()
        password.clear()
        button.setEnabled(False)
        status.setText("Чтение конфигурации…")

        def work() -> Path:
            snapshot = reader.collect(login, secret)
            with target.open("x", encoding="utf-8") as stream:
                json.dump(snapshot, stream, ensure_ascii=False, indent=2)
            return target

        def done(result: object) -> None:
            button.setEnabled(True)
            if isinstance(result, JobError):
                status.setText("Сбор не завершён. Проверьте соединение, версию и права API.")
                return
            if isinstance(result, Path):
                status.setText("Снимок сохранён и добавлен к импорту.")
                on_saved(result)

        runner.submit(work, done)

    button.clicked.connect(start)
    dialog.resize(540, 340)
    dialog.exec()
