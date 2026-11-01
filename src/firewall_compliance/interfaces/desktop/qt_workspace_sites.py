"""Explicit site assignments; all database access uses the desktop job runner."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.application.workspace_profile import ProfileVersion
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.profile_history import LegacyProfileHistory
from firewall_compliance.interfaces.desktop.project_store import ProjectStore


class WorkspaceSitesDialog(QDialog):
    """Keep legacy project provenance separate from user-assigned physical sites."""

    def __init__(
        self,
        store: ProjectStore,
        runner: JobRunner,
        project_id: str,
        context_valid: Callable[[], bool],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._runner = runner
        self._project_id = project_id
        self._context_valid = context_valid
        self._closed = False
        self._ticket: object | None = None
        self.setWindowTitle("Назначения площадок")
        self.resize(820, 560)
        layout = QVBoxLayout(self)
        explanation = QLabel(
            "Площадки задаются явно. Проекты и исходные конфигурации сохраняются.\n"
            "Ниже — устройства выбранного проекта. Назначения пока не фильтруют другие экраны.\n"
            "При первом сохранении площадок или версии настроек создаётся резервная копия БД."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        body = QHBoxLayout()
        site_column = QVBoxLayout()
        site_column.addWidget(QLabel("Площадки рабочего места"))
        self.sites = QListWidget()
        self.sites.setAccessibleName("Площадки рабочего места")
        site_column.addWidget(self.sites)
        self.create = QPushButton("Создать площадку")
        self.create.clicked.connect(self._create_site)
        site_column.addWidget(self.create)
        self.rename = QPushButton("Переименовать")
        self.rename.clicked.connect(self._rename_site)
        site_column.addWidget(self.rename)
        body.addLayout(site_column, 1)
        device_column = QVBoxLayout()
        device_column.addWidget(QLabel("Устройства выбранного проекта"))
        self.devices = QTableWidget(0, 3)
        self.devices.setHorizontalHeaderLabels(("Устройство", "Площадка", "Последний анализ"))
        self.devices.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.devices.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.devices.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.devices.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        device_column.addWidget(self.devices)
        self.target = QComboBox()
        self.target.setAccessibleName("Площадка для выбранных устройств")
        device_column.addWidget(self.target)
        self.assign = QPushButton("Назначить выбранным устройствам")
        self.assign.clicked.connect(self._assign)
        device_column.addWidget(self.assign)
        body.addLayout(device_column, 3)
        layout.addLayout(body, 1)
        self.profile_status = QLabel("Версии настроек проверки загружаются…")
        self.profile_status.setWordWrap(True)
        self.profile_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.profile_status)
        self.save_profile = QPushButton("Сохранить версию настроек проверки")
        self.save_profile.clicked.connect(self._save_profile)
        layout.addWidget(self.save_profile)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        layout.addWidget(self.progress)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        self.refresh = QPushButton("Обновить")
        self.refresh.clicked.connect(self._reload)
        buttons.addButton(self.refresh, QDialogButtonBox.ButtonRole.ActionRole)
        layout.addWidget(buttons)
        self.finished.connect(self._finish)
        self._reload()

    def _finish(self, _result: int) -> None:
        self._closed = True
        self._ticket = None

    def _read(
        self,
    ) -> tuple[
        list[dict[str, str]], list[dict[str, Any]], dict[str, str], tuple[ProfileVersion, ...]
    ]:
        metadata = self._store.workspace_metadata
        return (
            metadata.list_sites(),
            self._store.list_project_devices(self._project_id),
            metadata.device_sites(self._project_id),
            LegacyProfileHistory(self._store.path).list_versions(self._project_id),
        )

    def _busy(self, busy: bool) -> None:
        self.progress.setVisible(busy)
        for widget in (
            self.create, self.rename, self.assign, self.refresh, self.target, self.save_profile
        ):
            widget.setEnabled(not busy)

    def _submit(self, mutation: Callable[[], object] | None = None) -> None:
        if self._closed or not self._context_valid():
            self.reject()
            return
        ticket = object()
        self._ticket = ticket
        self._busy(True)
        self.status.setText("Загрузка…" if mutation is None else "Сохранение…")

        def work() -> object:
            if mutation is not None:
                mutation()
            return self._read()

        def done(value: Any) -> None:
            if self._closed or self._ticket is not ticket:
                return
            if not self._context_valid():
                self.reject()
                return
            self._busy(False)
            if isinstance(value, JobError):
                self.status.setText(
                    f"Операция не завершена: {value.message} "
                    "Назначения, сохранённые до ошибки, доступны после обновления."
                )
                return
            sites, devices, assignments, versions = value
            self._populate(sites, devices, assignments)
            self.profile_status.setText(
                f"Версий настроек: {len(versions)}. Последняя: {versions[-1].version}.\n"
                f"Fingerprint: {versions[-1].fingerprint}"
                if versions
                else "Версии настроек проверки ещё не сохранены."
            )
            self.status.setText(
                f"Площадок: {len(sites)}. Устройств в проекте: {len(devices)}. "
                "Выберите строки и площадку для назначения."
                if devices
                else "Нет разобранных устройств. Сначала выполните анализ конфигураций."
            )

        self._runner.submit(work, done)

    def _reload(self) -> None:
        self._submit()

    def _save_profile(self) -> None:
        def work() -> object:
            history = LegacyProfileHistory(self._store.path)
            history.initialize()
            return history.record(
                self._project_id, self._store.get_project(self._project_id)["settings"]
            )

        self._submit(work)

    def _populate(
        self,
        sites: list[dict[str, str]],
        devices: list[dict[str, Any]],
        assignments: dict[str, str],
    ) -> None:
        self.sites.clear()
        self.target.clear()
        self.target.addItem("Без площадки", None)
        names = {site["id"]: site["name"] for site in sites}
        for site in sites:
            item = QListWidgetItem(site["name"])
            item.setData(Qt.ItemDataRole.UserRole, site["id"])
            self.sites.addItem(item)
            self.target.addItem(site["name"], site["id"])
        self.devices.setRowCount(len(devices))
        for row, record in enumerate(devices):
            device_id = str(record["report"]["device_id"])
            item = QTableWidgetItem(device_id)
            item.setData(Qt.ItemDataRole.UserRole, device_id)
            self.devices.setItem(row, 0, item)
            self.devices.setItem(
                row, 1, QTableWidgetItem(names.get(assignments.get(device_id, ""), "Без площадки"))
            )
            self.devices.setItem(row, 2, QTableWidgetItem(str(record["run_created_at"])))

    def _create_site(self) -> None:
        name, accepted = QInputDialog.getText(self, "Новая площадка", "Название:")
        if not accepted:
            return
        name = name.strip()
        if not name or len(name) > 200 or "\x00" in name:
            self.status.setText("Укажите название от 1 до 200 символов.")
            return

        def work() -> None:
            metadata = self._store.workspace_metadata
            metadata.initialize()
            metadata.create_site(name)

        self._submit(work)

    def _rename_site(self) -> None:
        item = self.sites.currentItem()
        if item is None:
            self.status.setText("Выберите площадку для переименования.")
            return
        site_id = str(item.data(Qt.ItemDataRole.UserRole))
        name, accepted = QInputDialog.getText(
            self, "Переименовать площадку", "Название:", text=item.text()
        )
        if accepted:
            if not name.strip() or len(name.strip()) > 200 or "\x00" in name:
                self.status.setText("Укажите название от 1 до 200 символов.")
                return
            self._submit(lambda: self._store.workspace_metadata.rename_site(site_id, name))

    def _assign(self) -> None:
        selected = self.devices.selectionModel().selectedRows()
        device_ids = tuple(
            str(self.devices.item(index.row(), 0).data(Qt.ItemDataRole.UserRole))
            for index in selected
        )
        if not device_ids:
            self.status.setText("Выберите одно или несколько устройств в таблице.")
            return
        site_id = self.target.currentData()

        def work() -> None:
            metadata = self._store.workspace_metadata
            metadata.initialize()
            metadata.assign_devices(self._project_id, device_ids, site_id)

        self._submit(work)
