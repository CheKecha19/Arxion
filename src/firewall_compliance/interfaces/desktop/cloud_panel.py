"""Cloud.ru platform settings and independently scheduled read-only VMware scans."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import asdict
from functools import partial
from pathlib import Path
from threading import Event
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.devices.cloud.cloud_ru.public_client import (
    PLATFORM_RESOURCES,
    PUBLIC_DATA,
    PUBLIC_RESOURCES,
    AdvancedClient,
    EvolutionClient,
    PublicCloudClient,
    PublicSelection,
)
from firewall_compliance.devices.cloud.cloud_ru.vmware.client import (
    API_VERSIONS,
    DATA_TYPES,
    RESOURCE_TYPES,
    ScanResult,
    ScanSelection,
    VMwareClient,
    VMwareConfig,
)
from firewall_compliance.domain.cloud_security_groups import CloudSecurityGroupSnapshot
from firewall_compliance.interfaces.desktop.cloud_analysis import analyze_saved_vmware
from firewall_compliance.interfaces.desktop.cloud_public_form import PublicCloudForm
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_batch_report import write_report_file

SCAN_STATES = {
    "completed": "Завершено",
    "partial": "Частично",
    "failed": "Ошибка",
    "cancelled": "Отменено",
    "running": "Выполняется",
    "interrupted": "Прервано",
}
PLATFORMS = ("vmware", "advanced", "evolution")
ALL_RESOURCES = RESOURCE_TYPES | PUBLIC_RESOURCES
ALL_DATA = DATA_TYPES | PUBLIC_DATA


def _label(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    return label


class CloudPanel:
    def __init__(
        self,
        store: ProjectStore,
        parent: QWidget,
        *,
        client_factory: Callable[..., VMwareClient] = VMwareClient,
    ) -> None:
        self.store = store
        self.on_history_changed: Callable[[], None] = lambda: None
        self.on_open_analysis: Callable[[str], None] = lambda _run_id: None
        self.on_open_security_groups: Callable[[CloudSecurityGroupSnapshot], None] = lambda _snapshot: None
        self.client_factory = client_factory
        self.public_factories: dict[str, Callable[..., PublicCloudClient]] = {
            "advanced": AdvancedClient,
            "evolution": EvolutionClient,
        }
        self.project_id: str | None = None
        self.runner = JobRunner()
        self.busy = False
        self.cancel = Event()
        self._active_scan: str | None = None
        self._active_project: str | None = None
        self._deferred_history = False
        self._scan_read: tuple[tuple[str, str, str, str | None], Event] | None = None
        self._loaded_scan: dict[str, Any] | None = None
        self._scan_json: tuple[tuple[str, str, str, str | None], str] | None = None
        self._scan_json_pending: dict[str, Any] | None = None
        self._closed = False
        self.settings_widget = QTabWidget()
        self._build_settings()
        self.scans_widget = QWidget()
        self._build_scans()
        self.timer = QTimer(parent)
        self.timer.timeout.connect(self.runner.poll)
        self.timer.start(80)

    def _build_settings(self) -> None:
        vmware = QWidget()
        layout = QVBoxLayout(vmware)
        layout.addWidget(_label("Cloud.ru VMware · VMware Cloud Director"))
        form = QFormLayout()
        self.site = QLineEdit()
        self.site.setPlaceholderText("Адрес площадки или полная ссылка https://…/tenant/…/")
        self.site.editingFinished.connect(self._import_vmware_url)
        self.tenant = QLineEdit()
        self.tenant.setPlaceholderText("Имя из ссылки /tenant/<имя>/")
        self.token = QLineEdit()
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText(
            "API Token из Cloud Director → User preferences → Access Tokens"
        )
        self.api_version = QComboBox()
        self.api_version.setEditable(True)
        self.api_version.addItems(["Автоматически", *reversed(API_VERSIONS)])
        self.timeout = QSpinBox()
        self.timeout.setRange(5, 120)
        self.timeout.setValue(30)
        self.timeout.setSuffix(" с")
        for title, field in (
            ("Адрес площадки *", self.site),
            ("Tenant *", self.tenant),
            ("API Token *", self.token),
            ("Версия API", self.api_version),
            ("Таймаут запроса", self.timeout),
        ):
            form.addRow(title, field)
        layout.addLayout(form)
        layout.addWidget(
            _label(
                "API Token защищается Windows DPAPI и доступен только в вашем профиле Windows. "
                "Для смены токена введите новое значение; пустое поле сохраняет существующий токен."
            )
        )
        layout.addWidget(
            _label(
                "Нужны права чтения выбранных ВМ, сетей и Edge Gateway, "
                "включая Firewall/NAT/маршруты. "
                "В режиме «Автоматически» совместимая версия выбирается через /api/versions. "
                "Используется пользовательский API Token; сервисные аккаунты "
                "с ротацией refresh_token пока не поддержаны."
            )
        )
        buttons = QHBoxLayout()
        self.save_button = QPushButton("Сохранить подключение")
        self.save_button.clicked.connect(self.save)
        self.test_button = QPushButton("Проверить подключение")
        self.test_button.clicked.connect(self.test_connection)
        self.delete_button = QPushButton("Удалить подключение")
        self.delete_button.clicked.connect(self.delete)
        for button in (self.save_button, self.test_button, self.delete_button):
            buttons.addWidget(button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.connection_status = _label("Выберите или создайте проект.")
        self.connection_status.setTextFormat(Qt.TextFormat.PlainText)
        self.connection_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.connection_status)
        self.connection_details = QPlainTextEdit()
        self.connection_details.setReadOnly(True)
        self.connection_details.setPlaceholderText("Здесь появятся этапы проверки подключения.")
        self.connection_details.setMaximumHeight(120)
        self.connection_details.setAccessibleName("Диагностика подключения VMware")
        layout.addWidget(self.connection_details)
        docs = _label(
            '<a href="https://cloud.ru/docs/vdc/ug/topics/basic-info/basic-info__api-token">'
            "Как создать API Token в Cloud.ru VMware</a>"
        )
        docs.setOpenExternalLinks(True)
        layout.addWidget(docs)
        layout.addStretch()
        self.settings_widget.addTab(vmware, "VMware")
        self.public_forms: dict[str, PublicCloudForm] = {}
        for platform in ("advanced", "evolution"):
            public_form = PublicCloudForm(
                self.store, platform, partial(self._test_public, platform)
            )
            self.public_forms[platform] = public_form
            self.settings_widget.addTab(public_form, platform.capitalize())

    def _build_scans(self) -> None:
        root_layout = QVBoxLayout(self.scans_widget)
        title = _label("Сканирования")
        title.setObjectName("heading")
        root_layout.addWidget(title)
        self.collection_tabs = QTabWidget()
        root_layout.addWidget(self.collection_tabs, 1)
        preparation = QWidget()
        layout = QVBoxLayout(preparation)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(preparation)
        self.collection_tabs.addTab(scroll, "Новый сбор")
        source = QHBoxLayout()
        source.addWidget(_label("Источник"))
        self.source = QComboBox()
        self.source.addItems(["Cloud.ru VMware", "Cloud.ru Advanced", "Cloud.ru Evolution"])
        self.source.currentIndexChanged.connect(self._source_changed)
        source.addWidget(self.source, 1)
        self.configure_button = QPushButton("Настроить подключение")
        source.addWidget(self.configure_button)
        layout.addLayout(source)
        choices = QHBoxLayout()
        resources = QVBoxLayout()
        resources.addWidget(_label("Типы устройств и сетей"))
        self.resource_checks: dict[str, QCheckBox] = {}
        for key, name in ALL_RESOURCES.items():
            check = QCheckBox(name)
            check.setChecked(True)
            check.toggled.connect(self._update_data_choices)
            self.resource_checks[key] = check
            resources.addWidget(check)
        resources.addStretch()
        choices.addLayout(resources, 1)
        data = QVBoxLayout()
        data.addWidget(_label("Что получить"))
        data.addWidget(_label("Инвентарь и параметры выбранных ресурсов — всегда"))
        self.data_checks: dict[str, QCheckBox] = {}
        for key, name in ALL_DATA.items():
            check = QCheckBox(name)
            check.setChecked(True)
            self.data_checks[key] = check
            data.addWidget(check)
        choices.addLayout(data, 2)
        layout.addLayout(choices)
        self.scope_hint = _label(
            "Сбор конфигурации через API. Результат не является заключением "
            "о безопасности или достижимости сети."
        )
        layout.addWidget(self.scope_hint)
        actions = QHBoxLayout()
        self.scan_button = QPushButton("Запустить сканирование")
        self.scan_button.setObjectName("primary")
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button = QPushButton("Отменить сканирование")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.export_button = QPushButton("Экспорт JSON")
        self.export_button.clicked.connect(self.export_scan)
        actions.addWidget(self.scan_button)
        actions.addWidget(self.cancel_button)
        actions.addStretch()
        layout.addLayout(actions)
        self.scan_status = _label("Сначала настройте подключение Cloud.ru VMware.")
        layout.addWidget(self.scan_status)
        self.auto_analyze = QCheckBox(
            "После сбора VMware автоматически проверить правила Edge Firewall"
        )
        self.auto_analyze.setChecked(True)
        layout.addWidget(self.auto_analyze)
        layout.addStretch()
        self.open_result_button = QPushButton("Открыть результат сбора")
        self.open_result_button.clicked.connect(lambda: self.collection_tabs.setCurrentIndex(1))
        layout.addWidget(self.open_result_button)
        result_page = QWidget()
        layout = QVBoxLayout(result_page)
        self.collection_tabs.addTab(result_page, "Результат")
        self.history = QComboBox()
        self.history.setAccessibleName("История сканирований текущего проекта")
        self.history.currentIndexChanged.connect(self._show_scan)
        layout.addWidget(self.history)
        self.analyze_button = QPushButton("Проверить правила сохранённого сбора")
        self.analyze_button.clicked.connect(lambda: self.analyze_saved_scan())
        layout.addWidget(self.analyze_button)
        self.open_analysis_button = QPushButton("Открыть проблемы и результаты проверок")
        self.open_analysis_button.clicked.connect(self._open_analysis)
        layout.addWidget(self.open_analysis_button)
        self.security_groups_button = QPushButton("Сверить группу безопасности с матрицей…")
        self.security_groups_button.clicked.connect(self._open_security_groups)
        layout.addWidget(self.security_groups_button)
        self.analysis_status = _label(
            "Для проверки выберите сохранённый сбор VMware с правилами Firewall."
        )
        layout.addWidget(self.analysis_status)
        self.scan_read_status = _label("")
        self.scan_read_status.hide()
        layout.addWidget(self.scan_read_status)
        layout.addWidget(self.export_button)
        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        self.scan_detail_tabs = QTabWidget()
        resources_view = QSplitter()
        self.records_view = QTreeWidget()
        self.records_view.setHeaderLabels(["Тип", "Название", "Полученные данные"])
        self.records_view.currentItemChanged.connect(self._show_record)
        resources_view.addWidget(self.records_view)
        record_page = QWidget()
        record_layout = QVBoxLayout(record_page)
        record_layout.setContentsMargins(0, 0, 0, 0)
        self._edge_policy_id = ""
        self.copy_edge_policy_button = QPushButton("Скопировать ID политики")
        self.copy_edge_policy_button.setToolTip("Укажите этот ID в требовании или точке контроля матрицы.")
        self.copy_edge_policy_button.hide()
        self.copy_edge_policy_button.clicked.connect(self._copy_edge_policy)
        record_layout.addWidget(self.copy_edge_policy_button, 0, Qt.AlignmentFlag.AlignLeft)
        self.record_detail = QPlainTextEdit()
        self.record_detail.setReadOnly(True)
        record_layout.addWidget(self.record_detail, 1)
        resources_view.addWidget(record_page)
        self.errors_view = QPlainTextEdit()
        self.errors_view.setReadOnly(True)
        self.requests_view = QPlainTextEdit()
        self.requests_view.setReadOnly(True)
        self.scan_detail_tabs.addTab(resources_view, "Ресурсы")
        self.scan_detail_tabs.addTab(self.errors_view, "Ошибки")
        self.scan_detail_tabs.addTab(self.requests_view, "API-запросы")
        self.scan_detail_tabs.addTab(self.result, "JSON")
        self.scan_detail_tabs.currentChanged.connect(self._show_scan_json)
        layout.addWidget(self.scan_detail_tabs, 1)
        self.collection_tabs.currentChanged.connect(self._scan_tab_changed)

    def open_result(self, scan_id: str) -> None:
        """Открыть сохранённый сбор из карточки ресурса или общей истории."""
        self._fill_history(self._read_history(), scan_id)
        self.collection_tabs.setCurrentIndex(1)

    def set_project(self, project_id: str | None, *, refresh_history: bool = True) -> None:
        if project_id != self.project_id:
            self._loaded_scan = None
            self._scan_json = None
            self._scan_json_pending = None
            self._deferred_history = not refresh_history
        elif not refresh_history:
            self._deferred_history = True
        self.project_id = project_id
        self.analysis_status.setText("Выберите сохранённый сбор для проверки правил.")
        for public_form in self.public_forms.values():
            public_form.set_project(project_id)
        config = self.store.get_vmware_integration(project_id) if project_id else None
        self.site.setText(config.get("site", "") if config else "")
        self.tenant.setText(config.get("tenant", "") if config else "")
        version = config.get("api_version", "auto") if config else "auto"
        self.api_version.setCurrentText("Автоматически" if version == "auto" else version)
        self.timeout.setValue(config.get("timeout", 30) if config else 30)
        self.token.clear()
        self.connection_details.clear()
        self.connection_status.setText(
            "Подключение сохранено. API Token скрыт." if config else "Подключение не настроено."
        )
        platform = PLATFORMS[self.source.currentIndex()]
        scan_config = (
            config
            if platform == "vmware"
            else (
                self.store.get_public_cloud_integration(project_id, platform)
                if project_id
                else None
            )
        )
        self.scan_status.setText(
            "Готово к сканированию."
            if scan_config
            else f"Сначала настройте подключение Cloud.ru {platform.capitalize()}."
        )
        if refresh_history:
            self._refresh_history()
        else:
            # Clear the old project's selection without reading or formatting saved scans.
            self._fill_history([])
        self._set_busy(self.busy)

    def _config(self) -> VMwareConfig:
        version = self.api_version.currentText().strip()
        return VMwareConfig(
            self.site.text().strip(),
            self.tenant.text().strip(),
            "auto" if version == "Автоматически" else version,
            self.timeout.value(),
        )

    def _import_vmware_url(self) -> None:
        if "/tenant/" not in self.site.text():
            return
        try:
            config = VMwareConfig(self.site.text().strip(), "")
        except ValueError as error:
            self.connection_status.setText(str(error))
            return
        self.site.setText(config.site)
        self.tenant.setText(config.tenant)

    def _form_token(self, config: VMwareConfig) -> str:
        if not self.project_id:
            raise ValueError("Выберите или создайте проект.")
        token = self.token.text().strip()
        if token:
            return token
        saved = self.store.get_vmware_integration(self.project_id)
        if saved is None:
            raise ValueError("Введите API Token VMware Cloud Director.")
        if config.site != saved["site"] or config.tenant != saved["tenant"]:
            raise ValueError("Для нового адреса площадки или tenant введите API Token заново.")
        return self.store.get_vmware_token(self.project_id)

    def _saved_config(self) -> VMwareConfig:
        if not self.project_id:
            raise ValueError("Выберите или создайте проект.")
        saved = self.store.get_vmware_integration(self.project_id)
        if saved is None:
            raise ValueError("Сначала сохраните подключение в настройках.")
        return VMwareConfig(**saved)

    def save(self) -> None:
        if self.busy:
            return
        try:
            if not self.project_id:
                raise ValueError("Выберите или создайте проект.")
            config = self._config()
            token = self._form_token(config)
            self.store.save_vmware_integration(self.project_id, asdict(config), token)
            self.site.setText(config.site)
            self.tenant.setText(config.tenant)
            self.token.clear()
            self.connection_status.setText(
                "Подключение сохранено. Теперь можно проверить доступ или запустить сканирование."
            )
            self.scan_status.setText("Готово к сканированию.")
        except (ValueError, OSError) as error:
            self.connection_status.setText(
                str(error) if isinstance(error, ValueError) else "Не удалось сохранить подключение."
            )

    def delete(self) -> None:
        if self.project_id and not self.busy:
            self.store.delete_vmware_integration(self.project_id)
            self.set_project(self.project_id)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        configured_project = bool(self.project_id)
        for widget in (
            self.save_button,
            self.test_button,
            self.delete_button,
            self.site,
            self.tenant,
            self.token,
            self.api_version,
            self.timeout,
        ):
            widget.setEnabled(configured_project and not busy)
        self.scan_button.setEnabled(configured_project and not busy)
        self.cancel_button.setEnabled(busy)
        self.source.setEnabled(not busy)
        platform = PLATFORMS[self.source.currentIndex()]
        allowed = RESOURCE_TYPES.keys() if platform == "vmware" else PLATFORM_RESOURCES[platform]
        for key, check in self.resource_checks.items():
            check.setVisible(key in allowed)
            check.setEnabled(not busy and key in allowed)
        for public_form in self.public_forms.values():
            public_form.set_busy(busy)
        self._update_data_choices()
        self.auto_analyze.setEnabled(not busy)
        self._update_analysis_controls()

    def test_connection(self) -> None:
        if self.busy:
            return
        try:
            config = self._config()
            token = self._form_token(config)
            assert self.project_id
            client = self.client_factory(config, token)
            needs_save = bool(self.token.text().strip()) or (
                asdict(config) != self.store.get_vmware_integration(self.project_id)
            )
        except ValueError as error:
            self.connection_status.setText(str(error))
            return
        project_id = self.project_id
        self.cancel = client.cancel
        self._set_busy(True)
        self.connection_details.clear()
        self.connection_status.setText("Проверка адреса, версии API, токена и доступа к tenant…")

        def completed(result: object) -> None:
            self._set_busy(False)
            if self.project_id == project_id:
                if isinstance(result, ScanResult):
                    self.connection_status.setText(
                        f"Подключение успешно. API {client.api_version}. "
                        "Доступ к tenant подтверждён."
                        + (" Сохраните подключение перед сбором данных." if needs_save else "")
                        if result.state == "completed"
                        else result.errors[0]["message"]
                    )
                    self.connection_details.setPlainText(
                        "\n".join(
                            f"{request['method']} {request['path']}"
                            + (
                                f" · API {request['api_version']}"
                                if "api_version" in request
                                else ""
                            )
                            + (" · OK" if request.get("status") == "ok" else " · ошибка")
                            for request in result.requests
                        )
                        + (
                            "\n" + "\n".join(error["message"] for error in result.errors)
                            if result.errors
                            else ""
                        )
                    )
                else:
                    self.connection_status.setText("Не удалось проверить подключение.")

        self.runner.submit(client.check_connection, completed)

    def _update_data_choices(self, *_: Any) -> None:
        if not hasattr(self, "data_checks"):
            return
        allowed = DATA_TYPES.keys() if self.source.currentIndex() == 0 else PUBLIC_DATA.keys()
        for key, check in self.data_checks.items():
            dependency = (
                "vms"
                if key == "vm_networks"
                else "security_groups"
                if key == "security_rules"
                else "edges"
            )
            enabled = self.resource_checks[dependency].isChecked()
            check.setVisible(key in allowed)
            check.setEnabled(enabled and not self.busy and key in allowed)

    def _source_changed(self, *_: Any) -> None:
        self._set_busy(self.busy)
        self.scan_status.setText("Выберите состав сканирования и нажмите «Запустить сканирование».")

    def start_scan(self) -> None:
        if self.busy:
            return
        try:
            resources = tuple(
                key
                for key, check in self.resource_checks.items()
                if check.isChecked() and check.isEnabled()
            )
            data = tuple(
                key
                for key, check in self.data_checks.items()
                if check.isEnabled() and check.isChecked()
            )
            if not self.project_id:
                raise ValueError("Выберите или создайте проект.")
            self.cancel = Event()
            platform = PLATFORMS[self.source.currentIndex()]
            if platform == "vmware":
                config = self._saved_config()
                selection = ScanSelection(resources, data)
                client = self.client_factory(
                    config, self.store.get_vmware_token(self.project_id), cancel=self.cancel
                )
                work = partial(client.scan, selection)
                scan_config = {"platform": platform, **asdict(config)}
                scan_selection = asdict(selection)
            else:
                public_form = self.public_forms[platform]
                public_config = public_form.saved_config()
                public_selection = PublicSelection(resources, data)
                public_client = self.public_factories[platform](
                    public_config, public_form.credentials(), cancel=self.cancel
                )
                work = partial(public_client.scan, public_selection)
                scan_config = {"platform": platform, **asdict(public_config)}
                scan_selection = asdict(public_selection)
            site_ids = self.store.workspace_metadata.source_sites(self.project_id).get(f"cloud_ru_{platform}", ())
            if site_ids:
                scan_selection["workspace_site_ids"] = list(site_ids)
            scan_id = self.store.create_cloud_scan(self.project_id, scan_selection, scan_config)
        except ValueError as error:
            self.scan_status.setText(str(error))
            return
        self._active_scan = scan_id
        self._active_project = self.project_id
        scan_project_id = self.project_id
        scan_cancel = self.cancel
        auto_analyze = self.auto_analyze.isChecked()
        self._set_busy(True)
        self.scan_status.setText(
            "Сканирование выполняется в фоне… Отмена остановит сбор после текущего запроса."
        )
        self._refresh_history(scan_id)

        def completed(result: object) -> None:
            if isinstance(result, ScanResult):
                payload = asdict(result)
            else:
                payload = {
                    "state": "failed",
                    "records": [],
                    "requests": [],
                    "errors": [
                        {
                            "resource": "Сканирование",
                            "message": result.message
                            if isinstance(result, JobError)
                            else "Не удалось получить результат.",
                        }
                    ],
                }
            self.store.finish_cloud_scan(scan_id, payload)
            self._active_scan = None
            self._set_busy(False)
            if self.project_id == self._active_project:
                self.scan_status.setText(
                    f"{SCAN_STATES[payload['state']]} · ресурсов: {len(payload['records'])} "
                    f"· ошибок: {len(payload['errors'])}"
                )
                self._refresh_history(scan_id)
            self._active_project = None
            if (
                platform == "vmware"
                and auto_analyze
                and not scan_cancel.is_set()
                and payload.get("state") in {"completed", "partial"}
                and any(
                    "firewall" in record.get("data", {}) for record in payload.get("records", [])
                )
            ):
                self.analyze_saved_scan(scan_id, project_id=scan_project_id)

        self.runner.submit(work, completed)

    @staticmethod
    def _scan_key(scan: dict[str, Any]) -> tuple[str, str, str, str | None]:
        return scan["project_id"], scan["id"], scan["state"], scan.get("finished_at")

    def _selected_scan(self) -> dict[str, Any] | None:
        header = self.history.currentData()
        if not header or not self.project_id:
            return None
        if not header.get("workspace_projection"):
            return header
        scan = self._loaded_scan
        if (
            scan is not None and scan["project_id"] == self.project_id
            and self._scan_key(scan) == self._scan_key(header)
        ):
            return scan
        return None

    def _update_analysis_controls(self) -> None:
        scan = self._selected_scan()
        eligible = bool(
            scan
            and scan["config"].get("platform", "vmware") == "vmware"
            and any(
                isinstance(record, dict) and record.get("type") == "edges"
                and "firewall" in (record.get("data") or {})
                for record in scan.get("result", {}).get("records", [])
            )
        )
        self.analyze_button.setEnabled(eligible and not self.busy)
        self.security_groups_button.setEnabled(bool(
            scan and not self.busy
            and scan["config"].get("platform") in {"advanced", "evolution"}
            and any(
                isinstance(record, dict) and record.get("type") == "security_groups"
                for record in scan.get("result", {}).get("records", [])
            )
        ))
        runs = (
            self.store.cloud_analysis_runs(scan["id"], self.project_id)
            if scan and self.project_id
            else []
        )
        self.open_analysis_button.setEnabled(bool(runs) and not self.busy)

    def _open_analysis(self) -> None:
        scan = self._selected_scan()
        runs = (
            self.store.cloud_analysis_runs(scan["id"], self.project_id)
            if scan and self.project_id
            else []
        )
        if runs:
            self.on_open_analysis(runs[0])

    def _open_security_groups(self) -> None:
        from firewall_compliance.application.cloud_security_groups import security_group_snapshot

        scan = self._selected_scan()
        project_id = self.project_id
        if not scan or not project_id or self.busy:
            return
        self.cancel = Event()
        cancelled = self.cancel
        self._set_busy(True)
        self.analysis_status.setText("Читаем группы и интерфейсы сохранённого сбора…")

        def completed(value: object) -> None:
            if self._closed:
                return
            self._set_busy(False)
            if self.project_id != project_id or (self.history.currentData() or {}).get("id") != scan["id"]:
                return
            if cancelled.is_set():
                self.analysis_status.setText("Чтение снимка отменено.")
            elif isinstance(value, JobError):
                self.analysis_status.setText(value.message)
            elif isinstance(value, CloudSecurityGroupSnapshot):
                self.analysis_status.setText(
                    f"Групп: {len(value.groups)} · интерфейсов: {len(value.interfaces)}. "
                    "Выберите группу и подтверждённый интерфейс для сверки."
                )
                self.on_open_security_groups(value)

        self.runner.submit(partial(security_group_snapshot, scan), completed)

    def analyze_saved_scan(
        self, scan_id: str | None = None, *, project_id: str | None = None
    ) -> None:
        project_id = project_id or self.project_id
        if self.busy or not project_id:
            return
        selected = self._selected_scan() if project_id == self.project_id else None
        if not scan_id and selected is not None:
            scan_id = selected["id"]
        if not scan_id:
            self.analysis_status.setText("Выберите сохранённый сбор текущего проекта.")
            return
        scan = selected if selected is not None and selected["id"] == scan_id else None
        settings = self.store.get_project(project_id)["settings"]
        if settings.get("enabled_check_ids") is not None and not any(
            key.startswith("FW-") for key in settings["enabled_check_ids"]
        ):
            self.analysis_status.setText("Включите хотя бы одну проверку FW в Настройки → Проверки.")
            return
        self.cancel = Event()
        cancel = self.cancel
        self._set_busy(True)
        if self.project_id == project_id:
            self.analysis_status.setText(
                "Проверка сохранённых правил… Запросы к облаку не выполняются."
            )

        def work() -> list[dict[str, Any]]:
            snapshot = scan if scan is not None else self.store.get_cloud_scan(project_id, scan_id)
            if snapshot is None:
                raise ValueError("Сохранённый сбор текущего проекта не найден.")
            return analyze_saved_vmware(snapshot, settings, cancel)

        def selected_now() -> bool:
            return self.project_id == project_id and (self.history.currentData() or {}).get("id") == scan_id

        def completed(result: object) -> None:
            self._set_busy(False)
            if cancel.is_set():
                message = "Проверка отменена; новый результат не сохранён."
            elif isinstance(result, list) and result:
                try:
                    self.store.save_cloud_analysis(scan_id, result, settings)
                except (ValueError, OSError, sqlite3.Error):
                    if selected_now():
                        self.analysis_status.setText(
                            "Не удалось сохранить результат проверки. Исходный сбор доступен "
                            "для повторной проверки."
                        )
                        self._update_analysis_controls()
                    return
                findings = sum(
                    len(check["findings"])
                    for item in result
                    for check in (item.get("report") or {}).get("checks", [])
                )
                partial = sum(item["status"] == "partial" for item in result)
                failed = sum(item["status"] == "error" for item in result)
                message = (
                    f"Проверено Edge Gateway: {len(result) - failed} · "
                    f"частичных: {partial} · ошибок: {failed} · находок: {findings}."
                )
                self.on_history_changed()
            else:
                message = (
                    result.message
                    if isinstance(result, JobError)
                    else "Не удалось проверить правила."
                )
            if selected_now():
                self.analysis_status.setText(message)
                self._update_analysis_controls()

        self.runner.submit(work, completed)

    def _test_public(self, platform: str) -> None:
        if self.busy:
            return
        public_form = self.public_forms[platform]
        try:
            config = public_form.saved_config()
            client = self.public_factories[platform](config, public_form.credentials())
        except ValueError as error:
            public_form.status.setText(str(error))
            return
        project_id = self.project_id
        self.cancel = client.cancel
        self._set_busy(True)
        public_form.status.setText("Проверка доступа к облачному проекту…")

        def completed(result: object) -> None:
            self._set_busy(False)
            if self.project_id == project_id:
                public_form.status.setText(
                    "Подключение успешно. Доступ к проекту подтверждён."
                    if isinstance(result, ScanResult) and result.state == "completed"
                    else result.errors[0]["message"]
                    if isinstance(result, ScanResult)
                    else "Не удалось проверить подключение."
                )

        self.runner.submit(client.check_connection, completed)

    def cancel_scan(self) -> None:
        self.cancel.set()
        self.scan_status.setText("Отмена запрошена. Ожидается завершение текущего API-запроса.")

    def _refresh_history(self, selected_id: str | None = None) -> None:
        self._fill_history(self._read_history(), selected_id)
        self.on_history_changed()

    def refresh_history(self, scans: list[dict[str, Any]] | None = None) -> None:
        """Populate the visible history from a shared snapshot without change notifications."""
        if scans is None:
            scans = self._read_history()
        elif any(scan.get("workspace_projection") for scan in scans):
            self._deferred_history = True
        selected = self.history.currentData()
        self._fill_history(scans, selected["id"] if selected else None)

    def _read_history(self) -> list[dict[str, Any]]:
        if not self.project_id:
            return []
        if self._deferred_history:
            return [
                {**scan, "workspace_projection": True}
                for scan in self.store.list_cloud_scan_headers(self.project_id)
            ]
        return self.store.list_cloud_scans(self.project_id)

    def _fill_history(
        self, scans: list[dict[str, Any]], selected_id: str | None = None
    ) -> None:
        self.history.blockSignals(True)
        self.history.clear()
        if self.project_id:
            for scan in scans:
                if scan.get("workspace_projection") and "result" in scan:
                    scan = {key: value for key, value in scan.items() if key != "result"}
                platform_name = scan["config"].get("platform", "vmware").capitalize()
                self.history.addItem(
                    f"{scan['created_at']} · {platform_name} · {SCAN_STATES[scan['state']]}",
                    scan,
                )
        if selected_id:
            index = next(
                (
                    i
                    for i in range(self.history.count())
                    if self.history.itemData(i)["id"] == selected_id
                ),
                -1,
            )
            self.history.setCurrentIndex(index)
        self.history.blockSignals(False)
        self._show_scan()

    def _scan_tab_changed(self, _index: int) -> None:
        if (self.history.currentData() or {}).get("workspace_projection"):
            self._show_scan()

    def _show_scan(self, *_: Any) -> None:
        header, project_id = self.history.currentData(), self.project_id
        key = self._scan_key(header) if header and header.get("workspace_projection") else None
        if self._scan_read is not None:
            pending_key, cancel = self._scan_read
            if pending_key == key and self.collection_tabs.currentIndex() == 1:
                return
            cancel.set()
            self._scan_read = None
        scan = self._selected_scan()
        if scan is not None:
            self._render_scan(scan)
            return
        if not header or not project_id or key is None or key[0] != project_id:
            self._render_scan(None)
            return
        if header["state"] == "running":
            self._render_scan(None, message="Сбор ещё выполняется.")
            return
        if self.collection_tabs.currentIndex() != 1:
            self._render_scan(None, message="Откройте вкладку «Результат», чтобы прочитать сбор.")
            return
        self._render_scan(None, message="Читаем сохранённый сбор…")
        ticket = Event()
        request = key, ticket
        self._scan_read = request
        scan_id = header["id"]

        def work() -> dict[str, Any] | None:
            return None if ticket.is_set() else self.store.get_cloud_scan(project_id, scan_id)

        def completed(value: object) -> None:
            if self._closed or self._scan_read is not request or self.project_id != project_id:
                return
            self._scan_read = None
            if (self.history.currentData() or {}).get("id") != scan_id or self.collection_tabs.currentIndex() != 1:
                return
            if isinstance(value, dict):
                self._loaded_scan = value
                if loaded := self._selected_scan():
                    self._render_scan(loaded)
                    return
            self._render_scan(None, message="Не удалось прочитать сохранённый сбор.")

        self.runner.submit(work, completed)

    def _render_scan(self, scan: dict[str, Any] | None, *, message: str | None = None) -> None:
        self._update_analysis_controls()
        self.export_button.setEnabled(bool(scan) and scan["state"] != "running")
        self.scan_read_status.setText(message or "")
        self.scan_read_status.setVisible(bool(message))
        self.records_view.clear()
        self._show_record(None)
        if scan is None:
            self.result.setPlainText(message or "Сканирования ещё не запускались.")
            self.errors_view.clear()
            self.requests_view.clear()
            return
        if (self.history.currentData() or {}).get("workspace_projection"):
            self.result.clear()
            self._show_scan_json()
        else:
            self.result.setPlainText(json.dumps(scan, ensure_ascii=False, indent=2))
        payload = scan.get("result", {})
        projected = bool((self.history.currentData() or {}).get("workspace_projection"))
        for record_index, record in enumerate(payload.get("records", [])):
            if not isinstance(record, dict):
                continue
            collected = [ALL_DATA.get(key, key) for key in (record.get("data") or {})]
            resource_type = str(record.get("type") or "Неизвестный тип")
            item = QTreeWidgetItem(
                self.records_view,
                [
                    ALL_RESOURCES.get(resource_type, resource_type),
                    str(record.get("name") or ""),
                    ", ".join(["Инвентарь", *collected]),
                ],
            )
            item.setData(0, Qt.ItemDataRole.UserRole, record_index if projected else record)
        if self.records_view.topLevelItemCount():
            first_item = self.records_view.topLevelItem(0)
            assert first_item is not None
            self.records_view.setCurrentItem(first_item)
        self.errors_view.setPlainText(
            "\n".join(
                f"{error['resource']}: {error['message']}" for error in payload.get("errors", [])
            )
            or "Ошибок сбора не зарегистрировано."
        )
        if payload.get("integrity_warnings"):
            self.errors_view.appendPlainText(
                "\nПредупреждения о составе данных:\n"
                + "\n".join(warning["message"] for warning in payload["integrity_warnings"])
            )
        self.requests_view.setPlainText(
            "\n".join(
                f"{request['method']} {request['path']}" for request in payload.get("requests", [])
            )
            or "Запросов нет."
        )

    def _show_scan_json(self, *_: Any) -> None:
        header = self.history.currentData()
        if (
            not header or not header.get("workspace_projection")
            or self.scan_detail_tabs.currentWidget() is not self.result
        ):
            return
        scan = self._selected_scan()
        if scan is None:
            return
        key = self._scan_key(scan)
        if self._scan_json is not None and self._scan_json[0] == key:
            self.result.setPlainText(self._scan_json[1])
            return
        self.result.setPlainText("Подготавливаем JSON снимка…")
        if self._scan_json_pending is scan:
            return
        self._scan_json_pending = scan

        def completed(value: object) -> None:
            if self._scan_json_pending is scan:
                self._scan_json_pending = None
            if self._closed or self._loaded_scan is not scan:
                return
            if isinstance(value, str):
                self._scan_json = key, value
            if self._selected_scan() is scan and self.scan_detail_tabs.currentWidget() is self.result:
                self.result.setPlainText(value if isinstance(value, str) else "Не удалось подготовить JSON.")

        self.runner.submit(lambda: json.dumps(scan, ensure_ascii=False, indent=2), completed)

    def _show_record(self, item: QTreeWidgetItem | None, *_: Any) -> None:
        record = item.data(0, Qt.ItemDataRole.UserRole) if item else None
        if isinstance(record, int):
            scan = self._selected_scan()
            records = scan.get("result", {}).get("records", ()) if scan else ()
            record = records[record] if 0 <= record < len(records) else None
        header = self.history.currentData()
        policy_id = record.get("id") if (
            isinstance(header, dict) and header.get("config", {}).get("platform", "vmware") == "vmware"
            and isinstance(record, dict) and record.get("type") == "edges"
        ) else None
        self._edge_policy_id = policy_id if isinstance(policy_id, str) and policy_id.strip() else ""
        self.copy_edge_policy_button.setVisible(bool(self._edge_policy_id))
        self.record_detail.setPlainText(
            json.dumps(record, ensure_ascii=False, indent=2) if record else ""
        )

    def _copy_edge_policy(self) -> None:
        if self._edge_policy_id:
            QApplication.clipboard().setText(self._edge_policy_id)

    def export_scan(self) -> None:
        scan = self._selected_scan()
        if scan is None or scan["state"] == "running":
            return
        projected = bool((self.history.currentData() or {}).get("workspace_projection"))
        filename, _ = QFileDialog.getSaveFileName(
            self.scans_widget,
            "Экспорт сканирования",
            f"cloud-ru-{scan['config'].get('platform', 'vmware')}-scan.json",
            "JSON (*.json)",
        )
        if not filename:
            return

        def work() -> None:
            write_report_file(Path(filename), json.dumps(scan, ensure_ascii=False, indent=2))

        if not projected:
            try:
                work()
            except OSError:
                self.scan_status.setText("Не удалось сохранить JSON. Проверьте доступ к файлу.")
            return

        self.analysis_status.setText("Сохраняем JSON снимка…")

        def completed(value: object) -> None:
            if self._closed or self._selected_scan() is not scan:
                return
            message = (
                "Не удалось сохранить JSON. Проверьте доступ к файлу."
                if isinstance(value, JobError) else "JSON снимка сохранён."
            )
            self.analysis_status.setText(message)

        self.runner.submit(work, completed)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.timer.stop()
        self.cancel.set()
        if self._scan_read is not None:
            self._scan_read[1].set()
        self.runner.shutdown()
        if self._active_scan:
            self.store.finish_cloud_scan(
                self._active_scan,
                {
                    "state": "interrupted",
                    "records": [],
                    "errors": [
                        {
                            "resource": "Сканирование",
                            "message": "Приложение закрыто до окончания сбора.",
                        }
                    ],
                    "requests": [],
                },
            )
