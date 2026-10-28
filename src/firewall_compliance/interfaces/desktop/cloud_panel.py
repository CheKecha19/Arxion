"""Cloud.ru platform settings and independently scheduled read-only VMware scans."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import asdict
from functools import partial
from threading import Event
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
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

from firewall_compliance.infrastructure.cloud_public import (
    PLATFORM_RESOURCES,
    PUBLIC_DATA,
    PUBLIC_RESOURCES,
    AdvancedClient,
    EvolutionClient,
    PublicCloudClient,
    PublicSelection,
)
from firewall_compliance.infrastructure.cloud_vmware import (
    API_VERSIONS,
    DATA_TYPES,
    RESOURCE_TYPES,
    ScanResult,
    ScanSelection,
    VMwareClient,
    VMwareConfig,
)
from firewall_compliance.interfaces.desktop.cloud_analysis import analyze_saved_vmware
from firewall_compliance.interfaces.desktop.cloud_public_form import PublicCloudForm
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.project_store import ProjectStore

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
        layout.addWidget(_label("Данные подключения сохраняются отдельно для каждого проекта."))
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
        buttons = QVBoxLayout()
        self.save_button = QPushButton("Сохранить подключение")
        self.save_button.clicked.connect(self.save)
        self.test_button = QPushButton("Проверить подключение")
        self.test_button.clicked.connect(self.test_connection)
        self.delete_button = QPushButton("Удалить подключение")
        self.delete_button.clicked.connect(self.delete)
        for button in (self.save_button, self.test_button, self.delete_button):
            buttons.addWidget(button)
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
        root_layout.addWidget(
            _label(
                "Получение данных из подключённых платформ. История сохраняется в текущем проекте."
            )
        )
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
        self.analyze_button.clicked.connect(self.analyze_saved_scan)
        layout.addWidget(self.analyze_button)
        self.open_analysis_button = QPushButton("Открыть проблемы и результаты проверок")
        self.open_analysis_button.clicked.connect(self._open_analysis)
        layout.addWidget(self.open_analysis_button)
        self.analysis_status = _label(
            "Для проверки выберите сохранённый сбор VMware с правилами Firewall."
        )
        layout.addWidget(self.analysis_status)
        layout.addWidget(self.export_button)
        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        tabs = QTabWidget()
        resources_view = QSplitter()
        self.records_view = QTreeWidget()
        self.records_view.setHeaderLabels(["Тип", "Название", "Полученные данные"])
        self.records_view.currentItemChanged.connect(self._show_record)
        resources_view.addWidget(self.records_view)
        self.record_detail = QPlainTextEdit()
        self.record_detail.setReadOnly(True)
        resources_view.addWidget(self.record_detail)
        self.errors_view = QPlainTextEdit()
        self.errors_view.setReadOnly(True)
        self.requests_view = QPlainTextEdit()
        self.requests_view.setReadOnly(True)
        tabs.addTab(resources_view, "Ресурсы")
        tabs.addTab(self.errors_view, "Ошибки")
        tabs.addTab(self.requests_view, "API-запросы")
        tabs.addTab(self.result, "JSON")
        layout.addWidget(tabs, 1)

    def open_result(self, scan_id: str) -> None:
        """Открыть сохранённый сбор из карточки ресурса или общей истории."""
        self._refresh_history(scan_id)
        self.collection_tabs.setCurrentIndex(1)

    def set_project(self, project_id: str | None) -> None:
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
        self._refresh_history()
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

    def _update_analysis_controls(self) -> None:
        scan = self.history.currentData()
        eligible = bool(
            scan
            and scan["config"].get("platform", "vmware") == "vmware"
            and any(
                record.get("type") == "edges" and "firewall" in record.get("data", {})
                for record in scan.get("result", {}).get("records", [])
            )
        )
        self.analyze_button.setEnabled(eligible and not self.busy)
        runs = (
            self.store.cloud_analysis_runs(scan["id"], self.project_id)
            if scan and self.project_id
            else []
        )
        self.open_analysis_button.setEnabled(bool(runs) and not self.busy)

    def _open_analysis(self) -> None:
        scan = self.history.currentData()
        runs = (
            self.store.cloud_analysis_runs(scan["id"], self.project_id)
            if scan and self.project_id
            else []
        )
        if runs:
            self.on_open_analysis(runs[0])

    def analyze_saved_scan(
        self, scan_id: str | None = None, *, project_id: str | None = None
    ) -> None:
        project_id = project_id or self.project_id
        if self.busy or not project_id:
            return
        scan = (
            next(
                (s for s in self.store.list_cloud_scans(project_id) if s["id"] == scan_id),
                None,
            )
            if scan_id
            else self.history.currentData()
        )
        if not scan:
            self.analysis_status.setText("Выберите сохранённый сбор текущего проекта.")
            return
        settings = self.store.get_project(project_id)["settings"]
        if settings.get("enabled_check_ids") is not None and not any(
            key.startswith("FW-") for key in settings["enabled_check_ids"]
        ):
            self.analysis_status.setText("Включите хотя бы одну проверку FW в Настройки → Правила.")
            return
        self.cancel = Event()
        cancel = self.cancel
        self._set_busy(True)
        self.analysis_status.setText(
            "Проверка сохранённых правил… Запросы к облаку не выполняются."
        )

        def completed(result: object) -> None:
            self._set_busy(False)
            if cancel.is_set():
                message = "Проверка отменена; новый результат не сохранён."
            elif isinstance(result, list) and result:
                try:
                    self.store.save_cloud_analysis(scan["id"], result, settings)
                except (ValueError, OSError, sqlite3.Error):
                    if self.project_id == project_id:
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
            if self.project_id == project_id:
                self.analysis_status.setText(message)
                self._update_analysis_controls()

        self.runner.submit(partial(analyze_saved_vmware, scan, settings, cancel), completed)

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
        self.history.blockSignals(True)
        self.history.clear()
        if self.project_id:
            for scan in self.store.list_cloud_scans(self.project_id):
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
            if index >= 0:
                self.history.setCurrentIndex(index)
        self.history.blockSignals(False)
        self._show_scan()
        self.on_history_changed()

    def _show_scan(self, *_: Any) -> None:
        scan = self.history.currentData()
        self._update_analysis_controls()
        self.export_button.setEnabled(bool(scan) and scan["state"] != "running")
        self.result.setPlainText(
            json.dumps(scan, ensure_ascii=False, indent=2)
            if scan
            else "Сканирования ещё не запускались."
        )
        self.records_view.clear()
        self.record_detail.clear()
        payload = scan.get("result", {}) if scan else {}
        for record in payload.get("records", []):
            collected = [ALL_DATA.get(key, key) for key in record.get("data", {})]
            item = QTreeWidgetItem(
                self.records_view,
                [
                    ALL_RESOURCES.get(record["type"], record["type"]),
                    record.get("name", ""),
                    ", ".join(["Инвентарь", *collected]),
                ],
            )
            item.setData(0, Qt.ItemDataRole.UserRole, record)
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
        self.requests_view.setPlainText(
            "\n".join(
                f"{request['method']} {request['path']}" for request in payload.get("requests", [])
            )
            or "Запросов нет."
        )

    def _show_record(self, item: QTreeWidgetItem | None, *_: Any) -> None:
        record = item.data(0, Qt.ItemDataRole.UserRole) if item else None
        self.record_detail.setPlainText(
            json.dumps(record, ensure_ascii=False, indent=2) if record else ""
        )

    def export_scan(self) -> None:
        scan = self.history.currentData()
        if scan is None or scan["state"] == "running":
            return
        filename, _ = QFileDialog.getSaveFileName(
            self.scans_widget,
            "Экспорт сканирования",
            f"cloud-ru-{scan['config'].get('platform', 'vmware')}-scan.json",
            "JSON (*.json)",
        )
        if filename:
            from pathlib import Path

            try:
                Path(filename).write_text(
                    json.dumps(scan, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            except OSError:
                self.scan_status.setText("Не удалось сохранить JSON. Проверьте доступ к файлу.")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.timer.stop()
        self.cancel.set()
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
