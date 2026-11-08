"""Project-scoped forms for Advanced AK/SK and Evolution Key ID/Secret."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.devices.cloud.cloud_ru.public_client import (
    AdvancedConfig,
    CloudCredentials,
    EvolutionConfig,
)
from firewall_compliance.interfaces.desktop.project_store import ProjectStore


class PublicCloudForm(QWidget):
    def __init__(self, store: ProjectStore, platform: str, test: Callable[[], None]) -> None:
        super().__init__()
        self.store = store
        self.platform = platform
        self.project_id: str | None = None
        self.busy = False
        layout = QVBoxLayout(self)
        heading = QLabel(f"Cloud.ru {platform.capitalize()}")
        layout.addWidget(heading)
        form = QFormLayout()
        self.project = QLineEdit()
        self.project.setPlaceholderText("Project ID облачного проекта")
        self.access_key = QLineEdit()
        self.access_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret_key = QLineEdit()
        self.secret_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.timeout = QSpinBox()
        self.timeout.setRange(5, 120)
        self.timeout.setValue(30)
        self.timeout.setSuffix(" с")
        self.region = QLineEdit("ru-moscow-1")
        self.ecs_endpoint = QLineEdit()
        self.vpc_endpoint = QLineEdit()
        self.ecs_endpoint.setPlaceholderText("Пусто: стандартный ECS API выбранного региона")
        self.vpc_endpoint.setPlaceholderText("Пусто: стандартный VPC API выбранного региона")
        self.fields: dict[str, QWidget] = {
            "project_id": self.project,
            "access_key": self.access_key,
            "secret_key": self.secret_key,
            "timeout": self.timeout,
        }
        form.addRow("Project ID *", self.project)
        form.addRow("Access Key (AK) *" if platform == "advanced" else "Key ID *", self.access_key)
        form.addRow(
            "Secret Key (SK) *" if platform == "advanced" else "Key Secret *", self.secret_key
        )
        if platform == "advanced":
            form.addRow("Регион *", self.region)
            form.addRow("Адрес ECS API", self.ecs_endpoint)
            form.addRow("Адрес VPC API", self.vpc_endpoint)
            self.fields.update(
                region=self.region, ecs_endpoint=self.ecs_endpoint, vpc_endpoint=self.vpc_endpoint
            )
        form.addRow("Таймаут запроса", self.timeout)
        layout.addLayout(form)
        help_text = QLabel(
            "Нужны права чтения ECS и VPC выбранного проекта. Постоянные AK/SK можно "
            "создать в Advanced → My Credentials → Access Keys. Project ID берётся "
            "в My Credentials → API Credentials. При использовании временных AK/SK "
            "нужен Security Token; временные ключи пока не поддержаны."
            if platform == "advanced"
            else "Создайте ключ доступа сервисного аккаунта или персональный ключ Evolution. "
            "Нужны Key ID, Key Secret и UUID проекта, а также права чтения выбранных "
            "ресурсов Compute. Адреса IAM и Compute API задаются автоматически."
        )
        help_text.setWordWrap(True)
        layout.addWidget(help_text)
        storage = QLabel(
            "Обе части ключа защищены Windows DPAPI. "
            "Пустые поля сохраняют прежний ключ для того же подключения."
        )
        storage.setWordWrap(True)
        layout.addWidget(storage)
        self.save_button = QPushButton("Сохранить подключение")
        self.save_button.clicked.connect(self.save)
        self.test_button = QPushButton("Проверить подключение")
        self.test_button.clicked.connect(test)
        self.delete_button = QPushButton("Удалить подключение")
        self.delete_button.clicked.connect(self.delete)
        buttons = QHBoxLayout()
        for button in (self.save_button, self.test_button, self.delete_button):
            buttons.addWidget(button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.status = QLabel("Выберите или создайте проект.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        layout.addStretch()

    def config(self) -> EvolutionConfig | AdvancedConfig:
        if self.platform == "evolution":
            return EvolutionConfig(self.project.text().strip(), self.timeout.value())
        return AdvancedConfig(
            self.project.text().strip(),
            self.region.text().strip(),
            self.ecs_endpoint.text().strip(),
            self.vpc_endpoint.text().strip(),
            self.timeout.value(),
        )

    def saved_config(self) -> EvolutionConfig | AdvancedConfig:
        if not self.project_id:
            raise ValueError("Выберите или создайте проект.")
        saved = self.store.get_public_cloud_integration(self.project_id, self.platform)
        if saved is None:
            raise ValueError("Сначала сохраните подключение выбранной платформы в настройках.")
        return EvolutionConfig(**saved) if self.platform == "evolution" else AdvancedConfig(**saved)

    def credentials(self) -> CloudCredentials:
        if not self.project_id:
            raise ValueError("Выберите или создайте проект.")
        return CloudCredentials(
            **self.store.get_public_cloud_credentials(self.project_id, self.platform)
        )

    def set_project(self, project_id: str | None) -> None:
        self.project_id = project_id
        saved = (
            self.store.get_public_cloud_integration(project_id, self.platform)
            if project_id
            else None
        )
        config: dict[str, Any] = saved or {}
        self.project.setText(config.get("project_id", ""))
        self.region.setText(config.get("region", "ru-moscow-1"))
        self.ecs_endpoint.setText(config.get("ecs_endpoint", ""))
        self.vpc_endpoint.setText(config.get("vpc_endpoint", ""))
        self.timeout.setValue(config.get("timeout", 30))
        self.access_key.clear()
        self.secret_key.clear()
        self.status.setText(
            "Подключение сохранено. Ключи скрыты." if saved else "Подключение не настроено."
        )
        self.set_busy(self.busy)

    def set_busy(self, busy: bool) -> None:
        self.busy = busy
        for widget in (
            *self.fields.values(),
            self.save_button,
            self.test_button,
            self.delete_button,
        ):
            widget.setEnabled(bool(self.project_id) and not busy)

    def save(self) -> None:
        if self.busy:
            return
        try:
            if not self.project_id:
                raise ValueError("Выберите или создайте проект.")
            config = asdict(self.config())
            saved = self.store.get_public_cloud_integration(self.project_id, self.platform)
            if not self.access_key.text().strip() and not self.secret_key.text().strip():
                if not saved:
                    raise ValueError("Заполните обе части ключа доступа.")
                if {k: v for k, v in saved.items() if k != "timeout"} != {
                    k: v for k, v in config.items() if k != "timeout"
                }:
                    raise ValueError(
                        "Для нового проекта или адреса API введите обе части ключа заново."
                    )
                credentials = self.credentials()
            else:
                credentials = CloudCredentials(
                    self.access_key.text().strip(), self.secret_key.text().strip()
                )
            self.store.save_public_cloud_integration(
                self.project_id, self.platform, config, asdict(credentials)
            )
            self.access_key.clear()
            self.secret_key.clear()
            self.status.setText(
                "Подключение сохранено. Проверьте доступ или запустите сканирование."
            )
        except (ValueError, OSError) as error:
            self.status.setText(
                str(error) if isinstance(error, ValueError) else "Не удалось сохранить подключение."
            )

    def delete(self) -> None:
        if self.project_id and not self.busy:
            self.store.delete_public_cloud_integration(self.project_id, self.platform)
            self.set_project(self.project_id)
