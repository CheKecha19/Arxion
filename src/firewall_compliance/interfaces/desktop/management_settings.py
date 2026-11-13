"""Editable organizational management policy; completeness is per import only."""

import json
from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QCheckBox, QComboBox, QLabel, QLineEdit, QSpinBox, QVBoxLayout, QWidget

from firewall_compliance.domain.management import ManagementProfile


class ManagementSettings(QWidget):
    changed = Signal()

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.fields: dict[str, QLineEdit] = {}
        for key, title in {
            "approved_admin_networks": "Разрешённые сети администраторов (CIDR)",
            "approved_snmp_networks": "Разрешённые сети SNMP (CIDR)",
            "approved_syslog_servers": "Утверждённые серверы syslog (IP / DNS)",
            "approved_ntp_servers": "Утверждённые серверы NTP (IP / DNS)",
        }.items():
            layout.addWidget(QLabel(title))
            field = QLineEdit()
            field.setAccessibleName(title)
            field.setPlaceholderText("Значения через запятую")
            field.setToolTip("Пусто — не задано; [] — запретить все значения.")
            self.fields[key] = field
            layout.addWidget(field)
            field.editingFinished.connect(self.changed.emit)
        self.options: dict[str, QCheckBox] = {}
        for key, title, default in (
            ("allow_snmp_write", "Разрешить SNMP write-доступ", False),
            ("require_syslog", "Требовать внешний syslog", True),
            ("require_ntp", "Требовать NTP", True),
            ("require_banner", "Требовать непустой баннер входа", True),
        ):
            checkbox = QCheckBox(title)
            checkbox.setChecked(default)
            self.options[key] = checkbox
            layout.addWidget(checkbox)
            checkbox.toggled.connect(lambda _checked: self.changed.emit())
        layout.addWidget(QLabel("Максимальный тайм-аут сессии, секунд"))
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 86400)
        self.timeout.setValue(900)
        self.timeout.valueChanged.connect(lambda _value: self.changed.emit())
        layout.addWidget(self.timeout)
        self.complete = QCheckBox(
            "Следующий импорт: подтверждаю полноту всех выбранных конфигураций"
        )
        layout.addWidget(self.complete)
        layout.addWidget(QLabel("Следующий импорт Controller: вид конфигурации"))
        self.configuration_view = QComboBox()
        for title, value in (
            ("Не установлен", "unknown"), ("Локальная", "local"),
            ("Результирующая effective", "effective"),
            ("Effective с наследованием", "effective_detail"),
            ("Не применённые изменения pending", "pending"),
        ):
            self.configuration_view.addItem(title, value)
        layout.addWidget(self.configuration_view)
        self.configuration_node_path = QLineEdit()
        self.configuration_node_path.setPlaceholderText("Узел иерархии, если известен, например /md/site/device")
        layout.addWidget(self.configuration_node_path)
        self.error = QLabel()
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        self.profile_id = "baseline"
        self.profile_version = "1"

    def profile(self) -> ManagementProfile:
        values: dict[str, Any] = {
            "profile_id": self.profile_id,
            "version": self.profile_version,
            "max_idle_seconds": self.timeout.value(),
            **{key: box.isChecked() for key, box in self.options.items()},
        }
        for key, field in self.fields.items():
            text = field.text().strip()
            values[key] = (
                None
                if not text
                else ()
                if text == "[]"
                else tuple(part.strip() for part in text.split(","))
            )
        try:
            profile = ManagementProfile.model_validate(values)
        except ValueError:
            self.error.setText(
                "Проверьте сети CIDR и имена серверов. Некорректный профиль не сохранён."
            )
            raise
        self.error.clear()
        return profile

    def load_profile(self, payload: dict[str, Any] | None) -> None:
        profile = ManagementProfile.model_validate_json(json.dumps(payload or {}))
        self.profile_id, self.profile_version = profile.profile_id, profile.version
        for key, field in self.fields.items():
            value = getattr(profile, key)
            field.setText("" if value is None else ", ".join(value) if value else "[]")
        for key, checkbox in self.options.items():
            checkbox.setChecked(getattr(profile, key))
        self.timeout.setValue(profile.max_idle_seconds)
        self.complete.setChecked(False)
        self.configuration_view.setCurrentIndex(0)
        self.configuration_node_path.clear()
