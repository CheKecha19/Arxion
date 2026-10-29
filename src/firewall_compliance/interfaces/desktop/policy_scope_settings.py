"""Editor for explicit CHECKS-003/005 organization inputs."""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.domain.policy_scope import PolicyScopeProfile


class PolicyScopeSettings(QWidget):
    changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._loading = False
        layout = QVBoxLayout(self)
        note = QLabel(
            "CHECKS-003/005 используют только явные пороги, ролевые требования и полноту "
            "инвентаря привязок. JSON-массивы соответствуют POLICY_SCOPE_CHECKS.md."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        form = QFormLayout()
        self.excessive_state = self._state_combo()
        self.attachment_state = self._state_combo()
        self.thresholds: dict[str, QLineEdit] = {}
        form.addRow("Проверка ширины доступа", self.excessive_state)
        for key, title in (
            ("max_source_addresses", "Максимум адресов источника"),
            ("max_destination_addresses", "Максимум адресов назначения"),
            ("max_destination_ports", "Максимум портов назначения"),
        ):
            field = QLineEdit()
            field.setAccessibleName(title)
            field.setPlaceholderText("Пусто — порог не задан")
            field.editingFinished.connect(self._changed)
            self.thresholds[key] = field
            form.addRow(title, field)
        form.addRow("Полнота привязок ACL", self.attachment_state)
        self.exceptions = QLineEdit()
        self.exceptions.setPlaceholderText("ID правил через запятую")
        self.exceptions.editingFinished.connect(self._changed)
        form.addRow("Согласованные исключения", self.exceptions)
        layout.addLayout(form)
        self.role_requirements = self._json_editor("Ролевые требования JSON")
        self.required_attachments = self._json_editor("Обязательные привязки JSON")
        for title, editor in (
            ("Ролевые требования (пусто — unknown, [] — нет требований)", self.role_requirements),
            (
                "Обязательные привязки (пусто — unknown, [] — нет требований)",
                self.required_attachments,
            ),
        ):
            label = QLabel(title)
            label.setWordWrap(True)
            layout.addWidget(label)
            layout.addWidget(editor)
        self.error = QLabel()
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setWordWrap(True)
        layout.addWidget(self.error)

    def _state_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.addItem("Неизвестно", None)
        combo.addItem("Включено / подтверждено полностью", True)
        combo.addItem("Отключено / подтверждено неполно", False)
        combo.currentIndexChanged.connect(self._changed)
        return combo

    def _json_editor(self, name: str) -> QPlainTextEdit:
        editor = QPlainTextEdit()
        editor.setAccessibleName(name)
        editor.setPlaceholderText("JSON-массив; пусто означает неизвестные требования")
        editor.setMaximumHeight(130)
        editor.textChanged.connect(self._changed)
        return editor

    def _changed(self, *_: Any) -> None:
        if not self._loading:
            self.changed.emit()

    @staticmethod
    def _array(editor: QPlainTextEdit) -> list[Any] | None:
        text = editor.toPlainText().strip()
        if not text:
            return None
        value = json.loads(text)
        if not isinstance(value, list):
            raise ValueError("Ожидается JSON-массив.")
        return value

    def profile(self) -> PolicyScopeProfile:
        try:
            values: dict[str, Any] = {
                "excessive_access_enabled": self.excessive_state.currentData(),
                "attachment_inventory_complete": self.attachment_state.currentData(),
                "role_requirements": self._array(self.role_requirements),
                "required_attachments": self._array(self.required_attachments),
                "exception_rule_ids": [
                    value.strip() for value in self.exceptions.text().split(",") if value.strip()
                ],
            }
            for key, field in self.thresholds.items():
                text = field.text().strip()
                values[key] = int(text) if text else None
            result = PolicyScopeProfile.model_validate(values)
        except (ValueError, json.JSONDecodeError):
            message = "Проверьте числа, уникальные ID, CIDR и структуру JSON профиля."
            self.error.setText(message)
            raise ValueError(message) from None
        self.error.clear()
        return result

    def load_profile(self, payload: dict[str, Any] | None) -> None:
        profile = PolicyScopeProfile.model_validate(payload or {})
        self._loading = True
        try:
            for combo, value in (
                (self.excessive_state, profile.excessive_access_enabled),
                (self.attachment_state, profile.attachment_inventory_complete),
            ):
                combo.setCurrentIndex(max(0, combo.findData(value)))
            for key, field in self.thresholds.items():
                value = getattr(profile, key)
                field.setText("" if value is None else str(value))
            self.exceptions.setText(", ".join(profile.exception_rule_ids))
            for editor, collection in (
                (self.role_requirements, profile.role_requirements),
                (self.required_attachments, profile.required_attachments),
            ):
                editor.setPlainText(
                    ""
                    if collection is None
                    else json.dumps(
                        [item.model_dump(mode="json") for item in collection],
                        ensure_ascii=False,
                        indent=2,
                    )
                )
            self.error.clear()
        finally:
            self._loading = False
