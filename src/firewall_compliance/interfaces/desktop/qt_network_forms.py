"""Native forms for explicit network evidence; raw JSON remains an optional fallback."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Literal, cast

from pydantic import BaseModel, TypeAdapter, ValidationError
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.domain.forwarding import ForwardingSource
from firewall_compliance.domain.observation import ObservationEvidence, ObservationWindow
from firewall_compliance.domain.policy_decision import PolicyBindingEvidence
from firewall_compliance.parsers.network_contracts import NetworkDocumentMetadata

ContractKind = Literal[
    "metadata", "forward_metadata", "observation", "window", "binding", "profile"
]
COMMANDS = {
    "asa_running_config_interfaces": "show running-config interface",
    "asa_running_config_static_routes": "show running-config route",
    "asa_ipv4_rib": "show route",
}
SCOPES = (
    "interfaces",
    "acl_definitions",
    "acl_bindings",
    "same_security",
    "vpn_bypass",
    "object_nat",
    "manual_nat",
    "effective_nat",
    "pbr_bindings",
    "pbr_definitions",
    "exceptions",
)
LABELS = {
    "source_kind": "Роль документа",
    "command": "Команда экспорта (не выполняется)",
    "declared_version": "Заявленная версия",
    "version_provenance": "Происхождение версии",
    "version_reference": "Основание версии",
    "origin": "Происхождение документа",
    "origin_reference": "Основание происхождения",
    "context_mode": "Режим контекстов",
    "context": "Имя контекста (multiple)",
    "firewall_mode": "Режим firewall",
    "address_family": "Семейство адресов",
    "table_role": "Назначение таблицы",
    "table_id": "ID таблицы",
    "encoding": "Кодировка",
    "selection": "Область выборки",
    "extent": "Объём документа",
    "capture_success": "Подтверждён успешный захват",
    "complete": "Заявлена полнота",
    "completeness_reference": "Основание полноты",
    "observed_at": "Время состояния устройства (ISO 8601 с часовым поясом)",
    "method": "Способ подтверждения времени",
    "reference": "Основание времени состояния",
    "start": "Начало интервала (ISO 8601 с часовым поясом)",
    "end": "Конец интервала (ISO 8601 с часовым поясом)",
    "reason": "Основание согласованности",
    "policy_id": "ID политики / ACL",
    "direction": "Направление",
    "interface_id": "ID интерфейса",
    "interface_label": "Метка интерфейса",
    "interface_mapping_reference": "Основание соответствия метки и ID",
    "source_document_id": "UUID исходного документа",
    "binding_location.source_name": "Имя файла",
    "binding_location.line_start": "Начальная строка",
    "binding_location.line_end": "Конечная строка",
    "binding_location.object_path": "Путь объекта (вместо строки)",
    "binding_location.object_id": "ID объекта (вместо строки)",
    "declaration_origin": "Происхождение декларации",
    "implicit_action": "Неявное действие",
    "terminal": "Подтверждён конец цепочки ACL",
    "terminal_reference": "Основание конца цепочки",
    "coordinate_space": "Координаты потока",
    "purpose": "Назначение документа",
    "complete_scopes": "Области с подтверждённой полнотой",
    "profile_reference": "Основание профиля",
}
OPTIONS = {
    "source_kind": tuple(COMMANDS),
    "version_provenance": ("operator_declared", "documentation", "device_export"),
    "origin": ("operator_declared", "synthetic", "device_export"),
    "context_mode": ("single", "multiple"),
    "firewall_mode": ("routed", "transparent"),
    "address_family": ("ipv4", "ipv6"),
    "table_role": ("data", "management"),
    "encoding": ("utf-8", "ascii"),
    "selection": ("partial", "authored_excerpt", "all", "filtered", "single_interface"),
    "extent": ("excerpt", "full", "truncated"),
    "method": ("operator_declared", "device_export", "synthetic"),
    "direction": ("in", "out"),
    "declaration_origin": ("operator_declared", "synthetic"),
    "implicit_action": ("unknown", "deny"),
    "coordinate_space": ("acl_input",),
    "purpose": ("configuration", "effective_nat", "pbr_state"),
}
OPTIONAL = {"context", "completeness_reference", "terminal_reference"}
BOOLS = {"capture_success", "complete", "terminal"}
MODELS: dict[str, type[BaseModel]] = {
    "metadata": NetworkDocumentMetadata,
    "forward_metadata": ForwardingSource,
    "observation": ObservationEvidence,
    "window": ObservationWindow,
    "binding": PolicyBindingEvidence,
}
FIELDS = {
    "metadata": tuple(
        key
        for key in LABELS
        if key in NetworkDocumentMetadata.model_fields and key != "source_document_id"
    ),
    "forward_metadata": tuple(
        key
        for key in LABELS
        if key in ForwardingSource.model_fields and key != "source_document_id"
    ),
    "observation": ("observed_at", "method", "reference"),
    "window": ("start", "end", "reason"),
    "binding": (
        "policy_id",
        "direction",
        "interface_id",
        "interface_label",
        "interface_mapping_reference",
        "source_document_id",
        "binding_location.source_name",
        "binding_location.line_start",
        "binding_location.line_end",
        "binding_location.object_path",
        "binding_location.object_id",
        "complete",
        "completeness_reference",
        "declaration_origin",
        "implicit_action",
        "terminal",
        "terminal_reference",
        "coordinate_space",
    ),
    "profile": (
        "context_mode",
        "firewall_mode",
        "address_family",
        "table_role",
        "table_id",
        "profile_reference",
    ),
}


class NetworkContractForm(QWidget):
    """Typed fields with explicit unknown observation and compatible editor hooks.

    Generated IDs, hashes and collection timestamps remain exclusively backend-owned.
    ``setPlainText`` deliberately selects raw mode for existing callers and automation.
    """

    textChanged = Signal()

    def __init__(self, kind: ContractKind, defaults: dict[str, Any] | None = None) -> None:
        super().__init__()
        self.kind = kind
        self.defaults = deepcopy(defaults or {})
        self.fields: dict[str, QLineEdit | QComboBox | QCheckBox] = {}
        self.scope_checks: dict[str, QCheckBox] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.declared = QCheckBox(
            {
                "observation": "Время состояния известно и подтверждено",
                "window": "Заявить согласованный интервал наблюдений",
                "profile": "Заявить профиль устройства",
            }.get(kind, "Явная декларация")
        )
        self.declared.setChecked(bool(defaults))
        self.declared.setVisible(kind in {"observation", "window", "profile"})
        layout.addWidget(self.declared)
        self.form_widget = QWidget()
        form = QFormLayout(self.form_widget)
        form.setContentsMargins(0, 0, 0, 0)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.form_widget.setEnabled(
            kind not in {"observation", "window", "profile"} or bool(defaults)
        )
        self.declared.toggled.connect(self.form_widget.setEnabled)
        self.declared.toggled.connect(self.textChanged)
        layout.addWidget(self.form_widget)
        for key in FIELDS[kind]:
            initial = self._get(self.defaults, key)
            if key == "complete_scopes":
                group = QGroupBox(LABELS[key])
                checks = QVBoxLayout(group)
                for scope in SCOPES:
                    check = QCheckBox(scope)
                    check.setChecked(scope in (initial or []))
                    check.toggled.connect(self.textChanged)
                    self.scope_checks[scope] = check
                    checks.addWidget(check)
                form.addRow(group)
                continue
            field: QLineEdit | QComboBox | QCheckBox
            if key in BOOLS:
                field = QCheckBox()
                field.setChecked(initial is True)
                field.toggled.connect(self.textChanged)
            elif key in OPTIONS:
                field = QComboBox()
                field.addItem("Не выбрано", None)
                for option in OPTIONS[key]:
                    field.addItem(option, option)
                field.setCurrentIndex(max(0, field.findData(initial)))
                field.currentIndexChanged.connect(self.textChanged)
            else:
                field = QLineEdit(str(initial) if initial is not None else "")
                if key in {"observed_at", "start", "end"}:
                    field.setPlaceholderText("ГГГГ-ММ-ДДTчч:мм:сс+03:00 — только известное время")
                field.textChanged.connect(self.textChanged)
            field.setAccessibleName(LABELS[key])
            self.fields[key] = field
            form.addRow(LABELS[key], field)
        if kind == "metadata":
            command = QPushButton("Подставить команду выбранной роли")
            command.clicked.connect(self._command)
            form.addRow(command)
        hint = QLabel(
            "Неизвестное время оставьте незаявленным. Полнота, successful capture и конец ACL "
            "требуют отдельных оснований; форма не подтверждает эти факты автоматически."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.error = QLabel()
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        self.raw_group = QGroupBox("Дополнительно: редактировать исходный JSON вместо формы")
        self.raw_group.setCheckable(True)
        self.raw_group.setChecked(False)
        raw_layout = QVBoxLayout(self.raw_group)
        self.raw = QPlainTextEdit()
        self.raw.setMinimumHeight(130)
        self.raw.setAccessibleName("Дополнительный исходный JSON")
        self.raw.setVisible(False)
        raw_layout.addWidget(self.raw)
        self.raw_group.toggled.connect(self._raw_mode)
        self.raw.textChanged.connect(self.textChanged)
        layout.addWidget(self.raw_group)

    @staticmethod
    def _get(payload: dict[str, Any], key: str) -> Any:
        value: Any = payload
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        return value

    def _command(self) -> None:
        role, field = self.fields["source_kind"], self.fields["command"]
        if isinstance(role, QComboBox) and isinstance(field, QLineEdit):
            field.setText(COMMANDS.get(str(role.currentData()), ""))

    def _form_values(self) -> dict[str, Any]:
        if self.kind in {"observation", "window", "profile"} and not self.declared.isChecked():
            return {}
        result = deepcopy(self.defaults)
        for key, field in self.fields.items():
            value: Any = (
                field.isChecked()
                if isinstance(field, QCheckBox)
                else (field.currentData() if isinstance(field, QComboBox) else field.text().strip())
            )
            if (
                key in OPTIONAL
                or key.startswith("binding_location.")
                and key != "binding_location.source_name"
            ):
                value = value or None
            if (
                key in {"binding_location.line_start", "binding_location.line_end"}
                and value is not None
            ):
                try:
                    value = int(value)
                except ValueError:
                    raise ValueError(f"{LABELS[key]}: введите целое число от 1.") from None
            target = result
            parts = key.split(".")
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = value
        if self.kind == "forward_metadata":
            result["complete_scopes"] = [
                scope for scope, field in self.scope_checks.items() if field.isChecked()
            ] + [scope for scope in self.defaults.get("complete_scopes", []) if scope not in SCOPES]
        if self.kind == "profile":
            result = {key: value for key, value in result.items() if value not in ("", None)}
        return result

    def _raw_mode(self, enabled: bool) -> None:
        if enabled:
            try:
                self.raw.setPlainText(json.dumps(self._form_values(), ensure_ascii=False, indent=2))
            except ValueError as error:
                self.error.setText(str(error))
        else:
            try:
                payload = json.loads(self.raw.toPlainText())
                if not isinstance(payload, dict):
                    raise ValueError("Ожидается JSON-объект.")
                self._load(payload)
            except (ValueError, TypeError) as error:
                self.error.setText(self._message(error))
                self.raw_group.blockSignals(True)
                self.raw_group.setChecked(True)
                self.raw_group.blockSignals(False)
                return
        self.raw.setVisible(enabled)
        self.form_widget.setVisible(not enabled)
        self.declared.setEnabled(not enabled)
        self.textChanged.emit()

    def _load(self, payload: dict[str, Any]) -> None:
        self.defaults = deepcopy(payload)
        if self.kind in {"observation", "window", "profile"}:
            self.declared.setChecked(bool(payload))
        else:
            self.form_widget.setEnabled(True)
        for key, field in self.fields.items():
            value = self._get(payload, key)
            if isinstance(field, QCheckBox):
                field.setChecked(value is True)
            elif isinstance(field, QComboBox):
                index = field.findData(value)
                if index < 0:
                    field.addItem(str(value), value)
                    index = field.count() - 1
                field.setCurrentIndex(index)
            else:
                field.setText(str(value) if value is not None else "")
        for scope, check in self.scope_checks.items():
            check.setChecked(scope in (payload.get("complete_scopes") or []))

    def setPlainText(self, text: str) -> None:
        self.raw_group.setChecked(True)
        self.raw.setPlainText(text)

    def toPlainText(self) -> str:
        return (
            self.raw.toPlainText()
            if self.raw_group.isChecked()
            else json.dumps(self._form_values(), ensure_ascii=False, indent=2)
        )

    def values(self) -> dict[str, Any]:
        try:
            if self.raw_group.isChecked():
                result = json.loads(self.raw.toPlainText())
                if not isinstance(result, dict):
                    raise ValueError("Ожидается JSON-объект.")
            else:
                result = self._form_values()
            self._validate(result)
        except (ValueError, TypeError) as error:
            message = self._message(error)
            self.error.setText(message)
            raise ValueError(message) from None
        self.error.clear()
        return cast(dict[str, Any], result)

    @staticmethod
    def _message(error: Exception) -> str:
        if isinstance(error, ValidationError):
            first = error.errors(include_input=False)[0]
            field = ".".join(str(part) for part in first["loc"])
            return f"{LABELS.get(field, field) or 'Декларация'}: {first['msg']}"
        if isinstance(error, json.JSONDecodeError):
            return f"JSON: ошибка в строке {error.lineno}, столбце {error.colno}."
        return str(error)

    def _validate(self, values: dict[str, Any]) -> None:
        if self.kind in {"observation", "window", "profile"} and not values:
            return
        if self.kind == "profile":
            if set(values) - set(FIELDS["profile"]):
                raise ValueError("Профиль содержит недопустимые поля.")
            if not str(values.get("profile_reference") or "").strip():
                raise ValueError("Укажите основание явно заявленного профиля.")
            for key in set(values) & set(OPTIONS):
                if values[key] not in OPTIONS[key]:
                    raise ValueError(f"{LABELS[key]}: выберите допустимое значение.")
            return
        model = MODELS[self.kind]
        if self.kind in {"observation", "window", "binding"}:
            model.model_validate(values)
            return
        # Validate operator-owned DTO fields; identity/hash/capture dates are supplied
        # by the backend from the selected document and are never fabricated here.
        for key in FIELDS[self.kind]:
            definition = model.model_fields[key]
            if key not in values and not definition.is_required():
                continue
            try:
                TypeAdapter(definition.rebuild_annotation()).validate_python(values.get(key))
            except ValidationError as error:
                raise ValueError(f"{LABELS[key]}: {self._message(error)}") from None
        if values.get("context_mode") == "single" and values.get("context") is not None:
            raise ValueError("Для single имя отдельного контекста должно быть пустым.")
        complete = values.get("complete") or values.get("complete_scopes")
        if complete and (
            values.get("selection") != "all"
            or values.get("extent") != "full"
            or values.get("capture_success") is not True
            or not values.get("completeness_reference")
        ):
            raise ValueError("Полнота требует all / full, успешный захват и непустое основание.")
