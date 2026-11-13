"""Создание нескольких требований для одной пары групп."""

from collections import Counter
from collections.abc import Callable, Sequence
from uuid import uuid4

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.domain.access_matrix import MatrixGroup, MatrixRequirement, MatrixService, MatrixZonePair
from firewall_compliance.domain.policy_matching import Interval, merge_intervals
from firewall_compliance.interfaces.desktop.qt_matrix_boundary import group_combo, group_identifier, service_from_text
from firewall_compliance.interfaces.desktop.qt_matrix_zones import MatrixZoneDialog, ZoneChoices, zone_pair_caption


def _parse_services(text: str) -> tuple[MatrixService, ...]:
    services: list[MatrixService] = []
    seen: dict[tuple[str, tuple[Interval, ...]], int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        cleaned = line.strip().casefold()
        if not cleaned:
            continue
        protocol, separator, ports = cleaned.partition("/")
        ports = ports.strip()
        try:
            if separator and not ports:
                raise ValueError("missing ports")
            service = service_from_text(protocol.strip(), ports)
        except ValueError:
            raise ValueError(
                f"Проверьте сервис в строке {number}. Подходящие записи — tcp/443, udp/53, tcp/8000-8100, tcp/* и icmp."
            ) from None
        ranges = [(0, 65535)] if service.any_ports else [(port.start, port.end) for port in service.ports]
        key = service.protocol, merge_intervals(ranges)
        if key in seen:
            raise ValueError(f"Сервис в строке {number} повторяет строку {seen[key]}.")
        seen[key] = number
        services.append(service)
    if not services:
        raise ValueError("Укажите хотя бы один сервис.")
    return tuple(services)


class MatrixNewRequirementsDialog(QDialog):
    def __init__(
        self, groups: Sequence[MatrixGroup], scope_id: str, parent: QWidget, *,
        source_group: str = "", destination_group: str = "", policy_id: str = "",
        zone_pair: MatrixZonePair | None = None,
        policy_picker: Callable[[QWidget, str, str], str | None] | None = None,
        zone_choices: Callable[[str], ZoneChoices] | None = None,
    ) -> None:
        super().__init__(parent)
        self.requirements: tuple[MatrixRequirement, ...] = ()
        self._scope_id = scope_id
        counts = Counter(group.group_id for group in groups)
        self._group_ids = {identifier for identifier, count in counts.items() if count == 1}
        groups = tuple(group for group in groups if group.group_id in self._group_ids)
        self._group_names: dict[str, str | None] = {}
        for group in groups:
            name = group.name.casefold()
            self._group_names[name] = group.group_id if name not in self._group_names else None
        self._policy_id = policy_id.strip()
        self._zone_pair = zone_pair
        self._zone_choices = zone_choices
        self.setWindowTitle("Добавить требования для пары групп")
        self.resize(650, 440)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self._source = self._group_selector(groups, source_group, "Группа источника")
        self._destination = self._group_selector(groups, destination_group, "Группа назначения")
        form.addRow("Откуда", self._source)
        form.addRow("Куда", self._destination)
        scope = QLabel(scope_id)
        scope.setTextFormat(Qt.TextFormat.PlainText)
        scope.setWordWrap(True)
        form.addRow("Область", scope)

        self._action = QComboBox()
        for label, value in (
            ("Доступ необходим", "permit"),
            ("Доступ допустим", "allow_optional"),
            ("Запретить", "deny"),
            ("Не регламентировано", "unregulated"),
        ):
            self._action.addItem(label, value)
        form.addRow("Требование", self._action)

        self._policy = QLineEdit(policy_id)
        self._policy.setPlaceholderText("Можно оставить пустым")
        self._policy.setAccessibleName("ID политики")
        policy_field = QHBoxLayout()
        policy_field.addWidget(self._policy, 1)
        if policy_picker is not None:
            pick_policy = QPushButton("Из снимков…")
            pick_policy.setAutoDefault(False)
            pick_policy.setAccessibleName("Выбрать политику из сохранённых снимков")

            def choose_policy() -> None:
                selected = policy_picker(self, self._scope_id, self._policy.text().strip())
                if selected is not None:
                    self._policy.setText(selected)

            pick_policy.clicked.connect(choose_policy)
            policy_field.addWidget(pick_policy)
        form.addRow("Политика", policy_field)

        self._zone_label = QLabel()
        self._zone_label.setTextFormat(Qt.TextFormat.PlainText)
        self._zone_label.setWordWrap(True)
        if zone_choices is not None or zone_pair is not None:
            zones = QPushButton("Зоны политики…")
            zones.setAutoDefault(False)
            zones.clicked.connect(self._edit_zones)
            form.addRow(zones, self._zone_label)
        self._show_zones()
        self._policy.textChanged.connect(self._policy_changed)

        self._services = QPlainTextEdit()
        self._services.setAccessibleName("Сервисы, один на строку")
        self._services.setPlaceholderText("tcp/443\nudp/53\ntcp/8000-8100")
        self._services.setMinimumHeight(120)
        form.addRow("Сервисы", self._services)
        example = QLabel("Один сервис на строку. Для всех TCP-портов укажите tcp/*. Для ICMP укажите icmp.")
        example.setWordWrap(True)
        form.addRow("", example)
        layout.addLayout(form, 1)

        self._error = QLabel()
        self._error.setTextFormat(Qt.TextFormat.PlainText)
        self._error.setWordWrap(True)
        self._error.setAccessibleName("Проверка введённых требований")
        layout.addWidget(self._error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        proceed = buttons.button(QDialogButtonBox.StandardButton.Ok)
        proceed.setText("Предпросмотр")
        proceed.setAutoDefault(False)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setAutoDefault(False)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        first_field: QWidget = self._source
        if source_group in self._group_ids:
            first_field = self._services if destination_group in self._group_ids else self._destination
        first_field.setFocus()

    @staticmethod
    def _group_selector(groups: Sequence[MatrixGroup], identifier: str, accessible_name: str) -> QComboBox:
        selector = group_combo(groups, identifier)
        selector.setAccessibleName(accessible_name)
        if editor := selector.lineEdit():
            editor.setPlaceholderText("Название или ID группы")
        if completer := selector.completer():
            completer.setFilterMode(Qt.MatchFlag.MatchContains)
            completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        return selector

    def _group_id(self, selector: QComboBox) -> str:
        identifier = group_identifier(selector)
        if identifier in self._group_ids:
            return identifier
        index = selector.findText(identifier)
        if index >= 0:
            return str(selector.itemData(index))
        return self._group_names.get(identifier.casefold()) or ""

    def _policy_changed(self, text: str) -> None:
        policy_id = text.strip()
        if policy_id != self._policy_id:
            self._policy_id = policy_id
            self._zone_pair = None
            self._show_zones()

    def _show_zones(self) -> None:
        self._zone_label.setText(zone_pair_caption(self._zone_pair) or "Без пары зон")

    def _edit_zones(self) -> None:
        choices = self._zone_choices(self._policy_id) if self._zone_choices is not None else ((), ())
        dialog = MatrixZoneDialog(self._zone_pair, choices, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._zone_pair = dialog.zone_pair
            self._show_zones()
        dialog.deleteLater()

    def _save(self) -> None:
        source = self._group_id(self._source)
        destination = self._group_id(self._destination)
        if not source or not destination:
            self._error.setText("Выберите существующую группу источника и группу назначения.")
            (self._source if not source else self._destination).setFocus()
            return
        try:
            services = _parse_services(self._services.toPlainText())
        except ValueError as error:
            self._error.setText(str(error))
            self._services.setFocus()
            return
        try:
            self.requirements = tuple(
                MatrixRequirement(
                    requirement_id=f"req-{uuid4().hex}",
                    source_group=source,
                    destination_group=destination,
                    service=service,
                    requirement=self._action.currentData(),
                    scope_id=self._scope_id,
                    policy_id=self._policy_id or None,
                    zone_pair=self._zone_pair,
                )
                for service in services
            )
        except ValueError:
            self._error.setText("Проверьте область, ID политики и выбранные зоны.")
            return
        self.accept()
