"""Редактор условий требования и выбор доказательств конкретных сеансов."""

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox, QPushButton, QVBoxLayout, QWidget,
)
from pydantic import ValidationError

from firewall_compliance.domain.access_context import AccessContextCondition, AccessContextSnapshot
from firewall_compliance.domain.access_matrix import AccessMatrix
from firewall_compliance.domain.matrix_context_inputs import MatrixContextInputs
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.qt_matrix_inputs import select_matrix_input


_CHANNEL_LABELS = {"office": "Офис", "vpn": "VPN"}


class MatrixContextConditionDialog(QDialog):
    def __init__(self, current: AccessContextCondition | None, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Условия пользователя и устройства")
        self.condition: AccessContextCondition | None = None
        layout = QFormLayout(self)
        self.group = QLineEdit(current.group_id if current else "")
        self.channel = QComboBox()
        self.channel.addItem("Офис", "office")
        self.channel.addItem("VPN", "vpn")
        if current is not None:
            self.channel.setCurrentIndex(self.channel.findData(current.channel))
        self.corporate = QCheckBox("Требуется корпоративное устройство")
        self.corporate.setChecked(current is None or current.corporate_device_required)
        self.device = QLineEdit(current.device_id or "" if current else "")
        layout.addRow("ID группы пользователей", self.group)
        layout.addRow("Подключение", self.channel)
        layout.addRow(self.corporate)
        layout.addRow("ID устройства, если указан", self.device)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        if current is not None:
            buttons.addButton("Убрать условия", QDialogButtonBox.ButtonRole.ResetRole).clicked.connect(self.accept)
        layout.addRow(buttons)

    def _save(self) -> None:
        try:
            self.condition = AccessContextCondition.model_validate({
                "group_id": self.group.text().strip(), "channel": self.channel.currentData(),
                "corporate_device_required": self.corporate.isChecked(),
                "device_id": self.device.text().strip() or None,
            })
        except ValueError:
            QMessageBox.warning(self, "Условия требования", "Укажите ID группы и проверьте длину идентификаторов.")
            return
        self.accept()


class MatrixContextInputsDialog(QDialog):
    def __init__(
        self, matrix: AccessMatrix, project_id: str, scope_id: str,
        current: MatrixContextInputs | None, runner: JobRunner, parent: QWidget,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Свидетельства о сеансах")
        self.resize(730, 380)
        self.inputs: MatrixContextInputs | None = None
        self._project = project_id
        self._scope = scope_id
        self._runner = runner
        self._closed = False
        self._loading = False
        self.finished.connect(self._finish)
        self._rows = {
            row.requirement_id: (row, condition) for row in matrix.requirements
            if row.scope_id == scope_id and (condition := row.access_context) is not None
        }
        self._snapshots: dict[str, AccessContextSnapshot] = {}
        self._times: dict[str, str] = {}
        self._sessions: dict[str, tuple[str, str]] = {}
        if current is not None:
            self._use_package(current)
        layout = QVBoxLayout(self)
        self.summary = QLabel()
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.open_file = QPushButton("Добавить снимки или открыть пакет…")
        self.open_file.clicked.connect(self._load)
        layout.addWidget(self.open_file)
        form = QFormLayout()
        context_row = QHBoxLayout()
        self.context = QComboBox()
        self.context.setAccessibleName("Сетевой контекст снимка сеансов")
        self.context.currentIndexChanged.connect(self._select_context)
        context_row.addWidget(self.context, 1)
        self.remove_context = QPushButton("Убрать снимок")
        self.remove_context.clicked.connect(self._remove_context)
        context_row.addWidget(self.remove_context)
        form.addRow("Сетевой контекст", context_row)
        self.time = QLineEdit()
        self.time.textEdited.connect(self._edit_time)
        self.time.setPlaceholderText("2026-11-12T12:00:00+03:00")
        form.addRow("Время проверки с часовым поясом", self.time)
        layout.addLayout(form)
        self.selected = QLabel("Выберите требование и конкретный сеанс.")
        self.selected.setTextFormat(Qt.TextFormat.PlainText)
        self.selected.setWordWrap(True)
        layout.addWidget(self.selected)
        actions = QHBoxLayout()
        self.choose = QPushButton("Назначить сеанс требованию…")
        self.choose.clicked.connect(self._assign)
        self.clear = QPushButton("Очистить назначения")
        self.clear.clicked.connect(self._clear)
        actions.addWidget(self.choose)
        actions.addWidget(self.clear)
        layout.addLayout(actions)
        self.same_conditions = QCheckBox("Назначать сеанс строкам с теми же источником, условиями и политикой")
        layout.addWidget(self.same_conditions)
        layout.addStretch()
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        buttons.addButton("Сверять без сведений о сеансах", QDialogButtonBox.ButtonRole.ResetRole).clicked.connect(self.accept)
        self.save = buttons.button(QDialogButtonBox.StandardButton.Ok)
        layout.addWidget(buttons)
        self._show_contexts()

    def _finish(self, _result: int) -> None:
        self._closed = True

    def _refresh(self) -> None:
        context = self.context.currentData()
        snapshot = self._snapshots.get(context)
        self.open_file.setEnabled(not self._loading)
        self.save.setEnabled(not self._loading)
        self.context.setEnabled(not self._loading and bool(self._snapshots))
        self.remove_context.setEnabled(not self._loading and snapshot is not None)
        self.time.setEnabled(not self._loading and snapshot is not None)
        self.choose.setEnabled(not self._loading and bool(self._snapshots) and bool(self._rows))
        self.clear.setEnabled(not self._loading and bool(self._sessions))
        self.summary.setText(
            "Читаем сведения о сеансах…" if self._loading else
            f"Снимков: {len(self._snapshots)} · назначений: {len(self._sessions)} из {len(self._rows)}.\n"
            f"{snapshot.context_id} · снимок от {snapshot.captured_at.isoformat()} · сеансов: {len(snapshot.sessions)}."
            if snapshot is not None else "Выберите офлайн-снимок членства, устройств и сеансов."
        )

    def _use_package(self, inputs: MatrixContextInputs) -> None:
        sources = inputs.contexts
        self._snapshots = {item.snapshot.context_id: item.snapshot for item in sources}
        self._times = {item.snapshot.context_id: item.evaluated_at.isoformat() for item in sources}
        self._sessions = {
            item.requirement_id: (inputs.context_for_selection(item), item.session_id)
            for item in inputs.sessions if item.requirement_id in self._rows
        }

    def _show_contexts(self, preferred: str | None = None) -> None:
        previous = self.context.blockSignals(True)
        self.context.clear()
        for key in self._snapshots:
            self.context.addItem(key, key)
        if preferred is not None and (index := self.context.findData(preferred)) >= 0:
            self.context.setCurrentIndex(index)
        self.context.blockSignals(previous)
        self._select_context()

    def _select_context(self, *_: object) -> None:
        self.time.setText(self._times.get(self.context.currentData(), ""))
        self._refresh()

    def _edit_time(self, text: str) -> None:
        context = self.context.currentData()
        if isinstance(context, str) and context in self._snapshots:
            self._times[context] = text

    def _drop_assignments(self, contexts: set[str]) -> int:
        old_count = len(self._sessions)
        self._sessions = {key: value for key, value in self._sessions.items() if value[0] not in contexts}
        return old_count - len(self._sessions)

    def _remove_context(self) -> None:
        context = self.context.currentData()
        if not isinstance(context, str) or context not in self._snapshots:
            return
        del self._snapshots[context]
        del self._times[context]
        cleared = self._drop_assignments({context})
        self.selected.setText(f"Снимок {context} убран. Сброшено назначений: {cleared}.")
        self._show_contexts()

    def _load(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Сведения о сеансах", "", "JSON (*.json)")
        if not paths:
            return
        self._loading = True
        self._refresh()

        def work() -> tuple[AccessContextSnapshot, ...] | MatrixContextInputs | str:
            snapshots = []
            for path in paths:
                data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
                if isinstance(data, dict) and "snapshot" in data:
                    if len(paths) != 1:
                        return "Пакет с назначениями открывается отдельно от снимков."
                    inputs = MatrixContextInputs.model_validate(data)
                    if (inputs.snapshot.project_id, inputs.snapshot.scope_id) != (self._project, self._scope):
                        raise ValueError("Область пакета не совпадает с областью сверки")
                    return inputs
                snapshot = AccessContextSnapshot.model_validate(data)
                if (snapshot.project_id, snapshot.scope_id) != (self._project, self._scope):
                    raise ValueError("Область снимка не совпадает с областью сверки")
                snapshots.append(snapshot)
            if len({item.context_id for item in snapshots}) != len(snapshots):
                return "За один раз выберите по одному снимку каждого сетевого контекста."
            return tuple(snapshots)

        def complete(value: object) -> None:
            if self._closed:
                return
            self._loading = False
            self._refresh()
            if isinstance(value, (JobError, str)):
                message = value if isinstance(value, str) else "Не удалось прочитать сведения для текущего проекта и области."
                QMessageBox.warning(self, "Сведения о сеансах", message)
                return
            if isinstance(value, MatrixContextInputs):
                if self._snapshots and not self._confirm_replace("Заменить загруженные снимки и назначения сведениями из пакета?"):
                    return
                self._use_package(value)
                self.selected.setText("Пакет открыт. Можно изменить назначения или время проверки.")
                self._show_contexts(value.snapshot.context_id)
            else:
                assert isinstance(value, tuple)
                self._add_snapshots(value)

        self._runner.submit(work, complete)

    def _confirm_replace(self, message: str) -> bool:
        return QMessageBox.question(
            self, "Сведения о сеансах", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        ) == QMessageBox.StandardButton.Yes

    def _add_snapshots(self, snapshots: tuple[AccessContextSnapshot, ...]) -> None:
        contexts = {item.context_id for item in snapshots}
        replaced = contexts & self._snapshots.keys()
        if replaced and not self._confirm_replace(
            "Заменить снимки для выбранных контекстов и сбросить связанные с ними назначения?"
        ):
            return
        cleared = self._drop_assignments(replaced) if replaced else 0
        for snapshot in snapshots:
            self._snapshots[snapshot.context_id] = snapshot
            self._times[snapshot.context_id] = snapshot.captured_at.isoformat()
        message = f"Загружено снимков: {len(snapshots)}."
        if cleared:
            message += f" Сброшено назначений: {cleared}."
        self.selected.setText(message)
        self._show_contexts(snapshots[0].context_id)

    def _assign(self) -> None:
        if not self._snapshots:
            return
        keys = tuple(self._rows)
        choices = [
            f"{key} · {row.source_group} → {row.destination_group} · {condition.group_id} · "
            f"{_CHANNEL_LABELS[condition.channel]} · "
            + (" / ".join(self._sessions[key]) if key in self._sessions else "без сеанса")
            for key, (row, condition) in self._rows.items()
        ]
        index = select_matrix_input(self, choices, title="Требование для проверки сеанса",
                                    placeholder="Поиск по ID или группе пользователей")
        if index is None:
            return
        key = keys[index]
        row, condition = self._rows[key]
        candidates = tuple(
            (context, session) for context, snapshot in self._snapshots.items()
            for session in snapshot.sessions if session.channel == condition.channel
        )
        if not candidates:
            self.selected.setText(f"В загруженных снимках нет сеансов типа «{_CHANNEL_LABELS[condition.channel]}».")
            return
        choice = select_matrix_input(self, [
            f"{context} · {session.session_id} · {session.principal_id} · {session.device_id} · "
            f"{session.assigned_ip} · действует с {session.valid_from.isoformat()} до {session.valid_until.isoformat()}"
            for context, session in candidates
        ], title=f"Сеанс требования · {_CHANNEL_LABELS[condition.channel]}",
            placeholder="Поиск по контексту, сеансу, пользователю, устройству или IP")
        if choice is not None:
            context, session = candidates[choice]
            targets = [key]
            if self.same_conditions.isChecked():
                targets.extend(
                    identifier for identifier, (other, other_condition) in self._rows.items()
                    if identifier != key and other.source_group == row.source_group
                    and other_condition == condition and other.policy_id == row.policy_id
                    and other.zone_pair == row.zone_pair
                    and self._sessions.get(identifier, (context, ""))[0] == context
                )
            self._sessions.update((target, (context, session.session_id)) for target in targets)
            self.selected.setText(f"{context} · {session.session_id} · {session.assigned_ip} · назначений: {len(targets)}")
            self.context.setCurrentIndex(self.context.findData(context))
            self._refresh()

    def _clear(self) -> None:
        self._sessions.clear()
        self.selected.setText("Назначения очищены.")
        self._refresh()

    def _save(self) -> None:
        if not self._snapshots:
            self.accept()
            return
        primary, *additional = self._snapshots
        try:
            self.inputs = MatrixContextInputs.model_validate({
                "snapshot": self._snapshots[primary], "evaluated_at": self._times[primary].strip(),
                "additional_contexts": tuple(
                    {"snapshot": self._snapshots[key], "evaluated_at": self._times[key].strip()}
                    for key in additional
                ),
                "sessions": tuple(
                    {"requirement_id": key, "session_id": session, "context_id": context if context != primary else None}
                    for key, (context, session) in sorted(self._sessions.items())
                ),
            })
        except ValidationError as error:
            message = "Не удалось сохранить сведения о сеансах."
            for item in error.errors(include_input=False):
                location = item["loc"]
                if not location or location[-1] != "evaluated_at":
                    continue
                context = primary
                if len(location) == 3 and location[0] == "additional_contexts" and isinstance(location[1], int):
                    context = additional[location[1]]
                self.context.setCurrentIndex(self.context.findData(context))
                self.time.setFocus()
                message = f"Укажите время с часовым поясом для контекста {context}."
                break
            QMessageBox.warning(self, "Снимки сеансов", message)
            return
        self.accept()
