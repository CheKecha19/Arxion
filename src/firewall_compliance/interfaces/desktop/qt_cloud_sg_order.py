"""Фиксация порядка назначенных групп из внешнего источника."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMessageBox, QPushButton, QVBoxLayout, QWidget,
)

from firewall_compliance.application.cloud_sg_revision import CloudSGOrderEvidence
from firewall_compliance.domain.cloud_security_groups import CloudSecurityGroupSnapshot, CloudSGInterface


class CloudSGOrderDialog(QDialog):
    def __init__(self, snapshot: CloudSecurityGroupSnapshot, interface: CloudSGInterface, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Подтверждённый порядок групп Advanced")
        self.resize(680, 490)
        self.evidence: CloudSGOrderEvidence | None = None
        self._snapshot, self._interface = snapshot, interface
        layout = QVBoxLayout(self)
        note = QLabel(
            "Переставьте группы в порядке применения к входящему трафику. "
            "Список изначально отсортирован по названию."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self._groups = QListWidget()
        self._groups.setAccessibleName("Последовательность применения групп безопасности")
        names = {group.group_id: group.name or group.group_id for group in snapshot.groups}
        ids = {item.group_id for item in interface.assignments}
        for identifier in sorted(ids, key=lambda key: (names.get(key, key).casefold(), key)):
            item = QListWidgetItem(f"{names.get(identifier, identifier)} · {identifier}")
            item.setData(Qt.ItemDataRole.UserRole, identifier)
            self._groups.addItem(item)
        self._groups.setCurrentRow(0)
        layout.addWidget(self._groups, 1)
        order = QHBoxLayout()
        up = QPushButton("Выше")
        up.clicked.connect(lambda: self._move(-1))
        down = QPushButton("Ниже")
        down.clicked.connect(lambda: self._move(1))
        order.addWidget(up)
        order.addWidget(down)
        order.addStretch()
        layout.addLayout(order)
        form = QFormLayout()
        self._source = QLineEdit()
        self._reference = QLineEdit()
        self._time = QLineEdit(snapshot.captured_at.isoformat())
        form.addRow("Источник порядка", self._source)
        form.addRow("Ссылка или ID записи", self._reference)
        form.addRow("Время с часовым поясом", self._time)
        layout.addLayout(form)
        self._confirmed = QCheckBox("Источник подтверждает этот порядок для указанного интерфейса и сбора")
        layout.addWidget(self._confirmed)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        accept = buttons.button(QDialogButtonBox.StandardButton.Ok)
        accept.setEnabled(False)
        self._confirmed.toggled.connect(accept.setEnabled)
        layout.addWidget(buttons)

    def _move(self, offset: int) -> None:
        current = self._groups.currentRow()
        destination = current + offset
        if current >= 0 and 0 <= destination < self._groups.count():
            item = self._groups.takeItem(current)
            self._groups.insertItem(destination, item)
            self._groups.setCurrentRow(destination)
            self._confirmed.setChecked(False)

    def _save(self) -> None:
        try:
            evidence = CloudSGOrderEvidence.model_validate({
                "scan_id": self._snapshot.scan_id, "scope_id": self._snapshot.scope_id,
                "interface_id": self._interface.interface_id, "snapshot_sha256": self._snapshot.source_sha256,
                "observed_at": self._time.text().strip(), "source_name": self._source.text().strip(),
                "source_reference": self._reference.text().strip(),
                "group_ids": tuple(self._groups.item(index).data(Qt.ItemDataRole.UserRole)
                                   for index in range(self._groups.count())),
            })
        except ValueError:
            QMessageBox.warning(self, "Порядок групп", "Укажите источник, ссылку на запись и время с часовым поясом.")
            return
        if evidence.observed_at != self._snapshot.captured_at:
            QMessageBox.warning(self, "Порядок групп", "Время наблюдения должно совпадать со временем этого сбора.")
            return
        self.evidence = evidence
        self.accept()
