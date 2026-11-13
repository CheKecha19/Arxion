"""Выбор явно известных зон для сверки требований и ограничений."""

from PySide6.QtWidgets import QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QMessageBox, QWidget

from firewall_compliance.domain.access_matrix import MatrixZonePair

type ZoneChoices = tuple[tuple[str, ...], tuple[str, ...]]


def zone_pair_caption(pair: MatrixZonePair | None) -> str:
    return f"{pair.source_zone} → {pair.destination_zone}" if pair is not None else ""


class MatrixZoneDialog(QDialog):
    def __init__(self, current: MatrixZonePair | None, choices: ZoneChoices, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Зоны политики")
        self.zone_pair: MatrixZonePair | None = None
        form = QFormLayout(self)
        note = QLabel("Укажите имена зон как в политике. Пара ограничивает сверку этим направлением между зонами.")
        note.setWordWrap(True)
        form.addRow(note)
        self.source = self._combo(choices[0], current.source_zone if current else "")
        self.destination = self._combo(choices[1], current.destination_zone if current else "")
        form.addRow("Зона источника", self.source)
        form.addRow("Зона назначения", self.destination)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        clear = buttons.addButton("Без пары зон", QDialogButtonBox.ButtonRole.ResetRole)
        clear.clicked.connect(self.accept)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    @staticmethod
    def _combo(choices: tuple[str, ...], selected: str) -> QComboBox:
        combo = QComboBox()
        combo.setEditable(True)
        combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        combo.addItems(choices)
        combo.setEditText(selected)
        return combo

    def _save(self) -> None:
        try:
            self.zone_pair = MatrixZonePair(
                source_zone=self.source.currentText().strip(), destination_zone=self.destination.currentText().strip(),
            )
        except ValueError:
            QMessageBox.warning(self, "Зоны политики", "Укажите обе зоны или выберите «Без пары зон».")
            return
        self.accept()
