"""Редактирование общих ограничений по нескольким точкам проверки."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from uuid import uuid4

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QPushButton, QVBoxLayout, QWidget,
)

from firewall_compliance.application.matrix_reports import matrix_service_label
from firewall_compliance.domain.access_matrix import MatrixBoundary, MatrixBoundaryGroup
from firewall_compliance.interfaces.desktop.qt_matrix_inputs import select_matrix_input
from firewall_compliance.interfaces.desktop.qt_matrix_table import MatrixTable
from firewall_compliance.interfaces.desktop.qt_matrix_zones import zone_pair_caption


type BoundaryDomain = tuple[str, str, str, str, bool, tuple[tuple[int, int], ...]]


def boundary_domain(row: MatrixBoundary) -> BoundaryDomain:
    service = row.service
    return (
        row.scope_id, row.source_group, row.destination_group, service.protocol,
        service.any_ports, tuple((port.start, port.end) for port in service.ports),
    )


class MatrixBoundaryGroupDialog(QDialog):
    def __init__(
        self, boundaries: Sequence[MatrixBoundary], group_names: Mapping[str, str],
        scope_id: str, current: MatrixBoundaryGroup | None, unavailable_ids: set[str], parent: QWidget,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Общее ограничение доступа")
        self.resize(790, 450)
        self.value: MatrixBoundaryGroup | None = None
        self._scope = current.scope_id if current is not None else scope_id
        self._unavailable_ids = unavailable_ids
        self._points = list(current.boundary_ids) if current is not None else []
        self._point_names = dict(current.point_names) if current is not None else {}
        self._by_id = {row.boundary_id: row for row in boundaries if row.scope_id == self._scope}
        self._domains = Counter(boundary_domain(row) for row in self._by_id.values())
        self._group_names = group_names
        self._labels = {key: self._describe(row) for key, row in self._by_id.items()}

        layout = QVBoxLayout(self)
        description = QLabel(
            "Выберите минимум две точки проверки с одинаковыми группами и сервисом. "
            "Например, транзитный ACL и управление устройством. "
            "Если политики пока нет, скопируйте отдельное ограничение в другую точку и оставьте политику пустой."
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        form = QFormLayout()
        self._name = QLineEdit(current.name if current else "")
        self._name.setMaxLength(256)
        form.addRow("Название", self._name)
        self._id = QLineEdit(current.group_id if current else f"boundary-{uuid4().hex[:8]}")
        self._id.setMaxLength(128)
        form.addRow("ID общего ограничения", self._id)
        layout.addLayout(form)

        self._domain_label = QLabel()
        self._domain_label.setTextFormat(Qt.TextFormat.PlainText)
        self._domain_label.setWordWrap(True)
        layout.addWidget(self._domain_label)
        self._table = MatrixTable(("Точка проверки", "ID ограничения", "Политика", "Зоны"))
        self._table.setAccessibleName("Точки проверки общего ограничения")
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.doubleClicked.connect(lambda _: self._rename())
        layout.addWidget(self._table, 1)
        layout.addLayout(self._table.navigation())

        actions = QHBoxLayout()
        self._add_button = QPushButton("Добавить точку…")
        self._add_button.clicked.connect(self._add)
        actions.addWidget(self._add_button)
        self._rename_button = QPushButton("Назвать точку…")
        self._rename_button.clicked.connect(self._rename)
        actions.addWidget(self._rename_button)
        self._remove_button = QPushButton("Убрать точку")
        self._remove_button.clicked.connect(self._remove)
        actions.addWidget(self._remove_button)
        actions.addStretch()
        layout.addLayout(actions)
        self._table.itemSelectionChanged.connect(self._selection_changed)

        self._error = QLabel()
        self._error.setTextFormat(Qt.TextFormat.PlainText)
        self._error.setWordWrap(True)
        layout.addWidget(self._error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._refresh()

    def _interaction(self, row: MatrixBoundary) -> str:
        source = self._group_names.get(row.source_group, row.source_group)
        target = self._group_names.get(row.destination_group, row.destination_group)
        return f"{source} → {target} · {matrix_service_label(row.service)}"

    def _describe(self, row: MatrixBoundary) -> str:
        parts = row.boundary_id, self._interaction(row), row.policy_id or "Политика не указана"
        return " · ".join(filter(None, (*parts, zone_pair_caption(row.zone_pair))))

    def _candidates(self) -> list[str]:
        chosen = set(self._points)
        if not self._points:
            return [key for key, row in self._by_id.items() if self._domains[boundary_domain(row)] > 1]
        reference = boundary_domain(self._by_id[self._points[0]])
        return [
            key for key, row in self._by_id.items()
            if key not in chosen and boundary_domain(row) == reference
        ]

    def _refresh(self) -> None:
        self._domain_label.setText(
            self._interaction(self._by_id[self._points[0]]) if self._points else "Выберите первую точку проверки."
        )
        self._table.set_rows(range(len(self._points)), self._values)
        self._add_button.setEnabled(bool(self._candidates()))
        self._selection_changed()

    def _values(self, index: int) -> tuple[str, str, str, str]:
        key = self._points[index]
        row = self._by_id[key]
        return (
            self._point_names.get(key, key), key,
            row.policy_id or "Политика не указана", zone_pair_caption(row.zone_pair),
        )

    def _selection_changed(self) -> None:
        selected = self._table.selected_index() is not None
        self._rename_button.setEnabled(selected)
        self._remove_button.setEnabled(selected)

    def _add(self) -> None:
        candidates = self._candidates()
        choice = select_matrix_input(
            self, [self._labels[key] for key in candidates], title="Выбрать точку проверки",
            placeholder="ID, группа, сервис или политика",
        )
        if choice is not None:
            self._points.append(candidates[choice])
            self._refresh()
            self._table.show_index(len(self._points) - 1)

    def _rename(self) -> None:
        index = self._table.selected_index()
        if index is None:
            return
        key = self._points[index]
        value, accepted = QInputDialog.getText(
            self, "Название точки", "Название для результата сверки", text=self._point_names.get(key, ""),
        )
        if not accepted:
            return
        value = value.strip()
        if len(value) > 256:
            self._error.setText("Название точки должно содержать не больше 256 символов.")
            return
        if value:
            self._point_names[key] = value
        else:
            self._point_names.pop(key, None)
        self._error.clear()
        self._refresh()
        self._table.show_index(index)

    def _remove(self) -> None:
        index = self._table.selected_index()
        if index is not None:
            self._point_names.pop(self._points.pop(index), None)
            self._refresh()

    def _save(self) -> None:
        identifier, name = self._id.text().strip(), self._name.text().strip()
        if not identifier or not name or len(self._points) < 2:
            self._error.setText("Укажите ID, название и минимум две точки проверки.")
            return
        if identifier in self._unavailable_ids:
            self._error.setText("Такой ID уже используется другим ограничением или требованием.")
            return
        try:
            self.value = MatrixBoundaryGroup(
                group_id=identifier, name=name, scope_id=self._scope, boundary_ids=tuple(self._points),
                point_names=dict(self._point_names),
            )
        except ValueError:
            self._error.setText("Проверьте ID, название и выбранные точки.")
            return
        self.accept()
