"""Manage reusable file selections without reading their configuration contents."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.interfaces.desktop.file_sources import (
    FileSource,
    SavedFileSources,
    file_path_key,
)
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner


class FileSourceEditor(QDialog):
    def __init__(
        self,
        parent: QWidget,
        *,
        kind: Literal["files", "directory"],
        source: FileSource | None = None,
        paths: Sequence[Path] = (),
        device_ids: dict[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.kind = kind
        self.source = source
        self.value: FileSource | None = None
        self.device_ids = dict(source.device_ids if source else device_ids or {})
        self.setWindowTitle("Папка конфигураций" if kind == "directory" else "Набор конфигураций")
        self.resize(620, 380)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.label = QLineEdit(source.label if source else "")
        self.enabled = QCheckBox("Включать в «Обновить и проверить»")
        self.enabled.setChecked(source.enabled if source else True)
        form.addRow("Название", self.label)
        form.addRow(self.enabled)
        layout.addLayout(form)
        layout.addWidget(QLabel(
            "Содержимое папки проверяется при каждом запуске, без вложенных папок."
            if kind == "directory"
            else "Сохраняются пути; при запуске читается текущее содержимое файлов."
        ))
        self.paths = QListWidget()
        layout.addWidget(self.paths)
        self.paths.addItems(list(source.paths if source else (str(path) for path in paths)))
        actions = QHBoxLayout()
        choose = QPushButton("Выбрать папку…" if kind == "directory" else "Добавить файлы…")
        choose.clicked.connect(self._choose)
        actions.addWidget(choose)
        if kind == "files":
            remove = QPushButton("Исключить выбранный")
            remove.clicked.connect(self._remove)
            bind = QPushButton("Связать с устройством…")
            bind.clicked.connect(self._bind)
            actions.addWidget(remove)
            actions.addWidget(bind)
        layout.addLayout(actions)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept_source)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _choose(self) -> None:
        if self.kind == "directory":
            path = QFileDialog.getExistingDirectory(self, "Папка конфигураций")
            if path:
                self.paths.clear()
                self.paths.addItem(str(Path(path)))
                if not self.label.text():
                    self.label.setText(Path(path).name)
            return
        selected, _ = QFileDialog.getOpenFileNames(
            self, "Конфигурации", "",
            "Конфигурации (*.txt *.cfg *.conf *.config *.json);;Все файлы (*)",
        )
        existing = {file_path_key(Path(self.paths.item(i).text())) for i in range(self.paths.count())}
        for name in selected:
            key = file_path_key(Path(name))
            if key not in existing:
                existing.add(key)
                self.paths.addItem(str(Path(name)))

    def _remove(self) -> None:
        row = self.paths.currentRow()
        if row >= 0:
            self.device_ids.pop(self.paths.item(row).text(), None)
            self.paths.takeItem(row)

    def _bind(self) -> None:
        selected = self.paths.currentItem()
        if selected is None:
            return
        path = selected.text()
        value, accepted = QInputDialog.getText(
            self, "Связь с устройством",
            "Введите существующий идентификатор устройства. Пустое поле сбрасывает привязку.",
            text=self.device_ids.get(path, ""),
        )
        if accepted:
            if value.strip():
                self.device_ids[path] = value.strip()
            else:
                self.device_ids.pop(path, None)

    def _accept_source(self) -> None:
        paths = tuple(self.paths.item(i).text() for i in range(self.paths.count()))
        values = {
            "label": self.label.text().strip(), "kind": self.kind,
            "paths": paths, "enabled": self.enabled.isChecked(),
            "device_ids": {path: name for path, name in self.device_ids.items() if path in paths},
        }
        if self.source is not None:
            values["source_id"] = self.source.source_id
        try:
            self.value = FileSource.model_validate(values)
        except ValueError:
            self.status.setText("Укажите название и выберите папку или файлы.")
            return
        self.accept()


class FileSourcesDialog(QDialog):
    def __init__(
        self,
        sources: SavedFileSources,
        runner: JobRunner,
        project_id: str,
        context_valid: Callable[[], bool],
        parent: QWidget,
        *,
        staged: Sequence[tuple[Path, str | None]] = (),
    ) -> None:
        super().__init__(parent)
        self.sources = sources
        self.runner = runner
        self.project_id = project_id
        self.context_valid = context_valid
        self.staged = tuple(staged)
        self.rows: tuple[FileSource, ...] = ()
        self.closed = False
        self.changed = False
        self.saving = False
        self.setWindowTitle("Сохранённые файловые источники")
        self.resize(680, 360)
        layout = QVBoxLayout(self)
        explanation = QLabel(
            "Наборы сохраняются в текущем проекте. Назначьте их через «Площадки», "
            "затем используйте «Обновить и проверить»."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(lambda _item: self._edit_selected())
        layout.addWidget(self.list)
        row = QHBoxLayout()
        self.add_files = QPushButton("Новый набор…")
        self.add_files.clicked.connect(lambda: self._edit("files"))
        self.add_directory = QPushButton("Новая папка…")
        self.add_directory.clicked.connect(lambda: self._edit("directory"))
        self.edit = QPushButton("Изменить…")
        self.edit.clicked.connect(self._edit_selected)
        self.from_stage = QPushButton("Сохранить подготовленные…")
        self.from_stage.clicked.connect(lambda: self._edit("files", staged=True))
        for button in (self.add_files, self.add_directory, self.edit, self.from_stage):
            row.addWidget(button)
        layout.addLayout(row)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self.close_button = buttons.button(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.finished.connect(self._finish)
        self._load()

    def _finish(self, _code: int) -> None:
        self.closed = True

    def reject(self) -> None:
        if not self.saving:
            super().reject()

    def _load(self, previous: FileSource | None = None, value: FileSource | None = None) -> None:
        for widget in (self.list, self.add_files, self.add_directory, self.edit, self.from_stage):
            widget.setEnabled(False)
        self.close_button.setEnabled(value is None)
        self.saving = value is not None
        self.status.setText("Сохранение…" if value is not None else "Чтение источников…")

        def work() -> tuple[FileSource, ...]:
            if value is not None:
                self.sources.save(self.project_id, value, previous=previous)
            return self.sources.list(self.project_id)

        def done(result: object) -> None:
            self.saving = False
            if self.closed or not self.context_valid():
                return
            self.close_button.setEnabled(True)
            self.list.setEnabled(True)
            self.add_files.setEnabled(True)
            self.add_directory.setEnabled(True)
            self.edit.setEnabled(bool(self.rows))
            self.from_stage.setEnabled(bool(self.staged))
            if isinstance(result, JobError) or not isinstance(result, tuple):
                self.status.setText("Не удалось обновить список. Закройте и снова откройте окно.")
                return
            self.changed |= value is not None
            self.rows = result
            self.list.clear()
            for index, source in enumerate(self.rows):
                description = source.paths[0] if source.kind == "directory" else f"Файлов: {len(source.paths)}"
                state = " · выключен" if not source.enabled else ""
                self.list.addItem(f"{source.label} · {description}{state}")
                if value is not None and value.source_id == source.source_id:
                    self.list.setCurrentRow(index)
            if self.rows and self.list.currentRow() < 0:
                self.list.setCurrentRow(0)
            self.edit.setEnabled(bool(self.rows))
            self.status.setText(
                f"Источников в проекте: {len(self.rows)}" if self.rows
                else "Нет сохранённых источников. Добавьте набор файлов или папку."
            )

        self.runner.submit(work, done)

    def _edit_selected(self) -> None:
        row = self.list.currentRow()
        if 0 <= row < len(self.rows):
            source = self.rows[row]
            self._edit(source.kind, source)

    def _edit(
        self, kind: Literal["files", "directory"], source: FileSource | None = None,
        *, staged: bool = False,
    ) -> None:
        initial = self.staged if staged else ()
        editor = FileSourceEditor(
            self, kind=kind, source=source, paths=tuple(path for path, _ in initial),
            device_ids={str(path): name for path, name in initial if name},
        )
        if editor.exec() and editor.value is not None and self.context_valid():
            self._load(source, editor.value)
