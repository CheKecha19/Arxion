"""Выбор снимка и подтверждение адресов для источника сверки."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from threading import Event
from typing import TYPE_CHECKING, cast

from PySide6.QtCore import QModelIndex, QSortFilterProxyModel, QStringListModel, Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit,
    QListView, QPlainTextEdit, QVBoxLayout, QWidget,
)

from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.resource_registry import resource_address_binding

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.matrix_policy_catalog import MatrixDraftSourceChoice, MatrixPolicyChoice


class _PolicySearch(QSortFilterProxyModel):
    haystacks: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()

    def filterAcceptsRow(self, source_row: int, _source_parent: QModelIndex) -> bool:
        return 0 <= source_row < len(self.haystacks) and all(
            term in self.haystacks[source_row] for term in self.terms
        )

    def query(self, value: str) -> None:
        self.terms = tuple(value.casefold().split())
        self.invalidateFilter()


def select_saved_matrix_policy(
    parent: QWidget, runner: JobRunner, load: Callable[[Callable[[], bool]], tuple[MatrixPolicyChoice, ...]],
    *, current: str = "",
) -> str | None:
    choice = _select_saved_policy(
        parent, runner, load, current=current, title="Политики сохранённых снимков",
        empty="В последних снимках области нет доступных политик. ID можно указать вручную.",
        hint="Если ID повторяется, источник выбирается при сверке области.",
    )
    return choice.policy_id if choice is not None else None


def select_saved_matrix_draft_source(
    parent: QWidget, runner: JobRunner, load: Callable[[Callable[[], bool]], tuple[MatrixDraftSourceChoice, ...]],
) -> MatrixDraftSourceChoice | None:
    return _select_saved_policy(
        parent, runner, load, title="Политика для черновика",
        empty="В последних снимках области нет доступных политик. Загрузите конфигурации или выполните сбор.",
        hint="Выберите политику на нужном устройстве или облачном ресурсе.",
        preselect_single=True,
    )


def _select_saved_policy[Choice: (MatrixPolicyChoice, MatrixDraftSourceChoice)](
    parent: QWidget, runner: JobRunner, load: Callable[[Callable[[], bool]], tuple[Choice, ...]],
    *, title: str, empty: str, hint: str, current: str = "", preselect_single: bool = False,
) -> Choice | None:
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.resize(760, 500)
    layout = QVBoxLayout(dialog)
    search = QLineEdit()
    search.setPlaceholderText("ID политики, устройство, зона или облачный ресурс")
    search.setAccessibleName("Поиск сохранённой политики")
    search.setClearButtonEnabled(True)
    search.setEnabled(False)
    layout.addWidget(search)
    status = QLabel("Читаем политики выбранной области…")
    status.setWordWrap(True)
    layout.addWidget(status)
    model = QStringListModel(dialog)
    proxy = _PolicySearch(dialog)
    proxy.setSourceModel(model)
    view = QListView()
    view.setUniformItemSizes(True)
    view.setModel(proxy)
    view.setAccessibleName(title)
    layout.addWidget(view, 1)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    layout.addWidget(buttons)
    accept = buttons.button(QDialogButtonBox.StandardButton.Ok)
    accept.setText("Выбрать политику")
    accept.setEnabled(False)
    accept.setAutoDefault(False)
    buttons.button(QDialogButtonBox.StandardButton.Cancel).setAutoDefault(False)
    buttons.rejected.connect(dialog.reject)
    view.selectionModel().currentChanged.connect(lambda index, _: accept.setEnabled(index.isValid()))
    search_timer = QTimer(dialog)
    search_timer.setSingleShot(True)
    search_timer.setInterval(120)

    def filter_choices() -> None:
        search_timer.stop()
        proxy.query(search.text())
        accept.setEnabled(view.currentIndex().isValid())

    def choose() -> None:
        if search_timer.isActive():
            filter_choices()
        if view.currentIndex().isValid():
            dialog.accept()

    buttons.accepted.connect(choose)
    view.doubleClicked.connect(lambda index: choose() if index.isValid() else None)
    search_timer.timeout.connect(filter_choices)
    search.textChanged.connect(lambda _: search_timer.start())
    search.returnPressed.connect(choose if preselect_single else filter_choices)
    cancelled = Event()
    choices: tuple[Choice, ...] = ()

    def done(value: object) -> None:
        nonlocal choices
        if cancelled.is_set():
            return
        if isinstance(value, JobError):
            status.setText(value.message)
            return
        if not isinstance(value, tuple) or not value:
            status.setText(empty)
            return
        choices = cast(tuple[Choice, ...], value)
        proxy.haystacks = tuple((choice.search or choice.label).casefold() for choice in choices)
        model.setStringList([choice.label for choice in choices])
        index = next((index for index, choice in enumerate(choices) if choice.policy_id == current), None)
        if index is None and preselect_single and len(choices) == 1:
            index = 0
        if index is not None:
            view.setCurrentIndex(proxy.mapFromSource(model.index(index, 0)))
        search.setEnabled(True)
        search.setFocus()
        status.setText(f"Вариантов: {len(choices)}. {hint}")

    runner.submit(lambda: load(cancelled.is_set), done)
    accepted = dialog.exec() == QDialog.DialogCode.Accepted
    cancelled.set()
    index = proxy.mapToSource(view.currentIndex())
    result = choices[index.row()] if accepted and index.isValid() else None
    dialog.deleteLater()
    return result


def select_matrix_input(
    parent: QWidget, choices: list[str], *, title: str = "Данные для сверки матрицы",
    placeholder: str = "Поиск по устройству, платформе или времени",
) -> int | None:
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.resize(690, 420)
    layout = QVBoxLayout(dialog)
    search = QLineEdit(dialog)
    search.setPlaceholderText(placeholder)
    search.setAccessibleName(placeholder)
    layout.addWidget(search)
    model = QStringListModel(choices, dialog)
    proxy = QSortFilterProxyModel(dialog)
    proxy.setSourceModel(model)
    proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    view = QListView(dialog)
    view.setModel(proxy)
    view.setAccessibleName(title)
    layout.addWidget(view, 1)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    layout.addWidget(buttons)
    accept = buttons.button(QDialogButtonBox.StandardButton.Ok)
    view.selectionModel().currentChanged.connect(lambda index, _: accept.setEnabled(index.isValid()))

    def filter_choices(value: str) -> None:
        proxy.setFilterFixedString(value)
        view.setCurrentIndex(proxy.index(0, 0))
        accept.setEnabled(view.currentIndex().isValid())

    search.textChanged.connect(filter_choices)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    view.doubleClicked.connect(lambda _: dialog.accept())
    filter_choices("")
    if dialog.exec() != QDialog.DialogCode.Accepted or not view.currentIndex().isValid():
        return None
    return proxy.mapToSource(view.currentIndex()).row()


def edit_matrix_source_binding(
    parent: QWidget, *, device_label: str, resources: Sequence[tuple[str, str]],
    sites: Sequence[tuple[str, str]], existing: Mapping[tuple[str, str], tuple[str, ...]],
    suggested: Mapping[tuple[str, str], tuple[str, ...]],
) -> tuple[str, str, tuple[str, ...]] | None:
    """Выбрать одну привязку ресурса и подтвердить её адреса."""
    if not resources or not sites:
        return None
    dialog = QDialog(parent)
    dialog.setWindowTitle("Адреса ресурса для источника сверки")
    dialog.resize(650, 490 if len(resources) > 1 else 360)
    layout = QVBoxLayout(dialog)
    source = QLabel(device_label)
    source.setTextFormat(Qt.TextFormat.PlainText)
    source.setWordWrap(True)
    source.setAccessibleName("Источник сверки")
    layout.addWidget(source)

    form = QFormLayout()
    layout.addLayout(form)
    search: QLineEdit | None = None
    if len(resources) == 1:
        resource = QLabel(resources[0][1])
        resource.setTextFormat(Qt.TextFormat.PlainText)
        resource.setWordWrap(True)
        form.addRow("Ресурс", resource)
        resource_view = None
        proxy = None
    else:
        search = QLineEdit()
        search.setPlaceholderText("Имя или ID ресурса")
        search.setAccessibleName("Поиск ресурса")
        search.setClearButtonEnabled(True)
        model = QStringListModel([f"{name} · {identifier}" for identifier, name in resources], dialog)
        proxy = QSortFilterProxyModel(dialog)
        proxy.setSourceModel(model)
        proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        resource_view = QListView()
        resource_view.setModel(proxy)
        resource_view.setAccessibleName("Ресурс для привязки")
        resource_view.setMinimumHeight(110)
        form.addRow("Ресурс", search)
        form.addRow(resource_view)

    site = QComboBox()
    site.setAccessibleName("Площадка ресурса")
    for identifier, name in sites:
        site.addItem(name, identifier)
    site.setEnabled(len(sites) > 1)
    if len(sites) > 1:
        site.setPlaceholderText("Выберите площадку")
        site.setCurrentIndex(-1)
    form.addRow("Площадка", site)

    addresses = QPlainTextEdit()
    addresses.setAccessibleName("Подтверждённые адреса для источника сверки")
    addresses.setPlaceholderText("IP-адрес или CIDR на каждой строке")
    form.addRow("IP-адреса и CIDR", addresses)
    hint = QLabel("Сверьте адреса с тем, как ресурс представлен в выбранной политике.")
    hint.setWordWrap(True)
    layout.addWidget(hint)
    status = QLabel()
    status.setTextFormat(Qt.TextFormat.PlainText)
    status.setWordWrap(True)
    layout.addWidget(status)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
    layout.addWidget(buttons)
    save = buttons.button(QDialogButtonBox.StandardButton.Save)

    active_key: tuple[str, str] | None = None
    drafts: dict[tuple[str, str], str] = {}
    result: tuple[str, str, tuple[str, ...]] | None = None

    def update_save() -> None:
        has_addresses = bool(addresses.toPlainText().strip())
        can_remove = active_key is not None and bool(existing.get(active_key))
        save.setText("Удалить адреса" if can_remove and not has_addresses else "Сохранить")
        save.setEnabled(active_key is not None and (has_addresses or can_remove))
        status.clear()

    def update_selection() -> None:
        nonlocal active_key
        index = 0
        if resource_view is not None and proxy is not None:
            index = proxy.mapToSource(resource_view.currentIndex()).row()
        site_id = site.currentData()
        key = (resources[index][0], site_id) if index >= 0 and isinstance(site_id, str) else None
        if key != active_key:
            if active_key is not None:
                drafts[active_key] = addresses.toPlainText()
            active_key = key
            prefixes = existing.get(key, suggested.get(key, ())) if key is not None else ()
            addresses.setPlainText(drafts.get(key, "\n".join(prefixes)) if key is not None else "")
        addresses.setEnabled(key is not None)
        update_save()

    def commit() -> None:
        nonlocal result
        if active_key is None:
            return
        resource_id, site_id = active_key
        values = [line for line in addresses.toPlainText().splitlines() if line.strip()]
        try:
            binding = resource_address_binding({"site_id": site_id, "prefixes": values}) if values else None
        except ValueError as error:
            status.setText(str(error))
            return
        prefixes = tuple(binding["prefixes"]) if binding is not None else ()
        if prefixes or existing.get(active_key):
            result = resource_id, site_id, prefixes
            dialog.accept()

    def filter_resources(query: str) -> None:
        if resource_view is None or proxy is None:
            return
        proxy.setFilterFixedString(query)
        if proxy.rowCount() == 1:
            resource_view.setCurrentIndex(proxy.index(0, 0))
        update_selection()

    if resource_view is not None:
        resource_view.selectionModel().currentChanged.connect(update_selection)
    if search is not None:
        search.textChanged.connect(filter_resources)
    site.currentIndexChanged.connect(update_selection)
    addresses.textChanged.connect(update_save)
    buttons.accepted.connect(commit)
    buttons.rejected.connect(dialog.reject)
    update_selection()
    if search is not None:
        search.setFocus()
    elif active_key is not None:
        addresses.setFocus()
    else:
        site.setFocus()
    dialog.exec()
    return result
