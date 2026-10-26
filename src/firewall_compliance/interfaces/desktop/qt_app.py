"""Qt рабочее место: проекты, пакетный анализ и доказательная сводка."""

from __future__ import annotations

import gc
import html
import json
import re
import sqlite3
import sys
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QCoreApplication,
    QEvent,
    QItemSelectionModel,
    QModelIndex,
    QPersistentModelIndex,
    QSize,
    QSortFilterProxyModel,
    Qt,
    QTimer,
)
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence, QTextOption
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLayout,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTabBar,
    QTableView,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.analysis.management_checks import MANAGEMENT_CHECKS
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.interfaces.desktop.backend import (
    AnalysisSession,
    analyze_file,
    reanalyze_session,
    source_preview,
)
from firewall_compliance.interfaces.desktop.check_presentation import (
    check_execution_status,
    check_status_label,
)
from firewall_compliance.interfaces.desktop.cloud_panel import (
    ALL_RESOURCES,
    SCAN_STATES,
    CloudPanel,
)
from firewall_compliance.interfaces.desktop.cloud_rule_presentation import (
    cloud_rule_columns,
    cloud_rule_details,
    cloud_rule_values,
)
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner, JobStatus
from firewall_compliance.interfaces.desktop.management_settings import ManagementSettings
from firewall_compliance.interfaces.desktop.map_network_facts import (
    MapFactsOwner,
    MapNetworkFacts,
    bind_map_facts_owner,
    owner_matches,
    owner_reference,
)
from firewall_compliance.interfaces.desktop.map_store import (
    read_map_network_facts,
    write_map_network_facts,
)
from firewall_compliance.interfaces.desktop.object_presentation import (
    object_details,
    object_summary,
    rule_details,
    rule_endpoint_summary,
    rule_service_summary,
)
from firewall_compliance.interfaces.desktop.organization_lock import WorkspaceBusyError
from firewall_compliance.interfaces.desktop.project_map import build_project_map
from firewall_compliance.interfaces.desktop.qt_acl_map import (
    AclMapState,
    AclMapWidget,
    build_map_state,
)
from firewall_compliance.interfaces.desktop.qt_models import RowsModel
from firewall_compliance.interfaces.desktop.qt_network import NetworkFactsSnapshot
from firewall_compliance.interfaces.desktop.qt_project_map import ProjectMapWidget
from firewall_compliance.interfaces.desktop.qt_theme import apply_theme
from firewall_compliance.interfaces.desktop.qt_topology_map import TopologyMapWidget
from firewall_compliance.interfaces.desktop.resource_details import ResourceDetails
from firewall_compliance.interfaces.desktop.result_presentation import (
    check_limitations,
    finding_limitations,
    group_summary,
    project_item_limitations,
)
from firewall_compliance.interfaces.desktop.topology_map import build_topology_projection
from firewall_compliance.interfaces.desktop.workspace_history import WorkspaceHistory
from firewall_compliance.interfaces.desktop.workspace_models import (
    cloud_resources,
    project_operations,
)
from firewall_compliance.interfaces.desktop.workspace_navigation import (
    WORKSPACE_SECTIONS,
    section_for_page,
)
from firewall_compliance.parsers import ParseFailure
from firewall_compliance.parsers.catalog import create_default_registry


class _MapModeStack(QStackedWidget):
    """Size the map for its active mode, including on small windows."""

    def minimumSizeHint(self) -> QSize:
        current = self.currentWidget()
        return current.minimumSizeHint() if current is not None else super().minimumSizeHint()

    def sizeHint(self) -> QSize:
        current = self.currentWidget()
        return current.sizeHint() if current is not None else super().sizeHint()


SECTIONS = (
    "Главная",
    "Находки",
    "Устройства",
    "Правила и объекты",
    "История проверок",
    "Отчёты",
    "Расширенный анализ",
    "Карта",
    "Настройки",
    "Сканирования",
    "Файлы и проверки",
)
SECTION_IDS = (
    "home",
    "findings",
    "devices",
    "rules",
    "history",
    "reports",
    "advanced",
    "map",
    "settings",
    "scans",
    "staging",
)
STATUSES = {
    "new": "Новая",
    "confirmed": "Подтверждена",
    "in_progress": "В работе",
    "accepted_risk": "Риск принят",
    "false_positive": "Ложное срабатывание",
    "resolved": "Устранена (решение пользователя)",
}
SEVERITIES = {
    "critical": "Критическая",
    "high": "Высокая",
    "medium": "Средняя",
    "low": "Низкая",
    "info": "Информационная",
}
IMPORT_STATES = {
    "complete": "В границах проверок",
    "partial": "Частично",
    "failed": "Не обработан",
    "error": "Ошибка",
    "canceled": "Отменён",
    "unsupported": "Не поддерживается",
    "success": "Обработан",
}
CHECKS = {
    "FW-ANY-ANY": "Доступ any → any",
    "FW-DUPLICATE": "Дубликаты",
    "FW-SHADOWED": "Перекрытия",
    "FW-MERGE-CANDIDATE": "Кандидаты объединения",
    "FW-LOGGING": "Логирование",
    "FW-COMMENTS": "Комментарии",
    "FW-DISABLED": "Отключённые правила",
    **{key: values[1] for key, values in MANAGEMENT_CHECKS.items()},
}


def _check_count(check: dict[str, Any]) -> str:
    status = check_execution_status(check)
    count = len(check.get("findings", []))
    if status in {"not_executed", "not_applicable"}:
        return "—"
    return f"{count} в проверенной части" if status == "partial" else str(count)


def _fields_html(fields: Sequence[tuple[str, str]]) -> str:
    return (
        "<table cellpadding='6'>"
        + "".join(
            f"<tr><th align='left'>{html.escape(label)}</th>"
            f"<td>{html.escape(value).replace(chr(10), '<br>')}</td></tr>"
            for label, value in fields
        )
        + "</table>"
    )


class PayloadSearchProxy(QSortFilterProxyModel):
    """Искать полный состав и имя источника, не возвращая их в колонки."""

    def filterAcceptsRow(
        self, source_row: int, source_parent: QModelIndex | QPersistentModelIndex
    ) -> bool:
        if super().filterAcceptsRow(source_row, source_parent):
            return True
        model = self.sourceModel()
        if not isinstance(model, RowsModel) or source_row >= len(model.payloads):
            return False
        payload = model.payloads[source_row]
        if not isinstance(payload, dict):
            return False
        text = str(payload.get("search_text") or payload.get("source_name") or "")
        return self.filterRegularExpression().match(text).hasMatch()


def _label(text: str, *, muted: bool = False, heading: bool = False) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    if muted:
        label.setObjectName("muted")
    elif heading:
        label.setObjectName("heading")
    return label


def _button(text: str, callback: Callable[..., Any], *, primary: bool = False) -> QPushButton:
    button = QPushButton(text)
    if primary:
        button.setObjectName("primary")
    button.clicked.connect(callback)
    return button


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def inspect_file(path: Path) -> dict[str, Any]:
    """Распознать документ в фоновом потоке до запуска проверок."""
    source = FileSourceReader().read(path)
    registry = create_default_registry()
    parser = registry.select(source)
    hostname = re.search(
        r"(?mi)^\s*(?:hostname|sysname)\s+([^\s]+)",
        source.content.decode("utf-8", errors="replace"),
    )
    return {
        "parser": parser.metadata.parser_id if parser else "Не распознан",
        "warning": (
            "Предварительное определение; полнота будет известна после анализа"
            if parser
            else "Подходящий парсер не найден"
        ),
        "hostname": hostname.group(1) if hostname else "",
        "sha256": source.content_sha256,
    }


class MainWindow(QMainWindow):
    """Главное окно; backend callbacks доставляются таймером в GUI-потоке."""

    def __init__(
        self,
        store: Any = None,
        *,
        advanced_widget_factory: Callable[
            [Callable[[], tuple[AnalysisSession, ...]], JobRunner], QWidget
        ]
        | None = None,
    ) -> None:
        super().__init__()
        if store is None:
            from firewall_compliance.interfaces.desktop.project_store import ProjectStore

            store = ProjectStore()
        self.store = store
        self.runner = JobRunner()
        self.project_id: str | None = None
        self.run_id: str | None = None
        self.run: dict[str, Any] | None = None
        self.sessions: dict[str, AnalysisSession] = {}
        self._map_live_item_ids: set[str] = set()
        self.staged: list[dict[str, Any]] = []
        self._preflight_jobs: set[Any] = set()
        self._analysis_jobs: dict[Any, dict[str, Any]] = {}
        self._batch_active = False
        self._batch_cancelled = False
        self._restore_busy = False
        self._aux_run_id: str | None = None
        self._closed = False
        self._finding_payloads: list[dict[str, Any]] = []
        self._loading_settings = False
        self.current_section_id = "home"
        self._completed_run_id: str | None = None
        self.workspace_history = WorkspaceHistory(self)
        self.resource_details = ResourceDetails(self)
        self.setWindowTitle("Firewall Compliance — рабочее место аналитика")
        self.resize(1600, 940)
        self.setMinimumSize(1000, 650)
        screen = QApplication.primaryScreen()
        if screen is not None:
            available = screen.availableGeometry()
            self.resize(min(1600, available.width() - 40), min(940, available.height() - 60))
        self._build(advanced_widget_factory)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_jobs)
        self.timer.start(80)
        self.refresh_projects()

    def _build(self, advanced_factory: Any) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 16, 20, 12)
        header = QHBoxLayout()
        brand = _label("Firewall Compliance")
        brand.setObjectName("heading")
        header.addWidget(brand)
        header.addStretch()
        header.addWidget(_label("Проект"))
        self.project_combo = QComboBox()
        self.project_combo.setObjectName("projectSelector")
        self.project_combo.setMinimumWidth(230)
        self.project_combo.currentIndexChanged.connect(self._project_changed)
        header.addWidget(self.project_combo)
        self.create_button = _button("Новый проект", self._create_project_dialog)
        header.addWidget(self.create_button)
        self.add_data_button = _button("Добавить данные", self.choose_data_source, primary=True)
        header.addWidget(self.add_data_button)
        self.prepare_button = _button("Запустить проверку", lambda: self.navigate("staging"))
        header.addWidget(self.prepare_button)
        self.run_button = _button("Запустить проверку файлов", self.start_analysis, primary=True)
        self.run_button.setEnabled(False)
        root.addLayout(header)
        body = QHBoxLayout()
        sidebar = QWidget()
        sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        self.navigation = QTreeWidget()
        self.navigation.setObjectName("navigation")
        self.navigation.setHeaderHidden(True)
        self.navigation.setRootIsDecorated(False)
        self.navigation.setIndentation(18)
        self.navigation.setExpandsOnDoubleClick(False)
        self.navigation.setAccessibleName("Разделы приложения")
        self.nav_items: dict[str, QTreeWidgetItem] = {}
        for section in WORKSPACE_SECTIONS:
            item = QTreeWidgetItem(self.navigation, [section.title])
            item.setData(0, Qt.ItemDataRole.UserRole, section.key)
            for page_id, _title in section.pages:
                self.nav_items[page_id] = item
        self.navigation.currentItemChanged.connect(self._navigation_changed)
        self.navigation.itemClicked.connect(self._navigation_clicked)
        sidebar_layout.addWidget(self.navigation, 1)
        self.settings_button = _button("Настройки", lambda: self.navigate("settings"))
        self.settings_button.setCheckable(True)
        sidebar_layout.addWidget(self.settings_button)
        body.addWidget(sidebar)
        content = QVBoxLayout()
        context_row = QHBoxLayout()
        self.back_button = _button("← Назад", self.workspace_history.back)
        self.back_button.setEnabled(False)
        self.back_button.setMaximumWidth(110)
        context_row.addWidget(self.back_button)
        self.context_label = _label("Выберите или создайте проект.", muted=True)
        context_row.addWidget(self.context_label, 1)
        content.addLayout(context_row)
        self.section_tabs = QTabBar()
        self.section_tabs.setExpanding(False)
        self.section_tabs.setAccessibleName("Вкладки раздела")
        self.section_tabs.currentChanged.connect(self._section_tab_changed)
        content.addWidget(self.section_tabs)
        self.pages = QStackedWidget()
        content.addWidget(self.pages, 1)
        body.addLayout(content, 1)
        root.addLayout(body, 1)
        self._build_summary()
        self._build_findings()
        self._build_devices()
        self._build_rules()
        self._build_history()
        self._build_reports()
        if advanced_factory is None:
            from firewall_compliance.interfaces.desktop.qt_network import create_widget

            advanced_factory = create_widget
        self.advanced_panel = advanced_factory(lambda: tuple(self.sessions.values()), self.runner)
        self.pages.addWidget(self.advanced_panel)
        self._build_map()
        self.cloud_panel = CloudPanel(self.store, self)
        self.cloud_panel.configure_button.clicked.connect(self._configure_cloud)
        self._build_settings()
        self.pages.addWidget(self.cloud_panel.scans_widget)
        self._build_preparation()
        self.cloud_panel.on_history_changed = self._cloud_history_changed
        self.notification = QFrame()
        notification_row = QHBoxLayout(self.notification)
        self.notification_label = _label("")
        notification_row.addWidget(self.notification_label, 1)
        self.notification_button = _button("Открыть результат", self.open_completed_result)
        notification_row.addWidget(self.notification_button)
        notification_row.addWidget(_button("Закрыть", self.notification.hide))
        root.addWidget(self.notification)
        self.notification.hide()
        footer = QHBoxLayout()
        self.progress_label = _label(
            "Выберите или создайте проект, затем добавьте конфигурации.", muted=True
        )
        footer.addWidget(self.progress_label, 1)
        self.progress = QProgressBar()
        self.progress.setObjectName("batchProgress")
        self.progress.setFixedWidth(250)
        self.progress.hide()
        footer.addWidget(self.progress)
        self.cancel_button = _button("Отменить ожидающие", self.cancel_pending)
        self.cancel_button.setEnabled(False)
        footer.addWidget(self.cancel_button)
        root.addLayout(footer)
        self.workspace_history.ready = True
        self.navigate("home")
        for shortcut, callback in (
            ("Ctrl+O", self.choose_files),
            ("Ctrl+Shift+O", self.choose_folder),
            ("Alt+Left", self.workspace_history.back),
        ):
            action = QAction(self)
            action.setShortcut(QKeySequence(shortcut))
            action.triggered.connect(callback)
            self.addAction(action)

    def _page(self, title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 0, 0, 0)
        heading = _label(title)
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(_label(subtitle, muted=True))
        self.pages.addWidget(page)
        return page, layout

    def _table(
        self, headers: Sequence[str], name: str, *, search_payload: bool = False
    ) -> tuple[QTableView, RowsModel, QSortFilterProxyModel]:
        model = RowsModel(headers)
        proxy = PayloadSearchProxy(self) if search_payload else QSortFilterProxyModel(self)
        proxy.setSourceModel(model)
        proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        proxy.setFilterKeyColumn(-1)
        proxy.setSortRole(Qt.ItemDataRole.UserRole)
        table = QTableView()
        model.setParent(table)
        table.setObjectName(name)
        table.setModel(proxy)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(38)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        for column in range(len(headers)):
            table.setColumnWidth(column, 180 if column else 210)
        return table, model, proxy

    def _build_summary(self) -> None:
        _, outer_layout = self._page(
            "Обзор", "Инфраструктура проекта, охват данных и результаты последней проверки."
        )
        dashboard = QWidget()
        layout = QVBoxLayout(dashboard)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        self.overview_scroll = QScrollArea()
        self.overview_scroll.setWidgetResizable(True)
        self.overview_scroll.setWidget(dashboard)
        outer_layout.addWidget(self.overview_scroll, 1)
        hero = QFrame()
        hero.setObjectName("hero")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        self.device_count_label = _label("Устройств проекта: 0")
        self.device_count_label.setStyleSheet("font-size: 24px; font-weight: 600;")
        hero_layout.addWidget(self.device_count_label)
        self.last_check_label = _label("Последняя проверка: ещё не выполнялась")
        hero_layout.addWidget(self.last_check_label)
        self.summary_label = _label("Добавьте конфигурации в разделе «Устройства».")
        hero_layout.addWidget(self.summary_label)
        self.cloud_summary_label = _label("Облачных ресурсов: 0", muted=True)
        hero_layout.addWidget(self.cloud_summary_label)
        overview_actions = QHBoxLayout()
        overview_actions.addWidget(_button("Открыть инфраструктуру", self.open_overview_resources))
        overview_actions.addWidget(
            _button("Проблемы последней проверки", self.open_overview_findings)
        )
        overview_actions.addWidget(_button("Все операции", lambda: self.navigate("history")))
        hero_layout.addLayout(overview_actions)
        layout.addWidget(hero)
        layout.addWidget(_label("Производители · все уникальные устройства проекта", muted=True))
        self.vendor_table, self.vendor_model, self.vendor_proxy = self._table(
            ("Производитель", "Устройства"), "vendorSummary"
        )
        self.vendor_table.setMaximumHeight(230)
        self.vendor_table.setMinimumHeight(145)
        layout.addWidget(self.vendor_table)
        self.coverage_text = QTextBrowser()
        self.coverage_text.setMinimumHeight(140)
        self.coverage_text.setObjectName("coverageSummary")
        self.coverage_text.setOpenLinks(False)
        self.coverage_text.document().setDefaultStyleSheet("a { color: #79B8FF; }")
        self.coverage_text.anchorClicked.connect(
            lambda url: self.open_overview_findings(url.toString())
        )
        layout.addWidget(self.coverage_text, 1)
        self.activity_text = QTextBrowser()
        self.activity_text.setMinimumHeight(100)
        self.activity_text.setMaximumHeight(130)
        self.activity_text.setOpenLinks(False)
        self.activity_text.document().setDefaultStyleSheet("a { color: #79B8FF; }")
        self.activity_text.anchorClicked.connect(lambda _url: self.navigate("history"))
        layout.addWidget(self.activity_text)

    def _build_map(self) -> None:
        _, layout = self._page(
            "Сетевая карта",
            "Все устройства проекта, облачные области и связи по правилам ACL.",
        )
        self._map_items: dict[str, dict[str, Any]] = {}
        self._map_analysis_state = build_map_state(None)
        self._map_selection_identity: tuple[object, ...] | None = None
        self._map_facts_owner: MapFactsOwner | None = None
        self._map_pending_facts_snapshot: NetworkFactsSnapshot | None = None
        self._map_bound_network_facts: MapNetworkFacts | None = None
        self._map_bound_facts_generation: int | None = None
        self._map_facts_message = "Импортируйте сетевые документы в расширенном анализе."
        source_row = QHBoxLayout()
        self.map_result_selector = QComboBox()
        self.map_result_selector.setAccessibleName("Результат анализа для карт выбранной ревизии")
        self.map_result_label = _label("Результат:")
        source_row.addWidget(self.map_result_label)
        source_row.addWidget(self.map_result_selector, 1)
        self.map_mode_selector = QComboBox()
        self.map_mode_selector.setAccessibleName("Режим карты")
        self.map_mode_selector.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.map_mode_selector.addItem("Связи по правилам", "policy")
        self.map_mode_selector.addItem("Топология конфигурации", "topology")
        self.map_mode_selector.addItem("Карта проекта", "project")
        mode_label = _label("Режим:")
        mode_label.setBuddy(self.map_mode_selector)
        source_row.addWidget(mode_label)
        source_row.addWidget(self.map_mode_selector)
        self.map_sources_button = QPushButton("Источники…")
        self.map_sources_button.setCheckable(True)
        source_row.addWidget(self.map_sources_button)
        layout.addLayout(source_row)
        self.map_sources_panel = QWidget(self)
        sources_layout = QVBoxLayout(self.map_sources_panel)
        sources_layout.setContentsMargins(0, 0, 0, 0)
        sources_layout.addWidget(
            _button(
                "Импортировать сетевые документы…",
                lambda: self.navigate("advanced"),
            )
        )
        self.map_attach_network_button = _button(
            "Использовать сетевой импорт для выбранного результата",
            self._attach_map_network_facts,
        )
        self.map_attach_network_button.setEnabled(False)
        sources_layout.addWidget(self.map_attach_network_button)
        archive_actions = QHBoxLayout()
        self.map_save_network_button = _button(
            "Сохранить сетевой снимок…",
            self._save_map_network_facts,
        )
        self.map_open_network_button = _button(
            "Открыть сетевой снимок…",
            self._open_map_network_facts,
        )
        self.map_save_network_button.setEnabled(False)
        self.map_open_network_button.setEnabled(False)
        archive_actions.addWidget(self.map_save_network_button)
        archive_actions.addWidget(self.map_open_network_button)
        archive_actions.addStretch()
        sources_layout.addLayout(archive_actions)
        layout.addWidget(self.map_sources_panel)
        self.map_sources_panel.hide()
        self.map_sources_button.toggled.connect(self.map_sources_panel.setVisible)
        self.map_network_status = _label(self._map_facts_message, muted=True)
        self.map_network_status.setWordWrap(True)
        layout.addWidget(self.map_network_status)
        self.map_widget = AclMapWidget(self)
        self.topology_map_widget = TopologyMapWidget(self)
        self.project_map_widget = ProjectMapWidget(self)
        self.project_map_widget.labels_changed.connect(self._save_map_zone_labels)
        self.map_mode_stack = _MapModeStack(self)
        self.map_mode_stack.currentChanged.connect(self.map_mode_stack.updateGeometry)
        self.map_mode_stack.addWidget(self.map_widget)
        self.map_mode_stack.addWidget(self.topology_map_widget)
        self.map_mode_stack.addWidget(self.project_map_widget)
        layout.addWidget(self.map_mode_stack, 1)
        self.map_mode_selector.currentIndexChanged.connect(self._map_mode_changed)
        self.map_mode_selector.setCurrentIndex(2)
        self.map_result_selector.currentIndexChanged.connect(self._map_result_selected)
        facts_changed = getattr(self.advanced_panel, "facts_changed", None)
        if facts_changed is not None:
            facts_changed.connect(self._map_network_facts_changed)
        sources_layout.addWidget(
            _button(
                "Открыть правила и объекты",
                lambda: self.navigate("rules"),
            )
        )

    def _map_mode_changed(self, index: int) -> None:
        self.map_mode_stack.setCurrentIndex(index)
        project_mode = self.map_mode_selector.currentData() == "project"
        self.map_result_selector.setVisible(not project_mode)
        self.map_result_label.setVisible(not project_mode)
        self.map_sources_button.setVisible(not project_mode)
        self.map_network_status.setVisible(not project_mode)
        self.map_sources_panel.setVisible(not project_mode and self.map_sources_button.isChecked())
        if project_mode:
            self._refresh_project_map()

    def _save_map_zone_labels(self, labels: dict[str, str]) -> None:
        if self.project_id:
            self.store.update_settings(self.project_id, {"map_zone_labels": labels})

    def _refresh_project_map(self) -> None:
        devices = self._project_devices()
        revisions: dict[str, DeviceRevision] = {}
        for item in devices:
            session = self.sessions.get(str(item["id"]))
            if session is not None:
                revisions[str(item["id"])] = session.revision
        imported = getattr(self.advanced_panel, "imported", {})
        for item in devices:
            revision = revisions.get(str(item["id"]))
            if revision is None:
                try:
                    revision = DeviceRevision.model_validate(item.get("revision"))
                except ValueError:
                    continue
                revisions[str(item["id"])] = revision
            if revision is not None:
                network = imported.get(revision.revision_id)
                if network is not None:
                    revisions[str(item["id"])] = network.revision
        project_id = self.project_id or ""
        graph = build_project_map(
            project_id,
            devices,
            cloud_resources(self._cloud_scans()),
            self.store.list_map_integrations(project_id) if project_id else (),
            revisions=revisions,
        )
        labels = (
            self.store.get_project(project_id)["settings"].get("map_zone_labels", {})
            if project_id
            else {}
        )
        self.project_map_widget.set_graph(graph, labels)

    def _refresh_map_items(self, preferred_item: dict[str, Any] | None = None) -> None:
        """Use saved payloads or exact live item IDs, never reread a source."""
        previous_id = self.map_result_selector.currentData()
        items = [] if self._batch_active else self._items()
        self._map_items = {str(item["id"]): item for item in items}
        for item_id in sorted(self._map_live_item_ids):
            session = self.sessions.get(item_id)
            if session is not None:
                self._map_items.setdefault(
                    item_id,
                    {
                        "id": item_id,
                        "run_id": self.run_id,
                        "source_name": Path(session.path).name,
                    },
                )
        if preferred_item is not None and preferred_item.get("id") is not None:
            preferred_id = str(preferred_item["id"])
            self._map_items[preferred_id] = preferred_item
        else:
            preferred_id = previous_id
        previous_block = self.map_result_selector.blockSignals(True)
        try:
            self.map_result_selector.clear()
            self.map_result_selector.addItem("Выберите результат", None)
            for item_id, item in self._map_items.items():
                name = str(item.get("source_name") or item.get("name") or item_id)
                self.map_result_selector.addItem(name, item_id)
            index = self.map_result_selector.findData(preferred_id)
            if index <= 0 and self._map_items:
                index = 1
            self.map_result_selector.setCurrentIndex(max(0, index))
        finally:
            self.map_result_selector.blockSignals(previous_block)
        self._map_result_selected()
        if self.current_section_id == "map" and self.map_mode_selector.currentData() == "project":
            self._refresh_project_map()

    def _clear_map_selection(self) -> None:
        previous_block = self.map_result_selector.blockSignals(True)
        self.map_result_selector.setCurrentIndex(0)
        self.map_result_selector.blockSignals(previous_block)
        self._apply_map_state(build_map_state(None))

    def _apply_map_state(self, state: AclMapState) -> None:
        """Feed both modes from the same verified input, retaining mode choice."""
        self._map_analysis_state = state
        item_id = self.map_result_selector.currentData()
        item = self._map_items.get(item_id) if isinstance(item_id, str) else None
        run_id = item.get("run_id") if item is not None else None
        selection_identity = (
            self.project_id,
            run_id,
            item_id,
            state.revision.revision_id if state.revision is not None else None,
        )
        owner = None
        reason = "Выберите результат с project/run/item ID и исходными документами."
        if (
            state.revision is not None
            and isinstance(self.project_id, str)
            and isinstance(run_id, str)
            and isinstance(item_id, str)
        ):
            try:
                owner = owner_reference(
                    self.project_id,
                    run_id,
                    item_id,
                    state.revision,
                    association="explicit_attachment",
                )
            except ValueError:
                reason = (
                    "Привязка недоступна: отсутствуют полные ID или исходные документы результата."
                )
        if (
            selection_identity != self._map_selection_identity
            or owner != self._map_facts_owner
            or state.revision is None
        ):
            self._clear_map_network_facts()
        self._map_selection_identity = selection_identity
        self._map_facts_owner = owner
        projection = build_topology_projection(state.revision)
        record = self._map_bound_network_facts
        if record is not None and owner is not None and state.revision is not None:
            if owner_matches(
                record,
                owner.project_id,
                owner.run_id,
                owner.item_id,
                state.revision,
            ):
                projection = build_topology_projection(
                    record.network_import,
                    forwarding=record.forwarding,
                )
            else:
                self._clear_map_network_facts()
        if self._map_bound_network_facts is not None:
            bound_owner = self._map_bound_network_facts.owner
            status = (
                "Сетевой импорт подключён вручную · только топология."
                if bound_owner is not None and bound_owner.association == "explicit_attachment"
                else "Сетевой снимок выбранного результата · только топология."
            )
            if self._map_bound_facts_generation is None:
                status += " Открыт из файла."
            status += " Связи по правилам относятся к выбранному результату анализа."
        elif owner is None:
            status = reason
        else:
            status = self._map_facts_message
        self.map_network_status.setText(status)
        self.map_attach_network_button.setEnabled(
            owner is not None and self._map_pending_facts_snapshot is not None,
        )
        self.map_attach_network_button.setToolTip(status)
        self.map_save_network_button.setEnabled(
            owner is not None and self._map_bound_network_facts is not None,
        )
        self.map_open_network_button.setEnabled(owner is not None)
        self.map_open_network_button.setToolTip(
            "Открыть снимок с точной привязкой к выбранному результату."
            if owner is not None
            else reason,
        )
        if state.revision is None:
            projection = replace(projection, limitations=(state.message, *projection.limitations))
        self.map_widget.set_map_state(state)
        self.topology_map_widget.set_projection(projection)

    def _clear_map_network_facts(self) -> None:
        """Invalidate attachment inputs and future overlay identity together."""
        self._map_pending_facts_snapshot = None
        self._map_bound_network_facts = None
        self._map_bound_facts_generation = None
        self._map_facts_message = "Импортируйте сетевые документы в расширенном анализе."

    def _map_network_facts_changed(self, snapshot: NetworkFactsSnapshot | None) -> None:
        record = self._map_bound_network_facts
        owner = self._map_facts_owner
        revision = self._map_analysis_state.revision
        context = (
            (
                snapshot.bound_context
                or (snapshot.parsed.context if snapshot.parsed is not None else None)
            )
            if snapshot is not None
            else None
        )
        if (
            snapshot is not None
            and record is not None
            and owner is not None
            and revision is not None
            and snapshot.imported == record.network_import
            and context == record.forwarding
            and owner_matches(
                record,
                owner.project_id,
                owner.run_id,
                owner.item_id,
                revision,
            )
        ):
            self._map_pending_facts_snapshot = snapshot
            self._map_bound_facts_generation = snapshot.input_generation
            self._apply_map_state(self._map_analysis_state)
            return
        self._clear_map_network_facts()
        if snapshot is not None and snapshot.imported is not None:
            try:
                MapNetworkFacts(
                    snapshot.imported,
                    context,
                )
            except ValueError:
                self._map_facts_message = (
                    "Привязка недоступна: сетевой импорт и forwarding "
                    "имеют разные исходные привязки."
                )
            else:
                self._map_pending_facts_snapshot = snapshot
                self._map_facts_message = (
                    "Сетевой импорт готов. Подключите его вручную "
                    "к топологии выбранного результата."
                )
        self._apply_map_state(self._map_analysis_state)

    def _attach_map_network_facts(self) -> None:
        """Only this explicit user action associates independent network facts."""
        self._apply_map_state(self._map_analysis_state)
        snapshot = self._map_pending_facts_snapshot
        owner = self._map_facts_owner
        if snapshot is None or snapshot.imported is None or owner is None:
            return
        record = MapNetworkFacts(
            snapshot.imported,
            snapshot.bound_context
            or (snapshot.parsed.context if snapshot.parsed is not None else None),
        )
        self._map_bound_network_facts = bind_map_facts_owner(
            record,
            owner,
            explicit_attachment=True,
        )
        self._map_bound_facts_generation = snapshot.input_generation
        self._apply_map_state(self._map_analysis_state)

    def _save_map_network_facts(self) -> None:
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить сетевой снимок в новый файл",
            "",
            "Сетевой снимок (*.json)",
            options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if not destination:
            return
        owner = self._map_facts_owner
        revision = self._map_analysis_state.revision
        record = self._map_bound_network_facts
        if (
            owner is None
            or revision is None
            or record is None
            or not owner_matches(
                record,
                owner.project_id,
                owner.run_id,
                owner.item_id,
                revision,
            )
        ):
            QMessageBox.warning(
                self,
                "Сетевой снимок",
                "Для выбранного результата нет привязанного сетевого снимка.",
            )
            return
        try:
            write_map_network_facts(Path(destination), record)
        except FileExistsError:
            QMessageBox.warning(
                self,
                "Сетевой снимок",
                "Файл уже существует. Выберите новое имя для снимка.",
            )
        except WorkspaceBusyError:
            QMessageBox.warning(
                self,
                "Сетевой снимок",
                "Файл занят другой операцией. Повторите сохранение позже.",
            )
        except (OSError, ValueError):
            QMessageBox.warning(
                self,
                "Сетевой снимок",
                "Не удалось сохранить сетевой снимок в выбранный файл.",
            )

    def _open_map_network_facts(self) -> None:
        source, _ = QFileDialog.getOpenFileName(
            self,
            "Открыть сетевой снимок выбранного результата",
            "",
            "Сетевой снимок (*.json)",
        )
        if not source:
            return
        try:
            record = read_map_network_facts(Path(source))
            owner = self._map_facts_owner
            revision = self._map_analysis_state.revision
            if (
                owner is None
                or revision is None
                or not owner_matches(
                    record,
                    owner.project_id,
                    owner.run_id,
                    owner.item_id,
                    revision,
                )
            ):
                QMessageBox.warning(
                    self,
                    "Сетевой снимок",
                    "Снимок не привязан к выбранному результату анализа. "
                    "Выберите соответствующий результат.",
                )
                return
            build_topology_projection(record.network_import, forwarding=record.forwarding)
            loaded_snapshot = None
            loader = getattr(self.advanced_panel, "set_map_network_facts", None)
            if callable(loader):
                previous_block = self.advanced_panel.blockSignals(True)
                try:
                    loader(record)
                    loaded_snapshot = self.advanced_panel.facts_snapshot()
                finally:
                    self.advanced_panel.blockSignals(previous_block)
        except (OSError, ValueError):
            QMessageBox.warning(
                self,
                "Сетевой снимок",
                "Не удалось открыть снимок: файл недоступен, повреждён "
                "или имеет неподдерживаемый формат.",
            )
            return
        self._clear_map_network_facts()
        self._map_bound_network_facts = record
        if loaded_snapshot is not None:
            self._map_pending_facts_snapshot = loaded_snapshot
            self._map_bound_facts_generation = loaded_snapshot.input_generation
        self._apply_map_state(self._map_analysis_state)

    def _map_result_selected(self, *_: Any) -> None:
        item_id = self.map_result_selector.currentData()
        item = self._map_items.get(item_id) if isinstance(item_id, str) else None
        if item is None:
            self._apply_map_state(build_map_state(None))
            return
        if item.get("kind") == "cloud":
            self._apply_map_state(
                AclMapState(
                    "unsupported",
                    None,
                    "Облачная запись не содержит ревизию ACL; карта не построена.",
                )
            )
            return
        # Only sessions created by analysis in this window are live map inputs.
        # Restoring a saved source must not replace its embedded revision.
        session = self.sessions.get(item_id) if item_id in self._map_live_item_ids else None
        state = build_map_state(session.revision) if session is not None else build_map_state(item)
        self._apply_map_state(state)

    def _build_settings(self) -> None:
        _, layout = self._page("Настройки", "Параметры проекта сохраняются для следующих запусков.")
        body = QHBoxLayout()
        body.setSpacing(24)
        menu = QFrame()
        menu.setObjectName("settingsMenu")
        menu.setFixedWidth(180)
        menu_layout = QVBoxLayout(menu)
        self.settings_pages = QStackedWidget()
        self.settings_nav_buttons: dict[str, QPushButton] = {}
        for index, (key, title) in enumerate(
            (("integrations", "Интеграции"), ("rules", "Правила"))
        ):
            button = _button(title, partial(self._select_settings_tab, key, index))
            button.setCheckable(True)
            self.settings_nav_buttons[key] = button
            menu_layout.addWidget(button)
        menu_layout.addStretch()
        body.addWidget(menu)
        body.addWidget(self.settings_pages, 1)
        layout.addLayout(body, 1)
        integrations = QWidget()
        integrations_layout = QVBoxLayout(integrations)
        integrations_layout.setContentsMargins(0, 0, 0, 0)
        self.integration_pages = QStackedWidget()
        integrations_layout.addWidget(self.integration_pages)
        catalog = QWidget()
        catalog_layout = QVBoxLayout(catalog)
        catalog_layout.setContentsMargins(0, 0, 0, 0)
        catalog_layout.addWidget(_label("Интеграции", heading=True))
        catalog_layout.addWidget(
            _label("Выберите платформу для просмотра способов подключения.", muted=True)
        )
        self.integration_pages.addWidget(catalog)
        self.integration_buttons: dict[str, QPushButton] = {}
        self.integration_grids: list[QGridLayout] = []
        groups = (
            ("Серверное оборудование", (("aruba", "Aruba", False),)),
            (
                "NGFW",
                (("usergate", "UserGate", True), ("pt", "PT NGFW", True), ("ideco", "Ideco", True)),
            ),
            ("Платформы виртуализации", (("cloud_ru", "Cloud.ru", False),)),
        )
        for title, platforms in groups:
            group = QFrame()
            group.setObjectName("integrationGroup")
            group_layout = QVBoxLayout(group)
            group_layout.setContentsMargins(18, 16, 18, 18)
            group_layout.addWidget(_label(title))
            grid = QGridLayout()
            grid.setSpacing(12)
            for column in range(5):
                grid.setColumnStretch(column, 1)
                grid.setColumnMinimumWidth(column, 72)
            self.integration_grids.append(grid)
            for position, (key, name, planned) in enumerate(platforms):
                button = _button(
                    name + ("\nЗапланировано" if planned else ""),
                    partial(self._open_integration, key),
                )
                button.setObjectName("integrationCard")
                button.setMinimumHeight(86)
                button.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
                button.setCursor(Qt.CursorShape.PointingHandCursor)
                button.setToolTip(
                    "Посмотреть статус и ограничения планируемой интеграции"
                    if planned
                    else f"Открыть {name}"
                )
                self.integration_buttons[key] = button
                grid.addWidget(button, position // 5, position % 5)
            group_layout.addLayout(grid)
            catalog_layout.addWidget(group)
        catalog_layout.addStretch()
        self.integration_detail_indices: dict[str, int] = {}
        descriptions = (
            (
                "aruba",
                "Aruba",
                "Доступен импорт файлов конфигурации Aruba. "
                "Прямое подключение к устройству ещё не реализовано.",
            ),
            (
                "usergate",
                "UserGate",
                "Запланировано. Подключение по API и импорт конфигураций UserGate "
                "ещё не реализованы. Проверки политик, карта и расчёт доступности "
                "для этого производителя пока недоступны. "
                "Следующий этап — подтвердить версии и формат экспорта на образцах; "
                "готовность адаптера будет указана отдельно от готовности сетевого анализа.",
            ),
            (
                "pt",
                "PT NGFW",
                "Запланировано. Импорт конфигураций и подключение по API не реализованы. "
                "Проверки политик, карта и расчёт доступности недоступны. "
                "Для разработки требуется подтвердить версию продукта, формат выгрузки "
                "и область политики: менеджер, опубликованная политика или узел. "
                "Карточка описывает план и не выполняет подключение.",
            ),
            (
                "ideco",
                "Ideco",
                "Запланировано. Импорт конфигураций и подключение по API не реализованы. "
                "Проверки политик, карта и расчёт доступности недоступны. "
                "Поддержка будет определена отдельно для конкретных версий и форматов; "
                "экспорт таблицы правил не подтверждает полноту объектов и сетевых данных. "
                "Карточка описывает план и не выполняет подключение.",
            ),
            (
                "cloud_ru",
                "Cloud.ru",
                "Подключение облачных платформ и получение данных через API.",
            ),
        )
        for key, name, description in descriptions:
            detail = QWidget()
            detail_layout = QVBoxLayout(detail)
            detail_layout.setContentsMargins(0, 0, 0, 0)
            detail_layout.addWidget(
                _button("← Все интеграции", lambda: self.integration_pages.setCurrentIndex(0))
            )
            detail_layout.addWidget(_label(name, heading=True))
            detail_layout.addWidget(_label(description, muted=True))
            if key == "cloud_ru":
                detail_layout.addWidget(self.cloud_panel.settings_widget)
            if key == "aruba":
                detail_layout.addWidget(
                    _button(
                        "Импортировать конфигурации", self._import_integration_files, primary=True
                    )
                )
            detail_layout.addStretch()
            self.integration_detail_indices[key] = self.integration_pages.addWidget(detail)
        self.settings_pages.addWidget(self._settings_scroll_area(integrations))
        rules = QWidget()
        layout = QVBoxLayout(rules)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(_label("Правила", heading=True))
        layout.addWidget(_label("Требования к правилам и состав выполняемых проверок.", muted=True))
        self.logging_check = QCheckBox("Требовать логирование разрешающих правил")
        self.logging_check.setChecked(True)
        self.comments_check = QCheckBox("Требовать комментарии правил")
        self.comments_check.setChecked(True)
        layout.addWidget(self.logging_check)
        layout.addWidget(self.comments_check)
        self.logging_check.toggled.connect(self._save_analysis_settings)
        self.comments_check.toggled.connect(self._save_analysis_settings)
        self.management_settings = ManagementSettings()
        layout.addWidget(self.management_settings)
        self.management_settings.changed.connect(self._save_analysis_settings)
        layout.addWidget(_label("Выполняемые проверки", muted=True))
        self.check_boxes: dict[str, QCheckBox] = {}
        for check_id, title in CHECKS.items():
            checkbox = QCheckBox(title)
            checkbox.setChecked(True)
            self.check_boxes[check_id] = checkbox
            checkbox.toggled.connect(self._save_analysis_settings)
            checkbox.toggled.connect(self._refresh_staged)
            layout.addWidget(checkbox)
        layout.addWidget(
            _label(
                "Хотя бы одна проверка должна быть включена. "
                "Изменения не меняют сохранённые результаты.",
                muted=True,
            )
        )
        layout.addStretch()
        self.settings_pages.addWidget(self._settings_scroll_area(rules))
        self._select_settings_tab("integrations", 0)

    def _settings_scroll_area(self, content: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content)
        return scroll

    def _select_settings_tab(self, key: str, index: int) -> None:
        self.settings_pages.setCurrentIndex(index)
        for tab_key, button in self.settings_nav_buttons.items():
            button.setChecked(tab_key == key)

    def _open_integration(self, key: str) -> None:
        self.integration_pages.setCurrentIndex(self.integration_detail_indices[key])

    def _import_integration_files(self) -> None:
        self.navigate("staging")
        self.choose_files()

    def choose_data_source(self) -> None:
        """Выбрать источник новых данных отдельно от постоянного инвентаря."""
        if not self._ensure_project():
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Добавить данные")
        layout = QVBoxLayout(dialog)
        layout.addWidget(_label("Выберите источник данных", heading=True))
        layout.addWidget(_label("Файлы проверяются локально; облачный сбор сохраняет данные API."))

        def choose(page: str) -> None:
            dialog.accept()
            self.navigate(page)

        layout.addWidget(_button("Файлы конфигураций / папка", lambda: choose("staging")))
        layout.addWidget(_button("Облачное подключение", lambda: choose("scans")))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def _build_preparation(self) -> None:
        _, layout = self._page(
            "Файлы и проверки",
            "1. Добавьте файлы. 2. Подтвердите устройства. "
            "3. Проверьте состав и запустите проверку.",
        )
        self._build_staging(layout)
        self.preparation_checks = _label("")
        layout.addWidget(self.preparation_checks)
        layout.addWidget(_button("Изменить состав проверок", self._open_check_settings))
        layout.addWidget(self.run_button)
        layout.addStretch()

    def _open_check_settings(self) -> None:
        self.navigate("settings")
        self._select_settings_tab("rules", 1)

    def _configure_cloud(self) -> None:
        self.navigate("settings")
        self._select_settings_tab("integrations", 0)
        self._open_integration("cloud_ru")
        self.cloud_panel.settings_widget.setCurrentIndex(self.cloud_panel.source.currentIndex())

    def _save_analysis_settings(self, *_: Any) -> None:
        if self.project_id and not self._loading_settings:
            try:
                management_profile = self.management_settings.profile().model_dump(mode="json")
            except ValueError:
                return
            self.store.update_settings(
                self.project_id,
                {
                    "require_logging": self.logging_check.isChecked(),
                    "require_comments": self.comments_check.isChecked(),
                    "management_profile": management_profile,
                    "enabled_check_ids": [
                        key for key, box in self.check_boxes.items() if box.isChecked()
                    ],
                },
            )

    def _build_staging(self, layout: QVBoxLayout) -> None:
        actions = QHBoxLayout()
        self.folder_button = _button("Добавить папку", self.choose_folder, primary=True)
        self.files_button = _button("Добавить файлы", self.choose_files)
        self.clear_button = _button("Очистить список", self.clear_staged)
        self.remove_button = _button("Убрать выбранные", self.remove_staged)
        for button in (
            self.folder_button,
            self.files_button,
            self.clear_button,
            self.remove_button,
        ):
            actions.addWidget(button)
        actions.addStretch()
        layout.addLayout(actions)
        layout.addWidget(
            _label("Подготовка файлов · двойной щелчок меняет связь с устройством", muted=True)
        )
        self.stage_table, self.stage_model, self.stage_proxy = self._table(
            ("Файл", "Формат", "Устройство", "Состояние / предупреждение"), "stagingTable"
        )
        self.stage_table.setMaximumHeight(220)
        self.stage_table.doubleClicked.connect(self._edit_staged_device)
        layout.addWidget(self.stage_table)

    def _build_findings(self) -> None:
        _, layout = self._page(
            "Проблемы", "Приоритет, объяснение и проверенные доказательства рядом с таблицей."
        )
        scope_row = QHBoxLayout()
        self.finding_scope = QComboBox()
        self.finding_scope.addItem("Последние снимки устройств проекта", "project")
        self.finding_scope.addItem("Выбранная проверка", "run")
        self.finding_scope.currentIndexChanged.connect(self.refresh_findings)
        scope_row.addWidget(self.finding_scope)
        self.finding_device = QComboBox()
        self.finding_device.addItem("Все устройства", "")
        self.finding_device.currentIndexChanged.connect(self.refresh_findings)
        scope_row.addWidget(self.finding_device)
        self.finding_check = QComboBox()
        self.finding_check.addItem("Все проверки", "")
        for key, title in CHECKS.items():
            self.finding_check.addItem(title, key)
        self.finding_check.currentIndexChanged.connect(self.refresh_findings)
        scope_row.addWidget(self.finding_check)
        layout.addLayout(scope_row)
        self.finding_coverage = _label("", muted=True)
        layout.addWidget(self.finding_coverage)
        filters = QHBoxLayout()
        self.finding_search = QLineEdit()
        self.finding_search.setObjectName("findingSearch")
        self.finding_search.setPlaceholderText("Поиск по устройству, проверке, названию…")
        self.finding_search.textChanged.connect(self.refresh_findings)
        filters.addWidget(self.finding_search, 1)
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("Все приоритеты", "")
        for key, value in SEVERITIES.items():
            self.severity_filter.addItem(value, key)
        self.severity_filter.currentIndexChanged.connect(self.refresh_findings)
        filters.addWidget(self.severity_filter)
        self.status_filter = QComboBox()
        self.status_filter.addItem("Все статусы", "")
        for key, value in STATUSES.items():
            self.status_filter.addItem(value, key)
        self.status_filter.currentIndexChanged.connect(self.refresh_findings)
        filters.addWidget(self.status_filter)
        layout.addLayout(filters)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.finding_table, self.finding_model, self.finding_proxy = self._table(
            ("Приоритет", "Устройство", "Проверка", "Находка", "Статус"),
            "findingsTable",
        )
        self.finding_table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        for column, width in enumerate((125, 135, 150, 280, 145)):
            self.finding_table.setColumnWidth(column, width)
        split.addWidget(self.finding_table)
        detail = self.finding_detail_tabs = QTabWidget()
        evidence_page = QWidget()
        detail_layout = QVBoxLayout(evidence_page)
        self.finding_detail = QTextBrowser()
        self.finding_detail.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.finding_detail.setObjectName("findingDetail")
        self.finding_detail.setOpenLinks(False)
        self.finding_detail.anchorClicked.connect(
            lambda _url: self.resource_details.show_finding_limitations()
        )
        detail_layout.addWidget(self.finding_detail, 1)
        evidence_actions = QPushButton("Действия с доказательством")
        menu = QMenu(evidence_actions)
        for title, callback in (
            ("Открыть связанные правила", self.open_finding_rules),
            ("Подключить исходник", self.attach_finding_source),
            ("Технический JSON", self.show_finding_json),
        ):
            menu.addAction(title).triggered.connect(callback)
        evidence_actions.setMenu(menu)
        detail_layout.addWidget(evidence_actions)
        detail.addTab(evidence_page, "Доказательство")
        decision_page = QWidget()
        decision_layout = QVBoxLayout(decision_page)
        decision_layout.addWidget(_label("Решение пользователя по выбранным находкам", muted=True))
        self.mark_combo = QComboBox()
        self.mark_combo.setObjectName("findingMark")
        for key, value in STATUSES.items():
            self.mark_combo.addItem(value, key)
        decision_layout.addWidget(self.mark_combo)
        self.comment_edit = QPlainTextEdit()
        self.comment_edit.setObjectName("findingComment")
        self.comment_edit.setPlaceholderText("Комментарий к выбранным находкам")
        decision_layout.addWidget(self.comment_edit, 1)
        decision_layout.addWidget(_button("Применить к выбранным", self.save_marks))
        detail.addTab(decision_page, "Решение")
        split.addWidget(detail)
        split.setSizes([850, 430])
        layout.addWidget(split, 1)
        self.finding_table.selectionModel().selectionChanged.connect(self._finding_selected)

    def _build_devices(self) -> None:
        page, layout = self._page(
            "Инфраструктура", "Ресурсы проекта и доступные снимки конфигураций."
        )
        self.device_scope = QComboBox()
        self.device_scope.addItem("Импорты выбранного запуска", "run")
        self.device_scope.addItem("Все ресурсы проекта · последние снимки", "project")
        self.device_scope.setCurrentIndex(1)
        self.device_scope.currentIndexChanged.connect(self._refresh_devices)
        layout.addWidget(self.device_scope)
        filters = QHBoxLayout()
        self.resource_kind = QComboBox()
        for title, key in (("Все ресурсы", ""), ("Устройства", "device"), ("Облако", "cloud")):
            self.resource_kind.addItem(title, key)
        self.resource_kind.currentIndexChanged.connect(self._refresh_devices)
        filters.addWidget(self.resource_kind)
        self.resource_platform = QComboBox()
        self.resource_platform.addItem("Все платформы", "")
        self.resource_platform.currentIndexChanged.connect(self._refresh_devices)
        filters.addWidget(self.resource_platform)
        self.resource_type = QComboBox()
        self.resource_type.addItem("Все типы", "")
        self.resource_type.currentIndexChanged.connect(self._refresh_devices)
        filters.addWidget(self.resource_type)
        self.resource_search = QLineEdit()
        self.resource_search.setPlaceholderText("Поиск по имени, платформе, типу или источнику")
        filters.addWidget(self.resource_search, 1)
        layout.addLayout(filters)
        self.infrastructure_hint = _label("", muted=True)
        layout.addWidget(self.infrastructure_hint)
        self.import_errors_button = _button(
            "Импорт не выполнен: 0 записей", self.resource_details.show_import_errors
        )
        self._import_error_items: list[dict[str, Any]] = []
        layout.addWidget(self.import_errors_button)
        self.device_table, self.device_model, self.device_proxy = self._table(
            ("Устройство", "Платформа / версия", "Тип", "Правил"),
            "devicesTable",
            search_payload=True,
        )
        self.resource_search.textChanged.connect(self.device_proxy.setFilterFixedString)
        self.device_detail = QTextBrowser()
        self.device_detail.setOpenLinks(False)
        self.device_detail.anchorClicked.connect(self.resource_details.open_device_link)
        self.device_tabs = QTabWidget(page)
        self.device_tabs.addTab(self.device_detail, "Сведения")
        self.device_rules_table, self.device_rules_model, self.device_rules_proxy = self._table(
            ("Порядок", "Правило", "Действие", "Источник", "Назначение", "Сервис"),
            "deviceRules",
        )
        self.device_objects_table, self.device_objects_model, self.device_objects_proxy = (
            self._table(("Объект", "Тип", "Содержимое"), "deviceObjects")
        )
        for table, title, callback in (
            (self.device_rules_table, "Правила", self.resource_details.show_device_rule_details),
            (
                self.device_objects_table,
                "Объекты",
                self.resource_details.show_device_object_details,
            ),
        ):
            page = QWidget()
            page_layout = QVBoxLayout(page)
            page_layout.addWidget(table)
            page_layout.addWidget(_button("Открыть полный состав выбранного", callback))
            table.doubleClicked.connect(callback)
            self.device_tabs.addTab(page, title)
        problems_page = QWidget()
        problems_layout = QVBoxLayout(problems_page)
        self.resource_findings_hint = _label("")
        problems_layout.addWidget(self.resource_findings_hint)
        self.resource_findings_table, self.resource_findings_model, self.resource_findings_proxy = (
            self._table(("Приоритет", "Проверка", "Проблема"), "resourceFindings")
        )
        problems_layout.addWidget(self.resource_findings_table)
        problems_layout.addWidget(
            _button("Разобрать проблемы", self.resource_details.open_findings)
        )
        self.resource_findings_table.doubleClicked.connect(self.resource_details.open_findings)
        self.device_tabs.addTab(problems_page, "Проблемы")
        self.resource_history_table, self.resource_history_model, self.resource_history_proxy = (
            self._table(("Получено", "Операция", "Состояние"), "resourceHistory")
        )
        self.resource_history_table.doubleClicked.connect(self.resource_details.open_history)
        self.device_tabs.addTab(self.resource_history_table, "История")
        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        self.resource_source_detail = QTextBrowser()
        sources_layout.addWidget(self.resource_source_detail, 1)
        self.device_tabs.addTab(sources_page, "Источники")
        for column, width in enumerate((220, 180, 140, 75)):
            self.device_table.setColumnWidth(column, width)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self.device_table)
        # Временно скрыто до переработки инфраструктуры (INFRA-001).
        # Виджеты сохранены для действующих обработчиков и возврата панели.
        # split.addWidget(self.device_tabs)
        # split.setSizes([600, 560])
        self.device_tabs.hide()
        layout.addWidget(split, 1)
        self.device_table.selectionModel().selectionChanged.connect(self._device_selected)
        actions = QGridLayout()
        self.attach_button = _button("Подключить исходник", self.attach_selected_source)
        self.repeat_button = _button("Повторить проверки", self.repeat_selected)
        self.single_export_button = _button("JSON отдельного результата", self.export_single)
        for index, button in enumerate(
            (self.attach_button, self.repeat_button, self.single_export_button)
        ):
            actions.addWidget(button, index // 2, index % 2)
        self.resource_operation_button = _button("Открыть операцию", self.open_resource_operation)
        actions.addWidget(self.resource_operation_button, 1, 1)
        sources_layout.addLayout(actions)
        preview_row = QHBoxLayout()
        preview_row.addWidget(_label("Строки:"))
        self.line_start = QSpinBox()
        self.line_start.setRange(1, 10000000)
        self.line_end = QSpinBox()
        self.line_end.setRange(1, 10000000)
        self.line_end.setValue(20)
        preview_row.addWidget(self.line_start)
        preview_row.addWidget(_label("—"))
        preview_row.addWidget(self.line_end)
        preview_row.addWidget(_button("Показать фрагмент", self.preview_selected_source))
        preview_row.addStretch()
        sources_layout.addLayout(preview_row)

    def _build_rules(self) -> None:
        _, layout = self._page(
            "Правила и объекты",
            "Правила и объекты файлов, а также правила, полученные из облачных API. "
            "Облачный сбор не запускает проверки правил.",
        )
        self.rule_scope = QComboBox()
        self.rule_scope.addItem("Все ресурсы проекта · последние снимки", "project")
        self.rule_scope.addItem("Выбранный запуск", "run")
        self.rule_scope.currentIndexChanged.connect(self._refresh_rules)
        layout.addWidget(self.rule_scope)
        self.rule_inventory_status = _label("")
        layout.addWidget(self.rule_inventory_status)
        search = self.rule_search = QLineEdit()
        search.setPlaceholderText("Поиск по устройству, правилу, адресу или сервису")
        layout.addWidget(search)
        self.rules_table, self.rules_model, self.rules_proxy = self._table(
            (
                "Устройство",
                "Порядок",
                "Правило / объект",
                "Действие / тип",
                "Источник",
                "Назначение",
                "Сервис",
            ),
            "rulesTable",
            search_payload=True,
        )
        search.textChanged.connect(self.rules_proxy.setFilterFixedString)
        self.rule_detail = QTextBrowser()
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.rules_table)
        split.addWidget(self.rule_detail)
        split.setSizes([620, 180])
        layout.addWidget(split, 1)
        self.rules_table.selectionModel().selectionChanged.connect(self._rule_selected)
        self.rules_table.doubleClicked.connect(self.resource_details.show_rule_details)
        layout.addWidget(
            _button("Открыть полный состав выбранного", self.resource_details.show_rule_details)
        )
        rule_actions = QPushButton("Действия с правилом / объектом")
        menu = QMenu(rule_actions)
        menu.addAction("Показать доказательство / исходник").triggered.connect(
            self.resource_details.show_rule_source
        )
        menu.addAction("Технический JSON").triggered.connect(self.resource_details.show_rule_json)
        rule_actions.setMenu(menu)
        layout.addWidget(rule_actions)

    def _build_history(self) -> None:
        _, layout = self._page(
            "Операции",
            "Сбор данных и проверки проекта. Выберите операцию для просмотра результата.",
        )
        self.history_table, self.history_model, self.history_proxy = self._table(
            ("Дата", "Тип", "Состояние", "Файлы / ресурсы", "Проблемы / ошибки", "Операция"),
            "historyTable",
        )
        self.history_table.doubleClicked.connect(self._open_history)
        layout.addWidget(self.history_table, 1)
        actions = QHBoxLayout()
        actions.addWidget(_button("Открыть выбранный запуск", self._open_history))
        actions.addWidget(_button("Сравнить два выбранных", self.compare_selected_runs))
        actions.addStretch()
        layout.addLayout(actions)
        self.history_detail = QTextBrowser()
        layout.addWidget(self.history_detail, 1)

    def _build_reports(self) -> None:
        _, layout = self._page(
            "Отчёты", "Автономный HTML и версионированный JSON по всему запуску."
        )
        self.report_run = QComboBox()
        self.report_run.setAccessibleName("Запуск для отчёта")
        self.report_run.currentIndexChanged.connect(self._select_report_run)
        layout.addWidget(self.report_run)
        layout.addWidget(
            _label(
                "Отчёт включает управленческую сводку, обработанные и неподдерживаемые файлы, "
                "ограничения проверок, находки и ваши решения."
            )
        )
        self.fragments_check = QCheckBox("Включить фрагменты конфигураций в отчёт")
        self.fragments_check.setChecked(True)
        self.fragments_check.toggled.connect(self._save_report_settings)
        layout.addWidget(self.fragments_check)
        layout.addWidget(
            _label(
                "Фрагменты и доказательства могут содержать внутренние адреса "
                "и другую чувствительную информацию.",
                muted=True,
            )
        )
        row = QHBoxLayout()
        row.addWidget(_button("Сохранить HTML", lambda: self.export_batch("html"), primary=True))
        row.addWidget(_button("Сохранить JSON", lambda: self.export_batch("json")))
        row.addStretch()
        layout.addLayout(row)
        self.report_summary = QTextBrowser()
        self.report_summary.setOpenLinks(False)
        self.report_summary.anchorClicked.connect(self._open_report_limitations)
        layout.addWidget(self.report_summary, 1)

    def _open_report_limitations(self, url: Any) -> None:
        item = next((value for value in self._items() if str(value["id"]) == url.toString()), None)
        if item:
            self.resource_details.show_item_limitations(item)

    def navigate(self, section_id: str, *, remember: bool = True) -> None:
        """Открыть страницу по ID и синхронизировать вкладки и контекст раздела."""
        index = SECTION_IDS.index(section_id)
        if remember and section_id != self.current_section_id:
            self.workspace_history.remember()
        self.current_section_id = section_id
        self.pages.setCurrentIndex(index)
        if section_id == "map":
            self._refresh_project_map()
        section = section_for_page(section_id)
        self.section_tabs.blockSignals(True)
        while self.section_tabs.count():
            self.section_tabs.removeTab(0)
        if section:
            for key, title in section.pages:
                tab_index = self.section_tabs.addTab(title)
                self.section_tabs.setTabData(tab_index, key)
                if key == section_id:
                    self.section_tabs.setCurrentIndex(tab_index)
        self.section_tabs.setVisible(bool(section and len(section.pages) > 1))
        self.section_tabs.blockSignals(False)
        self.settings_button.setChecked(section_id == "settings")
        item = self.nav_items.get(section_id)
        self.navigation.blockSignals(True)
        if item is not None:
            parent = item.parent()
            if parent is not None:
                parent.setExpanded(True)
            self.navigation.setCurrentItem(item)
        else:
            self.navigation.clearSelection()
        self.navigation.blockSignals(False)
        self._refresh_context()

    def _section_tab_changed(self, index: int) -> None:
        key = self.section_tabs.tabData(index)
        if key:
            self.navigate(str(key))

    def _refresh_context(self) -> None:
        if not self.project_id:
            self.context_label.setText("Выберите или создайте проект → Добавить данные")
            return
        project = self.project_combo.currentText()
        page = self.current_section_id
        if page == "home":
            scope = "Обзор проекта · последние доступные данные"
        elif page in ("devices", "rules", "findings"):
            selector = {
                "devices": self.device_scope,
                "rules": self.rule_scope,
                "findings": self.finding_scope,
            }[page]
            scope = (
                "Последние снимки ресурсов · время получения может различаться"
                if selector.currentData() == "project"
                else self._run_context()
            )
        elif page == "reports":
            scope = self._run_context()
        elif page == "scans":
            scope = "Облачный сбор · не является проверкой правил"
        elif page == "staging":
            scope = "Подготовка новой проверки · сохранённые результаты не изменяются"
        else:
            scope = "Проект"
        self.context_label.setText(f"{project} / {scope}")

    def _select_report_run(self, *_: Any) -> None:
        run_id = self.report_run.currentData()
        if run_id and run_id != self.run_id and not self._batch_active and not self._restore_busy:
            self.workspace_history.remember()
            self.load_run(run_id)

    def open_overview_resources(self) -> None:
        self.workspace_history.remember()
        self.device_scope.setCurrentIndex(self.device_scope.findData("project"))
        for combo in (self.resource_kind, self.resource_platform, self.resource_type):
            combo.setCurrentIndex(0)
        self.resource_search.clear()
        self.navigate("devices", remember=False)

    def open_overview_findings(self, severity: str = "") -> None:
        if self._batch_active or self._restore_busy:
            self.progress_label.setText("Дождитесь завершения текущей проверки.")
            return
        self.workspace_history.remember()
        runs = self.store.list_runs(self.project_id) if self.project_id else []
        latest = next((run for run in runs if run.get("finished_at")), None)
        if latest:
            self.load_run(latest["id"])
        self.finding_scope.setCurrentIndex(self.finding_scope.findData("run"))
        self.finding_search.clear()
        for combo in (self.finding_device, self.finding_check, self.status_filter):
            combo.setCurrentIndex(0)
        self.severity_filter.setCurrentIndex(max(0, self.severity_filter.findData(severity)))
        self.navigate("findings", remember=False)

    def _run_context(self) -> str:
        if not self.run:
            return "Проверка не выбрана · откройте запуск в Операциях"
        return f"Проверка {self.run_id} · {self.run.get('created_at', '')}"

    def _navigation_changed(self, item: QTreeWidgetItem | None, *_: Any) -> None:
        if item is not None:
            section_id = item.data(0, Qt.ItemDataRole.UserRole)
            if section_id:
                self.navigate(section_id)

    def _navigation_clicked(self, item: QTreeWidgetItem, *_: Any) -> None:
        section_id = item.data(0, Qt.ItemDataRole.UserRole)
        if section_id:
            self.navigate(section_id)
        elif item.childCount():
            item.setExpanded(not item.isExpanded())

    def refresh_projects(self, selected_id: str | None = None) -> None:
        self.project_combo.blockSignals(True)
        self.project_combo.clear()
        for project in self.store.list_projects():
            self.project_combo.addItem(project["name"], project["id"])
        if selected_id:
            self.project_combo.setCurrentIndex(self.project_combo.findData(selected_id))
        self.project_combo.blockSignals(False)
        self._project_changed()

    def create_project(self, name: str) -> str:
        result = self.store.create_project(name)
        project_id = result["id"] if isinstance(result, dict) else result
        self.refresh_projects(str(project_id))
        return str(project_id)

    def _create_project_dialog(self) -> None:
        name, accepted = QInputDialog.getText(self, "Новый проект", "Название проекта / площадки")
        if accepted and name.strip():
            self.create_project(name.strip())

    def _project_changed(self, *_: Any) -> None:
        self.workspace_history.clear()
        self._loading_settings = True
        self.project_id = self.project_combo.currentData()
        self.cloud_panel.set_project(self.project_id)
        self.run_id = None
        self.run = None
        for name in self.workspace_history.searches:
            widget = getattr(self, name)
            widget.blockSignals(True)
            widget.clear()
            widget.blockSignals(False)
        for name in self.workspace_history.combos:
            widget = getattr(self, name)
            widget.blockSignals(True)
            index = widget.findData("project") if name.endswith("scope") else 0
            widget.setCurrentIndex(max(0, index))
            widget.blockSignals(False)
        self.sessions.clear()
        self._map_live_item_ids.clear()
        self._refresh_map_items()
        self.staged.clear()
        self.notification.hide()
        if self.project_id:
            project = self.store.get_project(self.project_id)
            settings = project.get("settings", {})
            self.management_settings.load_profile(settings.get("management_profile"))
            self.logging_check.setChecked(settings.get("require_logging", True))
            self.comments_check.setChecked(settings.get("require_comments", True))
            self.fragments_check.blockSignals(True)
            self.fragments_check.setChecked(settings.get("include_fragments", True))
            self.fragments_check.blockSignals(False)
            enabled = settings.get("enabled_check_ids", list(CHECKS))
            for check_id, checkbox in self.check_boxes.items():
                checkbox.setChecked(check_id in enabled)
            runs = self.store.list_runs(self.project_id)
            if runs:
                self.load_run(runs[0]["id"])
        self._loading_settings = False
        self._refresh_all()

    def choose_folder(self) -> None:
        if not self._ensure_project():
            return
        folder = QFileDialog.getExistingDirectory(self, "Папка конфигураций")
        if folder:
            self.stage_paths(
                sorted(
                    path
                    for path in Path(folder).iterdir()
                    if path.is_file()
                    and path.suffix.lower() in {".txt", ".cfg", ".conf", ".config"}
                )
            )

    def choose_files(self) -> None:
        if not self._ensure_project():
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Конфигурации",
            "",
            "Конфигурации (*.txt *.cfg *.conf *.config);;Все файлы (*)",
        )
        if paths:
            self.stage_paths([Path(path) for path in paths])

    def _ensure_project(self) -> bool:
        if self.project_id:
            return True
        self._create_project_dialog()
        return self.project_id is not None

    def stage_paths(self, paths: Sequence[Path]) -> None:
        """Поставить предварительное определение файлов в общую фоновую очередь."""
        if not self.project_id or self._batch_active or self._restore_busy:
            return
        existing = {str(item["path"]) for item in self.staged}
        for path in paths:
            path = path.resolve()
            if str(path) in existing:
                continue
            existing.add(str(path))
            item: dict[str, Any] = {
                "path": path,
                "parser": "Определение…",
                "device": path.stem,
                "warning": "В очереди",
                "ready": False,
                "ambiguous": False,
            }
            self.staged.append(item)
            job_id = self.runner.submit(
                partial(inspect_file, path),
                partial(self._inspected, item),
            )
            self._preflight_jobs.add(job_id)
        self.navigate("staging")
        self._refresh_staged()
        self.progress_label.setText("Определяем форматы файлов перед анализом…")
        self.cancel_button.setEnabled(bool(self._preflight_jobs))

    def _inspected(self, item: dict[str, Any], result: object) -> None:
        if not any(candidate is item for candidate in self.staged):
            return
        if isinstance(result, JobError):
            item.update(parser="Ошибка чтения", warning=result.message, ready=True)
        elif isinstance(result, dict):
            item.update(result)
            item["device"] = result["hostname"] or item["path"].stem
            item["ready"] = True
            source_key = item["path"].name
            suggestion = self.store.suggest_device(self.project_id, source_key)
            if isinstance(suggestion, str) and suggestion:
                item["device"] = suggestion
                item["confirmed"] = True
            elif isinstance(suggestion, dict):
                item["device"] = suggestion.get("device_id") or item["device"]
                item["ambiguous"] = suggestion.get("ambiguous", False)
            matches = [
                x
                for x in self.staged
                if x is not item and x.get("ready") and x["device"] == item["device"]
            ]
            if matches and not all(candidate.get("confirmed") for candidate in [item, *matches]):
                for candidate in [item, *matches]:
                    if candidate.get("confirmed"):
                        continue
                    candidate["ambiguous"] = True
                    candidate["warning"] = (
                        "Повторяется устройство: подтвердите связь двойным щелчком"
                    )
        self._refresh_staged()

    def _refresh_staged(self) -> None:
        if hasattr(self, "preparation_checks"):
            enabled = [CHECKS[key] for key, box in self.check_boxes.items() if box.isChecked()]
            self.preparation_checks.setText(
                "Будут выполнены: " + ", ".join(enabled)
                if enabled
                else "Выберите хотя бы одну проверку в настройках."
            )
        self.stage_model.replace(
            [
                (item["path"].name, item["parser"], item["device"], item["warning"])
                for item in self.staged
            ],
            self.staged,
        )
        self.run_button.setEnabled(
            bool(self.staged)
            and not self._batch_active
            and not self._restore_busy
            and all(item["ready"] and not item["ambiguous"] for item in self.staged)
            and any(checkbox.isChecked() for checkbox in self.check_boxes.values())
        )

    def _edit_staged_device(self, index: Any) -> None:
        item = self.stage_model.payloads[self.stage_proxy.mapToSource(index).row()]
        if self._batch_active:
            return
        value, accepted = QInputDialog.getText(
            self,
            "Связь с устройством",
            "Устройство для этого файла (одно имя для его ревизий)",
            text=item["device"],
        )
        if accepted and value.strip():
            item["device"] = value.strip()
            item["ambiguous"] = False
            item["confirmed"] = True
            item["warning"] = "Связь подтверждена пользователем"
            self.store.confirm_device(self.project_id, item["path"].name, item["device"])
            self._refresh_staged()

    def clear_staged(self) -> None:
        if not self._batch_active:
            self.staged.clear()
            self._refresh_staged()

    def remove_staged(self) -> None:
        if not self._batch_active:
            selected = self._selected_payloads(self.stage_table, self.stage_proxy, self.stage_model)
            self.staged = [item for item in self.staged if item not in selected]
            self._refresh_staged()

    def start_analysis(self) -> None:
        """Начать пакет; каждое задание независимо сохраняет успех или диагностику."""
        if not self.run_button.isEnabled() or not self.project_id:
            return
        try:
            management_profile = self.management_settings.profile()
        except ValueError:
            self._open_check_settings()
            return
        configuration_complete = self.management_settings.complete.isChecked()
        enabled = tuple(key for key, box in self.check_boxes.items() if box.isChecked())
        settings: dict[str, Any] = {
            "management_profile": management_profile.model_dump(mode="json"),
            "require_logging": self.logging_check.isChecked(),
            "require_comments": self.comments_check.isChecked(),
            "enabled_check_ids": enabled,
        }
        self.store.update_settings(self.project_id, settings)
        result = self.store.create_run(self.project_id)
        self.run_id = result["id"] if isinstance(result, dict) else str(result)
        self.sessions.clear()
        self._map_live_item_ids.clear()
        self._batch_active = True
        self._refresh_map_items()
        self.notification.hide()
        self._batch_cancelled = False
        self._set_controls_busy(True)
        for item in self.staged:
            item["warning"] = "В очереди"
            job_id = self.runner.submit(
                partial(
                    analyze_file,
                    item["path"],
                    device_id=item["device"],
                    require_logging=self.logging_check.isChecked(),
                    require_comments=self.comments_check.isChecked(),
                    enabled_check_ids=enabled,
                    management_profile=management_profile,
                    configuration_complete=configuration_complete,
                ),
                partial(self._analyzed, item),
            )
            self._analysis_jobs[job_id] = item
        self.progress.setRange(0, len(self.staged))
        self.management_settings.complete.setChecked(False)
        self.progress.setValue(0)
        self.progress.show()
        self.cancel_button.setEnabled(True)
        self._refresh_staged()

    def _analyzed(self, item: dict[str, Any], result: object) -> None:
        if isinstance(result, AnalysisSession):
            item_id = self.store.record_session(self.run_id, result)
            self.sessions[str(item_id)] = result
            self._map_live_item_ids.add(str(item_id))
            item["warning"] = "Анализ завершён"
        elif isinstance(result, ParseFailure):
            self.store.record_failure(self.run_id, item["path"], result)
            item["warning"] = "; ".join(error.message for error in result.errors)
        else:
            message = (
                result.message if isinstance(result, JobError) else "Результат анализа не получен"
            )
            self.store.record_error(self.run_id, item["path"], message)
            item["warning"] = message
        self._refresh_staged()

        self._refresh_map_items()

    def _set_controls_busy(self, busy: bool) -> None:
        for widget in (
            self.project_combo,
            self.create_button,
            self.folder_button,
            self.files_button,
            self.logging_check,
            self.comments_check,
            self.clear_button,
            self.remove_button,
        ):
            widget.setEnabled(not busy)
        for checkbox in self.check_boxes.values():
            checkbox.setEnabled(not busy)
        if busy:
            self.run_button.setEnabled(False)

    def poll_jobs(self) -> None:
        """Доставить завершения backend только в Qt-потоке и обновить счётчик пакета."""
        events = self.runner.poll()
        terminal_jobs = {
            event.job_id
            for event in events
            if event.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELED)
        }
        for event in events:
            if event.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELED):
                self._preflight_jobs.discard(event.job_id)
                item = self._analysis_jobs.pop(event.job_id, None)
                if event.status == JobStatus.CANCELED and item is not None:
                    item["warning"] = "Отменён до начала выполнения"
                    self.store.record_cancelled(self.run_id, item["path"])
                if item is not None:
                    self.progress.setValue(self.progress.value() + 1)
            if (
                event.status == JobStatus.RUNNING
                and event.job_id in self._analysis_jobs
                and event.job_id not in terminal_jobs
            ):
                item = self._analysis_jobs[event.job_id]
                item["warning"] = "Выполняется"
                self.progress_label.setText(
                    f"Завершено {self.progress.value()} из {len(self.staged)} · {item['path'].name}"
                )
        if events:
            self._refresh_staged()
        if not self._preflight_jobs and self.staged and not self._batch_active:
            ambiguous = sum(bool(item["ambiguous"]) for item in self.staged)
            if not self._restore_busy and self.progress_label.text().startswith("Определяем"):
                self.progress_label.setText(
                    f"Подготовлено файлов: {len(self.staged)}. "
                    + (
                        f"Подтвердите неоднозначные связи: {ambiguous}."
                        if ambiguous
                        else "Можно запускать анализ."
                    )
                )
        if self._batch_active and not self._analysis_jobs:
            self._batch_active = False
            self.store.finish_run(
                self.run_id, state="cancelled" if self._batch_cancelled else "completed"
            )
            if self.run_id is not None:
                self.load_run(self.run_id)
            self._set_controls_busy(False)
            self.progress.hide()
            self.progress_label.setText(
                "Пакет завершён. Ограничения и ошибки включены в сводку и отчёт."
            )
            self._notify_completion()
        self.cancel_button.setEnabled(bool(self.runner.pending_count))

    def _notify_completion(self) -> None:
        self._completed_run_id = self.run_id
        items = self._items()
        states = Counter(item["status"] for item in items)
        partial_count = states["partial"]
        missing_count = sum(not item.get("report") for item in items)
        title = "Анализ отменён" if self._batch_cancelled else "Анализ завершён"
        self.notification_label.setText(
            f"{title} · файлов: {len(items)} · частичных: {partial_count} · "
            f"без результата: {missing_count}."
        )
        self.notification.show()

    def open_completed_result(self) -> None:
        if not self._completed_run_id or self._batch_active or self._restore_busy:
            return
        self.workspace_history.remember()
        self.load_run(self._completed_run_id)
        self.finding_scope.setCurrentIndex(self.finding_scope.findData("run"))
        self.finding_search.clear()
        for combo in (
            self.finding_device,
            self.finding_check,
            self.severity_filter,
            self.status_filter,
        ):
            combo.setCurrentIndex(0)
        self.navigate("findings", remember=False)

    def cancel_pending(self) -> None:
        if self._batch_active and self.runner.pending_count:
            self._batch_cancelled = True
        self.runner.cancel_pending()
        for item in self.staged:
            if not item["ready"]:
                item.update(
                    ready=True,
                    warning="Определение отменено; добавьте файл повторно",
                    ambiguous=True,
                )
        self._refresh_staged()
        self.progress_label.setText("Ожидающие задания отменены. Выполняющееся задание завершится.")

    def load_run(self, run_id: str) -> None:
        """Открыть сохранённый запуск, не перечитывая оригинальные конфигурации."""
        if self._batch_active:
            return
        self.run_id = str(run_id)
        self.run = self.store.get_run(self.run_id)
        known = {str(item["id"]) for item in self.run.get("items", [])}
        self.sessions = {key: session for key, session in self.sessions.items() if key in known}
        self._map_live_item_ids.intersection_update(known)
        self._refresh_all()

    def _refresh_all(self) -> None:
        self._refresh_staged()
        self.refresh_findings()
        self._refresh_devices()
        self._refresh_rules()
        self._refresh_history()
        self._refresh_summary()
        self._refresh_context()
        self._refresh_map_items()
        refresher = getattr(self.advanced_panel, "refresh_sessions", None)
        if callable(refresher):
            refresher()

    def _items(self) -> list[dict[str, Any]]:
        return self.run.get("items", []) if self.run else []

    def _marks(self) -> dict[str, Any]:
        return self.store.get_run(self.run_id).get("marks", {}) if self.run_id else {}

    def refresh_findings(self, *_: Any) -> None:
        items = (
            self._project_devices()
            if self.finding_scope.currentData() == "project"
            else [{**item, "run_id": self.run_id} for item in self._items()]
        )
        device = self.finding_device.currentData() or ""
        self.finding_device.blockSignals(True)
        self.finding_device.clear()
        self.finding_device.addItem("Все устройства", "")
        for name in sorted({item["report"]["device_id"] for item in items if item.get("report")}):
            self.finding_device.addItem(name, name)
        self.finding_device.setCurrentIndex(max(0, self.finding_device.findData(device)))
        self.finding_device.blockSignals(False)
        device = self.finding_device.currentData()
        marks_by_run = {
            run_id: self.store.get_run(run_id).get("marks", {})
            for run_id in {item["run_id"] for item in items if item.get("run_id")}
        }
        rows, payloads = [], []
        coverage: Counter[str] = Counter()
        search = self.finding_search.text().casefold()
        for item in items:
            report = item.get("report") or {}
            if device and report.get("device_id") != device:
                continue
            for check in report.get("checks", []):
                if self.finding_check.currentData() not in ("", check["check_id"]):
                    continue
                coverage[check_status_label(check)] += 1
                for finding in check["findings"]:
                    mark = marks_by_run.get(item.get("run_id"), {}).get(
                        str(finding["finding_id"]), {}
                    )
                    status = mark.get("status", finding.get("status", "new"))
                    if self.severity_filter.currentData() not in ("", finding["severity"]):
                        continue
                    if self.status_filter.currentData() not in ("", status):
                        continue
                    row = (
                        SEVERITIES.get(finding["severity"], finding["severity"]),
                        report["device_id"],
                        CHECKS.get(check["check_id"], check["check_id"]),
                        finding["title"],
                        STATUSES.get(status, status),
                    )
                    if search and search not in " ".join(row).casefold():
                        continue
                    rows.append(row)
                    payloads.append(
                        {"finding": finding, "check": check, "item": item, "mark": mark}
                    )
        self._finding_payloads = payloads
        self.finding_model.replace(rows, payloads)
        self.finding_coverage.setText(
            "Выполнение проверок: "
            + " · ".join(f"{key}: {count}" for key, count in coverage.items())
            if coverage
            else "Результатов проверок нет. Получите данные и запустите проверку."
        )
        self._refresh_context()
        self.finding_detail.setPlainText(
            "Выберите находку. Можно выбрать несколько строк для общего статуса и комментария."
        )

    def _selected_payloads(
        self, table: QTableView, proxy: QSortFilterProxyModel, model: RowsModel
    ) -> list[Any]:
        return [
            model.payloads[proxy.mapToSource(index).row()]
            for index in table.selectionModel().selectedRows()
        ]

    def _finding_selected(self, *_: Any) -> None:
        payloads = self._selected_payloads(
            self.finding_table, self.finding_proxy, self.finding_model
        )
        if not payloads:
            self._clear_map_selection()
            return
        payload = payloads[0]
        finding, check, item = payload["finding"], payload["check"], payload["item"]
        self._refresh_map_items(item)
        evidence = finding["evidence"]
        locations = evidence.get("source_locations", [])
        fragments = [
            excerpt
            for excerpt in item.get("excerpts", [])
            if any(
                location.get("source_name") == excerpt["location"].get("source_name")
                and location.get("line_start") is not None
                and excerpt["location"].get("line_start") is not None
                and location["line_start"]
                <= (excerpt["location"].get("line_end") or excerpt["location"]["line_start"])
                and (location.get("line_end") or location["line_start"])
                >= excerpt["location"]["line_start"]
                for location in locations
            )
        ]
        pieces = [
            f"<h2>{html.escape(finding['title'])}</h2>",
            f"<p>{html.escape(finding['description'])}</p>",
            f"<h3>Рекомендация</h3><p>{html.escape(finding['recommendation'])}</p>",
            f"<p><b>Полнота проверки:</b> {html.escape(check_status_label(check))}</p>",
            f"<p>Источник: {html.escape(item.get('source_name', '—'))}<br>"
            f"SHA-256: {html.escape(item.get('content_sha256') or 'не определён')}<br>"
            "Получено: "
            + html.escape(
                str(item.get("run_created_at") or (self.run or {}).get("created_at", "—"))
            )
            + "</p>",
            f"<h3>Доказательства</h3><p>{html.escape(evidence.get('summary', ''))}</p>",
        ]
        selection = finding_limitations(item, check, finding)
        if selection.local:
            pieces.append("<h3>Ограничения выбранного вывода</h3><ul>")
            pieces.extend(
                f"<li>{html.escape(group_summary(group))}</li>" for group in selection.local
            )
            pieces.append("</ul>")
        if selection.common:
            pieces.append(
                f"<p>Общие ограничения источника / проверки: {len(selection.common)} групп. "
                "Они не привязаны только к выбранному правилу.<br>"
                + html.escape("; ".join(group_summary(group) for group in selection.common[:2]))
                + "</p>"
            )
        if selection.local or selection.common or selection.unrelated_count:
            pieces.append(
                '<p><a href="limitations">Открыть ограничения и исходные сообщения</a></p>'
            )
        pieces.extend(
            f"<p>{html.escape(location.get('source_name', ''))} · строки "
            f"{location.get('line_start') or 'не указаны'}–"
            f"{location.get('line_end') or location.get('line_start') or 'не указаны'}</p>"
            for location in locations
        )
        if fragments:
            pieces.append("<h3>Сохранённые фрагменты</h3>")
            pieces.extend(
                "<p style='font-family:Consolas;white-space:pre-wrap'>"
                + html.escape(fragment["text"]).replace("\n", "<br>")
                + "</p>"
                for fragment in fragments
            )
        else:
            pieces.append(
                "<p>Фрагмент не сохранён. Подключите исходник с совпадающим SHA-256 "
                "в разделе устройств.</p>"
            )
        self.finding_detail.setHtml("".join(pieces))
        mark = payload["mark"]
        self.mark_combo.setCurrentIndex(self.mark_combo.findData(mark.get("status", "new")))
        self.comment_edit.setPlainText(mark.get("comment", ""))

    def show_finding_json(self) -> None:
        selected = self._selected_payloads(
            self.finding_table,
            self.finding_proxy,
            self.finding_model,
        )
        if not selected:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Технический результат и доказательства")
        dialog.resize(900, 650)
        layout = QVBoxLayout(dialog)
        editor = QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setPlainText(
            _json(
                {
                    "finding": selected[0]["finding"],
                    "check": {
                        key: value
                        for key, value in selected[0]["check"].items()
                        if key != "findings"
                    },
                }
            )
        )
        layout.addWidget(editor)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def save_marks(self) -> None:
        if not self.run_id:
            return
        payloads = self._selected_payloads(
            self.finding_table, self.finding_proxy, self.finding_model
        )
        for payload in payloads:
            self.store.set_finding_mark(
                payload["item"].get("run_id") or self.run_id,
                str(payload["finding"]["finding_id"]),
                self.mark_combo.currentData(),
                self.comment_edit.toPlainText(),
            )
        self.refresh_findings()
        self.progress_label.setText(
            f"Сохранены решения для находок: {len(payloads)}. "
            "Исходные результаты проверок сохранены."
        )

    def attach_finding_source(self) -> None:
        selected = self._selected_payloads(
            self.finding_table, self.finding_proxy, self.finding_model
        )
        if not selected or self._batch_active or self._restore_busy:
            return
        filename, _ = QFileDialog.getOpenFileName(
            self, "Исходник доказательства · проверка SHA-256"
        )
        if filename:
            self.attach_source(selected[0]["item"]["id"], Path(filename))

    def open_finding_rules(self) -> None:
        selected = self._selected_payloads(
            self.finding_table, self.finding_proxy, self.finding_model
        )
        if not selected:
            return
        payload = selected[0]
        run_id = payload["item"].get("run_id") or self.run_id
        if not run_id:
            return
        if self._batch_active or self._restore_busy:
            self.progress_label.setText("Дождитесь завершения текущей проверки.")
            return
        self.workspace_history.remember()
        if run_id != self.run_id:
            self.load_run(run_id)
        self.rule_scope.setCurrentIndex(self.rule_scope.findData("run"))
        self.rule_search.clear()
        self._refresh_rules()
        self.navigate("rules", remember=False)
        self.rules_table.clearSelection()
        ids = payload["finding"].get("affected_rule_ids", [])
        for row, candidate in enumerate(self.rules_model.payloads):
            if (
                candidate["item"]["id"] == payload["item"]["id"]
                and candidate["value"].get("rule_id") in ids
            ):
                index = self.rules_proxy.mapFromSource(self.rules_model.index(row, 0))
                self.rules_table.selectionModel().select(
                    index,
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows,
                )
                self.rules_table.scrollTo(index)

    def _project_devices(self) -> list[dict[str, Any]]:
        return self.store.list_project_devices(self.project_id) if self.project_id else []

    def _cloud_scans(self) -> list[dict[str, Any]]:
        return self.store.list_cloud_scans(self.project_id) if self.project_id else []

    def _cloud_history_changed(self) -> None:
        if not self._loading_settings:
            self._refresh_devices()
            self._refresh_rules()
            self._refresh_history()
            self._refresh_summary()
            self._refresh_project_map()

    def open_resource_operation(self) -> None:
        selected = self._selected_payloads(self.device_table, self.device_proxy, self.device_model)
        if not selected:
            return
        item = selected[0]
        if self._batch_active or self._restore_busy:
            self.progress_label.setText("Дождитесь завершения текущей проверки.")
            return
        self.workspace_history.remember()
        if item.get("kind") == "cloud":
            self.navigate("scans", remember=False)
            self.cloud_panel.open_result(item["scan"]["id"])
        else:
            run_id = item.get("run_id") or self.run_id
            if not run_id:
                return
            self.load_run(run_id)
            self.navigate("reports", remember=False)

    def _refresh_devices(self, *_: Any) -> None:
        self._refresh_context()
        self._clear_map_selection()
        rows: list[tuple[Any, ...]] = []
        items = (
            self._project_devices()
            if self.device_scope.currentData() == "project"
            else self._items()
        )
        if self.device_scope.currentData() == "project":
            items = [*items, *cloud_resources(self._cloud_scans())]
            error_runs = (
                [self.store.get_run(run["id"]) for run in self.store.list_runs(self.project_id)]
                if self.project_id
                else []
            )
        else:
            error_runs = [self.run] if self.run else []
        self._import_error_items = [
            {**item, "run_id": run["id"], "run_created_at": run["created_at"]}
            for run in error_runs
            for item in run.get("items", [])
            if not item.get("report")
        ]
        error_scope = (
            "в истории проекта" if self.device_scope.currentData() == "project" else "в запуске"
        )
        self.import_errors_button.setText(
            f"Импорт не выполнен: {len(self._import_error_items)} записей {error_scope}"
        )
        self.import_errors_button.setEnabled(bool(self._import_error_items))

        def platform(item: dict[str, Any]) -> str:
            return str(
                "Cloud.ru " + item["platform"].capitalize()
                if item.get("kind") == "cloud"
                else (item.get("parse_result") or {}).get("configuration", {}).get("platform", "—")
            )

        def resource_type(item: dict[str, Any]) -> str:
            return str(item["record"]["type"]) if item.get("kind") == "cloud" else "device"

        for combo, title, values in (
            (self.resource_platform, "Все платформы", {platform(item) for item in items}),
            (self.resource_type, "Все типы", {resource_type(item) for item in items}),
        ):
            current = combo.currentData()
            combo.blockSignals(True)
            combo.clear()
            combo.addItem(title, "")
            for value in sorted(values):
                combo.addItem(
                    ALL_RESOURCES.get(value, "Устройство" if value == "device" else value), value
                )
            combo.setCurrentIndex(max(0, combo.findData(current)))
            combo.blockSignals(False)
        items = [
            item
            for item in items
            if self.resource_platform.currentData() in ("", platform(item))
            and self.resource_type.currentData() in ("", resource_type(item))
        ]
        kind = self.resource_kind.currentData()
        items = [item for item in items if not kind or item.get("kind", "device") == kind]
        self.infrastructure_hint.setText(
            "Последние наблюдения ресурсов; отсутствие в новом сборе не означает удаление."
            if items
            else "Ресурсов в выбранной области нет. Добавьте данные или измените фильтр."
        )
        self.device_detail.clear()
        self.device_rules_model.replace([], [])
        self.device_objects_model.replace([], [])
        self.resource_findings_model.replace([], [])
        self.resource_history_model.replace([], [])
        self.resource_source_detail.clear()
        self.resource_findings_hint.setText("Выберите ресурс для просмотра проблем.")
        for button in (
            self.attach_button,
            self.repeat_button,
            self.single_export_button,
            self.resource_operation_button,
        ):
            button.setEnabled(False)
        for item in items:
            if item.get("kind") == "cloud":
                record = item["record"]
                rows.append(
                    (
                        record.get("name") or record.get("id", "Без имени"),
                        "Cloud.ru " + item["platform"].capitalize(),
                        ALL_RESOURCES.get(record["type"], record["type"]),
                        "—",
                    )
                )
                continue
            report = item.get("report") or {}
            parsed = item.get("parse_result") or {}
            configuration = parsed.get("configuration") or {}
            name = report.get("device_id", item.get("source_name", ""))
            if not report:
                name += " · Импорт не выполнен"
            rows.append(
                (
                    name,
                    configuration.get("platform", "—") + " · версия не определена",
                    "Сетевое устройство" if report else "Источник без результата",
                    len(parsed.get("rules", [])) if parsed else "—",
                )
            )
        self.device_model.replace(rows, items)

    def _device_selected(self, *_: Any) -> None:
        items = self._selected_payloads(self.device_table, self.device_proxy, self.device_model)
        if len(items) != 1:
            self._clear_map_selection()
            self.device_detail.setPlainText(
                f"Выбрано ресурсов: {len(items)}. Выберите один для просмотра сведений."
                if items
                else "Выберите ресурс для просмотра сведений."
            )
            self.device_rules_model.replace([], [])
            self.device_objects_model.replace([], [])
            self.resource_findings_model.replace([], [])
            self.resource_history_model.replace([], [])
            self.resource_source_detail.clear()
            for button in (
                self.attach_button,
                self.repeat_button,
                self.single_export_button,
                self.resource_operation_button,
            ):
                button.setEnabled(False)
            return
        if items:
            item = items[0]
            self._refresh_map_items(item)
            self.resource_operation_button.setEnabled(True)
            self.resource_details.refresh(item)
            is_local = item.get("kind") != "cloud"
            for button in (self.attach_button, self.repeat_button, self.single_export_button):
                button.setEnabled(is_local and bool(item.get("report")))
            if not is_local:
                self._show_cloud_resource(item)
                return
            parsed = item.get("parse_result") or {}
            rules = parsed.get("rules", [])
            self.device_rules_model.replace(
                [
                    (
                        rule["sequence"],
                        rule["name"],
                        dict(rule_details(rule)).get("Действие", rule["action"]),
                        rule_endpoint_summary(rule, "sources"),
                        rule_endpoint_summary(rule, "destinations"),
                        rule_service_summary(rule),
                    )
                    for rule in rules
                ],
                rules,
            )
            objects = [
                (group, value)
                for group in ("endpoints", "services")
                for value in parsed.get(group, [])
            ]
            self.device_objects_model.replace(
                [
                    (
                        value.get("name", ""),
                        "Адресный объект" if group == "endpoints" else "Сервис",
                        object_summary(value),
                    )
                    for group, value in objects
                ],
                [value for _, value in objects],
            )
            report = item.get("report") or {}
            checks = "".join(
                f"<tr><td>{html.escape(CHECKS.get(check['check_id'], check['check_id']))}</td>"
                f"<td><a href='findings:{html.escape(check['check_id'], quote=True)}'>"
                f"{_check_count(check)}</a></td>"
                f"<td>{html.escape(check_status_label(check))}"
                + (
                    f" · <a href='check:{html.escape(check['check_id'], quote=True)}'>причины</a>"
                    if check.get("limitations")
                    else ""
                )
                + "</td></tr>"
                for check in report.get("checks", [])
            )
            groups = project_item_limitations(item)
            group_html = (
                "<ul>"
                + "".join(f"<li>{html.escape(group_summary(group))}</li>" for group in groups[:5])
                + "</ul>"
                f"<p>Всего групп: {len(groups)}. "
                "<a href='limitations'>Все исходные сообщения и связи</a></p>"
                if groups
                else "<p>В сохранённом результате ограничений не указано.</p>"
            )
            acquired = item.get("run_created_at") or (self.run or {}).get("created_at", "")
            self.device_detail.setHtml(
                f"<h2>{html.escape(report.get('device_id', item['source_name']))}</h2>"
                f"<p>Файл: {html.escape(item['source_name'])}</p>"
                f"<p>Получено: {html.escape(str(acquired))}</p>"
                f"<p>Разбор: {html.escape(IMPORT_STATES.get(item['status'], item['status']))}</p>"
                "<p>Платформа: "
                f"{html.escape(parsed.get('configuration', {}).get('platform', '—'))}; "
                "версия не определена.</p>"
                "<h3>Проверки</h3><table cellpadding='6'><tr>"
                "<th>Проверка</th><th>Найдено</th><th>Охват</th></tr>"
                f"{checks or '<tr><td>Результат анализа не получен</td></tr>'}</table>"
                "<h3>Ограничения и диагностика</h3>"
                + group_html
                + f"<p>SHA-256: {html.escape(item.get('content_sha256') or 'не определён')}</p>"
                "<p>Ноль находок не доказывает безопасность. Исходник после перезапуска "
                "подключается только при совпадении SHA-256.</p>"
            )

    def _show_cloud_resource(self, item: dict[str, Any]) -> None:
        record, scan = item["record"], item["scan"]
        self.device_rules_model.replace([], [])
        self.device_objects_model.replace([], [])
        data = record.get("data", {})
        rules = cloud_rule_values(record)
        self.device_rules_model.replace(
            [cloud_rule_columns(value) for value in rules],
            rules,
        )
        other = [
            (key, value)
            for key, value in data.items()
            if key not in {"firewall", "security_rules", "nat"}
        ]
        self.device_objects_model.replace(
            [(key, "Данные API", _json(value)) for key, value in other],
            [value for _, value in other],
        )
        self.device_detail.setHtml(
            f"<h2>{html.escape(record.get('name') or record.get('id', 'Ресурс'))}</h2>"
            f"<p>Cloud.ru {html.escape(item['platform'].capitalize())} · "
            f"{html.escape(ALL_RESOURCES.get(record['type'], record['type']))}</p>"
            f"<p>Получено: {html.escape(scan['created_at'])}</p>"
            f"<p>Сбор: {html.escape(SCAN_STATES.get(scan['state'], scan['state']))}</p>"
            f"<p>Получено правил: {len(rules)}. Каждое правило доступно на вкладке «Правила».</p>"
            "<p>Проверки недоступны. Сбор данных не подтверждает безопасность или достижимость.</p>"
            "<h3>Параметры ресурса</h3>"
            f"<pre>{html.escape(_json(record.get('inventory', {})))}</pre>"
            "<p>Ошибки и запросы доступны в исходной операции сбора.</p>"
        )

    def _refresh_rules(self, *_: Any) -> None:
        self._refresh_context()
        rows, payloads = [], []
        items = (
            self._project_devices() if self.rule_scope.currentData() == "project" else self._items()
        )
        self.rule_detail.clear()
        for item in items:
            parsed = item.get("parse_result") or {}
            device = (item.get("report") or {}).get("device_id", "")
            for rule in parsed.get("rules", []):
                rows.append(
                    (
                        device,
                        rule["sequence"],
                        rule["name"],
                        dict(rule_details(rule)).get("Действие", rule["action"]),
                        rule_endpoint_summary(rule, "sources"),
                        rule_endpoint_summary(rule, "destinations"),
                        rule_service_summary(rule),
                    )
                )
                payloads.append(
                    {
                        "item": item,
                        "value": rule,
                        "search_text": "\n".join(value for _, value in rule_details(rule)),
                    }
                )
            for group in ("endpoints", "services"):
                for value in parsed.get(group, []):
                    rows.append(
                        (
                            device,
                            "—",
                            value.get("name", ""),
                            "Адресный объект" if group == "endpoints" else "Сервис",
                            "—",
                            "—",
                            object_summary(value),
                        )
                    )
                    payloads.append(
                        {
                            "item": item,
                            "value": value,
                            "search_text": "\n".join(text for _, text in object_details(value)),
                        }
                    )
        cloud_count = 0
        if self.rule_scope.currentData() == "project":
            for item in cloud_resources(self._cloud_scans()):
                device = item["record"].get("name") or item["record"].get("id", "Cloud.ru")
                for value in cloud_rule_values(item["record"]):
                    rows.append((device, *cloud_rule_columns(value)))
                    payloads.append(
                        {
                            "item": item,
                            "value": value,
                            "search_text": "\n".join(
                                text for _, text in cloud_rule_details(item, value)
                            ),
                        }
                    )
                    cloud_count += 1
        self.rule_inventory_status.setText(
            f"Правил и объектов в таблице: {len(rows)} · облачных правил: {cloud_count}. "
            + (
                "Облачные правила получены через API; проверки для них не выполнялись."
                if self.rule_scope.currentData() == "project"
                else "Выбран файловый запуск; облачные сборы доступны "
                "в области «Все ресурсы проекта»."
            )
        )
        self.rules_model.replace(rows, payloads)

    def _rule_selected(self, *_: Any) -> None:
        selected = self._selected_payloads(self.rules_table, self.rules_proxy, self.rules_model)
        if len(selected) != 1:
            self._clear_map_selection()
            self.rule_detail.setPlainText(
                f"Выбрано: {len(selected)}. Выберите одно правило или объект для подробностей."
                if selected
                else "Выберите правило или объект."
            )
            return
        if selected:
            value = selected[0]["value"]
            item = selected[0]["item"]
            if value.get("cloud_rule"):
                self._clear_map_selection()
                self.rule_detail.setHtml(
                    f"<h3>{html.escape(value['name'])}</h3>"
                    + _fields_html(cloud_rule_details(item, value))
                )
                return
            fields = rule_details(value) if "rule_id" in value else object_details(value)
            self._refresh_map_items(item)
            self.rule_detail.setHtml(
                f"<h3>{html.escape(value.get('name', 'Правило / объект'))}</h3>"
                f"<p>Источник: {html.escape(item.get('source_name', '—'))}; "
                f"SHA-256: {html.escape(item.get('content_sha256') or 'не определён')}</p>"
                + _fields_html(fields)
            )

    def _refresh_summary(self) -> None:
        devices = self._project_devices()
        scans = self._cloud_scans()
        self.cloud_summary_label.setText(
            f"Облачных ресурсов: {len(cloud_resources(scans))} · "
            + (
                f"последний сбор: {scans[0]['created_at']} · "
                f"{SCAN_STATES.get(scans[0]['state'], scans[0]['state'])} · "
                f"ошибок: {len(scans[0].get('result', {}).get('errors', []))}"
                if scans
                else "сбор ещё не выполнялся"
            )
        )
        self.device_count_label.setText(f"Устройств проекта: {len(devices)}")
        vendors = Counter(
            (item.get("parse_result") or {}).get("configuration", {}).get("vendor", "unknown")
            for item in devices
        )
        vendor_labels = {
            "cisco": "Cisco",
            "hp_aruba": "HP/Aruba",
            "hp-aruba": "HP/Aruba",
            "hp-h3c": "HP/H3C (Comware)",
            "aruba": "HP/Aruba",
            "hp": "HP",
            "huawei": "Huawei",
            "juniper": "Juniper",
            "h3c": "H3C",
            "unknown": "Не определён",
        }
        self.vendor_model.replace(
            [(vendor_labels.get(key, key), count) for key, count in sorted(vendors.items())]
        )
        runs = self.store.list_runs(self.project_id) if self.project_id else []
        self.report_run.blockSignals(True)
        self.report_run.clear()
        for run in runs:
            self.report_run.addItem(f"{run['created_at']} · {run['id']}", run["id"])
        self.report_run.setCurrentIndex(self.report_run.findData(self.run_id))
        self.report_run.setEnabled(not self._batch_active and not self._restore_busy)
        self.report_run.blockSignals(False)
        operations = project_operations(runs, scans)[:3]
        self.activity_text.setHtml(
            "<b>Последние операции</b><br>"
            + "<br>".join(
                f"{html.escape(operation['created_at'])} · "
                f"{'Проверка' if operation['operation_kind'] == 'check' else 'Сбор'} · "
                f"{html.escape(SCAN_STATES.get(operation['state'], operation['state']))}"
                for operation in operations
            )
            + '<br><a href="history">Открыть историю операций</a>'
            if operations
            else "Операций пока нет. Начните с кнопки «Добавить данные»."
        )
        last = next((run for run in runs if run.get("finished_at")), None)
        if last is None:
            self.last_check_label.setText("Последняя проверка: ещё не выполнялась")
            self.summary_label.setText(
                "Добавьте конфигурации через «Добавить данные» и запустите проверку."
            )
            self.coverage_text.setPlainText("Результатов завершённых проверок пока нет.")
        else:
            latest = self.store.get_run(last["id"])
            items = latest["items"]
            states = Counter(item["status"] for item in items)
            findings = Counter(
                finding["severity"]
                for item in items
                for check in (item.get("report") or {}).get("checks", [])
                for finding in check["findings"]
            )
            state = {"completed": "Завершён", "cancelled": "Отменён", "interrupted": "Прерван"}.get(
                last["state"], last["state"]
            )
            if last["state"] == "completed" and (
                states["partial"] or any(not item.get("report") for item in items)
            ):
                state = "Завершён с ограничениями / ошибками"
            checked_at = datetime.fromisoformat(last["finished_at"]).astimezone()
            self.last_check_label.setText(
                f"Последняя проверка: {checked_at:%d.%m.%Y %H:%M} · {state}"
            )
            analyzed_devices = {item["report"]["device_id"] for item in items if item.get("report")}
            self.summary_label.setText(
                f"Последняя проверка: устройств {len(analyzed_devices)} · файлов {len(items)} · "
                f"частичных {states['partial']} · "
                f"без результата {sum(not item.get('report') for item in items)}"
            )
            self.coverage_text.setHtml(
                "<h3>Находки последней проверки</h3><p>"
                + " · ".join(
                    f'<a href="{key}">{SEVERITIES[key]}: {findings[key]}</a>' for key in SEVERITIES
                )
                + "</p><p>Ноль находок не доказывает безопасность. "
                "Частичный разбор ограничивает выводы.</p>"
            )
        if not self.run:
            self.report_summary.setPlainText("Откройте или выполните запуск анализа.")
            return
        rows = []
        for item in self._items():
            report = item.get("report") or {}
            for check in report.get("checks", []):
                rows.append(
                    f"<tr><td>{html.escape(report['device_id'])}</td>"
                    f"<td>{html.escape(CHECKS.get(check['check_id'], check['check_id']))}</td>"
                    f"<td>{html.escape(check_status_label(check))}</td>"
                    f"<td>{_check_count(check)}</td>"
                    f"<td>{len(check_limitations(item, check))} групп</td></tr>"
                )
        limitation_rows = "".join(
            f"<p>{html.escape(item.get('source_name', '—'))}: "
            f"<a href='{html.escape(str(item['id']), quote=True)}'>"
            f"Ограничения и исходные сообщения: {len(project_item_limitations(item))} групп</a></p>"
            for item in self._items()
            if project_item_limitations(item)
        )
        self.report_summary.setHtml(
            "<h3>Охват выбранного запуска</h3><table cellpadding='7'><tr><th>Устройство</th>"
            "<th>Проверка</th><th>Выполнение</th><th>Находки</th><th>Причины ограничений</th></tr>"
            + "".join(rows)
            + "</table>"
            + limitation_rows
        )

    def _refresh_history(self) -> None:
        runs = self.store.list_runs(self.project_id) if self.project_id else []
        operations = project_operations(runs, self._cloud_scans())
        self.history_model.replace(
            [
                (
                    run.get("created_at", ""),
                    "Проверка" if run["operation_kind"] == "check" else "Сбор",
                    SCAN_STATES.get(run["state"], run["state"]),
                    run.get("item_count", len(run.get("result", {}).get("records", []))),
                    run.get("finding_count", len(run.get("result", {}).get("errors", []))),
                    run["id"],
                )
                for run in operations
            ],
            operations,
        )

    def _open_history(self, *_: Any) -> None:
        selected = self._selected_payloads(
            self.history_table, self.history_proxy, self.history_model
        )
        if selected and not self._batch_active:
            self.workspace_history.remember()
            if selected[0]["operation_kind"] == "collection":
                self.navigate("scans", remember=False)
                self.cloud_panel.open_result(selected[0]["id"])
            else:
                self.load_run(selected[0]["id"])
                self.finding_scope.setCurrentIndex(self.finding_scope.findData("run"))
                self.navigate("findings", remember=False)

    def compare_selected_runs(self) -> None:
        selected = self._selected_payloads(
            self.history_table, self.history_proxy, self.history_model
        )
        if len(selected) != 2:
            self.history_detail.setPlainText("Выберите ровно два запуска (Ctrl + щелчок).")
            return
        if any(run.get("operation_kind") == "collection" for run in selected):
            self.history_detail.setPlainText(
                "Сравнение находок доступно для двух проверок. Облачный сбор не выполняет checks."
            )
            return
        runs = [
            self.store.get_run(run["id"])
            for run in sorted(selected, key=lambda run: run.get("created_at", ""))
        ]

        def signatures(run: dict[str, Any]) -> Counter[Any]:
            return Counter(
                (
                    report["device_id"],
                    check["check_id"],
                    finding["title"],
                    tuple(finding["affected_rule_ids"]),
                )
                for item in run["items"]
                for report in [item.get("report") or {}]
                for check in report.get("checks", [])
                for finding in check["findings"]
            )

        before, after = map(signatures, runs)
        self.history_detail.setPlainText(
            f"Раньше находок: {sum(before.values())}; сейчас: {sum(after.values())}\n"
            f"Появились в результатах: {sum((after - before).values())}\n"
            f"Отсутствуют в новых результатах: {sum((before - after).values())}\n\n"
            "Это различия результатов, а не подтверждение устранения: "
            "изменились правила, полнота или входные данные. "
            "Решения пользователя между запусками не переносятся.\n\n"
            + _json(
                {
                    "new": list((after - before).elements()),
                    "absent": list((before - after).elements()),
                }
            )
        )

    def export_batch(self, kind: str, path: Path | None = None) -> None:
        if not self.run_id:
            self.progress_label.setText("Сначала выполните или откройте запуск анализа.")
            return
        if path is None:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Сохранить отчёт", f"analysis.{kind}", f"Отчёт (*.{kind})"
            )
            if not filename:
                return
            path = Path(filename)
        from firewall_compliance.interfaces.desktop.batch_reports import (
            export_batch_html,
            export_batch_json,
        )

        exporter = export_batch_html if kind == "html" else export_batch_json
        try:
            exporter(
                self.store, self.run_id, path, include_fragments=self.fragments_check.isChecked()
            )
            self.progress_label.setText(f"Отчёт сохранён: {path.name}")
        except (OSError, ValueError):
            QMessageBox.warning(
                self, "Отчёт", "Не удалось сохранить отчёт. Проверьте папку и доступ к файлу."
            )

    def _save_report_settings(self, checked: bool) -> None:
        if self.project_id:
            self.store.update_settings(self.project_id, {"include_fragments": checked})

    def export_single(self) -> None:
        selected = self._selected_payloads(self.device_table, self.device_proxy, self.device_model)
        if not selected or not selected[0].get("report"):
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Исходный результат", "result.json", "JSON (*.json)"
        )
        if filename:
            try:
                Path(filename).write_text(_json(selected[0]["report"]), encoding="utf-8")
            except OSError:
                QMessageBox.warning(self, "Экспорт", "Не удалось сохранить файл.")

    def attach_selected_source(self) -> None:
        selected = self._selected_payloads(self.device_table, self.device_proxy, self.device_model)
        if not selected or not selected[0].get("report") or self._batch_active:
            return
        filename, _ = QFileDialog.getOpenFileName(self, "Подключить исходник с совпадающим SHA-256")
        if filename:
            self.attach_source(selected[0]["id"], Path(filename))

    def preview_selected_source(self) -> None:
        selected = self._selected_payloads(self.device_table, self.device_proxy, self.device_model)
        if not selected:
            return
        session = self.sessions.get(str(selected[0]["id"]))
        if session is None:
            self.progress_label.setText(
                "Подключите исходник с совпадающим SHA-256 для просмотра других строк."
            )
            return
        try:
            location = SourceLocation(
                source_name=session.source.source_name,
                line_start=self.line_start.value(),
                line_end=self.line_end.value(),
            )
            preview = source_preview(session, location)
            self.resource_source_detail.setPlainText(preview)
            self.device_detail.setPlainText(preview)
        except ValueError:
            self.progress_label.setText("Укажите существующий диапазон не более 200 строк.")

    def attach_source(self, item_id: str, path: Path) -> None:
        """Восстановить только проверенный снимок; изменившийся файл добавить в новую очередь."""
        self._restore_busy = True
        self._set_controls_busy(True)

        def work() -> object:
            from firewall_compliance.interfaces.desktop.project_store import SourceMismatchError

            try:
                return self.store.attach_source(item_id, path)
            except SourceMismatchError:
                return {"source_changed": True}

        def done(result: object) -> None:
            self._restore_busy = False
            self._set_controls_busy(False)
            if isinstance(result, AnalysisSession):
                self._map_live_item_ids.discard(str(item_id))
                self.sessions[str(item_id)] = result
                self.progress_label.setText(
                    "Исходник совпадает с сохранённым SHA-256. "
                    "Доступны повторные проверки и полный просмотр доказательств."
                )
                refresher = getattr(self.advanced_panel, "refresh_sessions", None)
                if callable(refresher):
                    refresher()
                self._refresh_map_items()
            elif isinstance(result, dict) and result.get("source_changed"):
                self.progress_label.setText(
                    "Исходник не подключён. Изменившийся файл добавлен для отдельного запуска; "
                    "старые доказательства сохранены."
                )
                self.stage_paths([path])
            else:
                message = (
                    result.message
                    if isinstance(result, JobError)
                    else "Не удалось подключить исходник"
                )
                self.progress_label.setText(message)
            self._refresh_staged()

        self.runner.submit(work, done)

    def repeat_selected(self) -> None:
        selected = self._selected_payloads(self.device_table, self.device_proxy, self.device_model)
        if not selected or self._batch_active or self._restore_busy:
            return
        session = self.sessions.get(str(selected[0]["id"]))
        if session is None:
            self.progress_label.setText(
                "Для повторных проверок подключите исходник с совпадающим SHA-256."
            )
            return
        require_logging = self.logging_check.isChecked()
        require_comments = self.comments_check.isChecked()
        try:
            management_profile = self.management_settings.profile()
        except ValueError:
            self._open_check_settings()
            return
        enabled_check_ids = tuple(key for key, box in self.check_boxes.items() if box.isChecked())
        if not enabled_check_ids:
            self.progress_label.setText("Выберите хотя бы одну проверку в настройках.")
            return
        self.store.update_settings(
            self.project_id,
            {
                "require_logging": require_logging,
                "require_comments": require_comments,
                "management_profile": management_profile.model_dump(mode="json"),
                "enabled_check_ids": enabled_check_ids,
            },
        )
        result = self.store.create_run(self.project_id)
        new_run = result["id"] if isinstance(result, dict) else str(result)
        self._restore_busy = True
        self._aux_run_id = new_run
        self._set_controls_busy(True)

        def done(outcome: object) -> None:
            if isinstance(outcome, AnalysisSession):
                item_id = self.store.record_session(new_run, outcome)
                self.sessions = {str(item_id): outcome}
                self._map_live_item_ids = {str(item_id)}
            else:
                self.store.record_error(new_run, session.path, "Повторные проверки не завершены")
            self.store.finish_run(new_run)
            self._aux_run_id = None
            self._restore_busy = False
            self._set_controls_busy(False)
            self.load_run(new_run)

        self.runner.submit(
            lambda: reanalyze_session(
                session,
                require_logging=require_logging,
                require_comments=require_comments,
                enabled_check_ids=enabled_check_ids,
                management_profile=management_profile,
            ),
            done,
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        """Отключить поздние callbacks без ожидания выполняющегося worker."""
        self._closed = True
        self.cloud_panel.close()
        self.timer.stop()
        if self.run_id and self._batch_active:
            for job_id, item in self._analysis_jobs.items():
                if self.runner.status(job_id) == JobStatus.RUNNING:
                    self.store.record_error(
                        self.run_id, item["path"], "Окно закрыто до получения результата задания"
                    )
                else:
                    self.store.record_cancelled(self.run_id, item["path"])
            self.store.finish_run(self.run_id, state="interrupted")
        if self._aux_run_id:
            self.store.finish_run(self._aux_run_id, state="interrupted")
        self.runner.shutdown()
        event.accept()


def main() -> None:
    """Запустить локальное Qt приложение."""
    app = QApplication.instance() or QApplication(sys.argv)
    if not isinstance(app, QApplication):
        raise RuntimeError("Для desktop требуется QApplication")
    app.setApplicationName("Firewall Compliance")
    app.setOrganizationName("FirewallCompliance")
    apply_theme(app)
    try:
        window = MainWindow()
    except (OSError, sqlite3.Error, ValueError):
        QMessageBox.critical(
            None,
            "Firewall Compliance",
            "Не удалось открыть локальное хранилище проектов. "
            "Проверьте доступ к папке FirewallCompliance в профиле Windows.",
        )
        return
    window.show()
    try:
        app.exec()
    finally:
        dispose_window(window)
        del window
        gc.collect()


def dispose_window(window: MainWindow) -> None:
    """Удалить Qt объекты в GUI-потоке до уничтожения QApplication."""
    window.close()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    gc.collect()


if __name__ == "__main__":
    main()
