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
from queue import Empty, Queue
from threading import Event
from typing import Any, Literal

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
    QListWidget,
    QListWidgetItem,
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

from firewall_compliance.application.cloud_analysis import vmware_device_id
from firewall_compliance.application.inspection_cycle import CycleProgress
from firewall_compliance.checks.management.rules import MANAGEMENT_CHECKS
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
from firewall_compliance.interfaces.desktop.check_selection import CheckSelection
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
from firewall_compliance.interfaces.desktop.cycle_backend import (
    FileCycleInput,
    FileCycleResult,
    run_file_cycle,
)
from firewall_compliance.interfaces.desktop.dashboard import build_dashboard
from firewall_compliance.interfaces.desktop.infrastructure_observations import project_observations
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
from firewall_compliance.interfaces.desktop.qt_rule_query import RuleQueryWidget
from firewall_compliance.interfaces.desktop.policy_exposure_settings import PolicyExposureSettings
from firewall_compliance.interfaces.desktop.policy_scope_settings import PolicyScopeSettings
from firewall_compliance.interfaces.desktop.project_map import build_project_map
from firewall_compliance.interfaces.desktop.project_snapshot import (
    ProjectSnapshot,
    read_project_snapshot,
    scoped_project_snapshot,
)
from firewall_compliance.interfaces.desktop.qt_acl_map import (
    AclMapState,
    AclMapWidget,
    build_map_state,
)
from firewall_compliance.interfaces.desktop.qt_controls import ControlsPanel
from firewall_compliance.interfaces.desktop.qt_dashboard import ProjectDashboard
from firewall_compliance.interfaces.desktop.qt_governance import GovernancePanel
from firewall_compliance.interfaces.desktop.qt_infrastructure_registry import (
    InfrastructureRegistryPanel,
)
from firewall_compliance.interfaces.desktop.qt_models import RowsModel
from firewall_compliance.interfaces.desktop.qt_network import NetworkFactsSnapshot
from firewall_compliance.interfaces.desktop.qt_project_map import ProjectMapWidget
from firewall_compliance.interfaces.desktop.qt_theme import apply_theme
from firewall_compliance.interfaces.desktop.qt_topology_map import TopologyMapWidget
from firewall_compliance.interfaces.desktop.resource_details import ResourceDetails
from firewall_compliance.interfaces.desktop.switch_details import (
    PURPOSE_LABELS,
    SwitchDetailsPanel,
    SwitchTopologyPanel,
    acl_rule_html,
    rule_category,
    safe_switch_source,
    switch_summary,
)
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
    "FW-PARTIAL-SHADOWED": "Частичное затенение",
    "FW-UNION-SHADOWED": "Покрытие несколькими правилами",
    "FW-DANGEROUS-SERVICES": "Запрещённые организацией сервисы",
    "FW-ADMIN-UNTRUSTED": "Административные сервисы из недоверенных сетей",
    "FW-EXCESSIVE-ACCESS": "Избыточная ширина и ролевой доступ",
    "FW-ACL-ATTACHMENT": "Привязки ACL и обязательная фильтрация",
    **{key: values[1] for key, values in MANAGEMENT_CHECKS.items()},
}
OPTIONAL_SCOPE_CHECKS = {"FW-EXCESSIVE-ACCESS", "FW-ACL-ATTACHMENT"}


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
        defer_startup: bool = False,
    ) -> None:
        super().__init__()
        self.store = store
        self._defer_startup = defer_startup
        self._ui_ready = False
        self._project_load_ticket: object | None = None
        self._project_snapshot: ProjectSnapshot | None = None
        self._site_selection: str | None = None
        self._site_reload_ticket: object | None = None
        self._snapshot_token: tuple[Any, ...] | None = None
        self._dirty_pages: set[str] = set(SECTION_IDS)
        self._map_pending_item: dict[str, Any] | None = None
        self._advanced_widget_factory = advanced_widget_factory
        self._inventory_evidence_token: tuple[Any, ...] | None = None
        self._inventory_runs: list[dict[str, Any]] = []
        self._inventory_scans: list[dict[str, Any]] = []
        self._analysis_network_snapshot: Any = None
        self._analysis_result_active: Any = None
        self._analysis_result_active_id: str | None = None
        self._analysis_result_ticket: object | None = None
        self._analysis_list_ticket: object | None = None
        self._analysis_result_busy = False
        self._analysis_result_save_id: Any = None
        self._acl_map_epoch = object()
        self._acl_map_busy = False
        self._acl_map_job_ticket: object | None = None
        self._acl_map_job_id: Any = None
        self._acl_map_load_id: Any = None
        self._acl_map_list_ticket: object | None = None
        self._acl_map_load_ticket: object | None = None
        self._acl_map_run_ticket: object | None = None
        self._acl_map_records: dict[str, dict[str, Any]] = {}
        self._acl_map_loaded_record: dict[str, Any] | None = None
        self._acl_map_batch_result: Any = None
        self.runner = JobRunner()
        self.project_id: str | None = None
        self.run_id: str | None = None
        self.run: dict[str, Any] | None = None
        self.sessions: dict[str, AnalysisSession] = {}
        self._map_live_item_ids: set[str] = set()
        self.staged: list[dict[str, Any]] = []
        self._preflight_jobs: set[Any] = set()
        self._analysis_jobs: dict[Any, dict[str, Any]] = {}
        self._cycle_job_id: Any = None
        self._cycle_run_id: str | None = None
        self._cycle_project_id: str | None = None
        self._cycle_epoch: object | None = None
        self._cycle_cancel = Event()
        self._cycle_progress: Queue[CycleProgress | str] = Queue()
        self._aggregate_tasks: dict[tuple[str, str], dict[str, Any]] = {}
        self._start_after_preflight = False
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
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_jobs)
        self.timer.start(80)
        if defer_startup:
            self._show_startup_loading("Открываем локальное хранилище проектов…")
            QTimer.singleShot(0, self._load_workspace)
        else:
            if self.store is None:
                from firewall_compliance.interfaces.desktop.project_store import ProjectStore

                self.store = ProjectStore()
            self._finish_workspace()

    def _show_startup_loading(self, message: str, *, failed: bool = False) -> None:
        loading = QWidget()
        layout = QVBoxLayout(loading)
        layout.addStretch()
        self._startup_message = _label(message)
        layout.addWidget(self._startup_message)
        self._startup_indicator = QProgressBar()
        self._startup_indicator.setRange(0, 0)
        self._startup_indicator.setVisible(not failed)
        layout.addWidget(self._startup_indicator)
        self._startup_retry = _button("Повторить загрузку", self._load_workspace)
        self._startup_retry.setVisible(failed)
        layout.addWidget(self._startup_retry)
        layout.addStretch()
        self.setCentralWidget(loading)

    def _load_workspace(self) -> None:
        if self._closed:
            return
        self._startup_retry.hide()
        self._startup_indicator.show()
        self._startup_message.setText("Открываем локальное хранилище проектов…")

        def work() -> object:
            from firewall_compliance.interfaces.desktop.project_store import ProjectStore

            store = self.store if self.store is not None else ProjectStore()
            return store, store.list_projects()

        def done(value: object) -> None:
            if self._closed:
                return
            if not isinstance(value, tuple):
                self._show_startup_loading(
                    "Не удалось открыть хранилище. Проверьте доступ к папке FirewallCompliance.",
                    failed=True,
                )
                return
            self.store, projects = value
            try:
                self._finish_workspace(projects)
            except (OSError, sqlite3.Error, ValueError):
                self._ui_ready = False
                for name in ("controls_panel", "governance_panel"):
                    panel = getattr(self, name, None)
                    if panel is not None:
                        panel.shutdown()
                cloud = getattr(self, "cloud_panel", None)
                if cloud is not None:
                    cloud.close()
                self._show_startup_loading(
                    "Не удалось подготовить рабочее место. Проверьте локальное хранилище.",
                    failed=True,
                )

        self.runner.submit(work, done)

    def _finish_workspace(self, projects: list[dict[str, Any]] | None = None) -> None:
        self._build(self._advanced_widget_factory)
        self._ui_ready = True
        self.refresh_projects(projects=projects)

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
        scope_row = QHBoxLayout()
        scope_row.addWidget(_label("Область просмотра"))
        self.sites_button = _button("Площадки", self._open_workspace_sites)
        self.site_selector = QComboBox()
        self.site_selector.setAccessibleName("Область площадок")
        self.site_selector.addItem("Все площадки", None)
        self.site_selector.currentIndexChanged.connect(self._site_changed)
        scope_row.addWidget(self.site_selector)
        scope_row.addWidget(self.sites_button)
        scope_row.addStretch()
        self.add_data_button = _button("Добавить данные", self.choose_data_source, primary=True)
        header.addWidget(self.add_data_button)
        self.prepare_button = _button("Обновить и проверить", self.update_and_check)
        header.addWidget(self.prepare_button)
        self.tasks_button = _button("Задачи", self._open_task_center)
        header.addWidget(self.tasks_button)
        self.run_button = _button("Запустить проверку файлов", self.start_analysis, primary=True)
        self.run_button.setEnabled(False)
        root.addLayout(header)
        root.addLayout(scope_row)
        self.site_scope_note = _label("", muted=True)
        self.site_scope_note.setWordWrap(True)
        self.site_scope_note.hide()
        body = QHBoxLayout()
        sidebar = QWidget()
        sidebar.setFixedWidth(252)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        self.navigation = QTreeWidget()
        self.navigation.setObjectName("navigation")
        self.navigation.setHeaderHidden(True)
        self.navigation.setRootIsDecorated(True)
        self.navigation.setIndentation(18)
        self.navigation.setExpandsOnDoubleClick(False)
        self.navigation.setAccessibleName("Разделы приложения")
        self.nav_items: dict[str, QTreeWidgetItem] = {}
        self.settings_tree_items: dict[str, QTreeWidgetItem] = {}
        for section in WORKSPACE_SECTIONS:
            item = QTreeWidgetItem(self.navigation, [section.title])
            if section.key == "home":
                item.setData(0, Qt.ItemDataRole.UserRole, "home")
                self.nav_items["home"] = item
            else:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                for page_id, title in section.pages:
                    child = QTreeWidgetItem(item, [title])
                    if page_id == "matrix":
                        child.setFlags(child.flags() & ~Qt.ItemFlag.ItemIsEnabled)
                    else:
                        child.setData(0, Qt.ItemDataRole.UserRole, page_id)
                        self.nav_items[page_id] = child
                item.setExpanded(True)
        reports_item = QTreeWidgetItem(self.navigation, ["Отчёты"])
        reports_item.setFlags(reports_item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
        self.settings_tree = QTreeWidgetItem(self.navigation, ["Настройки"])
        self.settings_tree.setFlags(self.settings_tree.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        for key, title in (
            ("general", "Общие"), ("integrations", "Интеграции"),
            ("rules", "Проверки"), ("license", "Лицензия"),
            ("documentation", "Документация"),
        ):
            child = QTreeWidgetItem(self.settings_tree, [title])
            self.settings_tree_items[key] = child
            if key in ("integrations", "rules"):
                child.setData(0, Qt.ItemDataRole.UserRole, "settings:" + key)
            else:
                child.setFlags(child.flags() & ~Qt.ItemFlag.ItemIsEnabled)
        self.settings_tree.setExpanded(True)
        self.navigation.itemClicked.connect(self._navigation_clicked)
        self.navigation.currentItemChanged.connect(self._navigation_changed)
        sidebar_layout.addWidget(self.navigation, 1)
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
        query_results = getattr(self.advanced_panel, "query_result_changed", None)
        if query_results is not None:
            query_results.connect(self._capture_analysis_network_result)
        self.pages.addWidget(self.advanced_panel)
        self._build_map()
        self.cloud_panel = CloudPanel(self.store, self)
        self.cloud_panel.configure_button.clicked.connect(self._configure_cloud)
        self.cloud_panel.on_open_analysis = self._open_cloud_analysis
        self._build_settings()
        for key, title in self.check_settings_groups:
            child = QTreeWidgetItem(self.settings_tree_items["rules"], [title])
            child.setData(0, Qt.ItemDataRole.UserRole, "checks:" + key)
            self.settings_tree_items["checks:" + key] = child
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
        _, outer_layout = self._page("Дашборд", "")
        dashboard = QWidget()
        layout = QVBoxLayout(dashboard)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        self.overview_scroll = QScrollArea()
        self.overview_scroll.setWidgetResizable(True)
        self.overview_scroll.setWidget(dashboard)
        outer_layout.addWidget(self.overview_scroll, 1)
        self.overview_scroll.hide()
        self.compact_dashboard = ProjectDashboard(self)
        self.compact_dashboard.navigation_requested.connect(self.navigate)
        self.compact_dashboard.severity_requested.connect(self.open_overview_findings)
        outer_layout.addWidget(self.compact_dashboard, 1)
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
        self.map_mode_selector.addItem("Структура коммутаторов", "switches")
        mode_label = _label("Режим:")
        mode_label.setBuddy(self.map_mode_selector)
        source_row.addWidget(mode_label)
        source_row.addWidget(self.map_mode_selector)
        self.map_sources_button = QPushButton("Источники…")
        self.map_sources_button.setCheckable(True)
        source_row.addWidget(self.map_sources_button)
        self.map_saved_panel_button = QPushButton("Архив ACL…")
        self.map_saved_panel_button.setToolTip("Сохранённые и пакетные карты ACL проекта")
        self.map_saved_panel_button.setCheckable(True)
        source_row.addWidget(self.map_saved_panel_button)
        layout.addLayout(source_row)
        self._build_acl_map_project_panel(layout)
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
        self.switch_topology_widget = SwitchTopologyPanel(self)
        self.project_map_widget.labels_changed.connect(self._save_map_zone_labels)
        self.project_map_widget.view_settings_changed.connect(self._save_map_view_settings)
        self.project_map_widget.rules_requested.connect(self._open_project_map_rules)
        self.map_mode_stack = _MapModeStack(self)
        self.map_mode_stack.currentChanged.connect(self.map_mode_stack.updateGeometry)
        self.map_mode_stack.addWidget(self.map_widget)
        self.map_mode_stack.addWidget(self.topology_map_widget)
        self.map_mode_stack.addWidget(self.project_map_widget)
        self.map_mode_stack.addWidget(self.switch_topology_widget)
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
        project_mode = self.map_mode_selector.currentData() in {"project", "switches"}
        self.map_result_selector.setVisible(not project_mode)
        self.map_result_label.setVisible(not project_mode)
        self.map_sources_button.setVisible(not project_mode)
        self.map_network_status.setVisible(not project_mode)
        self.map_sources_panel.setVisible(not project_mode and self.map_sources_button.isChecked())
        if self.map_mode_selector.currentData() == "switches":
            self.switch_topology_widget.set_items(self._project_devices())
        elif project_mode:
            self._refresh_project_map()

    def _save_map_zone_labels(self, labels: dict[str, str]) -> None:
        if self.project_id:
            self.store.update_settings(self.project_id, {"map_zone_labels": labels})

    def _save_map_view_settings(self, settings: dict[str, object]) -> None:
        if self.project_id:
            self.store.update_settings(self.project_id, {"map_view_settings": settings})

    def _open_project_map_rules(self, rule_ids: object) -> None:
        if not isinstance(rule_ids, (list, tuple)):
            return
        wanted = set(rule_ids)
        self.workspace_history.remember()
        self.rule_scope.setCurrentIndex(self.rule_scope.findData("project"))
        self.rule_search.clear()
        self._refresh_rules()
        self.navigate("rules", remember=False)
        self.rules_table.clearSelection()
        for row, payload in enumerate(self.rules_model.payloads):
            value, item = payload["value"], payload["item"]
            identity = value.get("rule_id")
            if value.get("cloud_rule") and item.get("platform") == "vmware":
                device_id = vmware_device_id(item["scan"]["config"], item["record"]["id"])
                identity = (
                    f"{device_id}:{value['group']}:{value['raw'].get('id', value['sequence'] - 1)}"
                )
            if identity in wanted:
                self.rules_table.selectionModel().select(
                    self.rules_proxy.mapFromSource(self.rules_model.index(row, 0)),
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows,
                )

    def _refresh_project_map(self) -> None:
        if self._defer_startup and self.current_section_id != "map":
            self._dirty_pages.add("map")
            return
        resources, _, scans = self._inventory_context()
        archived = {
            identity
            for resource in resources
            if resource.get("lifecycle") == "archived"
            for identity in resource.get("identities", [resource.get("identity")])
        }
        devices = [
            item
            for item in self._project_devices()
            if "device:" + str((item.get("report") or {}).get("device_id")) not in archived
        ]
        hidden_device_ids = {
            resource.get("source", {}).get("device_id")
            for resource in resources
            if resource.get("lifecycle") == "archived"
        } - {None}
        devices = [
            item
            for item in devices
            if (item.get("report") or {}).get("device_id") not in hidden_device_ids
        ]
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
            [item for item in cloud_resources(scans) if item["id"] not in archived],
            self.store.list_map_integrations(project_id) if project_id else (),
            revisions=revisions,
        )
        settings = self.store.get_project(project_id)["settings"] if project_id else {}
        self.project_map_widget.set_graph(
            graph, settings.get("map_zone_labels", {}), settings.get("map_view_settings", {}),
        )

    def _refresh_map_items(self, preferred_item: dict[str, Any] | None = None) -> None:
        """Use saved payloads or exact live item IDs, never reread a source."""
        if self._defer_startup and self.current_section_id != "map":
            self._dirty_pages.add("map")
            if preferred_item is not None:
                self._map_pending_item = preferred_item
            return
        previous_id = self.map_result_selector.currentData()
        items = [] if self._batch_active else self._view_items()
        self._map_items = {str(item["id"]): item for item in items}
        for item_id in sorted(self._map_live_item_ids):
            session = self.sessions.get(item_id)
            if session is not None and self._site_contains_device(str(session.report.device_id)):
                self._map_items.setdefault(
                    item_id,
                    {
                        "id": item_id,
                        "run_id": self.run_id,
                        "source_name": Path(session.path).name,
                    },
                )
        if (
            preferred_item is not None
            and preferred_item.get("id") is not None
            and self._site_contains_device((preferred_item.get("report") or {}).get("device_id"))
        ):
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
        if self.current_section_id == "map" and self.map_mode_selector.currentData() == "switches":
            self.switch_topology_widget.set_items(self._project_devices())
        if self.current_section_id == "map" and self.map_mode_selector.currentData() == "project":
            self._refresh_project_map()

    def _clear_map_selection(self) -> None:
        self._dirty_pages.add("map")
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
        self._update_acl_map_actions()

    def _build_acl_map_project_panel(self, parent_layout: QVBoxLayout) -> None:
        self.acl_map_project_panel = QTabWidget()
        self.acl_map_project_panel.setAccessibleName("Сохранённые и пакетные карты ACL проекта")
        saved_page = QWidget()
        saved_layout = QVBoxLayout(saved_page)
        saved_row = QHBoxLayout()
        self.acl_map_save_button = _button("Сохранить выбранную карту", self.save_selected_acl_map)
        self.acl_map_save_button.setObjectName("saveSelectedAclMap")
        self.acl_map_saved_selector = QComboBox()
        self.acl_map_saved_selector.setMinimumContentsLength(20)
        self.acl_map_saved_selector.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.acl_map_saved_selector.setAccessibleName("Сохранённые карты ACL проекта")
        self.acl_map_saved_selector.currentIndexChanged.connect(self._update_acl_map_actions)
        self.acl_map_load_button = _button("Открыть карту", self.load_selected_acl_map)
        saved_row.addWidget(self.acl_map_save_button)
        saved_row.addWidget(self.acl_map_saved_selector, 1)
        saved_row.addWidget(self.acl_map_load_button)
        saved_row.addWidget(_button("Обновить", self._refresh_saved_acl_maps))
        saved_layout.addLayout(saved_row)
        self.acl_map_saved_status = _label(
            "Карты сохраняют ревизию и доказательства, без чтения исходных файлов.", muted=True
        )
        self.acl_map_saved_status.setWordWrap(True)
        saved_layout.addWidget(self.acl_map_saved_status)
        saved_layout.addStretch()
        self.acl_map_project_panel.addTab(saved_page, "Сохранённые карты")
        batch_page = QWidget()
        batch_layout = QVBoxLayout(batch_page)
        batch_row = QHBoxLayout()
        batch_row.addWidget(_label("Запуск:"))
        self.acl_map_batch_run = QComboBox()
        self.acl_map_batch_run.setMinimumContentsLength(16)
        self.acl_map_batch_run.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.acl_map_batch_run.setAccessibleName("Запуск для пакетной карты ACL")
        self.acl_map_batch_run.currentIndexChanged.connect(self._acl_map_batch_run_selected)
        batch_row.addWidget(self.acl_map_batch_run, 1)
        self.acl_map_batch_selected_button = _button(
            "Построить выбранные", self.save_selected_acl_map_batch
        )
        self.acl_map_batch_all_button = _button(
            "Построить весь запуск", self.save_all_acl_map_batch
        )
        batch_row.addWidget(self.acl_map_batch_selected_button)
        batch_row.addWidget(self.acl_map_batch_all_button)
        batch_layout.addLayout(batch_row)
        self.acl_map_batch_items = QListWidget()
        self.acl_map_batch_items.setAccessibleName(
            "Входы запуска для карт ACL; можно выбрать несколько"
        )
        self.acl_map_batch_items.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.acl_map_batch_items.setMaximumHeight(80)
        self.acl_map_batch_items.itemSelectionChanged.connect(self._update_acl_map_actions)
        batch_layout.addWidget(self.acl_map_batch_items)
        self.acl_map_batch_status = QTextBrowser()
        self.acl_map_batch_status.setAccessibleName("Результаты и отказы пакетного построения карт")
        self.acl_map_batch_status.setMaximumHeight(90)
        self.acl_map_batch_status.setPlainText(
            "Построенные карты сохраняются в проекте; каждый отказ остаётся отдельным."
        )
        batch_layout.addWidget(self.acl_map_batch_status)
        self.acl_map_project_panel.addTab(batch_page, "Пакетное построение")
        parent_layout.addWidget(self.acl_map_project_panel)
        self.acl_map_project_panel.hide()
        self.map_saved_panel_button.toggled.connect(self.acl_map_project_panel.setVisible)

    def _selected_acl_map_scope(self) -> tuple[str | None, str | None] | None:
        if self._acl_map_loaded_record is not None:
            record = self._acl_map_loaded_record
            return record.get("run_id"), record.get("item_id")
        item_id = self.map_result_selector.currentData()
        item = self._map_items.get(item_id) if isinstance(item_id, str) else None
        if item is None:
            return None
        run_id = item.get("run_id")
        if run_id is None and any(row["id"] == item_id for row in self._items()):
            run_id = self.run_id
        return (str(run_id), str(item_id)) if run_id is not None else None

    def _update_acl_map_actions(self, *_: Any) -> None:
        ready = bool(
            self.project_id
            and not self._acl_map_busy
            and not self._batch_active
            and not self._restore_busy
        )
        self.acl_map_save_button.setEnabled(
            bool(
                ready
                and self._map_analysis_state.graph is not None
                and self._selected_acl_map_scope() is not None
                and callable(getattr(self.store, "save_acl_map", None))
            )
        )
        self.acl_map_load_button.setEnabled(
            bool(
                ready
                and self.acl_map_saved_selector.currentData() in self._acl_map_records
                and callable(getattr(self.store, "get_acl_map", None))
            )
        )
        batch_ready = bool(
            ready
            and self.acl_map_batch_run.currentData()
            and callable(getattr(self.store, "save_acl_map_batch", None))
        )
        self.acl_map_batch_all_button.setEnabled(batch_ready)
        self.acl_map_batch_selected_button.setEnabled(
            bool(batch_ready and self.acl_map_batch_items.selectedItems())
        )

    def _refresh_saved_acl_maps(self, *_: Any, preferred_id: str | None = None) -> None:
        project_id, epoch = self.project_id, self._acl_map_epoch
        listing = getattr(self.store, "list_acl_maps", None)
        previous = preferred_id or self.acl_map_saved_selector.currentData()
        previous_run = self.acl_map_batch_run.currentData() or self.run_id
        ticket = object()
        self._acl_map_list_ticket = ticket
        if not project_id or not callable(listing):
            self._fill_saved_acl_maps([], [], previous, previous_run)
            return
        runs = self._project_runs()

        def work() -> object:
            return listing(project_id), runs

        def done(value: object) -> None:
            if (
                self._closed
                or self.project_id != project_id
                or self._acl_map_epoch is not epoch
                or self._acl_map_list_ticket is not ticket
            ):
                return
            if isinstance(value, tuple) and len(value) == 2:
                self._fill_saved_acl_maps(value[0], value[1], previous, previous_run)
            else:
                self._fill_saved_acl_maps([], [], None, None)
                self.acl_map_saved_status.setText(
                    "Не удалось прочитать карты проекта; проверьте хранилище."
                )

        self.runner.submit(work, done)

    def _fill_saved_acl_maps(
        self,
        rows: list[dict[str, Any]],
        runs: list[dict[str, Any]],
        preferred: Any,
        preferred_run: Any,
    ) -> None:
        self._acl_map_records = {row["map_id"]: row for row in rows}
        self.acl_map_saved_selector.blockSignals(True)
        self.acl_map_saved_selector.clear()
        for row in rows:
            title = f"{row['built_at']} · {row['rule_count']} правил · {row['revision_id']}"
            self.acl_map_saved_selector.addItem(title, row["map_id"])
        index = self.acl_map_saved_selector.findData(preferred)
        self.acl_map_saved_selector.setCurrentIndex(max(0, index) if rows else -1)
        self.acl_map_saved_selector.blockSignals(False)
        self.acl_map_batch_run.blockSignals(True)
        self.acl_map_batch_run.clear()
        for run in runs:
            if run.get("state") != "running":
                self.acl_map_batch_run.addItem(f"{run['created_at']} · {run['id']}", run["id"])
        index = self.acl_map_batch_run.findData(preferred_run)
        self.acl_map_batch_run.setCurrentIndex(
            max(0, index) if self.acl_map_batch_run.count() else -1
        )
        self.acl_map_batch_run.blockSignals(False)
        self._acl_map_batch_run_selected()
        self._update_acl_map_actions()

    def _acl_map_batch_run_selected(self, *_: Any) -> None:
        self.acl_map_batch_items.clear()
        run_id, project_id, epoch = (
            self.acl_map_batch_run.currentData(),
            self.project_id,
            self._acl_map_epoch,
        )
        ticket = object()
        self._acl_map_run_ticket = ticket
        self._update_acl_map_actions()
        if not run_id or not project_id:
            return

        def work() -> object:
            run = self._get_run(run_id)
            if run.get("project_id") != project_id:
                raise ValueError("Run project differs")
            return run

        def done(value: object) -> None:
            if (
                self._closed
                or self.project_id != project_id
                or self._acl_map_epoch is not epoch
                or self._acl_map_run_ticket is not ticket
                or self.acl_map_batch_run.currentData() != run_id
            ):
                return
            if isinstance(value, dict):
                for item in value.get("items", []):
                    state = (
                        "ревизия сохранена"
                        if item.get("revision") is not None
                        else "ревизия отсутствует"
                    )
                    row = QListWidgetItem(f"{item.get('source_name') or item['id']} · {state}")
                    row.setData(Qt.ItemDataRole.UserRole, item["id"])
                    self.acl_map_batch_items.addItem(row)
                    row.setSelected(True)
            else:
                self.acl_map_batch_status.setPlainText(
                    "Не удалось открыть входы выбранного запуска."
                )
            self._update_acl_map_actions()

        self.runner.submit(work, done)

    def save_selected_acl_map(self) -> None:
        self._update_acl_map_actions()
        scope = self._selected_acl_map_scope()
        graph = self._map_analysis_state.graph
        if not self.acl_map_save_button.isEnabled() or scope is None or graph is None:
            return
        project_id, epoch, ticket = self.project_id, self._acl_map_epoch, object()
        self._acl_map_job_ticket = ticket
        self._acl_map_busy = True
        self._update_acl_map_actions()
        existing_id = (
            self._acl_map_loaded_record.get("map_id")
            if self._acl_map_loaded_record is not None
            else None
        )

        def work() -> object:
            return self.store.save_acl_map(
                project_id, graph, run_id=scope[0], item_id=scope[1], map_id=existing_id
            )

        def done(value: object) -> None:
            if (
                self._closed
                or self.project_id != project_id
                or self._acl_map_epoch is not epoch
                or self._acl_map_job_ticket is not ticket
            ):
                return
            self._acl_map_busy = False
            if isinstance(value, str):
                self.acl_map_saved_status.setText(
                    "Карта сохранена с исходной ревизией и привязкой к запуску."
                )
                self._refresh_saved_acl_maps(preferred_id=value)
            else:
                self.acl_map_saved_status.setText(
                    "Не удалось сохранить карту: проверьте исходную привязку и хранилище."
                )
            self._update_acl_map_actions()

        self._acl_map_job_id = self.runner.submit(work, done)

    def load_selected_acl_map(self) -> None:
        self._update_acl_map_actions()
        if not self.acl_map_load_button.isEnabled():
            return
        map_id, project_id, epoch = (
            self.acl_map_saved_selector.currentData(),
            self.project_id,
            self._acl_map_epoch,
        )
        record = self._acl_map_records[map_id]
        ticket = object()
        self._acl_map_load_ticket = ticket
        self.acl_map_saved_status.setText("Проверяем сохранённую карту…")

        def done(value: object) -> None:
            if (
                self._closed
                or self.project_id != project_id
                or self._acl_map_epoch is not epoch
                or self._acl_map_load_ticket is not ticket
                or self.acl_map_saved_selector.currentData() != map_id
            ):
                return
            from firewall_compliance.domain.acl_map import AclMap

            if isinstance(value, AclMap):
                self.map_result_selector.blockSignals(True)
                self.map_result_selector.setCurrentIndex(0)
                self.map_result_selector.blockSignals(False)
                self._acl_map_loaded_record = record
                state: Literal["empty", "partial", "ready"] = (
                    "empty"
                    if not value.relations
                    else "partial"
                    if len(value.limitations) > 2
                    else "ready"
                )
                self._apply_map_state(
                    AclMapState(
                        state,
                        value,
                        "Сохранённая карта заданных условий ACL.",
                        revision=value.revision,
                    )
                )
                self.map_mode_selector.setCurrentIndex(self.map_mode_selector.findData("policy"))
                self.acl_map_saved_status.setText(
                    "Открыт сохранённый снимок; исходный файл не перечитывался."
                )
            else:
                self.acl_map_saved_status.setText(
                    "Сохранённая карта повреждена или недоступна; текущая карта не заменена."
                )
            self._update_acl_map_actions()

        self._acl_map_load_id = self.runner.submit(
            lambda: self.store.get_acl_map(project_id, map_id), done
        )

    def save_selected_acl_map_batch(self) -> None:
        self._save_acl_map_batch(all_items=False)

    def save_all_acl_map_batch(self) -> None:
        self._save_acl_map_batch(all_items=True)

    def _save_acl_map_batch(self, *, all_items: bool) -> None:
        self._update_acl_map_actions()
        button = self.acl_map_batch_all_button if all_items else self.acl_map_batch_selected_button
        if not button.isEnabled():
            return
        project_id, run_id, epoch, ticket = (
            self.project_id,
            self.acl_map_batch_run.currentData(),
            self._acl_map_epoch,
            object(),
        )
        selected = (
            None
            if all_items
            else tuple(
                row.data(Qt.ItemDataRole.UserRole)
                for row in self.acl_map_batch_items.selectedItems()
            )
        )
        self._acl_map_job_ticket = ticket
        self._acl_map_busy = True
        self._update_acl_map_actions()
        self.acl_map_batch_status.setPlainText(
            "Строим карты сохранённых ревизий и сохраняем результаты…"
        )

        def work() -> object:
            return self.store.save_acl_map_batch(project_id, run_id, item_ids=selected)

        def done(value: object) -> None:
            if (
                self._closed
                or self.project_id != project_id
                or self._acl_map_epoch is not epoch
                or self._acl_map_job_ticket is not ticket
            ):
                return
            self._acl_map_busy = False
            if isinstance(value, tuple) and len(value) == 2:
                batch, identifiers = value
                self._acl_map_batch_result = batch
                lines = [
                    f"Запуск: {run_id}.",
                    f"Построено и сохранено карт: {len(identifiers)}. "
                    f"Отказов: {len(batch.failures)}.",
                ]
                if not identifiers:
                    lines.append(
                        "Карты не построены; отсутствие карт не означает отсутствие правил."
                    )
                for failure in batch.failures:
                    lines.append(
                        f"{failure.source_name or failure.input_reference}: "
                        f"{failure.code} · {failure.message}"
                    )
                    lines.extend(
                        f"  {issue.code}: {issue.message}" for issue in failure.diagnostics
                    )
                self.acl_map_batch_status.setPlainText("\n".join(lines))
                self._refresh_saved_acl_maps(preferred_id=identifiers[0] if identifiers else None)
            else:
                self.acl_map_batch_status.setPlainText(
                    "Пакет не сохранён: не удалось подтвердить ревизии или область запуска."
                )
            self._update_acl_map_actions()

        self._acl_map_job_id = self.runner.submit(work, done)

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
        self._acl_map_loaded_record = None
        self._acl_map_load_ticket = None
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
        self.settings_pages = QStackedWidget()
        layout.addWidget(self.settings_pages, 1)
        from PySide6.QtGui import QIcon

        integrations = QWidget()
        integrations_layout = QVBoxLayout(integrations)
        integrations_layout.setContentsMargins(0, 0, 0, 0)
        self.integration_pages = QStackedWidget()
        self.integration_pages.setMaximumWidth(980)
        integrations_layout.addWidget(self.integration_pages, 1, Qt.AlignmentFlag.AlignLeft)
        catalog = QWidget()
        catalog_layout = QVBoxLayout(catalog)
        catalog_layout.setContentsMargins(0, 0, 0, 0)
        catalog_layout.setSpacing(16)
        catalog_layout.addWidget(_label("Интеграции", heading=True))
        self.integration_pages.addWidget(catalog)
        self.integration_buttons: dict[str, QPushButton] = {}
        self.integration_grids: list[QGridLayout] = []
        assets = Path(__file__).parent / "assets"
        solution_icons = {
            "aruba": "hp_aruba.png", "usergate": "usergate.png",
            "pt": "positive technologies.png", "ideco": "ideco.png", "cloud_ru": "cloud_ru.png",
        }
        groups = (
            ("Серверное оборудование", assets / "integrations/server.svg", (("aruba", "Aruba", False),)),
            ("NGFW", assets / "integrations/wall.svg",
             (("usergate", "UserGate", False), ("pt", "PT NGFW", True), ("ideco", "Ideco", False))),
            ("Платформы виртуализации", assets / "integrations/cloud.svg", (("cloud_ru", "Cloud.ru", False),)),
        )
        for title, icon_path, platforms in groups:
            group = QFrame()
            group.setObjectName("integrationGroup")
            group_layout = QVBoxLayout(group)
            group_layout.setContentsMargins(16, 14, 16, 16)
            heading = QHBoxLayout()
            category_icon = QLabel()
            category_icon.setPixmap(QIcon(str(icon_path)).pixmap(24, 24))
            heading.addWidget(category_icon)
            heading.addWidget(_label(title))
            heading.addStretch()
            group_layout.addLayout(heading)
            grid = QGridLayout()
            grid.setSpacing(12)
            grid.setColumnStretch(3, 1)
            self.integration_grids.append(grid)
            for position, (key, name, planned) in enumerate(platforms):
                button = _button(name, partial(self._open_integration, key))
                button.setObjectName("integrationCard")
                button.setIcon(QIcon(str(assets / "integrations" / solution_icons[key])))
                button.setIconSize(QSize(40, 40))
                button.setFixedSize(188, 78)
                button.setCursor(Qt.CursorShape.PointingHandCursor)
                button.setToolTip("Запланировано" if planned else f"Открыть {name}")
                button.setStyleSheet(
                    'QPushButton[configured="true"] { background: #173b2e; '
                    'border: 1px solid #39815c; color: #bce9cd; }'
                )
                self.integration_buttons[key] = button
                grid.addWidget(button, position // 3, position % 3)
            group_layout.addLayout(grid)
            catalog_layout.addWidget(group)
        catalog_layout.addStretch()
        self.integration_detail_indices: dict[str, int] = {}
        self.integration_form_layouts: dict[str, QVBoxLayout] = {}
        self.integration_editors: dict[str, tuple[str, QDialog]] = {}
        descriptions = (
            ("aruba", "Aruba", "Импорт конфигураций. Прямое подключение пока недоступно."),
            ("usergate", "UserGate", "6.1.5+ / 7.x · TCP/HTTP; 7.3.3+ · HTTPS. NAT и карта имеют ограничения."),
            ("pt", "PT NGFW", "Запланировано. Импорт и API пока недоступны."),
            ("ideco", "Ideco", "NGFW v23 · классический VCE · HTTPS :8443. VPP/BPF не поддерживаются."),
            ("cloud_ru", "Cloud.ru", ""),
        )
        for key, name, description in descriptions:
            detail = QWidget()
            detail.setMaximumWidth(820)
            detail_layout = QVBoxLayout(detail)
            detail_layout.setContentsMargins(0, 0, 0, 0)
            back = _button("← Все интеграции", self._show_integrations)
            detail_layout.addWidget(back, 0, Qt.AlignmentFlag.AlignLeft)
            detail_layout.addWidget(_label(name, heading=True))
            if description:
                detail_layout.addWidget(_label(description, muted=True))
            if key == "cloud_ru":
                detail_layout.addWidget(self.cloud_panel.settings_widget)
            if key in ("usergate", "ideco"):
                form_layout = QVBoxLayout()
                detail_layout.addLayout(form_layout)
                self.integration_form_layouts[key] = form_layout
                detail_layout.addWidget(
                    _button("Импортировать сохранённый снимок", self._import_integration_files),
                    0, Qt.AlignmentFlag.AlignLeft,
                )
            if key == "aruba":
                detail_layout.addWidget(
                    _button("Импортировать конфигурации", self._import_integration_files, primary=True),
                    0, Qt.AlignmentFlag.AlignLeft,
                )
            detail_layout.addStretch()
            self.integration_detail_indices[key] = self.integration_pages.addWidget(detail)
        self.settings_pages.addWidget(self._settings_scroll_area(integrations))
        rules = QWidget()
        rules_layout = QVBoxLayout(rules)
        rules_layout.setContentsMargins(0, 0, 0, 0)
        rules_layout.addWidget(_label("Проверки", heading=True))
        self.check_settings_groups = (
            ("policy", "Правила firewall"),
            ("management", "Управление устройствами"),
            ("parameters", "Параметры проверок"),
        )
        self.check_settings_pages = QStackedWidget()
        self.check_settings_indices: dict[str, int] = {}
        self.check_boxes: dict[str, QCheckBox] = {}
        policy_groups = (
            ("Доступ и сетевые сервисы", (
                "FW-ANY-ANY", "FW-DANGEROUS-SERVICES", "FW-ADMIN-UNTRUSTED",
                "FW-EXCESSIVE-ACCESS", "FW-ACL-ATTACHMENT",
            )),
            ("Структура правил", (
                "FW-DUPLICATE", "FW-SHADOWED", "FW-PARTIAL-SHADOWED",
                "FW-UNION-SHADOWED", "FW-MERGE-CANDIDATE", "FW-DISABLED",
            )),
            ("Оформление и аудит", ("FW-LOGGING", "FW-COMMENTS")),
        )
        management_groups = (
            ("Доступ к управлению", (
                "MGMT-TELNET", "MGMT-HTTP", "MGMT-ADMIN-SOURCES",
                "MGMT-IDLE-TIMEOUT", "MGMT-BANNER",
            )),
            ("SNMP", ("MGMT-SNMP-LEGACY", "MGMT-SNMP-WRITE", "MGMT-SNMP-SOURCES")),
            ("Журналирование", ("MGMT-SYSLOG-MISSING", "MGMT-SYSLOG-UNAPPROVED")),
            ("Синхронизация времени", ("MGMT-NTP-MISSING", "MGMT-NTP-UNAPPROVED")),
        )
        for key, groups in (("policy", policy_groups), ("management", management_groups)):
            tree = CheckSelection(CHECKS, groups, OPTIONAL_SCOPE_CHECKS)
            self.check_settings_indices[key] = self.check_settings_pages.addWidget(tree)
            self.check_boxes.update(tree.check_boxes)
        for checkbox in self.check_boxes.values():
            checkbox.toggled.connect(self._save_analysis_settings)
            checkbox.toggled.connect(self._refresh_staged)
        parameters = QWidget()
        parameters_layout = QVBoxLayout(parameters)
        parameters_layout.setContentsMargins(0, 0, 0, 0)

        def parameter_group(title: str) -> QVBoxLayout:
            frame = QFrame()
            frame.setObjectName("integrationGroup")
            group_layout = QVBoxLayout(frame)
            group_layout.setContentsMargins(18, 16, 18, 18)
            group_layout.addWidget(_label(title, heading=True))
            parameters_layout.addWidget(frame)
            return group_layout

        policy_layout = parameter_group("Требования к правилам")
        self.logging_check = QCheckBox("Требовать логирование разрешающих правил")
        self.logging_check.setChecked(True)
        self.comments_check = QCheckBox("Требовать комментарии правил")
        self.comments_check.setChecked(True)
        policy_layout.addWidget(self.logging_check)
        policy_layout.addWidget(self.comments_check)
        self.logging_check.toggled.connect(self._save_analysis_settings)
        self.comments_check.toggled.connect(self._save_analysis_settings)
        self.management_settings = ManagementSettings()
        parameter_group("Управление устройствами").addWidget(self.management_settings)
        self.management_settings.changed.connect(self._save_analysis_settings)
        self.policy_exposure_settings = PolicyExposureSettings()
        parameter_group("Сетевые сервисы").addWidget(self.policy_exposure_settings)
        self.policy_exposure_settings.changed.connect(self._save_analysis_settings)
        self.policy_scope_settings = PolicyScopeSettings()
        parameter_group("Область доступа и привязки ACL").addWidget(self.policy_scope_settings)
        self.policy_scope_settings.changed.connect(self._save_analysis_settings)
        thresholds_layout = parameter_group("Изменение состава данных")
        self.rule_drop_threshold = QSpinBox()
        self.inventory_drop_threshold = QSpinBox()
        for title, widget in (
            ("Предупреждать при сокращении правил, %", self.rule_drop_threshold),
            ("Предупреждать при сокращении ресурсов, %", self.inventory_drop_threshold),
        ):
            row = QHBoxLayout()
            row.addWidget(_label(title))
            widget.setRange(1, 100)
            widget.setValue(30)
            widget.setSuffix(" %")
            widget.setMaximumWidth(110)
            widget.setAccessibleName(title)
            widget.valueChanged.connect(self._save_analysis_settings)
            row.addWidget(widget)
            row.addStretch()
            thresholds_layout.addLayout(row)
        parameters_layout.addStretch()
        self.check_settings_indices["parameters"] = self.check_settings_pages.addWidget(
            self._settings_scroll_area(parameters)
        )
        rules_layout.addWidget(self.check_settings_pages, 1)
        self.settings_pages.addWidget(rules)
        self._select_settings_tab("integrations", 0)

    def _select_check_settings_group(self, key: str) -> None:
        self.check_settings_pages.setCurrentIndex(self.check_settings_indices[key])

    def _settings_scroll_area(self, content: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        content.setMaximumWidth(1060)
        scroll.setWidget(content)
        return scroll

    def _select_settings_tab(self, key: str, index: int) -> None:
        self.settings_pages.setCurrentIndex(index)
        if index == 0:
            self._refresh_integration_status()
        if self.current_section_id == "settings":
            item = self.settings_tree_items[key]
            self.navigation.blockSignals(True)
            self.navigation.setCurrentItem(item)
            self.navigation.blockSignals(False)

    def _open_integration(self, key: str) -> None:
        if key in ("usergate", "ideco"):
            if not self._ensure_project():
                return
            assert self.project_id is not None
            existing = self.integration_editors.get(key)
            if existing is not None and existing[0] != self.project_id:
                self._reset_integration_editors()
                existing = None
            if existing is None:
                from firewall_compliance.interfaces.desktop.qt_ngfw_sources import (
                    create_ngfw_source_editor,
                )

                project_id = self.project_id

                def saved(path: Path) -> None:
                    if self.project_id == project_id:
                        self.stage_paths([path])

                editor = create_ngfw_source_editor(
                    self, self.runner, self.store, project_id, key, saved,
                    self._refresh_integration_status,
                )
                self.integration_form_layouts[key].addWidget(editor)
                self.integration_editors[key] = (project_id, editor)
        self.integration_pages.setCurrentIndex(self.integration_detail_indices[key])

    def _reset_integration_editors(self) -> None:
        for key, (_, editor) in self.integration_editors.items():
            editor.reject()
            self.integration_form_layouts[key].removeWidget(editor)
            editor.deleteLater()
        self.integration_editors.clear()
        self.integration_pages.setCurrentIndex(0)

    def _show_integrations(self) -> None:
        self.integration_pages.setCurrentIndex(0)
        self._refresh_integration_status()

    def _refresh_integration_status(self) -> None:
        for button in self.integration_buttons.values():
            button.setProperty("configured", False)
            button.style().unpolish(button)
            button.style().polish(button)
        project_id = self.project_id
        if not project_id:
            return

        def loaded(value: object) -> None:
            if self.project_id != project_id or not isinstance(value, list):
                return
            configured: set[str] = set()
            for connection in value:
                if not connection.get("config"):
                    continue
                provider = connection["provider"]
                if provider.startswith("cloud_ru_"):
                    configured.add("cloud_ru")
                elif provider.startswith("ngfw:"):
                    configured.add(provider.split(":")[1])
            for key, button in self.integration_buttons.items():
                button.setProperty("configured", key in configured)
                button.style().unpolish(button)
                button.style().polish(button)

        self.runner.submit(lambda: self.store.list_source_connections(project_id), loaded)

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

    def _site_changed(self, *_: Any) -> None:
        if self._loading_settings or self._restore_busy:
            return
        self._site_selection = self.site_selector.currentData()
        active = self._site_selection is not None
        self.site_scope_note.setText(
            "Площадка: " + self.site_selector.currentText() + ". "
            "Фильтр: устройства, находки, правила, история проверок и их карта. "
            "Ошибки без устройства, облачный инвентарь, источники и сборы остаются по проекту. "
            "Реестр, расширенные инструменты, сохранённые карты и отчёты — "
            "весь проект / выбранный полный запуск. Для сбора выбираются назначенные источники и файлы площадки; "
            "общий источник нескольких площадок обновляется целиком."
            if active
            else ""
        )
        self.site_selector.setToolTip(self.site_scope_note.text())
        self._refresh_all()

    def _populate_site_selector(self, snapshot: ProjectSnapshot | None) -> None:
        previous = self._site_selection
        self.site_selector.blockSignals(True)
        self.site_selector.clear()
        self.site_selector.addItem("Все площадки", None)
        self.site_selector.addItem("Без площадки", "")
        for site in snapshot.sites if snapshot is not None else ():
            self.site_selector.addItem(site["name"], site["id"])
        index = self.site_selector.findData(previous)
        self.site_selector.setCurrentIndex(max(0, index))
        self._site_selection = self.site_selector.currentData()
        self.site_selector.blockSignals(False)

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
                policy_exposure_profile = self.policy_exposure_settings.profile().model_dump(
                    mode="json"
                )
                policy_scope_profile = self.policy_scope_settings.profile().model_dump(mode="json")
            except ValueError:
                return
            self.store.update_settings(
                self.project_id,
                {
                    "require_logging": self.logging_check.isChecked(),
                    "require_comments": self.comments_check.isChecked(),
                    "rule_count_drop_percent": self.rule_drop_threshold.value(),
                    "inventory_count_drop_percent": self.inventory_drop_threshold.value(),
                    "management_profile": management_profile,
                    "policy_exposure_profile": policy_exposure_profile,
                    "policy_scope_profile": policy_scope_profile,
                    "enabled_check_ids": [
                        key for key, box in self.check_boxes.items() if box.isChecked()
                    ],
                },
            )

    def _build_staging(self, layout: QVBoxLayout) -> None:
        actions = QHBoxLayout()
        self.folder_button = _button("Добавить папку", self.choose_folder, primary=True)
        self.files_button = _button("Добавить файлы", self.choose_files)
        self.ideco_button = _button("Ideco · только чтение", self.choose_ideco)
        self.usergate_button = _button("UserGate · только чтение", self.choose_usergate)
        self.clear_button = _button("Очистить список", self.clear_staged)
        self.remove_button = _button("Убрать выбранные", self.remove_staged)
        for button in (
            self.folder_button,
            self.files_button,
            self.usergate_button,
            self.ideco_button,
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
        self.finding_search.setPlaceholderText("Устройство, IP, объект, сервис или ID правила…")
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
        self.finding_conditions = RuleQueryWidget(self)
        self.finding_conditions.changed.connect(self.refresh_findings)
        layout.addWidget(self.finding_conditions)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.finding_table, self.finding_model, self.finding_proxy = self._table(
            ("Приоритет", "Устройство", "Проверка", "Находка", "Статус", "Полнота / фильтр"),
            "findingsTable",
        )
        self.finding_table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        for column, width in enumerate((125, 135, 150, 280, 145, 175)):
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
        self.finding_history_button = _button("История решений", self.show_finding_history)
        decision_layout.addWidget(self.finding_history_button)
        detail.addTab(decision_page, "Решение")
        split.addWidget(detail)
        split.setSizes([850, 430])
        layout.addWidget(split, 1)
        self.finding_table.selectionModel().selectionChanged.connect(self._finding_selected)

    def _build_devices(self) -> None:
        page, outer_layout = self._page(
            "Инфраструктура", "Ресурсы проекта и доступные снимки конфигураций."
        )
        self.infrastructure_tabs = QTabWidget(page)
        self.registry_panel = InfrastructureRegistryPanel(self.store.resource_registry)
        self.registry_panel.changed.connect(self._registry_changed)
        self.registry_panel.operation_requested.connect(self._open_registry_operation)
        self.infrastructure_tabs.addTab(self.registry_panel, "Реестр ресурсов")
        snapshots_page = QWidget()
        layout = QVBoxLayout(snapshots_page)
        self.infrastructure_tabs.addTab(snapshots_page, "Снимки и проверки")
        outer_layout.addWidget(self.infrastructure_tabs, 1)
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
            ("Устройство", "Платформа / версия", "Тип", "Политики / состав"),
            "devicesTable",
            search_payload=True,
        )
        self.resource_search.textChanged.connect(self.device_proxy.setFilterFixedString)
        layout.addWidget(_button("Структура и политики выбранного устройства", self._open_switch_details))
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
        for column, width in enumerate((220, 180, 140, 350)):
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
        self.rule_category = QComboBox()
        self.rule_category.addItem("Все назначения правил и объекты", "")
        for key, title in PURPOSE_LABELS.items():
            self.rule_category.addItem(title, key)
        self.rule_category.currentIndexChanged.connect(self._refresh_rules)
        layout.addWidget(self.rule_category)
        self.rule_inventory_status = _label("")
        layout.addWidget(self.rule_inventory_status)
        search = self.rule_search = QLineEdit()
        search.setPlaceholderText("Поиск по устройству, правилу, адресу или сервису")
        layout.addWidget(search)
        self.rule_conditions = RuleQueryWidget(self)
        self.rule_conditions.changed.connect(self._refresh_rules)
        layout.addWidget(self.rule_conditions)
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
        menu.addAction("Матрица доступа…").triggered.connect(self._open_access_matrix)
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
        actions.addWidget(_button("Сравнить с предыдущим", self.compare_with_previous_run))
        actions.addWidget(_button("История сравнений", self.open_comparison_history))
        actions.addStretch()
        layout.addLayout(actions)
        self.history_detail = QTextBrowser()
        layout.addWidget(self.history_detail, 1)

    def _build_reports(self) -> None:
        _, outer_layout = self._page(
            "Отчёты", "Автономный HTML и версионированный JSON по всему запуску."
        )
        self.report_tabs = QTabWidget()
        self.report_tabs.setAccessibleName("Виды отчётов")
        legacy = QWidget()
        layout = QVBoxLayout(legacy)
        self.report_tabs.addTab(legacy, "Отчёт запуска")
        outer_layout.addWidget(self.report_tabs, 1)
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
        row.addWidget(_button("Предпросмотр отчёта", self.preview_batch_report))
        row.addWidget(_button("Матрица доступа…", self._open_access_matrix))
        row.addStretch()
        layout.addLayout(row)
        self.report_summary = QTextBrowser()
        self.report_summary.setOpenLinks(False)
        self.report_summary.anchorClicked.connect(self._open_report_limitations)
        layout.addWidget(self.report_summary, 1)
        self._build_analysis_reports()
        self.controls_panel: ControlsPanel | None = None
        self.governance_panel: GovernancePanel | None = None
        if (
            isinstance(getattr(self.store, "path", None), Path)
            and callable(getattr(self.store, "list_analysis_results", None))
            and callable(getattr(self.store, "get_analysis_result", None))
        ):
            self.controls_panel = ControlsPanel(self.store)
            self.report_tabs.addTab(self.controls_panel, "Технические контроли")
            self.report_tabs.currentChanged.connect(self._controls_report_selected)
            self.governance_panel = GovernancePanel(self.store)
            self.report_tabs.addTab(self.governance_panel, "Метаданные правил")
            self.report_tabs.currentChanged.connect(self._governance_report_selected)
            self.governance_panel.result_saved.connect(
                lambda result_id: self._refresh_analysis_results(preferred_id=result_id)
            )

    def _open_access_matrix(self) -> None:
        from firewall_compliance.application.workspace_profile import analysis_settings
        from firewall_compliance.interfaces.desktop.qt_access_matrix import AccessMatrixDialog

        project_id = self.project_id
        if not project_id or not isinstance(getattr(self.store, "path", None), Path):
            self.progress_label.setText("Выберите сохранённый проект для работы с матрицей доступа.")
            return
        site_id = self._site_selection
        items = self._project_devices()
        choices = ["Редактор без выбранного снимка"]
        choices.extend(
            f"{index + 1}. {(item.get('report') or {}).get('device_id') or item.get('source_name', 'Устройство')}"
            f" · {item.get('run_created_at') or item.get('created_at') or 'время не указано'}"
            for index, item in enumerate(items)
        )
        choice, accepted = QInputDialog.getItem(
            self, "Матрица доступа", "Снимок для сверки заданных условий:", choices, 0, False,
        )
        if not accepted:
            return
        revision = None
        profile_version = "не зафиксирована"
        profile_settings_json = None
        origin_run_id = None
        origin_item_id = None
        index = choices.index(choice) - 1
        if index >= 0:
            item = items[index]
            try:
                revision = DeviceRevision.model_validate(item.get("revision"))
            except (TypeError, ValueError):
                QMessageBox.information(
                    self, "Матрица доступа",
                    "В этом снимке нет пригодной нормализованной ревизии. Доступен редактор без сверки.",
                )
            if item.get("run_id"):
                origin_run_id = str(item["run_id"])
                origin_item_id = str(item["id"])
                settings = self._get_run(origin_run_id).get("settings", {})
                profile_version = str(settings.get("workspace_profile_version", "не зафиксирована"))
                profile_settings_json = json.dumps(analysis_settings(settings), ensure_ascii=False)
        dialog = AccessMatrixDialog(
            self.store.path, self.runner, project_id, revision, self,
            scope_id=site_id or project_id,
            profile_id="legacy-project-profile:" + project_id,
            profile_version=profile_version,
            origin_run_id=origin_run_id, profile_settings_json=profile_settings_json,
            origin_item_id=origin_item_id,
            context_valid=lambda: (
                not self._closed and self.project_id == project_id and self._site_selection == site_id
            ),
        )
        dialog.exec()
        dialog.deleteLater()

    def _controls_report_selected(self, *_: Any) -> None:
        panel = self.controls_panel
        if panel is not None and self.report_tabs.currentWidget() is panel:
            panel.refresh_results()

    def _governance_report_selected(self, *_: Any) -> None:
        panel = self.governance_panel
        if panel is not None and self.report_tabs.currentWidget() is panel:
            panel.refresh_results()

    def _build_analysis_reports(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        note = _label(
            "Общие результаты сохраняют входные снимки, параметры, выводы и ограничения. "
            "Полное выполнение не означает соответствие требованиям или доказанную достижимость.",
            muted=True,
        )
        layout.addWidget(note)
        saves = QHBoxLayout()
        self.save_run_analysis_button = _button(
            "Сохранить результат выбранного запуска", self.save_run_analysis_result
        )
        self.save_run_analysis_button.setObjectName("saveRunAnalysisResult")
        self.save_network_analysis_button = _button(
            "Сохранить последний сетевой результат", self.save_network_analysis_result
        )
        self.save_network_analysis_button.setObjectName("saveNetworkAnalysisResult")
        saves.addWidget(self.save_run_analysis_button)
        saves.addWidget(self.save_network_analysis_button)
        layout.addLayout(saves)
        self.analysis_result_hint = _label("Выберите проект и выполненный запуск.", muted=True)
        self.analysis_result_hint.setObjectName("analysisResultHint")
        layout.addWidget(self.analysis_result_hint)
        self.analysis_result_selector = QComboBox()
        self.analysis_result_selector.setObjectName("analysisResultSelector")
        self.analysis_result_selector.setAccessibleName("Сохранённые общие результаты проекта")
        self.analysis_result_selector.currentIndexChanged.connect(self._analysis_result_selected)
        layout.addWidget(self.analysis_result_selector)
        actions = QHBoxLayout()
        actions.addWidget(_button("Обновить список", self._refresh_analysis_results))
        self.analysis_result_export_buttons: dict[str, QPushButton] = {}
        for format_name in ("json", "csv", "html"):
            button = _button(
                "Экспорт " + format_name.upper(),
                partial(self.export_analysis_result, format_name),
            )
            button.setObjectName("exportAnalysisResult" + format_name.upper())
            self.analysis_result_export_buttons[format_name] = button
            actions.addWidget(button)
        actions.addStretch()
        layout.addLayout(actions)
        self.analysis_result_summary = QTextBrowser()
        self.analysis_result_summary.setObjectName("analysisResultSummary")
        self.analysis_result_summary.setOpenLinks(False)
        layout.addWidget(self.analysis_result_summary, 1)
        self.report_tabs.addTab(page, "Общие результаты")
        self.report_run.currentIndexChanged.connect(self._update_analysis_result_actions)
        self._update_analysis_result_actions()

    def _capture_analysis_network_result(self, snapshot: Any) -> None:
        self._analysis_network_snapshot = (
            snapshot
            if snapshot is not None
            and self.project_id is not None
            and getattr(snapshot, "project_reference", None) == self.project_id
            else None
        )
        self._update_analysis_result_actions()

    def _update_analysis_result_actions(self, *_: Any) -> None:
        storage = callable(getattr(self.store, "save_analysis_result", None))
        available = bool(
            self.project_id
            and storage
            and not self._analysis_result_busy
            and not self._batch_active
            and not self._restore_busy
        )
        self.save_run_analysis_button.setEnabled(available and bool(self.report_run.currentData()))
        self.save_network_analysis_button.setEnabled(
            available and self._analysis_network_snapshot is not None
        )
        selected = self.analysis_result_selector.currentData()
        exportable = bool(
            available
            and selected
            and selected == self._analysis_result_active_id
            and self._analysis_result_active is not None
        )
        for button in self.analysis_result_export_buttons.values():
            button.setEnabled(exportable)
        if not self.project_id:
            hint = "Выберите проект."
        elif not storage:
            hint = "Хранилище общих результатов недоступно."
        elif self._analysis_result_busy:
            hint = "Сохраняем снимок результата…"
        elif self._analysis_network_snapshot is None:
            hint = "Сетевой результат появится после запроса в расширенном анализе этого проекта."
        else:
            hint = "Последний сетевой результат готов к сохранению; его ограничения сохраняются."
        self.analysis_result_hint.setText(hint)

    def save_run_analysis_result(self) -> None:
        self._save_analysis_result(network=False)

    def save_network_analysis_result(self) -> None:
        self._save_analysis_result(network=True)

    def _save_analysis_result(self, *, network: bool) -> None:
        if (
            not self.project_id
            or self._analysis_result_busy
            or self._batch_active
            or self._restore_busy
        ):
            return
        project_id = self.project_id
        run_id = self.report_run.currentData()
        snapshot = self._analysis_network_snapshot
        if (network and snapshot is None) or (not network and not run_id):
            return
        if network and getattr(snapshot, "project_reference", None) != project_id:
            return
        self._analysis_result_busy = True
        self._update_analysis_result_actions()

        def work() -> object:
            from firewall_compliance.interfaces.desktop.analysis_result_adapter import (
                analysis_from_network,
                analysis_from_run,
            )

            result = (
                analysis_from_network(snapshot, project_id)
                if network
                else analysis_from_run(self.store, project_id, str(run_id))
            )
            result_id = self.store.save_analysis_result(project_id, result)
            return str(result_id), result

        def done(value: object) -> None:
            self._analysis_result_busy = False
            self._analysis_result_save_id = None
            if self._closed:
                return
            if self.project_id != project_id:
                self._update_analysis_result_actions()
                return
            if isinstance(value, tuple) and len(value) == 2:
                result_id, result = value
                self._analysis_result_active_id = str(result_id)
                self._analysis_result_active = result
                self._refresh_analysis_results(preferred_id=str(result_id))
                self.report_tabs.setCurrentIndex(1)
                self.progress_label.setText("Общий результат сохранён в проекте.")
            else:
                self.progress_label.setText(
                    "Не удалось сохранить общий результат. Исходные проверки сохранены."
                )
            self._update_analysis_result_actions()

        self._analysis_result_save_id = self.runner.submit(work, done)

    def _refresh_analysis_results(self, *_: Any, preferred_id: str | None = None) -> None:
        previous = preferred_id or self.analysis_result_selector.currentData()
        listing = getattr(self.store, "list_analysis_results", None)
        project_id = self.project_id
        ticket = object()
        self._analysis_list_ticket = ticket
        if not project_id or not callable(listing):
            self._fill_analysis_results([], previous)
            return

        def work() -> object:
            return listing(project_id) if self._analysis_list_ticket is ticket else []

        def done(value: object) -> None:
            if (
                self._closed
                or self.project_id != project_id
                or self._analysis_list_ticket is not ticket
            ):
                return
            if isinstance(value, list):
                self._fill_analysis_results(value, previous)
            else:
                self._fill_analysis_results([], None)
                self.progress_label.setText("Не удалось прочитать список общих результатов.")

        self.runner.submit(work, done)

    def _fill_analysis_results(self, rows: list[dict[str, Any]], previous: Any) -> None:
        self.analysis_result_selector.blockSignals(True)
        self.analysis_result_selector.clear()
        for row in rows:
            title = f"{row['created_at']} · {row['analysis_id']}"
            self.analysis_result_selector.addItem(title, row["analysis_id"])
        index = self.analysis_result_selector.findData(previous)
        self.analysis_result_selector.setCurrentIndex(max(0, index) if rows else -1)
        self.analysis_result_selector.blockSignals(False)
        self._analysis_result_selected()

    def _analysis_result_selected(self, *_: Any) -> None:
        result_id = self.analysis_result_selector.currentData()
        project_id = self.project_id
        ticket = object()
        self._analysis_result_ticket = ticket
        if (
            result_id
            and result_id == self._analysis_result_active_id
            and self._analysis_result_active is not None
        ):
            self._show_analysis_result_summary(self._analysis_result_active)
            self._update_analysis_result_actions()
            return
        self._analysis_result_active = None
        self._analysis_result_active_id = None
        self._update_analysis_result_actions()
        if not result_id or not project_id:
            self.analysis_result_summary.setPlainText("Сохранённых общих результатов пока нет.")
            return
        self.analysis_result_summary.setPlainText("Проверяем сохранённый снимок результата…")

        def done(value: object) -> None:
            if (
                self._closed
                or self._analysis_result_ticket is not ticket
                or self.project_id != project_id
                or self.analysis_result_selector.currentData() != result_id
            ):
                return
            if isinstance(value, JobError):
                self.analysis_result_summary.setPlainText(
                    "Не удалось проверить сохранённый результат. Экспорт недоступен."
                )
            else:
                self._analysis_result_active = value
                self._analysis_result_active_id = str(result_id)
                self._show_analysis_result_summary(value)
            self._update_analysis_result_actions()

        self.runner.submit(lambda: self.store.get_analysis_result(project_id, result_id), done)

    def _show_analysis_result_summary(self, result: Any) -> None:
        states = {
            "complete": "Полное выполнение",
            "partial": "Частичное выполнение",
            "failed": "Ошибка",
            "cancelled": "Отменено",
            "not_executed": "Не выполнено",
        }
        summary = result.summary
        lines = [
            "<h3>Общий результат</h3>",
            "<p>" + html.escape(states.get(result.state, str(result.state))) + "</p>",
            f"<p>Компонентов: {summary.components}; выполненных checks: {summary.checks_executed}; "
            f"находок: {summary.findings}; сетевых результатов: {summary.network_results}.</p>",
            "<p>Полное выполнение не является подтверждением соответствия требованиям.</p>",
            "<h4>Источники</h4>",
        ]
        for source in result.sources:
            basis = (
                "Сохранённая API-запись"
                if source.hash_basis == "canonical_api_record"
                else "Исходный файл"
            )
            lines.append(
                "<p>"
                + html.escape(source.source_name)
                + "<br>"
                + basis
                + " · SHA-256: "
                + html.escape(source.content_sha256)
                + "</p>"
            )
        if not result.sources:
            lines.append("<p>Источники для этого результата не определены.</p>")
        self.analysis_result_summary.setHtml("".join(lines))

    def export_analysis_result(self, format_name: str, path: Path | None = None) -> None:
        result = self._analysis_result_active
        if (
            result is None
            or not self.project_id
            or self._analysis_result_busy
            or self.analysis_result_selector.currentData() != self._analysis_result_active_id
        ):
            return
        from firewall_compliance.application.analysis_reports import (
            export_analysis_csv,
            export_analysis_html,
            export_analysis_json,
        )

        exports = {
            "json": export_analysis_json,
            "csv": export_analysis_csv,
            "html": export_analysis_html,
        }
        if format_name not in exports:
            raise ValueError("Неизвестный формат отчёта")
        if path is None:
            selected, _ = QFileDialog.getSaveFileName(
                self,
                "Экспорт общего результата",
                "analysis-result." + format_name,
                format_name.upper() + " (*." + format_name + ")",
            )
            if not selected:
                return
            path = Path(selected)
        try:
            path.write_text(exports[format_name](result), encoding="utf-8")
        except (OSError, ValueError):
            self.progress_label.setText(
                "Не удалось сохранить отчёт. Проверьте путь и доступ к файлу."
            )
            return
        self.progress_label.setText("Общий результат экспортирован: " + str(path))

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
        if self._ui_ready and not self._loading_settings:
            self._refresh_page(section_id)
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
        self.section_tabs.setVisible(section_id in ("findings", "staging", "scans", "advanced", "history", "reports"))
        self.section_tabs.blockSignals(False)
        item = (
            self.settings_tree_items.get("integrations" if self.settings_pages.currentIndex() == 0 else "rules")
            if section_id == "settings" else self.nav_items.get(section_id)
        )
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
        self.finding_scope.setCurrentIndex(self.finding_scope.findData("project"))
        self.finding_search.clear()
        for combo in (self.finding_device, self.finding_check, self.status_filter):
            combo.setCurrentIndex(0)
        self.severity_filter.setCurrentIndex(max(0, self.severity_filter.findData(severity)))
        self.navigate("findings", remember=False)

    def _active_tasks(self) -> list[dict[str, Any]]:
        rows = list(self._aggregate_tasks.values())
        if self._cycle_job_id is not None and not rows:
            rows.append({
                "kind": "run" if self._cycle_run_id else "cycle",
                "id": self._cycle_run_id,
                "state": "running",
                "limitations": self.progress_label.text(),
            })
        cloud = self.cloud_panel
        if cloud.busy and cloud._active_project == self.project_id:
            rows.append({
                "kind": "scan", "id": cloud._active_scan, "state": "running",
                "limitations": "Облачный сбор; состояние проверки правил показывается отдельно",
            })
        return rows

    def _open_task_center(self) -> None:
        from firewall_compliance.interfaces.desktop.qt_task_center import TaskCenterDialog

        project_id = self.project_id
        if not project_id:
            self.progress_label.setText("Сначала выберите проект для просмотра задач.")
            return
        dialog = TaskCenterDialog(
            self.store, project_id, self._active_tasks,
            lambda: not self._closed and self.project_id == project_id, self,
        )

        def open_run(run_id: str) -> None:
            if self._closed or self.project_id != project_id:
                return
            if self._batch_active or self._restore_busy:
                self.progress_label.setText("Запуск сохранён; открыть его можно после текущей операции.")
                return
            self.load_run(run_id)
            self.navigate("findings")

        def open_scan(scan_id: str) -> None:
            if not self._closed and self.project_id == project_id:
                self.cloud_panel.open_result(scan_id)
                self.navigate("scans")

        dialog.open_run.connect(open_run)
        dialog.open_scan.connect(open_scan)
        dialog.retry_requested.connect(self._retry_task_operation)
        dialog.exec()

    def _retry_task_operation(self, kind: str, task_id: str) -> None:
        if any(editor.property("operationActive") for _, editor in self.integration_editors.values()):
            self.progress_label.setText("Дождитесь завершения операции подключения.")
            return
        if self._batch_active or self._restore_busy or not self.project_id or self.cloud_panel.busy:
            self.progress_label.setText("Дождитесь текущей операции перед повтором.")
            return
        from firewall_compliance.interfaces.desktop.source_cycle import retry_task_inputs

        project_id = self.project_id
        self._restore_busy = True
        self._set_controls_busy(True)

        def done(value: object) -> None:
            if self._closed or self.project_id != project_id:
                return
            self._restore_busy = False
            self._set_controls_busy(False)
            self._refresh_staged()
            if isinstance(value, JobError):
                self.progress_label.setText(
                    "Повтор не подготовлен. Проверьте наличие ошибок, исходных файлов и сохранённого подключения."
                )
                return
            sources, files = value
            answer = QMessageBox.question(
                self, "Повтор неуспешных элементов",
                f"Источников: {len(sources)}, файлов: {len(files)}. "
                "Повторить с текущим профилем? Будет создан новый запуск по данным выбранной задачи; "
                "исходная история сохранится. Ограничение текущей площадки не заменяет область этой задачи.",
            )
            if answer == QMessageBox.StandardButton.Yes:
                self._start_source_cycle(sources, file_inputs=files)

        self.runner.submit(lambda: retry_task_inputs(self.store, project_id, kind, task_id), done)

    def _run_context(self) -> str:
        if not self.run:
            return "Проверка не выбрана · откройте Историю"
        return f"Проверка {self.run_id} · {self.run.get('created_at', '')}"

    def _navigation_changed(self, item: QTreeWidgetItem | None, *_: Any) -> None:
        if item is not None and item.data(0, Qt.ItemDataRole.UserRole):
            self._activate_navigation_item(item)

    def _activate_navigation_item(self, item: QTreeWidgetItem) -> None:
        target = item.data(0, Qt.ItemDataRole.UserRole)
        if not target:
            return
        if str(target).startswith("settings:"):
            key = str(target).split(":", 1)[1]
            self._select_settings_tab(key, 0 if key == "integrations" else 1)
            self.navigate("settings")
        elif str(target).startswith("checks:"):
            self._select_settings_tab("rules", 1)
            self._select_check_settings_group(str(target).split(":", 1)[1])
            self.navigate("settings")
            self.navigation.blockSignals(True)
            self.navigation.setCurrentItem(item)
            self.navigation.blockSignals(False)
        else:
            self.navigate(str(target))

    def _navigation_clicked(self, item: QTreeWidgetItem, *_: Any) -> None:
        if item.data(0, Qt.ItemDataRole.UserRole):
            if item is not self.navigation.currentItem():
                self._activate_navigation_item(item)
        elif item.childCount():
            item.setExpanded(not item.isExpanded())

    def refresh_projects(
        self,
        selected_id: str | None = None,
        *,
        projects: list[dict[str, Any]] | None = None,
        load_immediately: bool = False,
    ) -> None:
        self.project_combo.blockSignals(True)
        self.project_combo.clear()
        for project in self.store.list_projects() if projects is None else projects:
            self.project_combo.addItem(project["name"], project["id"])
        if selected_id:
            self.project_combo.setCurrentIndex(self.project_combo.findData(selected_id))
        self.project_combo.blockSignals(False)
        self._project_changed(load_immediately=load_immediately)

    def create_project(self, name: str) -> str:
        result = self.store.create_project(name)
        project_id = result["id"] if isinstance(result, dict) else result
        self.refresh_projects(str(project_id), load_immediately=True)
        return str(project_id)

    def _open_workspace_sites(self) -> None:
        from firewall_compliance.interfaces.desktop.qt_workspace_sites import WorkspaceSitesDialog

        project_id = self.project_id
        if not project_id:
            QMessageBox.information(self, "Площадки", "Сначала выберите или создайте проект.")
            return
        dialog = WorkspaceSitesDialog(
            self.store,
            self.runner,
            project_id,
            lambda: not self._closed and self.project_id == project_id,
            self,
        )
        dialog.exec()
        if not self._closed and self.project_id == project_id:
            self._reload_site_scope(project_id)

    def _reload_site_scope(self, project_id: str) -> None:
        ticket = object()
        self._site_reload_ticket = ticket
        project_ticket = self._project_load_ticket

        def done(value: Any) -> None:
            if (
                self._closed or self.project_id != project_id
                or self._site_reload_ticket is not ticket
                or self._project_load_ticket is not project_ticket
            ):
                return
            if isinstance(value, JobError):
                self.progress_label.setText("Не удалось обновить площадки: " + value.message)
                return
            snapshot, token = value
            self._project_snapshot, self._snapshot_token = snapshot, token
            self._populate_site_selector(snapshot)
            self._site_changed()

        self.runner.submit(lambda: self._read_stable_snapshot(project_id), done)

    def _create_project_dialog(self) -> None:
        name, accepted = QInputDialog.getText(self, "Новый проект", "Название проекта")
        if accepted and name.strip():
            self.create_project(name.strip())

    def _project_changed(self, *_: Any, load_immediately: bool = False) -> None:
        if hasattr(self, "integration_editors"):
            self._reset_integration_editors()
        project_id = self.project_combo.currentData()
        ticket = object()
        self._project_load_ticket = ticket
        self._loading_settings = True
        self._restore_busy = True
        self._set_controls_busy(True)
        self.pages.setEnabled(False)
        self.navigation.setEnabled(False)
        self.add_data_button.setEnabled(False)
        self.prepare_button.setEnabled(False)
        self.progress.setRange(0, 0)
        self.progress.show()
        self.cancel_button.setEnabled(False)
        self.progress_label.setText("Загружаем проект…")

        def work() -> object:
            if not project_id:
                return None, self._database_token(None)
            snapshot, token = self._read_stable_snapshot(project_id)
            self.store.resource_registry.reconcile(
                project_id, project_observations(snapshot.history, snapshot.scans)
            )
            if token != self._database_token(project_id):
                snapshot, token = self._read_stable_snapshot(project_id)
            return snapshot, token

        def done(value: object) -> None:
            if self._closed or self._project_load_ticket is not ticket:
                return
            self._restore_busy = False
            self._set_controls_busy(False)
            self.pages.setEnabled(True)
            self.navigation.setEnabled(True)
            self.add_data_button.setEnabled(True)
            self.prepare_button.setEnabled(True)
            self.progress.hide()
            if isinstance(value, JobError):
                self._loading_settings = False
                self.project_combo.blockSignals(True)
                self.project_combo.setCurrentIndex(self.project_combo.findData(self.project_id))
                self.project_combo.blockSignals(False)
                self.progress_label.setText("Не удалось загрузить проект. Выберите проект повторно.")
                return
            snapshot, token = value if isinstance(value, tuple) else (None, None)
            self._project_snapshot = snapshot
            self._populate_site_selector(snapshot)
            self._snapshot_token = token
            self._inventory_evidence_token = token
            self._inventory_runs = snapshot.history if snapshot is not None else []
            self._inventory_scans = snapshot.scans if snapshot is not None else []
            try:
                self._apply_project_context()
                self._site_changed()
            except (OSError, sqlite3.Error, ValueError, KeyError):
                self._loading_settings = False
                self._restore_busy = True
                self.pages.setEnabled(False)
                self.navigation.setEnabled(False)
                self.add_data_button.setEnabled(False)
                self.prepare_button.setEnabled(False)
                self.project_combo.blockSignals(True)
                self.project_combo.setCurrentIndex(-1)
                self.project_combo.blockSignals(False)
                self.progress_label.setText(
                    "Не удалось восстановить проект. Выберите другой проект или повторите загрузку."
                )
                return
            self.progress_label.setText("Проект загружен. Выберите раздел или добавьте данные.")

        if self._defer_startup and not load_immediately:
            self.runner.submit(work, done)
        else:
            done(work())

    def _apply_project_context(self) -> None:
        self.workspace_history.clear()
        self._start_after_preflight = False
        self._loading_settings = True
        self.project_id = self.project_combo.currentData()
        if self.controls_panel is not None:
            self.controls_panel.set_project_context(self.project_id, refresh=not self._defer_startup)
        if self.governance_panel is not None:
            self.governance_panel.set_project_context(self.project_id, refresh=not self._defer_startup)
        self._analysis_network_snapshot = None
        self._analysis_result_active = None
        self._analysis_result_active_id = None
        self._analysis_result_ticket = None
        self._analysis_list_ticket = None
        self._acl_map_epoch = object()
        self._acl_map_job_ticket = None
        self._acl_map_job_id = None
        self._acl_map_load_id = None
        self._acl_map_list_ticket = None
        self._acl_map_load_ticket = None
        self._acl_map_run_ticket = None
        self._acl_map_busy = False
        self._acl_map_records = {}
        self._acl_map_loaded_record = None
        self._acl_map_batch_result = None
        self.acl_map_batch_status.setPlainText("Выберите запуск текущего проекта.")
        self.acl_map_saved_status.setText("Карты сохраняют ревизию и доказательства.")
        project_context = getattr(self.advanced_panel, "set_project_context", None)
        if callable(project_context):
            project_context(self.project_id)
        self.registry_panel.set_project(self.project_id, refresh=not self._defer_startup)
        self.cloud_panel.set_project(self.project_id, refresh_history=not self._defer_startup)
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
        self.staged.clear()
        self.notification.hide()
        if self.project_id:
            project = self._read_project_snapshot().project
            settings = project.get("settings", {})
            self.management_settings.load_profile(settings.get("management_profile"))
            self.policy_exposure_settings.load_profile(settings.get("policy_exposure_profile"))
            self.policy_scope_settings.load_profile(settings.get("policy_scope_profile"))
            self.logging_check.setChecked(settings.get("require_logging", True))
            self.comments_check.setChecked(settings.get("require_comments", True))
            self.rule_drop_threshold.setValue(settings.get("rule_count_drop_percent", 30))
            self.inventory_drop_threshold.setValue(settings.get("inventory_count_drop_percent", 30))
            self.fragments_check.blockSignals(True)
            self.fragments_check.setChecked(settings.get("include_fragments", True))
            self.fragments_check.blockSignals(False)
            enabled = settings.get(
                "enabled_check_ids", [key for key in CHECKS if key not in OPTIONAL_SCOPE_CHECKS]
            )
            for check_id, checkbox in self.check_boxes.items():
                checkbox.setChecked(check_id in enabled)
            runs = self._project_runs()
            if runs:
                self.run_id = str(runs[0]["id"])
                self.run = self._get_run(self.run_id)
        self._loading_settings = False
        self._refresh_all()

    def choose_usergate(self) -> None:
        if not self._ensure_project() or self._batch_active or self._restore_busy:
            return
        self.navigate("settings")
        self._select_settings_tab("integrations", 0)
        self._open_integration("usergate")

    def choose_ideco(self) -> None:
        if not self._ensure_project() or self._batch_active or self._restore_busy:
            return
        self.navigate("settings")
        self._select_settings_tab("integrations", 0)
        self._open_integration("ideco")

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
                    and path.suffix.lower() in {".txt", ".cfg", ".conf", ".config", ".json"}
                )
            )

    def choose_files(self) -> None:
        if not self._ensure_project():
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Конфигурации",
            "",
            "Конфигурации (*.txt *.cfg *.conf *.config *.json);;Все файлы (*)",
        )
        if paths:
            self.stage_paths([Path(path) for path in paths])

    def _ensure_project(self) -> bool:
        if self._restore_busy:
            return False
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
                "site_id": self._site_selection or None,
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
        selected_inputs = self._scoped_staged() if self.project_id else ()
        self.run_button.setEnabled(
            bool(selected_inputs)
            and not self._batch_active
            and not self._restore_busy
            and all(item["ready"] and not item["ambiguous"] for item in selected_inputs)
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
            self._start_after_preflight = False
            self.staged.clear()
            self._refresh_staged()

    def remove_staged(self) -> None:
        if not self._batch_active:
            self._start_after_preflight = False
            selected = self._selected_payloads(self.stage_table, self.stage_proxy, self.stage_model)
            self.staged = [item for item in self.staged if item not in selected]
            self._refresh_staged()

    def update_and_check(self) -> None:
        """Discover configured sources without blocking the interface."""
        if any(editor.property("operationActive") for _, editor in self.integration_editors.values()):
            self.progress_label.setText("Дождитесь завершения операции подключения.")
            return
        if self._batch_active or self._restore_busy or not self._ensure_project():
            return
        if self.cloud_panel.busy:
            self.progress_label.setText("Дождитесь текущей облачной операции или отмените её.")
            return
        from firewall_compliance.interfaces.desktop.source_cycle import configured_sources

        project_id = self.project_id
        ticket = object()
        self._source_discovery_ticket = ticket
        self._restore_busy = True
        self._set_controls_busy(True)
        self.progress_label.setText("Подготовка сохранённых источников…")

        def done(value: object) -> None:
            if self._closed or self.project_id != project_id or self._source_discovery_ticket is not ticket:
                return
            self._restore_busy = False
            self._set_controls_busy(False)
            if isinstance(value, JobError):
                self.progress_label.setText("Не удалось прочитать источники: " + value.message)
                self._refresh_staged()
                return
            if not value:
                self._refresh_staged()
                self._update_file_inputs()
                return
            if self._preflight_jobs or any(not item.get("ready") for item in self.staged):
                self.progress_label.setText("Дождитесь определения подготовленных файлов.")
                self._refresh_staged()
                return
            sources = tuple(value)
            if self._site_selection is not None:
                sources = tuple(source for source in sources if (
                    not source.site_ids if self._site_selection == ""
                    else self._site_selection in source.site_ids
                ))
            if not sources:
                self._refresh_staged()
                if self._scoped_staged():
                    self._update_file_inputs()
                else:
                    self.progress_label.setText(
                        "Нет источников или файлов выбранной площадки. Назначьте источники через «Площадки»."
                    )
                return
            self._start_source_cycle(sources)

        self.runner.submit(lambda: configured_sources(self.store, project_id), done)

    def _start_source_cycle(
        self, sources: tuple, *, file_inputs: tuple[FileCycleInput, ...] | None = None
    ) -> None:
        if any(editor.property("operationActive") for _, editor in self.integration_editors.values()):
            self.progress_label.setText("Дождитесь завершения операции подключения.")
            return
        from firewall_compliance.interfaces.desktop.source_cycle import SourceCycleResult, run_source_cycle

        try:
            settings = {
                "management_profile": self.management_settings.profile().model_dump(mode="json"),
                "policy_exposure_profile": self.policy_exposure_settings.profile().model_dump(mode="json"),
                "policy_scope_profile": self.policy_scope_settings.profile().model_dump(mode="json"),
                "require_logging": self.logging_check.isChecked(),
                "require_comments": self.comments_check.isChecked(),
                "enabled_check_ids": [key for key, box in self.check_boxes.items() if box.isChecked()],
                "configuration_complete": self.management_settings.complete.isChecked(),
                "include_fragments": self.fragments_check.isChecked(),
                "rule_count_drop_percent": self.rule_drop_threshold.value(),
                "inventory_count_drop_percent": self.inventory_drop_threshold.value(),
            }
        except ValueError:
            self._open_check_settings()
            return
        rows = self._scoped_staged() if file_inputs is None else ()
        files = tuple(FileCycleInput(
            item["path"], item["device"], site_id=item.get("site_id")
        ) for item in rows) if file_inputs is None else file_inputs
        project_id, epoch = self.project_id, object()
        queue: Queue[CycleProgress | str] = Queue()
        stop = Event()
        self._cycle_epoch, self._cycle_project_id = epoch, project_id
        self._cycle_cancel, self._cycle_progress = stop, queue
        self._cycle_rows = rows
        self._cycle_run_id = None
        self._batch_active = True
        self._batch_cancelled = False
        self._set_controls_busy(True)
        self.cloud_panel._set_busy(True)
        self.cloud_panel.cancel = stop
        self.progress.setRange(0, len(sources) + bool(files))
        self.progress.setValue(0)
        self.progress.show()
        self.cancel_button.setEnabled(True)
        self.progress_label.setText("Обновление настроенных источников…")

        def done(value: object) -> None:
            if self._closed or self._cycle_epoch is not epoch or self.project_id != project_id:
                return
            self._cycle_job_id, self._cycle_epoch = None, None
            self._batch_active = False
            self._set_controls_busy(False)
            self.cloud_panel._set_busy(False)
            self.progress.hide()
            self.cancel_button.setEnabled(False)
            if not isinstance(value, SourceCycleResult):
                self.progress_label.setText(
                    value.message if isinstance(value, JobError)
                    else "Цикл прерван. Сохранённые результаты доступны в центре задач."
                )
                self._refresh_all()
                return
            runs = [item.run_id for item in value.items if item.run_id]
            self._batch_cancelled = any(item.state == "cancelled" for item in value.items)
            if runs:
                self.load_run(runs[-1])
            else:
                self._refresh_all()
            errors = sum(item.state in {"failed", "partial"} for item in value.items)
            warnings = sum(item.warning_count for item in value.items)
            self.progress_label.setText(
                f"Обработано источников: {len(value.items)}. "
                f"С ошибками/ограничениями: {errors}. Предупреждений: {warnings}. Подробности — в центре задач."
            )
            self._completed_run_id = runs[-1] if runs else None
            self.notification_label.setText(self.progress_label.text())
            self.notification_label.setToolTip(
                "\n".join(f"{item.source_id}: {item.state}. {item.message}" for item in value.items)
            )
            self.notification.show()
            self._refresh_staged()

        self._cycle_job_id = self.runner.submit(
            lambda: run_source_cycle(
                self.store, project_id, sources, settings, files=files, cancel=stop, progress=queue.put
            ), done,
        )
        self.management_settings.complete.setChecked(False)

    def _scoped_staged(self) -> tuple[dict[str, Any], ...]:
        if self._site_selection is None:
            return tuple(self.staged)
        assignments = self._source_project_snapshot().site_assignments
        return tuple(item for item in self.staged if (
            assignments.get(str(item["device"]), item.get("site_id") or "") == self._site_selection
        ))

    def _update_file_inputs(self) -> None:
        """Prepare and execute the saved file workflow from one entry point."""
        if self._batch_active or self._restore_busy or not self._ensure_project():
            return
        if self.staged:
            if self._preflight_jobs:
                self._start_after_preflight = True
                self.progress_label.setText("После определения файлов проверка начнётся автоматически.")
            elif self.run_button.isEnabled():
                self.start_analysis()
            else:
                self.navigate("staging")
                self.progress_label.setText("Подтвердите устройства и состав проверок перед запуском.")
            return
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Обновить и проверить")
        dialog.setText("Выберите данные для проверки.")
        dialog.setInformativeText(
            "Ранее загруженные файлы можно заново прочитать с диска. "
            "Это не обновляет конфигурации на самих устройствах."
        )
        choose = dialog.addButton("Выбрать файлы", QMessageBox.ButtonRole.AcceptRole)
        previous = dialog.addButton("Файлы последнего запуска", QMessageBox.ButtonRole.ActionRole)
        integration = dialog.addButton("Интеграции", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton(QMessageBox.StandardButton.Cancel)
        source = self._source_project_snapshot()
        latest = source.history[0] if source.history else None
        previous.setEnabled(
            bool(latest and any(item.get("path") for item in latest["items"]))
        )
        if latest:
            dialog.setDetailedText(
                "\n".join(str(item["path"]) for item in latest["items"] if item.get("path"))
            )
        dialog.exec()
        if dialog.clickedButton() is integration:
            self.choose_data_source()
            return
        if dialog.clickedButton() is choose:
            self.choose_files()
        elif dialog.clickedButton() is previous and latest is not None:
            paths = tuple(
                dict.fromkeys(Path(item["path"]) for item in latest["items"] if item.get("path"))
            )
            self.stage_paths(paths)
        else:
            return
        if self.staged:
            self._start_after_preflight = True
            self.progress_label.setText("Подготовка данных; проверка начнётся после определения файлов.")

    def start_analysis(self) -> None:
        """Capture inputs once; collection, analysis and persistence run in a worker."""
        if any(editor.property("operationActive") for _, editor in self.integration_editors.values()):
            self.progress_label.setText("Дождитесь завершения операции подключения.")
            return
        if not self.run_button.isEnabled() or not self.project_id:
            return
        try:
            settings: dict[str, Any] = {
                "management_profile": self.management_settings.profile().model_dump(mode="json"),
                "policy_exposure_profile": self.policy_exposure_settings.profile().model_dump(
                    mode="json"
                ),
                "policy_scope_profile": self.policy_scope_settings.profile().model_dump(mode="json"),
                "require_logging": self.logging_check.isChecked(),
                "require_comments": self.comments_check.isChecked(),
                "enabled_check_ids": [
                    key for key, box in self.check_boxes.items() if box.isChecked()
                ],
                "configuration_complete": self.management_settings.complete.isChecked(),
                "include_fragments": self.fragments_check.isChecked(),
                "rule_count_drop_percent": self.rule_drop_threshold.value(),
                "inventory_count_drop_percent": self.inventory_drop_threshold.value(),
            }
            rows = self._scoped_staged()
            if not rows:
                self.progress_label.setText("Нет подготовленных файлов выбранной площадки.")
                return
            manifest = tuple(FileCycleInput(
                item["path"], item["device"], site_id=item.get("site_id")
            ) for item in rows)
        except ValueError:
            self._open_check_settings()
            return
        project_id = self.project_id
        epoch = object()
        progress_queue: Queue[CycleProgress | str] = Queue()
        cancel = Event()
        self._cycle_rows = rows
        self._cycle_epoch = epoch
        self._cycle_run_id = None
        self._cycle_project_id = project_id
        self._cycle_cancel = cancel
        self._cycle_progress = progress_queue
        self._start_after_preflight = False
        self._batch_active = True
        self._batch_cancelled = False
        self.notification.hide()
        self._set_controls_busy(True)
        for item in rows:
            item["warning"] = "В очереди получения данных"
        self.progress.setRange(0, len(rows))
        self.progress.setValue(0)
        self.progress.show()
        self.progress_label.setText("Получение и проверка файлов выполняются в фоне.")
        self.cancel_button.setEnabled(True)

        def work() -> FileCycleResult:
            return run_file_cycle(
                self.store,
                project_id,
                manifest,
                settings,
                progress=progress_queue.put,
                cancel=cancel,
                started=progress_queue.put,
            )

        def done(value: object) -> None:
            if self._closed or self._cycle_epoch is not epoch or self.project_id != project_id:
                return
            self._cycle_job_id = None
            self._cycle_epoch = None
            self._batch_active = False
            self._set_controls_busy(False)
            self.progress.hide()
            self.cancel_button.setEnabled(False)
            if not isinstance(value, FileCycleResult):
                self.progress_label.setText(
                    value.message if isinstance(value, JobError)
                    else "Цикл не завершён. Сохранённые результаты доступны в истории."
                )
                for item in rows:
                    item["warning"] = "Цикл прерван; проверьте историю запуска"
                self._refresh_all()
                return
            self.sessions = dict(value.sessions)
            self._map_live_item_ids = set(self.sessions)
            for outcome in value.outcome.sources:
                if outcome.state != "collected":
                    rows[int(outcome.source_id)]["warning"] = outcome.message or "Отменено"
            labels = {
                "complete": "Анализ завершён",
                "partial": "Частичный результат",
                "failed": "Ошибка анализа",
                "cancelled": "Отменено",
            }
            for outcome in value.outcome.items:
                rows[int(outcome.input_id)]["warning"] = outcome.message or labels[outcome.state]
            self._batch_cancelled = value.outcome.state == "cancelled"
            self.load_run(value.run_id)
            self.progress_label.setText(
                "Цикл завершён. Полнота, ограничения и ошибки доступны в результатах."
                if value.outcome.state == "complete"
                else "Цикл завершён с ограничениями. Откройте результаты и ошибки источников."
            )
            self._notify_completion()

        self._cycle_job_id = self.runner.submit(work, done)
        self.management_settings.complete.setChecked(False)
        self._refresh_staged()

    def _poll_cycle_progress(self) -> None:
        changed = False
        while True:
            try:
                event = self._cycle_progress.get_nowait()
            except Empty:
                break
            if self._cycle_job_id is None or self.project_id != self._cycle_project_id:
                continue
            if isinstance(event, str):
                self._cycle_run_id = event
                continue
            changed = True
            self.progress.setRange(0, max(1, event.total))
            self.progress.setValue(event.completed)
            stage = {
                "collection": "Получение данных",
                "analysis": "Анализ",
                "finished": "Завершение",
            }[event.stage]
            self.progress_label.setText(f"{stage}: {event.completed} из {event.total}")
            identifier = event.item_id if event.item_id is not None else event.source_id
            rows = getattr(self, "_cycle_rows", ())
            if (
                identifier is not None
                and identifier.isdecimal()
                and int(identifier) < len(rows)
            ):
                rows[int(identifier)]["warning"] = stage
        if changed:
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
            self.sites_button,
            self.site_selector,
            self.add_data_button,
            self.prepare_button,
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
        self._update_analysis_result_actions()
        self._update_acl_map_actions()

    def poll_jobs(self) -> None:
        """Доставить завершения backend только в Qt-потоке и обновить счётчик пакета."""
        events = self.runner.poll()
        self._poll_cycle_progress()
        if not self._ui_ready or self._loading_settings:
            return
        terminal_jobs = {
            event.job_id
            for event in events
            if event.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELED)
        }
        for event in events:
            if event.status == JobStatus.CANCELED:
                if event.job_id == self._cycle_job_id:
                    self._cycle_job_id = None
                    self._cycle_epoch = None
                    self._batch_active = False
                    self._set_controls_busy(False)
                    self.progress.hide()
                    self.progress_label.setText("Цикл отменён до начала выполнения.")
                if event.job_id == self._analysis_result_save_id:
                    self._analysis_result_save_id = None
                    self._analysis_result_busy = False
                    self.progress_label.setText("Сохранение общего результата отменено до запуска.")
                    self._update_analysis_result_actions()
                if event.job_id == self._acl_map_job_id:
                    self._acl_map_job_ticket = None
                    self._acl_map_busy = False
                    self.acl_map_saved_status.setText("Операция карты отменена до запуска.")
                    self.acl_map_batch_status.setPlainText(
                        "Пакетное построение отменено до запуска."
                    )
                if event.job_id == self._acl_map_load_id:
                    self._acl_map_load_ticket = None
                    self.acl_map_saved_status.setText("Открытие карты отменено до запуска.")
                self._update_acl_map_actions()
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
            if self._start_after_preflight:
                self._start_after_preflight = False
                self._refresh_staged()
                if self.run_button.isEnabled():
                    self.start_analysis()
                else:
                    self.navigate("staging")
                    self.progress_label.setText("Подтвердите неоднозначные устройства перед запуском.")
        if self._batch_active and self._cycle_job_id is None and not self._analysis_jobs:
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
        self.cancel_button.setEnabled(bool(self._cycle_job_id or self.runner.pending_count))

    def _notify_completion(self) -> None:
        self._completed_run_id = self.run_id
        items = self._items()
        states = Counter(item["status"] for item in items)
        partial_count = states["partial"]
        missing_count = sum(not item.get("report") for item in items)
        warnings = [message for item in items for message in item.get("collection_warnings", ())]
        title = (
            "Анализ отменён" if self._batch_cancelled
            else "Анализ завершён с ограничениями" if (self.run or {}).get("state") == "interrupted"
            else "Анализ завершён"
        )
        self.notification_label.setText(
            f"{title} · файлов: {len(items)} · частичных: {partial_count} · "
            f"без результата: {missing_count} · предупреждений о составе: {len(warnings)}."
        )
        self.notification_label.setToolTip("\n".join(warnings))
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
        self._start_after_preflight = False
        if self._cycle_job_id is not None:
            self._batch_cancelled = True
            self._cycle_cancel.set()
            self.progress_label.setText(
                "Отмена запрошена. Текущий файл завершится, остальные будут отмечены отменёнными."
            )
            return
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
        self.run = self._get_run(self.run_id)
        known = {str(item["id"]) for item in self.run.get("items", [])}
        self.sessions = {key: session for key, session in self.sessions.items() if key in known}
        self._map_live_item_ids.intersection_update(known)
        self._refresh_all()

    def _database_token(self, project_id: str | None) -> tuple[Any, ...]:
        values: list[Any] = [project_id]
        for path in (self.store.path, Path(str(self.store.path) + "-wal")):
            try:
                stat = path.stat()
                values.extend((stat.st_mtime_ns, stat.st_size))
            except FileNotFoundError:
                values.extend((None, None))
        return tuple(values)

    def _inventory_token(self) -> tuple[Any, ...]:
        return self._database_token(self.project_id)

    def _read_stable_snapshot(self, project_id: str) -> tuple[ProjectSnapshot, tuple[Any, ...]]:
        for _ in range(3):
            before = self._database_token(project_id)
            snapshot = read_project_snapshot(self.store, project_id)
            if before == self._database_token(project_id):
                return snapshot, before
        raise ValueError("История проекта изменяется во время загрузки")

    def _source_project_snapshot(self) -> ProjectSnapshot:
        if self.project_id is None:
            raise ValueError("Проект не выбран")
        token = self._inventory_token()
        snapshot = self._project_snapshot
        if (
            snapshot is None
            or snapshot.project_id != self.project_id
            or token != self._snapshot_token
        ):
            snapshot, token = self._read_stable_snapshot(self.project_id)
            self._project_snapshot = snapshot
            self._snapshot_token = token
        return snapshot

    def _read_project_snapshot(self) -> ProjectSnapshot:
        snapshot = self._source_project_snapshot()
        return scoped_project_snapshot(snapshot, snapshot.site_assignments, self._site_selection)

    def _project_runs(self) -> list[dict[str, Any]]:
        return self._read_project_snapshot().runs if self.project_id else []

    def _get_run(self, run_id: str) -> dict[str, Any]:
        if self.project_id:
            run = self._source_project_snapshot().run_by_id.get(run_id)
            if run is not None:
                return run
        return self.store.get_run(run_id)

    def _inventory_context(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        if not self.project_id:
            return [], [], []
        token = self._inventory_token()
        if token != self._inventory_evidence_token:
            snapshot = self._source_project_snapshot()
            runs, scans = snapshot.history, snapshot.scans
            self.store.resource_registry.reconcile(
                self.project_id, project_observations(runs, scans)
            )
            self._inventory_runs, self._inventory_scans = runs, scans
            # Reconciliation writes must not certify older evidence as current.
            self._inventory_evidence_token = self._snapshot_token
        resources = self.store.resource_registry.list_resources(
            self.project_id, include_archived=True
        )
        snapshot = self._read_project_snapshot()
        if self._site_selection is not None:
            assignments = snapshot.site_assignments
            resources = [
                resource for resource in resources
                if not (resource.get("source") or {}).get("device_id")
                or assignments.get(str(resource["source"]["device_id"]), "")
                == self._site_selection
            ]
        return resources, snapshot.history, self._inventory_scans

    def _registry_changed(self) -> None:
        self._refresh_summary()
        self._refresh_project_map()

    def _open_registry_operation(self, resource: dict[str, Any]) -> None:
        if self._batch_active or self._restore_busy:
            self.progress_label.setText("Дождитесь завершения текущей проверки.")
            return
        if resource.get("project_id") != self.project_id:
            return
        source = resource.get("source") or {}
        run_id = source.get("run_id")
        if run_id:
            run = self._get_run(run_id)
            if run["project_id"] == self.project_id:
                self.load_run(run_id)
                self.navigate("reports")
        elif source.get("scan_id"):
            self.cloud_panel.open_result(source["scan_id"])
            self.navigate("scans")
        else:
            self.progress_label.setText(
                "Ресурс добавлен вручную; операций сбора и проверки ещё нет."
            )

    def _refresh_all(self) -> None:
        self._dirty_pages.update(SECTION_IDS)
        self._map_pending_item = None
        self._refresh_staged()
        if not self._defer_startup:
            # Embedded consumers keep the synchronous, fully populated window contract.
            self._inventory_context()
            self.registry_panel.refresh()
            self.refresh_findings()
            self._refresh_devices()
            self._refresh_rules()
            self._refresh_history()
            self._refresh_summary()
            self._refresh_report_runs()
            self._refresh_report_summary()
            self._refresh_analysis_results()
            self._refresh_saved_acl_maps()
            self._refresh_map_items()
            refresher = getattr(self.advanced_panel, "refresh_sessions", None)
            if callable(refresher):
                refresher()
            self._dirty_pages.clear()
            self._refresh_context()
            return
        self._refresh_page(self.current_section_id)
        self._refresh_context()

    def _refresh_page(self, page: str) -> None:
        if self.project_id and self._snapshot_token != self._inventory_token():
            self._dirty_pages.update(SECTION_IDS)
        if page not in self._dirty_pages:
            return
        self._dirty_pages.discard(page)
        if page == "home":
            self._refresh_summary()
        elif page == "findings":
            self.refresh_findings()
        elif page == "devices":
            self._inventory_context()
            self.registry_panel.refresh()
            self._refresh_devices()
        elif page == "rules":
            self._refresh_rules()
        elif page == "history":
            self._refresh_history()
        elif page == "reports":
            self._refresh_report_runs()
            self._refresh_report_summary()
            self._refresh_analysis_results()
            if self.controls_panel is not None:
                self.controls_panel.refresh_results()
            if self.governance_panel is not None:
                self.governance_panel.refresh_results()
        elif page == "map":
            pending, self._map_pending_item = self._map_pending_item, None
            self._refresh_map_items(pending)
            self._refresh_project_map()
            self._refresh_saved_acl_maps()
        elif page == "scans":
            self.cloud_panel.refresh_history(self._cloud_scans())
        elif page == "advanced":
            refresher = getattr(self.advanced_panel, "refresh_sessions", None)
            if callable(refresher):
                refresher()

    def _items(self) -> list[dict[str, Any]]:
        return self.run.get("items", []) if self.run else []

    def _view_items(self) -> list[dict[str, Any]]:
        """Visible subset only; forensic reads and exporters retain the full run."""
        if self._site_selection is None or not self.project_id:
            return self._items()
        return [
            item for item in self._items()
            if self._site_contains_device((item.get("report") or {}).get("device_id"))
        ]

    def _site_contains_device(self, device_id: str | None) -> bool:
        if self._site_selection is None or not device_id or not self.project_id:
            return True
        return (
            self._source_project_snapshot().site_assignments.get(str(device_id), "")
            == self._site_selection
        )

    def _marks(self) -> dict[str, Any]:
        return self._get_run(self.run_id).get("marks", {}) if self.run_id else {}

    def refresh_findings(self, *_: Any) -> None:
        if self._defer_startup and self.current_section_id != "findings":
            self._dirty_pages.add("findings")
            return
        items = (
            self._project_devices()
            if self.finding_scope.currentData() == "project"
            else [{**item, "run_id": self.run_id} for item in self._view_items()]
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
            run_id: self._get_run(run_id).get("marks", {})
            for run_id in {item["run_id"] for item in items if item.get("run_id")}
        }
        rows, payloads = [], []
        coverage: Counter[str] = Counter()
        search = self.finding_search.text().casefold()
        for item in items:
            report = item.get("report") or {}
            rule_index = {
                rule["rule_id"]: rule for rule in (item.get("parse_result") or {}).get("rules", [])
            }
            rule_matches = {
                key: self.finding_conditions.match(rule) for key, rule in rule_index.items()
            } if self.finding_conditions.query.active else {}
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
                    related_ids = set(finding.get("affected_rule_ids", ())) | set(
                        finding.get("evidence", {}).get("related_rule_ids", ())
                    )
                    condition_match: bool | None = True
                    if self.finding_conditions.query.active:
                        matches = [rule_matches.get(rule_id) for rule_id in related_ids]
                        condition_match = (
                            True if True in matches else None if not matches or None in matches else False
                        )
                        if not self.finding_conditions.accepts(condition_match):
                            continue
                    row = (
                        SEVERITIES.get(finding["severity"], finding["severity"]),
                        report["device_id"],
                        CHECKS.get(check["check_id"], check["check_id"]),
                        finding["title"],
                        STATUSES.get(status, status),
                        check_status_label(check) + (" · фильтр неизвестен" if condition_match is None else ""),
                    )
                    if search:
                        search_text = " ".join(row) + _json(finding.get("evidence", {}))
                        search_text += " ".join(
                            _json(rule_index[rule_id]) for rule_id in related_ids if rule_id in rule_index
                        )
                        if search not in search_text.casefold():
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
        related_ids = set(finding.get("affected_rule_ids", ())) | set(evidence.get("related_rule_ids", ()))
        related_rules = [
            rule for rule in (item.get("parse_result") or {}).get("rules", [])
            if rule.get("rule_id") in related_ids
        ]
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
        if related_ids:
            pieces.append("<h3>Затронутые правила и условия</h3>")
            facts = evidence.get("facts", {})
            covering = set(facts.get("covering_rule_ids", ()))
            target = facts.get("target_rule_id")
            for rule in sorted(related_rules, key=lambda value: (value.get("sequence", 0), value["rule_id"])):
                role = (
                    "Перекрываемое правило" if rule["rule_id"] == target
                    else "Перекрывающее правило" if rule["rule_id"] in covering
                    else "Связанное правило"
                )
                pieces.append(f"<h4>{role}: {html.escape(rule['name'])}</h4>")
                pieces.append(_fields_html((
                    ("ID / порядок", f"{rule['rule_id']} / {rule.get('sequence', '—')}"),
                    ("Политика / направление", f"{rule.get('policy_id') or 'не указана'} / {rule.get('policy_direction') or 'не указано'}"),
                    ("Источник", rule_endpoint_summary(rule, "sources")),
                    ("Назначение", rule_endpoint_summary(rule, "destinations")),
                    ("Сервисы", rule_service_summary(rule)),
                    ("Действие / включено", f"{rule.get('action', 'unknown')} / {rule.get('enabled', 'неизвестно')}"),
                    ("Полнота условий", str(rule.get("match_status", "unknown"))),
                )))
            missing = related_ids - {rule["rule_id"] for rule in related_rules}
            if missing:
                pieces.append("<p>Условия отсутствуют в этом сохранённом снимке: " + html.escape(", ".join(sorted(missing))) + ".</p>")
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

    def finding_history_html(self, timeline: dict[str, Any]) -> str:
        """Render stored transitions without treating a legacy state as a past event."""
        baseline = timeline["baseline"]
        parts = ["<h3>История решений по находке</h3>"]
        if not timeline["history_complete"]:
            parts.append(
                "<p>До включения журнала сохранено только последнее решение. "
                "Более ранние переходы неизвестны.</p>"
            )
        parts.append(
            "<p>Исходное состояние журнала: "
            + html.escape(STATUSES.get(baseline["status"], baseline["status"]))
            + "<br>Комментарий: "
            + html.escape(baseline["comment"])
            + "</p>"
        )
        for event in timeline["events"]:
            previous = STATUSES.get(event["previous_status"], event["previous_status"])
            current = STATUSES.get(event["new_status"], event["new_status"])
            parts.append(
                "<p><b>"
                + html.escape(str(event["changed_at"]))
                + "</b><br>"
                + html.escape(previous)
                + " → "
                + html.escape(current)
                + "<br>Прежний комментарий: "
                + html.escape(event["previous_comment"])
                + "<br>Новый комментарий: "
                + html.escape(event["new_comment"])
                + "</p>"
            )
        if not timeline["events"]:
            parts.append("<p>Изменений с момента включения журнала нет.</p>")
        return "".join(parts)

    def show_finding_history(self) -> None:
        selected = self._selected_payloads(
            self.finding_table, self.finding_proxy, self.finding_model
        )
        if not selected or not self.project_id:
            return
        payload = selected[0]
        run_id = payload["item"].get("run_id") or self.run_id
        if not run_id:
            return
        try:
            timeline = self.store.finding_mark_timeline(
                self.project_id, run_id, str(payload["finding"]["finding_id"])
            )
        except (KeyError, ValueError, sqlite3.Error):
            self.progress_label.setText("Не удалось прочитать историю решений по находке.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("История решений")
        dialog.resize(720, 500)
        layout = QVBoxLayout(dialog)
        view = QTextBrowser()
        view.setObjectName("findingTransitionHistory")
        view.setHtml(self.finding_history_html(timeline))
        layout.addWidget(view)
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
        self._refresh_summary()

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
        return self._read_project_snapshot().devices if self.project_id else []

    def _cloud_scans(self) -> list[dict[str, Any]]:
        return self._read_project_snapshot().scans if self.project_id else []

    def _cloud_history_changed(self) -> None:
        self._inventory_evidence_token = None
        if not self._loading_settings:
            self._refresh_all()

    def _open_cloud_analysis(self, run_id: str) -> None:
        if self._batch_active or self._restore_busy:
            self.progress_label.setText("Дождитесь завершения текущей проверки.")
            return
        run = self._get_run(run_id)
        if run["project_id"] != self.project_id:
            return
        self.load_run(run_id)
        self.finding_scope.setCurrentIndex(self.finding_scope.findData("run"))
        self.finding_search.clear()
        for combo in (
            self.finding_device,
            self.finding_check,
            self.severity_filter,
            self.status_filter,
        ):
            combo.setCurrentIndex(0)
        self.navigate("findings")

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
        if self._defer_startup and self.current_section_id != "devices":
            self._dirty_pages.add("devices")
            return
        self._refresh_context()
        self._clear_map_selection()
        rows: list[tuple[Any, ...]] = []
        items = (
            self._project_devices()
            if self.device_scope.currentData() == "project"
            else self._view_items()
        )
        if self.device_scope.currentData() == "project":
            analyses = {
                (item["cloud_origin"]["scan_id"], item["cloud_origin"]["resource_id"]): item
                for item in items
                if item.get("cloud_origin")
            }
            inventory = cloud_resources(self._cloud_scans())
            for resource in inventory:
                analysis = analyses.get((resource["scan"]["id"], resource["record"].get("id")))
                if analysis:
                    resource.update(
                        {
                            key: analysis[key]
                            for key in (
                                "report",
                                "parse_result",
                                "revision",
                                "cloud_origin",
                                "run_id",
                            )
                        }
                    )
            items = [*(item for item in items if not item.get("cloud_origin")), *inventory]
            error_runs = (
                self._read_project_snapshot().history
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
                        str(sum(len(check["findings"]) for check in item["report"]["checks"]))
                        if item.get("report")
                        else "Не проверено",
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
                    configuration.get("platform", "—") + " · " + str(
                        (parsed.get("switch_facts") or {}).get("os_version")
                        or "версия не определена"
                    ),
                    "Сетевое устройство" if report else "Источник без результата",
                    (
                        switch_summary(parsed) if parsed.get("switch_policies")
                        else len(parsed.get("rules", [])) if parsed else "—"
                    ),
                )
            )
        self.device_model.replace(rows, items)

    def _open_switch_details(self) -> None:
        """Открыть факты сохранённой ревизии, не меняя исторические результаты."""
        items = self._selected_payloads(self.device_table, self.device_proxy, self.device_model)
        if len(items) != 1:
            QMessageBox.information(self, "Сведения об устройстве", "Выберите один снимок устройства.")
            return
        item = items[0]
        parsed = item.get("parse_result") or {}
        if not parsed.get("switch_facts") and not parsed.get("switch_policies"):
            QMessageBox.information(
                self, "Сведения об устройстве",
                "В этой ревизии факты коммутатора не сохранены. Импортируйте конфигурацию заново для новой ревизии.",
            )
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Структура и политики устройства")
        dialog.resize(1100, 720)
        layout = QVBoxLayout(dialog)
        panel = SwitchDetailsPanel(dialog)
        panel.set_item(item)

        def show_source(location: object) -> None:
            session = self.sessions.get(str(item.get("id")))
            if session is None:
                panel.show_source("Подключите исходник с совпадающим SHA-256 в карточке источника.")
                return
            if not isinstance(location, dict):
                return
            try:
                preview = source_preview(session, SourceLocation.model_validate(location))
                panel.show_source(safe_switch_source(preview))
            except ValueError:
                panel.show_source("Фрагмент недоступен: проверьте источник и диапазон строк.")

        panel.source_requested.connect(show_source)
        layout.addWidget(panel)
        dialog.exec()

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
                button.setEnabled(
                    is_local and not item.get("cloud_origin") and bool(item.get("report"))
                )
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
            + (
                "<p>Проверки Edge Firewall выполнены; находки доступны в «Проблемах». "
                "Ограничения и неполные условия указаны в отчёте.</p>"
                if item.get("report")
                else "<p>Не проверено. Выполните проверку правил сохранённого сбора.</p>"
            )
            + "<p>Сбор данных не подтверждает эффективную достижимость сети.</p>"
            "<h3>Параметры ресурса</h3>"
            f"<pre>{html.escape(_json(record.get('inventory', {})))}</pre>"
            "<p>Ошибки и запросы доступны в исходной операции сбора.</p>"
        )

    def _refresh_rules(self, *_: Any) -> None:
        if self._defer_startup and self.current_section_id != "rules":
            self._dirty_pages.add("rules")
            return
        self._refresh_context()
        rows, payloads = [], []
        cloud_count = 0
        items = (
            self._project_devices()
            if self.rule_scope.currentData() == "project"
            else self._view_items()
        )
        self.rule_detail.clear()
        analyzed = {
            (item["cloud_origin"]["scan_id"], item["cloud_origin"]["resource_id"])
            for item in items
            if item.get("cloud_origin")
        }
        for item in items:
            parsed = item.get("parse_result") or {}
            device = (item.get("report") or {}).get("device_id", "")
            for rule in parsed.get("rules", []):
                if (
                    self.rule_category.currentData()
                    and rule_category(rule) != self.rule_category.currentData()
                ):
                    continue
                condition_match = self.rule_conditions.match(rule)
                if not self.rule_conditions.accepts(condition_match):
                    continue
                if item.get("cloud_origin"):
                    cloud_count += 1
                rows.append(
                    (
                        device,
                        rule["sequence"],
                        rule["name"] + " · " + PURPOSE_LABELS[rule_category(rule)],
                        dict(rule_details(rule)).get("Действие", rule["action"]),
                        rule_endpoint_summary(rule, "sources"),
                        rule_endpoint_summary(rule, "destinations"),
                        rule_service_summary(rule) + (" · фильтр неизвестен" if condition_match is None else ""),
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
                if self.rule_conditions.query.active or self.rule_category.currentData():
                    continue
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
        if (
            self.rule_scope.currentData() == "project"
            and self.rule_category.currentData() in {"", "unknown"}
        ):
            for item in cloud_resources(self._cloud_scans()):
                device = item["record"].get("name") or item["record"].get("id", "Cloud.ru")
                for value in cloud_rule_values(item["record"]):
                    if self.rule_conditions.query.active and not self.rule_conditions.include_unknown:
                        continue
                    if (item["scan"]["id"], item["record"].get("id")) in analyzed and value[
                        "group"
                    ] != "nat":
                        continue
                    columns = list(cloud_rule_columns(value))
                    if self.rule_conditions.query.active:
                        columns[-1] = str(columns[-1]) + " · фильтр неизвестен"
                    rows.append((device, *columns))
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
                "Для анализа выберите сохранённый сбор в «Операции → Облачный сбор»."
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
                + (acl_rule_html(item.get("parse_result") or {}, value) if "rule_id" in value else "")
            )

    def _refresh_summary(self) -> None:
        if self._defer_startup and self.current_section_id != "home":
            self._dirty_pages.add("home")
            self._dirty_pages.add("reports")
            return
        resources, history, saved_scans = self._inventory_context()
        self.compact_dashboard.refresh(
            build_dashboard(
                resources,
                history,
                saved_scans,
                self.store.list_map_integrations(self.project_id) if self.project_id else [],
                self._source_project_snapshot().source_health if self.project_id else (),
            )
        )
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
        runs = self._project_runs()
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
            latest = self._read_project_snapshot().run_by_id[last["id"]]
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

    def _refresh_report_runs(self) -> None:
        self.report_run.blockSignals(True)
        self.report_run.clear()
        for run in self._source_project_snapshot().runs if self.project_id else []:
            self.report_run.addItem(f"{run['created_at']} · {run['id']}", run["id"])
        self.report_run.setCurrentIndex(self.report_run.findData(self.run_id))
        self.report_run.setEnabled(not self._batch_active and not self._restore_busy)
        self.report_run.blockSignals(False)

    def _refresh_report_summary(self) -> None:
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
        if self._defer_startup and self.current_section_id != "history":
            self._dirty_pages.add("history")
            return
        runs = self._project_runs()
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
        if self._restore_busy:
            self.history_detail.setPlainText("Дождитесь открытия выбранного проекта или запуска.")
            return
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
        try:
            if any(datetime.fromisoformat(run["created_at"]).utcoffset() is None for run in selected):
                raise ValueError("Run timestamp has no timezone")
            ordered = sorted(selected, key=lambda run: datetime.fromisoformat(run["created_at"]))
            snapshot = self._read_project_snapshot()
            before, after = (snapshot.run_by_id[run["id"]] for run in ordered)
        except (ValueError, TypeError, KeyError):
            self.history_detail.setPlainText("Не удалось определить время или область выбранных запусков.")
            return
        self._open_run_comparison(before, after)

    def compare_with_previous_run(self) -> None:
        from firewall_compliance.interfaces.desktop.run_comparison import previous_comparable_run

        if self._restore_busy or not self.project_id:
            return
        selected = self._selected_payloads(self.history_table, self.history_proxy, self.history_model)
        if len(selected) != 1 or selected[0].get("operation_kind") == "collection":
            self.history_detail.setPlainText("Выберите одну проверку для поиска предыдущего сопоставимого запуска.")
            return
        snapshot = self._read_project_snapshot()
        after = snapshot.run_by_id.get(selected[0]["id"])
        if after is None:
            return
        before = previous_comparable_run(tuple(snapshot.run_by_id.values()), after)
        if before is None:
            self.history_detail.setPlainText(
                "Предыдущего полного сопоставимого запуска нет: нужны подтверждённый одинаковый профиль, "
                "та же область входов и состав устройств, платформа/контекст, парсер и версии выполненных проверок. "
                "Для просмотра ограниченных различий выберите два запуска вручную."
            )
            return
        self._open_run_comparison(
            before, after,
            "Выбран ближайший предыдущий полный запуск с тем же подтверждённым профилем, "
            "областью входов, составом устройств, контекстами, парсером и версиями проверок. Другую пару можно выбрать в истории.",
        )

    def _open_run_comparison(
        self, before: dict[str, Any], after: dict[str, Any],
        selection_basis: str = "Два запуска выбраны вручную.",
    ) -> None:
        from firewall_compliance.interfaces.desktop.qt_run_comparison import RunComparisonDialog
        from firewall_compliance.interfaces.desktop.run_comparison_store import RunComparisonStore

        project_id, site_id = self.project_id, self._site_selection
        if not project_id:
            return
        identities = (
            (before["id"], frozenset(item["id"] for item in before["items"])),
            (after["id"], frozenset(item["id"] for item in after["items"])),
        )

        def load_runs() -> tuple[dict[str, Any], dict[str, Any]]:
            values = []
            for run_id, item_ids in identities:
                run = self.store.get_run(run_id)
                if run["project_id"] != project_id:
                    raise ValueError("Comparison run belongs to another project")
                if site_id is not None:
                    run["items"] = [item for item in run["items"] if item["id"] in item_ids]
                run["site_selection"] = site_id
                values.append(run)
            return values[0], values[1]

        dialog = RunComparisonDialog(
            {"id": before["id"], "created_at": before["created_at"]},
            {"id": after["id"], "created_at": after["created_at"]}, self.runner, self,
            context_valid=lambda: (
                not self._closed and not self._restore_busy
                and self.project_id == project_id and self._site_selection == site_id
            ),
            load_runs=load_runs,
            selection_basis=selection_basis,
            comparison_store=RunComparisonStore(self.store.path) if isinstance(getattr(self.store, "path", None), Path) else None,
        )
        dialog.exec()
        dialog.deleteLater()

    def open_comparison_history(self) -> None:
        from firewall_compliance.interfaces.desktop.qt_run_comparison import ComparisonHistoryDialog
        from firewall_compliance.interfaces.desktop.run_comparison_store import RunComparisonStore

        project_id, site_id = self.project_id, self._site_selection
        if not project_id or self._restore_busy or not isinstance(getattr(self.store, "path", None), Path):
            return
        dialog = ComparisonHistoryDialog(
            RunComparisonStore(self.store.path), self.runner, project_id, self, site_id=site_id,
            context_valid=lambda: (
                not self._closed and not self._restore_busy and self.project_id == project_id
                and self._site_selection == site_id
            ),
        )
        dialog.exec()
        dialog.deleteLater()

    def preview_batch_report(self) -> None:
        self._open_batch_report_dialog()

    def _open_batch_report_dialog(self, target: tuple[str, Path] | None = None) -> None:
        from firewall_compliance.interfaces.desktop.qt_batch_report import BatchReportDialog

        project_id, run_id = self.project_id, self.run_id
        if not project_id or not run_id:
            self.progress_label.setText("Откройте сохранённый запуск для отчёта.")
            return
        dialog = BatchReportDialog(
            self.store, self.runner, project_id, run_id, self,
            include_fragments=self.fragments_check.isChecked(), target=target,
            context_valid=lambda: (
                not self._closed and self.project_id == project_id and self.run_id == run_id
            ),
        )
        dialog.exec()
        if not self._closed and self.project_id == project_id and dialog.saved_path is not None:
            self.progress_label.setText("Отчёт сохранён: " + dialog.saved_path.name)
        dialog.deleteLater()

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
            self._open_batch_report_dialog((kind, Path(filename)))
            return
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
        if any(editor.property("operationActive") for _, editor in self.integration_editors.values()):
            self.progress_label.setText("Дождитесь завершения операции подключения.")
            return
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
        if any(editor.property("operationActive") for _, editor in self.integration_editors.values()):
            self.progress_label.setText("Дождитесь завершения операции подключения.")
            return
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
            policy_exposure_profile = self.policy_exposure_settings.profile()
            policy_scope_profile = self.policy_scope_settings.profile()
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
                "policy_exposure_profile": policy_exposure_profile.model_dump(mode="json"),
                "policy_scope_profile": policy_scope_profile.model_dump(mode="json"),
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
                policy_exposure_profile=policy_exposure_profile,
                policy_scope_profile=policy_scope_profile,
            ),
            done,
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        """Отключить поздние callbacks без ожидания выполняющегося worker."""
        if hasattr(self, "integration_editors"):
            self._reset_integration_editors()
        self._closed = True
        self._cycle_cancel.set()
        self._cycle_epoch = None
        if not self._ui_ready:
            self.timer.stop()
            self.runner.shutdown()
            event.accept()
            return
        if self.controls_panel is not None:
            self.controls_panel.shutdown()
        if self.governance_panel is not None:
            self.governance_panel.shutdown()
        self.cloud_panel.close()
        self.timer.stop()
        if self.run_id and self._batch_active and self._cycle_job_id is None:
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
        window = MainWindow(defer_startup=True)
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
