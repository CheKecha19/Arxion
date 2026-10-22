"""Сетевые формы desktop: отдельные роли, provenance и локальные решения."""

from __future__ import annotations

import json
import tkinter as tk
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID, uuid4

from pydantic import BaseModel

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.interfaces.desktop.jobs import JobError
from firewall_compliance.interfaces.desktop.network_backend import (
    NetworkDocumentDraft,
    import_documents,
    parse_forwarding,
    run_network_query,
)

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.backend import AnalysisSession


NETWORK_METADATA: dict[str, object] = {
    "source_kind": "asa_running_config_interfaces",
    "context_mode": "single",
    "context": None,
    "firewall_mode": "routed",
    "declared_version": "",
    "version_provenance": "operator_declared",
    "version_reference": "",
    "origin": "operator_declared",
    "origin_reference": "",
    "address_family": "ipv4",
    "table_role": "data",
    "table_id": "default",
    "command": "",
    "encoding": "utf-8",
    "selection": "partial",
    "extent": "excerpt",
    "capture_success": False,
    "complete": False,
    "completeness_reference": None,
}
FORWARDING_METADATA: dict[str, object] = {
    "purpose": "configuration",
    "command": "",
    "declared_version": "",
    "version_provenance": "operator_declared",
    "version_reference": "",
    "origin": "operator_declared",
    "origin_reference": "",
    "selection": "partial",
    "extent": "excerpt",
    "encoding": "utf-8",
    "capture_success": False,
    "complete_scopes": [],
    "completeness_reference": None,
}
BINDING_TEMPLATE: dict[str, object] = {
    "policy_id": "",
    "direction": "in",
    "interface_id": "",
    "interface_label": "",
    "interface_mapping_reference": "",
    "source_document_id": "",
    "binding_location": {"source_name": "", "line_start": None},
    "complete": False,
    "completeness_reference": None,
    "declaration_origin": "operator_declared",
    "implicit_action": "unknown",
    "terminal": False,
    "terminal_reference": None,
    "coordinate_space": "acl_input",
}


@dataclass
class NetworkState:
    """Память сессии; исходные контракты не заменяются UI DTO."""

    imported: dict[UUID, NetworkImportResult] = field(default_factory=dict)
    results: dict[tuple[UUID, str], BaseModel] = field(default_factory=dict)
    drafts: dict[UUID, list[NetworkDocumentDraft]] = field(default_factory=dict)
    jobs: dict[tuple[UUID, str], UUID] = field(default_factory=dict)


class JsonForm(ttk.Frame):
    """Редактор явного контракта с подсказкой и прокруткой."""

    def __init__(self, parent: tk.Misc, title: str, value: object, *, height: int = 12):
        super().__init__(parent)
        label = ttk.Label(self, text=title, wraplength=400)
        label.pack(anchor="w", fill="x", pady=(4, 3))

        def wrap_title(event: tk.Event[tk.Misc]) -> None:
            label.configure(wraplength=max(180, event.width - 16))

        self.bind("<Configure>", wrap_title)
        area = ttk.Frame(self)
        area.pack(fill="both", expand=True)
        self.text = tk.Text(area, height=height, wrap="word", font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(area, command=self.text.yview)
        self.text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.text.pack(fill="both", expand=True)
        self.set(value)

    def set(self, value: object) -> None:
        self.text.delete("1.0", "end")
        self.text.insert("1.0", json.dumps(value, ensure_ascii=False, indent=2))

    def get(self) -> dict[str, Any]:
        value = json.loads(self.text.get("1.0", "end"))
        if not isinstance(value, dict):
            raise ValueError("Ожидается JSON-объект.")
        return cast(dict[str, Any], value)


class NetworkPanel(ttk.Frame):
    """Фоновый импорт и API первого сетевого среза в выбранной реальной сессии."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        get_sessions: Callable[[], tuple[AnalysisSession, ...]],
        submit: Callable[[Callable[[], object], Callable[[object], None]], None],
        state: NetworkState | None = None,
    ) -> None:
        super().__init__(parent)
        self.get_sessions = get_sessions
        self.submit = submit
        self.network_state = state if state is not None else NetworkState()
        self.sessions = get_sessions()
        self.base_var = tk.StringVar()
        self.status = tk.StringVar(value="Выберите базовую реальную ASA-сессию.")
        self.current_result: BaseModel | None = None
        self.generation = 0
        self._build()
        self.refresh_sessions()

    def _build(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", padx=10, pady=6)
        ttk.Label(header, text="Базовая конфигурация и revision UUID:").pack(anchor="w")
        self.session_combo = ttk.Combobox(header, textvariable=self.base_var, state="readonly")
        self.session_combo.pack(side="left", fill="x", expand=True)
        self.session_combo.bind("<<ComboboxSelected>>", self._context_changed)
        ttk.Button(header, text="Обновить сессии", command=self.refresh_sessions).pack(side="left")
        ttk.Label(self, textvariable=self.status, wraplength=1050).pack(anchor="w", padx=10)
        ttk.Label(
            self,
            wraplength=1050,
            text="Выбор маршрута и локальный ACL не доказывают итоговую доступность. "
            "Enabled означает только административное состояние. NAT/PBR, полный путь, "
            "матрицы и общий отчёт ещё не поддерживаются. Сетевые API этой панели только для ASA; "
            "HP/Aruba и Comware разбираются на основном экране импорта.",
        ).pack(anchor="w", padx=10, pady=5)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        self.tab_hosts: dict[ttk.Frame, ttk.Frame] = {}
        self.import_tab = self._tab("Сетевые документы")
        self.inventory_tab = self._tab("Интерфейсы / маршруты")
        self.query_tab = self._tab("Маршрут / локальный ACL")
        self.forward_tab = self._tab("Forwarding ASA")
        self.result_tab = self._tab("Результат / JSON")
        self._build_import()
        self._build_inventory()
        self._build_query()
        self._build_forwarding()
        self.saved_result = tk.StringVar()
        self.saved_combo = ttk.Combobox(
            self.result_tab, textvariable=self.saved_result, state="readonly"
        )
        self.saved_combo.pack(fill="x", pady=4)
        self.saved_combo.bind("<<ComboboxSelected>>", self._show_saved)
        ttk.Button(
            self.result_tab, text="Сохранить оригинальную модель JSON", command=self._export
        ).pack(anchor="w", pady=5)
        self.output = tk.Text(self.result_tab, wrap="word", font=("Consolas", 10))
        scroll = ttk.Scrollbar(self.result_tab, command=self.output.yview)
        self.output.configure(yscrollcommand=scroll.set, state="disabled")
        scroll.pack(side="right", fill="y")
        self.output.pack(fill="both", expand=True)

    def _tab(self, title: str) -> ttk.Frame:
        host = ttk.Frame(self.notebook)
        canvas = tk.Canvas(host, highlightthickness=0)
        scrollbar = ttk.Scrollbar(host, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        tab = ttk.Frame(canvas, padding=8)
        window = canvas.create_window((0, 0), window=tab, anchor="nw")

        def resize_frame(_event: tk.Event[tk.Misc]) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_canvas(event: tk.Event[tk.Misc]) -> None:
            canvas.itemconfigure(window, width=event.width)

        tab.bind("<Configure>", resize_frame)
        canvas.bind("<Configure>", resize_canvas)
        self.notebook.add(host, text=title)
        self.tab_hosts[tab] = host
        return tab

    def _build_import(self) -> None:
        panes = ttk.Panedwindow(self.import_tab, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left, right = ttk.Frame(panes), ttk.Frame(panes)
        panes.add(left, weight=3)
        panes.add(right, weight=2)
        self.network_path = tk.StringVar()
        self._file_field(left, self.network_path)
        self.metadata = JsonForm(
            left,
            "Metadata одного документа: заполните команду, версию, ссылки provenance. "
            "Роли: asa_running_config_interfaces / asa_running_config_static_routes / "
            "asa_ipv4_rib. "
            "device_id, UUID и SHA-256 берутся из реальной сессии и байтов файла.",
            NETWORK_METADATA,
            height=16,
        )
        self.metadata.pack(fill="both", expand=True)
        self.document_observation = JsonForm(
            left,
            "Observation этого файла ({} = неизвестно). Формат: observed_at ISO с timezone, "
            "method operator_declared/device_export/synthetic, reference. Время не подставляется.",
            {},
            height=4,
        )
        self.document_observation.pack(fill="x")
        ttk.Button(left, text="Добавить документ с этими metadata", command=self._stage).pack(
            anchor="w", pady=4
        )
        self.baseline_observation = JsonForm(
            right,
            "Отдельное основание observation базовой конфигурации ({} сохраняет неизвестное). "
            "Тот же формат ObservationEvidence; не время файла или импорта.",
            {},
            height=5,
        )
        self.baseline_observation.pack(fill="x")
        self.window = JsonForm(
            right,
            "Согласованный интервал базового снимка, если нужен: start/end ISO с timezone, "
            "reason. {} = не заявлен.",
            {},
            height=4,
        )
        self.window.pack(fill="x")
        ttk.Label(right, text="Очередь ролей для нового snapshot:").pack(anchor="w", pady=4)
        self.draft_list = tk.Listbox(right, height=8)
        self.draft_list.pack(fill="both", expand=True)
        ttk.Button(right, text="Убрать выбранный документ", command=self._remove_draft).pack(
            anchor="w", pady=4
        )
        ttk.Button(right, text="Импортировать вместе → новая ревизия", command=self._import).pack(
            anchor="w", pady=4
        )

    def _build_inventory(self) -> None:
        ttk.Label(
            self.inventory_tab,
            wraplength=1000,
            text="Отдельные наборы: configured_routes не заменяет наблюдаемую RIB. "
            "Полные metadata, interface_settings, source_map, diagnostics и ограничения "
            "сохранены в NetworkImportResult.documents.",
        ).pack(anchor="w")
        self.inventory = ttk.Treeview(self.inventory_tab, columns=("kind", "status", "count"))
        for key, title in (
            ("#0", "Документ / набор"),
            ("kind", "Роль"),
            ("status", "Статус"),
            ("count", "Фактов"),
        ):
            self.inventory.heading(key, text=title)
        self.inventory.pack(fill="both", expand=True, pady=8)
        self.inventory.bind("<<TreeviewSelect>>", self._show_document)
        ttk.Button(
            self.inventory_tab,
            text="Показать и экспортировать полный NetworkImportResult",
            command=self._show_import,
        ).pack(anchor="w")

    def _build_query(self) -> None:
        form = ttk.Frame(self.query_tab)
        form.pack(fill="x")
        self.query_vars: dict[str, tk.StringVar] = {}
        for row, (key, title, default) in enumerate(
            (
                ("ingress_interface_id", "Входной interface_id", ""),
                ("source_ip", "Source IP в координатах acl_input", ""),
                ("destination_ip", "Destination IP в координатах acl_input", ""),
                ("protocol", "TCP / UDP / ICMP (tcp/udp/icmp)", "tcp"),
                ("destination_port", "Destination port (пусто для ICMP)", ""),
                ("table_id", "Таблица", "default"),
            )
        ):
            var = tk.StringVar(value=default)
            self.query_vars[key] = var
            ttk.Label(form, text=title).grid(row=row, column=0, sticky="w", pady=2)
            ttk.Entry(form, textvariable=var, width=50).grid(row=row, column=1, sticky="ew", pady=2)
        form.columnconfigure(1, weight=1)
        self.binding = JsonForm(
            self.query_tab,
            "Явная декларация PolicyBindingEvidence. Укажите существующий source UUID, "
            "имя и позицию access-group, label↔interface mapping и его основание. "
            "complete/terminal "
            "можно заявить только с реальными completeness_reference/terminal_reference. "
            "Наличие ACL не является доказательством; NAT-нормализация не выполняется.",
            BINDING_TEMPLATE,
            height=10,
        )
        self.binding.pack(fill="both", expand=True)
        buttons = ttk.Frame(self.query_tab)
        buttons.pack(fill="x", pady=4)
        for title, operation in (
            ("Выбор RIB", "route"),
            ("Предварительный результат", "reachability"),
            ("Админ. интерфейс", "interface"),
            ("Одна ACL", "policy"),
            ("Локальная композиция", "device"),
        ):
            ttk.Button(buttons, text=title, command=partial(self._query, operation)).pack(
                side="left", padx=2
            )

    def _build_forwarding(self) -> None:
        ttk.Label(
            self.forward_tab,
            wraplength=1000,
            text="Отдельный конфигурационный parser. Application binding не реализован: UUID "
            "не доказывают связь с текущей ревизией. Показывается только инвентарь. "
            "Effective NAT остаётся unknown; NAT/PBR не вычисляются.",
        ).pack(anchor="w")
        self.forward_path = tk.StringVar()
        self._file_field(self.forward_tab, self.forward_path)
        self.forward_metadata = JsonForm(
            self.forward_tab,
            "ForwardingSource: точная команда и согласованный ASA header обязательны. "
            "Полнота задаётся отдельными complete_scopes с основанием и observation.",
            FORWARDING_METADATA,
            height=12,
        )
        self.forward_metadata.pack(fill="both", expand=True)
        self.forward_observation = JsonForm(
            self.forward_tab,
            "ObservationEvidence ({} = неизвестно)",
            {},
            height=3,
        )
        self.forward_observation.pack(fill="x")
        self.forward_profile = JsonForm(
            self.forward_tab,
            "Необязательный профиль: context_mode, firewall_mode, address_family, "
            "table_role, table_id. Если заявлен, заполните profile_reference.",
            {},
            height=3,
        )
        self.forward_profile.pack(fill="x")
        ttk.Button(
            self.forward_tab,
            text="Разобрать отдельный forwarding-контекст",
            command=self._forwarding,
        ).pack(anchor="w", pady=4)

    def _file_field(self, parent: tk.Misc, var: tk.StringVar) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=4)
        ttk.Entry(bar, textvariable=var).pack(side="left", fill="x", expand=True)

        def choose() -> None:
            path = filedialog.askopenfilename(parent=self, title="Выбрать локальный документ")
            if path:
                var.set(path)

        ttk.Button(bar, text="Выбрать файл", command=choose).pack(side="right")

    def refresh_sessions(self) -> None:
        previous = self.base_var.get()
        self.sessions = self.get_sessions()
        values = tuple(
            f"{session.path.name} | {session.revision.revision_id}" for session in self.sessions
        )
        self.session_combo.configure(values=values)
        self.base_var.set(previous if previous in values else (values[0] if values else ""))
        self._context_changed()

    def _base(self) -> AnalysisSession:
        index = self.session_combo.current()
        if index < 0 or index >= len(self.sessions):
            raise ValueError("Сначала импортируйте реальную ASA-конфигурацию на экране импорта.")
        return self.sessions[index]

    def _context_changed(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        self.generation += 1
        self.current_result = None
        self._text("")
        self.saved_combo.configure(values=())
        self.saved_result.set("")
        self.draft_list.delete(0, "end")
        for item in self.inventory.get_children():
            self.inventory.delete(item)
        try:
            session = self._base()
        except ValueError as exc:
            self.status.set(str(exc))
            return
        for draft in self.network_state.drafts.get(session.revision.revision_id, []):
            self.draft_list.insert(
                "end", f"{draft.metadata.get('source_kind')} | {draft.path.name}"
            )
        imported = self.network_state.imported.get(session.revision.revision_id)
        self.saved_combo.configure(
            values=tuple(
                label
                for base_id, label in self.network_state.results
                if base_id == session.revision.revision_id
            )
        )
        self.status.set(
            f"База: {session.revision.revision_id}. "
            + (
                f"Сетевой снимок: {imported.revision.revision_id}."
                if imported
                else "Сеть не импортирована."
            )
        )
        if imported is not None:
            for index, document in enumerate(imported.documents):
                self.inventory.insert(
                    "",
                    "end",
                    iid=str(index),
                    text=document.source.source_name,
                    values=(
                        document.scope,
                        document.status.value,
                        len(document.interfaces) + len(document.routes),
                    ),
                )

    def _stage(self) -> None:
        try:
            session = self._base()
            if not self.network_path.get().strip():
                raise ValueError("Выберите файл сетевого документа.")
            draft = NetworkDocumentDraft(
                Path(self.network_path.get()),
                self.metadata.get(),
                self.document_observation.get() or None,
            )
            self.network_state.drafts.setdefault(session.revision.revision_id, []).append(draft)
            self._context_changed()
        except (ValueError, TypeError) as exc:
            self._input_error(exc)

    def _remove_draft(self) -> None:
        selected = self.draft_list.curselection()  # type: ignore[no-untyped-call]
        if selected:
            self.network_state.drafts[self._base().revision.revision_id].pop(selected[0])
            self._context_changed()

    def _input_error(self, _exc: Exception) -> None:
        self.status.set(
            "Входные данные не приняты. Проверьте JSON, обязательные поля и выбранный файл."
        )
        messagebox.showerror("Сетевой ввод", self.status.get(), parent=self)

    def _run(self, label: str, work: Callable[[], object]) -> None:
        base_id = self._base().revision.revision_id
        if label == "Сетевой импорт":
            self.network_state.imported.pop(base_id, None)
            self._context_changed()
        self.generation += 1
        generation = self.generation
        ticket = uuid4()
        self.network_state.jobs[(base_id, label)] = ticket
        self.current_result = None
        self._text("")
        self.status.set(f"{label}: фоновое задание. Анализ не имеет кооперативной отмены.")

        def receive(result: object) -> None:
            if self.network_state.jobs.get((base_id, label)) != ticket:
                return
            if isinstance(result, JobError):
                if self.winfo_exists() and self.generation == generation:
                    self.status.set(f"{label}: {result.message}")
                return
            if not isinstance(result, BaseModel):
                return
            self.network_state.results[(base_id, label)] = result
            if isinstance(result, NetworkImportResult):
                self.network_state.imported[base_id] = result
            if not self.winfo_exists() or self.generation != generation:
                return
            if self._base().revision.revision_id != base_id:
                return
            self._context_changed()
            self._show(result)
            self.status.set(
                f"{label}: получен {type(result).__name__}; причины и diagnostics в JSON."
            )

        self.submit(work, receive)

    def _import(self) -> None:
        try:
            base = self._base().revision
            drafts = tuple(self.network_state.drafts.get(base.revision_id, []))
            if not drafts:
                raise ValueError("Добавьте документы в очередь.")
            observation = self.baseline_observation.get() or None
            window = self.window.get() or None
            self._run(
                "Сетевой импорт",
                lambda: import_documents(
                    base,
                    drafts,
                    baseline_observation=observation,
                    observation_window=window,
                ),
            )
        except (ValueError, TypeError) as exc:
            self._input_error(exc)

    def _query(self, operation: str) -> None:
        try:
            base = self._base().revision
            imported = self.network_state.imported.get(base.revision_id)
            revision = imported.revision if imported is not None else base
            values: dict[str, Any] = {
                key: var.get().strip() for key, var in self.query_vars.items()
            }
            if operation != "interface":
                port = values["destination_port"]
                values["destination_port"] = int(port) if port else None
            binding = self.binding.get() if operation in {"policy", "device"} else None
            op = cast(Literal["route", "reachability", "interface", "policy", "device"], operation)
            self._run(
                f"Локальный API {operation}",
                lambda: run_network_query(
                    revision,
                    op,
                    values,
                    binding_values=binding,
                    imported=imported,
                ),
            )
        except (ValueError, TypeError) as exc:
            self._input_error(exc)

    def _forwarding(self) -> None:
        try:
            base = self._base().revision
            if not self.forward_path.get().strip():
                raise ValueError("Выберите конфигурационный файл.")
            draft = NetworkDocumentDraft(
                Path(self.forward_path.get()),
                self.forward_metadata.get(),
                self.forward_observation.get() or None,
            )
            profile = self.forward_profile.get()
            self._run(
                "Forwarding inventory (связь не доказана)",
                lambda: parse_forwarding(base, draft, profile),
            )
        except (ValueError, TypeError) as exc:
            self._input_error(exc)

    def _text(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", text)
        self.output.configure(state="disabled")

    def _show(self, result: BaseModel) -> None:
        self.current_result = result
        self._text(result.model_dump_json(indent=2))
        self.notebook.select(self.tab_hosts[self.result_tab])  # type: ignore[no-untyped-call]

    def _show_import(self) -> None:
        try:
            base_id = self._base().revision.revision_id
        except ValueError:
            self.status.set("Выберите реальную базовую сессию.")
            return
        imported = self.network_state.imported.get(base_id)
        if imported is not None:
            self._show(imported)

    def _show_saved(self, _event: tk.Event[tk.Misc]) -> None:
        try:
            base_id = self._base().revision.revision_id
        except ValueError:
            return
        result = self.network_state.results.get((base_id, self.saved_result.get()))
        if result is not None:
            self._show(result)

    def _show_document(self, _event: tk.Event[tk.Misc]) -> None:
        selected = self.inventory.selection()
        try:
            base_id = self._base().revision.revision_id
        except ValueError:
            return
        imported = self.network_state.imported.get(base_id)
        if selected and imported is not None:
            index = int(selected[0])
            if 0 <= index < len(imported.documents):
                self._show(imported.documents[index])

    def _export(self) -> None:
        if self.current_result is None:
            self.status.set("Нет результата выбранного контекста для экспорта.")
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".json", filetypes=[("JSON", "*.json")]
        )
        if path:
            result = self.current_result
            generation = self.generation

            def saved(value: object) -> None:
                if self.winfo_exists() and self.generation == generation:
                    self.status.set(
                        value.message
                        if isinstance(value, JobError)
                        else "Оригинальная модель JSON сохранена."
                    )

            self.submit(
                lambda: Path(path).write_text(result.model_dump_json(indent=2), encoding="utf-8"),
                saved,
            )
