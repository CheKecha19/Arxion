"""Рабочее место аналитика на демонстрационных данных."""

from __future__ import annotations

import gc
import json
import tkinter as tk
from collections.abc import Callable
from dataclasses import asdict
from functools import partial
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from firewall_compliance.interfaces.desktop.demo import FindingView, load_demo_workspace

BG = "#f3f5f8"
PANEL = "#ffffff"
INK = "#203047"
MUTED = "#63758b"
LINE = "#e2e7ef"
ACCENT = "#2359bb"
SIDE = "#172336"


class DesktopApp:
    """UI получает только представление данных; анализ будет подключён отдельно."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.workspace = load_demo_workspace()
        self.page = "Проблемы политик"
        self.device = tk.StringVar(value="Все устройства")
        self.revision = tk.StringVar(value="Все ревизии")
        self.search = tk.StringVar()
        self.severity = tk.StringVar(value="Любая критичность")
        self.status = tk.StringVar(value="Демонстрационные данные · Ядро анализа не подключено")
        self.staged_files: list[Path] = []
        self.nav_buttons: dict[str, tk.Button] = {}
        self.finding_tree: ttk.Treeview | None = None
        self.detail: tk.Frame | None = None
        self.root.title("Firewall Compliance — рабочее место аналитика")
        self.root.geometry("1440x900")
        self.root.minsize(1000, 680)
        self.root.configure(background=BG)
        self._styles()
        self._shell()
        self.search.trace_add("write", self._filter_changed)
        self.severity.trace_add("write", self._filter_changed)
        self.show_page(self.page)

    def _styles(self) -> None:
        self.root.option_add("*Font", "{Segoe UI} 10")
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=PANEL,
            foreground=INK,
            fieldbackground=PANEL,
            rowheight=42,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background=BG,
            foreground=MUTED,
            font=("Segoe UI", 9),
            padding=(10, 12),
            relief="flat",
        )
        style.map("Treeview", background=[("selected", "#e8effc")], foreground=[("selected", INK)])
        style.configure("TCombobox", padding=7, fieldbackground=PANEL, foreground=INK)
        style.configure("TEntry", padding=8, fieldbackground=PANEL, foreground=INK)
        style.configure("TNotebook", background=PANEL, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 9), background=BG, foreground=MUTED)
        style.map(
            "TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", ACCENT)]
        )
        style.configure("Vertical.TScrollbar", background=LINE, troughcolor=BG, borderwidth=0)

    def _label(
        self,
        parent: tk.Misc,
        text: str,
        *,
        size: int = 10,
        color: str = INK,
        bg: str = PANEL,
        bold: bool = False,
    ) -> tk.Label:
        return tk.Label(
            parent,
            text=text,
            bg=bg,
            fg=color,
            anchor="w",
            justify="left",
            font=("Segoe UI", size, "bold" if bold else "normal"),
        )

    def _button(
        self, parent: tk.Misc, text: str, command: Callable[[], None], *, primary: bool = False
    ) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            cursor="hand2",
            relief="flat",
            bg=ACCENT if primary else "#eaf0f8",
            fg="white" if primary else ACCENT,
            activebackground="#dbe6f8",
            activeforeground=INK,
            padx=14,
            pady=9,
            borderwidth=0,
            font=("Segoe UI", 10),
        )

    def _shell(self) -> None:
        sidebar = tk.Frame(self.root, bg=SIDE, width=222)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self._label(sidebar, "FIREWALL", size=18, color="white", bg=SIDE, bold=True).pack(
            anchor="w", padx=22, pady=(30, 0)
        )
        self._label(sidebar, "COMPLIANCE", size=11, color="#90a8c8", bg=SIDE).pack(
            anchor="w", padx=23, pady=(0, 28)
        )
        self._label(sidebar, "РАБОЧАЯ ОБЛАСТЬ", size=8, color="#90a8c8", bg=SIDE).pack(
            anchor="w", padx=22, pady=(0, 12)
        )
        for name in (
            "Обзор",
            "Проблемы политик",
            "Правила и объекты",
            "Сетевой доступ",
            "Сравнение ревизий",
            "Устройства и импорты",
            "Отчёты",
        ):
            button = tk.Button(
                sidebar,
                text=name,
                anchor="w",
                bg=SIDE,
                fg="#c4d1e2",
                activebackground="#263a57",
                activeforeground="white",
                relief="flat",
                cursor="hand2",
                padx=18,
                pady=12,
                command=partial(self.show_page, name),
            )
            button.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[name] = button
        self._label(
            sidebar, "Локальный режим\nDesktop UI · v0.2", size=9, color="#90a8c8", bg=SIDE
        ).pack(side="bottom", anchor="w", padx=22, pady=25)
        body = tk.Frame(self.root, bg=BG)
        body.pack(side="left", fill="both", expand=True)
        bar = tk.Frame(body, bg=PANEL, padx=24, pady=14)
        bar.pack(fill="x")
        self._label(bar, "Рабочая область /", color=MUTED).pack(side="left", padx=(0, 12))
        self.device_picker = ttk.Combobox(
            bar,
            textvariable=self.device,
            width=20,
            state="readonly",
            values=("Все устройства", *sorted({d.name for d in self.workspace.devices})),
        )
        self.device_picker.pack(side="left", padx=(0, 10))
        self.device_picker.bind("<<ComboboxSelected>>", self._device_changed)
        self.revision_picker = ttk.Combobox(
            bar, textvariable=self.revision, width=17, state="readonly"
        )
        self.revision_picker.pack(side="left")
        self.revision_picker.bind("<<ComboboxSelected>>", self._context_changed)
        self._refresh_revisions()
        self.mode_badge = self._label(bar, "ДЕМО", size=9, color=ACCENT, bold=True)
        self.mode_badge.pack(side="right")
        self.content = tk.Frame(body, bg=BG, padx=24, pady=22)
        self.content.pack(fill="both", expand=True)
        tk.Label(
            body,
            textvariable=self.status,
            anchor="w",
            bg=PANEL,
            fg=MUTED,
            padx=24,
            pady=10,
            font=("Segoe UI", 9),
        ).pack(fill="x", side="bottom")

    def _refresh_revisions(self) -> None:
        values = sorted(
            {
                d.revision
                for d in self.workspace.devices
                if self.device.get() in ("Все устройства", d.name)
            }
        )
        self.revision_picker.configure(values=("Все ревизии", *values))
        if self.revision.get() not in values:
            self.revision.set("Все ревизии")

    def _device_changed(self, _event: tk.Event[tk.Misc]) -> None:
        self._refresh_revisions()
        self.show_page(self.page)

    def _context_changed(self, _event: tk.Event[tk.Misc]) -> None:
        self.show_page(self.page)

    def _filter_changed(self, *_args: str) -> None:
        if self.page == "Проблемы политик" and self.finding_tree is not None:
            self._populate_findings()

    def _matches_context(self, device: str, revision: str) -> bool:
        return self.device.get() in ("Все устройства", device) and self.revision.get() in (
            "Все ревизии",
            revision,
        )

    def show_page(self, name: str) -> None:
        self.page = name
        self.finding_tree = None
        self.detail = None
        for child in self.content.winfo_children():
            child.destroy()
        for key, button in self.nav_buttons.items():
            button.configure(
                bg="#2c4160" if key == name else SIDE, fg="white" if key == name else "#c4d1e2"
            )
        heading = tk.Frame(self.content, bg=BG)
        heading.pack(fill="x", pady=(0, 8))
        self._label(heading, name, size=23, bg=BG, bold=True).pack(side="left")
        self._button(heading, "Добавить файлы", self._stage_files, primary=True).pack(side="right")
        caption = self._label(
            self.content,
            self._context_caption(),
            color=MUTED,
            bg=BG,
        )
        caption.pack(fill="x", pady=(0, 20))
        caption.bind("<Configure>", lambda e: caption.configure(wraplength=max(100, e.width)))
        pages = {
            "Обзор": self._overview,
            "Проблемы политик": self._findings,
            "Правила и объекты": self._rules,
            "Сетевой доступ": self._network,
            "Сравнение ревизий": self._revisions,
            "Устройства и импорты": self._devices,
            "Отчёты": self._reports,
        }
        pages[name]()

    def _context_caption(self) -> str:
        return "Демонстрационная рабочая область · Анализ не выполняется"

    def _notice(self, text: str) -> None:
        label = tk.Label(
            self.content,
            text=text,
            anchor="w",
            justify="left",
            bg="#fff2d9",
            fg="#805616",
            padx=16,
            pady=12,
            wraplength=900,
        )
        label.pack(fill="x", pady=(0, 18))
        label.bind("<Configure>", lambda e: label.configure(wraplength=max(100, e.width - 32)))

    def _panel(self, parent: tk.Misc) -> tk.Frame:
        return tk.Frame(
            parent, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=18, pady=16
        )

    def _text(self, parent: tk.Misc, text: str, *, color: str = INK) -> None:
        label = self._label(parent, text, color=color)
        label.pack(fill="x", pady=(0, 12))
        label.configure(wraplength=420)
        label.bind("<Configure>", lambda e: label.configure(wraplength=max(80, e.width - 8)))

    def _tree(
        self, parent: tk.Misc, columns: tuple[str, ...], widths: tuple[int, ...]
    ) -> ttk.Treeview:
        frame = tk.Frame(parent, bg=PANEL)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        for column, width in zip(columns, widths, strict=True):
            tree.heading(column, text=column)
            tree.column(column, width=width, minwidth=70, anchor="w")
        return tree

    def visible_findings(self) -> list[FindingView]:
        """Фильтрует только демонстрационное представление, без вызова проверок."""
        query = self.search.get().casefold().strip()
        return [
            f
            for f in self.workspace.findings
            if self._matches_context(f.device, f.revision)
            and self.severity.get() in ("Любая критичность", f.severity)
            and (
                not query
                or query
                in " ".join(
                    (f.title, f.rule, f.device, f.source, f.destination, f.service)
                ).casefold()
            )
        ]

    def _findings(self) -> None:
        self._notice(
            "Частичный анализ в демопримере: неподдержанные условия не считаются безопасными."
        )
        controls = tk.Frame(self.content, bg=BG)
        controls.pack(fill="x", pady=(0, 16))
        self._label(controls, "Поиск", bg=BG).pack(side="left", padx=(0, 10))
        ttk.Entry(controls, textvariable=self.search, width=32).pack(side="left", padx=(0, 16))
        ttk.Combobox(
            controls,
            textvariable=self.severity,
            state="readonly",
            width=21,
            values=(
                "Любая критичность",
                "Критическая",
                "Высокая",
                "Средняя",
                "Низкая",
                "Информационная",
            ),
        ).pack(side="left")
        self.count_label = self._label(controls, "", color=MUTED, bg=BG)
        self.count_label.pack(side="right")
        split = tk.PanedWindow(
            self.content, orient="horizontal", bg=BG, sashwidth=12, borderwidth=0, sashrelief="flat"
        )
        split.pack(fill="both", expand=True)
        listing = tk.Frame(split, bg=PANEL)
        self.detail = self._panel(split)
        split.add(listing, minsize=310, width=510, stretch="always")
        split.add(self.detail, minsize=290, stretch="always")
        self.finding_tree = self._tree(
            listing, ("Критичность", "Проблема", "Правило"), (105, 260, 150)
        )
        self.finding_tree.bind("<<TreeviewSelect>>", self._finding_selected)
        self._populate_findings()

    def _populate_findings(self) -> None:
        tree = self.finding_tree
        if tree is None:
            return
        selected = tree.selection()
        tree.delete(*tree.get_children())
        findings = self.visible_findings()
        for finding in findings:
            tree.insert(
                "", "end", iid=finding.id, values=(finding.severity, finding.title, finding.rule)
            )
        self.count_label.configure(text=f"Находок: {len(findings)}")
        if findings:
            selected_id = selected[0] if selected and tree.exists(selected[0]) else findings[0].id
            tree.selection_set(selected_id)
            tree.focus(selected_id)
            self._show_finding(next(f for f in findings if f.id == selected_id))
        elif self.detail is not None:
            for child in self.detail.winfo_children():
                child.destroy()
            self._text(self.detail, "По выбранным фильтрам находок нет.")
            self._text(self.detail, "Это не заключение о безопасности.", color=MUTED)

    def _finding_selected(self, _event: tk.Event[tk.Misc]) -> None:
        if self.finding_tree is not None and self.finding_tree.selection():
            selected = self.finding_tree.selection()[0]
            finding = next((f for f in self.workspace.findings if f.id == selected), None)
            if finding is not None:
                self._show_finding(finding)

    def _show_finding(self, finding: FindingView) -> None:
        if self.detail is None:
            return
        for child in self.detail.winfo_children():
            child.destroy()
        self._text(
            self.detail,
            f"{finding.severity} критичность · {finding.device} / {finding.revision}",
            color=ACCENT,
        )
        title = self._label(self.detail, finding.title, size=16, bold=True)
        title.pack(fill="x", pady=(0, 15))
        title.bind("<Configure>", lambda e: title.configure(wraplength=max(100, e.width)))
        notebook = ttk.Notebook(self.detail)
        notebook.pack(fill="both", expand=True)
        overview_tab = tk.Frame(notebook, bg=PANEL)
        canvas = tk.Canvas(overview_tab, bg=PANEL, highlightthickness=0, width=280)
        scroll = ttk.Scrollbar(overview_tab, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        overview = tk.Frame(canvas, bg=PANEL, padx=12, pady=18)
        window = canvas.create_window((0, 0), window=overview, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        overview.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        evidence = tk.Frame(notebook, bg=PANEL, padx=12, pady=18)
        notebook.add(overview_tab, text="Объяснение")
        notebook.add(evidence, text="Доказательства")
        self._text(overview, finding.explanation)
        self._text(
            overview, f"{finding.source}  →  {finding.destination}\nСервис: {finding.service}"
        )
        self._label(overview, "РЕКОМЕНДАЦИЯ", size=9, color=MUTED).pack(anchor="w", pady=(12, 10))
        self._text(overview, finding.recommendation)
        self._label(overview, "ГРАНИЦЫ ВЫВОДА", size=9, color=MUTED).pack(anchor="w", pady=(12, 10))
        self._text(overview, finding.limitation, color=MUTED)

        def scroll_overview(event: tk.Event[tk.Misc]) -> str:
            canvas.yview_scroll(-int(event.delta / 120), "units")
            return "break"

        canvas.bind("<MouseWheel>", scroll_overview)
        overview.bind("<MouseWheel>", scroll_overview)
        for child in overview.winfo_children():
            child.bind("<MouseWheel>", scroll_overview)
        self._text(evidence, f"Правило: {finding.rule}\nРевизия: {finding.revision}")
        code_frame = tk.Frame(evidence, bg=PANEL)
        code_frame.pack(fill="both", expand=True)
        code = tk.Text(
            code_frame,
            wrap="word",
            bg="#f0f4fa",
            fg=INK,
            font=("Consolas", 10),
            relief="flat",
            height=12,
            padx=12,
            pady=12,
        )
        code.insert("1.0", finding.evidence)
        code.configure(state="disabled")
        code_scroll = ttk.Scrollbar(code_frame, command=code.yview)
        code.configure(yscrollcommand=code_scroll.set)
        code_scroll.pack(side="right", fill="y")
        code.pack(side="left", fill="both", expand=True)
        self._button(
            evidence, "Копировать доказательства", lambda: self._copy(finding.evidence)
        ).pack(anchor="w", pady=(12, 0))

    def _copy(self, value: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.status.set("Демонстрационные доказательства скопированы")

    def _overview(self) -> None:
        self._notice(
            "Это визуальный прототип. Все числа и результаты ниже — синтетические примеры."
        )
        stats = tk.Frame(self.content, bg=BG)
        stats.pack(fill="x", pady=(0, 20))
        findings = [
            f for f in self.workspace.findings if self._matches_context(f.device, f.revision)
        ]
        values = (
            (
                "Устройства",
                len(
                    {
                        d.name
                        for d in self.workspace.devices
                        if self._matches_context(d.name, d.revision)
                    }
                ),
            ),
            ("Находки", len(findings)),
            ("Высокая критичность", sum(f.severity == "Высокая" for f in findings)),
        )
        for index, (title, value) in enumerate(values):
            stats.columnconfigure(index, weight=1)
            panel = self._panel(stats)
            panel.grid(row=0, column=index, sticky="nsew", padx=(0, 14 if index < 2 else 0))
            self._label(panel, title, color=MUTED).pack(anchor="w")
            self._label(panel, str(value), size=30, bold=True).pack(anchor="w", pady=(8, 0))
        panel = self._panel(self.content)
        panel.pack(fill="both", expand=True)
        self._label(panel, "С чего начать", size=16, bold=True).pack(anchor="w", pady=(0, 18))
        for title, description in (
            ("Проблемы политик", "Разобрать риски и открыть исходные строки."),
            ("Сравнение ревизий", "Посмотреть изменения конфигурации."),
            ("Сетевой доступ", "Опробовать форму запроса потока."),
        ):
            self._button(panel, title, partial(self.show_page, title)).pack(anchor="w")
            self._text(panel, description, color=MUTED)

    def _rules(self) -> None:
        self._notice(
            "Демонстрационный инвентарь ACL. NAT и разрешение объектов будут подключены к ядру."
        )
        tree = self._tree(
            self.content,
            (
                "Устройство",
                "Ревизия",
                "Порядок",
                "Правило",
                "Источник",
                "Назначение",
                "Сервис",
                "Действие",
                "Логирование",
            ),
            (110, 90, 80, 150, 140, 140, 110, 100, 110),
        )
        for rule in self.workspace.rules:
            if self._matches_context(str(rule[0]), str(rule[1])):
                tree.insert("", "end", values=rule)

    def _network(self) -> None:
        self._notice(
            "Network Assurance дорабатывается. Форма не вычисляет маршрут, policy или NAT."
        )
        panel = self._panel(self.content)
        panel.pack(fill="both", expand=True)
        self._label(panel, "Проверка сетевого потока", size=16, bold=True).pack(
            anchor="w", pady=(0, 18)
        )
        form = tk.Frame(panel, bg=PANEL)
        form.pack(fill="x", pady=(0, 20))
        fields: list[ttk.Entry] = []
        for index, (label, value) in enumerate(
            (("Источник", "10.10.1.25"), ("Назначение", "172.16.20.10"), ("Сервис", "TCP / 443"))
        ):
            form.columnconfigure(index, weight=1)
            self._label(form, label, color=MUTED).grid(row=0, column=index, sticky="w", pady=(0, 8))
            entry = ttk.Entry(form)
            entry.insert(0, value)
            entry.grid(row=1, column=index, sticky="ew", padx=(0, 16))
            fields.append(entry)
        result = tk.StringVar(value="Задайте поток, чтобы проверить компоновку экрана результата.")

        def preview() -> None:
            values = [field.get().strip() for field in fields]
            if not all(values):
                result.set("Заполните источник, назначение и сервис.")
                return
            result.set(
                f"Запрос: {values[0]} → {values[1]} · {values[2]}\n\n"
                "Анализ не выполнялся. Итоговая достижимость не определена.\n"
                "Здесь появятся пути и доказательства route / interface / policy / NAT."
            )

        self._button(panel, "Показать форму результата", preview, primary=True).pack(anchor="w")
        result_label = tk.Label(
            panel, textvariable=result, bg=PANEL, fg=INK, justify="left", anchor="nw"
        )
        result_label.pack(fill="both", expand=True, pady=25)
        result_label.bind(
            "<Configure>", lambda e: result_label.configure(wraplength=max(100, e.width - 10))
        )

    def _revisions(self) -> None:
        self._notice(
            "Структурный демопример. Изменение адресов само по себе "
            "не доказывает расширение доступа."
        )
        devices = sorted(
            {
                d.name
                for d in self.workspace.devices
                if self.device.get() in ("Все устройства", d.name)
            }
        )
        panel = self._panel(self.content)
        panel.pack(fill="both", expand=True)
        if "ASA-HQ" not in devices or self.revision.get() != "Все ревизии":
            self._text(panel, "Демосравнение доступно для ASA-HQ при выборе «Все ревизии».")
            return
        self._label(panel, "ASA-HQ · Ревизия A → Ревизия B", size=16, bold=True).pack(
            anchor="w", pady=(0, 20)
        )
        tree = self._tree(panel, ("Изменение", "Сущность", "До", "После"), (130, 180, 240, 240))
        for row in (
            ("Изменено", "WEB_SERVERS", "172.16.20.10/32", "172.16.20.0/24"),
            ("Добавлено", "OUTSIDE_IN / 24", "—", "permit tcp … eq 443"),
            ("Удалено", "OUTSIDE_IN / 31", "deny ip …", "—"),
        ):
            tree.insert("", "end", values=row)

    def _devices(self) -> None:
        self._notice(
            "Добавленные файлы остаются только в памяти UI. Чтение и парсинг ещё не подключены."
        )
        tree = self._tree(
            self.content,
            ("Устройство", "Платформа", "Ревизия", "Время наблюдения", "Полнота данных"),
            (150, 180, 110, 180, 180),
        )
        for device in self.workspace.devices:
            if self._matches_context(device.name, device.revision):
                tree.insert(
                    "",
                    "end",
                    values=(
                        device.name,
                        device.platform,
                        device.revision,
                        device.observed_at,
                        device.completeness,
                    ),
                )
        self._label(self.content, "Очередь файлов · без анализа", bg=BG, bold=True).pack(
            anchor="w", pady=(18, 8)
        )
        queue = tk.Text(self.content, height=4, bg=PANEL, fg=INK, relief="flat", wrap="word")
        queue.insert(
            "1.0", "\n".join(str(p) for p in self.staged_files) or "Файлы пока не добавлены"
        )
        queue.configure(state="disabled")
        queue.pack(fill="x")

    def _stage_files(self) -> None:
        paths = filedialog.askopenfilenames(
            parent=self.root,
            title="Добавить файлы в очередь UI",
            filetypes=(("Конфигурации", "*.cfg *.conf *.txt *.json"), ("Все файлы", "*.*")),
        )
        for path in paths:
            candidate = Path(path)
            if candidate not in self.staged_files:
                self.staged_files.append(candidate)
        if paths:
            self.status.set(f"Файлов в очереди: {len(self.staged_files)} · Анализ не выполнялся")
            self.show_page("Устройства и импорты")

    def _reports(self) -> None:
        panel = self._panel(self.content)
        panel.pack(fill="both", expand=True)
        self._label(panel, "Экспорт демонстрационной рабочей области", size=16, bold=True).pack(
            anchor="w", pady=(0, 20)
        )
        self._text(
            panel,
            "JSON содержит синтетические данные и отметку demo. "
            "Это образец интерфейса экспорта, а не результат анализа.",
        )
        self._text(
            panel,
            "Выбранные устройство и ревизия определяют состав выгрузки. "
            "Поисковый фильтр и фильтр критичности сюда не применяются.",
            color=MUTED,
        )
        self._button(panel, "Сохранить демоданные в JSON", self._export_demo, primary=True).pack(
            anchor="w", pady=12
        )
        self._text(
            panel,
            "Технические controls, CSV и HTML появятся после подключения единой модели результата.",
            color=MUTED,
        )

    def _export_demo(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Сохранить демоданные",
            initialfile="firewall-demo.json",
            defaultextension=".json",
            filetypes=(("JSON", "*.json"),),
        )
        if not path:
            return
        payload = {
            "demo": True,
            "analysis_executed": False,
            "devices": [
                asdict(d)
                for d in self.workspace.devices
                if self._matches_context(d.name, d.revision)
            ],
            "findings": [
                asdict(f)
                for f in self.workspace.findings
                if self._matches_context(f.device, f.revision)
            ],
        }
        try:
            Path(path).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError as error:
            messagebox.showerror("Не удалось сохранить файл", str(error), parent=self.root)
        else:
            self.status.set(f"Демоданные сохранены: {path}")


def main() -> None:
    """Запускает отдельное локальное окно аналитического интерфейса."""
    from firewall_compliance.interfaces.desktop.live_app import IntegratedApp

    automatic_gc = gc.isenabled()
    root = tk.Tk()
    app = IntegratedApp(root)
    try:
        root.mainloop()
    finally:
        if not app.closed:
            app.close()
        del app
        del root
        gc.collect()
        if automatic_gc:
            gc.enable()
