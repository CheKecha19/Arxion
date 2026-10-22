"""Desktop-интеграция аналитических API с раздельными live/demo сессиями."""

from __future__ import annotations

import json
import tkinter as tk
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from time import monotonic
from tkinter import filedialog, messagebox, ttk
from uuid import UUID, uuid4

from pydantic import BaseModel, ValidationError

from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.revision import DeviceRevision, DeviceRevisionDiff
from firewall_compliance.interfaces.desktop.app import BG, INK, MUTED, PANEL, DesktopApp
from firewall_compliance.interfaces.desktop.backend import (
    AnalysisSession,
    analyze_file,
    compare_revisions,
    diagnostic_lines,
    reanalyze_session,
    source_preview,
    view_workspace,
)
from firewall_compliance.interfaces.desktop.demo import FindingView, load_demo_workspace
from firewall_compliance.interfaces.desktop.gui_lifetime import GuiGarbageCollector
from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner
from firewall_compliance.interfaces.desktop.network_panel import NetworkPanel, NetworkState
from firewall_compliance.parsers import ParseFailure


@dataclass
class ImportTask:
    """Состояние задания в памяти, отдельно от неизменяемой ревизии."""

    id: UUID
    path: Path
    device_id: str | None
    status: str = "Готов к запуску"
    runner_id: UUID | None = None
    diagnostic: str = ""
    result: AnalysisSession | ParseFailure | None = None


class IntegratedApp(DesktopApp):
    """Оркестрирует UI-состояние; ядро выполняется через отдельный worker."""

    def __init__(self, root: tk.Tk) -> None:
        self.gui_gc = GuiGarbageCollector()
        self.next_gc = monotonic() + 2
        self.mode = tk.StringVar(root, value="Анализ файлов")
        self.sessions: list[AnalysisSession] = []
        self.tasks: list[ImportTask] = []
        self.runner = JobRunner()
        self.network_state = NetworkState()
        self.import_device = tk.StringVar(root)
        self.require_logging = tk.BooleanVar(root, value=True)
        self.require_comments = tk.BooleanVar(root, value=True)
        self.lifecycle: dict[str, str] = {}
        self.loaded_reports: list[FirewallAssuranceResult] = []
        self.diff_result: DeviceRevisionDiff | None = None
        self.closed = False
        self.poll_id: str | None = None
        self.view_generation = 0
        super().__init__(root)
        self.status.set("Выберите конфигурацию · ASA, HP/Aruba, Comware · ограниченные адаптеры")
        self.show_page("Устройства и импорты")
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.poll_id = root.after(100, self._poll)

    def _shell(self) -> None:
        super()._shell()
        picker = ttk.Combobox(
            self.device_picker.master,
            textvariable=self.mode,
            values=("Анализ файлов", "Демонстрация"),
            state="readonly",
            width=14,
        )
        picker.pack(side="left", before=self.device_picker, padx=(0, 10))
        picker.bind("<<ComboboxSelected>>", self._mode_changed)
        self.device_picker.configure(width=16)
        self.revision_picker.configure(width=12)

    def _mode_changed(self, _event: tk.Event[tk.Misc]) -> None:
        self.device.set("Все устройства")
        self.revision.set("Все ревизии")
        self.search.set("")
        self._sync_workspace()
        self.show_page("Обзор" if self.mode.get() == "Демонстрация" else "Устройства и импорты")

    def _sync_workspace(self) -> None:
        self.workspace = (
            load_demo_workspace()
            if self.mode.get() == "Демонстрация"
            else view_workspace(tuple(self.sessions))
        )
        names = sorted({d.name for d in self.workspace.devices})
        self.device_picker.configure(values=("Все устройства", *names))
        if self.device.get() not in names:
            self.device.set("Все устройства")
        self._refresh_revisions()
        self.mode_badge.configure(text="ДЕМО" if self.mode.get() == "Демонстрация" else "АНАЛИЗ")

    def _context_caption(self) -> str:
        if self.mode.get() == "Демонстрация":
            return super()._context_caption()
        return (
            "Результаты ядра · История в памяти текущей сессии · "
            "Ноль находок не доказывает безопасность"
        )

    def show_page(self, name: str) -> None:
        self.view_generation += 1
        self._sync_workspace()
        super().show_page(name)

    def _poll(self) -> None:
        if self.closed:
            return
        if monotonic() >= self.next_gc:
            self.gui_gc.collect()
            self.next_gc = monotonic() + 2
        events = self.runner.poll()
        for task in self.tasks:
            if task.runner_id is not None and task.status == "В очереди":
                status = self.runner.status(task.runner_id)
                if status is not None and status.value == "running":
                    task.status = "Выполняется"
        if events and self.mode.get() != "Демонстрация":
            self._sync_workspace()
            if self.page == "Устройства и импорты":
                self._refresh_task_tree()
        if self.runner.running_count or self.runner.pending_count:
            self.status.set(
                f"Выполняется: {self.runner.running_count} · "
                f"В очереди: {self.runner.pending_count} · Окно остаётся доступным"
            )
        self.poll_id = self.root.after(100, self._poll)

    def submit_background(
        self, work: Callable[[], object], callback: Callable[[object], None]
    ) -> None:
        """Общий worker для панелей; callback вызывается только в GUI-потоке."""
        self.runner.submit(work, callback)
        self.status.set("Задание поставлено в очередь")

    def close(self) -> None:
        self.closed = True
        self.runner.shutdown()
        if self.poll_id is not None:
            self.root.after_cancel(self.poll_id)
        self.root.destroy()
        self.gui_gc.collect()

    def _current_sessions(self) -> tuple[AnalysisSession, ...]:
        if self.mode.get() == "Демонстрация":
            return ()
        return tuple(
            s
            for s in self.sessions
            if self._matches_context(s.revision.device.device_id, str(s.revision.revision_id))
        )

    def _notice(self, text: str) -> None:
        if self.mode.get() != "Демонстрация":
            if text.startswith("Частичный анализ в демопримере"):
                partial_checks = sum(
                    c.status.value == "partial"
                    for s in self._current_sessions()
                    for c in s.report.checks
                )
                text = (
                    f"Проверок partial: {partial_checks}. "
                    "Статусы и ограничения доступны в диагностике. "
                    "complete означает выполнение проверки в её границе."
                )
            elif text.startswith("Это визуальный прототип"):
                text = (
                    "Результаты загруженных файлов. "
                    "История сохраняется в памяти до закрытия приложения."
                )
        super()._notice(text)

    def _findings(self) -> None:
        super()._findings()
        if self.mode.get() != "Демонстрация":
            listing = self.content.winfo_children()[-1]
            actions = tk.Frame(self.content, bg=BG)
            actions.pack(fill="x", before=listing, pady=(0, 10))
            self._button(actions, "Диагностика и полнота", self._show_diagnostics).pack(side="left")

    def _show_finding(self, finding: FindingView) -> None:
        super()._show_finding(finding)
        if self.mode.get() == "Демонстрация" or self.detail is None:
            return
        actions = tk.Frame(self.detail, bg=PANEL)
        actions.pack(fill="x", side="bottom", pady=(8, 0))
        self._button(actions, "Исходный фрагмент", partial(self._source_fragment, finding.id)).pack(
            anchor="w"
        )
        lifecycle = tk.StringVar(value=self.lifecycle.get(finding.id, "new"))
        picker = ttk.Combobox(
            actions,
            textvariable=lifecycle,
            state="readonly",
            width=14,
            values=(
                "new",
                "confirmed",
                "in_progress",
                "accepted_risk",
                "false_positive",
                "resolved",
            ),
        )
        picker.pack(anchor="w", pady=(6, 0))

        def changed(_event: tk.Event[tk.Misc]) -> None:
            self.lifecycle[finding.id] = lifecycle.get()
            self.status.set(
                "Статус изменён только в UI-сессии; исходный отчёт и экспорт не изменены"
            )

        picker.bind("<<ComboboxSelected>>", changed)

    def _source_fragment(self, finding_id: str) -> None:
        for session in self.sessions:
            for check in session.report.checks:
                for finding in check.findings:
                    if str(finding.finding_id) != finding_id:
                        continue
                    snippets: list[str] = []
                    for location in finding.evidence.source_locations:
                        try:
                            snippets.append(source_preview(session, location))
                        except ValueError:
                            snippets.append(
                                "Фрагмент недоступен: источник, SHA-256 или позиции не совпадают."
                            )
                    self._text_dialog(
                        "Исходный фрагмент · проверенный снимок",
                        "\n\n".join(snippets) or "Нет строкового source mapping.",
                    )
                    return

    def _text_dialog(self, title: str, text: str) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("920x620")
        dialog.minsize(500, 300)
        frame = tk.Frame(dialog, bg=PANEL)
        frame.pack(fill="both", expand=True)
        widget = tk.Text(
            frame,
            wrap="word",
            bg=PANEL,
            fg=INK,
            font=("Consolas", 10),
            padx=16,
            pady=16,
            relief="flat",
        )
        scroll = ttk.Scrollbar(frame, command=widget.yview)
        widget.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        widget.pack(fill="both", expand=True)
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _scrolling_panel(self) -> tk.Frame:
        holder = self._panel(self.content)
        holder.pack(fill="both", expand=True)
        canvas = tk.Canvas(holder, bg=PANEL, highlightthickness=0)
        scroll = ttk.Scrollbar(holder, command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        panel = tk.Frame(canvas, bg=PANEL)
        window = canvas.create_window((0, 0), window=panel, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        panel.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))

        def wheel(event: tk.Event[tk.Misc]) -> str:
            canvas.yview_scroll(-int(event.delta / 120), "units")
            return "break"

        canvas.bind("<MouseWheel>", wheel)
        panel.bind("<MouseWheel>", wheel)
        return panel

    def _show_diagnostics(self) -> None:
        lines: list[str] = []
        for session in self._current_sessions():
            lines.extend(
                (
                    f"\n{session.path.name} · {session.revision.revision_id}",
                    *diagnostic_lines(session),
                )
            )
        self._text_dialog(
            "Диагностика и полнота", "\n".join(lines) or "Нет результатов в выбранном контексте."
        )

    def _copy(self, value: str) -> None:
        super()._copy(value)
        if self.mode.get() != "Демонстрация":
            self.status.set("Доказательства скопированы")

    def _rules(self) -> None:
        if self.mode.get() == "Демонстрация":
            super()._rules()
            return
        self._notice(
            "Инвентарь ParseResult. Полный vendor/NAT-инвентарь не обещается; "
            "source_map и статусы каждого поля доступны в деталях."
        )
        notebook = ttk.Notebook(self.content)
        notebook.pack(fill="both", expand=True)
        rules_page = tk.Frame(notebook, bg=PANEL)
        objects_page = tk.Frame(notebook, bg=PANEL)
        notebook.add(rules_page, text="Правила")
        notebook.add(objects_page, text="Объекты и сервисы")
        rules = self._tree(
            rules_page,
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
            (130, 130, 75, 150, 150, 150, 130, 90, 90),
        )
        for index, rule in enumerate(self.workspace.rules):
            if self._matches_context(str(rule[0]), str(rule[1])):
                rules.insert("", "end", iid=str(index), values=rule)
        originals = tuple(rule for session in self.sessions for rule in session.parse_result.rules)

        def rule_detail(_event: tk.Event[tk.Misc]) -> None:
            if not rules.selection():
                return
            original = originals[int(rules.selection()[0])]
            self._text_dialog("Нормализованное правило", original.model_dump_json(indent=2))

        rules.bind("<Double-1>", rule_detail)
        rules.bind("<Return>", rule_detail)
        objects = self._tree(
            objects_page, ("Устройство", "Ревизия", "Тип", "Объект"), (160, 150, 100, 450)
        )
        for session in self._current_sessions():
            for item in (*session.parse_result.endpoints, *session.parse_result.services):
                objects.insert(
                    "",
                    "end",
                    values=(
                        session.report.device_id,
                        str(session.report.revision_id),
                        type(item).__name__,
                        item.model_dump_json(),
                    ),
                )

    def _network(self) -> None:
        if self.mode.get() == "Демонстрация":
            super()._network()
            return
        if self._current_sessions() and not self._asa_sessions():
            self._notice(
                "Этот сетевой экран работает только с ASA. Для HP/Aruba и Comware "
                "доступны нормализованные правила, объекты, диагностика и policy checks. "
                "Сетевой импорт и итоговая достижимость этих платформ ещё не подключены."
            )
            return
        panel = NetworkPanel(
            self.content,
            get_sessions=self._asa_sessions,
            submit=self.submit_background,
            state=self.network_state,
        )
        panel.pack(fill="both", expand=True)

    def _asa_sessions(self) -> tuple[AnalysisSession, ...]:
        return tuple(
            s
            for s in self._current_sessions()
            if s.parse_result.configuration.platform == "asa-9.16"
        )

    def _revisions(self) -> None:
        if self.mode.get() == "Демонстрация":
            super()._revisions()
            return
        self.diff_result = None
        self._notice(
            "Экспериментальный структурный diff (SR-005): значения и provenance могут смешиваться. "
            "Результат не доказывает расширение доступа или удаление правила на устройстве."
        )
        sessions = self._current_sessions()
        labels: dict[str, DeviceRevision] = {
            f"{s.report.device_id} · {s.path.name} · {s.revision.revision_id}": s.revision
            for s in sessions
        }
        for session in sessions:
            imported = self.network_state.imported.get(session.revision.revision_id)
            if imported is not None:
                revision = imported.revision
                labels[f"{revision.device.device_id} · Сетевой снимок · {revision.revision_id}"] = (
                    revision
                )
        if len(labels) < 2:
            self._text(
                self.content,
                "Нужны два импорта одного устройства. "
                "Укажите одинаковый идентификатор устройства при импорте и выберите «Все ревизии».",
            )
            return
        controls = tk.Frame(self.content, bg=BG)
        controls.pack(fill="x")
        before = tk.StringVar(value=next(iter(labels)))
        after = tk.StringVar(value=list(labels)[-1])
        for caption, variable in (("До", before), ("После", after)):
            self._label(controls, caption, bg=BG).pack(anchor="w")
            ttk.Combobox(
                controls, textvariable=variable, values=tuple(labels), state="readonly"
            ).pack(fill="x", pady=(0, 8))
        result_frame = tk.Frame(self.content, bg=PANEL)
        result_frame.pack(fill="both", expand=True, pady=14)
        result = tk.Text(result_frame, bg=PANEL, fg=INK, wrap="word", font=("Consolas", 10))
        scroll = ttk.Scrollbar(result_frame, command=result.yview)
        result.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        result.pack(side="left", fill="both", expand=True)
        result.configure(state="disabled")
        generation = self.view_generation

        def clear_diff(*_args: str) -> None:
            self.diff_result = None
            result.configure(state="normal")
            result.delete("1.0", "end")
            result.configure(state="disabled")

        before.trace_add("write", clear_diff)
        after.trace_add("write", clear_diff)

        def compare() -> None:
            self.diff_result = None
            left, right = labels[before.get()], labels[after.get()]
            selected_pair = (before.get(), after.get())
            if left.device.device_id != right.device.device_id:
                messagebox.showerror(
                    "Несовместимые ревизии", "Выберите ревизии одного устройства.", parent=self.root
                )
                return
            if left.revision_id == right.revision_id:
                messagebox.showerror(
                    "Одинаковая ревизия", "Выберите два разных импорта.", parent=self.root
                )
                return

            def deliver(value: object) -> None:
                if (
                    self.view_generation != generation
                    or not result.winfo_exists()
                    or (before.get(), after.get()) != selected_pair
                ):
                    return
                result.configure(state="normal")
                result.delete("1.0", "end")
                if isinstance(value, JobError):
                    result.insert("1.0", value.message)
                elif isinstance(value, DeviceRevisionDiff):
                    self.diff_result = value
                    result.insert("1.0", value.model_dump_json(indent=2))
                result.configure(state="disabled")

            self.submit_background(lambda: compare_revisions(left, right), deliver)

        buttons = tk.Frame(controls, bg=BG)
        buttons.pack(fill="x")
        self._button(buttons, "Сравнить", compare, primary=True).pack(side="left")
        self._button(buttons, "Сохранить diff JSON", self._export_diff).pack(side="left", padx=10)

    def _export_diff(self) -> None:
        if self.diff_result is None:
            messagebox.showinfo("Нет результата", "Сначала выполните сравнение.", parent=self.root)
            return
        self._export_model(self.diff_result, "revision-diff.json")

    def _devices(self) -> None:
        if self.mode.get() == "Демонстрация":
            super()._devices()
            return
        self._notice(
            "Автоопределение: ASA, HP/Aruba AOS-Switch/AOS-CX и Comware ACL. "
            "Адаптеры экспериментальные; неизвестные условия отмечаются в диагностике. "
            "Сетевые экспорты импортируются отдельно на экране «Сетевой доступ»."
        )
        controls = tk.Frame(self.content, bg=BG)
        controls.pack(fill="x", pady=(0, 12))
        self._label(controls, "ID устройства (необязательно)", bg=BG).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Entry(controls, textvariable=self.import_device, width=26).grid(
            row=1, column=0, sticky="w", padx=(0, 20)
        )
        ttk.Checkbutton(controls, text="Требовать логирование", variable=self.require_logging).grid(
            row=0, column=1, sticky="w"
        )
        ttk.Checkbutton(controls, text="Требовать описание", variable=self.require_comments).grid(
            row=1, column=1, sticky="w"
        )
        actions = tk.Frame(self.content, bg=BG)
        actions.pack(fill="x", pady=(0, 14))
        self._button(actions, "Запустить очередь", self._start_imports, primary=True).grid(
            row=0, column=0, sticky="w", pady=4
        )
        self._button(actions, "Отменить ожидающие", self._cancel_pending).grid(
            row=0, column=1, sticky="w", padx=10, pady=4
        )
        self._button(actions, "Открыть результат", self._open_task).grid(
            row=1, column=0, sticky="w", pady=4
        )
        self._button(actions, "Диагностика задания", self._task_diagnostics).grid(
            row=1, column=1, sticky="w", padx=10, pady=4
        )
        self._button(actions, "Сохранить JSON задания", self._export_task).grid(
            row=2, column=0, sticky="w", pady=4
        )
        self.task_tree = self._tree(
            self.content, ("Файл", "Устройство", "Состояние", "Ревизия"), (270, 150, 200, 220)
        )
        self.task_tree.bind("<Double-1>", lambda _event: self._open_task())
        self._refresh_task_tree()

    def _refresh_task_tree(self) -> None:
        if self.page != "Устройства и импорты" or self.mode.get() == "Демонстрация":
            return
        if not hasattr(self, "task_tree") or not self.task_tree.winfo_exists():
            return
        selected = self.task_tree.selection()
        self.task_tree.delete(*self.task_tree.get_children())
        for task in self.tasks:
            session = task.result if isinstance(task.result, AnalysisSession) else None
            self.task_tree.insert(
                "",
                "end",
                iid=str(task.id),
                values=(
                    task.path.name,
                    session.report.device_id if session else task.device_id or "Авто",
                    task.status,
                    str(session.revision.revision_id) if session else "—",
                ),
            )
        if selected and self.task_tree.exists(selected[0]):
            self.task_tree.selection_set(selected[0])

    def _selected_task(self) -> ImportTask | None:
        if (
            hasattr(self, "task_tree")
            and self.task_tree.winfo_exists()
            and self.task_tree.selection()
        ):
            selected = self.task_tree.selection()[0]
            return next((t for t in self.tasks if str(t.id) == selected), None)
        return None

    def _open_task(self) -> None:
        task = self._selected_task()
        if task is None:
            return
        if not isinstance(task.result, AnalysisSession):
            self._text_dialog(
                task.path.name, task.diagnostic or "Для этого файла результата анализа пока нет."
            )
            return
        self.device.set(task.result.report.device_id)
        self.revision.set(str(task.result.revision.revision_id))
        self.show_page("Проблемы политик")

    def _task_diagnostics(self) -> None:
        task = self._selected_task()
        if task is not None:
            text = (
                "\n".join(diagnostic_lines(task.result))
                if isinstance(task.result, AnalysisSession)
                else task.diagnostic or "Задание не завершено."
            )
            self._text_dialog(f"Диагностика · {task.path.name}", text)

    def _export_task(self) -> None:
        task = self._selected_task()
        if task is None:
            return
        if isinstance(task.result, AnalysisSession):
            self._export_model(task.result.report, "firewall-assurance.json")
        elif isinstance(task.result, ParseFailure):
            self._export_model(task.result, "parse-failure.json")
        else:
            self.status.set("Для этого задания пока нет модели результата.")

    def _stage_files(self) -> None:
        if self.mode.get() == "Демонстрация":
            super()._stage_files()
            return
        paths = filedialog.askopenfilenames(
            parent=self.root,
            title="Конфигурации для Firewall Assurance",
            filetypes=(("Конфигурации", "*.cfg *.conf *.txt"), ("Все файлы", "*.*")),
        )
        for path in paths:
            self.tasks.append(
                ImportTask(uuid4(), Path(path), self.import_device.get().strip() or None)
            )
        if paths:
            self.status.set(
                f"Добавлено файлов: {len(paths)}. Для чтения и анализа нажмите «Запустить очередь»."
            )
            self.show_page("Устройства и импорты")

    def _start_imports(self) -> None:
        for task in self.tasks:
            if task.status != "Готов к запуску":
                continue
            task.device_id = task.device_id or self.import_device.get().strip() or None
            task.status = "В очереди"
            work = partial(
                analyze_file,
                task.path,
                job_id=task.id,
                device_id=task.device_id,
                require_logging=self.require_logging.get(),
                require_comments=self.require_comments.get(),
            )
            task.runner_id = self.runner.submit(work, partial(self._import_finished, task))
        self._refresh_task_tree()

    def _import_finished(self, task: ImportTask, value: object) -> None:
        if isinstance(value, AnalysisSession):
            task.result = value
            task.status = "Результат готов"
            task.diagnostic = "\n".join(diagnostic_lines(value))
            self.sessions.append(value)
            self._sync_workspace()
        elif isinstance(value, ParseFailure):
            task.result = value
            task.status = (
                "Формат не поддержан"
                if any(i.code == "PARSER_NOT_FOUND" for i in value.errors)
                else "Ошибка парсинга"
            )
            task.diagnostic = value.model_dump_json(indent=2)
        elif isinstance(value, JobError):
            task.result = None
            task.status = "Ошибка задания"
            task.diagnostic = value.message
        self.status.set(
            f"{task.path.name}: {task.status}. Результат открывается отдельно из очереди."
        )
        if self.mode.get() != "Демонстрация":
            self._refresh_task_tree()

    def _cancel_pending(self) -> None:
        canceled = set(self.runner.cancel_pending())
        for task in self.tasks:
            if task.runner_id in canceled:
                task.status = "Отменено до запуска"
        self.status.set("Ожидающие задания отменены. Текущий анализ продолжает выполняться.")
        self._refresh_task_tree()

    def _reports(self) -> None:
        if self.mode.get() == "Демонстрация":
            super()._reports()
            return
        panel = self._scrolling_panel()
        self._label(panel, "Отчёты текущей сессии", size=16, bold=True).pack(
            anchor="w", pady=(0, 15)
        )
        self._text(
            panel,
            "Сохраняется оригинальный FirewallAssuranceResult: версии, checks, полнота, "
            "findings и evidence. Поисковые фильтры и UI-статусы не меняют отчёт.",
        )
        sessions = self._current_sessions()
        choices = {
            f"{s.path.name} · {s.report.device_id} · {s.report.revision_id}": s for s in sessions
        }
        selected = tk.StringVar(value=next(iter(choices), ""))
        ttk.Combobox(panel, textvariable=selected, values=tuple(choices), state="readonly").pack(
            fill="x", pady=12
        )

        def export() -> None:
            session = choices.get(selected.get())
            if session is not None:
                self._export_model(session.report, "firewall-assurance.json")

        self._button(panel, "Сохранить отчёт JSON", export, primary=True).pack(anchor="w", pady=10)
        controls = tk.Frame(panel, bg=PANEL)
        controls.pack(fill="x")
        ttk.Checkbutton(controls, text="Требовать логирование", variable=self.require_logging).pack(
            side="left"
        )
        ttk.Checkbutton(controls, text="Требовать описание", variable=self.require_comments).pack(
            side="left", padx=12
        )

        def repeat() -> None:
            session = choices.get(selected.get())
            if session is None:
                return
            logging, comments = self.require_logging.get(), self.require_comments.get()
            self.status.set("Проверки той же ревизии выполняются повторно, без чтения файла")

            def completed(value: object) -> None:
                if isinstance(value, JobError):
                    self.status.set(value.message)
                elif isinstance(value, AnalysisSession):
                    for index, previous in enumerate(self.sessions):
                        if previous.revision.revision_id == value.revision.revision_id:
                            self.sessions[index] = value
                    for task in self.tasks:
                        if (
                            isinstance(task.result, AnalysisSession)
                            and task.result.revision.revision_id == value.revision.revision_id
                        ):
                            task.result = value
                            task.diagnostic = "\n".join(diagnostic_lines(value))
                    self._sync_workspace()
                    self.status.set("Проверки обновлены. Идентификатор ревизии сохранён.")
                    if self.page == "Отчёты" and self.mode.get() != "Демонстрация":
                        self.show_page("Отчёты")

            self.submit_background(
                partial(
                    reanalyze_session, session, require_logging=logging, require_comments=comments
                ),
                completed,
            )

        self._button(panel, "Повторить проверки ревизии", repeat).pack(anchor="w", pady=10)
        self._button(panel, "Открыть сохранённый отчёт", self._load_report).pack(
            anchor="w", pady=10
        )
        self._text(
            panel,
            "Открытый JSON проверяется моделью и версией. Он не содержит полного инвентаря "
            "правил и не восстанавливает ревизию. CSV/HTML и постоянная история пока отсутствуют.",
            color=MUTED,
        )

    def _export_model(self, model: BaseModel, filename: str) -> None:
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            initialfile=filename,
            defaultextension=".json",
            filetypes=(("JSON", "*.json"),),
        )
        if not destination:
            return
        payload = model.model_dump_json(indent=2)

        def save() -> object:
            Path(destination).write_text(payload, encoding="utf-8")
            return destination

        def completed(value: object) -> None:
            if isinstance(value, JobError):
                messagebox.showerror("Не удалось сохранить", value.message, parent=self.root)
            else:
                self.status.set("JSON сохранён без изменения контрактов ядра")

        self.submit_background(save, completed)

    def _load_report(self) -> None:
        filename = filedialog.askopenfilename(parent=self.root, filetypes=(("JSON", "*.json"),))
        if not filename:
            return

        def read() -> object:
            payload = json.loads(Path(filename).read_text(encoding="utf-8"))
            if (
                not isinstance(payload, dict)
                or payload.get("demo") is True
                or payload.get("schema_version") != "1.0.0"
            ):
                return JobError(
                    "report", "Это demo, неизвестная версия или неподдержанный тип отчёта."
                )
            try:
                return FirewallAssuranceResult.model_validate(payload)
            except ValidationError:
                return JobError(
                    "report", "JSON не соответствует контракту FirewallAssuranceResult 1.0.0."
                )

        def completed(value: object) -> None:
            if isinstance(value, JobError):
                messagebox.showerror("Отчёт не открыт", value.message, parent=self.root)
            elif isinstance(value, FirewallAssuranceResult):
                self.loaded_reports.append(value)
                self._text_dialog(
                    "Сохранённый отчёт · без полной ревизии", value.model_dump_json(indent=2)
                )

        self.submit_background(read, completed)
