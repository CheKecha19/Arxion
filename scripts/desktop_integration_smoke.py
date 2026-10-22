"""Оконная проверка реального desktop-конвейера на synthetic данных."""

from __future__ import annotations

import gc
import json
import sys
import tempfile
import tkinter as tk
from collections.abc import Callable, Iterator
from pathlib import Path
from threading import Event
from time import monotonic, sleep
from tkinter import ttk
from unittest.mock import patch

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.reachability import ReachabilityResult, RouteSelectionResult
from firewall_compliance.interfaces.desktop.backend import AnalysisSession
from firewall_compliance.interfaces.desktop.live_app import IntegratedApp
from firewall_compliance.interfaces.desktop.network_panel import NetworkPanel
from firewall_compliance.parsers import ParseFailure
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseResult

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/assurance/policy_quality.cfg"


def descendants(widget: tk.Misc) -> Iterator[tk.Misc]:
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


def pump(root: tk.Tk, predicate: Callable[[], bool], *, timeout: float = 12) -> None:
    deadline = monotonic() + timeout
    while not predicate():
        root.update()
        if monotonic() >= deadline:
            raise AssertionError("Истекло ожидание фонового результата")
        sleep(0.005)
    root.update()


def click(app: IntegratedApp, text: str) -> None:
    button = next(
        widget
        for widget in descendants(app.content)
        if isinstance(widget, tk.Button) and widget.cget("text") == text
    )
    assert isinstance(button, tk.Button)
    button.invoke()


def dismiss_dialogs(root: tk.Tk) -> None:
    for child in root.winfo_children():
        if isinstance(child, tk.Toplevel):
            child.destroy()


def stage(app: IntegratedApp, *paths: Path) -> None:
    with patch("tkinter.filedialog.askopenfilenames", return_value=tuple(map(str, paths))):
        app._stage_files()


def check_multivendor(app: IntegratedApp, root: tk.Tk, directory: Path) -> None:
    """Новые адаптеры выполняются через кнопки того же окна."""
    comware = directory / "synthetic-comware.cfg"
    comware.write_text(
        "version 7.1.045\nsysname SYNTHETIC-COMWARE\nacl number 2000\n"
        " rule 0 permit source 192.0.2.10 0\n#\n"
        "snmp-agent community read SYNTHETIC acl 2000\n",
        encoding="utf-8",
    )
    fixtures = FIXTURE.parents[1] / "hp_aruba"
    app.show_page("Устройства и импорты")
    app.import_device.set("")
    start = len(app.tasks)
    stage(app, fixtures / "aos_switch.cfg", fixtures / "aos_cx.cfg", comware)
    click(app, "Запустить очередь")
    pump(root, lambda: all(task.status == "Результат готов" for task in app.tasks[start:]))
    platforms: set[str] = set()
    for task in app.tasks[start:]:
        assert isinstance(task.result, AnalysisSession)
        platforms.add(task.result.parse_result.configuration.platform)
        app.show_page("Устройства и импорты")
        app.task_tree.selection_set(str(task.id))
        click(app, "Открыть результат")
        app.show_page("Правила и объекты")
        root.update()
        trees = [w for w in descendants(app.content) if isinstance(w, ttk.Treeview)]
        assert trees and len(trees[0].get_children()) == len(task.result.parse_result.rules)
        app.show_page("Сетевой доступ")
        root.update()
        assert not any(isinstance(w, NetworkPanel) for w in descendants(app.content))
        destination = directory / f"{task.id}.json"
        with patch("tkinter.filedialog.asksaveasfilename", return_value=str(destination)):
            app._export_model(task.result.report, "synthetic.json")
        pump(
            root,
            lambda target=destination: (
                target.exists() and app.runner.pending_count == 0 and app.runner.running_count == 0
            ),
        )
        assert (
            FirewallAssuranceResult.model_validate_json(destination.read_text(encoding="utf-8"))
            == task.result.report
        )
    assert platforms == {"aos-switch", "aos-cx", "comware"}


def check_network_tabs(app: IntegratedApp, root: tk.Tk) -> None:
    panel = next(w for w in descendants(app.content) if isinstance(w, NetworkPanel))
    assert isinstance(panel, NetworkPanel)
    assert len(panel.notebook.tabs()) == 5
    for tab_id in panel.notebook.tabs():
        panel.notebook.select(tab_id)
        root.update()
        host = root.nametowidget(tab_id)
        canvas = next(w for w in descendants(host) if isinstance(w, tk.Canvas))
        assert isinstance(canvas, tk.Canvas)
        canvas.yview_moveto(1)
        root.update()
        right_edge = canvas.winfo_rootx() + canvas.winfo_width()
        for widget in descendants(host):
            if isinstance(widget, ttk.Button):
                assert widget.winfo_ismapped(), f"Скрыта кнопка {widget.cget('text')}"
                assert widget.winfo_width() >= widget.winfo_reqwidth(), (
                    f"Кнопка обрезана: {widget.cget('text')}"
                )
                assert widget.winfo_rootx() + widget.winfo_width() <= right_edge + 1, (
                    f"Кнопка за краем окна: {widget.cget('text')}"
                )
        canvas.yview_moveto(0)
    panel.notebook.select(panel.notebook.tabs()[0])
    root.update()


def check_network_apis(app: IntegratedApp, root: tk.Tk, directory: Path) -> None:
    sys.path.insert(0, str(FIXTURE.parents[3]))
    try:
        from tests.asa_forwarding_fixtures import ROOT as FORWARDING_ROOT
        from tests.asa_forwarding_fixtures import forwarding_request
        from tests.network_import_fixtures import INTERFACES, make_document
    finally:
        sys.path.pop(0)

    app.show_page("Сетевой доступ")
    root.update()
    panel = next(w for w in descendants(app.content) if isinstance(w, NetworkPanel))
    assert isinstance(panel, NetworkPanel)
    base = panel._base().revision
    values = {
        "ingress_interface_id": "interface:GigabitEthernet0/0",
        "source_ip": "192.0.2.10",
        "destination_ip": "203.0.113.10",
        "protocol": "tcp",
        "destination_port": "443",
        "table_id": "default",
    }
    for key, value in values.items():
        panel.query_vars[key].set(value)
    for operation in ("route", "interface", "reachability"):
        key = (base.revision_id, f"Локальный API {operation}")
        panel._query(operation)
        pump(root, lambda result_key=key: result_key in app.network_state.results)
        result = app.network_state.results[key]
        assert result.schema_version == "0.1.0"  # type: ignore[attr-defined]
        if operation == "route":
            assert isinstance(result, RouteSelectionResult)
            assert result.status in ("unknown", "not_enough_evidence")
            assert result.reasons
        elif operation == "reachability":
            assert isinstance(result, ReachabilityResult)
            assert result.status in ("unknown", "not_enough_evidence")
            assert result.reasons
        else:
            assert type(result).__name__ == "InterfaceDecisionResult"
        assert panel.current_result is result

    request = forwarding_request("ingress_no_match_global_permit")
    metadata = request.metadata.model_dump(mode="json")
    for field in (
        "source_document_id",
        "source_name",
        "content_sha256",
        "device_id",
        "device_context",
        "captured_at",
        "observation",
    ):
        metadata.pop(field, None)
    panel.forward_path.set(str(FORWARDING_ROOT / request.source.source_name))
    panel.forward_metadata.set(metadata)
    panel.forward_observation.set({})
    panel.forward_profile.set({})
    panel._forwarding()
    forwarding_key = (base.revision_id, "Forwarding inventory (связь не доказана)")
    pump(root, lambda: forwarding_key in app.network_state.results)
    forwarding = app.network_state.results[forwarding_key]
    assert isinstance(forwarding, ForwardingParseResult)
    assert forwarding.context.revision_id == base.revision_id
    assert forwarding.context.device_id == base.device.device_id
    assert panel.current_result is forwarding

    network_path = directory / "synthetic-interfaces.txt"
    network_path.write_text(INTERFACES, encoding="ascii")
    network_request = make_document(
        base,
        INTERFACES,
        "asa_running_config_interfaces",
        complete=False,
        selection="partial",
        extent="excerpt",
        completeness_reference=None,
    )
    network_metadata = network_request.metadata.model_dump(mode="json")
    for field in ("source_document_id", "device_id", "content_sha256"):
        network_metadata.pop(field, None)
    panel.network_path.set(str(network_path))
    panel.metadata.set(network_metadata)
    panel.document_observation.set({})
    panel.baseline_observation.set({})
    panel.window.set({})
    panel._stage()
    assert len(app.network_state.drafts[base.revision_id]) == 1
    panel._import()
    pump(root, lambda: base.revision_id in app.network_state.imported)
    imported = app.network_state.imported[base.revision_id]
    assert isinstance(imported, NetworkImportResult)
    assert imported.revision.revision_id != base.revision_id
    assert imported.revision.observed_at is None
    assert imported.documents
    assert imported.revision.interfaces
    assert panel.current_result is imported


def exercise() -> None:
    root = tk.Tk()
    callback_errors: list[str] = []
    dialog_errors: list[str] = []
    release = Event()
    app: IntegratedApp | None = None

    def callback_error(kind: type[BaseException], _error: BaseException, _trace: object) -> None:
        callback_errors.append(kind.__name__)

    root.report_callback_exception = callback_error

    def show_error(_title: str, message: str, **_options: object) -> None:
        dialog_errors.append(message)

    try:
        with (
            patch("tkinter.messagebox.showerror", side_effect=show_error),
            patch("tkinter.messagebox.showinfo"),
            tempfile.TemporaryDirectory(prefix="firewall-live-ui-") as directory,
        ):
            app = IntegratedApp(root)
            root.update()
            assert app.mode.get() == "Анализ файлов"
            assert app.sessions == []
            assert app.workspace.findings == ()
            assert app.workspace.devices == ()
            app.show_page("Сетевой доступ")
            root.update()
            empty_panel = next(w for w in descendants(app.content) if isinstance(w, NetworkPanel))
            assert isinstance(empty_panel, NetworkPanel)
            error_count = len(dialog_errors)
            for action in (
                lambda: empty_panel._query("route"),
                empty_panel._forwarding,
                empty_panel._import,
            ):
                action()
                root.update()
            assert len(dialog_errors) == error_count + 3
            assert app.runner.running_count == app.runner.pending_count == 0
            app.show_page("Устройства и импорты")
            app.import_device.set("SYNTHETIC-UI")

            heartbeats: list[float] = []

            def heartbeat() -> None:
                heartbeats.append(monotonic())
                if app is not None and not app.closed:
                    root.after(10, heartbeat)

            root.after(10, heartbeat)
            started = Event()

            def gate() -> object:
                started.set()
                assert release.wait(10)
                return None

            app.runner.submit(gate, lambda _value: None)
            pump(root, started.is_set)
            stage(app, FIXTURE)
            app._start_imports()
            assert app.tasks[0].status == "В очереди"
            heartbeat_before = len(heartbeats)
            pump(root, lambda: len(heartbeats) >= heartbeat_before + 3)
            assert len(app.sessions) == 0

            app.mode.set("Демонстрация")
            app._mode_changed(None)  # type: ignore[arg-type]
            app.device.set("ASA-HQ")
            app._refresh_revisions()
            app.revision.set("B")
            app.show_page("Проблемы политик")
            context = (app.mode.get(), app.device.get(), app.revision.get())
            release.set()
            pump(root, lambda: len(app.sessions) == 1)
            assert (app.mode.get(), app.device.get(), app.revision.get()) == context
            assert all(f.device == "ASA-HQ" for f in app.visible_findings())

            app.mode.set("Анализ файлов")
            app._mode_changed(None)  # type: ignore[arg-type]
            task = app.tasks[0]
            assert task.status == "Результат готов"
            assert isinstance(task.result, AnalysisSession)
            session = task.result
            assert len(session.report.checks) == 7
            assert sum(len(check.findings) for check in session.report.checks) == 14
            assert session.report.schema_version == "1.0.0"
            app.task_tree.selection_set(str(task.id))
            app._open_task()
            root.update()
            assert app.device.get() == "SYNTHETIC-UI"
            assert app.revision.get() == str(session.revision.revision_id)
            assert len(app.visible_findings()) == 14
            assert app.finding_tree is not None
            assert len(app.finding_tree.get_children()) == 14

            app.search.set("невозможное совпадение")
            root.update()
            assert app.visible_findings() == []
            assert not app.finding_tree.get_children()
            app.search.set("")
            app.severity.set("Высокая")
            root.update()
            assert all(f.severity == "Высокая" for f in app.visible_findings())
            app.severity.set("Любая критичность")
            root.update()
            for finding_id in app.finding_tree.get_children()[:3]:
                app.finding_tree.selection_set(finding_id)
                root.update()
            assert app.detail is not None
            notebooks = [w for w in descendants(app.detail) if isinstance(w, ttk.Notebook)]
            assert notebooks
            evidence = notebooks[0].tabs()[1]
            notebooks[0].select(evidence)
            root.update()
            evidence_widgets = [
                w for w in descendants(root.nametowidget(evidence)) if isinstance(w, tk.Text)
            ]
            assert evidence_widgets and evidence_widgets[0].get("1.0", "end").strip()
            assert evidence_widgets[0].cget("yscrollcommand"), "Evidence требует прокрутки"
            app._source_fragment(app.visible_findings()[0].id)
            root.update()
            assert any(isinstance(w, tk.Toplevel) for w in root.winfo_children())
            dismiss_dialogs(root)
            app._show_diagnostics()
            root.update()
            dismiss_dialogs(root)

            export_path = Path(directory) / "assurance.json"
            with patch("tkinter.filedialog.asksaveasfilename", return_value=str(export_path)):
                app._export_model(session.report, "assurance.json")
            pump(
                root,
                lambda: (
                    export_path.exists()
                    and not app.runner.running_count
                    and not app.runner.pending_count
                ),
            )
            pump(root, lambda: "JSON сохранён" in app.status.get())
            exported = FirewallAssuranceResult.model_validate_json(export_path.read_text("utf-8"))
            assert exported.model_dump(mode="json") == session.report.model_dump(mode="json")
            with patch("tkinter.filedialog.askopenfilename", return_value=str(export_path)):
                app._load_report()
            pump(root, lambda: len(app.loaded_reports) == 1)
            dismiss_dialogs(root)

            demo_path = Path(directory) / "demo.json"
            demo_path.write_text(json.dumps({"demo": True, "analysis_executed": False}), "utf-8")
            errors_before = len(dialog_errors)
            with patch("tkinter.filedialog.askopenfilename", return_value=str(demo_path)):
                app._load_report()
            pump(root, lambda: len(dialog_errors) == errors_before + 1)
            assert "demo" in dialog_errors[-1]
            assert len(app.loaded_reports) == 1

            unsupported = Path(directory) / "unsupported.cfg"
            unsupported.write_text("set system host-name SYNTHETIC-JUNIPER\n", "utf-8")
            missing = Path(directory) / "missing-secret-password.cfg"
            stage(app, unsupported, missing)
            app._start_imports()
            pump(
                root,
                lambda: all(
                    t.status not in ("Готов к запуску", "В очереди", "Выполняется")
                    for t in app.tasks
                ),
            )
            assert len(app.sessions) == 1
            assert isinstance(app.tasks[1].result, ParseFailure)
            assert app.tasks[1].status == "Формат не поддержан"
            assert app.tasks[2].status == "Ошибка задания"
            assert app.tasks[2].result is None
            assert "secret-password" not in app.tasks[2].diagnostic
            app.task_tree.selection_set(str(app.tasks[1].id))
            app._open_task()
            root.update()
            assert (app.device.get(), app.revision.get()) == (
                "SYNTHETIC-UI",
                str(session.revision.revision_id),
            )
            assert len(app.visible_findings()) == 14
            dismiss_dialogs(root)

            stage(app, FIXTURE)
            app._start_imports()
            pump(root, lambda: len(app.sessions) == 2)
            assert app.sessions[0].report.device_id == app.sessions[1].report.device_id
            assert app.sessions[0].revision.revision_id != app.sessions[1].revision.revision_id
            app.device.set("SYNTHETIC-UI")
            app.revision.set("Все ревизии")
            app.show_page("Сравнение ревизий")
            root.update()
            click(app, "Сравнить")
            pump(root, lambda: app.diff_result is not None)
            assert app.diff_result is not None

            for geometry in ("1440x900", "1000x680"):
                root.geometry(geometry)
                for page in app.nav_buttons:
                    app.show_page(page)
                    root.update()
                    assert app.content.winfo_width() > 0
                    assert app.content.winfo_height() > 0
                    if page == "Сетевой доступ":
                        check_network_tabs(app, root)
                    assert not callback_errors, callback_errors
            assert len(heartbeats) >= heartbeat_before + 3
            check_network_apis(app, root, Path(directory))
            app.device.set("SYNTHETIC-UI")
            app.revision.set(str(session.revision.revision_id))
            app.show_page("Отчёты")
            app.require_logging.set(False)
            app.require_comments.set(False)
            selected_context = (app.mode.get(), app.device.get(), app.revision.get())
            with patch(
                "firewall_compliance.infrastructure.source_reader.FileSourceReader.read",
                side_effect=AssertionError("Повторные проверки не должны читать файл"),
            ):
                click(app, "Повторить проверки ревизии")
                pump(root, lambda: "Проверки обновлены" in app.status.get())
            repeated = next(
                s for s in app.sessions if s.revision.revision_id == session.revision.revision_id
            )
            assert repeated.revision.revision_id == session.revision.revision_id
            assert repeated.report.configuration_id == session.report.configuration_id
            assert repeated.report.device_id == session.report.device_id
            assert repeated.report.require_logging is False
            assert repeated.report.require_comments is False
            assert repeated.parse_result == session.parse_result
            assert (app.mode.get(), app.device.get(), app.revision.get()) == selected_context
            check_multivendor(app, root, Path(directory))
            assert not callback_errors, callback_errors
            print(
                "Desktop integration smoke: real analysis, 7 checks/14 findings, filters/evidence, "
                "responsive queue, mode context, safe failures, JSON roundtrip, diff, "
                "all pages at 1440/1000, network APIs/import/forwarding, repeat without reread, "
                "HP/Aruba/Comware real imports and JSON: OK"
            )
    finally:
        release.set()
        if app is not None and not app.closed:
            app.close()
        else:
            root.destroy()


def main() -> None:
    original_hook = sys.unraisablehook
    original_threshold = gc.get_threshold()
    original_enabled = gc.isenabled()
    unraisable_errors: list[str] = []

    def unraisable(event: object) -> None:
        error_type = getattr(event, "exc_type", None)
        unraisable_errors.append(getattr(error_type, "__name__", "unknown"))

    sys.unraisablehook = unraisable
    gc.set_threshold(5, 1, 1)
    try:
        exercise()
    finally:
        gc.collect()
        gc.set_threshold(*original_threshold)
        if original_enabled:
            gc.enable()
        sys.unraisablehook = original_hook
    assert not unraisable_errors, unraisable_errors


if __name__ == "__main__":
    main()
