"""Проверка событий UI без запуска ядра; требует оконной сессии Windows."""

import json
import tempfile
import tkinter as tk
from pathlib import Path
from unittest.mock import patch

from firewall_compliance.interfaces.desktop.app import DesktopApp


def main() -> None:
    root = tk.Tk()
    errors: list[str] = []

    def capture_error(*args: object) -> None:
        errors.append(str(args))

    root.report_callback_exception = capture_error
    app = DesktopApp(root)
    try:
        root.update()
        app.search.set("невозможное совпадение")
        root.update()
        assert app.finding_tree is not None
        assert not app.finding_tree.get_children()
        app.search.set("")
        app.device.set("ASA-HQ")
        app._refresh_revisions()
        app.revision.set("B")
        app.show_page("Проблемы политик")
        root.update()
        assert app.visible_findings()
        assert all(f.device == "ASA-HQ" and f.revision == "B" for f in app.visible_findings())
        app.severity.set("Высокая")
        root.update()
        assert all(f.severity == "Высокая" for f in app.visible_findings())
        app.severity.set("Любая критичность")
        app.device.set("Все устройства")
        app.revision.set("Все ревизии")
        app._refresh_revisions()
        for geometry in ("1440x900", "1000x680"):
            root.geometry(geometry)
            for page in app.nav_buttons:
                app.show_page(page)
                root.update()
                assert app.content.winfo_width() > 0
        with tempfile.TemporaryDirectory(prefix="firewall-ui-") as directory:
            path = Path(directory) / "demo.json"
            with patch("tkinter.filedialog.asksaveasfilename", return_value=str(path)):
                app._export_demo()
            payload = json.loads(path.read_text(encoding="utf-8"))
            assert payload["demo"] is True
            assert payload["analysis_executed"] is False
            assert len(payload["findings"]) == len(app.workspace.findings)
            with patch("tkinter.filedialog.asksaveasfilename", return_value=""):
                app._export_demo()
            candidate = Path(directory) / "does-not-exist.cfg"
            with patch("tkinter.filedialog.askopenfilenames", return_value=(str(candidate),)):
                app._stage_files()
                app._stage_files()
            assert app.staged_files == [candidate]
            assert not candidate.exists()
        root.update()
        assert not errors, errors
        print("Desktop smoke: navigation, filtering, context, demo export, staging: OK")
    finally:
        root.destroy()


if __name__ == "__main__":
    main()
