"""История навигации в памяти, не изменяющая результаты анализа."""

from __future__ import annotations

from typing import Any
from weakref import ref

from PySide6.QtCore import QItemSelectionModel, Qt


class WorkspaceHistory:
    """Восстановить фильтры и выбранные объекты по идентификаторам при возврате."""

    combos = (
        "device_scope",
        "resource_kind",
        "resource_platform",
        "resource_type",
        "finding_scope",
        "finding_device",
        "finding_check",
        "severity_filter",
        "status_filter",
        "rule_scope",
    )
    searches = ("resource_search", "finding_search", "rule_search")
    tables = ("device", "finding", "rules", "history", "resource_findings", "resource_history")

    def __init__(self, window: Any) -> None:
        self._window = ref(window)
        self.locations: list[dict[str, Any]] = []
        self.ready = False

    @property
    def window(self) -> Any:
        window = self._window()
        if window is None:
            raise RuntimeError("Окно уже закрыто")
        return window

    @staticmethod
    def payload_key(payload: dict[str, Any]) -> str:
        if "finding" in payload:
            return str(payload["finding"]["finding_id"])
        if "value" in payload:
            value = payload["value"]
            return str((payload["item"]["id"], value.get("rule_id") or value.get("name"), value))
        return str(payload.get("id", ""))

    def remember(self) -> None:
        if not self.ready:
            return
        view = self.window
        selection = {}
        for name in self.tables:
            table, proxy, model = (
                getattr(view, name + suffix) for suffix in ("_table", "_proxy", "_model")
            )
            selection[name] = {
                "keys": [
                    self.payload_key(item) for item in view._selected_payloads(table, proxy, model)
                ],
                "column": table.horizontalHeader().sortIndicatorSection(),
                "order": table.horizontalHeader().sortIndicatorOrder().value,
                "scroll": table.verticalScrollBar().value(),
            }
        scan = view.cloud_panel.history.currentData()
        self.locations.append(
            {
                "page": view.current_section_id,
                "project": view.project_id,
                "run": view.run_id,
                "combos": {name: getattr(view, name).currentData() for name in self.combos},
                "searches": {name: getattr(view, name).text() for name in self.searches},
                "selection": selection,
                "device_tab": view.device_tabs.currentIndex(),
                "finding_tab": view.finding_detail_tabs.currentIndex(),
                "scan": scan["id"] if scan else None,
                "collection_tab": view.cloud_panel.collection_tabs.currentIndex(),
                "settings": view.settings_pages.currentIndex(),
                "integration": view.integration_pages.currentIndex(),
            }
        )
        self.locations = self.locations[-50:]
        view.back_button.setEnabled(True)

    def clear(self) -> None:
        self.locations.clear()
        self.window.back_button.setEnabled(False)

    def back(self) -> None:
        view = self.window
        if not self.locations:
            return
        location = self.locations[-1]
        if view._batch_active or view._restore_busy:
            view.progress_label.setText(
                "Возврат к другому контексту доступен после текущей операции."
            )
            return
        self.locations.pop()
        if location["project"] != view.project_id:
            self.clear()
            return
        if location["run"] and location["run"] != view.run_id:
            view.load_run(location["run"])
        elif not location["run"]:
            view.run_id, view.run = None, None
            view._refresh_all()
        view.navigate(location["page"], remember=False)
        for name, value in location["combos"].items():
            combo = getattr(view, name)
            combo.setCurrentIndex(max(0, combo.findData(value)))
        for name, value in location["searches"].items():
            getattr(view, name).setText(value)
        if location["scan"]:
            view.cloud_panel._refresh_history(location["scan"])
        view.cloud_panel.collection_tabs.setCurrentIndex(location["collection_tab"])
        for name, saved in location["selection"].items():
            table, proxy, model = (
                getattr(view, name + suffix) for suffix in ("_table", "_proxy", "_model")
            )
            table.sortByColumn(saved["column"], Qt.SortOrder(saved["order"]))
            table.clearSelection()
            for row, payload in enumerate(model.payloads):
                if self.payload_key(payload) in saved["keys"]:
                    table.selectionModel().select(
                        proxy.mapFromSource(model.index(row, 0)),
                        QItemSelectionModel.SelectionFlag.Select
                        | QItemSelectionModel.SelectionFlag.Rows,
                    )
            table.verticalScrollBar().setValue(saved["scroll"])
        view.device_tabs.setCurrentIndex(location["device_tab"])
        view.finding_detail_tabs.setCurrentIndex(location["finding_tab"])
        settings_index = location["settings"]
        view._select_settings_tab(
            "integrations" if settings_index == 0 else "rules", settings_index
        )
        view.integration_pages.setCurrentIndex(location["integration"])
        view.back_button.setEnabled(bool(self.locations))
