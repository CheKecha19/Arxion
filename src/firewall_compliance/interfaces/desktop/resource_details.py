"""Карточки ресурсов, история наблюдений и переходы к доказательствам."""

from __future__ import annotations

import json
from typing import Any
from weakref import ref

from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
)

from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.interfaces.desktop.backend import AnalysisSession, source_preview
from firewall_compliance.interfaces.desktop.cloud_rule_presentation import cloud_rule_details
from firewall_compliance.interfaces.desktop.object_presentation import object_details, rule_details
from firewall_compliance.interfaces.desktop.result_presentation import (
    check_limitations,
    finding_limitations,
    group_details,
    project_item_limitations,
)
from firewall_compliance.interfaces.desktop.workspace_models import cloud_resource_key


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def rule_evidence_text(
    item: dict[str, Any], value: dict[str, Any], session: AnalysisSession | None = None
) -> str:
    """Показывать только фрагменты, относящиеся к выбранному правилу или объекту."""
    if item.get("kind") == "cloud" and value.get("cloud_rule"):
        return (
            "Источник: сохранённый ответ облачного API.\n"
            + "\n".join(f"{key}: {text}" for key, text in cloud_rule_details(item, value))
            + "\n\nИсходные поля правила API:\n"
            + _json(value["raw"])
        )
    location = value.get("source_location")
    text = f"Файл: {item.get('source_name', '—')}\nSHA-256: {item.get('content_sha256', '—')}\n"
    if not location or not location.get("line_start"):
        return text + "Расположение в исходнике не сохранено."
    start = location["line_start"]
    end = location.get("line_end") or start
    text += f"Строки: {start}–{end}\n"
    if session is not None:
        try:
            return text + "\n" + source_preview(session, SourceLocation.model_validate(location))
        except ValueError:
            text += "\nУкажите диапазон до 200 строк в карточке источника.\n"
    matching = []
    for excerpt in item.get("excerpts", []):
        saved = excerpt["location"]
        saved_start = saved.get("line_start")
        if (
            saved.get("source_name") == location.get("source_name")
            and saved_start is not None
            and start <= (saved.get("line_end") or saved_start)
            and end >= saved_start
        ):
            matching.append(excerpt["text"])
    text += "\nСохранённые фрагменты:\n" + ("\n".join(matching) or "Нет фрагмента этого правила.")
    return text + "\n\nПолный исходник не подключён. Подключение проверяет SHA-256."


class ResourceDetails:
    """Представление desktop без изменения сохранённых результатов и контрактов."""

    def __init__(self, window: Any) -> None:
        self._view = ref(window)

    @property
    def view(self) -> Any:
        window = self._view()
        if window is None:
            raise RuntimeError("Окно уже закрыто")
        return window

    def refresh(self, item: dict[str, Any]) -> None:
        view = self.view
        cloud = item.get("kind") == "cloud"
        report = item.get("report") or {}
        findings = [
            {"finding": finding, "check": check, "item": item}
            for check in report.get("checks", [])
            for finding in check["findings"]
        ]
        view.resource_findings_model.replace(
            [
                (p["finding"]["severity"], p["check"]["check_id"], p["finding"]["title"])
                for p in findings
            ],
            findings,
        )
        view.resource_findings_hint.setText(
            "Проверки недоступны: облачный сбор сохраняет данные API."
            if cloud
            else "Находки выбранного снимка. Полнота проверок указана в Сведениях."
            if report
            else "Результат проверки не получен."
        )
        observations = []
        if cloud:
            for scan in view._cloud_scans():
                if any(
                    "cloud:" + cloud_resource_key(scan, record, index) == item["id"]
                    for index, record in enumerate(scan.get("result", {}).get("records", []))
                ):
                    observations.append({**scan, "operation_kind": "collection"})
            source = {
                "Платформа": item["platform"],
                "Операция": item["scan"]["id"],
                "Получено": item["scan"]["created_at"],
                "ID ресурса": item["record"].get("id"),
                "Подключение": item["scan"]["config"],
                "Ошибки сбора": item["scan"].get("result", {}).get("errors", []),
            }
        else:
            for run in view.store.list_runs(view.project_id) if view.project_id else []:
                saved = view.store.get_run(run["id"])
                if any(
                    candidate["report"]["device_id"] == report.get("device_id")
                    for candidate in saved["items"]
                    if candidate.get("report")
                ):
                    observations.append({**run, "operation_kind": "check"})
            source = {
                "Файл": item.get("source_name"),
                "SHA-256": item.get("content_sha256"),
                "Получено": item.get("run_created_at") or (view.run or {}).get("created_at"),
                "Диагностика": item.get("diagnostics", []),
                "Фрагменты": item.get("excerpts", []),
            }
        view.resource_history_model.replace(
            [(entry["created_at"], entry["id"], entry["state"]) for entry in observations],
            observations,
        )
        view.resource_source_detail.setPlainText(_json(source))

    def open_findings(self, *_: Any) -> None:
        view = self.view
        selected = view._selected_payloads(view.device_table, view.device_proxy, view.device_model)
        if (
            len(selected) != 1
            or not selected[0].get("report")
            or view._batch_active
            or view._restore_busy
        ):
            return
        item = selected[0]
        findings = view._selected_payloads(
            view.resource_findings_table, view.resource_findings_proxy, view.resource_findings_model
        )
        view.workspace_history.remember()
        view.load_run(item.get("run_id") or view.run_id)
        view.finding_scope.setCurrentIndex(view.finding_scope.findData("run"))
        view.finding_device.setCurrentIndex(
            view.finding_device.findData(item["report"]["device_id"])
        )
        view.finding_search.clear()
        for combo in (view.severity_filter, view.status_filter, view.finding_check):
            combo.setCurrentIndex(0)
        view.refresh_findings()
        view.navigate("findings", remember=False)
        if findings:
            identity = findings[0]["finding"]["finding_id"]
            for row, payload in enumerate(view.finding_model.payloads):
                if payload["finding"]["finding_id"] == identity:
                    view.finding_table.selectRow(
                        view.finding_proxy.mapFromSource(view.finding_model.index(row, 0)).row()
                    )
                    break

    def open_history(self, *_: Any) -> None:
        view = self.view
        selected = view._selected_payloads(
            view.resource_history_table, view.resource_history_proxy, view.resource_history_model
        )
        if not selected or view._batch_active or view._restore_busy:
            return
        view.workspace_history.remember()
        entry = selected[0]
        if entry["operation_kind"] == "collection":
            view.navigate("scans", remember=False)
            view.cloud_panel.open_result(entry["id"])
        else:
            view.load_run(entry["id"])
            view.finding_scope.setCurrentIndex(view.finding_scope.findData("run"))
            view.navigate("findings", remember=False)

    def show_rule_source(self) -> None:
        view = self.view
        selected = view._selected_payloads(view.rules_table, view.rules_proxy, view.rules_model)
        if not selected:
            return
        payload = selected[0]
        item, value = payload["item"], payload["value"]
        dialog = QDialog(view)
        dialog.setWindowTitle("Доказательство правила / объекта")
        dialog.resize(760, 540)
        layout = QVBoxLayout(dialog)
        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        session = view.sessions.get(str(item["id"]))
        viewer.setPlainText(rule_evidence_text(item, value, session))
        layout.addWidget(viewer)

        def attach() -> None:
            from pathlib import Path

            filename, _ = QFileDialog.getOpenFileName(dialog, "Подключить исходник доказательства")
            if filename:
                view.attach_source(item["id"], Path(filename))
                dialog.accept()

        button = QPushButton("Подключить исходник")
        button.clicked.connect(attach)
        button.setEnabled(
            item.get("kind") != "cloud" and not view._batch_active and not view._restore_busy
        )
        layout.addWidget(button)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        dialog.exec()

    def show_rule_json(self) -> None:
        """Сохранить доступ ко всем исходным полям нормализованной модели."""
        view = self.view
        selected = view._selected_payloads(view.rules_table, view.rules_proxy, view.rules_model)
        if not selected:
            return
        dialog = QDialog(view)
        dialog.setWindowTitle("Технические данные правила / объекта")
        dialog.resize(760, 540)
        layout = QVBoxLayout(dialog)
        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        viewer.setPlainText(_json(selected[0]["value"]))
        layout.addWidget(viewer)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        dialog.exec()

    def _selected_device(self) -> dict[str, Any] | None:
        view = self.view
        values = view._selected_payloads(view.device_table, view.device_proxy, view.device_model)
        return values[0] if len(values) == 1 else None

    def _text_dialog(self, title: str, text: str) -> None:
        dialog = QDialog(self.view)
        dialog.setWindowTitle(title)
        dialog.resize(840, 600)
        layout = QVBoxLayout(dialog)
        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        viewer.setPlainText(text)
        layout.addWidget(viewer)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        dialog.exec()

    def show_item_limitations(self, item: dict[str, Any], check_id: str | None = None) -> None:
        groups = project_item_limitations(item)
        if check_id:
            check = next(
                (
                    value
                    for value in (item.get("report") or {}).get("checks", [])
                    if value["check_id"] == check_id
                ),
                None,
            )
            groups = check_limitations(item, check) if check else ()
        self._text_dialog(
            "Ограничения и исходные сообщения",
            "\n\n".join(group_details(group) for group in groups)
            or "В сохранённом результате ограничений не указано.",
        )

    def open_device_link(self, url: QUrl) -> None:
        item = self._selected_device()
        if item is None:
            return
        target = url.toString()
        if target.startswith("findings:"):
            if self.view._batch_active or self.view._restore_busy:
                return
            self.open_findings()
            view = self.view
            index = view.finding_check.findData(target.split(":", 1)[1])
            if index >= 0:
                view.finding_check.setCurrentIndex(index)
            return
        self.show_item_limitations(
            item, target.split(":", 1)[1] if target.startswith("check:") else None
        )

    def show_finding_limitations(self) -> None:
        view = self.view
        selected = view._selected_payloads(
            view.finding_table, view.finding_proxy, view.finding_model
        )
        if not selected:
            return
        value = selected[0]
        selection = finding_limitations(value["item"], value["check"], value["finding"])
        local = "\n\n".join(group_details(group) for group in selection.local) or "Не указаны."
        common = "\n\n".join(group_details(group) for group in selection.common) or "Не указаны."
        self._text_dialog(
            "Ограничения выбранной находки",
            "Связанные с находкой:\n"
            + local
            + "\n\nОбщие для источника / проверки:\n"
            + common
            + f"\n\nОстальные локальные группы: {selection.unrelated_count}. "
            "Полный набор доступен в сведениях выбранного устройства и техническом JSON.",
        )

    def show_rule_details(self, *_: Any) -> None:
        view = self.view
        selected = view._selected_payloads(view.rules_table, view.rules_proxy, view.rules_model)
        if len(selected) == 1:
            self._show_value_details(selected[0]["item"], selected[0]["value"])

    def _show_device_value_details(self, kind: str) -> None:
        view = self.view
        item = self._selected_device()
        if item is None or (item.get("kind") == "cloud" and kind != "rules"):
            return
        selected = view._selected_payloads(
            getattr(view, f"device_{kind}_table"),
            getattr(view, f"device_{kind}_proxy"),
            getattr(view, f"device_{kind}_model"),
        )
        if len(selected) == 1:
            self._show_value_details(item, selected[0])

    def show_device_rule_details(self, *_: Any) -> None:
        self._show_device_value_details("rules")

    def show_device_object_details(self, *_: Any) -> None:
        self._show_device_value_details("objects")

    def _show_value_details(self, item: dict[str, Any], value: dict[str, Any]) -> None:
        view = self.view
        dialog = QDialog(view)
        dialog.setWindowTitle("Правило / объект · полный состав")
        dialog.resize(840, 600)
        layout = QVBoxLayout(dialog)
        tabs = QTabWidget()
        cloud = item.get("kind") == "cloud" and value.get("cloud_rule")
        fields = (
            cloud_rule_details(item, value)
            if cloud
            else rule_details(value)
            if "rule_id" in value
            else object_details(value)
        )
        context = (
            "Источник: облачный API, сохранённый снимок.\n\n"
            if cloud
            else (
                f"Файл: {item.get('source_name', '—')}\n"
                f"SHA-256: {item.get('content_sha256') or 'не определён'}\n"
                "Получено: "
                f"{item.get('run_created_at') or (view.run or {}).get('created_at', '—')}\n\n"
            )
        )
        for title, text in (
            ("Понятное описание", context + "\n\n".join(f"{key}: {text}" for key, text in fields)),
            ("Доказательство", rule_evidence_text(item, value, view.sessions.get(str(item["id"])))),
            ("Технический JSON", _json(value)),
        ):
            editor = QPlainTextEdit()
            editor.setReadOnly(True)
            editor.setPlainText(text)
            tabs.addTab(editor, title)
        layout.addWidget(tabs)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        dialog.exec()

    def show_import_errors(self) -> None:
        view = self.view
        entries = view._import_error_items
        if not entries:
            return
        dialog = QDialog(view)
        dialog.setWindowTitle("Источники без результата · записи импорта")
        dialog.resize(900, 620)
        layout = QVBoxLayout(dialog)
        table, model, proxy = view._table(("Файл", "Состояние", "Получено"), "importErrors")
        from firewall_compliance.interfaces.desktop.qt_app import IMPORT_STATES

        model.replace(
            [
                (
                    item["source_name"],
                    IMPORT_STATES.get(item["status"], item["status"]),
                    item.get("run_created_at", "—"),
                )
                for item in entries
            ],
            entries,
        )
        layout.addWidget(table)
        detail = QPlainTextEdit()
        detail.setReadOnly(True)
        layout.addWidget(detail)

        def selected_entry() -> dict[str, Any] | None:
            selected = view._selected_payloads(table, proxy, model)
            return selected[0] if selected else None

        def refresh(*_: Any) -> None:
            item = selected_entry()
            detail.setPlainText(_json(item) if item else "Выберите запись импорта.")
            open_button.setEnabled(bool(item) and not view._batch_active and not view._restore_busy)

        def open_operation() -> None:
            item = selected_entry()
            if item is None or view._batch_active or view._restore_busy:
                return
            view.workspace_history.remember()
            view.load_run(item["run_id"])
            view.navigate("reports", remember=False)
            dialog.accept()

        open_button = QPushButton("Открыть исходную операцию")
        open_button.clicked.connect(open_operation)
        layout.addWidget(open_button)
        table.selectionModel().selectionChanged.connect(refresh)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        table.selectRow(0)
        refresh()
        dialog.exec()
