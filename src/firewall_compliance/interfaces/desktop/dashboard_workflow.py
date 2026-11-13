"""Select the next useful action from the available project evidence."""

from __future__ import annotations

from dataclasses import dataclass

from firewall_compliance.interfaces.desktop.dashboard import DashboardSnapshot


@dataclass(frozen=True, slots=True)
class DashboardWorkflow:
    heading: str
    text: str
    action_label: str
    action: str
    secondary: tuple[str, str] | None = None
    show_details: bool = True


def dashboard_workflow(
    snapshot: DashboardSnapshot, *, project_selected: bool, site_id: str | None,
    staged: int, pending: int, ambiguous: int, active: bool,
) -> DashboardWorkflow:
    show_details = bool(snapshot.recent_operations or snapshot.active_resources)
    if active:
        return DashboardWorkflow(
            "Операция выполняется", "Ход сбора, проверки и ошибки доступны в центре задач.",
            "Открыть задачи", "tasks", show_details=show_details,
        )
    if not project_selected:
        return DashboardWorkflow(
            "Начните с проекта", "В проекте сохраняются источники, ресурсы, требования доступа и результаты.",
            "Создать проект", "create", show_details=False,
        )
    if staged:
        if pending:
            text = f"Файлов в области: {staged}. Определяем формат и устройство ещё для {pending}."
        elif ambiguous:
            text = f"Уточните связь с устройством для {ambiguous} из {staged} файлов."
        else:
            text = f"Файлов в области: {staged}. Проверьте состав и запустите анализ."
        return DashboardWorkflow(
            "Подготовка файлов", text, "Открыть файлы и запуск", "staging", show_details=show_details,
        )

    sources = tuple(
        source for source in snapshot.source_health
        if source["state"] != "disabled" and (
            site_id is None or (
                not source.get("site_ids") if site_id == "" else site_id in source.get("site_ids", ())
            )
        )
    )
    inventory = ("Открыть ресурсы", "devices") if snapshot.active_resources else None
    if sources and any(source["state"] == "running" for source in sources):
        return DashboardWorkflow(
            "Сбор выполняется", "Состояние сохранённых попыток доступно в центре задач.",
            "Открыть задачи", "tasks", inventory, show_details,
        )
    if sources and all(source["state"] == "never" for source in sources):
        return DashboardWorkflow(
            "Соберите данные", f"Источников в области: {len(sources)}. Запустите сбор и применимые проверки.",
            "Обновить и проверить", "update", inventory, show_details,
        )
    source_issues = sum(
        source["state"] in {
            "failed", "error", "partial", "interrupted", "cancelled", "invalid", "configuration_changed",
        }
        for source in sources
    )
    if source_issues or (not snapshot.executed_checks and (
        snapshot.error_items or snapshot.unsupported_items or snapshot.collection_errors
    )):
        return DashboardWorkflow(
            "Проверьте полноту данных",
            (
                f"Источников с ошибками или изменениями: {source_issues}. "
                "Доступные результаты остаются в истории."
                if source_issues else
                "В истории есть ошибки получения или неподдержанные входы. Откройте причины по операциям."
            ),
            "Открыть задачи", "tasks", inventory, show_details,
        )
    if sources and any(source["state"] == "never" for source in sources):
        return DashboardWorkflow(
            "Обновите состав данных",
            f"Источников в области без сохранённого сбора: {sum(source['state'] == 'never' for source in sources)}.",
            "Обновить и проверить", "update", inventory, show_details,
        )
    if snapshot.executed_checks:
        if snapshot.open_findings:
            return DashboardWorkflow(
                "Разберите результаты",
                f"Открытых находок в последних проверенных снимках: {snapshot.open_findings}.",
                "Открыть находки", "findings", ("Матрица доступа", "matrix"),
            )
        return DashboardWorkflow(
            "Проверьте требования доступа", "Откройте матрицу, чтобы описать необходимые связи и сверить политики.",
            "Открыть матрицу", "matrix", inventory,
        )
    if snapshot.active_resources:
        return DashboardWorkflow(
            "Ресурсы доступны в реестре",
            "Откройте состав сети и источники. Для проверки правил добавьте подходящие конфигурации.",
            "Открыть ресурсы", "devices", ("Добавить данные", "add"),
        )
    if sources:
        return DashboardWorkflow(
            "Обновите источники", "Запустите сбор, чтобы получить ресурсы и применимые политики.",
            "Обновить и проверить", "update", show_details=show_details,
        )
    return DashboardWorkflow(
        "Добавьте данные", "Загрузите конфигурации или настройте интеграции для первого сбора.",
        "Добавить данные", "add", show_details=show_details,
    )
