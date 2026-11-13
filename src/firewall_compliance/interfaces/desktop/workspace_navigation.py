"""Структура разделов desktop независимо от виджетов и контрактов backend."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkspaceSection:
    key: str
    title: str
    pages: tuple[tuple[str, str], ...]


WORKSPACE_SECTIONS = (
    WorkspaceSection("home", "Обзор", (("home", "Обзор"),)),
    WorkspaceSection("findings", "Анализ", (("findings", "Проверки"), ("history", "История и изменения"))),
    WorkspaceSection(
        "devices", "Инфраструктура",
        (("devices", "Ресурсы и VLAN"), ("map", "Карта сети")),
    ),
    WorkspaceSection(
        "rules", "Доступ",
        (("rules", "Правила"), ("matrix", "Матрица доступа"), ("advanced", "Сетевые инструменты")),
    ),
    WorkspaceSection("reports", "Отчёты", (("reports", "Отчёты"),)),
    WorkspaceSection(
        "staging", "Источники данных", (("staging", "Файлы и запуск"), ("scans", "Облачный сбор")),
    ),
)

def section_for_page(page: str) -> WorkspaceSection | None:
    """Найти основной раздел страницы; настройки расположены отдельно."""
    return next(
        (section for section in WORKSPACE_SECTIONS if any(key == page for key, _ in section.pages)),
        None,
    )
