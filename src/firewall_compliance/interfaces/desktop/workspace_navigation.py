"""Структура разделов desktop независимо от виджетов и контрактов backend."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkspaceSection:
    key: str
    title: str
    pages: tuple[tuple[str, str], ...]


WORKSPACE_SECTIONS = (
    WorkspaceSection("home", "Дашборд", (("home", "Дашборд"),)),
    WorkspaceSection(
        "devices", "Инфраструктура",
        (("devices", "Ресурсы"), ("rules", "Правила"), ("map", "Карта сети")),
    ),
    WorkspaceSection(
        "findings", "Анализ", (("matrix", "Матрица доступа"), ("findings", "Проверки")),
    ),
)

# Действующие инструменты доступны из рабочего раздела проверок.
ANALYSIS_PAGES = (
    ("findings", "Проверки"), ("staging", "Файлы и запуск"),
    ("scans", "Облачный сбор"), ("advanced", "Инструменты"),
    ("history", "История"), ("reports", "Экспорт"),
)


def section_for_page(page: str) -> WorkspaceSection | None:
    """Найти основной раздел страницы; настройки расположены отдельно."""
    if page in {key for key, _ in ANALYSIS_PAGES}:
        return WorkspaceSection("findings", "Анализ", ANALYSIS_PAGES)
    return next(
        (section for section in WORKSPACE_SECTIONS if any(key == page for key, _ in section.pages)),
        None,
    )
