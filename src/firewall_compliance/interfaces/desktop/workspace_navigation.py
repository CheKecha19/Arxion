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
    WorkspaceSection(
        "devices", "Инфраструктура", (("devices", "Ресурсы проекта"), ("map", "Сетевая карта"))
    ),
    WorkspaceSection(
        "findings",
        "Проверки",
        (
            ("findings", "Проблемы"),
            ("rules", "Правила и объекты"),
            ("staging", "Файлы и запуск"),
            ("scans", "Облачный сбор"),
            ("advanced", "Расширенные инструменты"),
        ),
    ),
    WorkspaceSection(
        "history",
        "Изменения",
        (("history", "Запуски и сравнение"),),
    ),
    WorkspaceSection("reports", "Отчёты", (("reports", "Отчёты"),)),
)


def section_for_page(page: str) -> WorkspaceSection | None:
    """Найти основной раздел страницы; настройки расположены отдельно."""
    return next(
        (section for section in WORKSPACE_SECTIONS if any(key == page for key, _ in section.pages)),
        None,
    )
