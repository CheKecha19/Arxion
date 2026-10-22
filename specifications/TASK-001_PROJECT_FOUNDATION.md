# TASK-001: Создание модульного фундамента проекта

## Цель

Создать новый Windows-ориентированный Python-проект Firewall Compliance без переноса legacy-функциональности.

## Контекст

- `ARCHITECTURE.md`
- `TECH_STACK.md`
- `DEPLOYMENT_TARGETS.md`
- `DEVELOPMENT_RULES.md`
- Фаза 2 из `ROADMAP.md`

## Область задачи

- Структура пакета `src/firewall_compliance` по архитектурным слоям.
- `pyproject.toml` и `uv.lock`.
- CLI entry point с командой `version`.
- Настройки pytest, Ruff и mypy.
- Git ignore rules для окружения, cache, результатов и чувствительных конфигураций.
- Windows CI workflow.
- Базовый unit-тест CLI.

## Вне области задачи

- Перенос legacy-моделей, парсеров, security checks или визуализации.
- Выбор первого production-quality vendor/parser.
- Реализация API, БД или web UI.

## Критерии приёмки

- Пакет устанавливается через `uv sync --all-groups`.
- Доступна команда `firewall-compliance version`.
- Автоматические проверки запускаются через Ruff, mypy и pytest.
- Legacy-проект не изменён.

## Запись о завершении

Статус: Готово, 2026-10-09.

Результат: создан Windows-ориентированный модульный каркас, lock-файл зависимостей и минимальный CI workflow.

Проверка:

- `uv run ruff format --check src tests` - успешно.
- `uv run ruff check src tests` - успешно.
- `uv run mypy src` - успешно.
- `uv run pytest` - 1 passed.
- `uv run firewall-compliance version` - вывела `0.1.0a0`.

Следующая задача: Фаза 3, каноническая доменная модель.
