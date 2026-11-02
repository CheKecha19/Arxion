# TASK-002: Каноническая доменная модель

## Цель

Реализовать независимую от производителей модель конфигурации, правил, сетевых объектов, findings и результатов парсинга.

## Контекст

- `DOMAIN_MODEL.md`
- `FUNCTIONAL_REQUIREMENTS.md`, FR-003, FR-004, FR-010, FR-012 и FR-020
- `ARCHITECTURE.md`
- `DEVELOPMENT_RULES.md`

## Область задачи

- Pydantic-модели и enum-значения в `domain/`.
- Валидация адресных и портовых диапазонов.
- Source mapping для правил и evidence.
- Явные статусы неполных данных.
- Unit-тесты, сериализация и проверка инвариантов.

## Вне области задачи

- Парсинг конкретного формата.
- Хранилище, экспорт отчётов и security checks.
- Расчёт reachability, NAT или топологии.

## Критерии приёмки

- Реализованы Configuration, Device, Rule, Endpoint, Service, Finding, Evidence и ParseResult.
- Невалидные диапазоны, source locations и временные отметки отклоняются.
- Модели сериализуются в JSON и восстанавливаются без потери данных.
- Все новые инварианты защищены unit-тестами.

## Запись о завершении

Статус: Готово, 2026-10-09.

Реализованы Configuration, Device, Rule, Endpoint, Service, Finding, Evidence, ParseResult и связанные enum-модели. Добавлены SourceLocation, ParseCoverage, ParseIssue, UnsupportedConstruct, IP/port ranges и явные статусы неполных данных.

Проверка:

- `uv run ruff format --check src tests` - успешно.
- `uv run ruff check src tests` - успешно.
- `uv run mypy src` - успешно.
- `uv run pytest` - 20 passed.

Следующая задача: Фаза 4, parser-contract, fixtures, golden и integration tests.
