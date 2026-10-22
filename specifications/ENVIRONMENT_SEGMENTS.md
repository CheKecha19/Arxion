# Сегменты dev / test / prod

Дата: 21.10.2026. Решение пользователя: заменить старые сборки одной из текущих исходников и разделить контуры работы.

| Сегмент | Расположение | Назначение |
|---|---|---|
| DEV | src/, scripts/, specifications/, dev/.venv, dev/build | Единственный набор исходников, окружение и промежуточная сборка |
| TEST | tests/, test/ | Тестовый код и fixtures; отдельно отчёты, временные БД и smoke-результаты |
| PROD | prod/FirewallCompliance, prod/FirewallCompliance-windows-x64.zip | Portable EXE с полной папкой _internal и README |

src/ и tests/ остаются в корне: это общие исходники с существующими путями и контрактами.
Три копии исходного дерева не создаются. Python 3.14.8 и uv 0.13.4 установлены локально.
uv доступен в dev/tools/uv.exe. PATH и системный реестр не изменены.

## Команды из корня проекта

Окружение: задать UV_PROJECT_ENVIRONMENT=dev/.venv и выполнить uv sync --python 3.14 --all-groups --locked.
Установленный Python сейчас находится в рабочем каталоге инструментов Codex; при переносе ПК окружение пересоздаётся.

Проверки: powershell -ExecutionPolicy Bypass -File scripts/check_segments.ps1.
Сборка: powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1 -Production.
Проверка EXE: prod/FirewallCompliance/FirewallCompliance.exe --self-test test/packaged-smoke.

## Данные и продвижение

Тесты используют синтетические источники и отдельную БД в test/. Пользовательская БД в LOCALAPPDATA не переносится и не включается в ZIP.
PROD содержит собранный артефакт; статус проверки определяется результатами тестов и packaged smoke.
Расположение в prod/ само по себе не подтверждает приёмку. Версия приложения остаётся 0.1.0a0.

## Очистка

Старые dist/ и build/ подлежат удалению по запросу пользователя, но удаление отклонено автоматической политикой среды (sandbox approval отключён).
До фактического удаления они считаются историческими артефактами и не являются текущей поставкой.
Кэши Python, Ruff, mypy и старое переносимое .venv — кандидаты на очистку.
artifacts/ и .hypothesis/ требуют отбора: могут содержать доказательства проверок и сохранённые регрессионные примеры.
