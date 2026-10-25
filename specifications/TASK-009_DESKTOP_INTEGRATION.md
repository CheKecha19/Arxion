# TASK-009: Подключение desktop UI к готовому аналитическому ядру

## Цель

Локальный Tkinter UI вызывает готовые policy и сетевые APIs и показывает реальные результаты без подмены полноты или демонстрационных данных.

## Контекст

ARCHITECTURE.md, UI_BACKEND_INTEGRATION.md, DESKTOP_UI.md, CURRENT_STATE.md, DOMAIN_MODEL.md, REQUIREMENT_STATUS.md. Ограничение структурного diff SR-005 сохраняется.

## Область задачи

- Согласованная policy AnalysisSession, инвентарь правил/объектов, findings/diagnostics.
- Worker queue, безопасные ошибки, job/context identity, отмена ожидающих заданий.
- JSON экспорт/чтение оригинального отчёта, повторные checks той же ревизии.
- Сетевые metadata, import/inventory/query, отдельный forwarding context, структурный diff.

## Вне области задачи

- Новые adapters Aruba/Juniper, REST, Docker, постоянное хранилище.
- Итоговая достижимость, NAT/PBR evaluator и application binding forwarding.
- Изменение публичных схем аналитического ядра.

## Критерии приёмки

- Demo и реальные результаты явно разделены; ParseFailure не оставляет старые findings под новым источником.
- Rules, revision и report имеют согласованные IDs, evidence и версии.
- unknown/partial/unsupported и пустые результаты показываются с ограничениями.
- Worker не вызывает Tkinter; поздние результаты привязаны к исходному заданию.
- Экспорт проходит roundtrip, чтение отчёта не создаёт ложный полный снимок.
- Source preview использует captured bytes с SHA-256 и bounds.
- Network metadata задаются явно; результаты не объявляются итоговой проверкой доступа.

## Проверка

- Integration: tests/integration/test_desktop_backend.py — 7 passed.
- Scoped Ruff/mypy backend — passed.
- Полный pytest: 1164 passed, включая 7 backend, 12 worker и 15 network desktop тестов.
- Полный Ruff check, format check и mypy: passed (57 source files).
- scripts/desktop_integration_smoke.py: настоящее окно, policy_quality 7 checks/14 findings,
  фильтры, evidence/scroll, queue responsiveness, demo/live context, безопасные ошибки,
  JSON roundtrip, diff и все страницы/пять сетевых вкладок при 1440×900 и 1000×680.
- Дополнительный оконный QA: реальные route/interface/reachability API, физический synthetic
  network import и forwarding parse; повторные checks сохраняют IDs и не читают файл снова.
- Шесть регрессий запрещают подменить source/metadata/IDs/imported_at через forwarding profile.

## Безопасность и обработка данных

Рабочая сессия хранит исходный документ в памяти. Raw content не добавляется автоматически в отчёт. Source preview доступен явным действием; evidence не используется как произвольный файловый путь. Ошибки не раскрывают raw content/traceback. Fixtures и QA синтетические, реальные экспорты не коммитятся.

## Зависимости и риски

- Tkinter и существующее Python окружение проекта.
- Ядро не предоставляет cooperative cancel/progress callbacks.
- JSON advanced metadata требует знания provenance и полноты входных документов.
- SR-005 ограничивает интерпретацию структурного diff.

## Запись о завершении

Реализован desktop orchestration без изменения контрактов ядра. Документация DESKTOP_UI.md описывает реальные операции и ограничения. Статусы FR не расширяются до промышленной поддержки или итоговой достижимости. Полный тестовый прогон и оконная проверка успешны. Использовались только synthetic данные.

Освобождение циклических Tk-объектов выполняется в GUI-потоке. Два отдельных стресс-прогона с GC thresholds `(5, 1, 1)` завершились без ошибок Tk callbacks и unraisable exceptions, включая финальную сборку после закрытия окна.

Последующие задачи: постоянное хранилище, более удобные формы metadata и дальнейшие backend-сценарии после application binding/evaluator.
