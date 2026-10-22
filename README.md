# Структура тестов

- `unit/` - изолированные тесты доменной логики и checks.
- `contract/` - проверки единых контрактов парсеров и адаптеров.
- `integration/` - сквозные сценарии pipeline.
- `golden/` - сравнение нормализованных результатов с эталонами.
- `fixtures/` - только обезличенные входные данные.

Реальные конфигурации и результаты заказчиков в тесты не добавляются.

## Desktop UI: Qt и исторический Tk

`integration/test_desktop_backend.py`, `test_desktop_jobs.py` и
`test_desktop_network.py` проверяют сессии, очередь, снимки и подключение сетевых API
без открытия окна. Оконный `scripts/desktop_integration_smoke.py` запускается отдельно
из корня проекта:

```powershell
.\.venv\Scripts\python.exe scripts/desktop_integration_smoke.py
```

Для оконной проверки требуется интерактивная Windows-сессия с Tkinter. Скрипт
использует synthetic fixtures, проверяет реальные действия, геометрию экранов,
фоновую очередь и освобождение Tk-объектов при частой сборке мусора. Этот сценарий
не является аппаратной валидацией ASA или испытанием готового установщика.

`contract/test_hp_aruba.py`, `contract/test_comware.py` и
`integration/test_multivendor_desktop.py` проверяют новые ограниченные adapters и общий
catalog CLI/UI. Оконный smoke также импортирует authored HP/Aruba и Comware fixtures.
Внешние masked конфигурации в fixtures не включаются; их локальный batch inventory
не заменяет synthetic regressions и не является коммерческим quality gate.

Основной Qt smoke:

```powershell
.\.venv\Scripts\python.exe scripts/qt_desktop_smoke.py
.\.venv\Scripts\python.exe scripts/qt_desktop_smoke.py --visible --screenshot
```

По умолчанию используется offscreen; `--visible` проверяет native Windows.
Скрипт создаёт временную SQLite и 80 synthetic входов, проверяет очередь/heartbeat,
семь страниц, клавиатуру/поиск, marks, экспорт, перезапуск, hash guard и закрытие
worker. Скриншоты `--screenshot` сохраняются только с synthetic данными в
`artifacts/qt-window-smoke`. `QT_SCALE_FACTOR=1.5` позволяет отдельный масштабный прогон.
Qt teardown освобождает окна до QApplication. Предыдущий Tk smoke — исторический
сценарий; он не проверяет основной Qt entrypoint.

`integration/test_qt_models.py` проверяет proxy mapping и 12 контрастных пар;
`integration/test_qt_network.py` — guard/context существующих ASA API;
`integration/test_qt_storage_reports.py` — постоянные проекты и отчёты.

