# Dev / test / prod

Единственный источник кода: src/. Тесты и fixtures: tests/. Документация: specifications/.

- dev/.venv: локальное окружение Python 3.14; dev/build: промежуточная сборка.
- test/: результаты pytest, временные базы и packaged smoke; только синтетические данные.
- prod/: единственный собранный portable-дистрибутив, ZIP и контрольные суммы.

Сборка: powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1 -Production

Проверки: dev/.venv/Scripts/python.exe -m pytest --basetemp=test/pytest-temp

Продвижение в prod требует проверки тестов и запуска EXE с --self-test test/packaged-smoke.
Пользовательская БД в LOCALAPPDATA не относится к этим каталогам.
