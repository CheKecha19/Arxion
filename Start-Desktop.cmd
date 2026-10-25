@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 (
    echo Could not open the project directory.
    pause
    exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
    echo Project Python environment was not found: .venv\Scripts\python.exe
    echo Create the environment and install the project in editable mode first.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m firewall_compliance.interfaces.desktop
set "desktop_exit_code=%errorlevel%"
if not "%desktop_exit_code%"=="0" pause
exit /b %desktop_exit_code%
