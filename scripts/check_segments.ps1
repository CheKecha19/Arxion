$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $python = Join-Path $projectRoot 'dev/.venv/Scripts/python.exe'
    & $python -m ruff check src tests scripts --no-cache
    if ($LASTEXITCODE -ne 0) { throw 'Ruff failed' }
    & $python -m mypy src --cache-dir dev/mypy-cache
    if ($LASTEXITCODE -ne 0) { throw 'Mypy failed' }
    & $python -m pytest --basetemp=test/pytest-temp --junitxml=test/pytest.xml
    if ($LASTEXITCODE -ne 0) { throw 'Pytest failed' }
} finally {
    Pop-Location
}
