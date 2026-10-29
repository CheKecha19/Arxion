param(
    [switch]$Console
)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).ProviderPath

function Assert-WorkspacePath([string]$Candidate) {
    $full = [IO.Path]::GetFullPath($Candidate)
    $prefix = $projectRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Build target is outside the workspace: $full"
    }
    $current = $projectRoot
    $relative = $full.Substring($prefix.Length)
    foreach ($part in @('') + $relative.Split([IO.Path]::DirectorySeparatorChar)) {
        if ($part) { $current = Join-Path $current $part }
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Build targets must not traverse reparse points: $current"
            }
        }
    }
    return $full
}

$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Сначала выполните uv sync --all-groups.'
}
Push-Location $projectRoot
$previousBuildPath = $env:PATH
try {
    # Сторонние ICU DLL из PATH не должны подменять системный ICU, используемый Qt.
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$projectRoot\.venv\Scripts"
    $versionOutput = & $pythonPath -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])'
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось прочитать версию проекта.' }
    $version = ([string]$versionOutput).Trim()
    if ($version -notmatch '^[0-9][A-Za-z0-9.!+_-]*$') {
        throw 'Версия проекта недопустима для имени дистрибутива.'
    }
    $bundleName = "FirewallComplience_v$version"
    $buildOutput = Assert-WorkspacePath (Join-Path $projectRoot 'dist')
    $bundlePath = Assert-WorkspacePath (Join-Path $buildOutput $bundleName)
    $workPath = Assert-WorkspacePath (Join-Path $projectRoot '_temp_files/build/desktop')
    if (Get-Process -Name $bundleName, 'FirewallCompliance' -ErrorAction SilentlyContinue) {
        throw 'Приложение запущено. Закройте его перед перезаписью дистрибутива.'
    }
    $windowMode = if ($Console) { '--console' } else { '--windowed' }
    & $pythonPath -m PyInstaller --noconfirm --onedir $windowMode `
        --distpath $buildOutput `
        --workpath $workPath --specpath $workPath `
        --name $bundleName --paths src `
        --collect-submodules firewall_compliance --collect-data firewall_compliance `
        --exclude-module hypothesis --exclude-module mypy --exclude-module pytest `
        --exclude-module tkinter --exclude-module PySide6.QtWebEngineCore `
        --exclude-module PySide6.QtWebEngineWidgets --exclude-module PySide6.QtPdf `
        scripts/qt_launcher.py
    if ($LASTEXITCODE -ne 0) { throw 'Сборка PyInstaller завершилась с ошибкой.' }
    $readme = Get-Content -LiteralPath 'scripts/windows_distribution_README.txt' -Raw -Encoding UTF8
    $readme = $readme.Replace('FirewallCompliance.exe', "$bundleName.exe")
    [IO.File]::WriteAllText((Join-Path $bundlePath 'README.txt'), $readme, [Text.UTF8Encoding]::new($false))
    Write-Output (Join-Path $bundlePath "$bundleName.exe")
} finally {
    $env:PATH = $previousBuildPath
    Pop-Location
}
