param(
    [switch]$Console,
    [switch]$Production,
    [switch]$ArubaUpdate,
    [ValidatePattern('^[A-Za-z][A-Za-z0-9-]{0,40}$')][string]$Variant
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$distDirectory = if ($Production) { 'prod' } elseif ($Variant) { "dist/$Variant" } elseif ($ArubaUpdate) {
    'dist/ArubaUpdate'
} else { 'dist' }
$buildOutput = [IO.Path]::GetFullPath((Join-Path $projectRoot $distDirectory))
if (-not $buildOutput.StartsWith($projectRoot + [IO.Path]::DirectorySeparatorChar)) {
    throw 'Папка сборки должна находиться внутри проекта.'
}
if (-not $ArubaUpdate -and -not $Variant -and
    (Get-Process FirewallCompliance -ErrorAction SilentlyContinue)) {
    throw 'Приложение запущено. Закройте его или используйте -ArubaUpdate для отдельной сборки.'
}
$pythonPath = Join-Path $projectRoot 'dev\.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Сначала выполните uv sync --all-groups.'
}
Push-Location $projectRoot
$previousBuildPath = $env:PATH
try {
    # Сторонние ICU DLL из PATH не должны подменять системный ICU, используемый Qt.
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$projectRoot\.venv\Scripts"
    $windowMode = if ($Console) { '--console' } else { '--windowed' }
    & $pythonPath -m PyInstaller --noconfirm --onedir $windowMode `
        --distpath $buildOutput --workpath (Join-Path $projectRoot 'dev/build') `
        --name FirewallCompliance --paths src `
        --collect-data firewall_compliance `
        --exclude-module hypothesis --exclude-module mypy --exclude-module pytest `
        --exclude-module tkinter --exclude-module PySide6.QtWebEngineCore `
        --exclude-module PySide6.QtWebEngineWidgets --exclude-module PySide6.QtPdf `
        scripts/qt_launcher.py
    if ($LASTEXITCODE -ne 0) { throw 'Сборка PyInstaller завершилась с ошибкой.' }
    Copy-Item -LiteralPath 'scripts/windows_distribution_README.txt' `
        -Destination (Join-Path $buildOutput 'FirewallCompliance/README.txt') -Force
    $archiveName = if ($Variant) {
        "FirewallCompliance-$Variant-windows-x64.zip"
    } elseif ($ArubaUpdate) {
        'FirewallCompliance-ArubaUpdate-windows-x64.zip'
    } else {
        'FirewallCompliance-windows-x64.zip'
    }
    $archivePath = Join-Path $buildOutput $archiveName
    for ($archiveAttempt = 0; ; $archiveAttempt++) {
        try {
            Compress-Archive -LiteralPath (Join-Path $buildOutput 'FirewallCompliance') `
                -DestinationPath $archivePath -Force -ErrorAction Stop
            break
        } catch {
            if ($archiveAttempt -ge 2) { throw }
            # Newly generated EXEs can be temporarily locked by antivirus scanning.
            Start-Sleep -Seconds 2
        }
    }
    Write-Output (Join-Path $buildOutput 'FirewallCompliance/FirewallCompliance.exe')
    Write-Output $archivePath
} finally {
    $env:PATH = $previousBuildPath
    Pop-Location
}
