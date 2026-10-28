param(
    [long]$SourceDateEpoch = -1
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

$distRoot = Assert-WorkspacePath (Join-Path $projectRoot 'dist')
$bundle = Assert-WorkspacePath (Join-Path $distRoot 'ArxionCLI')
$workRoot = Assert-WorkspacePath (Join-Path $projectRoot 'build/ArxionCLI')
$workPath = Assert-WorkspacePath (Join-Path $workRoot 'work')
$archive = Assert-WorkspacePath (Join-Path $distRoot 'ArxionCLI-windows-x64.zip')
$specPath = Assert-WorkspacePath (Join-Path $workRoot 'ArxionCLI.spec')
$python = Assert-WorkspacePath (Join-Path $projectRoot '.venv/Scripts/python.exe')
if (-not (Test-Path -LiteralPath $python) -or
    -not (Test-Path -LiteralPath (Join-Path $projectRoot 'uv.lock'))) {
    throw 'Prepare the existing locked .venv with python harness/build setup first.'
}
if (Get-Process ArxionCLI -ErrorAction SilentlyContinue) {
    throw 'ArxionCLI is running. Close its copies before replacing this distribution.'
}
$commit = (& git -C $projectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[a-fA-F0-9]{40,64}$') {
    throw 'Cannot determine the source Git commit.'
}
if (-not $PSBoundParameters.ContainsKey('SourceDateEpoch')) {
    if ($env:SOURCE_DATE_EPOCH) {
        if ($env:SOURCE_DATE_EPOCH -notmatch '^\d+$') {
            throw 'SOURCE_DATE_EPOCH must be a non-negative integer.'
        }
        $SourceDateEpoch = [long]$env:SOURCE_DATE_EPOCH
    } else {
        $commitTime = (& git -C $projectRoot show -s --format=%ct HEAD).Trim()
        if ($LASTEXITCODE -ne 0 -or $commitTime -notmatch '^\d+$') {
            throw 'Cannot determine Git commit time.'
        }
        $SourceDateEpoch = [long]$commitTime
    }
}
if ($SourceDateEpoch -lt 0 -or $SourceDateEpoch -gt 4354819199) {
    throw 'SOURCE_DATE_EPOCH must fit the supported ZIP timestamp range.'
}
New-Item -ItemType Directory -Path $workRoot, $distRoot -Force | Out-Null
$previousHashSeed = $env:PYTHONHASHSEED
$previousEpoch = $env:SOURCE_DATE_EPOCH
$previousPath = $env:PATH
Push-Location $projectRoot
try {
    $env:PYTHONHASHSEED = '0'
    $env:SOURCE_DATE_EPOCH = $SourceDateEpoch.ToString([Globalization.CultureInfo]::InvariantCulture)
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$projectRoot\.venv\Scripts"
    & $python -c "import struct, PyInstaller; assert struct.calcsize('P') == 8, 'x64 Python required'"
    if ($LASTEXITCODE -ne 0) { throw 'The existing .venv has no working x64 PyInstaller.' }
    $version = (& $python -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])').Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read the project version.' }
    $spec = @'
from pathlib import Path
import sys
project = Path(SPECPATH).resolve().parents[1]
sys.path.insert(0, str(project / 'scripts'))
from package_inventory import capture_analysis
a = Analysis(
    [str(project / 'scripts' / 'cli_launcher.py')],
    pathex=[str(project / 'src')],
    excludes=['PySide6', 'shiboken6', 'PyQt5', 'PyQt6', 'tkinter', '_tkinter',
              'pytest', '_pytest', 'hypothesis', 'mypy', 'ruff', 'docker',
              'pip', 'uv', 'setuptools', '_distutils_hack', 'wheel'],
    noarchive=False,
)
capture_analysis(
    [*a.pure, *a.binaries, *a.scripts, *getattr(a, '_modules_outside_pyz', [])],
    project / 'build' / 'ArxionCLI' / 'analysis.json',
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='ArxionCLI',
          debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
          console=True)
collect = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='ArxionCLI')
'@
    [IO.File]::WriteAllText($specPath, $spec, [Text.UTF8Encoding]::new($false))
    # Validate again immediately before --noconfirm may replace its exact targets.
    Assert-WorkspacePath $bundle | Out-Null
    Assert-WorkspacePath $workPath | Out-Null
    & $python -m PyInstaller --noconfirm --workpath $workPath --distpath $distRoot $specPath
    if ($LASTEXITCODE -ne 0) { throw 'CLI PyInstaller build failed.' }
    Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts/cli_distribution_README.txt') `
        -Destination (Join-Path $bundle 'README.txt') -Force
    & $python scripts/package_inventory.py smoke --executable (Join-Path $bundle 'ArxionCLI.exe') `
        --output (Join-Path $workRoot 'smoke') --version $version
    if ($LASTEXITCODE -ne 0) { throw 'Native CLI version/analyze smoke failed.' }
    & $python scripts/package_inventory.py package --root $bundle `
        --analysis (Join-Path $workRoot 'analysis.json') --project $projectRoot `
        --epoch $SourceDateEpoch --commit $commit --archive $archive
    if ($LASTEXITCODE -ne 0) { throw 'CLI inventory/SBOM/ZIP verification failed.' }
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($archive + '.sha256', "$archiveHash  $([IO.Path]::GetFileName($archive))`n", [Text.UTF8Encoding]::new($false))
    Write-Output (Join-Path $bundle 'ArxionCLI.exe')
    Write-Output $archive
    Write-Output "SHA256: $archiveHash"
    Write-Output "SOURCE_DATE_EPOCH: $SourceDateEpoch; PYTHONHASHSEED: 0"
} finally {
    $env:PYTHONHASHSEED = $previousHashSeed
    $env:SOURCE_DATE_EPOCH = $previousEpoch
    $env:PATH = $previousPath
    Pop-Location
}
