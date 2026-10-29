# Совместимый вход: собирается только полный дистрибутив.
# Правила: specifications/WINDOWS_DISTRIBUTION.md.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build_desktop.ps1')
