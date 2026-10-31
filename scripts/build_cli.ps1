# Совместимый вход: собирается только полный дистрибутив.
# Правила: DEVELOPMENT.md (Windows distribution).
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build_desktop.ps1')
