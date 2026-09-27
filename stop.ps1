Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
docker compose down
Write-Host "GhostSOC stopped. Persistent volumes were preserved."
