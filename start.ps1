Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path .env)) { throw "Run .\install.ps1 first." }
docker compose up -d
docker compose ps
Write-Host "Continuity: http://localhost:8080"
