Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function New-RandomHex([int]$Bytes) {
    $buffer = New-Object byte[] $Bytes
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($buffer) } finally { $generator.Dispose() }
    return -join ($buffer | ForEach-Object { $_.ToString("x2") })
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker Desktop is not installed. See INSTALL.md."
}
docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker Compose v2 is required." }
docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker Desktop is installed but is not running." }

$generated = $false
$adminPassword = ""
if (-not (Test-Path .env)) {
    if (-not (Test-Path .env.example)) { throw ".env.example is missing." }
    $secret = New-RandomHex 32
    $adminPassword = if ($env:GHOSTSOC_ADMIN_PASSWORD) { $env:GHOSTSOC_ADMIN_PASSWORD } else { New-RandomHex 18 }
    $postgresPassword = New-RandomHex 24
    $content = Get-Content .env.example
    $content = $content -replace '^GHOSTSOC_SECRET_KEY=.*$', "GHOSTSOC_SECRET_KEY=$secret"
    $content = $content -replace '^GHOSTSOC_BOOTSTRAP_ADMIN_PASSWORD=.*$', "GHOSTSOC_BOOTSTRAP_ADMIN_PASSWORD=$adminPassword"
    $content = $content -replace '^POSTGRES_PASSWORD=.*$', "POSTGRES_PASSWORD=$postgresPassword"
    Set-Content -Path .env -Value $content -Encoding UTF8
    $generated = $true
    Write-Host "Created .env with generated local credentials."
} else {
    Write-Host "Using existing .env; no credentials were overwritten."
}

docker compose config | Out-Null
if ($LASTEXITCODE -ne 0) { throw "docker-compose.yml or .env validation failed." }
if ($args -contains "--no-start") {
    Write-Host "Preflight passed. Start later with .\start.ps1"
    exit 0
}

Write-Host "Building and starting GhostSOC. OpenSearch can take several minutes on first start..."
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { throw "Docker Compose startup failed." }

$healthy = $false
Write-Host -NoNewline "Waiting for GhostSOC health"
for ($attempt = 0; $attempt -lt 100; $attempt++) {
    try {
        $result = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/health" -TimeoutSec 4
        if ($result.status -eq "healthy") { $healthy = $true; break }
    } catch { }
    Write-Host -NoNewline "."
    Start-Sleep -Seconds 3
}
Write-Host ""
if (-not $healthy) {
    docker compose ps
    docker compose logs --tail=120 backend frontend postgres opensearch
    throw "Services did not become healthy within 5 minutes. See INSTALL.md troubleshooting."
}

Write-Host ""
Write-Host "GhostSOC is ready: http://localhost:8080"
if ($generated) {
    Write-Host "Email: admin@ghostsoc.local"
    Write-Host "Password: $adminPassword"
    Write-Host "Save this password now. It remains in .env and is not written to another file."
} else {
    Write-Host "Use the administrator email/password configured in .env."
}
Write-Host "Status: docker compose ps"
Write-Host "Logs:   docker compose logs -f"
Write-Host "Stop:   .\stop.ps1"
