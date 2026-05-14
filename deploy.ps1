<#
.SYNOPSIS
    Deploy UMEagleEye 2.0: React frontend to Cloudflare Pages, backend exposed via Cloudflare Quick Tunnel.

.DESCRIPTION
    Uses Cloudflare Quick Tunnel -- no account, no domain required.
    Steps:
      1. Check prerequisites (Docker, Node, npm, cloudflared)
      2. Start Docker Compose backend services
      3. Start Quick Tunnel -> get a trycloudflare.com URL
      4. Build the React frontend with that URL as VITE_API_URL
      5. Deploy frontend to Cloudflare Pages via wrangler (opens browser for Cloudflare login once)
      6. Print final URLs

    NOTE: The Quick Tunnel URL changes every time cloudflared restarts.
    If you restart cloudflared, run .\redeploy-frontend.ps1 to update the frontend.

.PARAMETER ProjectName
    Cloudflare Pages project name. Frontend will be at https://<ProjectName>.pages.dev
    Default: umeagleeye

.PARAMETER BackendPort
    Local port FastAPI listens on. Default: 8000

.EXAMPLE
    .\deploy.ps1
    .\deploy.ps1 -ProjectName myapp
#>
param(
    [string]$ProjectName = "umeagleeye",
    [int]$BackendPort    = 8000
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$PagesUrl = "https://$ProjectName.pages.dev"

# --- Helpers -----------------------------------------------------------------
function Write-Step { param([string]$msg) Write-Host "`n>>> $msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$msg) Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }

function Test-Cmd([string]$cmd) {
    return $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)
}

function Wait-ForBackend([int]$port, [int]$timeoutSec = 120) {
    Write-Warn "Waiting for backend on :$port (up to ${timeoutSec}s)..."
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-RestMethod "http://localhost:$port/health" -TimeoutSec 3
            if ($r.status -eq "healthy") { Write-Ok "Backend is healthy"; return }
        } catch { }
        Start-Sleep 3
    }
    Write-Warn "Backend health check timed out -- it may still be starting."
}

# --- Banner ------------------------------------------------------------------
Write-Host ""
Write-Host "  +-------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |   UMEagleEye 2.0  -  Cloudflare Deployment     |" -ForegroundColor Cyan
Write-Host "  |   Frontend  ->  Cloudflare Pages (.pages.dev)  |" -ForegroundColor Cyan
Write-Host "  |   Backend   ->  Cloudflare Quick Tunnel         |" -ForegroundColor Cyan
Write-Host "  +-------------------------------------------------+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Pages URL  : $PagesUrl"
Write-Host "  Backend    : localhost:$BackendPort"
Write-Host ""

# --- Step 1: Prerequisites ---------------------------------------------------
Write-Step "Checking prerequisites"

if (-not (Test-Cmd "docker")) {
    throw "Docker not found. Install Docker Desktop: https://docs.docker.com/desktop/windows/"
}
Write-Ok "Docker found"

if (-not (Test-Cmd "node")) { throw "Node.js not found. Install from: https://nodejs.org/" }
Write-Ok "Node.js $(node --version)"

if (-not (Test-Cmd "npm")) { throw "npm not found." }
Write-Ok "npm $(npm --version)"

if (-not (Test-Cmd "cloudflared")) {
    Write-Warn "cloudflared not found. Installing via winget..."
    winget install --id Cloudflare.cloudflared --accept-package-agreements --accept-source-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")
}
if (-not (Test-Cmd "cloudflared")) {
    throw "cloudflared not found. Install from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
}
Write-Ok "cloudflared found"

# --- Step 2: Start Docker Compose backend ------------------------------------
Write-Step "Starting backend services via Docker Compose"

$composeFile1 = Join-Path $ScriptDir "docker-compose.yml"
$composeFile2 = Join-Path $ScriptDir "docker-compose.prod.yml"

& docker compose -f $composeFile1 -f $composeFile2 up -d --build db redis backend celery-worker celery-beat
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
Write-Ok "Docker services started"

Wait-ForBackend -port $BackendPort

# --- Step 3: Start Cloudflare Quick Tunnel and capture URL -------------------
Write-Step "Starting Cloudflare Quick Tunnel (no login required)"

$tunnelLog = "$env:TEMP\cloudflared-quicktunnel.log"
if (Test-Path $tunnelLog) { Remove-Item $tunnelLog -Force }

Write-Warn "Starting tunnel process in background..."
$tunnelProcess = Start-Process -FilePath "cloudflared" `
    -ArgumentList "tunnel --url http://localhost:$BackendPort" `
    -RedirectStandardError $tunnelLog `
    -WindowStyle Hidden -PassThru

# Wait for the trycloudflare.com URL to appear in the log (up to 60s)
$tunnelUrl = $null
$deadline = (Get-Date).AddSeconds(60)
Write-Warn "Waiting for tunnel URL..."
while ((Get-Date) -lt $deadline) {
    if (Test-Path $tunnelLog) {
        $content = Get-Content $tunnelLog -Raw -ErrorAction SilentlyContinue
        if ($content) {
            $match = [regex]::Match($content, 'https://[a-z0-9\-]+\.trycloudflare\.com')
            if ($match.Success) {
                $tunnelUrl = $match.Value
                break
            }
        }
    }
    Start-Sleep 2
}

if (-not $tunnelUrl) {
    # Dump log for diagnosis
    if (Test-Path $tunnelLog) { Get-Content $tunnelLog | Write-Host }
    throw "Could not get Quick Tunnel URL after 60s. Check log at: $tunnelLog"
}

Write-Ok "Tunnel URL: $tunnelUrl"
Write-Warn "This URL changes if cloudflared restarts. Run .\redeploy-frontend.ps1 to update it."

# Save tunnel URL for the redeploy script
[System.IO.File]::WriteAllText(
    (Join-Path $ScriptDir ".tunnel-url"),
    $tunnelUrl,
    [System.Text.Encoding]::UTF8
)

# Also save the tunnel process PID so it can be managed later
[System.IO.File]::WriteAllText(
    (Join-Path $ScriptDir ".tunnel-pid"),
    "$($tunnelProcess.Id)",
    [System.Text.Encoding]::UTF8
)

# --- Step 4: Update CORS in .env ---------------------------------------------
Write-Step "Updating BACKEND_CORS_ORIGINS in .env"

$envPath = Join-Path $ScriptDir ".env"
if (-not (Test-Path $envPath)) { throw ".env not found at $envPath" }

$envContent = Get-Content $envPath -Raw

# Add Pages URL to CORS if not already there
if ($envContent -notmatch [regex]::Escape($PagesUrl)) {
    $envContent = $envContent -replace '(BACKEND_CORS_ORIGINS=[^\r\n]+)', "`$1,$PagesUrl"
    [System.IO.File]::WriteAllText($envPath, $envContent, [System.Text.Encoding]::UTF8)
    Write-Ok "Added $PagesUrl to BACKEND_CORS_ORIGINS"
} else {
    Write-Warn "$PagesUrl already in BACKEND_CORS_ORIGINS"
}

# Force-recreate backend to reload .env (restart alone does not re-read env vars)
Write-Warn "Recreating backend container to apply CORS update..."
& docker compose -f $composeFile1 -f $composeFile2 up -d --force-recreate backend
Write-Ok "Backend recreated with updated CORS"

# --- Step 5: Create frontend/.env.production ---------------------------------
Write-Step "Creating frontend/.env.production"

$frontendEnvPath = Join-Path $ScriptDir "frontend\.env.production"
[System.IO.File]::WriteAllText(
    $frontendEnvPath,
    "VITE_API_URL=$tunnelUrl/api/v1`n",
    [System.Text.Encoding]::UTF8
)
Write-Ok "VITE_API_URL=$tunnelUrl/api/v1"

# --- Step 6: Build the React frontend ----------------------------------------
Write-Step "Building React frontend (npm run build)"

Push-Location (Join-Path $ScriptDir "frontend")
try {
    npm ci --silent
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }

    npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }

    Write-Ok "Build successful -> frontend/dist/"
} finally {
    Pop-Location
}

# --- Step 7: Deploy to Cloudflare Pages --------------------------------------
Write-Step "Deploying frontend to Cloudflare Pages: $ProjectName"
Write-Warn "A browser will open asking you to log in to Cloudflare (one-time)."
Write-Warn "You only need a free Cloudflare account -- no domain required."

Push-Location (Join-Path $ScriptDir "frontend")
try {
    npx wrangler pages deploy dist --project-name $ProjectName --commit-dirty=true
    if ($LASTEXITCODE -ne 0) { throw "wrangler pages deploy failed" }
    Write-Ok "Deployed -> $PagesUrl"
} finally {
    Pop-Location
}

# --- Done --------------------------------------------------------------------
Write-Host ""
Write-Host "  +-------------------------------------------------+" -ForegroundColor Green
Write-Host "  |             Deployment Complete!                |" -ForegroundColor Green
Write-Host "  +-------------------------------------------------+" -ForegroundColor Green
Write-Host ""
Write-Host "  Frontend  : $PagesUrl" -ForegroundColor Cyan
Write-Host "  Backend   : $tunnelUrl" -ForegroundColor Cyan
Write-Host "  API Docs  : $tunnelUrl/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "  IMPORTANT: The tunnel URL changes if cloudflared restarts." -ForegroundColor Yellow
Write-Host "  To update the frontend after a restart, run:" -ForegroundColor Yellow
Write-Host "    .\redeploy-frontend.ps1" -ForegroundColor Yellow
Write-Host ""
Write-Host "  To keep the tunnel running persistently, leave this PowerShell window open."
Write-Host "  Or run cloudflared manually: cloudflared tunnel --url http://localhost:$BackendPort"
Write-Host ""
