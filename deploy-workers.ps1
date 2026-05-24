<#
.SYNOPSIS
    Deploy UMEagleEye Workers backend to Cloudflare.
    Run once after setting up your Neon DB and Cloudflare account.

.DESCRIPTION
    1. Install Workers dependencies
    2. Push secrets to Cloudflare (reads from .env)
    3. Deploy the Worker
    4. Rebuild + redeploy frontend with Workers URL as VITE_API_URL

.PARAMETER WorkerName
    Cloudflare Worker name. Default: umeagleeye-api

.PARAMETER ProjectName
    Cloudflare Pages project name. Default: umeagleeye
#>
param(
    [string]$WorkerName  = "umeagleeye-api",
    [string]$ProjectName = "umeagleeye-caasm"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Explicitly set the Cloudflare Account ID for non-interactive deployments
$env:CLOUDFLARE_ACCOUNT_ID = "6952d86b33a173095e02adcf78bc6fe1"

function Write-Step { param([string]$msg) Write-Host "`n>>> $msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$msg) Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  UMEagleEye 2.0  -  Workers Deployment" -ForegroundColor Cyan
Write-Host ""

# ── Load .env ─────────────────────────────────────────────────────
Write-Step "Loading .env"
$envPath = Join-Path $ScriptDir ".env"
if (-not (Test-Path $envPath)) { throw ".env not found. Copy .env.example to .env and fill values." }

$envVars = @{}
foreach ($line in Get-Content $envPath) {
    if ($line -match '^\s*#' -or $line -match '^\s*$') { continue }
    $parts = $line -split '=', 2
    if ($parts.Count -eq 2) { $envVars[$parts[0].Trim()] = $parts[1].Trim() }
}
Write-Ok "Loaded $(($envVars.Keys).Count) variables"

# ── Install Workers dependencies ──────────────────────────────────
Write-Step "Installing Workers dependencies"
Push-Location (Join-Path $ScriptDir "workers")
try {
    npm install
    if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
    Write-Ok "Dependencies installed"

    # ── Push secrets to Cloudflare ─────────────────────────────────
    Write-Step "Pushing secrets to Cloudflare Workers"
    $secrets = @(
        "DATABASE_URL", "JWT_SECRET_KEY", "GOOGLE_CLIENT_ID",
        "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "OTX_API_KEY", "THREATFOX_API_KEY",
        "NVD_API_KEY", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"
    )
    foreach ($key in $secrets) {
        $val = $envVars[$key]
        if ([string]::IsNullOrEmpty($val)) {
            Write-Warn "Skipping empty secret: $key"
            continue
        }
        # pipe the value into wrangler secret put
        $val | npx wrangler secret put $key --name $WorkerName
        Write-Ok "Set secret: $key"
    }

    # ── Deploy the Worker and capture its URL ─────────────────────
    Write-Step "Deploying Worker: $WorkerName"
    $deployLogs = npx wrangler deploy 2>&1
    $deployLogs | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "wrangler deploy failed" }
    Write-Ok "Worker deployed"

    # Extract the actual URL from wrangler output (e.g. https://umeagleeye-api.syntaxch404.workers.dev)
    $urlLine = $deployLogs | Where-Object { $_ -match 'https://[^\s]+\.workers\.dev' } | Select-Object -First 1
    if ($urlLine -match '(https://[^\s]+\.workers\.dev)') {
        $workersUrl = $matches[1]
    } else {
        $workersUrl = "https://$WorkerName.workers.dev"
    }
    Write-Ok "Workers URL: $workersUrl"

} finally {
    Pop-Location
}

# ── Update frontend to use Workers URL ────────────────────────────
Write-Step "Updating frontend/.env.production with Workers URL"
$frontendEnvPath = Join-Path $ScriptDir "frontend\.env.production"
[System.IO.File]::WriteAllText($frontendEnvPath, "VITE_API_URL=$workersUrl/api/v1`n", [System.Text.Encoding]::UTF8)
Write-Ok "VITE_API_URL=$workersUrl/api/v1"

# ── Add GOOGLE_CLIENT_ID to frontend env if present ───────────────
$googleClientId = $envVars["GOOGLE_CLIENT_ID"]
if (-not [string]::IsNullOrEmpty($googleClientId)) {
    $content = Get-Content $frontendEnvPath -Raw
    $content += "VITE_GOOGLE_CLIENT_ID=$googleClientId`n"
    [System.IO.File]::WriteAllText($frontendEnvPath, $content, [System.Text.Encoding]::UTF8)
    Write-Ok "VITE_GOOGLE_CLIENT_ID set"
}

# ── Rebuild and redeploy frontend ─────────────────────────────────
Write-Step "Building and deploying frontend to Cloudflare Pages"
Push-Location (Join-Path $ScriptDir "frontend")
try {
    npm install
    if ($LASTEXITCODE -ne 0) { throw "npm install (frontend) failed" }
    Write-Ok "Frontend dependencies installed"

    npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
    Write-Ok "Build done"

    npx wrangler pages deploy dist --project-name $ProjectName --commit-dirty=true
    if ($LASTEXITCODE -ne 0) { throw "Pages deploy failed" }
    Write-Ok "Frontend deployed -> https://$ProjectName.pages.dev"
} finally {
    Pop-Location
}

# ── Done ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Deployment Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Frontend  : https://$ProjectName.pages.dev" -ForegroundColor Cyan
Write-Host "  Workers   : $workersUrl" -ForegroundColor Cyan
Write-Host "  API Docs  : $workersUrl/" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run database migrations: cd workers && npm run db:push" -ForegroundColor Yellow
Write-Host "  2. Create your first superadmin: POST $workersUrl/api/v1/auth/register" -ForegroundColor Yellow
Write-Host "  3. Register an EagleEye agent: POST $workersUrl/api/v1/agents" -ForegroundColor Yellow
Write-Host ""
