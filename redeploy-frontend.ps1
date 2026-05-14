<#
.SYNOPSIS
    Re-deploy the frontend after the Quick Tunnel URL has changed.
    Run this whenever cloudflared was restarted and got a new trycloudflare.com URL.

.PARAMETER ProjectName
    Cloudflare Pages project name. Default: umeagleeye

.PARAMETER BackendPort
    Port the backend is running on. Default: 8000
#>
param(
    [string]$ProjectName = "umeagleeye",
    [int]$BackendPort    = 8000
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

function Write-Step { param([string]$msg) Write-Host "`n>>> $msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$msg) Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  UMEagleEye - Frontend Redeploy" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Start a fresh Quick Tunnel --------------------------------------
Write-Step "Starting new Quick Tunnel"

$tunnelLog = "$env:TEMP\cloudflared-quicktunnel.log"
if (Test-Path $tunnelLog) { Remove-Item $tunnelLog -Force }

$tunnelProcess = Start-Process -FilePath "cloudflared" `
    -ArgumentList "tunnel --url http://localhost:$BackendPort" `
    -RedirectStandardError $tunnelLog `
    -WindowStyle Hidden -PassThru

$tunnelUrl = $null
$deadline = (Get-Date).AddSeconds(60)
Write-Warn "Waiting for tunnel URL..."
while ((Get-Date) -lt $deadline) {
    if (Test-Path $tunnelLog) {
        $content = Get-Content $tunnelLog -Raw -ErrorAction SilentlyContinue
        if ($content) {
            $match = [regex]::Match($content, 'https://[a-z0-9\-]+\.trycloudflare\.com')
            if ($match.Success) { $tunnelUrl = $match.Value; break }
        }
    }
    Start-Sleep 2
}

if (-not $tunnelUrl) {
    throw "Could not get Quick Tunnel URL. Check log: $tunnelLog"
}
Write-Ok "New tunnel URL: $tunnelUrl"

[System.IO.File]::WriteAllText((Join-Path $ScriptDir ".tunnel-url"), $tunnelUrl, [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllText((Join-Path $ScriptDir ".tunnel-pid"), "$($tunnelProcess.Id)", [System.Text.Encoding]::UTF8)

# --- Step 2: Update frontend/.env.production ---------------------------------
Write-Step "Updating frontend/.env.production"
$frontendEnvPath = Join-Path $ScriptDir "frontend\.env.production"
[System.IO.File]::WriteAllText($frontendEnvPath, "VITE_API_URL=$tunnelUrl/api/v1`n", [System.Text.Encoding]::UTF8)
Write-Ok "VITE_API_URL=$tunnelUrl/api/v1"

# --- Step 3: Rebuild and redeploy --------------------------------------------
Write-Step "Building frontend"
Push-Location (Join-Path $ScriptDir "frontend")
try {
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
    Write-Ok "Build done"

    Write-Step "Deploying to Cloudflare Pages"
    npx wrangler pages deploy dist --project-name $ProjectName --commit-dirty=true
    if ($LASTEXITCODE -ne 0) { throw "Deploy failed" }
    Write-Ok "Deployed -> https://$ProjectName.pages.dev"
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "  Done! Frontend updated with new tunnel URL." -ForegroundColor Green
Write-Host "  Frontend : https://$ProjectName.pages.dev" -ForegroundColor Cyan
Write-Host "  Backend  : $tunnelUrl" -ForegroundColor Cyan
Write-Host ""
