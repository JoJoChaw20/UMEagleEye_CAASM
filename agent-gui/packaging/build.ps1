# Builds the Windows package of the EagleEye Agent.
#   1. icon      build\eagleeye.ico (drawn by the app's own code)
#   2. program   dist\EagleEyeAgent\  (PyInstaller one-folder build: EagleEyeAgent.exe + eagleeye.exe)
#   3. installer dist\EagleEyeAgent-Setup-<version>.exe  (only if Inno Setup 6 is installed)
#
# Run from agent-gui\ in PowerShell:   .\packaging\build.ps1
# Uses .venv\Scripts\python.exe when present, otherwise python on PATH.

# Not "Stop": PyInstaller logs to stderr, which Windows PowerShell 5.1 would treat as an
# error. Each step checks $LASTEXITCODE instead.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

$version = (& $python -c "import eagleeye; print(eagleeye.VERSION)").Trim()
$fileVersion = ($version -replace '[^0-9.].*$', '')
Write-Host "EagleEye Agent $version (installer version $fileVersion)"

Write-Host "`n[1/3] Icon"
& $python packaging\make_icon.py build\eagleeye.ico
if ($LASTEXITCODE -ne 0) { throw "icon step failed" }

Write-Host "`n[2/3] PyInstaller"
& $python -m PyInstaller --noconfirm --clean --distpath dist --workpath build\pyinstaller packaging\eagleeye-agent.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
& dist\EagleEyeAgent\eagleeye.exe version
if ($LASTEXITCODE -ne 0) { throw "the built eagleeye.exe does not start" }

Write-Host "`n[3/3] Installer"
$iscc = @(
    (Get-Command iscc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($iscc) {
    & $iscc "/DAppVersion=$fileVersion" packaging\installer.iss
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
    Write-Host "`nDone: dist\EagleEyeAgent-Setup-$fileVersion.exe"
} else {
    Write-Host "Inno Setup 6 not found, so no installer was made. The program is in dist\EagleEyeAgent\."
    Write-Host "Install it from https://jrsoftware.org/isdl.php (or: winget install JRSoftware.InnoSetup), then re-run."
}
