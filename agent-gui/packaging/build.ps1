# Builds the Windows package of the EagleEye Agent.
#   0. stamp     eagleeye\_build.py: the build stamp 0.1.0+<UTC time>.<commit> (packaging\buildstamp.py)
#   1. icon      build\eagleeye.ico (the EagleEye emblem, eagleeye\gui\assets\mark.png)
#   2. program   dist\EagleEyeAgent\  (PyInstaller one-folder build: EagleEyeAgent.exe + eagleeye.exe)
#   3. installer dist\EagleEyeAgent-Setup-<version>.exe  (only if Inno Setup 6 is installed)
#   4. signed    dist\EagleEyeAgent-Setup-<version>.exe.manifest.json, for updates from the dashboard
#                (packaging\sign_package.py; needs the signing key on this machine)
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
$build = (& $python packaging\buildstamp.py write).Trim()
if ($LASTEXITCODE -ne 0) { throw "build stamp failed" }
Write-Host "EagleEye Agent $version, build $build (installer version $fileVersion)"

try {
    Write-Host "`n[1/4] Icon"
    & $python packaging\make_icon.py build\eagleeye.ico
    if ($LASTEXITCODE -ne 0) { throw "icon step failed" }

    Write-Host "`n[2/4] PyInstaller"
    & $python -m PyInstaller --noconfirm --clean --distpath dist --workpath build\pyinstaller packaging\eagleeye-agent.spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
    $reported = (& dist\EagleEyeAgent\eagleeye.exe version) -join " "
    if ($LASTEXITCODE -ne 0) { throw "the built eagleeye.exe does not start" }
    if ($reported -notmatch [regex]::Escape($build)) { throw "the built eagleeye.exe reports '$reported', not build $build" }
    & $python packaging\size_report.py dist\EagleEyeAgent
} finally {
    & $python packaging\buildstamp.py remove          # the source tree reports "dev" again
}

Write-Host "`n[3/4] Installer"
$iscc = @(
    (Get-Command iscc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) {
    Write-Host "Inno Setup 6 not found, so no installer was made. The program is in dist\EagleEyeAgent\."
    Write-Host "Install it from https://jrsoftware.org/isdl.php (or: winget install JRSoftware.InnoSetup), then re-run."
    exit 0
}
& $iscc "/DAppVersion=$fileVersion" packaging\installer.iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
$setup = "dist\EagleEyeAgent-Setup-$fileVersion.exe"

Write-Host "`n[4/4] Signature for updates"
& $python packaging\sign_package.py windows $setup $build
if ($LASTEXITCODE -ne 0) { Write-Host "Not signed: agents will not update to this build from the dashboard (a manual install still works)." }
Write-Host "`nDone: $setup (build $build)"
