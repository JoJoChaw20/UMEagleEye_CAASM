<#
  Build the agent for a test round on the VMs (development PC, from agent-gui\):

    .\packaging\dev\build-test.ps1                                   # Windows installer + Linux package
    .\packaging\dev\build-test.ps1 -Ubuntu user@192.168.36.50        # ...and copy the Linux package to the Ubuntu VM
    .\packaging\dev\build-test.ps1 -SkipInstaller -Ubuntu user@...   # Linux only (no Inno Setup run)

  The Windows VM takes the installer from the shared folder (agent-gui\dist); the Ubuntu VM gets
  the .tar.gz and update-ubuntu-vm.sh in its home folder. See TESTING-VMS.md.
#>
param(
  [string]$Ubuntu = "",
  [switch]$SkipInstaller
)
$ErrorActionPreference = "Stop"
$agent = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $agent
$python = Join-Path $agent ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

Write-Host "== tests" -ForegroundColor Cyan
& $python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed: fix them before testing on the VMs" }

$started = Get-Date
if (-not $SkipInstaller) {
  Write-Host "== Windows installer" -ForegroundColor Cyan
  & .\packaging\build.ps1
  $fresh = Get-ChildItem dist\EagleEyeAgent-Setup-*.exe -ErrorAction SilentlyContinue | Where-Object LastWriteTime -ge $started
  if (-not $fresh) { throw "build.ps1 made no new installer (is Inno Setup 6 installed?)" }
}

Write-Host "== Linux package" -ForegroundColor Cyan
& $python packaging\make_source.py
if ($LASTEXITCODE -ne 0) { throw "make_source.py failed" }
$tarball = Get-ChildItem dist\eagleeye-agent-*.tar.gz | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$installer = Get-ChildItem dist\EagleEyeAgent-Setup-*.exe -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($Ubuntu) {
  Write-Host "== copying to $Ubuntu" -ForegroundColor Cyan
  scp $tarball.FullName (Join-Path $PSScriptRoot "update-ubuntu-vm.sh") "${Ubuntu}:"
  if ($LASTEXITCODE -ne 0) { throw "scp to $Ubuntu failed" }
}

Write-Host ""
Write-Host "Built:" -ForegroundColor Green
if ($installer) { Write-Host ("  {0}  ({1:yyyy-MM-dd HH:mm})" -f $installer.Name, $installer.LastWriteTime) }
Write-Host ("  {0}  ({1:yyyy-MM-dd HH:mm})" -f $tarball.Name, $tarball.LastWriteTime)
Write-Host ""
Write-Host "Next:"
Write-Host "  Windows VM (administrator PowerShell):  & '\\vmware-host\Shared Folders\agent-gui\packaging\dev\update-windows-vm.ps1'"
Write-Host "  Ubuntu VM:                              sudo bash ~/update-ubuntu-vm.sh ~/$($tarball.Name)"
