<#
  Install or upgrade the agent on a Windows test VM from the newest build in the shared folder.
  Run in an administrator PowerShell on the VM:

    & '\\vmware-host\Shared Folders\agent-gui\packaging\dev\update-windows-vm.ps1'
    & '...\update-windows-vm.ps1' -CodeFile C:\eagleeye-code.txt      # first install: connect it with a code
    & '...\update-windows-vm.ps1' -Purge                               # remove the agent and its settings first

  An upgrade keeps the agent's connection and settings (no code needed). Exit code 10 from Setup:
  installed, but it could not register with the code. See TESTING-VMS.md.
#>
param(
  [string]$Dist = '\\vmware-host\Shared Folders\agent-gui\dist',
  [string]$CodeFile = "",
  [switch]$Purge
)
$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this in an administrator PowerShell" }

$exe = 'C:\Program Files\EagleEye Agent\eagleeye.exe'
if ($Purge -and (Test-Path $exe)) {
  Write-Host "== removing the agent and its settings" -ForegroundColor Cyan
  & $exe service uninstall --purge
  $uninstaller = 'C:\Program Files\EagleEye Agent\unins000.exe'
  if (Test-Path $uninstaller) { Start-Process $uninstaller -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait }
}

$setup = Get-ChildItem (Join-Path $Dist 'EagleEyeAgent-Setup-*.exe') | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $setup) { throw "No EagleEyeAgent-Setup-*.exe in $Dist (build it on the PC first)" }
Write-Host ("== installing {0} (built {1:yyyy-MM-dd HH:mm})" -f $setup.Name, $setup.LastWriteTime) -ForegroundColor Cyan
$local = Join-Path $env:TEMP $setup.Name
Copy-Item $setup.FullName $local -Force              # run it from a local disk, not the share

$setupArgs = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/MERGETASKS="!autostart"', "/LOG=`"$env:TEMP\eagleeye-setup.log`"")
if ($CodeFile) { $setupArgs += "/CONNECTIONCODEFILE=`"$CodeFile`"" }
$code = (Start-Process $local -ArgumentList $setupArgs -Wait -PassThru).ExitCode
switch ($code) {
  0 { Write-Host "Setup: installed" -ForegroundColor Green }
  10 { Write-Host "Setup: installed, but it could not register with the code (see $env:TEMP\eagleeye-setup.log)" -ForegroundColor Yellow }
  default { throw "Setup ended with code $code (see $env:TEMP\eagleeye-setup.log)" }
}

Write-Host "== the service" -ForegroundColor Cyan
for ($i = 0; $i -lt 30; $i++) {
  $svc = Get-Service EagleEyeAgent -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -eq 'Running') { break }
  Start-Sleep 2
}
& $exe service status
Write-Host "== last lines of the log" -ForegroundColor Cyan
Get-Content 'C:\ProgramData\EagleEye\logs\agent.log' -Tail 15 -ErrorAction SilentlyContinue
