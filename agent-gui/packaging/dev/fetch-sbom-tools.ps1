<#
  Download Syft and Grype (the SBOM tools) on the PC for test VMs that cannot reach GitHub themselves:
  the latest Windows and Linux (amd64) releases from github.com/anchore, checked against each release's
  checksums file, unpacked into agent-gui\dist\sbom-tools\windows and \linux (the Windows VM sees them
  through the shared folder; copy the Linux ones to the Ubuntu VM with scp). See TESTING-VMS.md.

    .\packaging\dev\fetch-sbom-tools.ps1
    .\packaging\dev\fetch-sbom-tools.ps1 -Ubuntu user@192.168.36.50     # ...and copy the Linux ones to the VM
#>
param([string]$Ubuntu = "")
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$out = Join-Path $PSScriptRoot "..\..\dist\sbom-tools"
$work = Join-Path $out ".download"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $work, (Join-Path $out "windows"), (Join-Path $out "linux") | Out-Null

# Through the API's asset address, not github.com/.../releases/download: github.com itself has answered
# 504 on this network while the API and its download host worked.
function Get-Asset($asset, [string]$path) {
  Invoke-WebRequest $asset.url -OutFile $path -UseBasicParsing -Headers @{ "Accept" = "application/octet-stream"; "User-Agent" = "eagleeye-dev" }
}

foreach ($tool in "syft", "grype") {
  $release = Invoke-RestMethod "https://api.github.com/repos/anchore/$tool/releases/latest" -Headers @{ "User-Agent" = "eagleeye-dev" }
  $version = $release.tag_name.TrimStart("v")
  $sums = @{}
  $sumsAsset = $release.assets | Where-Object name -eq "${tool}_${version}_checksums.txt"
  $sumsFile = Join-Path $work $sumsAsset.name
  Get-Asset $sumsAsset $sumsFile
  (Get-Content $sumsFile) | ForEach-Object {
    $hash, $name = $_.Trim() -split "\s+", 2
    if ($name) { $sums[$name] = $hash.ToLower() }
  }
  foreach ($target in @(@{ os = "windows"; file = "${tool}_${version}_windows_amd64.zip"; exe = "$tool.exe" },
                        @{ os = "linux"; file = "${tool}_${version}_linux_amd64.tar.gz"; exe = $tool })) {
    $asset = $release.assets | Where-Object name -eq $target.file
    if (-not $asset) { throw "$($target.file) is not in the $tool $version release" }
    $archive = Join-Path $work $target.file
    Get-Asset $asset $archive
    $hash = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLower()
    if ($sums[$target.file] -ne $hash) { throw "$($target.file): checksum does not match the release's checksums file" }
    $unpack = Join-Path $work "$tool-$($target.os)"
    New-Item -ItemType Directory -Force $unpack | Out-Null
    tar -xf $archive -C $unpack $target.exe          # only the program, nothing else from the archive
    Copy-Item (Join-Path $unpack $target.exe) (Join-Path $out $target.os) -Force
    Write-Host ("{0} {1} for {2}: checksum OK" -f $tool, $version, $target.os) -ForegroundColor Green
  }
}
Remove-Item $work -Recurse -Force

if ($Ubuntu) {
  scp (Join-Path $out "linux\syft") (Join-Path $out "linux\grype") "${Ubuntu}:"
  if ($LASTEXITCODE -ne 0) { throw "scp to $Ubuntu failed" }
}
Write-Host ""
Write-Host "Windows VM (administrator PowerShell):"
Write-Host "  New-Item -ItemType Directory -Force 'C:\Program Files\syft','C:\Program Files\grype' | Out-Null"
Write-Host "  Copy-Item '\\vmware-host\Shared Folders\agent-gui\dist\sbom-tools\windows\syft.exe' 'C:\Program Files\syft\'"
Write-Host "  Copy-Item '\\vmware-host\Shared Folders\agent-gui\dist\sbom-tools\windows\grype.exe' 'C:\Program Files\grype\'"
Write-Host "Ubuntu VM:"
Write-Host "  sudo install -m 755 ~/syft ~/grype /usr/local/bin/"
