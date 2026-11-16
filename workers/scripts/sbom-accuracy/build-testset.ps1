# Builds the labelled SBOM test set on a Windows VM (scripts/sbom-accuracy/README.md).
#
# Every package in manifest.json is downloaded at its pinned version and UNPACKED as files in
# C:\Program Files\SbomTestSet (one of the agent's SBOM folders); nothing is installed or run.
# Syft reads only the metadata: Python *.dist-info, npm node_modules\*\package.json, Java
# jars, .NET *.deps.json. Windows PowerShell 5.1, run as Administrator:
#
#   powershell -ExecutionPolicy Bypass -File .\build-testset.ps1
#
# Run again to rebuild from scratch (the folder is replaced).
param([string]$Dest = "$env:ProgramFiles\SbomTestSet")

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$manifest = Get-Content -Raw (Join-Path $PSScriptRoot 'manifest.json') | ConvertFrom-Json
$tmp = Join-Path $env:TEMP "sbomtest-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force $tmp | Out-Null
if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
New-Item -ItemType Directory -Force $Dest | Out-Null

function Get-File([string]$url, [string]$path) {
  Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $path -Headers @{ 'User-Agent' = 'UMEagleEye-sbom-accuracy' }
}

function Add-PyPI($p) {
  $meta = Invoke-RestMethod -UseBasicParsing "https://pypi.org/pypi/$($p.name)/$($p.version)/json"
  $wheel = $meta.urls | Where-Object { $_.packagetype -eq 'bdist_wheel' -and $_.filename -like '*-none-any.whl' } | Select-Object -First 1
  if (-not $wheel) { throw "no pure-Python wheel" }
  $zip = Join-Path $tmp "$($p.name)-$($p.version).zip"     # Expand-Archive wants a .zip name
  Get-File $wheel.url $zip
  Expand-Archive -Force $zip (Join-Path $Dest 'python\site-packages')
}

function Add-Npm($p) {
  $tgz = Join-Path $tmp "$($p.name)-$($p.version).tgz"
  Get-File "https://registry.npmjs.org/$($p.name)/-/$($p.name)-$($p.version).tgz" $tgz
  $target = Join-Path $Dest "node\node_modules\$($p.name)"
  New-Item -ItemType Directory -Force $target | Out-Null
  & tar.exe -xzf $tgz -C $target --strip-components=1      # drop the tarball's "package/" folder
  if ($LASTEXITCODE -ne 0) { throw "tar failed" }
}

function Add-Maven($p) {
  $group, $artifact = $p.name.Split(':')
  $dir = Join-Path $Dest 'java\lib'
  New-Item -ItemType Directory -Force $dir | Out-Null
  Get-File "https://repo1.maven.org/maven2/$($group.Replace('.', '/'))/$artifact/$($p.version)/$artifact-$($p.version).jar" (Join-Path $dir "$artifact-$($p.version).jar")
}

# A .NET app folder: its deps.json lists the packages, and their DLLs sit beside it.
function Add-NuGetApp($pkgs) {
  $app = Join-Path $Dest 'dotnet\SbomTestApp'
  New-Item -ItemType Directory -Force $app | Out-Null
  $tfm = '.NETCoreApp,Version=v6.0'
  $deps = [ordered]@{}; foreach ($p in $pkgs) { $deps[$p.name] = $p.version }
  $targets = [ordered]@{ 'SbomTestApp/1.0.0' = [ordered]@{ dependencies = $deps; runtime = @{ 'SbomTestApp.dll' = @{} } } }
  $libraries = [ordered]@{ 'SbomTestApp/1.0.0' = [ordered]@{ type = 'project'; serviceable = $false; sha512 = '' } }
  foreach ($p in $pkgs) {
    $key = "$($p.name)/$($p.version)"
    $zip = Join-Path $tmp "$($p.name).$($p.version).zip"
    Get-File "https://www.nuget.org/api/v2/package/$($p.name)/$($p.version)" $zip
    $out = Join-Path $tmp "$($p.name).$($p.version)"
    Expand-Archive -Force $zip $out
    $dll = Get-ChildItem -Path (Join-Path $out 'lib\netstandard2.0') -Filter *.dll -ErrorAction SilentlyContinue | Select-Object -First 1
    $runtime = @{}
    if ($dll) { Copy-Item $dll.FullName $app; $runtime["lib/netstandard2.0/$($dll.Name)"] = @{} }
    $targets[$key] = [ordered]@{ runtime = $runtime }
    $libraries[$key] = [ordered]@{ type = 'package'; serviceable = $true; sha512 = ''; path = $key.ToLower(); hashPath = "$($p.name.ToLower()).$($p.version).nupkg.sha512" }
  }
  $doc = [ordered]@{ runtimeTarget = @{ name = $tfm; signature = '' }; compilationOptions = @{}; targets = @{ $tfm = $targets }; libraries = $libraries }
  Write-Utf8 (Join-Path $app 'SbomTestApp.deps.json') ($doc | ConvertTo-Json -Depth 10)
}

# UTF-8 WITHOUT a byte-order mark: Windows PowerShell's "-Encoding UTF8" adds one, and Syft
# then cannot read the deps.json (it falls back to the DLLs' file names and versions).
function Write-Utf8([string]$path, [string]$text) {
  [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding $false))
}

$ok = 0; $failed = @()
foreach ($p in $manifest.packages) {
  if ($p.ecosystem -eq 'NuGet') { continue }
  try {
    switch ($p.ecosystem) { 'PyPI' { Add-PyPI $p } 'npm' { Add-Npm $p } 'Maven' { Add-Maven $p } }
    $ok++; Write-Host ("  ok  {0,-6} {1} {2}" -f $p.ecosystem, $p.name, $p.version)
  } catch { $failed += "$($p.name) $($p.version): $_" }
}
$nuget = @($manifest.packages | Where-Object { $_.ecosystem -eq 'NuGet' })
try { Add-NuGetApp $nuget; $ok += $nuget.Count; Write-Host "  ok  NuGet  $($nuget.Count) packages in dotnet\SbomTestApp" }
catch { $failed += "NuGet app: $_" }

Write-Utf8 (Join-Path $Dest 'MANIFEST.json') ($manifest | ConvertTo-Json -Depth 5)
Remove-Item -Recurse -Force $tmp
Write-Host "`n$ok packages placed in $Dest"
if ($failed.Count) { Write-Host "FAILED:`n  $($failed -join "`n  ")" -ForegroundColor Red; exit 1 }
