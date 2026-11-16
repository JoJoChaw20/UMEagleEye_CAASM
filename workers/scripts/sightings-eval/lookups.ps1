# Threat sightings evaluation, Windows side (see scripts/sightings-eval.ts and lookups.py).
#
# Looks up the planted domains mixed at random into the normal ones (Tranco top 1,000), one
# every 50 ms, then opens 4 connections to the planted IP, each held 20 s. Writes what it did,
# with times, to lookups-<computer>.csv in the current folder. Needs no administrator rights.
#
#   powershell -ExecutionPolicy Bypass -File lookups.ps1 planted-domains.txt normal-domains.txt 188.184.67.127
param([string]$Planted, [string]$Normal, [string]$Ip)

# Plain .NET reads and string arrays: the lab VM's PowerShell turned the first version's
# pipeline into one item per file (2 lookups instead of 1,020).
function Read-Names([string]$path) {
    $full = (Resolve-Path -LiteralPath $path).ProviderPath
    return [string[]]@([System.IO.File]::ReadAllLines($full) | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}
$plantedNames = Read-Names $Planted
$normalNames = Read-Names $Normal
Write-Host "Read $($plantedNames.Length) planted and $($normalNames.Length) normal names"
if ($plantedNames.Length -lt 1 -or $normalNames.Length -lt 100) { throw "The name files did not read as expected; nothing looked up" }

$all = New-Object System.Collections.Generic.List[object]
foreach ($n in $plantedNames) { $all.Add(@($n, $true)) }
foreach ($n in $normalNames) { $all.Add(@($n, $false)) }
$rng = New-Object System.Random 7
for ($i = $all.Count - 1; $i -gt 0; $i--) {          # Fisher-Yates shuffle, fixed seed
    $j = $rng.Next($i + 1)
    $tmp = $all[$i]; $all[$i] = $all[$j]; $all[$j] = $tmp
}

$out = "lookups-$env:COMPUTERNAME.csv"
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('utc,what,value,planted,result')
$now = { ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0).ToString('F3', [Globalization.CultureInfo]::InvariantCulture) }

foreach ($pair in $all) {
    $name = [string]$pair[0]
    $t = & $now
    try {
        $a = @(Resolve-DnsName -Name $name -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
        $result = ($a | Sort-Object -Unique) -join ' '
    } catch {
        $result = 'error'
    }
    $lines.Add("$t,lookup,$name,$($pair[1]),$result")
    Start-Sleep -Milliseconds 50
}
for ($i = 0; $i -lt 4; $i++) {
    $t = & $now
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect($Ip, 80)
        $bytes = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: info.cern.ch`r`n")   # unfinished: the server waits
        $c.GetStream().Write($bytes, 0, $bytes.Length)
        $lines.Add("$t,connect,$Ip,True,open")
        Start-Sleep -Seconds 20
        $c.Close()
    } catch {
        $lines.Add("$t,connect,$Ip,True,error")
    }
}
[System.IO.File]::WriteAllLines((Join-Path (Get-Location).ProviderPath $out), $lines)
Write-Host "$($all.Count) lookups ($($plantedNames.Length) planted) and 4 connections to $Ip; log in $out"
