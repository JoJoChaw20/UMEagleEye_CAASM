# EagleEye endpoint inventory for Windows (PowerShell 5.1+). Read-only: it only queries
# CIM/WMI, the registry and built-in cmdlets. Prints one JSON document on stdout.
# Each section is independent; a failing section is reported in "errors" and left null.
#
# Data minimisation: per-user software (HKCU) and local administrator account names are
# personal data and are only read when explicitly requested with the switches below.
param(
    [switch]$IncludeUserSoftware,
    [switch]$IncludeAdminNames
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$errors = New-Object System.Collections.Generic.List[string]

function Section([string]$name, [scriptblock]$block) {
    try { & $block } catch { $errors.Add("${name}: $($_.Exception.Message)"); $null }
}
function Iso($value) {
    if ($null -eq $value -or "$value" -eq '') { return $null }
    try { return ([datetime]$value).ToUniversalTime().ToString('o') } catch { return $null }
}
function RegValue([string]$path, [string]$name) {
    try { return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { return $null }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$cs   = Section 'computer_system'  { Get-CimInstance Win32_ComputerSystem }
$csp  = Section 'computer_product' { Get-CimInstance Win32_ComputerSystemProduct }
$bios = Section 'bios'             { Get-CimInstance Win32_BIOS }
$os   = Section 'os'               { Get-CimInstance Win32_OperatingSystem }
$encl = Section 'enclosure'        { Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1 }
$cv   = Section 'os_registry'      { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' }

$cpus = Section 'cpu' {
    ,@(Get-CimInstance Win32_Processor | ForEach-Object {
        [ordered]@{ name = "$($_.Name)".Trim(); cores = [int]$_.NumberOfCores; threads = [int]$_.NumberOfLogicalProcessors }
    })
}
$disks = Section 'disks' {
    ,@(Get-PhysicalDisk | ForEach-Object {
        [ordered]@{ model = "$($_.FriendlyName)".Trim(); media = [string]$_.MediaType; bus = [string]$_.BusType; size_bytes = [int64]$_.Size }
    })
}
$volumes = Section 'volumes' {
    ,@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [ordered]@{ drive = $_.DeviceID; filesystem = $_.FileSystem; size_bytes = [int64]$_.Size; free_bytes = [int64]$_.FreeSpace }
    })
}

$hotfixes = Section 'hotfixes' {
    ,@(Get-HotFix | ForEach-Object {
        [ordered]@{ id = $_.HotFixID; description = $_.Description; installed_on = (Iso $_.InstalledOn) }
    })
}
$pendingReboot = Section 'pending_reboot' {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    [bool](@($keys | Where-Object { Test-Path $_ }).Count)
}

$software = Section 'software' {
    $roots = @(
        @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';             scope = 'machine'; arch = 'x64' },
        @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; scope = 'machine'; arch = 'x86' },
        @{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';             scope = 'user';    arch = $null }
    )
    if (-not $IncludeUserSoftware) { $roots = @($roots | Where-Object { $_.scope -ne 'user' }) }
    ,@(foreach ($root in $roots) {
        Get-ItemProperty -Path $root.path -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName -and
            $_.ReleaseType -notin @('Update', 'Hotfix', 'Security Update')
        } | ForEach-Object {
            [ordered]@{
                name = [string]$_.DisplayName; version = [string]$_.DisplayVersion; publisher = [string]$_.Publisher
                install_date = [string]$_.InstallDate; scope = $root.scope; arch = $root.arch
            }
        }
    })
}

$interfaces = Section 'interfaces' {
    $ips = @(Get-NetIPAddress -ErrorAction SilentlyContinue)
    ,@(Get-NetAdapter | ForEach-Object {
        $index = $_.ifIndex
        [ordered]@{
            name = $_.Name; description = $_.InterfaceDescription; mac = $_.MacAddress; status = [string]$_.Status
            virtual = [bool]$_.Virtual; hardware = [bool]$_.HardwareInterface; speed_bps = [int64]$_.ReceiveLinkSpeed
            ipv4 = @($ips | Where-Object { $_.InterfaceIndex -eq $index -and $_.AddressFamily -eq 'IPv4' } | ForEach-Object { $_.IPAddress })
            ipv6 = @($ips | Where-Object { $_.InterfaceIndex -eq $index -and $_.AddressFamily -eq 'IPv6' } | ForEach-Object { $_.IPAddress })
        }
    })
}

$listening = Section 'listening' {
    $names = @{}
    Get-Process | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
    $tcp = @(Get-NetTCPConnection -State Listen | ForEach-Object {
        [ordered]@{ protocol = 'tcp'; address = $_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; process = $names[[int]$_.OwningProcess] }
    })
    $udp = @(Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object {
        [ordered]@{ protocol = 'udp'; address = $_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; process = $names[[int]$_.OwningProcess] }
    })
    ,@($tcp + $udp)
}

$firewall = Section 'firewall' {
    ,@(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') } })
}
$defender = Section 'defender' {
    $mp = Get-MpComputerStatus
    [ordered]@{
        service_enabled = [bool]$mp.AMServiceEnabled; antivirus_enabled = [bool]$mp.AntivirusEnabled
        realtime_enabled = [bool]$mp.RealTimeProtectionEnabled; signature_age_days = [int]$mp.AntivirusSignatureAge
        signature_updated = (Iso $mp.AntivirusSignatureLastUpdated); product_version = [string]$mp.AMProductVersion
    }
}
$antivirus = Section 'antivirus_products' {
    ,@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object {
        [ordered]@{ name = [string]$_.displayName; product_state = [int]$_.productState }
    })
}
$bitlocker = $null
if ($isAdmin) {
    $bitlocker = Section 'bitlocker' {
        ,@(Get-BitLockerVolume | ForEach-Object {
            [ordered]@{ drive = $_.MountPoint; protection = [string]$_.ProtectionStatus; status = [string]$_.VolumeStatus }
        })
    }
}
$tpm = $null
if ($isAdmin) {
    $tpm = Section 'tpm' { $t = Get-Tpm; [ordered]@{ present = [bool]$t.TpmPresent; ready = [bool]$t.TpmReady } }
}
$smb1 = $null
if ($isAdmin) {
    $smb1 = Section 'smb1' { [bool](Get-SmbServerConfiguration).EnableSMB1Protocol }
}
$adminMembers = Section 'local_admins' { ,@(Get-LocalGroupMember -SID 'S-1-5-32-544') }
$localAdminCount = if ($null -eq $adminMembers) { $null } else { @($adminMembers).Count }
$localAdmins = $null
if ($IncludeAdminNames -and $null -ne $adminMembers) {
    $localAdmins = @($adminMembers | ForEach-Object {
        [ordered]@{ name = [string]$_.Name; kind = [string]$_.ObjectClass; source = [string]$_.PrincipalSource }
    })
}

$secureBoot = RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
$enableLua  = RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
$denyRdp    = RegValue 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'

$result = [ordered]@{
    schema   = 1
    is_admin = $isAdmin
    options  = [ordered]@{ user_software = [bool]$IncludeUserSoftware; admin_names = [bool]$IncludeAdminNames }
    identity = [ordered]@{
        hostname     = $env:COMPUTERNAME
        dns_hostname = $cs.DNSHostName
        domain       = $cs.Domain
        part_of_domain = [bool]$cs.PartOfDomain
        workgroup    = $cs.Workgroup
        machine_guid = (RegValue 'HKLM:\SOFTWARE\Microsoft\Cryptography' 'MachineGuid')
        smbios_uuid  = $csp.UUID
        serial_number = $bios.SerialNumber
    }
    hardware = [ordered]@{
        manufacturer   = $cs.Manufacturer
        model          = $cs.Model
        system_type    = [int]$cs.PCSystemType
        chassis_types  = @($encl.ChassisTypes)
        memory_bytes   = [int64]$cs.TotalPhysicalMemory
        cpus           = $cpus
        disks          = $disks
        volumes        = $volumes
        bios = [ordered]@{ vendor = $bios.Manufacturer; version = $bios.SMBIOSBIOSVersion; release_date = (Iso $bios.ReleaseDate) }
    }
    os = [ordered]@{
        name          = $os.Caption
        version       = $os.Version
        build         = $os.BuildNumber
        ubr           = $cv.UBR
        display_version = $cv.DisplayVersion
        edition       = $cv.EditionID
        architecture  = $os.OSArchitecture
        product_type  = [int]$os.ProductType
        install_date  = (Iso $os.InstallDate)
        last_boot     = (Iso $os.LastBootUpTime)
    }
    patches = [ordered]@{ hotfixes = $hotfixes; pending_reboot = $pendingReboot }
    security = [ordered]@{
        firewall           = $firewall
        defender           = $defender
        antivirus_products = $antivirus
        bitlocker          = $bitlocker
        tpm                = $tpm
        secure_boot        = $(if ($null -eq $secureBoot) { $null } else { [bool]$secureBoot })
        uac_enabled        = $(if ($null -eq $enableLua) { $null } else { [bool]$enableLua })
        rdp_enabled        = $(if ($null -eq $denyRdp) { $null } else { -not [bool]$denyRdp })
        smb1_enabled       = $smb1
        local_admins       = $localAdmins
        local_admin_count  = $localAdminCount
    }
    network  = [ordered]@{ interfaces = $interfaces; listening = $listening }
    software = $software
    errors   = @($errors)
}
$result | ConvertTo-Json -Depth 6 -Compress
