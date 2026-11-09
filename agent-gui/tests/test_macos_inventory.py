"""macOS collector, launchd daemon and macOS network readers against recorded output (no Mac in
the lab: the output below is what the commands print on an Apple silicon MacBook Pro running
macOS Sonoma 14.5, with FileVault on, the application firewall off, Screen Sharing on and
Homebrew installed; identifiers are synthetic)."""

from __future__ import annotations

import json
import plistlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from eagleeye.collectors import macos
from eagleeye.collectors.macos import (
    build_inventory, parse_boottime, parse_hardware_ports, parse_ifconfig, parse_ioreg_platform, parse_lsof,
    parse_sw_vers, publisher_of,
)
from eagleeye.engine.presence import parse_arp_an
from eagleeye.passive.adapters import darwin_adapters, parse_netstat_default
from eagleeye.serviceinstall import launchd_job, launchd_label

NOW = datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc)

IOREG = '''+-o MacBookPro18,3  <class IOPlatformExpertDevice, id 0x100000213, registered, matched, active, busy 0 (2 ms), retain 39>
    {
      "IOPlatformSystemSleepPolicy" = <534c505402000a00>
      "IOPlatformSerialNumber" = "C02XK1ABCDEF"
      "IOPlatformUUID" = "6D3E2C1A-1B2C-4D5E-8F90-0123456789AB"
      "model" = <"MacBookPro18,3">
    }
'''
SW_VERS = "ProductName:\t\tmacOS\nProductVersion:\t\t14.5\nBuildVersion:\t\t23F79\n"
HARDWARE = json.dumps({"SPHardwareDataType": [{
    "_name": "hardware_overview", "boot_rom_version": "10151.121.1", "chip_type": "Apple M1 Pro",
    "machine_model": "MacBookPro18,3", "machine_name": "MacBook Pro", "model_number": "MKGR3LL/A",
    "number_processors": "proc 8:6:2", "physical_memory": "16 GB", "platform_UUID": "6D3E2C1A-1B2C-4D5E-8F90-0123456789AB",
    "serial_number": "C02XK1ABCDEF"}]})
STORAGE = json.dumps({"SPStorageDataType": [
    {"_name": "Macintosh HD - Data", "bsd_name": "disk3s5", "mount_point": "/System/Volumes/Data", "size_in_bytes": 494384795648,
     "physical_drive": {"device_name": "APPLE SSD AP0512R", "is_internal_disk": "yes", "medium_type": "ssd"}},
    {"_name": "Macintosh HD", "bsd_name": "disk3s1s1", "mount_point": "/", "size_in_bytes": 494384795648,
     "physical_drive": {"device_name": "APPLE SSD AP0512R", "is_internal_disk": "yes", "medium_type": "ssd"}},
    {"_name": "Backup", "bsd_name": "disk5s1", "mount_point": "/Volumes/Backup", "size_in_bytes": 1000000000000,
     "physical_drive": {"device_name": "Samsung T7", "is_internal_disk": "no", "medium_type": "ssd"}}]})
APPS = json.dumps({"SPApplicationsDataType": [
    {"_name": "Google Chrome", "arch_kind": "arch_arm_i64", "lastModified": "2026-11-01T02:11:09Z", "obtained_from": "identified_developer",
     "path": "/Applications/Google Chrome.app", "signed_by": ["Developer ID Application: Google LLC (EQHXZ8M8AV)",
                                                               "Developer ID Certification Authority", "Apple Root CA"], "version": "130.0.6723.117"},
    {"_name": "Safari", "arch_kind": "arch_arm_i64", "obtained_from": "apple", "path": "/Applications/Safari.app",
     "signed_by": ["Software Signing", "Apple Code Signing Certification Authority", "Apple Root CA"], "version": "17.5"},
    {"_name": "Calculator", "obtained_from": "apple", "path": "/System/Applications/Calculator.app", "version": "11.0"},
    {"_name": "Zoom", "obtained_from": "identified_developer", "path": "/Users/alice/Applications/zoom.us.app",
     "signed_by": ["Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)"], "version": "6.2.5"},
    {"_name": "Microsoft Defender", "obtained_from": "identified_developer", "path": "/Applications/Microsoft Defender.app",
     "signed_by": ["Developer ID Application: Microsoft Corporation (UBF8T346G9)"], "version": "101.24092.0004"}]})
IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
\tether 3c:22:fb:12:34:56
\tinet6 fe80::1c2b:3d4e:5f60:7182%en0 prefixlen 64 secured scopeid 0xb
\tinet 192.168.0.142 netmask 0xffffff00 broadcast 192.168.0.255
\tnd6 options=201<PERFORMNUD,DAD>
\tmedia: autoselect
\tstatus: active
en1: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
\toptions=460<TSO4,TSO6,CHANNEL_IO>
\tether 36:8d:1a:00:aa:01
\tmedia: autoselect <full-duplex>
\tstatus: inactive
bridge0: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tether 36:8d:1a:00:aa:00
\tstatus: inactive
awdl0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 9a:1b:2c:3d:4e:5f
\tinet6 fe80::981b:2cff:fe3d:4e5f%awdl0 prefixlen 64 scopeid 0xd
\tstatus: active
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet6 fe80::2a1b:3c4d:5e6f:7081%utun0 prefixlen 64 scopeid 0xf
"""
HARDWARE_PORTS = """
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 3c:22:fb:12:34:56

Hardware Port: Thunderbolt 1
Device: en1
Ethernet Address: 36:8d:1a:00:aa:01

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:8d:1a:00:aa:00

VLAN Configurations
===================
"""
NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.0.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0
192.168.0          link#11            UCS                   en0      !
192.168.0.1/32     link#11            UCS                   en0      !
"""
LSOF_TCP = "p1\nclaunchd\nPTCP\nn*:5900\nPTCP\nn*:22\np512\ncrapportd\nPTCP\nn127.0.0.1:631\np701\ncnode\nPTCP\nn*:3000\n"
LSOF_UDP = "p320\ncmDNSResponder\nPUDP\nn*:5353\np801\ncControlCenter\nPUDP\nn192.168.0.142:51515->17.248.1.1:443\n"
ARP_AN = """? (192.168.0.1) at a4:2b:b0:12:34:56 on en0 ifscope [ethernet]
? (192.168.0.120) at (incomplete) on en0 ifscope [ethernet]
? (192.168.0.157) at 2:11:22:33:44:5 on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""
HISTORY = plistlib.dumps([
    {"date": datetime(2026, 5, 20, 9, 0), "displayName": "macOS Sonoma 14.5", "displayVersion": "14.5", "processName": "softwareupdated"},
    {"date": datetime(2026, 11, 2, 9, 0), "displayName": "XProtectPlistConfigData", "displayVersion": "5277", "processName": "softwareupdated"},
    {"date": datetime(2026, 11, 5, 9, 0), "displayName": "MRTConfigData", "displayVersion": "1.93", "processName": "softwareupdated"},
    {"date": datetime(2026, 3, 1, 9, 0), "displayName": "macOS Sonoma 14.4", "displayVersion": "14.4", "processName": "softwareupdated"},
    {"date": datetime(2026, 10, 1, 9, 0), "displayName": "Google Chrome", "processName": "installer"},
])


class FakeMac(macos.System):
    def __init__(self, root: bool = True, files: Optional[dict[str, bytes]] = None) -> None:
        self.is_root = root
        self.commands = {
            "ioreg -rd1 -c IOPlatformExpertDevice": IOREG,
            "scutil --get LocalHostName": "Alices-MacBook-Pro\n",
            "sw_vers": SW_VERS,
            "sysctl -n kern.boottime": "{ sec = 1762570800, usec = 0 } Sat Nov  8 03:00:00 2026\n",
            "sysctl -n hw.physicalcpu": "8\n", "sysctl -n hw.logicalcpu": "8\n", "sysctl -n hw.memsize": "17179869184\n",
            "system_profiler SPHardwareDataType -json": HARDWARE, "system_profiler SPStorageDataType -json": STORAGE,
            "system_profiler SPApplicationsDataType -json -detailLevel mini": APPS,
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate": "Firewall is disabled. (State = 0)\n",
            "fdesetup status": "FileVault is On.\n",
            "dscl . -read /Groups/admin GroupMembership": "GroupMembership: root alice it-admin\n",
            "networksetup -listallhardwareports": HARDWARE_PORTS, "ifconfig -a": IFCONFIG,
            "lsof -nP -iTCP -sTCP:LISTEN -F pcPn": LSOF_TCP, "lsof -nP -iUDP -F pcPn": LSOF_UDP,
        }
        self.files = {"/Library/Receipts/InstallHistory.plist": HISTORY,
                      "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist":
                          plistlib.dumps({"CFBundleShortVersionString": "5277"}), **(files or {})}
        self.dirs = {"/Applications": ["Google Chrome.app", "Microsoft Defender.app", "Safari.app"],
                     "/opt/homebrew/Cellar": ["nmap", "python@3.12"],
                     "/opt/homebrew/Cellar/nmap": ["7.95"], "/opt/homebrew/Cellar/python@3.12": ["3.12.6", "3.12.7"]}

    def run(self, argv: list[str], timeout: int = 60) -> Optional[str]:
        return self.commands.get(" ".join(argv))

    def read_bytes(self, path: str) -> Optional[bytes]:
        return self.files.get(path)

    def exists(self, path: str) -> bool:
        return path in self.files or path in self.dirs

    def listdir(self, path: str) -> list[str]:
        return self.dirs.get(path, [])

    def stat_mtime(self, path: str) -> Optional[float]:
        return datetime(2024, 1, 15, tzinfo=timezone.utc).timestamp() if path == "/var/db/.AppleSetupDone" else None

    def hostname(self) -> str:
        return "Alices-MacBook-Pro.local"

    def fqdn(self) -> str:
        return "Alices-MacBook-Pro.local"

    def machine(self) -> str:
        return "arm64"

    def now(self) -> datetime:
        return NOW

    def primary_ip(self) -> Optional[str]:
        return "192.168.0.142"


def test_parsers():
    assert parse_ioreg_platform(IOREG)["IOPlatformUUID"] == "6D3E2C1A-1B2C-4D5E-8F90-0123456789AB"
    assert parse_sw_vers(SW_VERS) == {"ProductName": "macOS", "ProductVersion": "14.5", "BuildVersion": "23F79"}
    assert parse_boottime("{ sec = 1762570800, usec = 0 } Sat Nov  8") == datetime(2025, 11, 8, 3, 0, tzinfo=timezone.utc)
    assert parse_hardware_ports(HARDWARE_PORTS) == {"en0": "Wi-Fi", "en1": "Thunderbolt 1", "bridge0": "Thunderbolt Bridge"}
    nics = {n["name"]: n for n in parse_ifconfig(IFCONFIG)}
    assert nics["en0"]["ipv4"] == ["192.168.0.142"] and nics["en0"]["prefixes"] == {"192.168.0.142": 24}
    assert nics["en0"]["mac"] == "3c:22:fb:12:34:56" and nics["en0"]["active"] is True and nics["en1"]["active"] is False
    assert nics["lo0"]["prefixes"] == {"127.0.0.1": 8} and nics["utun0"]["ipv6"] == ["fe80::2a1b:3c4d:5e6f:7081"]
    socks = parse_lsof(LSOF_TCP + LSOF_UDP)
    assert {(s["protocol"], s["address"], s["port"], s["process"]) for s in socks} == {
        ("tcp", "0.0.0.0", 5900, "launchd"), ("tcp", "0.0.0.0", 22, "launchd"), ("tcp", "127.0.0.1", 631, "rapportd"),
        ("tcp", "0.0.0.0", 3000, "node"), ("udp", "0.0.0.0", 5353, "mDNSResponder")}      # a connected UDP socket is not listening
    assert publisher_of({"signed_by": ["Developer ID Application: Google LLC (EQHXZ8M8AV)"]}) == "Google LLC"
    assert publisher_of({"obtained_from": "apple", "signed_by": ["Software Signing"]}) == "Apple Inc."
    assert publisher_of({"obtained_from": "mac_app_store", "signed_by": ["Apple Mac OS Application Signing"]}) is None


def test_inventory_of_a_macbook():
    inv = build_inventory(FakeMac(), user_software=False, admin_names=True)
    assert inv["platform"] == "darwin" and inv["errors"] == [] and inv["unavailable"] == []
    assert inv["identity"]["hostname"] == "Alices-MacBook-Pro"
    assert inv["identity"]["smbios_uuid"] == "6D3E2C1A-1B2C-4D5E-8F90-0123456789AB"
    assert inv["identity"]["serial_number"] == "C02XK1ABCDEF"
    hw = inv["hardware"]
    assert (hw["manufacturer"], hw["model"], hw["form_factor"]) == ("Apple Inc.", "MacBook Pro (MacBookPro18,3)", "laptop")
    assert hw["memory_bytes"] == 17179869184 and hw["cpus"] == [{"name": "Apple M1 Pro", "cores": 8, "threads": 8}]
    assert hw["disks"] == [{"model": "APPLE SSD AP0512R", "size_bytes": 494384795648, "media": "SSD"}]    # not the USB drive
    osd = inv["os"]
    assert (osd["name"], osd["version"], osd["build"], osd["role"]) == ("macOS Sonoma 14.5", "14.5", "23F79", "workstation")
    assert osd["last_boot"] == "2025-11-08T03:00:00+00:00"
    p = inv["patches"]
    # Only macOS updates count (not the XProtect/MRT data files 4 days ago, not apps)
    assert (p["hotfix_count"], p["last_patch_id"], p["days_since_last_patch"]) == (2, "macOS Sonoma 14.5", 173)
    s = inv["security"]
    assert s["firewall"] == [{"profile": "Application Firewall", "enabled": False}] and s["firewall_all_enabled"] is False
    assert s["antivirus"] == [{"name": "XProtect 5277", "enabled": True, "up_to_date": True},
                              {"name": "Microsoft Defender", "enabled": None, "up_to_date": None}]
    assert s["disk_encryption"] == [{"volume": "/", "protection": "on"}]
    assert s["rdp_enabled"] is True                       # Screen Sharing listens on 5900
    assert (s["tpm"], s["secure_boot"], s["uac_enabled"], s["smb1_enabled"]) == (None, None, None, None)
    assert s["local_admins"] == [{"name": "alice"}, {"name": "it-admin"}] and s["local_admin_count"] == 2
    nics = {n["name"]: n for n in inv["network"]["interfaces"]}
    assert nics["en0"]["physical"] and nics["en0"]["description"] == "Wi-Fi" and nics["en0"]["status"] == "Up"
    assert nics["en1"]["physical"] and nics["en1"]["status"] == "Down"
    assert all(nics[n]["virtual"] for n in ("lo0", "bridge0", "awdl0", "utun0"))
    assert inv["network"]["primary_ip"] == "192.168.0.142"
    assert {(e["port"], e["local_only"]) for e in inv["network"]["listening"] if e["protocol"] == "tcp"} == {
        (22, False), (631, True), (3000, False), (5900, False)}
    names = {(a["name"], a["version"], a["publisher"], a["scope"]) for a in inv["software"]}
    assert ("Google Chrome", "130.0.6723.117", "Google LLC", "machine") in names
    assert ("Safari", "17.5", "Apple Inc.", "machine") in names
    assert ("nmap", "7.95", "Homebrew", "machine") in names and ("python@3.12", "3.12.7", "Homebrew", "machine") in names
    assert not any(a["name"] in ("Calculator", "Zoom") for a in inv["software"])    # macOS's own; a user's (opt-in)
    assert any(a["name"] == "Zoom" for a in build_inventory(FakeMac(), user_software=True)["software"])


def test_unprivileged_and_old_xprotect():
    old = plistlib.dumps([{"date": datetime(2026, 6, 1), "displayName": "XProtectPayloads", "processName": "softwareupdated"}])
    inv = build_inventory(FakeMac(root=False, files={"/Library/Receipts/InstallHistory.plist": old}))
    assert inv["unavailable"] == ["listening_other_users"] and inv["is_admin"] is False
    assert inv["security"]["antivirus"][0]["up_to_date"] is False
    assert inv["patches"]["days_since_last_patch"] is None          # no macOS update on record


def test_network_readers():
    assert parse_netstat_default(NETSTAT) == {"en0": "192.168.0.1"}
    adapters = {a["name"]: a for a in darwin_adapters(IFCONFIG, NETSTAT, index={"en0": 11, "lo0": 1}.get)}
    assert adapters["en0"]["ips"] == ["192.168.0.142"] and adapters["en0"]["prefixes"] == {"192.168.0.142": 24}
    assert adapters["en0"]["gateway"] == "192.168.0.1" and adapters["en0"]["index"] == 11
    assert adapters["en0"]["mac"] == "3c:22:fb:12:34:56"
    assert parse_arp_an(ARP_AN) == {"192.168.0.1": "A4:2B:B0:12:34:56", "192.168.0.157": "02:11:22:33:44:05",
                                    "224.0.0.251": "01:00:5E:00:00:FB"}


def test_launchd_daemon():
    job = launchd_job("", ["/opt/eagleeye/.venv/bin/python", "-m", "eagleeye", "service", "run"], "/opt/eagleeye",
                      Path("/Library/Application Support/EagleEye/logs"))
    assert job["Label"] == launchd_label() == "com.umeagleeye.agent"
    assert job["KeepAlive"] == {"SuccessfulExit": False} and job["RunAtLoad"] is True
    assert job["EnvironmentVariables"] == {"PYTHONPATH": "/opt/eagleeye"}
    assert plistlib.loads(plistlib.dumps(job))["ProgramArguments"][-1] == "run"
    assert launchd_label("lab") == "com.umeagleeye.agent-lab"
