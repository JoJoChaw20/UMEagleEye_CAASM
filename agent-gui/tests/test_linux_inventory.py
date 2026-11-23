"""Linux collector against a recorded system: an Ubuntu 26.04 server VM on VMware (the
Phase C3 test VM: LVM without LUKS, ufw installed but off, snapd, no desktop). Files and
command output are replayed through a fake System; identifiers are synthetic."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from eagleeye.collectors import linux
from eagleeye.collectors.linux import (
    build_inventory, parse_apt_history, parse_cpuinfo, parse_dnf_rpm_log, parse_os_release, parse_ss,
)

NOW = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)

OS_RELEASE = '''PRETTY_NAME="Ubuntu 26.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
VERSION="26.04.1 LTS (Resolute Raccoon)"
ID=ubuntu
'''
CPUINFO = "\n\n".join(
    f"processor\t: {i}\nphysical id\t: 0\ncore id\t\t: {i}\ncpu cores\t: 2\nmodel name\t: Intel(R) Core(TM) i7-1165G7 @ 2.80GHz"
    for i in range(2))
APT_HISTORY = """Start-Date: 2026-09-20  08:00:01
Commandline: apt install nmap
Install: nmap:amd64 (7.95)
End-Date: 2026-09-20  08:00:09

Start-Date: 2026-10-01  03:10:00
Commandline: /usr/bin/unattended-upgrade
Upgrade: libc6:amd64 (2.41-1, 2.41-2)
End-Date: 2026-10-01  03:12:00
"""
SS = """udp   UNCONN 0      0          127.0.0.54:53        0.0.0.0:*    users:(("systemd-resolve",pid=612,fd=16))
udp   UNCONN 0      0             0.0.0.0:161       0.0.0.0:*    users:(("snmpd",pid=901,fd=6))
tcp   LISTEN 0      4096    127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=612,fd=15))
tcp   LISTEN 0      4096          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=1001,fd=3))
tcp   LISTEN 0      4096             [::]:22           [::]:*    users:(("sshd",pid=1001,fd=4))
tcp   ESTAB  0      0      192.168.150.128:22 192.168.150.1:51515 users:(("sshd",pid=2000,fd=4))"""
LSBLK_DISKS = json.dumps({"blockdevices": [
    {"name": "loop0", "size": 75000000, "model": None, "rota": False, "type": "loop"},
    {"name": "sda", "size": 21474836480, "model": "VMware Virtual S", "rota": True, "type": "disk"},
    {"name": "sr0", "size": 3000000000, "model": "VMware SATA CD01", "rota": True, "type": "rom"}]})
LSBLK_TREE = json.dumps({"blockdevices": [
    {"name": "loop0", "type": "loop", "mountpoints": ["/snap/core24/2124"]},
    {"name": "sda", "type": "disk", "mountpoints": [None], "children": [
        {"name": "sda1", "type": "part", "mountpoints": [None]},
        {"name": "sda2", "type": "part", "mountpoints": ["/boot"]},
        {"name": "sda3", "type": "part", "mountpoints": [None], "children": [
            {"name": "ubuntu--vg-ubuntu--lv", "type": "lvm", "mountpoints": ["/"]}]}]},
    {"name": "sr0", "type": "rom", "mountpoints": [None]}]})
IP_ADDR = json.dumps([
    {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
    {"ifname": "ens33", "addr_info": [{"family": "inet", "local": "192.168.150.128"}, {"family": "inet6", "local": "fe80::20c:29ff:fe11:2233"}]},
    {"ifname": "ens37", "addr_info": [{"family": "inet", "local": "192.168.80.130"}]},
    {"ifname": "docker0", "addr_info": [{"family": "inet", "local": "172.17.0.1"}]}])
DPKG = ("openssh-server\t1:9.9p1-3ubuntu1\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\tamd64\tinstalled\n"
        "snmpd\t5.9.4+dfsg-2\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\tamd64\tinstalled\n"
        "oldpkg\t1.0\tSomeone <a@b>\tamd64\tconfig-files\n")
SNAP = "Name    Version   Rev    Tracking       Publisher   Notes\ncore24  20250901  1643   latest/stable  canonical✓  base\n"


class FakeSystem(linux.System):
    def __init__(self, root: bool = True, files=None, commands=None, dirs=None, exists=None, tools=None):
        self.is_root = root
        self.files = {
            "/etc/os-release": OS_RELEASE, "/proc/cpuinfo": CPUINFO, "/proc/meminfo": "MemTotal:        2010000 kB\n",
            "/proc/uptime": "3600.5 7000.0\n", "/etc/machine-id": "0123456789abcdef0123456789abcdef\n",
            f"{linux.DMI}/sys_vendor": "VMware, Inc.\n", f"{linux.DMI}/product_name": "VMware Virtual Platform\n",
            f"{linux.DMI}/chassis_type": "1\n", f"{linux.DMI}/bios_vendor": "VMware, Inc.\n", f"{linux.DMI}/bios_version": "6.00\n",
            "/var/log/apt/history.log": APT_HISTORY, "/etc/ufw/ufw.conf": "# /etc/ufw/ufw.conf\nENABLED=no\nLOGLEVEL=low\n",
            "/etc/group": "root:x:0:\nsudo:x:27:user,ops\nadm:x:4:syslog,user\n",
            "/sys/class/net/lo/address": "00:00:00:00:00:00\n", "/sys/class/net/lo/operstate": "unknown\n",
            "/sys/class/net/ens33/address": "00:0c:29:11:22:33\n", "/sys/class/net/ens33/operstate": "up\n", "/sys/class/net/ens33/speed": "1000\n",
            "/sys/class/net/ens37/address": "00:0c:29:11:22:3d\n", "/sys/class/net/ens37/operstate": "up\n",
            "/sys/class/net/docker0/address": "02:42:ac:11:00:01\n", "/sys/class/net/docker0/operstate": "down\n",
        }
        if root:
            self.files[f"{linux.DMI}/product_uuid"] = "6f1d2a90-3c55-4b8e-9d0a-1b2c3d4e5f60\n"
            self.files[f"{linux.DMI}/product_serial"] = "VMware-56 4d d6 98 9a 35 09 9c-b4 bb 2e 97 3f 04 6c 77\n"
        self.files.update(files or {})
        self.commands = {
            ("lsblk", "-J", "-b", "-d", "-o", "NAME,SIZE,MODEL,ROTA,TYPE"): LSBLK_DISKS,
            ("lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINTS"): LSBLK_TREE,
            ("ip", "-j", "addr"): IP_ADDR, ("ss", "-H", "-tulnp"): SS,
            # Ubuntu Server boots graphical.target although no desktop is installed (seen on the test VM).
            ("systemctl", "get-default"): "graphical.target\n",
            ("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\t${Architecture}\t${db:Status-Status}\n"): DPKG,
            ("snap", "list"): SNAP, ("nft", "list", "ruleset"): "table inet filter {\n}\n",
        }
        self.commands.update(commands or {})
        self.dirs = {"/var/log/apt": ["history.log"], "/sys/class/net": ["docker0", "ens33", "ens37", "lo"]}
        self.dirs.update(dirs or {})
        self.extra_exists = set(exists or ()) | {"/sys/class/net/ens33/device", "/sys/class/net/ens37/device", "/var/log/apt/history.log"}
        self.tools = set(tools or ()) | {"lsblk", "ip", "ss", "systemctl", "dpkg-query", "snap", "nft", "ufw"}

    def read(self, path):
        return self.files.get(path)

    def read_bytes(self, path):
        v = self.files.get(path)
        return v if isinstance(v, bytes) else None

    def exists(self, path):
        return path in self.files or path in self.extra_exists or path in self.dirs

    def listdir(self, path):
        return list(self.dirs.get(path, []))

    def which(self, tool):
        return tool in self.tools

    def run(self, argv, timeout=60):
        return self.commands.get(tuple(argv)) if argv[0] in self.tools else None

    def stat_mtime(self, path):
        return datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp() if path == "/var/log/installer" else None

    def stat_mode(self, path):
        return {"/etc/shadow": (0o640, 0, 42), "/boot/grub/grub.cfg": (0o600, 0, 0)}.get(path)

    def hostname(self):
        return "umeagleeye"

    def fqdn(self):
        return "umeagleeye"

    def machine(self):
        return "x86_64"

    def kernel(self):
        return "7.0.0-15-generic"

    def now(self):
        return NOW

    def primary_ip(self):
        return "192.168.150.128"


def inv(**kw):
    return build_inventory(FakeSystem(**kw))


def test_identity_and_hardware_from_sysfs():
    doc = inv()
    assert doc["platform"] == "linux" and doc["schema"] == 1 and doc["is_admin"] is True
    assert doc["identity"]["machine_id"] == "0123456789abcdef0123456789abcdef"
    assert doc["identity"]["smbios_uuid"] == "6f1d2a90-3c55-4b8e-9d0a-1b2c3d4e5f60"
    assert doc["identity"]["hostname"] == "umeagleeye" and doc["identity"]["domain"] is None
    hw = doc["hardware"]
    assert (hw["manufacturer"], hw["model"], hw["form_factor"]) == ("VMware, Inc.", "VMware Virtual Platform", "virtual")
    assert hw["memory_bytes"] == 2010000 * 1024
    assert hw["cpus"] == [{"name": "Intel(R) Core(TM) i7-1165G7 @ 2.80GHz", "cores": 2, "threads": 2}]
    assert hw["disks"] == [{"model": "VMware Virtual S", "size_bytes": 21474836480, "media": "HDD"}]
    assert doc["unavailable"] == [] and doc["errors"] == []


def test_without_root_the_uuid_is_reported_unavailable_not_guessed():
    doc = inv(root=False)
    assert doc["identity"]["smbios_uuid"] is None and doc["identity"]["serial_number"] is None
    assert doc["unavailable"] == ["hardware_uuid"] and doc["is_admin"] is False


def test_os_role_patches_and_reboot():
    doc = inv(exists={"/var/run/reboot-required"})
    assert doc["os"]["name"] == "Ubuntu 26.04.1 LTS" and doc["os"]["build"] == "7.0.0-15-generic"
    assert doc["os"]["role"] == "server"                          # no desktop session
    assert doc["os"]["last_boot"] == "2026-10-12T09:00:00+00:00"
    p = doc["patches"]
    assert (p["last_patch_id"], p["last_patch_date"], p["days_since_last_patch"]) == ("apt upgrade", "2026-10-01T03:10:00+00:00", 11)
    assert p["pending_reboot"] is True and p["hotfix_count"] == 1     # the 'Install:' run is not an update


def test_desktop_machine_is_a_workstation():
    assert inv(dirs={"/usr/share/wayland-sessions": ["ubuntu.desktop"]})["os"]["role"] == "workstation"
    assert inv(exists={"/etc/systemd/system/display-manager.service"})["os"]["role"] == "workstation"


def test_security_matches_the_test_vm():
    sec = inv()["security"]
    assert sec["firewall"] == [{"profile": "ufw", "enabled": False}, {"profile": "nftables", "enabled": False}]
    assert sec["firewall_all_enabled"] is False
    assert sec["disk_encryption"] == [{"volume": "/", "protection": "off"}]   # LVM without LUKS; /boot ignored
    assert sec["secure_boot"] is False                                     # no /sys/firmware/efi: BIOS boot
    assert sec["tpm"] == {"present": False, "ready": False}
    assert sec["uac_enabled"] is None and sec["smb1_enabled"] is False and sec["rdp_enabled"] is False
    assert sec["antivirus"] == [] and sec["local_admin_count"] == 2 and sec["local_admins"] == []


def test_luks_ufw_on_uefi_secure_boot_tpm():
    tree = json.dumps({"blockdevices": [{"name": "nvme0n1", "type": "disk", "mountpoints": [None], "children": [
        {"name": "nvme0n1p3", "type": "part", "mountpoints": [None], "children": [
            {"name": "dm_crypt-0", "type": "crypt", "mountpoints": [None], "children": [
                {"name": "ubuntu--vg-root", "type": "lvm", "mountpoints": ["/"]}]}]}]}]})
    sec = inv(files={"/etc/ufw/ufw.conf": "ENABLED=yes\n"}, commands={
        ("lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINTS"): tree, ("mokutil", "--sb-state"): "SecureBoot enabled\n"},
        exists={"/sys/firmware/efi", "/sys/class/tpm/tpm0"}, tools={"mokutil"})["security"]
    assert sec["firewall_all_enabled"] is True and sec["disk_encryption"] == [{"volume": "/", "protection": "on"}]
    assert sec["secure_boot"] is True and sec["tpm"] == {"present": True, "ready": True}


def test_admin_names_only_when_opted_in():
    doc = build_inventory(FakeSystem(), admin_names=True)
    assert doc["security"]["local_admins"] == [{"name": "ops"}, {"name": "user"}] and doc["privacy"]["admin_names"] is True


def test_interfaces_identity_grade_macs_only():
    nics = {n["name"]: n for n in inv()["network"]["interfaces"]}
    assert nics["ens33"]["physical"] and nics["ens33"]["mac"] == "00:0C:29:11:22:33" and nics["ens33"]["speed_bps"] == 1_000_000_000
    assert nics["ens33"]["ipv4"] == ["192.168.150.128"] and nics["ens37"]["physical"]
    assert not nics["lo"]["physical"] and not nics["docker0"]["physical"] and nics["docker0"]["virtual"]


def test_listening_ports_hide_local_only_owners():
    rows = inv()["network"]["listening"]
    assert [(r["protocol"], r["address"], r["port"]) for r in rows] == [
        ("tcp", "0.0.0.0", 22), ("tcp", "::", 22), ("tcp", "127.0.0.53", 53), ("udp", "127.0.0.54", 53), ("udp", "0.0.0.0", 161)]
    by = {(r["address"], r["port"]): r for r in rows}
    assert by[("0.0.0.0", 22)]["process"] == "sshd" and by[("0.0.0.0", 161)]["process"] == "snmpd"
    assert by[("127.0.0.53", 53)]["process"] is None and by[("127.0.0.53", 53)]["local_only"] is True


def test_software_from_dpkg_and_snap_without_email_addresses():
    sw = inv()["software"]
    assert [s["name"] for s in sw] == ["core24", "openssh-server", "snmpd"]          # config-files only: not installed
    assert sw[1]["publisher"] == "Ubuntu Developers" and sw[0]["publisher"] == "canonical"
    assert all("@" not in (s["publisher"] or "") for s in sw)


def test_rpm_systems():
    rpm = "bash\t5.2.26-3.el9\tRocky Enterprise Software Foundation\tx86_64\t1760000000\n"
    sw = inv(commands={("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\t${Architecture}\t${db:Status-Status}\n"): None,
                       ("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{ARCH}\t%{INSTALLTIME}\n"): rpm,
                       ("snap", "list"): None}, tools={"rpm"})["software"]
    assert sw == [{"name": "bash", "version": "5.2.26-3.el9", "publisher": "Rocky Enterprise Software Foundation",
                   "install_date": "2025-10-09", "scope": "machine", "arch": "x86_64"}]


def test_a_broken_section_is_reported_and_the_rest_survives(monkeypatch):
    monkeypatch.setattr(linux, "_software", lambda s: 1 / 0)
    doc = inv()
    assert doc["software"] == [] and doc["errors"] == ["software: division by zero"] and doc["identity"]["machine_id"]


def test_pure_parsers():
    assert parse_os_release(OS_RELEASE)["VERSION_ID"] == "26.04"
    assert parse_cpuinfo("") == []
    assert parse_apt_history([APT_HISTORY]) == [datetime(2026, 10, 1, 3, 10, tzinfo=timezone.utc)]
    assert parse_dnf_rpm_log("2026-10-05T09:00:00+0000 SUBDEBUG Upgraded: bash-5.2\n") == [datetime(2026, 10, 5, 9, 0, tzinfo=timezone.utc)]
    assert parse_ss("tcp LISTEN 0 128 *:8080 *:*") == [{"protocol": "tcp", "address": "0.0.0.0", "port": 8080, "process": None, "pid": None}]


def test_the_server_accepts_the_document_shape():
    """What the server's binding and posture read must be present and well-typed."""
    doc = inv()
    assert isinstance(doc["network"]["interfaces"], list) and all("physical" in n for n in doc["network"]["interfaces"])
    assert isinstance(doc["software"], list) and all(set(s) >= {"name", "version", "publisher"} for s in doc["software"])
    assert doc["os"]["role"] in ("server", "workstation") and len(doc["platform"]) <= 16
    json.dumps(doc)                                                    # serialisable as sent


def test_container_host_keeps_real_nics_within_the_server_limit():
    many = {f"veth{i:03d}": None for i in range(100)}
    files = {f"/sys/class/net/{n}/address": f"02:42:00:00:{i // 256:02x}:{i % 256:02x}\n" for i, n in enumerate(many)}
    doc = inv(files=files, dirs={"/sys/class/net": ["ens33", "lo", *many]})
    nics = doc["network"]["interfaces"]
    assert len(nics) == 64 and nics[0]["name"] == "ens33" and nics[0]["physical"]


def test_long_package_versions_are_trimmed_to_the_server_limit():
    long_version = "1:" + "9" * 150
    dpkg = f"weird\t{long_version}\tX <x@y>\tamd64\tinstalled\n"
    sw = inv(commands={("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\t${Architecture}\t${db:Status-Status}\n"): dpkg,
                       ("snap", "list"): None})["software"]
    assert len(sw[0]["version"]) == 100


def test_primary_ip_is_never_a_virtual_interface(monkeypatch):
    # Same rule as Windows (2.3.1): routed through docker0 before the network is up.
    assert inv()["network"]["primary_ip"] == "192.168.150.128"
    monkeypatch.setattr(FakeSystem, "primary_ip", lambda self: "172.17.0.1")
    assert inv()["network"]["primary_ip"] == "192.168.150.128"      # the first physical NIC instead


# ── security baseline facts (judged by the server, workers/src/lib/baseline.ts) ──
APT_SIM = """NOTE: This is only a simulation!
Inst libssl3t64 [3.5.0-1ubuntu1] (3.5.0-1ubuntu1.1 Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security [amd64])
Inst openssl [3.5.0-1ubuntu1] (3.5.0-1ubuntu1.1 Ubuntu:26.04/resolute-security [amd64])
Inst tzdata [2026a-1] (2026b-0ubuntu0.26.04 Ubuntu:26.04/resolute-updates [all])
Conf openssl (3.5.0-1ubuntu1.1 Ubuntu:26.04/resolute-security [amd64])
"""
HARDENED = {
    "/etc/pam.d/common-password": "password requisite pam_pwquality.so retry=3\npassword [success=1 default=ignore] pam_unix.so obscure yescrypt\n",
    "/etc/security/pwquality.conf": "# minlen = 8\nminlen = 14\n",
    "/etc/pam.d/common-auth": "auth required pam_faillock.so preauth\nauth [success=1 default=ignore] pam_unix.so\n",
    "/etc/security/faillock.conf": "deny = 5\nunlock_time = 900\n",
    "/etc/login.defs": "PASS_MAX_DAYS\t365\nPASS_MIN_DAYS\t1\n",
    "/etc/shadow": "root:!:20000:0:99999:7:::\nuser:$y$j9T$abc:20000:0:99999:7:::\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
    "/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
    "/etc/default/ufw": 'DEFAULT_INPUT_POLICY="DROP"\n', "/etc/ufw/ufw.conf": "ENABLED=yes\n",
    "/proc/sys/kernel/randomize_va_space": "2\n", "/proc/sys/net/ipv4/ip_forward": "0\n",
    "/proc/sys/net/ipv4/conf/all/accept_redirects": "0\n", "/proc/sys/net/ipv4/conf/default/accept_redirects": "0\n",
    "/sys/module/apparmor/parameters/enabled": "Y\n",
    "/sys/kernel/security/apparmor/profiles": "/usr/sbin/cupsd (enforce)\nsnap.lxd (complain)\n/usr/bin/man (enforce)\n",
}
SSHD_T = "port 22\npermitrootlogin no\npermitemptypasswords no\nmaxauthtries 4\n"


def test_baseline_facts_of_a_hardened_server():
    b = inv(files=HARDENED, exists=["/usr/sbin/sshd", "/usr/bin/unattended-upgrade"],
            dirs={"/etc/apt/apt.conf.d": ["20auto-upgrades"]},
            commands={("apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"): APT_SIM, ("sshd", "-T"): SSHD_T,
                      ("timedatectl", "show", "-p", "NTP", "--value"): "yes\n"},
            tools=["apt-get", "sshd", "timedatectl"])["baseline"]
    assert b["security_updates"] == 2 and b["auto_updates"] is True and b["uefi"] is False
    assert b["security_update_packages"] == [
        {"name": "libssl3t64", "installed": "3.5.0-1ubuntu1", "available": "3.5.0-1ubuntu1.1"},
        {"name": "openssl", "installed": "3.5.0-1ubuntu1", "available": "3.5.0-1ubuntu1.1"}]       # tzdata: -updates only
    assert b["password_quality"] == {"min_length": 14} and b["lockout"] == {"deny": 5} and b["pass_max_days"] == 365
    assert b["shadow"] == {"empty_passwords": 0, "root_locked": True} and b["uid0"] == ["root"]
    assert b["default_incoming"] == "deny"
    assert b["sshd"] == {"source": "sshd -T", "permitrootlogin": "no", "permitemptypasswords": "no", "maxauthtries": 4}
    assert (b["aslr"], b["ip_forward"], b["accept_redirects"]) == (2, 0, [0, 0])
    assert b["mac"] == {"apparmor": True, "apparmor_enforcing": 2, "selinux": None}
    assert b["bootloader_config"] == {"mode": 0o600, "uid": 0, "gid": 0} and b["shadow_file"] == {"mode": 0o640, "uid": 0, "gid": 42}
    assert b["time_sync"] is True and b["insecure_servers"] == [] and b["container_host"] is True   # docker0 in the recorded VM


def test_baseline_facts_of_a_default_install_without_root():
    b = inv(root=False, files={"/etc/login.defs": "PASS_MAX_DAYS\t99999\n",
                               "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n#PermitRootLogin prohibit-password\n",
                               "/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\nMaxAuthTries 3\n"},
            dirs={"/etc/ssh/sshd_config.d": ["50-cloud-init.conf"]}, exists=["/usr/sbin/sshd"])["baseline"]
    assert b["password_quality"] is None and b["lockout"] is None and b["pass_max_days"] == 99999
    assert b["shadow"] is None                                     # needs root: the server says so
    assert b["sshd"] == {"source": "config files", "permitrootlogin": "prohibit-password", "permitemptypasswords": "no", "maxauthtries": 3}
    assert b["default_incoming"] is None and b["security_updates"] is None


def test_debian_version_order_matches_dpkg():
    cmp = linux.deb_version_cmp
    assert cmp("1.25.0-2ubuntu4", "1.25.0-2ubuntu4.4") < 0                 # the wget test on the lab VM
    assert cmp("2:9.1.2141-1ubuntu4.10", "2:9.1.2141-1ubuntu4.9") > 0      # 10 > 9 as numbers, not text
    assert cmp("1.0~rc1", "1.0") < 0 and cmp("1.0", "1.0~rc1") > 0         # ~ sorts before the end
    assert cmp("1:1.0", "2.0") > 0                                          # the epoch wins
    assert cmp("1.0a", "1.0") > 0 and cmp("1.0+b1", "1.0") > 0 and cmp("1.0-1", "1.0-1") == 0
    assert cmp("3.4.1+ds1-7ubuntu0.3", "3.4.1+ds1-7") > 0


def test_a_security_fix_hidden_behind_a_newer_updates_version_is_found():
    # vim-tiny: installed 4.8; -security has 4.9, -updates 4.10, so apt-get names only -updates
    apt = ("Inst vim-tiny [2:9.1.2141-1ubuntu4.8] (2:9.1.2141-1ubuntu4.10 Ubuntu:26.04/resolute-updates [amd64]) []\n"
           "Inst tzdata [2026a-1] (2026b-0ubuntu0.26.04 Ubuntu:26.04/resolute-updates [all])\n")
    madison = (" vim-tiny | 2:9.1.2141-1ubuntu4.10 | http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 Packages\n"
               " vim-tiny | 2:9.1.2141-1ubuntu4.9 | http://security.ubuntu.com/ubuntu resolute-security/main amd64 Packages\n"
               " vim-tiny | 2:9.1.2141-1ubuntu4 | http://archive.ubuntu.com/ubuntu resolute/main amd64 Packages\n"
               "   tzdata | 2026b-0ubuntu0.26.04 | http://archive.ubuntu.com/ubuntu resolute-updates/main all Packages\n")
    b = inv(commands={("apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"): apt,
                      ("apt-cache", "madison", "vim-tiny", "tzdata"): madison}, tools=["apt-get", "apt-cache"])["baseline"]
    assert b["security_updates"] == 1
    assert b["security_update_packages"] == [{"name": "vim-tiny", "installed": "2:9.1.2141-1ubuntu4.8", "available": "2:9.1.2141-1ubuntu4.9"}]
    # installed already at the security version (the lab VM today): nothing waiting
    apt_now = apt.replace("ubuntu4.8]", "ubuntu4.9]")
    b = inv(commands={("apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"): apt_now,
                      ("apt-cache", "madison", "vim-tiny", "tzdata"): madison}, tools=["apt-get", "apt-cache"])["baseline"]
    assert b["security_updates"] == 0


def test_security_updates_on_rpm_systems():
    dnf = ("RHSA-2026:1234 Important/Sec.  openssl-libs-1:3.2.2-6.el9_5.1.x86_64\n"
           "RHBA-2026:2000 bugfix         tzdata-2026b-1.el9.noarch\n"
           "RHSA-2026:1300 Moderate/Sec.  curl-7.76.1-31.el9_6.x86_64\n")
    pk = linux.parse_security_updates(dnf_out=dnf)
    assert [p["name"] for p in pk] == ["openssl-libs-1:3.2.2-6.el9_5.1.x86_64", "curl-7.76.1-31.el9_6.x86_64"]
    assert pk[0]["advisory"] == "RHSA-2026:1234" and pk[0]["severity"] == "Important"
    assert linux.parse_security_updates() is None                  # could not ask: not "none waiting"


def test_aslr_in_the_sysctl_configuration_not_only_in_effect():
    assert inv()["baseline"]["aslr_configured"] is False                    # the running value alone (CIS fails it)
    files = {"/etc/sysctl.d/60-hardening.conf": "# CIS 1.5.9\nkernel.randomize_va_space = 2\n"}
    assert inv(files=files, dirs={"/etc/sysctl.d": ["60-hardening.conf"]})["baseline"]["aslr_configured"] is True
    later = {**files, "/etc/sysctl.d/99-local.conf": "kernel.randomize_va_space=0\n"}   # a later file wins
    assert inv(files=later, dirs={"/etc/sysctl.d": ["60-hardening.conf", "99-local.conf"]})["baseline"]["aslr_configured"] is False


def test_insecure_servers_come_from_the_package_list():
    dpkg = DPKG + "telnetd\t0.17-44\tUbuntu Developers <x@y>\tamd64\tinstalled\n"
    cmd = ("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\t${Architecture}\t${db:Status-Status}\n")
    assert inv(commands={cmd: dpkg})["baseline"]["insecure_servers"] == ["telnetd"]
