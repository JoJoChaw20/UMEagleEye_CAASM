from __future__ import annotations

import ipaddress

import pytest

from eagleeye.pipeline import PipelineContext
from eagleeye.stages import scan_nmap
from eagleeye.stages.scan_nmap import (
    NmapScanStage, hosts_from_scanner, parse_arp_table, validate_target,
)


# ── parsing ──
def test_hosts_from_recorded_xml(scanner):
    hosts = {h.ip: h for h in hosts_from_scanner(scanner)}
    assert set(hosts) == {"192.168.1.10", "192.168.1.50", "172.17.0.5", "172.17.0.6", "192.168.1.77"}   # 'down' host skipped

    linux = hosts["192.168.1.10"]
    assert linux.hostname == "server-01.lan"
    assert linux.mac == "AA:BB:CC:44:55:66"
    assert [p["port"] for p in linux.ports] == [22, 80, 443]          # closed 3306 excluded
    ssh = linux.ports[0]
    assert (ssh["service"], ssh["product"]) == ("ssh", "OpenSSH")
    assert ssh["banner"].startswith("SSH-2.0-OpenSSH")
    assert linux.os == {"name": "Linux 5.4", "accuracy": "95"}        # osmatch fallback

    windows = hosts["192.168.1.50"]
    assert windows.os["name"].startswith("Windows 10 Pro")            # SMB wins over osmatch
    assert windows.os["smb_domain"] == "lan"
    assert windows.hostname == "DESKTOP-ABC123"                       # SMB name beats reverse DNS

    docker = hosts["172.17.0.5"]
    assert docker.hostname is None                                    # docker-internal DNS ignored
    assert docker.os is None
    assert hosts["172.17.0.6"].hostname is None                       # name starting with "docker" ignored
    assert len(hosts["172.17.0.6"].ports[0]["banner"]) == 200         # long banner truncated

    quiet = hosts["192.168.1.77"]
    assert quiet.ports == [] and quiet.mac == "6E:DC:C8:20:6C:E8"


# ── target validation ──
@pytest.mark.parametrize("value", ["192.168.1.0/24", "10.0.0.5", " 172.16.0.0/16 ", "192.168.1.5/24"])
def test_valid_targets(value):
    assert validate_target(value) == value.strip()


@pytest.mark.parametrize("value", [
    "", "example.com", "192.168.1.0/24; calc", "-sS 10.0.0.1", "192.168.1.0/24 --script x",
    "10.0.0.0/8", "::1", "192.168.1.1-50", "192.168.1.0/33",
])
def test_rejected_targets(value):
    with pytest.raises(ValueError):
        validate_target(value)


def test_builtin_sweep_size_limit():
    validate_target("192.168.0.0/22", max_hosts=1024)
    with pytest.raises(ValueError, match="built-in sweep"):
        validate_target("192.168.0.0/21", max_hosts=1024)


# ── ARP cache parsing ──
WINDOWS_ARP = """
Interface: 192.168.1.20 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.77          6e-dc-c8-20-6c-e8     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  10.9.9.9              aa-bb-cc-dd-ee-99     dynamic
"""
LINUX_ARP = """? (192.168.1.1) at aa:bb:cc:dd:ee:01 [ether] on eth0
? (192.168.1.30) at <incomplete> on eth0
? (192.168.1.31) at 0:1:2:3:4:5 on en0 ifscope [ethernet]
"""


def test_parse_windows_arp():
    net = ipaddress.ip_network("192.168.1.0/24")
    assert parse_arp_table(WINDOWS_ARP, net) == {
        "192.168.1.1": "AA:BB:CC:DD:EE:01",
        "192.168.1.77": "6E:DC:C8:20:6C:E8",
    }


def test_parse_unix_arp_pads_macs_and_skips_incomplete():
    net = ipaddress.ip_network("192.168.1.0/24")
    assert parse_arp_table(LINUX_ARP, net) == {
        "192.168.1.1": "AA:BB:CC:DD:EE:01",
        "192.168.1.31": "00:01:02:03:04:05",
    }


# ── the stage ──
def test_stage_uses_builtin_sweep_when_nmap_missing(monkeypatch):
    monkeypatch.setattr(scan_nmap.deps, "find_nmap", lambda: None)
    sentinel = [scan_nmap.HostRecord(ip="192.168.1.5")]
    monkeypatch.setattr(scan_nmap, "builtin_sweep", lambda *a, **k: sentinel)
    ctx = PipelineContext("active", subnet="192.168.1.0/24")
    NmapScanStage("192.168.1.0/24").run(ctx)
    assert ctx.hosts == sentinel
    assert ctx.summary["scanner"] == "builtin"


def test_stage_uses_nmap_when_present(monkeypatch, fake_nmap):
    monkeypatch.setattr(scan_nmap.deps, "find_nmap", lambda: "C:/nmap.exe")
    ctx = PipelineContext("active", subnet="192.168.1.0/24")
    NmapScanStage("192.168.1.0/24").run(ctx)
    assert len(ctx.hosts) == 5
    assert ctx.summary["scanner"] == "nmap"


def test_stage_rejects_bad_target_before_running_anything(monkeypatch):
    monkeypatch.setattr(scan_nmap.deps, "find_nmap", lambda: "C:/nmap.exe")
    called = []
    monkeypatch.setattr(scan_nmap, "run_nmap", lambda *a: called.append(a))
    with pytest.raises(ValueError):
        NmapScanStage("192.168.1.0/24; calc").run(PipelineContext("active"))
    assert not called
