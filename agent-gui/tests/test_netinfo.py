"""The network this computer is on (subnet and gateway from the route table), the
network block sent with uploads, the offline MAC vendor lookup, and this computer's
own entry in an active scan (2.2.2)."""

from __future__ import annotations

import ipaddress

import pytest

from eagleeye import netinfo, vendor
from eagleeye.pipeline.record import HostRecord
from eagleeye.stages import scan_nmap


def ip(a: str) -> int:
    return int(ipaddress.IPv4Address(a))


def route(net: str, mask: str, gw: str, src: str, metric: int = 50) -> tuple:
    return (ip(net), ip(mask), gw, r"\Device\NPF_{X}", src, metric)


# Shaped like scapy's table on the campus Wi-Fi (a /19) with the GNS3 loopback adapter.
CAMPUS_ROUTES = [
    route("0.0.0.0", "0.0.0.0", "142.19.0.11", "142.19.0.1", 281),
    route("0.0.0.0", "0.0.0.0", "10.179.63.254", "10.179.37.235", 50),
    route("10.179.32.0", "255.255.224.0", "0.0.0.0", "10.179.37.235", 306),
    route("10.179.37.235", "255.255.255.255", "0.0.0.0", "10.179.37.235", 306),
    route("10.179.63.255", "255.255.255.255", "0.0.0.0", "10.179.37.235", 306),
    route("142.19.0.0", "255.255.254.0", "0.0.0.0", "142.19.0.1", 281),
    route("224.0.0.0", "240.0.0.0", "0.0.0.0", "10.179.37.235", 306),
]


def test_the_subnet_is_read_from_the_route_table_not_assumed_to_be_a_24():
    assert netinfo.network_of("10.179.37.235", CAMPUS_ROUTES) == ("10.179.32.0/19", "10.179.63.254")
    assert netinfo.network_of("142.19.0.1", CAMPUS_ROUTES) == ("142.19.0.0/23", "142.19.0.11")


def test_an_address_without_routes_has_no_network():
    assert netinfo.network_of("192.168.0.139", CAMPUS_ROUTES) == (None, None)
    assert netinfo.network_of("not an ip", CAMPUS_ROUTES) == (None, None)


def test_local_network_falls_back_to_the_24_around_the_address(monkeypatch):
    monkeypatch.setattr(netinfo, "_scapy_routes", lambda: [])
    assert netinfo.local_network("192.168.0.139") == {"local_ip": "192.168.0.139", "subnet": "192.168.0.0/24", "gateway_ip": None}


def test_passive_hosts_go_up_with_the_network_they_were_heard_on(monkeypatch):
    monkeypatch.setattr(netinfo, "default_gateway", lambda: "192.168.0.1")      # now at home
    monkeypatch.setattr(netinfo, "local_ip", lambda: "192.168.0.139")
    campus = {"local_ip": "10.179.37.235", "subnet": "10.179.32.0/19", "gateway_ip": "10.179.63.254"}
    hosts = [HostRecord(ip="10.179.63.254", mac="9c:09:71:3b:f6:01")]
    assert netinfo.build_network_info(None, hosts, campus) == {
        "subnet": "10.179.32.0/19", "lan_subnet": "10.179.32.0/19",
        "gateway_ip": "10.179.63.254", "gateway_mac": "9c:09:71:3b:f6:01"}
    # Gateway unknown for the old network: never borrow today's (it would flip the old router).
    assert netinfo.build_network_info(None, hosts, {**campus, "gateway_ip": None})["gateway_ip"] is None
    home = {"local_ip": "192.168.0.139", "subnet": "192.168.0.0/24", "gateway_ip": None}
    assert netinfo.build_network_info(None, [], home)["gateway_ip"] == "192.168.0.1"


@pytest.mark.parametrize("mac, expected", [
    ("7c:61:30:38:96:02", "Apple, Inc."),
    ("9C-B8-B4-B8-73-0A", "AMPAK Technology,Inc."),
    ("9c:09:71:3b:f6:01", "New H3C Technologies Co., Ltd"),
    ("0a:4d:41:f7:1d:2e", None),            # private (randomised): no vendor
    ("01:00:5e:7f:ff:fa", None),            # multicast
    (None, None),
    ("garbage", None),
])
def test_mac_vendor_is_looked_up_offline(mac, expected):
    pytest.importorskip("scapy.all")
    assert vendor.mac_vendor(mac) == expected


def test_private_macs_are_recognised():
    assert vendor.is_private_mac("ae:9a:84:6c:83:ac") and vendor.is_private_mac("02-C4-45-10-57-1F")
    assert not vendor.is_private_mac("7c:61:30:38:96:02") and not vendor.is_private_mac(None)


def test_the_upload_carries_the_vendor():
    pytest.importorskip("scapy.all")
    assert HostRecord(ip="192.168.0.190", mac="7c:61:30:38:96:02").to_payload()["mac_vendor"] == "Apple, Inc."
    assert HostRecord(ip="192.168.0.191", mac="ce:a7:68:c3:fd:5f").to_payload()["mac_vendor"] is None


def test_this_computer_gets_its_own_mac_and_name_in_an_active_scan(monkeypatch):
    monkeypatch.setattr(netinfo, "local_ip", lambda: "10.179.37.235")
    monkeypatch.setattr(netinfo, "own_mac", lambda ip: "14:13:33:c3:f6:03" if ip == "10.179.37.235" else None)
    monkeypatch.setattr(scan_nmap.socket, "gethostname", lambda: "LAPTOP-JOJO")
    hosts = [HostRecord(ip="10.179.37.199", mac="50:C2:E8:39:56:29"), HostRecord(ip="10.179.37.235")]
    scan_nmap.fill_own_host(hosts)
    assert (hosts[1].mac, hosts[1].hostname) == ("14:13:33:c3:f6:03", "LAPTOP-JOJO")
    assert (hosts[0].mac, hosts[0].hostname) == ("50:C2:E8:39:56:29", None)


def test_an_active_scan_reports_the_lan_apart_from_the_range_it_scanned(monkeypatch):
    # The server keys identity by the LAN (a /22 office is one network); the scanned
    # range can be anything the user typed, e.g. one /24 of it.
    monkeypatch.setattr(netinfo, "default_gateway", lambda: "10.20.0.1")
    monkeypatch.setattr(netinfo, "local_network",
                        lambda ip=None: {"local_ip": "10.20.1.15", "subnet": "10.20.0.0/22", "gateway_ip": "10.20.0.1"})
    info = netinfo.build_network_info("10.20.2.0/24", [])
    assert (info["subnet"], info["lan_subnet"]) == ("10.20.2.0/24", "10.20.0.0/22")


# ── 2.2.5: scapy read the Windows route table after freeing it ──
def test_copied_route_rows_hold_plain_values_not_views_into_native_memory():
    import ctypes
    addr = (ctypes.c_ubyte * 4)(192, 168, 0, 1)
    row = {"NextHop": {"Ipv4": {"sin_addr": {"byte": addr}}}, "Metric": 25}
    copy = netinfo._copy_ctypes(row)
    addr[0] = 10                                         # the native table changing or freed
    assert copy == {"NextHop": {"Ipv4": {"sin_addr": {"byte": [192, 168, 0, 1]}}}, "Metric": 25}
    assert bytes(bytearray(copy["NextHop"]["Ipv4"]["sin_addr"]["byte"])) == b"\xc0\xa8\x00\x01"


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="Windows route table")
def test_scapy_reads_the_windows_route_table_through_the_safe_copy():
    pytest.importorskip("scapy.all")
    import ctypes

    import scapy.arch.windows as win
    original = win.GetIpForwardTable2
    try:
        before = sorted(win._read_routes_c(False))
        assert netinfo.patch_scapy_route_reader() is True
        assert netinfo.patch_scapy_route_reader() is True             # idempotent
        assert win.GetIpForwardTable2 is netinfo._get_ip_forward_table2
        assert sorted(win._read_routes_c(False)) == before            # same routes as scapy's own

        def views(v):
            if isinstance(v, dict):
                return any(views(x) for x in v.values())
            if isinstance(v, list):
                return any(views(x) for x in v)
            return isinstance(v, (ctypes.Array, ctypes.Structure, ctypes.Union))
        assert not views(netinfo._get_ip_forward_table2(2))
    finally:
        win.GetIpForwardTable2 = original
