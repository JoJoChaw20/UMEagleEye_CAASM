"""The own active engine (engine/) and its stage, comparison and settings. No network: every
probe is replaced by a fake that answers like the lab network would."""

from __future__ import annotations

import ipaddress
import json

import pytest

from eagleeye import vendor
from eagleeye.config import Settings
from eagleeye.engine import names, portscan, presence
from eagleeye.engine.ports import BASE_PORTS, CONSUMER_PORTS, PING_PORTS, WIDE_PORTS, ports_for, service_name
from eagleeye.engine.scan import Probes, run_own_scan
from eagleeye.pipeline import PipelineContext
from eagleeye.pipeline.record import HostRecord
from eagleeye.pipeline.runner import Cancelled
from eagleeye.stages import scan_nmap, scan_own
from eagleeye.stages.scan_own import CompareScanStage, OwnScanStage, active_scan_stage, compare_hosts

LAB = ipaddress.ip_network("192.168.36.0/24")


# ── port tiers ──
def test_base_tier_is_the_agents_old_list_without_tcp_161():
    assert set(BASE_PORTS) == {22, 23, 80, 139, 443, 445, 3389, 8080, 8443, 3306, 5432, 6379, 27017}
    assert 161 not in WIDE_PORTS                       # SNMP is UDP; a TCP check of it is useless


def test_tiers_grow_and_never_repeat_a_port():
    assert set(BASE_PORTS) < set(CONSUMER_PORTS) < set(WIDE_PORTS)
    for tier in (BASE_PORTS, CONSUMER_PORTS, WIDE_PORTS):
        assert len(tier) == len(set(tier))
    assert {62078, 8008, 9100} <= set(CONSUMER_PORTS)  # iPhone, Chromecast, printer
    assert set(PING_PORTS) <= set(WIDE_PORTS)


def test_unknown_tier_is_refused_and_names_come_from_iana():
    with pytest.raises(ValueError):
        ports_for("everything")
    assert service_name(22) == "ssh" and service_name(27017) == "mongodb" and service_name(1) == ""


# ── port scan ──
def fake_connect(table, calls=None):
    """connect() answering from {(ip, port): state or [states per attempt]}; unknown = filtered."""
    tries: dict = {}

    def connect(ip, port, timeout):
        if calls is not None:
            calls.append((ip, port, timeout))
        answer = table.get((ip, port), portscan.FILTERED)
        if isinstance(answer, list):
            n = tries.get((ip, port), 0)
            tries[(ip, port)] = n + 1
            return answer[min(n, len(answer) - 1)]
        return answer
    return connect


def test_scan_reports_each_state_and_retries_only_hosts_known_up_with_a_longer_wait():
    calls: list = []
    table = {("10.0.0.1", 22): "open", ("10.0.0.1", 80): [portscan.FILTERED, "open"],
             ("10.0.0.2", 22): "closed"}
    results, attempts = portscan.scan(["10.0.0.1", "10.0.0.2", "10.0.0.3"], [22, 80], timeout=0.5,
                                      connect=fake_connect(table, calls))
    assert results["10.0.0.1"] == {22: "open", 80: "open"}            # found on the retry
    assert results["10.0.0.2"] == {22: "closed", 80: "filtered"}
    assert results["10.0.0.3"] == {22: "filtered", 80: "filtered"}    # silent: never retried
    retried = calls[6:]
    assert {(ip, port) for ip, port, _ in retried} == {("10.0.0.1", 80), ("10.0.0.2", 80)}
    assert all(t >= portscan.RETRY_MIN_TIMEOUT for *_, t in retried)
    assert all(t == 0.5 for *_, t in calls[:6])
    assert attempts == 8


def test_scan_known_up_hosts_get_their_retries_even_when_every_port_was_silent():
    results, attempts = portscan.scan(["10.0.0.9"], [22], timeout=0.1, known_up=["10.0.0.9"],
                                      connect=fake_connect({("10.0.0.9", 22): [portscan.FILTERED, "open"]}))
    assert results["10.0.0.9"][22] == "open" and attempts == 2


def test_scan_stops_when_cancelled():
    with pytest.raises(Cancelled):
        portscan.scan(["10.0.0.1"], [22], connect=fake_connect({}), cancelled=lambda: True)


# ── presence helpers ──
def test_split_by_link_places_each_address_and_skips_this_computer():
    nets = [("192.168.36.1", LAB), ("192.168.0.139", ipaddress.ip_network("192.168.0.0/24"))]
    local, routed = presence.split_by_link(["192.168.36.1", "192.168.36.50", "192.168.0.7", "10.1.1.1"], nets)
    assert local == {"192.168.36.1": ["192.168.36.50"], "192.168.0.139": ["192.168.0.7"]}
    assert routed == ["10.1.1.1"]


def test_proc_net_arp_keeps_only_resolved_entries():
    text = ("IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.36.50    0x1         0x2         00:0c:29:04:6c:77     *        ens33\n"
            "192.168.36.51    0x1         0x0         00:00:00:00:00:00     *        ens33\n")
    assert presence.parse_proc_net_arp(text) == {"192.168.36.50": "00:0C:29:04:6C:77"}


def test_format_mac_refuses_empty_and_broadcast():
    assert presence.format_mac(b"\x00\x0c\x29\x02\xa4\xf9") == "00:0C:29:02:A4:F9"
    assert presence.format_mac(b"\x00" * 6) is None and presence.format_mac(b"\xff" * 6) is None
    assert presence.format_mac(b"\x01\x02") is None


# ── the engine ──
def lab_probes(table=None, names_by_ip=None, ping_answers=(), networks=None, findings=None, snmp=None, netbios=None):
    return Probes(
        identify=lambda ip, port: (findings or {}).get((ip, port)),
        snmp=lambda ip: (snmp or {}).get(ip),
        netbios=lambda ip: (netbios or {}).get(ip),
        own_mac=lambda ip: "00:50:56:C0:00:01" if ip == "192.168.36.1" else None,
        networks=lambda: networks if networks is not None else [("192.168.36.1", LAB)],
        arp=lambda addrs, src, cancelled=None: {ip: mac for ip, mac in
                                                {"192.168.36.50": "00:0C:29:04:6C:77",
                                                 "192.168.36.60": "00:0C:29:02:A4:F9"}.items() if ip in addrs},
        ping=lambda addrs, cancelled=None: {ip for ip in addrs if ip in ping_answers},
        connect=fake_connect(table or {}),
        reverse_dns=lambda ips: {ip: n for ip, n in (names_by_ip or {}).items() if ip in ips},
    )


def test_engine_on_an_attached_network_finds_devices_by_arp_even_with_every_port_silent():
    table = {("192.168.36.50", 22): "open", ("192.168.36.50", 80): "open", ("192.168.36.50", 23): "closed"}
    hosts, stats = run_own_scan("192.168.36.0/24", "base", probes=lab_probes(table, {"192.168.36.60": "LAB-WIN11"}))
    by_ip = {h.ip: h for h in hosts}
    assert list(by_ip) == ["192.168.36.1", "192.168.36.50", "192.168.36.60"]     # own address included
    assert by_ip["192.168.36.1"].mac == "00:50:56:C0:00:01"                       # its own MAC, no scapy
    ubuntu, win = by_ip["192.168.36.50"], by_ip["192.168.36.60"]
    assert ubuntu.mac == "00:0C:29:04:6C:77"
    assert [p["port"] for p in ubuntu.ports] == [22, 80]                            # closed 23 left out
    assert ubuntu.ports[0] == {"port": 22, "protocol": "tcp", "service": "ssh", "version": "", "product": ""}
    assert win.ports == [] and win.hostname == "LAB-WIN11"                          # firewalled, still found
    assert (stats.addresses, stats.up, stats.by_arp, stats.by_ping, stats.open_ports) == (254, 3, 2, 0, 2)


def test_engine_beyond_the_attached_networks_uses_ping_then_ping_ports():
    table = {("10.9.0.5", 445): "closed"}                      # a refusal is an answer
    hosts, stats = run_own_scan("10.9.0.0/29", "base", probes=lab_probes(table, ping_answers={"10.9.0.2"}))
    assert [h.ip for h in hosts] == ["10.9.0.2", "10.9.0.5"]
    assert all(h.mac is None for h in hosts)                   # ARP does not cross routers
    assert (stats.by_arp, stats.by_ping, stats.by_port) == (0, 1, 1)


def test_engine_names_prefer_a_specific_name_and_drop_docker_ones():
    hosts, _ = run_own_scan("192.168.36.48/29", "base",
                            probes=lab_probes(names_by_ip={"192.168.36.50": "docker-desktop.local"}))
    assert {h.ip: h.hostname for h in hosts}["192.168.36.50"] is None


def test_pick_name_ranking():
    assert names.pick_name([("Android", "mdns"), ("OPPO-A31", "dhcp")]) == ("OPPO-A31", "dhcp")
    assert names.pick_name([("Android", "mdns")]) == ("Android", "mdns")
    assert names.pick_name([(None, "rdns"), ("host.docker.internal", "rdns")]) == (None, None)
    assert names.pick_name([("printer.lan.", "rdns")]) == ("printer.lan", "rdns")


# ── stage, comparison, choice ──
def test_own_stage_rejects_bad_targets_and_large_ranges(monkeypatch):
    monkeypatch.setattr(scan_own, "run_own_scan", lambda *a, **k: pytest.fail("must not scan"))
    with pytest.raises(ValueError):
        OwnScanStage("192.168.1.0/24; calc").run(PipelineContext("active"))
    with pytest.raises(ValueError):
        OwnScanStage("10.0.0.0/16").run(PipelineContext("active"))       # 65,536 addresses


def test_own_stage_reports_the_engine(monkeypatch):
    from eagleeye.engine.scan import EngineStats
    monkeypatch.setattr(scan_own, "run_own_scan", lambda *a, **k: ([HostRecord(ip="192.168.36.50")], EngineStats(tier="consumer", up=1)))
    ctx = PipelineContext("active", subnet="192.168.36.0/24")
    OwnScanStage("192.168.36.0/24", "consumer").run(ctx)
    assert ctx.summary["scanner"] == "own" and ctx.summary["engine"]["tier"] == "consumer"
    assert [h.ip for h in ctx.hosts] == ["192.168.36.50"]


def _host(ip, mac=None, ports=(), name=None):
    return HostRecord(ip=ip, mac=mac, hostname=name,
                      ports=[{"port": p, "protocol": "tcp", "service": s, "product": "", "version": ""} for p, s in ports])


def test_compare_hosts_counts_agreement():
    own = [_host("192.168.0.1", "98:48:27:CB:55:6C", [(80, "http")]), _host("192.168.0.113", "FC:31:5D:79:3C:3D"),
           _host("192.168.0.139", "14:13:33:c3:f6:03", [(139, "netbios-ssn"), (443, "https")])]
    ref = [_host("192.168.0.1", "98:48:27:CB:55:6C", [(80, "http")]), _host("192.168.0.186", "9C:B8:B4:B8:73:0A"),
           _host("192.168.0.139", "14:13:33:C3:F6:03", [(139, "netbios-ssn"), (445, "microsoft-ds"), (443, "ssl/http")])]
    r = compare_hosts(own, ref)
    assert r["hosts"] == {"own": 3, "ref": 3, "both": 2, "only_own": ["192.168.0.113"], "only_ref": ["192.168.0.186"]}
    assert r["ports"] == {"both": 3, "union": 4, "agreement": 0.75}
    assert r["macs"] == {"compared": 2, "same": 2, "own_only": 0, "ref_only": 0}      # case does not matter
    pc = {h["ip"]: h for h in r["per_host"]}["192.168.0.139"]
    assert pc["ports_only_ref"] == [445] and pc["services"]["443"]["same_service"] is True


def test_compare_stage_keeps_the_own_hosts_and_writes_a_report(monkeypatch, tmp_path):
    from eagleeye.engine.scan import EngineStats
    monkeypatch.setattr(scan_own, "run_own_scan", lambda *a, **k: ([_host("192.168.36.50", ports=[(22, "ssh")])], EngineStats(tier="base")))

    def nmap_run(self, ctx):
        ctx.hosts = [_host("192.168.36.50", ports=[(22, "ssh"), (80, "http")])]
        ctx.summary["scanner"] = "nmap"
    monkeypatch.setattr(scan_nmap.NmapScanStage, "run", nmap_run)
    ctx = PipelineContext("active", subnet="192.168.36.0/24")
    CompareScanStage("192.168.36.0/24", "base", tmp_path).run(ctx)
    assert ctx.summary["scanner"] == "own" and [p["port"] for p in ctx.hosts[0].ports] == [22]
    report = json.loads(next(tmp_path.glob("compare-*.json")).read_text())
    assert report["ref"]["scanner"] == "nmap" and report["ports"]["agreement"] == 0.5


@pytest.mark.parametrize("engine, kind", [("auto", "OwnScanStage"), ("nmap", "NmapScanStage"),
                                          ("own", "OwnScanStage"), ("compare", "CompareScanStage")])
def test_active_scan_stage_follows_the_setting(engine, kind):
    stage = active_scan_stage("192.168.36.0/24", Settings(scan_engine=engine, scan_ports="consumer"))
    assert type(stage).__name__ == kind
    if kind != "NmapScanStage":
        assert stage.tier == "consumer"


def test_settings_refuse_unknown_engine_and_tier():
    s = Settings(api_url="https://x", api_key="k", agent_id="a", scan_engine="masscan", scan_ports="all")
    problems = " ".join(s.problems())
    assert "scan_engine" in problems and "scan_ports" in problems
    assert Settings().scan_engine == "auto" and Settings().scan_ports == "base"   # old behaviour by default


# ── MAC vendors ──
@pytest.fixture
def vendors(monkeypatch):
    monkeypatch.setattr(vendor, "_ieee", {"7C6130": "Apple, Inc.", "984827": "TP-LINK TECHNOLOGIES CO.,LTD.",
                                          "70B3D5": "IEEE Registration Authority", "70B3D5F2D": "Small Maker Ltd"})

    class Scapy:
        def lookup(self, mac):
            known = {"98:48:27": "Tp-Link Technologies Co.,Ltd.", "70:b3:d5": "IEEE Registration Authority"}
            return ("x", known.get(mac[:8], mac))
    monkeypatch.setattr(vendor, "_manufdb", lambda: Scapy())


def test_vendor_sub_block_beats_the_parent_block(vendors):
    assert vendor.mac_vendor("70:b3:d5:f2:d1:23") == "Small Maker Ltd"


def test_vendor_keeps_scapys_spelling_then_falls_back_to_ieee(vendors, monkeypatch):
    assert vendor.mac_vendor("98:48:27:cb:55:6c") == "Tp-Link Technologies Co.,Ltd."
    assert vendor.mac_vendor("7c:61:30:38:96:02") == "Apple, Inc."             # scapy echoes: unknown there
    monkeypatch.setattr(vendor, "_manufdb", lambda: None)
    assert vendor.mac_vendor("98:48:27:cb:55:6c") == "TP-LINK TECHNOLOGIES CO.,LTD."


def test_vendor_none_for_private_and_unknown(vendors):
    assert vendor.mac_vendor("7e:ab:ab:dc:b3:1a") is None
    assert vendor.mac_vendor("00:11:22:33:44:55") is None


def test_shipped_ieee_list_is_readable():
    monkey_free = vendor.ieee_vendor("00:0c:29:04:6c:77")
    assert monkey_free == "VMware, Inc."


# ── identification (recorded lab replies) ──
from eagleeye.engine import asn1, probes, udp  # noqa: E402


def test_engine_puts_findings_snmp_and_netbios_into_the_host():
    findings = {("192.168.36.50", 22): probes.Finding("ssh", "OpenSSH", "10.2p1", "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.8",
                                                      {"os_hint": "Ubuntu"})}
    hosts, stats = run_own_scan(
        "192.168.36.48/29", "base",
        probes=lab_probes({("192.168.36.50", 22): "open", ("192.168.36.50", 80): "open"}, findings=findings,
                          snmp={"192.168.36.50": {"vendor": "net-snmp", "enterprise": 8072}},
                          netbios={"192.168.36.50": {"computer": "LAB-UBUNTU", "mac": "00:0C:29:04:6C:77"}},
                          names_by_ip={"192.168.36.50": "ubuntu.lan"}))
    h = {x.ip: x for x in hosts}["192.168.36.50"]
    assert h.ports[0] == {"port": 22, "protocol": "tcp", "service": "ssh", "version": "10.2p1", "product": "OpenSSH",
                          "banner": "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.8"}
    assert h.ports[1]["service"] == "http" and h.ports[1]["product"] == ""          # no finding: name only
    assert h.ports[2] == {"port": 161, "protocol": "udp", "service": "snmp", "version": "", "product": "net-snmp"}
    assert h.hostname == "LAB-UBUNTU"                                                  # NetBIOS beats reverse DNS
    assert stats.identified == 1 and stats.details["192.168.36.50"]["name_source"] == "netbios"
    assert stats.details["192.168.36.50"]["ports"]["22"] == {"os_hint": "Ubuntu"}


def test_a_failing_probe_does_not_end_the_scan():
    def boom(ip, port):
        raise RuntimeError("device sent garbage")
    p = lab_probes({("192.168.36.50", 22): "open"})
    p.identify = boom
    hosts, _ = run_own_scan("192.168.36.48/29", "base", probes=p)
    assert {x.ip: x for x in hosts}["192.168.36.50"].ports[0]["service"] == "ssh"


def test_ssh_banners():
    f = probes.parse_ssh("SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.8")
    assert (f.product, f.version, f.extra["os_hint"]) == ("OpenSSH", "10.2p1", "Ubuntu")
    assert probes.parse_ssh("SSH-2.0-dropbear_2022.83").product == "Dropbear sshd"
    assert probes.parse_ssh("SSH-2.0-ROSSSH").product == "MikroTik RouterOS sshd"
    assert probes.parse_ssh("SSH-2.0-SomethingElse_1").product == "SomethingElse_1"


def test_http_reply_gives_server_title_and_realm():
    data = (b"HTTP/1.1 401 Unauthorized\r\nServer: nginx/1.28.3 (Ubuntu)\r\n"
            b'WWW-Authenticate: Basic realm="TP-LINK Archer C6"\r\n\r\n<html><title> Lab\n web </title></html>')
    f = probes.parse_http(data)
    assert (f.service, f.product, f.version) == ("http", "nginx", "1.28.3")
    assert f.extra["realm"] == "TP-LINK Archer C6" and f.extra["title"] == "Lab web" and f.extra["status"] == 401
    assert probes.parse_http(b"SSH-2.0-x\r\n") is None
    assert probes.server_product("Apache/2.4.62 (Unix)") == ("Apache httpd", "2.4.62", "Unix")
    assert probes.server_product("Microsoft-IIS/10.0") == ("Microsoft IIS httpd", "10.0", "")


def test_mysql_handshake_and_error():
    hs = b"\x4a\x00\x00\x00\x0a8.4.3\x00" + b"\x01" * 20
    assert (probes.parse_mysql(hs).product, probes.parse_mysql(hs).version) == ("MySQL", "8.4.3")
    maria = b"\x4a\x00\x00\x00\x0a5.5.5-10.11.6-MariaDB-0+deb12u1\x00"
    assert (probes.parse_mysql(maria).product, probes.parse_mysql(maria).version) == ("MariaDB", "10.11.6")
    err = b"\x45\x00\x00\x00\xff\x6a\x04Host '10.0.0.9' is not allowed to connect"
    assert probes.parse_mysql(err).product == "MySQL" and "not allowed" in probes.parse_mysql(err).extra["error"]


def test_redis_info_and_password_reply():
    info = b"$300\r\n# Server\r\nredis_version:7.4.1\r\nos:Linux 7.0.0-38-generic x86_64\r\n\r\n"
    f = probes.parse_redis(info)
    assert (f.product, f.version, f.extra["os_hint"]) == ("Redis", "7.4.1", "Linux 7.0.0-38-generic x86_64")
    assert probes.parse_redis(b"-NOAUTH Authentication required.\r\n").version == ""
    assert probes.parse_redis(b"garbage") is None


def test_mongo_build_info_round_trip():
    req = probes.mongo_build_info_request()
    assert struct.unpack_from("<i", req, 0)[0] == len(req) and struct.unpack_from("<i", req, 12)[0] == 2013
    doc = probes.bson_doc([("version", "8.0.3"), ("ok", 1), ("gitVersion", "89d97f27")])
    reply = struct.pack("<iiii", 21 + len(doc), 1, 0x45454545, 2013) + b"\x00\x00\x00\x00\x00" + doc
    f = probes.parse_mongo(reply)
    assert (f.product, f.version, f.extra["gitVersion"]) == ("MongoDB", "8.0.3", "89d97f27")


def test_greetings_and_telnet_negotiation_are_cleaned():
    assert probes.parse_greeting(21, b"220 (vsFTPd 3.0.5)\r\n").product == "vsFTPd"
    assert probes.parse_greeting(21, b"220 (vsFTPd 3.0.5)\r\n").version == "3.0.5"
    t = probes.parse_greeting(23, b"\xff\xfd\x18\xff\xfd\x20\xff\xfa\x18\x01\xff\xf0Router login: ")
    assert t.service == "telnet" and t.banner == "Router login:"


def test_certificate_names_and_dates():
    import base64
    der = base64.b64decode(LAB_CERT_B64)
    c = asn1.certificate(der)
    assert c["subject"]["CN"] == "lab-ubuntu.eagleeye.test" and c["self_signed"] is True
    assert c["not_after"].startswith("20") and c["not_before"] < c["not_after"]


def test_snmp_engine_discovery_request_and_report():
    req = udp.snmp_discovery_request()
    _t, msg, _ = asn1.read(req)
    parts = list(asn1.children(msg))
    assert asn1.to_int(parts[0][1]) == 3 and parts[1][1][-3:] == b"\x02\x01\x03"     # SNMPv3, USM
    engine = bytes.fromhex("80001f88800cd281521ecfed6a00000000")
    usm = asn1.seq(asn1.octets(engine), asn1.integer(5), asn1.integer(12849), asn1.octets(b""), asn1.octets(b""), asn1.octets(b""))
    report = asn1.seq(asn1.integer(3), asn1.seq(asn1.integer(1)), asn1.octets(usm), asn1.seq())
    r = udp.parse_snmp_report(report)
    assert (r["vendor"], r["enterprise"], r["boots"], r["uptime_seconds"]) == ("net-snmp", 8072, 5, 12849)
    cisco = udp.parse_engine_id(bytes.fromhex("800000090300") + bytes.fromhex("0011223344"))
    assert cisco["vendor"] == "Cisco"
    assert udp.parse_engine_id(bytes.fromhex("8000000903001122334455"))["mac"] == "00:11:22:33:44:55"
    assert udp.parse_snmp_report(b"\x30\x03\x02\x01\x01") is None                     # SNMPv1 reply


def test_netbios_node_status_reply():
    def entry(name, suffix, group):
        return name.ljust(15).encode() + bytes([suffix]) + struct.pack(">H", 0x8400 if group else 0x0400)
    body = entry("LAB-WIN11", 0x00, False) + entry("WORKGROUP", 0x00, True) + entry("LAB-WIN11", 0x20, False)
    reply = b"\x00" * 56 + bytes([3]) + body + bytes.fromhex("000c2902a4f9")
    r = udp.parse_node_status(reply)
    assert (r["computer"], r["workgroup"], r["mac"]) == ("LAB-WIN11", "WORKGROUP", "00:0C:29:02:A4:F9")
    assert udp.parse_node_status(b"\x00" * 10) is None


import struct  # noqa: E402

# The lab Ubuntu VM's self-signed nginx certificate (CN lab-ubuntu.eagleeye.test).
LAB_CERT_B64 = (
    "MIIDJzCCAg+gAwIBAgIUNDW/pAdE7r/BIodmINQebLPoWREwDQYJKoZIhvcNAQELBQAwIzEhMB8GA1UEAwwYbGFiLXVidW50"
    "dS5lYWdsZWV5ZS50ZXN0MB4XDTI2MTEwNjEzMjA0MFoXDTI3MTEwNjEzMjA0MFowIzEhMB8GA1UEAwwYbGFiLXVidW50dS5l"
    "YWdsZWV5ZS50ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnXNYZWjVo3HTSY+ZRDHjpuSLw8keVtEwk2Nc"
    "+Yn6v8WpBYBIB1Cbb3FIBoSvi+niylwJuBdGXtnT2g50THYvINq1XPTD6n4QHQXGPujTnr/zJt+JgKiOz2AwuYZf0oUVYvLY"
    "a73HiK36eiSaIgwpVHdeR+Y9xJBAqZujZxuP9R2o+f6pTN+urNB0t5vTdMKqWHy8jCH4isMPU+B9rjvzBfkVlBY7RYgvjKAJ"
    "j/bxA5tUTiPHVFTu7Gj8zaXNyeMXMTDPO4dbDYgmMtgLVBednQ2A179FlON9Bq9DELemonWj7Cte4BFgVbumkyNc7FztDgT+"
    "SjqgHT9aB1O0LcGXLwIDAQABo1MwUTAdBgNVHQ4EFgQUROt+zeWz+u07Ji8TleUZzZjy2m0wHwYDVR0jBBgwFoAUROt+zeWz"
    "+u07Ji8TleUZzZjy2m0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEADQlx5f4+GR4+RwKi1ybjCutsIkvb"
    "0+jctVsGedrfvzAa6m4WHvycBu8C+JCxF6RbQuHyvS2BJ4mX2z/5sd8UrJq38B4jNY+h4mTTNu1+lrC8xeQDhI2Bz7ngs8cW"
    "vIij1tSiokTdrPasz+4pKr5b+1GlZi+Df5Y5Lyt9/pRRrjb/J5hGyqudPAxW1DdB8JeaGwjRojWyrCzXnnwA3QMqMsgVq7h7"
    "I/V01DjhdPT1Mxn5OFDs0ji95GV7ndPolObeDtuBRJqg5VVztbDtXc24mI29WeUs/MDJ1yHNbJ5Ob3fhKqmZWUU9rx5HHQ9q"
    "zxEtj23kC3dk7heEPMDEmer8PA=="
)


# ── SMB / RDP (msproto) ──
from eagleeye.engine import msproto  # noqa: E402


def _challenge(major, minor, build, pairs, flags=0x02800000):
    info = b"".join(struct.pack("<HH", k, len(v.encode("utf-16-le"))) + v.encode("utf-16-le") for k, v in pairs) + b"\x00" * 4
    head = msproto.NTLMSSP + struct.pack("<I", 2) + struct.pack("<HHI", 0, 0, 56) + struct.pack("<I", flags)
    head += b"\x11" * 8 + b"\x00" * 8 + struct.pack("<HHI", len(info), len(info), 56)
    head += bytes([major, minor]) + struct.pack("<H", build) + b"\x00\x00\x00\x0f"
    return b"spnego-wrapper" + head + info


def test_ntlm_challenge_names_a_windows_machine_in_a_domain():
    r = msproto.parse_challenge(_challenge(10, 0, 26100, [(1, "LAB-WIN11"), (2, "CORP"), (3, "lab-win11.corp.local"), (4, "corp.local")]))
    assert r == {"ntlm_version": "10.0.26100", "name": "Windows 11 24H2 or later / Server 2025", "smb_computer_name": "LAB-WIN11",
                 "smb_netbios_domain": "CORP", "smb_fqdn": "lab-win11.corp.local", "smb_domain": "corp.local"}


def test_ntlm_challenge_of_a_workgroup_pc_and_of_samba():
    pc = msproto.parse_challenge(_challenge(10, 0, 19045, [(1, "JOJOCHAW"), (3, "JoJochaw"), (4, "JoJochaw")]))
    assert pc["name"] == "Windows 10" and "smb_domain" not in pc                       # no domain: name repeated
    samba = msproto.parse_challenge(_challenge(6, 1, 0, [(1, "LAB-UBUNTU"), (3, "lab-ubuntu"), (4, "")]))
    assert "name" not in samba and samba["smb_computer_name"] == "LAB-UBUNTU"          # build 0: not Windows
    assert msproto.parse_challenge(b"no ntlm here") is None


def test_windows_names_by_build():
    assert msproto.windows_name(10, 0, 26300) == "Windows 11"
    assert msproto.windows_name(10, 0, 17763) == "Windows 10 1809 / Server 2019"
    assert msproto.windows_name(6, 1, 0) is None


def test_smb2_negotiate_reply():
    body = struct.pack("<HHHH", 65, 0x3, 0x0302, 0) + bytes(range(16)) + b"\x00" * 16 + struct.pack("<Q", 134070000000000000) + b"\x00" * 24
    r = msproto.parse_negotiate(msproto.SMB2_MAGIC + b"\x00" * 60 + body)
    assert r["smb_dialect"] == "3.0.2" and r["signing_required"] is True and r["server_time"].startswith("2025")
    assert msproto.parse_negotiate(b"\xffSMB" + b"\x00" * 200) is None                 # SMBv1 answer


def test_smb_requests_are_well_formed():
    neg = msproto.negotiate_request()
    assert struct.unpack(">I", neg[:4])[0] == len(neg) - 4 and neg[4:8] == msproto.SMB2_MAGIC
    ss = msproto.session_setup_request()
    assert msproto.NTLMSSP + b"\x01\x00\x00\x00" in ss and ss[4 + 12:4 + 14] == b"\x01\x00"   # SESSION_SETUP


def test_smb_finding_separates_machine_facts():
    f = probes.smb_finding({"smb_dialect": "3.0.2", "ntlm_version": "10.0.26100", "name": "Windows 11", "smb_computer_name": "PC1"})
    assert (f.product, f.version) == ("Microsoft Windows SMB", "10.0.26100")
    assert f.extra == {"smb_dialect": "3.0.2", "os": {"name": "Windows 11", "smb_computer_name": "PC1", "ntlm_version": "10.0.26100"}}
    assert probes.smb_finding({"smb_dialect": "3.0.2", "smb_computer_name": "NAS"}).product == "SMB server"


def test_engine_takes_os_and_name_from_smb():
    smb = probes.smb_finding({"ntlm_version": "10.0.26100", "name": "Windows 11", "smb_computer_name": "LAB-WIN11"})
    hosts, stats = run_own_scan("192.168.36.56/29", "base",
                                probes=lab_probes({("192.168.36.60", 445): "open"}, findings={("192.168.36.60", 445): smb},
                                                  netbios={"192.168.36.60": {"computer": "OTHER"}}))
    h = {x.ip: x for x in hosts}["192.168.36.60"]
    assert h.os == {"name": "Windows 11", "smb_computer_name": "LAB-WIN11", "ntlm_version": "10.0.26100"}
    assert h.hostname == "LAB-WIN11" and stats.details["192.168.36.60"]["name_source"] == "smb"


def test_rdp_confirm_replies():
    def cc(neg):
        x224 = bytes([6 + len(neg), 0xD0, 0, 0, 0, 0, 0]) + neg
        return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
    assert msproto.parse_x224_confirm(cc(struct.pack("<BBHI", 2, 0, 8, 2))) == {"selected": "credssp"}
    assert msproto.parse_x224_confirm(cc(struct.pack("<BBHI", 3, 0, 8, 5))) == {"failure": 5}
    assert msproto.parse_x224_confirm(cc(b"")) == {"selected": "rdp"}
    assert msproto.parse_x224_confirm(b"HTTP/1.1 400") is None
    req = msproto.x224_request(0x3)
    assert req[:2] == b"\x03\x00" and struct.unpack(">H", req[2:4])[0] == len(req) and req[-4:] == b"\x03\x00\x00\x00"


# ── edge cases found by mutation testing ──
def test_ntlm_version_is_read_only_when_the_server_says_it_sent_one():
    r = msproto.parse_challenge(_challenge(10, 0, 26100, [(1, "PC1")], flags=0x00800000))
    assert "ntlm_version" not in r and "name" not in r and r["smb_computer_name"] == "PC1"


def test_mysql_version_drops_the_distribution_suffix():
    f = probes.parse_mysql(b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00")
    assert f.version == "8.0.36" and f.extra["version_string"] == "8.0.36-0ubuntu0.22.04.1"


def test_telnet_option_bytes_never_leak_into_the_banner():
    assert probes.parse_greeting(23, b'Router\xff\xfb\x22 login:').banner == "Router login:"   # WILL LINEMODE (0x22 = '"')


def test_netbios_computer_name_is_the_unique_name_even_after_the_group():
    def entry(name, suffix, group):
        return name.ljust(15).encode() + bytes([suffix]) + struct.pack(">H", 0x8400 if group else 0x0400)
    body = entry("WORKGROUP", 0x00, True) + entry("NAS-01", 0x00, False)
    r = udp.parse_node_status(b"\x00" * 56 + bytes([2]) + body + b"\x00" * 6)
    assert (r["computer"], r["workgroup"]) == ("NAS-01", "WORKGROUP") and "mac" not in r


def test_certificate_signed_by_a_ca_is_not_self_signed():
    def name(cn):
        return asn1.seq(asn1.tlv(0x31, asn1.seq(asn1.tlv(asn1.OID, b"\x55\x04\x03"), asn1.tlv(0x0C, cn.encode()))))
    validity = asn1.seq(asn1.tlv(0x17, b"260101000000Z"), asn1.tlv(0x17, b"270101000000Z"))
    tbs = asn1.seq(asn1.tlv(0xA0, asn1.integer(2)), asn1.integer(7), asn1.seq(), name("Lab CA"), validity, name("nas.lab"), asn1.seq())
    c = asn1.certificate(asn1.seq(tbs, asn1.seq(), asn1.tlv(0x03, b"\x00")))
    assert c["subject"] == {"CN": "nas.lab"} and c["issuer"] == {"CN": "Lab CA"} and c["self_signed"] is False
    assert c["not_after"] == "2027-01-01T00:00:00+00:00"


def test_scan_never_has_more_than_per_host_connections_open_to_one_device():
    import threading
    import time as _t
    live, peak, lock = {}, {}, threading.Lock()

    def slow(ip, port, timeout):
        with lock:
            live[ip] = live.get(ip, 0) + 1
            peak[ip] = max(peak.get(ip, 0), live[ip])
        _t.sleep(0.02)
        with lock:
            live[ip] -= 1
        return "closed"
    portscan.scan(["10.0.0.1", "10.0.0.2"], range(1, 21), workers=64, per_host=3, connect=slow)
    assert peak == {"10.0.0.1": 3, "10.0.0.2": 3}


def test_own_macs_from_ip_addr_json():
    data = [{"ifname": "lo", "address": "00:00:00:00:00:00", "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
            {"ifname": "ens33", "address": "00:0c:29:04:6c:77",
             "addr_info": [{"family": "inet", "local": "142.19.0.1"}, {"family": "inet", "local": "192.168.36.50"},
                           {"family": "inet6", "local": "fe80::1"}]}]
    assert presence.parse_ip_addr_macs(data) == {"142.19.0.1": "00:0C:29:04:6C:77", "192.168.36.50": "00:0C:29:04:6C:77"}


def test_arp_trigger_uses_a_fresh_non_blocking_socket_per_batch(monkeypatch):
    made = []

    class FakeSocket:
        def __init__(self, *a):
            self.sent, self.blocking = [], True
            made.append(self)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def setblocking(self, flag): self.blocking = flag
        def bind(self, addr): self.bound = addr
        def sendto(self, data, addr):
            if addr[0].endswith(".7"):
                raise BlockingIOError()               # a full buffer skips one address, not the sweep
            self.sent.append(addr)
    monkeypatch.setattr(presence.socket, "socket", FakeSocket)
    addrs = [f"192.168.36.{i}" for i in range(1, 71)]
    assert presence.trigger_arp(addrs, "192.168.36.50", batch=32) == 69
    assert [len(s.sent) for s in made] == [31, 32, 6] and all(not s.blocking for s in made)
    assert made[0].sent[0] == ("192.168.36.1", 9) and made[0].bound == ("192.168.36.50", 0)



def test_netbios_session_request_encodes_names():
    req = msproto.session_request("LAB-WIN11")
    assert req[0] == 0x81 and struct.unpack(">H", req[2:4])[0] == len(req) - 4
    assert req[4:38] == msproto.netbios_name("LAB-WIN11") and req[5:7] == b"EM"     # 'L' = 0x4C -> 'E','M'
    assert msproto.netbios_name("*SMBSERVER")[1:3] == b"CK"                          # '*' = 0x2A -> 'C','K'


def test_port_139_falls_back_to_the_computer_name(monkeypatch):
    calls = []

    def exchange(ip, port, timeout, called):
        calls.append(called)
        return {"smb_computer_name": "LAB-WIN11"} if called == "LAB-WIN11" else None
    monkeypatch.setattr(msproto, "_smb_exchange", exchange)
    monkeypatch.setattr(udp, "netbios_status", lambda ip, timeout=1.5: {"computer": "LAB-WIN11"})
    assert msproto.smb_probe("192.168.36.60", 139) == {"smb_computer_name": "LAB-WIN11"}
    assert calls == ["*SMBSERVER", "LAB-WIN11"]
    calls.clear()
    msproto.smb_probe("192.168.36.60", 445)
    assert calls == [None]                                                           # 445 needs no session


def test_samba_is_recognised_by_its_ntlm_version():
    r = msproto.parse_challenge(_challenge(6, 1, 0, [(1, "LAB-UBUNTU")]))
    assert r["samba"] is True and "name" not in r
    f = probes.smb_finding(r, "netbios-ssn")
    assert (f.service, f.product, f.version) == ("netbios-ssn", "Samba smbd", "") and "samba" not in f.extra
