"""The network agent (netagent/): our SNMP client, recordings, one device's tables, the crawl and
its analysis, scoring against the GNS3 lab's ground truth, and `eagleeye netpoll`.

The lab recordings (fixtures/gns3) are what the lab's routers and switches answered, completed
from their show commands where a table was not walked yet (marked in each file)."""

from __future__ import annotations

import argparse
import socket
import threading
import time
from pathlib import Path

import pytest

from eagleeye.netagent import collect, crawl as crawl_mod, recorded, snmp, truth
from eagleeye.netagent.collect import Device, Interface, Neighbor, base_name, describe, short_port
from eagleeye.netagent.command import credentials
from eagleeye.netagent.crawl import CrawlResult, analyse, crawl, parse_ranges
from eagleeye.netagent.recorded import RecordedSession, Recorder

LAB = Path(__file__).parent / "fixtures" / "gns3"
LAB_RANGES = parse_ranges(["10.10.0.0/16", "10.99.0.0/24"])


def lab_session(address):
    return RecordedSession.from_dir(LAB, address)


def lab_crawl(**kw):
    return crawl(["10.99.0.1"], lab_session, kw.pop("allowed", LAB_RANGES), **kw)


# ── BER and keys ──
@pytest.mark.parametrize("oid", [(1, 3, 6, 1, 2, 1, 1, 1, 0), (1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9),
                                 (1, 3, 6, 1, 4, 1, 9, 9, 46, 1, 3, 1, 1, 2, 1, 1005), (2, 999, 3), (1, 3, 4294967295)])
def test_oids_survive_encoding(oid):
    from eagleeye.engine import asn1
    _tag, value, _ = asn1.read(snmp.encode_oid(oid))
    assert snmp.decode_oid(value) == oid


def test_values_are_plain_python():
    assert snmp.decode_value(0x02, b"\xff") == -1
    assert snmp.decode_value(0x41, b"\xff\xff\xff\xff") == 4294967295          # Counter32 is unsigned
    assert snmp.decode_value(0x40, bytes([10, 10, 99, 2])) == "10.10.99.2"
    assert snmp.decode_value(0x04, b"SW1") == b"SW1"
    assert snmp.decode_value(0x06, b"\x2b\x06\x01") == (1, 3, 6, 1)
    assert snmp.decode_value(0x80, b"") is snmp.NO_SUCH and snmp.decode_value(0x82, b"") is snmp.END_OF_MIB


def test_a_pdu_survives_encoding():
    pdu = snmp.build_pdu(snmp.GETBULK, 77, [(1, 3, 6, 1, 2, 1, 1)], 0, 25)
    tag, rid, a, b, binds = snmp.parse_pdu(pdu)
    assert (tag, rid, a, b) == (snmp.GETBULK, 77, 0, 25) and binds == [((1, 3, 6, 1, 2, 1, 1), None)]


def test_keys_match_rfc_3414_appendix_a3():
    engine = bytes.fromhex("000000000000000000000002")
    md5 = snmp.localize_key(snmp.password_to_key("maplesyrup", "md5"), engine, "md5")
    sha = snmp.localize_key(snmp.password_to_key("maplesyrup", "sha1"), engine, "sha1")
    assert md5.hex() == "526f5eed9fcce26f8964c2930787d82b"
    assert sha.hex() == "6695febc9288e36282235fc7151f128497b38f3f"


def test_credentials_are_checked_and_never_printed():
    good = snmp.Credentials(user="eagleeye", auth_key="EagleEyeAuth1", priv_key="EagleEyePriv1")
    good.check()
    assert "EagleEye" not in repr(good) and good.level == "authPriv"
    assert "Lab" not in repr(snmp.Credentials(version="2c", community="LabRO"))
    for bad, why in ((snmp.Credentials(user="u", auth_key="short", priv_key="EagleEyePriv1"), "at least 8"),
                     (snmp.Credentials(user="u", auth_key="EagleEyeAuth1", priv_protocol="AES256", priv_key="x" * 8), "only AES-128"),
                     (snmp.Credentials(user="", auth_key="EagleEyeAuth1"), "user name"),
                     (snmp.Credentials(version="2c"), "community"),
                     (snmp.Credentials(version="1", community="c"), "3 or 2c")):
        with pytest.raises(ValueError, match=why):
            bad.check()


def test_a_tampered_answer_is_refused():
    pytest.importorskip("cryptography")
    s = snmp.Session("192.0.2.1", snmp.Credentials(user="eagleeye", auth_key="EagleEyeAuth1", priv_key="EagleEyePriv1"))
    s._engine = bytes.fromhex("800000090300" + "0c59a9ef0000")
    s._auth_key = snmp.localize_key(snmp.password_to_key("EagleEyeAuth1", "sha1"), s._engine, "sha1")
    s._priv_key = snmp.localize_key(snmp.password_to_key("EagleEyePriv1", "sha1"), s._engine, "sha1")[:16]
    s._set_clock(3, 1000)
    # an answer signed and encrypted with the user's keys, as the device would send it
    answer = s._v3_message(42, snmp.build_pdu(snmp.RESPONSE, 42, [(1, 3, 6, 1, 2, 1, 1, 5, 0)]), "")
    assert s._parse_v3(answer, 42)[0] == snmp.RESPONSE
    assert s._parse_v3(answer, 41) is None                              # an answer to another request
    at = len(answer) - 5                                                # a byte of the encrypted PDU
    tampered = answer[:at] + bytes([answer[at] ^ 1]) + answer[at + 1:]
    with pytest.raises(snmp.SnmpAuthError, match="failed authentication"):
        s._parse_v3(tampered, 42)


def test_a_closed_port_is_a_clear_error():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with snmp.Session("127.0.0.1", snmp.Credentials(version="2c", community="public"), port=port,
                      timeout=0.5, retries=0) as session:
        with pytest.raises(snmp.SnmpError):
            session.get(["1.3.6.1.2.1.1.5.0"])


# ── interop: our client against pysnmp's agent ──
@pytest.fixture(scope="module")
def pysnmp_agent():
    pytest.importorskip("cryptography")
    pytest.importorskip("pysnmp")
    import asyncio
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import cmdrsp, context

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ready = threading.Event()

    def serve():
        asyncio.set_event_loop(asyncio.new_event_loop())
        e = engine.SnmpEngine()
        config.add_transport(e, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", port)))
        config.add_v3_user(e, "sha-aes", config.USM_AUTH_HMAC96_SHA, "authpass1", config.USM_PRIV_CFB128_AES, "privpass1")
        config.add_v3_user(e, "sha256-aes", config.USM_AUTH_HMAC192_SHA256, "authpass1", config.USM_PRIV_CFB128_AES, "privpass1")
        config.add_v3_user(e, "md5-auth", config.USM_AUTH_HMAC96_MD5, "authpass1")
        for user in ("sha-aes", "sha256-aes"):
            config.add_vacm_user(e, 3, user, "authPriv", (1, 3, 6), (1, 3, 6))
        config.add_vacm_user(e, 3, "md5-auth", "authNoPriv", (1, 3, 6), (1, 3, 6))
        config.add_v1_system(e, "area", "public")
        config.add_vacm_user(e, 2, "area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
        ctx = context.SnmpContext(e)
        for responder in (cmdrsp.GetCommandResponder, cmdrsp.NextCommandResponder, cmdrsp.BulkCommandResponder):
            responder(e, ctx)
        e.transport_dispatcher.job_started(1)
        ready.set()
        e.open_dispatcher()

    threading.Thread(target=serve, daemon=True).start()
    assert ready.wait(10)
    time.sleep(0.3)
    return port


@pytest.mark.parametrize("creds", [
    snmp.Credentials(version="2c", community="public"),
    snmp.Credentials(user="sha-aes", auth_protocol="SHA", auth_key="authpass1", priv_key="privpass1"),
    snmp.Credentials(user="sha256-aes", auth_protocol="SHA256", auth_key="authpass1", priv_key="privpass1"),
    snmp.Credentials(user="md5-auth", auth_protocol="MD5", auth_key="authpass1", priv_protocol=""),
], ids=["v2c", "v3-sha-aes", "v3-sha256-aes", "v3-md5-authNoPriv"])
def test_our_client_talks_to_pysnmp(pysnmp_agent, creds):
    with snmp.Session("127.0.0.1", creds, port=pysnmp_agent, timeout=2, max_repetitions=10) as s:
        got = s.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.99.0"])
        assert got[(1, 3, 6, 1, 2, 1, 1, 1, 0)].startswith(b"PySNMP") and got[(1, 3, 6, 1, 2, 1, 1, 99, 0)] is None
        system = s.walk("1.3.6.1.2.1.1")
        assert [o[-2] for o, _v in system][:2] == [1, 2] and all(o[:7] == (1, 3, 6, 1, 2, 1, 1) for o, _v in system)
        big = s.walk("1.3.6.1.6.3")                     # many values: several GETBULKs
        assert len(big) > 100 and big == sorted(big, key=lambda x: x[0])


@pytest.mark.parametrize("creds, why", [
    (snmp.Credentials(user="sha-aes", auth_key="WRONGpass1", priv_key="privpass1"), "authentication password"),
    (snmp.Credentials(user="sha-aes", auth_key="authpass1", priv_key="WRONGpass1"), "privacy password"),
    (snmp.Credentials(user="nobody", auth_key="authpass1", priv_key="privpass1"), "does not know this SNMPv3 user"),
])
def test_wrong_credentials_say_what_is_wrong(pysnmp_agent, creds, why):
    with snmp.Session("127.0.0.1", creds, port=pysnmp_agent, timeout=1, retries=0) as s:
        with pytest.raises(snmp.SnmpAuthError, match=why):
            s.get(["1.3.6.1.2.1.1.1.0"])


# ── recordings ──
def test_net_snmp_text_is_read_back():
    text = '''iso.3.6.1.2.1.1.1.0 = STRING: "Cisco IOS Software, line one
second line with a \\"quote\\""
iso.3.6.1.2.1.4.22.1.2.1.10.99.0.1 = Hex-STRING: 0C 59 A9 EF 00 00
.1.3.6.1.2.1.2.2.1.8.1 = INTEGER: up(1)
.1.3.6.1.2.1.1.3.0 = Timeticks: (360000) 1:00:00.00
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.9.1.1041
iso.0.8802.1.1.2.1.4.1.1.9.0.2.1 = STRING: "SW1"
iso.3.6.1.2.1.17.7.1.2.2.1.2 = No Such Object available on this agent at this OID
.1.3.6.1.2.1.4.20.1.3.10.99.0.1 = IpAddress: 255.255.255.0
.1.3.6.1.4.1.9.9.23.1.2.1.1.8.2.2 = ""
Timeout: No Response from 10.10.99.2
'''
    values = dict(recorded.parse_text(text))
    assert values[(1, 3, 6, 1, 2, 1, 1, 1, 0)] == b'Cisco IOS Software, line one\nsecond line with a "quote"'
    assert values[(1, 3, 6, 1, 2, 1, 4, 22, 1, 2, 1, 10, 99, 0, 1)] == bytes.fromhex("0C59A9EF0000")
    assert values[(1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1)] == 1 and values[(1, 3, 6, 1, 2, 1, 1, 3, 0)] == 360000
    assert values[(1, 3, 6, 1, 2, 1, 1, 2, 0)] == (1, 3, 6, 1, 4, 1, 9, 1, 1041)
    assert values[(1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9, 0, 2, 1)] == b"SW1"
    assert values[(1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 1, 1, 8, 2, 2)] == b""
    assert len(values) == 8                                          # the missing object is skipped


def test_formatting_and_reading_agree():
    values = [((1, 3, 6, 1, 2, 1, 1, 5, 0), b'R1 "lab"'), ((1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 1), bytes.fromhex("0c59a9ef0000")),
              ((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1), 1), ((1, 3, 6, 1, 2, 1, 4, 20, 1, 3, 10, 0, 0, 1), "255.255.255.0"),
              ((1, 3, 6, 1, 2, 1, 1, 2, 0), (1, 3, 6, 1, 4, 1, 9)), ((1, 3, 6, 1, 2, 1, 1, 1, 0), b"two\nlines")]
    assert recorded.parse_text(recorded.format_text(values)) == sorted(values)


def test_a_context_without_a_recording_times_out():
    session = lab_session("10.10.99.2")
    assert session.walk("1.3.6.1.2.1.17.4.3.1.2")                       # VLAN 1
    with pytest.raises(snmp.SnmpTimeout):
        session.walk("1.3.6.1.2.1.17.4.3.1.2", vlan=10)                 # IOSvL2 has no vlan-10 context
    with pytest.raises(snmp.SnmpTimeout):
        lab_session("10.10.99.9").get(["1.3.6.1.2.1.1.5.0"])            # no such device


def test_a_recording_replays_to_the_same_crawl(tmp_path):
    recorders = []

    def recording(address):
        rec = Recorder(lab_session(address))
        recorders.append(rec)
        return rec
    first = crawl(["10.99.0.1"], recording, LAB_RANGES)
    for rec in recorders:
        rec.write(tmp_path, "test")
    again = crawl(["10.99.0.1"], lambda a: RecordedSession.from_dir(tmp_path, a), LAB_RANGES)
    strip = lambda r: {k: v for k, v in r.to_dict().items() if k not in ("seconds",)}
    for d in first.devices + again.devices:
        d.seconds = 0
    assert strip(first) == strip(again)


# ── one device ──
@pytest.mark.parametrize("name, short", [("GigabitEthernet0/1", "Gi0/1"), ("Gig 0/1", "Gi0/1"), ("Gi0/1", "Gi0/1"),
                                         ("TenGigabitEthernet1/1/1", "Te1/1/1"), ("FastEthernet0/24", "Fa0/24"),
                                         ("Port-channel1", "Po1"), ("Vlan99", "Vl99"), ("GigabitEthernet0/1.10", "Gi0/1.10"),
                                         ("Ethernet1/1", "Et1/1"), ("Eth1/1", "Et1/1"), ("Nu0", "Nu0"), ("ens33", "ens33"), ("", ""),
                                         ("gi0/1", "Gi0/1"), ("te1/1", "Te1/1")])
def test_port_names_are_made_the_same(name, short):
    assert short_port(name) == short


def test_device_names_lose_their_domain():
    assert base_name("SW2.lab.local") == "SW2" and base_name("SW1") == "SW1"
    assert base_name("N5K-A(FOC1234X0YZ)") == "N5K-A" and base_name("10.10.99.2") == "10.10.99.2"


def test_the_operating_system_comes_from_sysdescr():
    assert describe("Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.9(3)M12, RELEASE") == ("Cisco IOS", "15.9(3)M12")
    assert describe("Cisco IOS Software [Cupertino], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), "
                    "Version 17.9.4a, RELEASE SOFTWARE (fc3) ... IOS-XE") == ("Cisco IOS XE", "17.9.4a")
    assert describe("Juniper Networks, Inc. ex2300 internet router, kernel JUNOS 21.4R3")[0] == "Junos"


def test_r1_tables():
    dev = collect.poll_device(lab_session("10.99.0.1"), "10.99.0.1")
    assert (dev.name, dev.label, dev.vendor, dev.os, dev.version) == ("R1.lab.local", "R1", "Cisco", "Cisco IOS", "15.9(3)M12")
    assert dev.interfaces[2].name == "Gi0/1" and dev.interfaces[1].mac == "0C:59:A9:EF:00:00"
    assert {i.name: i.vlan for i in dev.interfaces.values() if i.vlan} == {"Gi0/1": 1, "Gi0/1.10": 10, "Gi0/1.20": 20, "Gi0/1.99": 99}
    assert {a["ip"]: a["network"] for a in dev.addresses}["10.10.10.1"] == "10.10.10.0/24"
    arp = {e["ip"]: (e["mac"], e["if_index"]) for e in dev.arp}
    assert arp["10.10.10.11"] == ("00:50:79:66:68:00", 6) and arp["10.99.0.10"] == ("00:0C:29:04:6C:77", 1)
    assert len(dev.arp) == 13 and not dev.fdb                        # a router: no MAC table
    assert {"network": "10.10.10.0/24", "next_hop": None, "if_index": 6, "type": "local"} in dev.routes
    cdp = [n for n in dev.neighbors if n.protocol == "cdp"]
    assert [(n.local_port, n.name, n.port, n.address) for n in cdp] == [("Gi0/1", "SW1", "Gi0/0", "10.10.99.2")]
    lldp = [n for n in dev.neighbors if n.protocol == "lldp"]
    assert [(n.local_if, n.name, n.port, n.address) for n in lldp] == [(2, "SW1", "Gi0/0", "10.10.99.2")]
    assert dev.errors == []


def test_switch_tables_and_the_missing_vlan_contexts():
    dev = collect.poll_device(lab_session("10.10.99.3"), "10.10.99.3")
    assert dev.label == "SW2" and dev.vlans == [1, 10, 20, 99, 1002, 1003, 1004, 1005]
    assert dev.interfaces[1].trunk is True and dev.interfaces[4].trunk is False
    # IOSvL2 does not answer CISCO-VLAN-MEMBERSHIP-MIB: no access VLANs (the router's subinterfaces give them)
    assert (dev.interfaces[2].vlan, dev.interfaces[4].vlan, dev.interfaces[1].vlan) == (None, None, None)
    assert dev.interfaces[4].alias == "PC-D"
    fdb = {f["mac"]: (f["vlan"], dev.port_name(f["if_index"])) for f in dev.fdb}
    assert fdb == {"00:50:79:66:68:04": (1, "Gi0/3"), "0C:37:FC:DE:00:01": (1, "Gi0/0"), "0C:59:A9:EF:00:01": (1, "Gi0/0")}
    assert len(dev.notes) == 1 and "VLAN 10" in dev.notes[0]          # tried once, then stopped


def test_a_trunk_has_no_access_vlan():
    # Cisco keeps a port's access VLAN in its configuration even while it trunks
    base = [(collect.SYS_NAME, b"SW9"), ((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, 1), b"Gi0/0"),
            ((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, 2), b"Gi0/1"), (collect.BASE_PORT_IFINDEX + (1,), 1),
            (collect.BASE_PORT_IFINDEX + (2,), 2), (collect.TRUNK_STATUS + (1,), 1), (collect.TRUNK_STATUS + (2,), 2),
            (collect.VM_VLAN + (1,), 1), (collect.VM_VLAN + (2,), 30)]
    dev = collect.poll_device(RecordedSession("10.0.0.9", {None: base}), "10.0.0.9")
    assert (dev.interfaces[1].trunk, dev.interfaces[1].vlan) == (True, None)
    assert (dev.interfaces[2].trunk, dev.interfaces[2].vlan) == (False, 30)


def test_a_standard_switch_uses_q_bridge_and_mac_port_ids():
    walk = [((1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2, 20, 0, 80, 121, 102, 104, 3), 7)]
    assert collect.parse_qbridge_fdb(walk, {7: 107}) == [{"mac": "00:50:79:66:68:03", "vlan": 20, "if_index": 107}]
    rem = collect.LLDP_REM
    lldp = collect.parse_lldp(
        [(rem + (6, 0, 7, 1), 3), (rem + (7, 0, 7, 1), bytes.fromhex("00505479a001")), (rem + (9, 0, 7, 1), b"ap-1"),
         (rem + (4, 0, 7, 1), 4), (rem + (5, 0, 7, 1), bytes.fromhex("00505479a000"))],
        [], [], {7: Interface(7, "ge-0/0/7")})
    assert [(n.local_if, n.local_port, n.name, n.port, n.chassis) for n in lldp] == \
        [(7, "ge-0/0/7", "ap-1", "00:50:54:79:A0:01", "00:50:54:79:A0:00")]


# ── the crawl ──
def test_the_lab_crawl_finds_the_chain_once():
    r = lab_crawl()
    assert [(d.label, d.address, d.found_via, d.depth) for d in r.devices] == [
        ("R1", "10.99.0.1", "seed", 0), ("SW1", "10.10.99.2", "CDP from R1 Gi0/1", 1),
        ("SW2", "10.10.99.3", "CDP from SW1 Gi0/1", 2)]
    assert r.unreachable == [] and r.skipped == []                    # SW1's CDP names R1 by 10.10.1.1: same device
    assert [(l["a"]["device"], l["a"]["port"], l["b"]["device"], l["b"]["port"], l["protocols"], l["both_polled"])
            for l in r.links] == [("R1", "Gi0/1", "SW1", "Gi0/0", ["cdp", "lldp"], True),
                                  ("SW1", "Gi0/1", "SW2", "Gi0/0", ["cdp", "lldp"], True)]
    hosts = {h["ip"]: h for h in r.hosts}
    assert hosts["10.10.1.41"]["location"] == {"switch": "SW2", "port": "Gi0/3", "vlan": 1, "macs_on_port": 1, "ambiguous": False}
    assert hosts["10.10.99.3"]["device"] == "SW2" and hosts["10.10.10.1"]["device"] == "R1"
    assert hosts["10.10.10.11"]["vlan"] == 10 and hosts["10.10.10.11"]["location"] is None
    assert [n["network"] for n in r.networks] == ["10.10.1.0/24", "10.10.10.0/24", "10.10.20.0/24", "10.10.99.0/24", "10.99.0.0/24"]
    assert r.requests > 0


def test_each_device_is_polled_once():
    # SW1's CDP and LLDP name R1 by 10.10.1.1, R1 and SW2 both name SW1: one session each
    opened = []

    def counting(address):
        opened.append(address)
        return lab_session(address)
    crawl(["10.99.0.1"], counting, LAB_RANGES)
    assert opened == ["10.99.0.1", "10.10.99.2", "10.10.99.3"]
    # two seeds: SW1 names R1 by 10.10.1.1 before R1's own addresses are known
    opened.clear()
    r = crawl(["10.10.99.2", "10.99.0.1"], counting, LAB_RANGES)
    assert opened == ["10.10.99.2", "10.99.0.1", "10.10.99.3"] and len(r.devices) == 3


def test_the_live_lab_run():
    # What the lab answered on 2026-11-08: R1 sends LLDP from each subinterface, so SW1 hears four
    # R1 neighbours on Gi0/0 (Gi0/1, Gi0/1.10, .20, .99); that is still one cable.
    live = Path(__file__).parent / "fixtures" / "gns3-live"
    r = crawl(["10.99.0.1"], lambda a: RecordedSession.from_dir(live, a), LAB_RANGES)
    assert [d.label for d in r.devices] == ["R1", "SW1", "SW2"]
    sw1 = r.devices[1]
    assert sorted(n.port for n in sw1.neighbors if n.protocol == "lldp" and n.name == "R1.lab.local") == \
        ["Gi0/1", "Gi0/1.10", "Gi0/1.20", "Gi0/1.99"]
    assert [(l["a"]["device"], l["a"]["port"], l["b"]["device"], l["b"]["port"]) for l in r.links] == \
        [("R1", "Gi0/1", "SW1", "Gi0/0"), ("SW1", "Gi0/1", "SW2", "Gi0/0")]
    assert r.devices[0].interfaces[2].vlan == 1                        # Gi0/1 routes the native VLAN 1
    assert len(r.hosts) == 8 and all(h["location"] is None for h in r.hosts)   # the PCs had aged out
    assert r.devices[2].interfaces[4].alias == "PC-D"


def test_a_cable_joins_physical_ports():
    assert collect.cable_port("GigabitEthernet0/1.10") == "Gi0/1" and collect.cable_port("Gi0/1") == "Gi0/1"
    assert collect.cable_port("Vlan99") == "Vl99"


def test_the_crawl_stays_inside_the_allowed_ranges_and_depth():
    only_seed = lab_crawl(allowed=[])
    assert [d.label for d in only_seed.devices] == ["R1"]
    assert only_seed.skipped == [{"name": "SW1", "address": "10.10.99.2", "reason": "outside the allowed ranges",
                                  "via": "CDP from R1 Gi0/1"}]
    one_hop = lab_crawl(depth=1)
    assert [d.label for d in one_hop.devices] == ["R1", "SW1"]
    assert [(s["name"], s["reason"]) for s in one_hop.skipped] == [("SW2.lab.local", "more than 1 hops from a seed")]
    assert one_hop.links[-1]["both_polled"] is False                   # the link to SW2 is still known


def test_a_seed_that_does_not_answer_is_reported():
    r = crawl(["10.10.99.9", "10.99.0.1"], lab_session, LAB_RANGES)
    assert r.unreachable == [{"address": "10.10.99.9", "error": "no answer from 10.10.99.9", "via": "seed"}]
    assert len(r.devices) == 3


def test_the_crawl_stops_at_the_device_limit():
    r = lab_crawl(max_devices=2)
    assert [d.label for d in r.devices] == ["R1", "SW1"] and r.skipped[0]["reason"] == "more than 2 devices"


def _switch(label, fdb, trunks=(), neighbours=()):
    d = Device(label, name=label)
    for idx in range(1, 6):
        d.interfaces[idx] = Interface(idx, f"Gi0/{idx}", trunk=idx in trunks)
    d.fdb = [{"mac": m, "vlan": 10, "if_index": i} for m, i in fdb]
    d.neighbors = [Neighbor("lldp", i, f"Gi0/{i}", n, "Gi0/1") for i, n in neighbours]
    return d


def test_only_edge_ports_locate_and_the_quietest_port_wins():
    pc, behind_hub = "00:00:00:00:00:01", "00:00:00:00:00:02"
    core = _switch("CORE", [(pc, 1), (behind_hub, 1)], trunks={1})                  # the uplink carries everything
    access = _switch("ACC", [(pc, 3), (behind_hub, 4), ("00:00:00:00:00:03", 4), ("00:00:00:00:00:04", 4)])
    other = _switch("ACC2", [(behind_hub, 2)], neighbours=[(5, "CORE")])            # an unmanaged switch's MACs
    access.interfaces[5].mac = "0C:00:00:00:00:05"
    core.fdb.append({"mac": "0C:00:00:00:00:05", "vlan": 10, "if_index": 2})       # a polled switch, no CDP/LLDP
    r = CrawlResult(devices=[core, access, other])
    analyse(r)
    where = {h["mac"]: h["location"] for h in r.hosts}
    assert "0C:00:00:00:00:05" not in where                            # a device we polled is not a host
    assert where[pc] == {"switch": "ACC", "port": "Gi0/3", "vlan": 10, "macs_on_port": 1, "ambiguous": False}
    assert where[behind_hub]["switch"] == "ACC2" and where[behind_hub]["ambiguous"] is True
    assert all(h["ip"] is None for h in r.hosts)                       # heard on switches only


# ── ground truth and the command ──
def test_the_lab_scores_against_its_ground_truth():
    s = truth.score(lab_crawl(), truth.load_csv(LAB / "gns3-truth.csv"), truth.load_csv(LAB / "gns3-links.csv"))
    assert (s["addresses"], s["found"], s["mac_right"], s["names_right"], s["names_checked"]) == (13, 13, 13, 7, 7)
    rows = {r["ip"]: r for r in s["rows"]}
    assert rows["10.10.1.41"]["location"] == "right" and rows["10.10.99.3"]["location"] == "right (link)"
    assert rows["10.10.10.12"]["location"] == "not located"          # VLAN 10: no MAC table on IOSvL2
    assert (s["located_right"], s["located_wrong"], s["not_located"]) == (6, 0, 4)
    assert s["links"]["found"] == s["links"]["expected"] == 2 and s["links"]["extra"] == []
    assert s["links"]["not_visible"] == [{"link": "R1 - Gi0/0 - lab-ubuntu - ens33", "found": False}]
    # the right switch on the wrong port is wrong
    r = lab_crawl()
    next(h for h in r.hosts if h["ip"] == "10.10.1.41")["location"]["port"] = "Gi0/2"
    s = truth.score(r, truth.load_csv(LAB / "gns3-truth.csv"))
    assert {x["ip"]: x["location"] for x in s["rows"] if "location" in x}["10.10.1.41"] == "wrong (SW2 Gi0/2)"
    assert (s["located_right"], s["located_wrong"]) == (5, 1)


def _args(**kw):
    base = dict(credentials=None, snmp_version=None, snmp_user=None, auth_protocol=None, priv_protocol=None)
    return argparse.Namespace(**{**base, **kw})


def test_credentials_come_from_a_file_the_environment_and_flags(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.stdin", None)
    env = {"EAGLEEYE_SNMP_USER": "eagleeye", "EAGLEEYE_SNMP_AUTH_KEY": "EagleEyeAuth1", "EAGLEEYE_SNMP_PRIV_KEY": "EagleEyePriv1"}
    c = credentials(_args(), env)
    assert (c.version, c.user, c.auth_protocol, c.priv_protocol, c.auth_key) == ("3", "eagleeye", "SHA", "AES", "EagleEyeAuth1")
    assert credentials(_args(priv_protocol="none", auth_protocol="SHA256"), env).level == "authNoPriv"
    f = tmp_path / "snmp.json"
    f.write_text('{"version": "2c", "community": "LabRO"}')
    assert credentials(_args(credentials=f), {}).community == "LabRO"
    with pytest.raises(ValueError, match="user name"):
        credentials(_args(), {})                                       # nothing given and nobody to ask


def test_netpoll_replays_the_lab(capsys, tmp_path):
    from eagleeye.cli import main
    out = tmp_path / "result.json"
    code = main(["netpoll", "--seed", "10.99.0.1", "--allow", "10.10.0.0/16", "--allow", "10.99.0.0/24",
                 "--replay", str(LAB), "--truth", str(LAB / "gns3-truth.csv"), "--links", str(LAB / "gns3-links.csv"),
                 "--json", str(out)])
    text = capsys.readouterr().out
    assert code == 0
    assert "R1 Gi0/1  <->  SW1 Gi0/0" in text and "SW2 Gi0/3" in text and "Links: 2/2 found" in text
    assert "addresses 13/13" in text
    import json
    assert [d["label"] for d in json.loads(out.read_text())["devices"]] == ["R1", "SW1", "SW2"]
