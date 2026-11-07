"""The built-in capture's own decoding (decode.py) and adapter list (adapters.py).

test_passive.py runs every sniffer test through both scapy and decode.py; these tests
cover the decoder itself: its output against scapy's fields, malformed input, and the
cases scapy does not bind (NetBIOS name refresh)."""

from __future__ import annotations

import random

import pytest

pytest.importorskip("scapy.all")
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, UDP, Ether, IPv6, load_layer  # noqa: E402

load_layer("netbios")
from scapy.layers.netbios import (  # noqa: E402
    NBNS_ADD_ENTRY, NBNSHeader, NBNSNodeStatusResponse, NBNSNodeStatusResponseService, NBNSQueryResponse,
    NBNSRegistrationRequest,
)

from eagleeye.passive import adapters, decode  # noqa: E402

PHONE = "c4:fe:5b:a9:44:05"


def test_frame_arp_ipv4_ipv6_and_padding():
    arp = decode.frame(bytes(Ether(src=PHONE) / ARP(hwsrc=PHONE, psrc="192.168.0.174")))
    assert arp.arp == ("192.168.0.174", PHONE) and arp.src_mac == PHONE
    small = bytes(Ether(src=PHONE, dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.0.5", dst="255.255.255.255")
                  / UDP(sport=137, dport=137) / b"hi")
    f = decode.frame(small + b"\x00" * 20)                        # Ethernet pads short frames
    assert (f.ip_src, f.sport, f.dport, f.payload) == ("192.168.0.5", 137, 137, b"hi")
    f6 = decode.frame(bytes(Ether() / IPv6(src="fe80::1:2") / UDP(sport=5353, dport=5353) / b"x"))
    assert (f6.ip6_src, f6.ip_src, f6.payload) == ("fe80::1:2", None, b"x")
    tcp = decode.frame(bytes(Ether() / IP(src="192.168.0.5", proto=6) / (b"\0" * 20)))
    assert tcp.ip_src == "192.168.0.5" and tcp.sport is None
    assert decode.frame(b"\x01\x02") is None


def test_dns_has_the_shape_the_sniffer_reads_from_scapy():
    msg = DNS(qr=1, qd=[DNSQR(qname="_airplay._tcp.local", qtype="PTR")],
              an=[DNSRR(rrname="_airplay._tcp.local", type="PTR", rdata="Jo's iPad._airplay._tcp.local"),
                  DNSRR(rrname="Jos-iPad.local", type="A", rdata="192.168.0.186")],
              ar=[DNSRR(rrname="Jos-iPad.local", type="AAAA", rdata="fe80::1c2:3")])
    ours, theirs = decode.dns(bytes(msg)), DNS(bytes(msg))
    assert ours.qr == theirs.qr == 1
    assert [q.qname for q in ours.qd] == [theirs.qd[0].qname]
    for mine, ref in zip(ours.an + ours.ar, list(theirs.an) + list(theirs.ar)):
        assert (mine.rrname, mine.type) == (ref.rrname, ref.type)
        assert mine.rdata == (ref.rdata if not isinstance(ref.rdata, str) else str(ref.rdata))


def test_dns_compression_loops_and_truncation_are_refused():
    loop = b"\x00\x00\x84\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    assert decode.dns(loop) is None
    whole = bytes(DNS(qr=1, an=[DNSRR(rrname="a.local", type="A", rdata="1.2.3.4")]))
    assert decode.dns(whole[:-2]) is None and decode.dns(b"\0" * 5) is None


def nbns(hdr, layer):
    return bytes(hdr / layer)


def test_netbios_registration_query_response_and_node_status():
    reg = nbns(NBNSHeader(OPCODE=5), NBNSRegistrationRequest(QUESTION_NAME="LAB-WIN11", SUFFIX=0x4141, G=0,
                                                              NB_ADDRESS="192.168.36.60"))
    assert decode.netbios_names(reg, "192.168.36.60") == [("192.168.36.60", "LAB-WIN11")]
    group = nbns(NBNSHeader(OPCODE=5), NBNSRegistrationRequest(QUESTION_NAME="WORKGROUP", SUFFIX=0x4141, G=1))
    assert decode.netbios_names(group, "192.168.36.60") == []
    other = nbns(NBNSHeader(OPCODE=5), NBNSRegistrationRequest(QUESTION_NAME="LAB-WIN11", SUFFIX=0x4241))  # "BA" = <10>
    assert decode.netbios_names(other, "192.168.36.60") == []        # not a workstation <00> or server <20> name
    resp = nbns(NBNSHeader(OPCODE=0, RESPONSE=1, NM_FLAGS=0x50, ANCOUNT=1),
                NBNSQueryResponse(RR_NAME="FILESRV", SUFFIX=0x4341,
                                  ADDR_ENTRY=[NBNS_ADD_ENTRY(G=0, NB_ADDRESS="10.0.0.5"),
                                              NBNS_ADD_ENTRY(G=0, NB_ADDRESS="10.0.1.5")]))
    assert decode.netbios_names(resp, "10.0.0.5") == [("10.0.0.5", "FILESRV"), ("10.0.1.5", "FILESRV")]
    status = nbns(NBNSHeader(OPCODE=0, RESPONSE=1, NM_FLAGS=0x40, ANCOUNT=1),
                  NBNSNodeStatusResponse(NODE_NAME=[
                      NBNSNodeStatusResponseService(NETBIOS_NAME="WORKGROUP", SUFFIX=0x00, NAME_FLAGS=0x84),
                      NBNSNodeStatusResponseService(NETBIOS_NAME="LAB-WIN11", SUFFIX=0x00, NAME_FLAGS=0x04)]))
    assert decode.netbios_names(status, "192.168.36.60") == [("192.168.36.60", "LAB-WIN11")]
    assert decode.netbios_names(status, None) == []                  # whose name it is: the sender's


def test_netbios_name_refresh_is_read_too():
    # Windows refreshes its names (opcode 8) every few minutes; scapy only binds opcode 5,
    # so the Npcap path never read these.
    refresh = bytearray(nbns(NBNSHeader(OPCODE=5), NBNSRegistrationRequest(QUESTION_NAME="LAB-WIN11",
                                                                           NB_ADDRESS="192.168.36.60")))
    refresh[2] = (refresh[2] & 0x87) | (8 << 3)
    assert decode.netbios_names(bytes(refresh), "192.168.36.60") == [("192.168.36.60", "LAB-WIN11")]


def test_dhcp_options_have_scapys_types_and_the_last_repeat_wins():
    msg = bytes(BOOTP(chaddr=bytes.fromhex(PHONE.replace(":", "")) + b"\0" * 10, ciaddr="192.168.0.174")
                / DHCP(options=[("message-type", "request"), ("requested_addr", "192.168.0.174"),
                                ("hostname", b"old"), ("hostname", b"HUAWEI_P30"),
                                ("param_req_list", [1, 3, 6]), ("vendor_class_id", b"HUAWEI:android"), "end"]))
    d = decode.dhcp(msg)
    assert decode.mac_str(d.chaddr) == PHONE and (d.ciaddr, d.yiaddr) == ("192.168.0.174", "0.0.0.0")
    assert d.options == {53: 3, 50: "192.168.0.174", 12: b"HUAWEI_P30", 55: [1, 3, 6], 60: b"HUAWEI:android"}
    assert decode.dhcp(bytes(BOOTP())) is None                       # BOOTP without DHCP
    assert decode.dhcp(msg[:200]) is None


def test_nothing_malformed_makes_the_decoders_raise():
    samples = [
        bytes(Ether() / IP(src="192.168.0.5", dst="224.0.0.251") / UDP(sport=5353, dport=5353)
              / DNS(qr=1, an=[DNSRR(rrname="x.local", type="A", rdata="192.168.0.5")])),
        bytes(Ether() / IP() / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[("message-type", "discover"), "end"])),
        bytes(Ether() / IP() / UDP(sport=137, dport=137)
              / NBNSHeader(OPCODE=5) / NBNSRegistrationRequest(QUESTION_NAME="X1")),
    ]
    rnd = random.Random(11)
    cases = [s[:n] for s in samples for n in range(len(s))]
    for s in samples:
        for _ in range(300):
            b = bytearray(s)
            for _ in range(rnd.randrange(1, 6)):
                b[rnd.randrange(14, len(b))] = rnd.randrange(256)
            cases.append(bytes(b))
    cases += [rnd.randbytes(rnd.randrange(0, 400)) for _ in range(300)]
    for raw in cases:
        f = decode.frame(raw)
        payload = f.payload if f is not None else raw
        decode.dns(payload)
        decode.netbios_names(payload, "192.168.0.5")
        decode.dhcp(payload)


# ── adapters ─────────────────────────────────────────────────────────────────

IP_ADDR = [  # `ip -j addr` on the lab Ubuntu VM (trimmed)
    {"ifindex": 1, "ifname": "lo", "address": "00:00:00:00:00:00",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
    {"ifindex": 2, "ifname": "ens33", "address": "00:0c:29:04:6c:77",
     "addr_info": [{"family": "inet", "local": "142.19.0.1", "prefixlen": 23},
                   {"family": "inet", "local": "192.168.36.50", "prefixlen": 24},
                   {"family": "inet6", "local": "fe80::20c:29ff:fe04:6c77", "prefixlen": 64}]},
    {"ifindex": 3, "ifname": "ens37", "address": "00:0c:29:04:6c:81", "addr_info": []},
]


def test_linux_adapters_from_ip_json():
    found = adapters.parse_ip_addr(IP_ADDR, [{"dst": "default", "gateway": "192.168.36.1", "dev": "ens33"}])
    ens33 = found[1]
    assert (ens33["name"], ens33["index"], ens33["mac"], ens33["ips"]) == (
        "ens33", 2, "00:0c:29:04:6c:77", ["142.19.0.1", "192.168.36.50"])
    assert found[0]["mac"] is None and found[2]["ips"] == []
    assert adapters.network_from("192.168.36.50", found) == {
        "local_ip": "192.168.36.50", "subnet": "192.168.36.0/24", "gateway_ip": "192.168.36.1"}
    assert adapters.network_from("142.19.0.1", found)["subnet"] == "142.19.0.0/23"
    assert adapters.network_from("10.9.9.9", found) == {"local_ip": "10.9.9.9", "subnet": "10.9.9.0/24",
                                                        "gateway_ip": None}


@pytest.mark.skipif(not hasattr(adapters, "_windows_adapters"), reason="Windows only")
def test_windows_adapter_list_matches_scapys():
    from scapy.arch.windows import get_windows_if_list
    mine = {a["index"]: a for a in adapters.list_adapters()}
    for ref in get_windows_if_list():
        a = mine[ref["index"]]
        assert (a["name"], a["description"], a["mac"]) == (ref["name"], ref["description"], (ref["mac"] or "").lower() or None)
        assert sorted(a["ips"]) == sorted(ip for ip in ref["ips"] if ":" not in ip)


def test_node_status_never_takes_the_logged_on_users_name():
    # The messenger <03> entry often carries the signed-in user's name: never a device name.
    status = nbns(NBNSHeader(OPCODE=0, RESPONSE=1, NM_FLAGS=0x40, ANCOUNT=1),
                  NBNSNodeStatusResponse(NODE_NAME=[
                      NBNSNodeStatusResponseService(NETBIOS_NAME="JOJO", SUFFIX=0x03, NAME_FLAGS=0x04),
                      NBNSNodeStatusResponseService(NETBIOS_NAME="LAB-WIN11", SUFFIX=0x00, NAME_FLAGS=0x04)]))
    assert decode.netbios_names(status, "192.168.36.60") == [("192.168.36.60", "LAB-WIN11")]


def test_udp_payload_ends_where_the_udp_length_says():
    raw = bytearray(bytes(Ether() / IP(src="192.168.0.5") / UDP(sport=1900, dport=1900) / b"NOTIFY * HTTP/1.1\r\n\r\nJUNK"))
    raw[38:40] = (8 + len(b"NOTIFY * HTTP/1.1\r\n\r\n")).to_bytes(2, "big")     # UDP length shorter than IP's
    assert decode.frame(bytes(raw)).payload == b"NOTIFY * HTTP/1.1\r\n\r\n"


def test_connected_networks_are_the_real_adapters_networks():
    found = adapters.parse_ip_addr(IP_ADDR + [
        {"ifindex": 4, "ifname": "docker0", "address": "02:42:11:22:33:44",
         "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16}]}], [])
    assert adapters.connected_networks(found) == ["142.19.0.0/23", "192.168.36.0/24"]   # not lo, not docker0
