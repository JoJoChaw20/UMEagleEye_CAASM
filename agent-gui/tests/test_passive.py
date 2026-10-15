"""Passive parsers (mDNS, NetBIOS-NS, DHCP) against packets built with scapy and
round-tripped through bytes, as they arrive off the wire. The cases come from two
live captures on a home Wi-Fi network (Phase C): Apple devices announcing over IPv6,
A records in the additional section, NetBIOS node-status answers, DHCP from 0.0.0.0.

Set EAGLEEYE_TEST_PCAP to a local capture (e.g. from the passive diagnostic) to also
replay real traffic through the parsers; captures stay out of the repository because
they hold device names."""

from __future__ import annotations

import os

import pytest

scapy_all = pytest.importorskip("scapy.all")
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, UDP, Ether, IPv6, load_layer  # noqa: E402

load_layer("netbios")
from scapy.layers.netbios import (  # noqa: E402
    NBNS_ADD_ENTRY, NBNSHeader, NBNSNodeStatusResponse, NBNSNodeStatusResponseService,
    NBNSQueryRequest, NBNSQueryResponse, NBNSRegistrationRequest,
)

from eagleeye.passive.sniffers import ArpSniffer, DhcpSniffer, InterfaceChooser, MdnsNetbiosSniffer  # noqa: E402
from eagleeye.pipeline.record import HostRecord  # noqa: E402
from eagleeye.stages import enrich_passive_hosts  # noqa: E402

IPAD_MAC = "0e:18:7c:8f:fd:91"
APPLE_MAC = "06:00:59:e5:9a:c6"
PHONE_MAC = "c4:fe:5b:a9:44:05"


def wire(pkt):
    return Ether(bytes(pkt))


def mdns4(src, mac, **dns):
    return wire(Ether(src=mac) / IP(src=src, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(**dns))


def mdns6(src6, mac, **dns):
    return wire(Ether(src=mac) / IPv6(src=src6, dst="ff02::fb") / UDP(sport=5353, dport=5353) / DNS(**dns))


@pytest.fixture
def mdns():
    sniffer = MdnsNetbiosSniffer()
    sniffer.feed = sniffer._make_handler()
    return sniffer


@pytest.fixture
def dhcp():
    sniffer = DhcpSniffer()
    sniffer.feed = sniffer._make_handler()
    return sniffer


# ── mDNS ──
def test_mdns_a_record_in_answers(mdns):
    mdns.feed(mdns4("192.168.100.149", "4a:15:f7:3b:8c:29", qr=1, aa=1,
                    an=[DNSRR(rrname="Jos-iPhone.local.", type="A", rdata="192.168.100.149")]))
    assert mdns.get_hostname("192.168.100.149") == "Jos-iPhone"
    assert mdns.get_mac_info("4a:15:f7:3b:8c:29")["hostname"] == "Jos-iPhone"


def test_mdns_a_record_in_additional_section(mdns):
    mdns.feed(mdns4("192.168.100.21", "60:fb:00:7b:7e:44", qr=1, aa=1,
                    an=[DNSRR(rrname="_googlecast._tcp.local.", type="PTR", rdata="TVBox._googlecast._tcp.local.")],
                    ar=[DNSRR(rrname="TVBox.local.", type="A", rdata="192.168.100.21")]))
    assert mdns.get_hostname("192.168.100.21") == "TVBox"
    info = mdns.get_mac_info("60:fb:00:7b:7e:44")
    assert info["mdns_name"] == "TVBox" and info["mdns_services"] == ["_googlecast._tcp"]


def test_mdns_over_ipv6_names_the_mac_when_the_aaaa_record_is_the_sender(mdns):
    mdns.feed(mdns6("fe80::10ac:16e0:5fe2:520d", IPAD_MAC, qr=1, aa=1, an=[
        DNSRR(rrname="Jojos-iPad.local.", type="A", rdata="192.168.100.186"),
        DNSRR(rrname="Jojos-iPad.local.", type="AAAA", rdata="fe80::10ac:16e0:5fe2:520d"),
    ]))
    assert mdns.get_hostname("192.168.100.186") == "Jojos-iPad"
    assert mdns.get_mac_info(IPAD_MAC.upper())["mdns_name"] == "Jojos-iPad"     # MAC lookups ignore case


def test_mdns_answer_for_another_device_is_not_credited_to_the_sender(mdns):
    # A Bonjour sleep proxy answers for sleeping devices: the name maps to the IP, not to the proxy's MAC.
    mdns.feed(mdns4("192.168.100.50", "aa:aa:aa:aa:aa:01", qr=1, aa=1,
                    an=[DNSRR(rrname="Sleepy-Mac.local.", type="A", rdata="192.168.100.60")]))
    assert mdns.get_hostname("192.168.100.60") == "Sleepy-Mac"
    assert mdns.get_mac_info("aa:aa:aa:aa:aa:01") == {}


def test_mdns_services_from_queries_and_announcements(mdns):
    mdns.feed(mdns6("fe80::a:392c:3ee7:ded0", APPLE_MAC, qr=0, qd=[
        DNSQR(qname="_rdlink._tcp.local.", qtype="PTR"), DNSQR(qname="_companion-link._tcp.local.", qtype="PTR")]))
    mdns.feed(mdns6("fe80::a:392c:3ee7:ded0", APPLE_MAC, qr=0, qd=[
        DNSQR(qname="_CC32E753._sub._googlecast._tcp.local.", qtype="PTR"),
        DNSQR(qname="_services._dns-sd._udp.local.", qtype="PTR"),
        DNSQR(qname="186.100.168.192.in-addr.arpa.", qtype="PTR")]))
    mdns.feed(mdns6("fe80::a:392c:3ee7:ded0", APPLE_MAC, qr=1, an=[
        DNSRR(rrname="Jo’s iPad._device-info._tcp.local.", type="TXT", rdata="model=iPad13,1")]))
    assert mdns.get_mac_info(APPLE_MAC)["mdns_services"] == [
        "_companion-link._tcp", "_device-info._tcp", "_googlecast._tcp", "_rdlink._tcp"]
    assert "hostname" not in mdns.get_mac_info(APPLE_MAC)          # services alone give no name


# ── NetBIOS ──
def nbns(src, mac, hdr, layer, dst="192.168.100.255"):
    return wire(Ether(src=mac) / IP(src=src, dst=dst) / UDP(sport=137, dport=137) / hdr / layer)


def test_netbios_registration_names_the_owner(mdns):
    mdns.feed(nbns("192.168.100.165", "78:af:08:24:e9:5b", NBNSHeader(OPCODE=5, RESPONSE=0),
                   NBNSRegistrationRequest(QUESTION_NAME="HMSB-P1SV0105", SUFFIX=0x4141, G=0, NB_ADDRESS="192.168.100.165")))
    assert mdns.get_hostname("192.168.100.165") == "HMSB-P1SV0105"
    assert mdns.get_mac_info("78:af:08:24:e9:5b")["netbios_name"] == "HMSB-P1SV0105"


def test_netbios_group_names_and_queries_are_not_owner_names(mdns):
    mdns.feed(nbns("192.168.100.165", "78:af:08:24:e9:5b", NBNSHeader(OPCODE=5, RESPONSE=0),
                   NBNSRegistrationRequest(QUESTION_NAME="WORKGROUP", SUFFIX=0x4141, G=1, NB_ADDRESS="192.168.100.165")))
    # A query names the machine being looked FOR, not the sender.
    mdns.feed(nbns("192.168.100.71", "14:13:33:c3:f6:03", NBNSHeader(OPCODE=0, RESPONSE=0),
                   NBNSQueryRequest(QUESTION_NAME="FILESERVER", SUFFIX=0x4141)))
    assert mdns.get_hostname("192.168.100.165") is None and mdns.get_hostname("192.168.100.71") is None


def test_netbios_positive_query_response(mdns):
    mdns.feed(nbns("192.168.100.165", "78:af:08:24:e9:5b", NBNSHeader(OPCODE=0, RESPONSE=1, RCODE=0),
                   NBNSQueryResponse(RR_NAME="HMSB-P1SV0105", SUFFIX=0x4141,
                                     ADDR_ENTRY=[NBNS_ADD_ENTRY(G=0, NB_ADDRESS="192.168.100.165")]),
                   dst="192.168.100.71"))
    assert mdns.get_hostname("192.168.100.165") == "HMSB-P1SV0105"


def test_netbios_node_status_response_takes_the_unique_workstation_name(mdns):
    names = [NBNSNodeStatusResponseService(NETBIOS_NAME="WORKGROUP", SUFFIX=0x00, NAME_FLAGS=0x84),   # group
             NBNSNodeStatusResponseService(NETBIOS_NAME="HMSB-P1SV0105", SUFFIX=0x20, NAME_FLAGS=0x04),  # server svc
             NBNSNodeStatusResponseService(NETBIOS_NAME="HMSB-P1SV0105", SUFFIX=0x00, NAME_FLAGS=0x04)]
    mdns.feed(nbns("192.168.100.165", "78:af:08:24:e9:5b", NBNSHeader(OPCODE=0, RESPONSE=1),
                   NBNSNodeStatusResponse(NODE_NAME=names), dst="192.168.100.71"))
    assert mdns.get_hostname("192.168.100.165") == "HMSB-P1SV0105"


def test_netbios_never_replaces_an_mdns_name(mdns):
    mdns.feed(mdns4("192.168.100.165", "78:af:08:24:e9:5b", qr=1,
                    an=[DNSRR(rrname="hmsb-laptop.local.", type="A", rdata="192.168.100.165")]))
    mdns.feed(nbns("192.168.100.165", "78:af:08:24:e9:5b", NBNSHeader(OPCODE=5, RESPONSE=0),
                   NBNSRegistrationRequest(QUESTION_NAME="HMSB-P1SV0105", SUFFIX=0x4141, G=0, NB_ADDRESS="192.168.100.165")))
    assert mdns.get_hostname("192.168.100.165") == "hmsb-laptop"


def test_malformed_packet_is_skipped(mdns):
    mdns.feed(wire(Ether() / IP(src="192.168.100.9") / UDP(sport=137, dport=137) / b"\x00\x01"))
    assert mdns._hostnames == {}


# ── DHCP ──
def dhcp_pkt(src, mac, options, ciaddr="0.0.0.0", yiaddr="0.0.0.0"):
    chaddr = bytes.fromhex(mac.replace(":", ""))
    return wire(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=src, dst="255.255.255.255") / UDP(sport=68, dport=67)
                / BOOTP(chaddr=chaddr, ciaddr=ciaddr, yiaddr=yiaddr) / DHCP(options=options + ["end"]))


def test_dhcp_request_from_0_0_0_0_is_fingerprinted_by_mac_and_requested_ip(dhcp):
    dhcp.feed(dhcp_pkt("0.0.0.0", PHONE_MAC, [("message-type", "request"), ("requested_addr", "192.168.100.235"),
                                             ("hostname", b"OPPO-A78"), ("vendor_class_id", b"android-dhcp-13"),
                                             ("param_req_list", [1, 3, 6, 15, 26, 28, 51, 58, 59, 43])]))
    expected = {"dhcp_hostname": "OPPO-A78", "dhcp_vendor_class": "android-dhcp-13", "dhcp_device_hint": "Android",
                "dhcp_param_list": "1,3,6,15,26,28,51,58,59,43"}
    assert dhcp.get_info("192.168.100.235") == expected
    assert dhcp.get_info_by_mac(PHONE_MAC.upper()) == expected


def test_dhcp_discover_without_an_ip_gets_its_ip_from_the_ack(dhcp):
    dhcp.feed(dhcp_pkt("0.0.0.0", PHONE_MAC, [("message-type", "discover"), ("hostname", b"OPPO-A78")]))
    assert dhcp.get_info_by_mac(PHONE_MAC)["dhcp_hostname"] == "OPPO-A78" and dhcp._info == {}
    dhcp.feed(dhcp_pkt("192.168.100.1", PHONE_MAC, [("message-type", "ack")], yiaddr="192.168.100.235"))
    assert dhcp.get_info("192.168.100.235")["dhcp_hostname"] == "OPPO-A78"


def test_dhcp_renewal_uses_the_client_address(dhcp):
    dhcp.feed(dhcp_pkt("192.168.100.71", "14:13:33:c3:f6:03", [("message-type", "request"), ("vendor_class_id", b"MSFT 5.0")],
                       ciaddr="192.168.100.71"))
    assert dhcp.get_info("192.168.100.71")["dhcp_device_hint"] == "Windows"


def test_dhcp_server_offers_and_other_types_are_ignored(dhcp):
    dhcp.feed(dhcp_pkt("192.168.100.1", PHONE_MAC, [("message-type", "offer"), ("hostname", b"router")], yiaddr="192.168.100.235"))
    assert dhcp._by_mac == {} and dhcp._info == {}


# ── Enrichment ──
def test_enrichment_falls_back_to_the_mac_and_adds_services(mdns, dhcp):
    mdns.feed(mdns6("fe80::10ac:16e0:5fe2:520d", IPAD_MAC, qr=1, aa=1, an=[
        DNSRR(rrname="Jojos-iPad.local.", type="A", rdata="192.168.100.199"),            # announced another time, other IP
        DNSRR(rrname="Jojos-iPad.local.", type="AAAA", rdata="fe80::10ac:16e0:5fe2:520d")]))
    mdns.feed(mdns6("fe80::10ac:16e0:5fe2:520d", IPAD_MAC, qr=0, qd=[DNSQR(qname="_companion-link._tcp.local.", qtype="PTR")]))
    dhcp.feed(dhcp_pkt("0.0.0.0", PHONE_MAC, [("message-type", "discover"), ("vendor_class_id", b"android-dhcp-13")]))

    class Suite:
        pass
    suite = Suite()
    suite.mdns, suite.dhcp = mdns, dhcp
    hosts = [HostRecord(ip="192.168.100.186", mac=IPAD_MAC, hostname=None),
             HostRecord(ip="192.168.100.235", mac=PHONE_MAC, hostname=None, os={"name": "kept"})]
    ipad, phone = enrich_passive_hosts(hosts, suite)
    assert ipad.hostname == "Jojos-iPad"
    assert ipad.os == {"mdns_services": ["_companion-link._tcp"], "mdns_name": "Jojos-iPad"}
    assert phone.os == {"name": "kept", "dhcp_vendor_class": "android-dhcp-13", "dhcp_device_hint": "Android"}


# ── Real traffic (local only) ──
@pytest.mark.skipif(not os.environ.get("EAGLEEYE_TEST_PCAP"), reason="set EAGLEEYE_TEST_PCAP to a local capture")
def test_replay_local_capture(mdns, dhcp):
    from scapy.all import rdpcap
    for pkt in rdpcap(os.environ["EAGLEEYE_TEST_PCAP"]):
        mdns.feed(pkt)
        dhcp.feed(pkt)
    print("names:", mdns._hostnames, "\nby mac:", {m: mdns.get_mac_info(m) for m in mdns._by_mac},
          "\ndhcp:", dhcp._by_mac)
    assert mdns._hostnames or mdns._by_mac or dhcp._by_mac


# ── Where passive listening listens, and this computer's own packets (2.0.1) ──
# Shaped like the PC where scapy's default was a GNS3 KM-TEST loopback adapter with a
# default gateway, listed before Wi-Fi, while Windows routed through Wi-Fi.
LOOP_MAC, WIFI_MAC, VMNET_MAC = "02:00:4c:4f:4f:50", "14:13:33:c3:f6:03", "00:50:56:c0:00:08"
ADAPTERS = [
    {"name": "Ethernet 2", "description": "Microsoft KM-TEST Loopback Adapter #2", "ips": ["142.19.0.1"], "mac": LOOP_MAC},
    {"name": "VMware Network Adapter VMnet8", "description": "VMware Virtual Ethernet Adapter", "ips": ["192.168.217.1"], "mac": VMNET_MAC},
    {"name": "Wi-Fi", "description": "MediaTek MT7921 Wi-Fi 6", "ips": ["192.168.100.71"], "mac": WIFI_MAC},
]


class FakeProbe:
    def __init__(self, route_ip, adapters=ADAPTERS):
        self.route_ip, self.adapters, self.calls = route_ip, list(adapters), 0

    def __call__(self):
        self.calls += 1
        if self.route_ip is None:
            raise OSError("adapter list unavailable")
        return self.route_ip, self.adapters


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_automatic_listens_where_the_os_routes_not_on_a_virtual_adapter():
    chooser = InterfaceChooser(probe=FakeProbe("192.168.100.71"))
    assert chooser.refresh() == "Wi-Fi"
    assert chooser.label == "Wi-Fi (192.168.100.71)"


def test_no_network_yet_waits_then_follows_wifi_when_it_connects():
    # Npcap lists a loopback adapter that really holds 127.0.0.1: never listen there.
    probe, clock = FakeProbe("127.0.0.1", ADAPTERS + [
        {"name": "Npcap Loopback Adapter", "description": "Adapter for loopback traffic capture", "ips": ["127.0.0.1"], "mac": None}]), Clock()
    chooser = InterfaceChooser(probe=probe, clock=clock)
    assert chooser.refresh() is None and chooser.label == "waiting for a network connection"
    probe.route_ip = "192.168.100.71"
    clock.t = 31
    assert chooser.refresh() == "Wi-Fi"


def test_rechecks_every_30_seconds_and_follows_a_switch_to_a_cable():
    probe, clock = FakeProbe("192.168.100.71"), Clock()
    chooser = InterfaceChooser(probe=probe, clock=clock)
    assert chooser.refresh() == "Wi-Fi"
    probe.adapters = ADAPTERS + [{"name": "Ethernet", "description": "Realtek PCIe GbE", "ips": ["10.0.0.5"], "mac": "aa:bb:cc:00:11:22"}]
    probe.route_ip = "10.0.0.5"
    clock.t = 10
    assert chooser.refresh() == "Wi-Fi" and probe.calls == 1        # not asked again yet
    clock.t = 31
    assert chooser.refresh() == "Ethernet" and chooser.label == "Ethernet (10.0.0.5)"
    assert chooser.refresh(force=True) == "Ethernet" and probe.calls == 3


def test_an_interface_set_in_settings_is_kept():
    chooser = InterfaceChooser("Ethernet 2", probe=FakeProbe("192.168.100.71"))
    assert chooser.refresh() == "Ethernet 2"
    assert chooser.label == "Ethernet 2 (set in Settings)"
    assert chooser.is_own(LOOP_MAC)                     # own packets are still recognised


def test_a_failed_adapter_listing_keeps_the_last_choice():
    probe, clock = FakeProbe("192.168.100.71"), Clock()
    chooser = InterfaceChooser(probe=probe, clock=clock)
    chooser.refresh()
    probe.route_ip = None                               # the probe now raises
    clock.t = 31
    assert chooser.refresh() == "Wi-Fi"


def test_own_adapters_are_recognised_in_any_spelling():
    chooser = InterfaceChooser(probe=FakeProbe("192.168.100.71"))
    assert not chooser.is_own(LOOP_MAC)                 # nothing known before the first look
    chooser.refresh()
    assert chooser.is_own("02-00-4C-4F-4F-50") and chooser.is_own(WIFI_MAC.upper()) and chooser.is_own(VMNET_MAC)
    assert not chooser.is_own(IPAD_MAC) and not chooser.is_own(None) and not chooser.is_own("not a mac")


def arp(ip, mac):
    return wire(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=ip, hwsrc=mac, pdst="192.168.100.1"))


def test_sniffers_ignore_this_computers_own_packets():
    chooser = InterfaceChooser(probe=FakeProbe("192.168.100.71"))
    chooser.refresh()
    arp_sniffer = ArpSniffer(chooser=chooser)
    feed = arp_sniffer._make_handler()
    feed(arp("142.19.0.1", LOOP_MAC))                   # the PC's own loopback adapter
    feed(arp("192.168.100.71", WIFI_MAC))               # the PC itself on Wi-Fi
    feed(arp("192.168.100.186", IPAD_MAC))              # a real device
    assert arp_sniffer.pending() == 1

    names = MdnsNetbiosSniffer(chooser=chooser)
    names_feed = names._make_handler()
    names_feed(nbns("142.19.0.1", LOOP_MAC, NBNSHeader(OPCODE=5, RESPONSE=0),
                    NBNSRegistrationRequest(QUESTION_NAME="JOJOCHAW", SUFFIX=0x4141, G=0, NB_ADDRESS="142.19.0.1"), dst="142.19.1.255"))
    assert names.get_hostname("142.19.0.1") is None

    dhcp_sniffer = DhcpSniffer(chooser=chooser)
    dhcp_feed = dhcp_sniffer._make_handler()
    dhcp_feed(dhcp_pkt("0.0.0.0", WIFI_MAC, [("message-type", "request"), ("requested_addr", "192.168.100.71"), ("hostname", b"JoJochaw")]))
    assert dhcp_sniffer.get_info_by_mac(WIFI_MAC) == {}


def test_without_a_chooser_nothing_is_filtered():
    arp_sniffer = ArpSniffer()
    arp_sniffer._make_handler()(arp("142.19.0.1", LOOP_MAC))
    assert arp_sniffer.pending() == 1
