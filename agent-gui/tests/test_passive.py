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
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, UDP, Ether, IPv6, Raw, load_layer  # noqa: E402

load_layer("netbios")
from scapy.layers.netbios import (  # noqa: E402
    NBNS_ADD_ENTRY, NBNSHeader, NBNSNodeStatusResponse, NBNSNodeStatusResponseService,
    NBNSQueryRequest, NBNSQueryResponse, NBNSRegistrationRequest,
)

from eagleeye.passive.sniffers import (  # noqa: E402
    ArpSniffer, DhcpSniffer, InterfaceChooser, MdnsNetbiosSniffer, SsdpSniffer, parse_ssdp,
)
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
    # Only the TXT record in its own answer is something it provides; the rest it looked for.
    assert mdns.get_mac_info(APPLE_MAC)["mdns_offered"] == ["_device-info._tcp"]


def test_a_device_looking_for_a_chromecast_is_not_one(mdns):
    mdns.feed(mdns4("192.168.100.50", PHONE_MAC, qr=0, qd=[DNSQR(qname="_googlecast._tcp.local.", qtype="PTR")]))
    info = mdns.get_mac_info(PHONE_MAC)
    assert info["mdns_services"] == ["_googlecast._tcp"]
    assert "mdns_offered" not in info


def test_a_chromecast_announcing_itself_offers_googlecast(mdns):
    mdns.feed(mdns4("192.168.100.60", TV_MAC, qr=1, aa=1, an=[
        DNSRR(rrname="_googlecast._tcp.local.", type="PTR", rdata="Living-Room-TV._googlecast._tcp.local."),
        DNSRR(rrname="Living-Room-TV._googlecast._tcp.local.", type="TXT", rdata="md=Chromecast")]))
    assert mdns.get_mac_info(TV_MAC)["mdns_offered"] == ["_googlecast._tcp"]


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


# ── SSDP / UPnP ──
TV_MAC = "70:2a:d5:11:22:33"
ROUTER_MAC = "d4:d5:2e:44:55:66"


def ssdp(src, mac, text, dst="239.255.255.250", sport=1900, dport=1900):
    return wire(Ether(src=mac) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=text.replace("\n", "\r\n").encode()))


@pytest.fixture
def upnp():
    sniffer = SsdpSniffer()
    sniffer.feed = sniffer._make_handler()
    return sniffer


def test_parse_ssdp_kinds_and_headers():
    assert parse_ssdp(b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\r\n") == (
        "notify", {"host": "239.255.255.250:1900", "nt": "upnp:rootdevice"})
    assert parse_ssdp(b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\n")[0] == "response"
    assert parse_ssdp(b"M-SEARCH * HTTP/1.1\r\n")[0] == "search"
    assert parse_ssdp(b"GET / HTTP/1.1\r\n") is None


def test_ssdp_notify_records_server_and_device_types(upnp):
    for nt in ("upnp:rootdevice", "uuid:1234", "urn:schemas-upnp-org:device:MediaRenderer:1",
               "urn:dial-multiscreen-org:service:dial:1"):
        upnp.feed(ssdp("192.168.100.60", TV_MAC,
                       f"NOTIFY * HTTP/1.1\nHOST: 239.255.255.250:1900\nNT: {nt}\nNTS: ssdp:alive\n"
                       f"SERVER: Linux/4.4 UPnP/1.0 Samsung SmartTV\nLOCATION: http://192.168.100.60:9197/dmr\n\n"))
    assert upnp.get_mac_info(TV_MAC) == {
        "ssdp_server": "Linux/4.4 UPnP/1.0 Samsung SmartTV",
        "ssdp_types": ["device:MediaRenderer:1", "dial-multiscreen-org:service:dial:1"],
    }
    assert upnp.get_info("192.168.100.60") == upnp.get_mac_info(TV_MAC)


def test_ssdp_answer_to_this_computers_search_counts(upnp):
    upnp.feed(ssdp("192.168.100.1", ROUTER_MAC,
                   "HTTP/1.1 200 OK\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\nSERVER: miniupnpd/2.1\n\n",
                   dst="192.168.100.20", dport=50000))
    assert upnp.get_mac_info(ROUTER_MAC)["ssdp_types"] == ["device:InternetGatewayDevice:1"]


def test_ssdp_searches_say_nothing_about_the_sender(upnp):
    upnp.feed(ssdp("192.168.100.50", PHONE_MAC,
                   "M-SEARCH * HTTP/1.1\nST: urn:dial-multiscreen-org:service:dial:1\nUSER-AGENT: Android/14\n\n"))
    assert upnp.get_mac_info(PHONE_MAC) == {}


def test_ssdp_garbage_is_skipped(upnp):
    upnp.feed(wire(Ether(src=TV_MAC) / IP(src="192.168.100.60", dst="239.255.255.250") / UDP(sport=1900, dport=1900) / Raw(load=b"\xff\xfe")))
    assert upnp.get_mac_info(TV_MAC) == {}


def test_enrichment_adds_ssdp_details(upnp):
    upnp.feed(ssdp("192.168.100.60", TV_MAC,
                   "NOTIFY * HTTP/1.1\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\nSERVER: Roku/12.0 UPnP/1.0\n\n"))

    class Suite:
        mdns = None
        dhcp = None
    suite = Suite()
    suite.ssdp = upnp
    (tv,) = enrich_passive_hosts([HostRecord(ip="192.168.100.60", mac=TV_MAC, hostname=None, os={"name": "kept"})], suite)
    assert tv.os == {"name": "kept", "ssdp_server": "Roku/12.0 UPnP/1.0", "ssdp_types": ["device:MediaRenderer:1"]}


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


def test_hosts_are_discovered_from_their_broadcast_and_multicast_not_only_arp():
    # A quiet Wi-Fi network: only the router ARPs; the other devices are heard only
    # through mDNS, NetBIOS or SSDP until an active scan makes them answer.
    chooser = InterfaceChooser(probe=FakeProbe("192.168.100.71"))
    chooser.refresh()
    hosts = ArpSniffer(chooser=chooser)
    feed = hosts._make_handler()
    feed(arp("192.168.100.1", "98:48:27:cb:55:6c"))
    feed(mdns4("192.168.100.186", IPAD_MAC, qd=DNSQR(qname="_airplay._tcp.local", qtype="PTR")))
    feed(wire(Ether(src=PHONE_MAC, dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.100.50", dst="192.168.100.255")
              / UDP(sport=137, dport=137)))
    feed(wire(Ether(src=APPLE_MAC, dst="01:00:5e:7f:ff:fa") / IP(src="192.168.100.60", dst="239.255.255.250")
              / UDP(sport=50000, dport=1900)))
    feed(mdns4("192.168.100.71", WIFI_MAC, qd=DNSQR(qname="_googlecast._tcp.local", qtype="PTR")))  # the PC itself
    feed(wire(Ether(src="98:48:27:cb:55:6c", dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
              / UDP(sport=67, dport=68)))                                                      # no sender address
    seen = {h.ip: h.mac.lower() for h in hosts.drain()}
    assert seen == {"192.168.100.1": "98:48:27:cb:55:6c", "192.168.100.186": IPAD_MAC,
                    "192.168.100.50": PHONE_MAC, "192.168.100.60": APPLE_MAC}


def test_without_a_chooser_nothing_is_filtered():
    arp_sniffer = ArpSniffer()
    arp_sniffer._make_handler()(arp("142.19.0.1", LOOP_MAC))
    assert arp_sniffer.pending() == 1


# ── 2.2.2: the network hosts were heard on, expiring caches, reverse DNS last ──
from collections import Counter  # noqa: E402

from eagleeye.passive import sniffers  # noqa: E402
from eagleeye.passive.sniffers import ReverseDnsCache  # noqa: E402
from eagleeye.stages.passive import describe_sources  # noqa: E402

CAMPUS_MAC = "9c:09:71:3b:f6:01"


@pytest.fixture(autouse=True)
def fixed_networks(monkeypatch):
    """Networks come from a fake route lookup, never from this computer's own table."""
    nets = {"192.168.100.71": {"local_ip": "192.168.100.71", "subnet": "192.168.100.0/24", "gateway_ip": "192.168.100.1"},
            "10.179.37.235": {"local_ip": "10.179.37.235", "subnet": "10.179.32.0/19", "gateway_ip": "10.179.63.254"}}
    monkeypatch.setattr(sniffers, "_local_network", lambda ip: dict(nets.get(ip, {"local_ip": ip, "subnet": None, "gateway_ip": None})))
    return nets


def campus_adapters():
    return [{"name": "Wi-Fi", "description": "Wi-Fi", "ips": ["10.179.37.235"], "mac": WIFI_MAC}]


def test_the_chooser_knows_the_subnet_and_refuses_addresses_from_elsewhere():
    chooser = InterfaceChooser(probe=FakeProbe("10.179.37.235", campus_adapters()))
    chooser.refresh()
    assert chooser.network == {"local_ip": "10.179.37.235", "subnet": "10.179.32.0/19", "gateway_ip": "10.179.63.254"}
    assert chooser.accepts("10.179.53.238") and chooser.accepts("10.179.63.254")   # a /19, not the /24
    assert not chooser.accepts("172.20.10.6")          # the hotspot address a laptop just left
    assert not chooser.accepts("169.254.15.196")       # self-assigned
    assert not chooser.accepts("not an ip")


def test_without_a_known_subnet_only_self_assigned_addresses_are_refused():
    chooser = InterfaceChooser(probe=FakeProbe("172.31.5.9", [{"name": "Wi-Fi", "ips": ["172.31.5.9"], "mac": WIFI_MAC}]))
    chooser.refresh()
    assert chooser.accepts("10.1.2.3") and not chooser.accepts("169.254.1.1")


def test_an_interface_set_in_settings_takes_the_network_of_its_own_address():
    chooser = InterfaceChooser("Wi-Fi", probe=FakeProbe("192.168.100.71", campus_adapters()))
    chooser.refresh()
    assert chooser.network["subnet"] == "10.179.32.0/19"


def test_hosts_are_kept_per_network_and_a_failed_batch_goes_back():
    probe, clock = FakeProbe("10.179.37.235", campus_adapters()), Clock()
    chooser = InterfaceChooser(probe=probe, clock=clock)
    chooser.refresh()
    hosts = ArpSniffer(chooser=chooser)
    feed = hosts._make_handler()
    feed(arp("10.179.63.254", CAMPUS_MAC))
    feed(arp("172.20.10.6", "10:91:d1:b7:25:78"))     # stale hotspot address: not a host here
    feed(arp("169.254.15.196", "10:91:d1:b7:25:78"))
    probe.route_ip, probe.adapters = "192.168.100.71", ADAPTERS          # the laptop came home
    clock.t = 31
    chooser.refresh()
    feed(arp("192.168.100.186", IPAD_MAC))
    batches = hosts.drain_batches()
    assert [(n["subnet"], [h.ip for h in hs]) for n, hs in batches] == [
        ("10.179.32.0/19", ["10.179.63.254"]), ("192.168.100.0/24", ["192.168.100.186"])]
    assert hosts.pending() == 0
    hosts.restore(*batches[0])
    feed(arp("192.168.100.187", PHONE_MAC))
    again = hosts.drain_batches()
    assert [(n["gateway_ip"], [h.ip for h in hs]) for n, hs in again] == [
        ("10.179.63.254", ["10.179.63.254"]), ("192.168.100.1", ["192.168.100.187"])]


def test_an_address_name_expires_but_the_devices_own_name_wins(mdns):
    clock = Clock()
    mdns._clock = clock
    mdns.feed(mdns4("192.168.100.149", "4a:15:f7:3b:8c:29", qr=1, aa=1,
                    an=[DNSRR(rrname="Jos-iPhone.local.", type="A", rdata="192.168.100.149")]))
    clock.t = 4 * 3600 + 1                             # DHCP may have given the address away
    assert mdns.get_hostname("192.168.100.149") is None
    assert mdns.get_mac_info("4a:15:f7:3b:8c:29")["hostname"] == "Jos-iPhone"
    clock.t = 24 * 3600 + 1
    assert mdns.get_mac_info("4a:15:f7:3b:8c:29") == {}
    mdns._maybe_prune()
    assert mdns._hostnames == {} and mdns._by_mac == {}


def test_a_device_on_a_reused_address_keeps_its_own_name_not_the_old_owners(mdns, dhcp):
    # The old owner announced 192.168.100.50; the address now belongs to a phone that
    # told DHCP its own name.
    mdns.feed(mdns4("192.168.100.50", APPLE_MAC, qr=1, aa=1,
                    an=[DNSRR(rrname="Old-MacBook.local.", type="A", rdata="192.168.100.50")]))
    mdns.feed(mdns4("192.168.100.60", PHONE_MAC, qr=1, aa=1,
                    an=[DNSRR(rrname="Galaxy-S23.local.", type="A", rdata="192.168.100.60")]))

    class Suite:
        pass
    suite = Suite()
    suite.mdns, suite.dhcp = mdns, dhcp
    host = HostRecord(ip="192.168.100.50", mac=PHONE_MAC)
    sources = Counter()
    enrich_passive_hosts([host], suite, sources)
    assert host.hostname == "Galaxy-S23" and sources == Counter(mdns=1)


def test_dhcp_address_links_expire(dhcp):
    clock = Clock()
    dhcp._clock = clock
    dhcp.feed(dhcp_pkt("0.0.0.0", PHONE_MAC, [("message-type", "request"), ("requested_addr", "192.168.100.235"),
                                              ("vendor_class_id", b"android-dhcp-13")]))
    assert dhcp.get_info("192.168.100.235")["dhcp_device_hint"] == "Android"
    assert "_t" not in dhcp.get_info_by_mac(PHONE_MAC)
    clock.t = 4 * 3600 + 1
    assert dhcp.get_info("192.168.100.235") == {}
    assert dhcp.get_info_by_mac(PHONE_MAC)["dhcp_device_hint"] == "Android"


class SlowLookup:
    def __init__(self, names, slow=()):
        self.names, self.slow, self.asked = names, set(slow), []

    def __call__(self, ip):
        self.asked.append(ip)
        if ip in self.slow:
            import time as _t
            _t.sleep(0.5)
        return self.names.get(ip)


def test_reverse_dns_runs_in_parallel_within_a_budget_and_remembers_answers():
    lookup = SlowLookup({"10.0.0.5": "fin-pc07.corp.local", "10.0.0.6": "srv-file01.corp.local"}, slow={"10.0.0.6"})
    clock = Clock()
    rdns = ReverseDnsCache(lookup=lookup, budget=0.2, clock=clock)
    first = rdns.resolve(["10.0.0.5", "10.0.0.6", "10.0.0.7"])
    assert first == {"10.0.0.5": "fin-pc07.corp.local", "10.0.0.7": None}   # .6 was too slow this time
    import time as _t
    _t.sleep(0.6)
    second = rdns.resolve(["10.0.0.5", "10.0.0.6", "10.0.0.7"])
    assert second == {"10.0.0.5": "fin-pc07.corp.local", "10.0.0.6": "srv-file01.corp.local", "10.0.0.7": None}
    assert sorted(lookup.asked) == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]     # each asked once
    clock.t = 3601
    rdns.resolve(["10.0.0.7"])
    assert lookup.asked.count("10.0.0.7") == 2                              # asked again after an hour
    rdns.shutdown()


def test_reverse_dns_is_asked_only_for_hosts_no_sniffer_named(mdns):
    mdns.feed(mdns4("192.168.100.149", "4a:15:f7:3b:8c:29", qr=1, aa=1,
                    an=[DNSRR(rrname="Jos-iPhone.local.", type="A", rdata="192.168.100.149")]))
    lookup = SlowLookup({"192.168.100.10": "printer-2f.corp.local"})

    class Suite:
        pass
    suite = Suite()
    suite.mdns, suite.dhcp, suite.rdns = mdns, None, ReverseDnsCache(lookup=lookup, budget=1)
    hosts = [HostRecord(ip="192.168.100.149", mac="4a:15:f7:3b:8c:29"), HostRecord(ip="192.168.100.10"),
             HostRecord(ip="192.168.100.11")]
    sources = Counter()
    enrich_passive_hosts(hosts, suite, sources)
    assert [h.hostname for h in hosts] == ["Jos-iPhone", "printer-2f.corp.local", None]
    assert sorted(lookup.asked) == ["192.168.100.10", "192.168.100.11"]
    assert describe_sources(sources) == "names: mDNS 1, reverse DNS 1, none 1"
    suite.rdns.shutdown()


# ── 2.2.3: platform default names rank last; DHCP names in any language ──
from eagleeye.hostnames import is_generic_hostname  # noqa: E402

OPPO_MAC = "b8:c9:b5:bf:81:f9"


def _suite(mdns=None, dhcp=None, rdns=None):
    class Suite:
        pass
    suite = Suite()
    suite.mdns, suite.dhcp = mdns, dhcp
    if rdns is not None:
        suite.rdns = rdns
    return suite


def test_a_dhcp_name_beats_androids_default_mdns_name(mdns, dhcp):
    # Seen on the home network: the router listed OPPO-A31, EagleEye said "Android".
    mdns.feed(mdns4("192.168.0.141", OPPO_MAC, qr=1, aa=1,
                    an=[DNSRR(rrname="Android.local.", type="A", rdata="192.168.0.141")]))
    dhcp.feed(dhcp_pkt("0.0.0.0", OPPO_MAC, [("message-type", "request"), ("requested_addr", "192.168.0.141"),
                                             ("hostname", b"OPPO-A31")]))
    host = HostRecord(ip="192.168.0.141", mac=OPPO_MAC)
    sources = Counter()
    enrich_passive_hosts([host], _suite(mdns, dhcp), sources)
    assert host.hostname == "OPPO-A31" and sources == Counter(dhcp=1)


def test_a_default_name_is_kept_when_nothing_better_is_known_and_reverse_dns_is_asked(mdns):
    mdns.feed(mdns4("192.168.0.180", "6e:dc:c8:20:6c:e8", qr=1, aa=1,
                    an=[DNSRR(rrname="Android.local.", type="A", rdata="192.168.0.180")]))
    mdns.feed(mdns4("10.0.0.20", "6e:dc:c8:20:6c:e9", qr=1, aa=1,
                    an=[DNSRR(rrname="Android.local.", type="A", rdata="10.0.0.20")]))
    lookup = SlowLookup({"10.0.0.20": "sales-tab-03.corp.local"})
    rdns = ReverseDnsCache(lookup=lookup, budget=1)
    home = HostRecord(ip="192.168.0.180", mac="6e:dc:c8:20:6c:e8")
    office = HostRecord(ip="10.0.0.20", mac="6e:dc:c8:20:6c:e9")
    sources = Counter()
    enrich_passive_hosts([home, office], _suite(mdns, rdns=rdns), sources)
    assert home.hostname == "Android"                       # nothing better: the default stays
    assert office.hostname == "sales-tab-03.corp.local"     # the office DNS knew its real name
    assert sorted(lookup.asked) == ["10.0.0.20", "192.168.0.180"]
    assert sources == Counter(mdns=1, rdns=1)
    rdns.shutdown()


def test_a_specific_mdns_name_still_beats_dhcp(mdns, dhcp):
    mdns.feed(mdns4("192.168.0.190", "7c:61:30:38:96:02", qr=1, aa=1,
                    an=[DNSRR(rrname="Jojos-iPad.local.", type="A", rdata="192.168.0.190")]))
    dhcp.feed(dhcp_pkt("0.0.0.0", "7c:61:30:38:96:02", [("message-type", "request"),
                                                        ("requested_addr", "192.168.0.190"), ("hostname", b"iPad")]))
    host = HostRecord(ip="192.168.0.190", mac="7c:61:30:38:96:02")
    enrich_passive_hosts([host], _suite(mdns, dhcp))
    assert host.hostname == "Jojos-iPad"


@pytest.mark.parametrize("raw, expected", [
    ("庄某某的电脑".encode("utf-8"), "庄某某的电脑"),          # UTF-8 (Chinese)
    ("Café-TV".encode("utf-8"), "Café-TV"),
    ("Café-TV".encode("latin-1"), "Café-TV"),               # not UTF-8: read as Latin-1, never dropped
    (b"OPPO-A31\x00\x00", "OPPO-A31"),                      # NUL padding
])
def test_dhcp_names_keep_every_character(dhcp, raw, expected):
    dhcp.feed(dhcp_pkt("0.0.0.0", PHONE_MAC, [("message-type", "request"), ("requested_addr", "192.168.0.50"),
                                              ("hostname", raw)]))
    assert dhcp.get_info("192.168.0.50")["dhcp_hostname"] == expected


@pytest.mark.parametrize("name", ["Android", "Android-2", "ANDROID.local", "android-83f59958ba7e18a1", "iPhone", "iPhone-3", "iPad",
                                  "localhost", "MacBook-Pro", "7dff5f02-7c94-4a60-b5ee-ef77df02d62a"])
def test_platform_defaults_are_generic(name):
    assert is_generic_hostname(name)


@pytest.mark.parametrize("name", ["OPPO-A31", "Galaxy-A14-5G", "Jojos-iPad", "zhuangmojoyang", "android-tv",
                                  "KHZ4-4D50ED-11834F4F", "", None])
def test_real_names_are_not_generic(name):
    assert not is_generic_hostname(name)



# ── 2.2.4: virtual adapters, and saying when listening resumes ──
def test_when_wifi_drops_it_waits_instead_of_listening_on_the_gns3_loopback():
    # Seen on the campus Wi-Fi: Windows routed through "Ethernet 2" (KM-TEST loopback,
    # 142.19.0.1) for 13 minutes while Wi-Fi was down, and nothing was heard there.
    probe, clock = FakeProbe("192.168.100.71"), Clock()
    chooser = InterfaceChooser(probe=probe, clock=clock)
    assert chooser.refresh() == "Wi-Fi"
    probe.route_ip = "142.19.0.1"
    clock.t = 31
    assert chooser.refresh() is None and chooser.label == "waiting for a network connection"
    probe.route_ip = "192.168.100.71"
    clock.t = 62
    assert chooser.refresh() == "Wi-Fi"


def test_a_vpn_is_still_followed():
    vpn = ADAPTERS + [{"name": "OpenVPN Data Channel Offload", "description": "OpenVPN Data Channel Offload",
                       "ips": ["10.8.0.6"], "mac": "aa:bb:cc:dd:ee:01"}]
    assert InterfaceChooser(probe=FakeProbe("10.8.0.6", vpn)).refresh() == "OpenVPN Data Channel Offload"


def test_a_sniffer_says_when_it_listens_again(monkeypatch, caplog):
    import scapy.all as scapy_mod
    calls = {"n": 0}
    sniffer = ArpSniffer(interface="Wi-Fi")

    def fake_sniff(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("Network interface was not found")
        sniffer._stop.set()                         # one good slice, then stop

    monkeypatch.setattr(scapy_mod, "sniff", fake_sniff)
    monkeypatch.setattr(sniffer._stop, "wait", lambda timeout=None: False)
    with caplog.at_level("INFO", logger="eagleeye.passive"):
        sniffer._loop()
    text = caplog.text
    assert "cannot listen on Wi-Fi" in text and "listening on Wi-Fi again" in text
