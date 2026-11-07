"""Built-in capture (no Npcap): the frame rules that stand in for each sniffer's BPF
filter, the Linux kernel filter, Wi-Fi frames from Microsoft's capture driver, and the
hub that feeds the existing sniffers. The end-to-end tests send frames built with
scapy through the hub into the real sniffers and check they learn what they learn from
Npcap."""

from __future__ import annotations

import random
import struct
import threading

import pytest

pytest.importorskip("scapy.all")
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, LLC, SNAP, TCP, UDP, Dot11, Dot11QoS, Ether, IPv6  # noqa: E402
from scapy.layers.inet6 import IPv6ExtHdrHopByHop  # noqa: E402

from eagleeye.passive import capture, frames  # noqa: E402
from eagleeye.passive.capture import CaptureHub, PacketSocketSource, as_ethernet, parse_fragment, resolve_backend  # noqa: E402
from eagleeye.passive.sniffers import InterfaceChooser, PassiveSuite  # noqa: E402

PC_MAC, ROUTER_MAC, PHONE_MAC, TV_MAC = "14:13:33:c3:f6:03", "98:48:27:cb:55:6c", "c4:fe:5b:a9:44:05", "8c:79:f5:00:11:22"
BCAST, MDNS_MAC = "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb"


def arp_frame(ip=b"", mac=ROUTER_MAC):
    return bytes(Ether(src=mac, dst=BCAST) / ARP(op=1, hwsrc=mac, psrc=ip or "192.168.0.1", pdst="192.168.0.139"))


def mdns_frame(ip="192.168.0.174", mac=PHONE_MAC, name="HUAWEI-P30.local"):
    return bytes(Ether(src=mac, dst=MDNS_MAC) / IP(src=ip, dst="224.0.0.251") / UDP(sport=5353, dport=5353)
                 / DNS(qr=1, aa=1, an=[DNSRR(rrname=name, type="A", rdata=ip)]))


def dhcp_frame(mac=PHONE_MAC, requested="192.168.0.174"):
    return bytes(Ether(src=mac, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
                 / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")) + b"\0" * 10, xid=1)
                 / DHCP(options=[("message-type", "request"), ("requested_addr", requested),
                                 ("hostname", b"HUAWEI_P30"), ("param_req_list", [1, 3, 6, 15]), "end"]))


def ssdp_frame(ip="192.168.0.60", mac=TV_MAC):
    body = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n"
            b"SERVER: Linux/4.4 UPnP/1.0 Samsung SmartTV\r\nLOCATION: http://192.168.0.60:9197/dmr\r\n\r\n")
    return bytes(Ether(src=mac, dst="01:00:5e:7f:ff:fa") / IP(src=ip, dst="239.255.255.250")
                 / UDP(sport=50000, dport=1900) / body)


def corpus() -> list[bytes]:
    """Frames each rule must get right, plus cut-off and random ones."""
    uni = dict(src=PHONE_MAC, dst=PC_MAC)
    out = [
        arp_frame(), mdns_frame(), dhcp_frame(), ssdp_frame(),
        bytes(Ether(**uni) / IP(src="192.168.0.1", dst="192.168.0.139") / UDP(sport=67, dport=68)),       # DHCP ack
        bytes(Ether(**uni) / IP(src="192.168.0.5", dst="192.168.0.139") / UDP(sport=5353, dport=40000)),  # unicast mDNS answer
        bytes(Ether(**uni) / IP(src="192.168.0.5", dst="192.168.0.139") / UDP(sport=40000, dport=137)),
        bytes(Ether(**uni) / IP(src="192.168.0.5", dst="192.168.0.139") / TCP(sport=443, dport=5353)),    # TCP: no
        bytes(Ether(**uni) / IP(src="192.168.0.5", dst="192.168.0.139") / UDP(sport=53, dport=40000)),    # DNS: no
        bytes(Ether(**uni) / IP(src="192.168.0.5", dst="192.168.0.139", options=b"\x94\x04\x00\x00")    # IP options
              / UDP(sport=1900, dport=40000)),
        bytes(Ether(**uni) / IP(src="192.168.0.5", dst="192.168.0.139", proto=17, frag=10) / (b"\x14\xe9" * 8)),  # later fragment
        bytes(Ether(src=PHONE_MAC, dst=BCAST) / IP(src="192.168.0.5", dst="192.168.0.255") / TCP()),      # broadcast, not UDP
        bytes(Ether(src=PHONE_MAC, dst="33:33:00:00:00:fb") / IPv6(src="fe80::1", dst="ff02::fb") / UDP(sport=5353, dport=5353)),
        bytes(Ether(src=PHONE_MAC, dst="33:33:00:00:00:0c") / IPv6(src="fe80::1", dst="ff02::c") / UDP(sport=40000, dport=1900)),
        bytes(Ether(src=PHONE_MAC, dst="33:33:00:00:00:01") / IPv6(src="fe80::1", dst="ff02::1") / TCP(dport=5353)),
        bytes(Ether(src=PHONE_MAC, dst="33:33:00:00:00:fb") / IPv6(src="fe80::1", dst="ff02::fb") / IPv6ExtHdrHopByHop()
              / UDP(sport=5353, dport=5353)),                                                             # extension header: no
        bytes.fromhex("ffffffffffff" + PHONE_MAC.replace(":", "") + "8100" + "0001" + "0806") + b"\0" * 28,  # VLAN: no
        bytes(Ether(**uni) / IP(src="192.168.0.5", dst="192.168.0.139", proto=17, frag=0x1000) / (b"\x14\xe9" * 8)),  # offset 32768
        bytes(Ether(**uni) / IP(src="192.168.0.5", dst="192.168.0.139", flags="MF") / UDP(sport=5353, dport=40000)),  # first fragment
        bytes(Ether(src=PHONE_MAC, dst=PC_MAC) / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=5353, dport=40000)),
        bytes(Ether(**uni) / IP(src="192.168.0.5", dst="192.168.0.139") / UDP(sport=68, dport=40000)),
        bytes(Ether(**uni) / IP(src="192.168.0.60", dst="192.168.0.139") / UDP(sport=1900, dport=40000)),  # SSDP answer
    ]
    for whole in (mdns_frame(), dhcp_frame(), out[13]):
        out += [whole[:n] for n in range(len(whole))]
    rnd = random.Random(7)
    for _ in range(300):
        frame = bytearray(rnd.randbytes(rnd.randrange(10, 80)))
        if len(frame) >= 14 and rnd.random() < 0.7:
            frame[12:14] = rnd.choice((b"\x08\x00", b"\x86\xdd", b"\x08\x06"))
        if len(frame) >= 24 and rnd.random() < 0.5:
            frame[23 if frame[12:14] == b"\x08\x00" else 20 % len(frame)] = 17
        out.append(bytes(frame))
    return out


# ── frame rules ──────────────────────────────────────────────────────────────

def test_each_sniffer_gets_what_its_bpf_filter_lets_through():
    assert frames.arp_or_broadcast(arp_frame()) and frames.arp_or_broadcast(mdns_frame())
    assert frames.arp_or_broadcast(ssdp_frame()) and frames.arp_or_broadcast(dhcp_frame())
    assert not frames.arp_or_broadcast(corpus()[4])                 # unicast to this computer
    assert frames.mdns_or_netbios(mdns_frame()) and not frames.mdns_or_netbios(dhcp_frame())
    assert frames.mdns_or_netbios(corpus()[6]) and frames.mdns_or_netbios(corpus()[12])   # NetBIOS; mDNS over IPv6
    assert frames.dhcp(dhcp_frame()) and frames.dhcp(corpus()[4]) and not frames.dhcp(ssdp_frame())
    assert frames.ssdp(ssdp_frame()) and frames.ssdp(corpus()[9]) and frames.ssdp(corpus()[13])
    assert not frames.ssdp(mdns_frame())


def test_rules_skip_tcp_later_fragments_extension_headers_vlans_and_scraps():
    c = corpus()
    for frame in (c[7], c[8], c[10], c[14], c[15], c[16]):
        assert not (frames.mdns_or_netbios(frame) or frames.dhcp(frame) or frames.ssdp(frame))
    assert frames.udp_ports(c[9]) == (1900, 40000)                   # IP options shift the UDP header
    assert frames.udp_ports(b"") is None and frames.udp_ports(mdns_frame()[:37]) is None
    assert frames.udp_ports(mdns_frame()[:38]) == (5353, 5353)       # 14 + 20 + 4: both ports


def test_fragments_and_unicast_answers():
    c = corpus()
    assert not frames.mdns_or_netbios(c[17]) and not frames.run_filter(frames.kernel_filter(), c[17])
    assert frames.mdns_or_netbios(c[18]) and frames.mdns_or_netbios(c[19])    # first fragment; IPv6 answer
    assert frames.dhcp(c[20]) and frames.ssdp(c[21])


def test_the_kernel_filter_keeps_everything_any_sniffer_wants():
    program = frames.kernel_filter()
    rules = (frames.arp_or_broadcast, frames.mdns_or_netbios, frames.dhcp, frames.ssdp)
    for frame in corpus():
        if any(rule(frame) for rule in rules):
            assert frames.wanted(frame) and frames.run_filter(program, frame), frame.hex()


def test_the_kernel_filter_agrees_with_the_rules_on_every_frame():
    program = frames.kernel_filter()
    checked = wanted = 0
    for frame in corpus():
        got = frames.run_filter(program, frame)
        assert bool(got) == frames.wanted(frame), frame.hex()
        assert got in (0, frames.ACCEPT_BYTES)
        checked += 1
        wanted += bool(got)
    assert checked > 500 and 20 < wanted < checked - 100            # the corpus has both kinds


def test_the_kernel_filter_is_valid_classic_bpf():
    program = frames.kernel_filter()
    assert len(program) < 64
    for i, (code, jt, jf, k) in enumerate(program):
        assert code in (frames.LD_H_ABS, frames.LD_B_ABS, frames.LD_H_IND, frames.LDX_B_MSH,
                        frames.JEQ, frames.JSET, frames.RET)
        if code in (frames.JEQ, frames.JSET):
            assert i + 1 + max(jt, jf) < len(program)                # every jump lands inside
        else:
            assert jt == jf == 0
    assert program[-1] == (frames.RET, 0, 0, frames.ACCEPT_BYTES) and len(struct.pack("HBBI", *program[0])) == 8


# ── Microsoft's capture driver ───────────────────────────────────────────────

def test_ndis_fragment_event_payload():
    frame = mdns_frame()
    data = struct.pack("<III", 2, 2, len(frame)) + frame
    assert parse_fragment(data) == (2, 2, frame)
    assert parse_fragment(struct.pack("<III", 2, 7, 10) + frame[:10] + b"padding") == (2, 7, frame[:10])
    assert parse_fragment(b"\x02\0\0\0") is None and parse_fragment(struct.pack("<III", 2, 2, 0)) is None


@pytest.mark.parametrize("qos", [False, True])
def test_wifi_frames_from_the_driver_become_the_ethernet_frames_npcap_sees(qos):
    ip_part = IP(src="192.168.0.174", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="x.local"))
    # A phone's multicast as the router relays it to this computer (from the access point).
    head = Dot11(type=2, subtype=8 if qos else 0, FCfield=0x02, addr1=MDNS_MAC, addr2=ROUTER_MAC, addr3=PHONE_MAC)
    wifi = bytes((head / Dot11QoS() if qos else head) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(code=0x0800) / ip_part)
    expected = bytes(Ether(dst=MDNS_MAC, src=PHONE_MAC) / ip_part)
    assert as_ethernet(wifi) == expected
    assert as_ethernet(expected) == expected                         # an Ethernet adapter's frame is kept


def test_a_frame_sent_by_this_computer_over_wifi_takes_the_sender_from_addr2():
    ip_part = IP(src="192.168.0.139", dst="192.168.0.1") / UDP(sport=68, dport=67)
    wifi = bytes(Dot11(type=2, FCfield=0x01, addr1=ROUTER_MAC, addr2=PC_MAC, addr3=ROUTER_MAC)
                 / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(code=0x0800) / ip_part)
    assert as_ethernet(wifi) == bytes(Ether(dst=ROUTER_MAC, src=PC_MAC) / ip_part)


# ── which capture ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("setting, platform, npcap, expected", [
    ("auto", "win32", True, "npcap"),          # what the agent always used, where installed
    ("auto", "win32", False, "ndis"),
    ("native", "win32", True, "ndis"),
    ("npcap", "win32", False, "npcap"),
    ("auto", "linux", False, "packet"),
    ("native", "linux", False, "packet"),
    ("npcap", "linux", False, "npcap"),
    ("auto", "darwin", False, "npcap"),        # libpcap is all macOS has
    ("native", "darwin", False, "npcap"),
])
def test_backend_choice(setting, platform, npcap, expected):
    assert resolve_backend(setting, platform, lambda: npcap) == expected


# ── the hub and the sniffers ─────────────────────────────────────────────────

ADAPTERS = [
    {"name": "VMware Network Adapter VMnet8", "description": "VMware Virtual Ethernet Adapter",
     "ips": ["192.168.217.1"], "mac": "00:50:56:c0:00:08", "index": 21},
    {"name": "Wi-Fi", "description": "MediaTek MT7921 Wi-Fi 6", "ips": ["192.168.0.139"], "mac": PC_MAC, "index": 2},
]


def chooser():
    return InterfaceChooser(probe=lambda: ("192.168.0.139", ADAPTERS),
                            network_of=lambda ip: {"local_ip": ip, "subnet": "192.168.0.0/24", "gateway_ip": "192.168.0.1"})


class FakeSource:
    name = "fake capture"

    def __init__(self, opens=True):
        self.opens, self.error, self.selected, self.opened, self.closed = opens, None, [], 0, 0
        self.selected_event = threading.Event()
        self.end_session = False

    def open(self, deliver):
        self.opened += 1
        self.deliver = deliver
        if not self.opens:
            self.error = "requires Administrator"
        return self.opens

    def select(self, adapter):
        self.selected.append(adapter)
        self.selected_event.set()

    def pump(self, stop, seconds):
        if self.end_session:
            self.end_session = False
            return False
        stop.wait(0.01)
        return True

    def close(self):
        self.closed += 1


def test_the_chooser_knows_the_index_of_the_adapter_it_picked():
    c = chooser()
    assert c.refresh() == "Wi-Fi" and c.index == 2
    fixed = InterfaceChooser("VMware Network Adapter VMnet8", probe=lambda: ("192.168.0.139", ADAPTERS))
    assert fixed.refresh() == "VMware Network Adapter VMnet8" and fixed.index == 21


def test_hub_decodes_once_and_gives_each_sniffer_only_what_it_wants():
    decoded, got = [], {"arp": [], "mdns": [], "bad": []}
    hub = CaptureHub(FakeSource(), chooser(), decode=lambda f: decoded.append(f) or f)
    arp_handler = got["arp"].append
    hub.add(frames.arp_or_broadcast, arp_handler)
    hub.add(frames.mdns_or_netbios, got["mdns"].append)

    def bad(pkt):
        got["bad"].append(pkt)
        raise ValueError("broken parser")
    hub.add(frames.mdns_or_netbios, bad)
    tcp = bytes(Ether(src=PHONE_MAC, dst=PC_MAC) / IP() / TCP())
    for frame in (arp_frame(), mdns_frame(), tcp):
        hub.deliver(frame)
    assert got["arp"] == [arp_frame(), mdns_frame()] and got["mdns"] == [mdns_frame()] == got["bad"]
    assert decoded == [arp_frame(), mdns_frame()]                    # TCP never decoded; mDNS once
    assert (hub.frames, hub.dispatched) == (3, 2)
    hub.remove(arp_handler)                                          # a stopped sniffer gets nothing
    hub.deliver(arp_frame())
    assert len(got["arp"]) == 2


def test_hub_listens_on_the_chosen_adapter_and_reopens_an_ended_session():
    source = FakeSource()
    hub = CaptureHub(source, chooser())
    assert hub.start() and hub.label == "fake capture"
    assert source.selected_event.wait(2)
    assert source.selected[0] == {"name": "Wi-Fi", "index": 2}
    source.end_session = True                                        # e.g. someone ran logman stop
    for _ in range(200):
        if source.opened == 2:
            break
        threading.Event().wait(0.01)
    hub.stop()
    hub._thread.join(2)
    assert source.opened == 2 and source.closed >= 2 and not hub.running


def test_suite_with_the_built_in_capture_learns_what_npcap_would_have_given():
    hubs = []

    def make_hub(name, ch):
        hubs.append(CaptureHub(FakeSource(), ch))
        return hubs[0]
    suite = PassiveSuite(chooser=chooser(), backend="native", make_hub=make_hub)
    assert suite.backend in ("ndis", "packet")
    assert suite.start() and suite.capture == "fake capture"
    try:
        suite.chooser.refresh()
        hub = hubs[0]
        for frame in (arp_frame(), mdns_frame(), dhcp_frame(), ssdp_frame(),
                      mdns_frame(ip="192.168.0.139", mac=PC_MAC, name="THIS-PC.local")):   # the PC itself
            hub.deliver(frame)
        seen = {h.ip: h.mac.lower() for h in suite.arp.drain()}
        assert seen == {"192.168.0.1": ROUTER_MAC, "192.168.0.174": PHONE_MAC, "192.168.0.60": TV_MAC}
        assert suite.mdns.get_hostname("192.168.0.174") == "HUAWEI-P30"
        assert suite.mdns.get_hostname("192.168.0.139") is None
        assert suite.dhcp.get_info_by_mac(PHONE_MAC)["dhcp_hostname"] == "HUAWEI_P30"
        assert "Samsung SmartTV" in str(suite.ssdp.get_mac_info(TV_MAC))
        assert all(s.running for s in (suite.arp, suite.mdns, suite.dhcp, suite.ssdp))
    finally:
        suite.stop()
    assert not suite.arp.running and hub._sniffers == []


def test_suite_reports_why_the_built_in_capture_did_not_start():
    suite = PassiveSuite(chooser=chooser(), backend="native",
                         make_hub=lambda name, ch: CaptureHub(FakeSource(opens=False), ch))
    assert not suite.start() and suite.arp is None
    assert suite.problems() == ["fake capture: requires Administrator"]


def test_npcap_backend_leaves_the_sniffers_on_their_own_capture():
    suite = PassiveSuite(chooser=chooser(), backend="npcap", make_hub=lambda *a: pytest.fail("no hub for Npcap"))
    assert suite.backend == "npcap" and suite.hub is None and suite.capture == "Npcap/libpcap"


# ── Linux packet socket (with a fake socket) ─────────────────────────────────

class FakeSocket:
    def __init__(self, packets, fail_bind=False):
        self.packets, self.bound, self.closed, self.fail_bind = list(packets), None, False, fail_bind

    def bind(self, addr):
        if self.fail_bind:
            raise OSError("No such device")
        self.bound = addr

    def recvfrom(self, size):
        if not self.packets:
            raise capture.socket.timeout()
        return self.packets.pop(0)

    def close(self):
        self.closed = True


def test_packet_socket_binds_the_adapter_and_skips_this_computers_own_frames():
    made = []

    def make():
        made.append(FakeSocket([(arp_frame(), ("ens33", 0x0806, 0, 1)),
                                (mdns_frame(ip="142.19.0.10", mac=PC_MAC), ("ens33", 0x0800, capture.PACKET_OUTGOING, 1)),
                                (mdns_frame(), ("ens33", 0x0800, 2, 1))]))
        return made[-1]
    src = PacketSocketSource(make)
    got = []
    assert src.open(got.append) and made[0].closed                  # the permission check
    src.select({"name": "ens33", "index": 2})
    assert made[1].bound == ("ens33", 0)
    src.select({"name": "ens33", "index": 2})                        # unchanged: same socket
    assert len(made) == 2
    stop = threading.Event()
    assert src.pump(stop, 0.05)
    assert got == [arp_frame(), mdns_frame()]
    src.select({"name": "ens34"})                                    # moved: a new socket
    assert made[1].closed and made[2].bound == ("ens34", 0)
    src.select(None)                                                 # no network: none
    assert made[2].closed and src.pump(stop, 0.01)


def test_packet_socket_says_it_needs_root():
    def make():
        raise PermissionError(1, "Operation not permitted")
    src = PacketSocketSource(make)
    assert not src.open(lambda f: None) and "root" in src.error


def test_packet_socket_survives_an_adapter_that_is_gone():
    src = PacketSocketSource(lambda: FakeSocket([], fail_bind=True))
    assert src.open(lambda f: None)
    src.select({"name": "wlan0"})
    assert src._sock is None and src.pump(threading.Event(), 0.01)


# ── listen --compare ─────────────────────────────────────────────────────────

def test_compare_lines_up_what_each_capture_learned():
    from eagleeye.passive import compare
    a = {"hosts": {"192.168.0.1": ROUTER_MAC, "192.168.0.174": PHONE_MAC}, "names": {"192.168.0.174": "HUAWEI-P30"},
         "dhcp": [PHONE_MAC], "ssdp": []}
    b = {"hosts": {"192.168.0.1": ROUTER_MAC, "192.168.0.60": TV_MAC}, "names": {"192.168.0.174": "HUAWEI-P30"},
         "dhcp": [PHONE_MAC], "ssdp": [TV_MAC]}
    rows = compare.side_by_side(a, b)
    assert rows["hosts"] == {"npcap": 2, "built_in": 2, "both": 1,
                             "only_npcap": [str(("192.168.0.174", PHONE_MAC))],
                             "only_built_in": [str(("192.168.0.60", TV_MAC))]}
    assert rows["names"]["both"] == 1 and rows["dhcp"]["both"] == 1 and rows["ssdp"]["only_built_in"] == [TV_MAC]


def test_compare_reads_what_a_suites_sniffers_know():
    from eagleeye.passive import compare
    hub = CaptureHub(FakeSource(), chooser())
    suite = PassiveSuite(chooser=chooser(), backend="native", make_hub=lambda name, ch: hub)
    assert suite.start()
    try:
        suite.chooser.refresh()
        for frame in (arp_frame(), mdns_frame(), dhcp_frame(), ssdp_frame()):
            hub.deliver(frame)
        got = compare.learned(suite)
    finally:
        suite.stop()
    assert got == {"hosts": {"192.168.0.1": ROUTER_MAC, "192.168.0.174": PHONE_MAC, "192.168.0.60": TV_MAC},
                   "names": {"192.168.0.174": "HUAWEI-P30"}, "dhcp": [PHONE_MAC], "ssdp": [TV_MAC]}


def test_thread_cpu_is_measured_per_named_thread():
    from eagleeye.passive import compare
    stop = threading.Event()

    def busy():
        while not stop.is_set():
            sum(range(1000))
    t = threading.Thread(target=busy, name="capture-hub", daemon=True)
    t.start()
    try:
        threading.Event().wait(0.3)
        used = compare.thread_cpu_seconds(("capture-hub",))
        assert used is not None and used > 0.05
        assert compare.thread_cpu_seconds(("no-such-thread",)) == 0
    finally:
        stop.set()
        t.join()


def test_the_capture_stops_when_no_sniffer_could_start(monkeypatch):
    from eagleeye.passive import sniffers
    monkeypatch.setattr(sniffers._Sniffer, "start", lambda self: False)        # e.g. scapy missing
    hub = CaptureHub(FakeSource(), chooser())
    suite = PassiveSuite(chooser=chooser(), backend="native", make_hub=lambda name, ch: hub)
    assert not suite.start()
    hub._thread.join(2)
    assert not hub.running and hub.source.closed == 1


# ── without scapy (the default package) ──────────────────────────────────────

def test_automatic_needs_scapy_to_use_npcap():
    assert resolve_backend("auto", "win32", lambda: True, lambda: False) == "ndis"
    assert resolve_backend("auto", "win32", lambda: True, lambda: True) == "npcap"


def test_the_built_in_path_runs_with_scapy_missing():
    # A fresh interpreter in which every scapy import fails, as in the package.
    import subprocess
    import sys
    code = (
        "import sys; sys.modules['scapy'] = None\n"
        "from tests.test_capture_noscapy import run; run()\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.strip().endswith("ok")
