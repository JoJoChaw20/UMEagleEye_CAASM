"""Threat sightings (eagleeye/sightings): the DNS-answer capture filter, reading answers,
the local threat list and its sync, the connection tables of each system, counting
matches, and the monitor that uploads only matches."""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import struct

import pytest

from eagleeye.api import AgentClient
from eagleeye.passive import decode, frames
from eagleeye.sightings import connections, dns
from eagleeye.sightings.connections import Conn
from eagleeye.sightings.indicators import EVENTS_EVERY, FEEDS_EVERY, FULL_EVERY, RETRY_AFTER, IndicatorList, ListSync
from eagleeye.sightings.monitor import SightingsMonitor
from eagleeye.sightings.recorder import HitRecorder

AGENT = "11111111-1111-4111-8111-111111111111"


# ── building packets ─────────────────────────────────────────────────────────
def _qname(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_answer_msg(name: str, cname: str | None = None, a: str | None = None, qr: int = 1) -> bytes:
    """A DNS response: the question, an optional CNAME (owner by pointer to the question) and an A record."""
    answers = []
    if cname:
        answers.append(b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(_qname(cname))) + _qname(cname))
    if a:
        answers.append(b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ipaddress.IPv4Address(a).packed)
    header = struct.pack(">HHHHHH", 0x1234, (qr << 15) | 0x0180, 1, len(answers), 0, 0)
    return header + _qname(name) + struct.pack(">HH", 1, 1) + b"".join(answers)


def udp_frame(payload: bytes, sport: int, dport: int, v6: bool = False, proto: int = 17) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
    if v6:
        ip = struct.pack(">IHBB", 0x60000000, len(udp), proto, 64) + ipaddress.IPv6Address("2001:4860::1").packed \
            + ipaddress.IPv6Address("2001:db8::2").packed
        return eth + b"\x86\xdd" + ip + udp
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, proto, 0,
                     ipaddress.IPv4Address("8.8.8.8").packed, ipaddress.IPv4Address("192.168.1.20").packed)
    return eth + b"\x08\x00" + ip + udp


# ── capture filter ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("v6", [False, True])
def test_only_dns_answers_pass_and_the_kernel_filter_agrees(v6):
    program = frames.dns_kernel_filter()
    msg = dns_answer_msg("example.org", a="93.184.216.34")
    cases = [
        (udp_frame(msg, 53, 51000, v6), True),          # an answer
        (udp_frame(msg, 51000, 53, v6), False),         # a question this computer sent
        (udp_frame(msg, 5353, 5353, v6), False),        # mDNS
        (udp_frame(msg, 53, 51000, v6, proto=6), False),  # not UDP
    ]
    for frame, want in cases:
        assert frames.dns_answer(frame) is want
        assert (frames.run_filter(program, frame) > 0) is want
        assert frames.run_filter(program, frame[:30]) == 0 or want is False or v6


def test_cname_targets_are_names_now():
    msg = decode.dns(dns_answer_msg("www.example.org", cname="cdn.bad.example.net", a="93.184.216.34"))
    assert msg is not None
    cname = [rr for rr in msg.an if rr.type == 5][0]
    assert cname.rdata == b"cdn.bad.example.net."


# ── which adapter ────────────────────────────────────────────────────────────
def test_dns_answers_are_heard_on_every_adapter_and_on_macos_on_the_default_route():
    from eagleeye.passive.capture import ANY, ANY_INDEX
    from eagleeye.sightings.monitor import DnsAdapters
    linux = DnsAdapters("ens33", platform="linux")              # not passive listening's pinned adapter
    assert linux.refresh() == ANY and linux.index == ANY_INDEX
    calls = []
    now = [0.0]

    def adapters():
        calls.append(1)
        return [{"name": "en5", "index": 7, "ips": ["192.168.36.9"], "gateway": None},
                {"name": "en0", "index": 4, "ips": ["192.168.217.9"], "gateway": "192.168.217.2"}]
    mac = DnsAdapters(None, platform="darwin", list_adapters=adapters, clock=lambda: now[0])
    assert mac.refresh() == "en0" and mac.index == 4
    now[0] += 5
    assert mac.refresh() == "en0" and len(calls) == 1          # listed once a minute, not every 5 s
    now[0] += 60
    mac.refresh()
    assert len(calls) == 2


def test_an_unbound_packet_socket_hears_every_adapter_but_not_tunnels():
    from eagleeye.passive.capture import ANY, PacketSocketSource
    from tests.test_capture import FakeSocket
    import threading
    answer = udp_frame(dns_answer_msg("example.org"), 53, 51000)
    made = []

    def make():
        made.append(FakeSocket([(answer, ("ens37", 0x0800, 0, 1)), (answer, ("lo", 0x0800, 0, 772)),
                                (answer, ("tun0", 0x0800, 0, 65534)), (answer, ("ens37", 0x0800, 4, 1))]))
        return made[-1]
    src = PacketSocketSource(make, program=frames.dns_kernel_filter())
    got = []
    assert src.open(got.append)
    src.select({"name": ANY})
    assert made[1].bound is None                                # never bound to one adapter
    src.pump(threading.Event(), 0.05)
    assert len(got) == 2                                        # ens37 and loopback; not the tunnel or our own


# ── reading answers ──────────────────────────────────────────────────────────
def test_an_answer_gives_the_question_the_cname_chain_and_addresses():
    names, addresses = dns.answers(dns_answer_msg("www.example.org", cname="cdn.bad.example.net", a="93.184.216.34"))
    assert names == ["www.example.org", "cdn.bad.example.net"]
    assert addresses == ["93.184.216.34"]


def test_questions_reverse_and_local_lookups_are_not_answers():
    assert dns.answers(dns_answer_msg("example.org", qr=0)) is None
    assert dns.answers(b"\x00\x01") is None
    names, _ = dns.answers(dns_answer_msg("4.3.2.1.in-addr.arpa"))
    assert names == []
    names, _ = dns.answers(dns_answer_msg("printer.local"))
    assert names == []


# ── the list ─────────────────────────────────────────────────────────────────
def listed(domains=(), ips=(), event_domains=(), event_ips=()) -> IndicatorList:
    lst = IndicatorList()
    lst.domains, lst.ips = set(domains), set(ips)
    lst.event_domains, lst.event_ips = set(event_domains), set(event_ips)
    return lst


def test_a_name_matches_itself_or_a_listed_parent_and_ips_compare_normalised():
    lst = listed(domains={"evil.com"}, ips={"2001:db8::5"}, event_domains={"c2.campaign.net"}, event_ips={"93.184.216.34"})
    assert lst.match_domain("a.b.EVIL.com.") == "evil.com"
    assert lst.match_domain("evil.com") == "evil.com"
    assert lst.match_domain("notevil.com") is None
    assert lst.match_domain("x.c2.campaign.net") == "c2.campaign.net"
    assert lst.match_domain("campaign.net") is None
    assert lst.match_ip("2001:0db8:0000::0005") == "2001:db8::5"
    assert lst.match_ip("93.184.216.34") == "93.184.216.34"
    assert lst.match_ip("not an ip") is None


def test_server_items_are_split_and_junk_is_skipped():
    domains, ips = IndicatorList.split([
        {"k": "d", "v": "Evil.COM."}, {"k": "i", "v": "93.184.216.34"}, {"k": "d", "v": "localhost"},
        {"k": "i", "v": "nope"}, {"k": "x", "v": "a.b"}, "junk", {"k": "d"},
    ])
    assert domains == {"evil.com"} and ips == {"93.184.216.34"}


class FakeServer:
    def __init__(self, feed_pages, events, fail=False):
        self.feed_pages = feed_pages        # cursor -> answer
        self.events = events
        self.fail = fail
        self.fail_feeds = False
        self.events_answer_rules = None
        self.calls = []

    def __call__(self, part, after):
        self.calls.append((part, after))
        if self.fail or (part == "feeds" and self.fail_feeds):
            raise ConnectionError("no network")
        if part == "events":
            answer = {"items": self.events, "truncated": False}
            if self.events_answer_rules is not None:
                answer["rules"] = self.events_answer_rules
            return answer
        return self.feed_pages[after]


def test_first_sync_fetches_events_and_every_feed_page_then_only_changes(tmp_path):
    now = [1_000_000.0]
    server = FakeServer({
        None: {"items": [{"k": "d", "v": "evil.com"}], "next": "c1", "done": False},
        "c1": {"items": [{"k": "i", "v": "93.184.216.34"}], "next": "c2", "done": True},
        "c2": {"items": [{"k": "d", "v": "new.example"}], "next": "c3", "done": True},
    }, events=[{"k": "d", "v": "campaign.net"}])
    path = tmp_path / "sightings-list.json.gz"
    sync = ListSync(IndicatorList(), server, path, AGENT, clock=lambda: now[0])
    assert sync.due()
    sync.sync()
    assert server.calls == [("events", None), ("feeds", None), ("feeds", "c1")]
    assert sync.list.domains == {"evil.com"} and sync.list.ips == {"93.184.216.34"}
    assert sync.list.event_domains == {"campaign.net"} and sync.list.cursor == "c2"
    assert not sync.due()

    now[0] += FEEDS_EVERY
    server.calls.clear()
    sync.sync()
    assert server.calls == [("events", None), ("feeds", "c2")]        # only what changed since c2
    assert sync.list.domains == {"evil.com", "new.example"}

    again = IndicatorList.load(path, AGENT)                           # kept on disk
    assert again.domains == {"evil.com", "new.example"} and again.cursor == "c3"
    assert IndicatorList.load(path, "22222222-2222-4222-8222-222222222222").domains == set()   # another agent's


def test_the_weekly_full_sync_drops_what_the_server_removed():
    now = [1_000_000.0]
    server = FakeServer({None: {"items": [{"k": "d", "v": "evil.com"}, {"k": "d", "v": "gone.example"}],
                                "next": "c1", "done": True}}, events=[])
    sync = ListSync(IndicatorList(), server, None, AGENT, clock=lambda: now[0])
    sync.sync()
    server.feed_pages[None] = {"items": [{"k": "d", "v": "evil.com"}], "next": "c9", "done": True}
    now[0] += FULL_EVERY
    sync.sync()
    assert sync.list.domains == {"evil.com"} and sync.list.cursor == "c9"


def test_a_failed_sync_keeps_the_list_and_waits_before_trying_again():
    now = [1_000_000.0]
    lst = listed(domains={"evil.com"})
    server = FakeServer({}, events=[], fail=True)
    sync = ListSync(lst, server, None, AGENT, clock=lambda: now[0])
    assert sync.sync() == []
    assert lst.domains == {"evil.com"} and sync.last_error
    assert not sync.due()
    now[0] += RETRY_AFTER
    assert sync.due()


def test_new_list_rules_on_the_server_fetch_the_whole_list_again(tmp_path):
    now = [1_000_000.0]
    server = FakeServer({None: {"items": [{"k": "d", "v": "t.me"}], "next": "c1", "done": True},
                         "c1": {"items": [], "next": "c1", "done": True}}, events=[])
    path = tmp_path / "list.json.gz"
    sync = ListSync(IndicatorList(), server, path, AGENT, clock=lambda: now[0])
    sync.sync()                                         # first sync: no rules said (an older server)
    assert sync.list.rules is None and sync.list.domains == {"t.me"}

    server.events_answer_rules = 2
    server.feed_pages[None] = {"items": [{"k": "d", "v": "evil.com"}], "next": "c2", "done": True}
    now[0] += EVENTS_EVERY
    server.fail_feeds = True                            # the whole list cannot be fetched yet
    sync.sync()
    assert sync.list.rules is None and sync.list.domains == {"t.me"}
    server.fail_feeds = False
    now[0] += RETRY_AFTER
    server.calls.clear()
    sync.sync()                                         # asked again, so the rules still force it
    assert server.calls == [("events", None), ("feeds", None)]
    assert sync.list.domains == {"evil.com"} and sync.list.rules == 2
    assert IndicatorList.load(path, AGENT).rules == 2
    now[0] += EVENTS_EVERY
    server.calls.clear()
    sync.sync()                                         # the same rules: only the events
    assert server.calls == [("events", None)]


def test_events_alone_are_refreshed_every_half_hour():
    now = [1_000_000.0]
    server = FakeServer({None: {"items": [], "next": None, "done": True}}, events=[{"k": "i", "v": "93.184.216.34"}])
    sync = ListSync(IndicatorList(), server, None, AGENT, clock=lambda: now[0])
    sync.sync()
    now[0] += EVENTS_EVERY
    server.calls.clear()
    sync.sync()
    assert server.calls == [("events", None)]


# ── connection tables ────────────────────────────────────────────────────────
PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0
   1: 1401A8C0:C350 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2222 1 0
   2: 1401A8C0:C351 0101A8C0:0016 01 00000000:00000000 00:00000000 00000000  1000        0 3333 1 0
   3: 1401A8C0:C352 22D8B85D:0050 02 00000000:00000000 00:00000000 00000000  1000        0 4444 1 0
   4: 1401A8C0:C353 22D8B85D:0050 06 00000000:00000000 00:00000000 00000000  1000        0 5555 1 0
"""

PROC_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7777 1 0
   1: B80D0120000000000000000002000000:D431 60480120000000000000000088880000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 8888 1 0
"""


def test_linux_tables_give_open_and_opening_connections_to_public_addresses():
    conns = connections.parse_proc_net_tcp(PROC_TCP)
    # 93.184.216.34: 443 established, 80 SYN sent; the LAN one and the TIME_WAIT one are left out
    assert [(c.remote, c.port, c.inode) for c in conns] == [("93.184.216.34", 443, 2222), ("93.184.216.34", 80, 4444)]
    six = connections.parse_proc_net_tcp(PROC_TCP6)
    assert [(c.remote, c.port, c.local_port) for c in six] == [("2001:4860::8888", 443, 0xD431)]


def test_linux_program_found_from_the_socket_inode(tmp_path, monkeypatch):
    for pid, link in (("41", "socket:[1]"), ("42", "socket:[2222]")):
        (tmp_path / pid / "fd").mkdir(parents=True)
        (tmp_path / pid / "fd" / "3").write_text("")
        (tmp_path / pid / "comm").write_text(f"prog{pid}\n")
    links = {str(tmp_path / "41" / "fd" / "3"): "socket:[1]", str(tmp_path / "42" / "fd" / "3"): "socket:[2222]"}
    monkeypatch.setattr(connections.os, "readlink", lambda p: links[str(p)])
    assert connections.linux_process(2222, proc=str(tmp_path)) == "prog42"
    assert connections.linux_process(9, proc=str(tmp_path)) is None
    assert connections.linux_process(None) is None


MAC_NETSTAT = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.20.50123     93.184.216.34.443      ESTABLISHED
tcp4       0      0  192.168.1.20.50124     93.184.216.34.80       SYN_SENT
tcp4       0      0  192.168.1.20.50125     192.168.1.1.53         ESTABLISHED
tcp6       0      0  2001:db8::2.50126      2001:4860::8888.443    ESTABLISHED
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  192.168.1.20.50127     93.184.216.34.443      TIME_WAIT
"""


def test_macos_netstat_gives_open_and_opening_connections_to_public_addresses():
    conns = connections.parse_macos_netstat(MAC_NETSTAT)
    assert [(c.remote, c.port, c.local_port) for c in conns] == [
        ("93.184.216.34", 443, 50123), ("93.184.216.34", 80, 50124), ("2001:4860::8888", 443, 50126)]
    assert connections.parse_lsof("p123\ncsafari\n") == "safari"
    assert connections.parse_lsof("") is None


def _row4(state, local_port, remote, port, pid):
    return struct.pack("<II", state, 0) + struct.pack(">H2x", local_port) + ipaddress.IPv4Address(remote).packed \
        + struct.pack(">H2x", port) + struct.pack("<I", pid)


def _row6(state, local_port, remote, port, pid):
    return bytes(16) + struct.pack("<I", 0) + struct.pack(">H2x", local_port) + ipaddress.IPv6Address(remote).packed \
        + struct.pack("<I", 0) + struct.pack(">H2x", port) + struct.pack("<II", state, pid)


def test_windows_tables_give_open_and_opening_connections_with_their_process():
    rows = [_row4(5, 50123, "93.184.216.34", 443, 4321), _row4(3, 50124, "93.184.216.34", 80, 4322),
            _row4(5, 50125, "192.168.1.1", 445, 4), _row4(11, 50126, "93.184.216.34", 443, 4323)]
    table = struct.pack("<I", len(rows)) + b"".join(rows)
    conns = connections.parse_tcp_table_v4(table)
    assert [(c.remote, c.port, c.local_port, c.pid) for c in conns] == [
        ("93.184.216.34", 443, 50123, 4321), ("93.184.216.34", 80, 50124, 4322)]
    six = struct.pack("<I", 1) + _row6(5, 50200, "2001:4860::8888", 443, 99)
    assert [(c.remote, c.port, c.local_port, c.pid) for c in connections.parse_tcp_table_v6(six)] == [
        ("2001:4860::8888", 443, 50200, 99)]
    assert connections.parse_tcp_table_v4(struct.pack("<I", 5) + rows[0]) != []      # a short table: what is whole
    assert connections.parse_tcp_table_v4(b"") == []


# ── counting ─────────────────────────────────────────────────────────────────
def test_counts_a_repeated_answer_once_within_two_seconds_and_keeps_the_newest_process():
    now = [100.0]
    rec = HitRecorder(clock=lambda: now[0])
    rec.record("evil.com", "domain", "dns")
    now[0] += 0.5
    rec.record("evil.com", "domain", "dns")              # the same packet at another layer
    now[0] += 10
    rec.record("evil.com", "domain", "dns")
    rec.record("93.184.216.34", "ip", "connection", "curl", 443)
    assert rec.fresh()
    entries = {(e.value, e.via): e for e in rec.take()}
    assert entries[("evil.com", "dns")].count == 2
    assert entries[("93.184.216.34", "connection")].payload()["process"] == "curl"
    assert not rec.fresh() and rec.pending() == 0


def test_a_failed_upload_is_put_back_and_merged():
    now = [100.0]
    rec = HitRecorder(clock=lambda: now[0])
    rec.record("evil.com", "domain", "dns")
    held = rec.take()
    now[0] += 60
    rec.record("evil.com", "domain", "dns")
    rec.restore(held)
    [entry] = rec.take()
    assert entry.count == 2 and entry.first == 100.0 and entry.last == 160.0


# ── the monitor ──────────────────────────────────────────────────────────────
class FakeClient:
    def __init__(self, ok=True):
        self.ok = ok
        self.sent = []

    def sightings_indicators(self, part, after=None):
        return {"items": [], "next": None, "done": True}

    def send_sightings(self, hits):
        self.sent.append(hits)
        return (self.ok, "1 contact(s) accepted" if self.ok else "could not reach the server")


class Pkt:
    def __init__(self, payload):
        self.payload = payload


def monitor(conns=None, processes=None, client=None, now=None):
    clock = now or [1000.0]
    looked_up = []

    def process_of(conn):
        looked_up.append(conn)
        return (processes or {}).get(conn.remote)
    m = SightingsMonitor(client or FakeClient(), AGENT, None, poll_connections=lambda: list(conns or []),
                         process_of=process_of, clock=lambda: clock[0])
    m.list.domains, m.list.ips = {"evil.com"}, {"93.184.216.34"}
    return m, looked_up, clock


def test_only_listed_names_and_addresses_in_answers_are_recorded():
    m, _, _ = monitor()
    m.on_dns(Pkt(dns_answer_msg("www.example.org", cname="cdn.evil.com", a="93.184.216.34")))
    m.on_dns(Pkt(dns_answer_msg("www.example.org", a="1.1.1.1")))
    got = sorted((e.value, e.type, e.via) for e in m.recorder.take())
    assert got == [("93.184.216.34", "ip", "dns"), ("cdn.evil.com", "domain", "dns")]


def test_a_connection_is_counted_when_it_opens_and_only_a_match_gets_its_program_looked_up():
    conns = [Conn("93.184.216.34", 443, 50123, pid=1), Conn("151.101.1.69", 443, 50124, pid=2)]
    m, looked_up, _ = monitor(conns, processes={"93.184.216.34": "beacon.exe"})
    assert m.poll_connections_once() == 1
    assert m.poll_connections_once() == 0                # the same connection, still open
    conns.append(Conn("93.184.216.34", 443, 50125, pid=1))
    assert m.poll_connections_once() == 1                # a new one to the same address
    assert [c.remote for c in looked_up] == ["93.184.216.34", "93.184.216.34"]
    [entry] = m.recorder.take()
    assert (entry.value, entry.via, entry.count, entry.process, entry.port) == ("93.184.216.34", "connection", 2,
                                                                                "beacon.exe", 443)


def test_first_contacts_go_up_within_a_minute_repeats_every_five_and_failures_are_kept():
    client = FakeClient()
    m, _, now = monitor(client=client)
    assert not m.upload_due()                            # nothing waiting
    m.recorder.record("evil.com", "domain", "dns")
    now[0] += 59
    assert not m.upload_due()
    now[0] += 1
    assert m.upload_due() and m.upload()
    assert client.sent[0][0]["value"] == "evil.com" and m.uploaded == 1
    now[0] += 10
    m.recorder.record("evil.com", "domain", "dns")       # a repeat is not fresh
    now[0] += 120
    assert not m.upload_due()
    now[0] += 300
    assert m.upload_due()
    client.ok = False
    assert not m.upload()
    assert m.recorder.pending() == 1 and m.problems() == ["upload: could not reach the server"]


# ── the API client ───────────────────────────────────────────────────────────
class Resp:
    def __init__(self, body, status=200):
        self.status_code, self._body = status, body

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return self._body


class Session:
    def __init__(self, *answers):
        self.answers, self.calls, self.headers = list(answers), [], {}

    def request(self, method, url, timeout=None, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.answers.pop(0)


def test_the_list_is_asked_for_compressed_and_hits_go_up_in_chunks_of_200():
    session = Session(Resp({"items": [], "next": "c1", "done": True}),
                      Resp({"accepted": 200, "created": 1, "updated": 0}), Resp({"accepted": 50, "created": 0, "updated": 1}))
    c = AgentClient("https://api.example/api/v1", "key", AGENT, session=session, sleep=lambda s: None)
    assert c.sightings_indicators("feeds", "c0")["next"] == "c1"
    method, url, kwargs = session.calls[0]
    assert (method, url, kwargs["params"], kwargs["accept_gzip"]) == (
        "GET", "https://api.example/api/v1/sightings/indicators", {"part": "feeds", "after": "c0"}, True)
    ok, message = c.send_sightings([{"value": f"h{i}.evil.com"} for i in range(250)])
    assert ok and "250 contact(s) accepted" in message and "1 new, 1 updated" in message
    assert [len(json.loads(k["data"])["hits"]) for _, _, k in session.calls[1:]] == [200, 50]


def test_a_refused_list_raises_so_the_sync_keeps_its_copy():
    session = Session(Resp({"detail": "Sightings are for a computer's own agent"}, status=403))
    c = AgentClient("https://api.example/api/v1", "key", AGENT, session=session, sleep=lambda s: None)
    with pytest.raises(Exception, match="own agent"):
        c.sightings_indicators("events")


def test_saved_list_is_gzip_json(tmp_path):
    lst = listed(domains={"evil.com"})
    path = tmp_path / "l.json.gz"
    lst.save(path, AGENT)
    data = json.loads(gzip.decompress(path.read_bytes()))
    assert data["domains"] == ["evil.com"] and data["agent_id"] == AGENT


# ── running programs against listed malware hashes (programs.py) ────────────
# Plain bytes standing in for a payload (not EICAR: antivirus quarantines that file under the test)
PAYLOAD = b"eagleeye sightings test payload\n" * 1000
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
PAYLOAD_MD5 = hashlib.md5(PAYLOAD).hexdigest()  # noqa: S324


def test_hash_items_are_taken_lowercase_and_junk_is_skipped():
    hashes = IndicatorList.hashes_of([
        {"k": "h", "v": PAYLOAD_SHA256.upper()}, {"k": "h", "v": PAYLOAD_MD5}, {"k": "h", "v": "abc"},
        {"k": "h", "v": "z" * 64}, {"k": "d", "v": "evil.com"}, "junk",
    ])
    assert hashes == {PAYLOAD_SHA256, PAYLOAD_MD5}
    # an older agent's split() skips them: domains and IPs only
    assert IndicatorList.split([{"k": "h", "v": PAYLOAD_MD5}]) == (set(), set())


def test_hashes_sync_from_feeds_and_events_and_are_kept_on_disk(tmp_path):
    server = FakeServer({None: {"items": [{"k": "d", "v": "evil.com"}, {"k": "h", "v": PAYLOAD_SHA256}], "next": "c1", "done": True}},
                        events=[{"k": "h", "v": PAYLOAD_MD5}])
    path = tmp_path / "l.json.gz"
    sync = ListSync(IndicatorList(), server, path, AGENT, clock=lambda: 1_000_000.0)
    sync.sync()
    assert sync.list.hashes == {PAYLOAD_SHA256} and sync.list.event_hashes == {PAYLOAD_MD5}
    assert sync.list.match_hash(PAYLOAD_SHA256.upper()) == PAYLOAD_SHA256 and sync.list.match_hash("00" * 32) is None
    again = IndicatorList.load(path, AGENT)
    assert again.hashes == {PAYLOAD_SHA256} and again.event_hashes == {PAYLOAD_MD5} and len(again) == 3


def test_hash_file_gives_the_three_hashes_in_one_read_and_skips_large_files(tmp_path):
    from eagleeye.sightings.programs import hash_file
    f = tmp_path / "payload.bin"
    f.write_bytes(PAYLOAD)
    h = hash_file(str(f))
    assert h is not None and h.sha256 == PAYLOAD_SHA256 and h.md5 == PAYLOAD_MD5 and len(h.sha1) == 40
    assert hash_file(str(f), max_size=10) is None
    assert hash_file(str(tmp_path / "gone")) is None


def test_each_program_is_hashed_once_while_it_stays_the_same_and_rounds_are_capped():
    from eagleeye.sightings.programs import Hashes, Program, ProgramHasher
    running = [Program("/usr/bin/a", "/usr/bin/a"), Program("/usr/bin/b", "/usr/bin/b"), Program("/usr/bin/a", "/usr/bin/a")]
    stats = {"/usr/bin/a": (1, 1), "/usr/bin/b": (2, 2)}
    hashed = []

    def hasher(path):
        hashed.append(path)
        return Hashes("s" + path, "x", "m")
    h = ProgramHasher(lambda: list(running), hasher=hasher, stat=lambda p: stats.get(p), max_new=1)
    assert [p.path for p, _ in h.round()] == ["/usr/bin/a"]          # one new file per round here
    assert [p.path for p, _ in h.round()] == ["/usr/bin/a", "/usr/bin/b"]
    h.round()
    assert hashed == ["/usr/bin/a", "/usr/bin/b"]                    # not again while unchanged
    stats["/usr/bin/a"] = (1, 99)                                    # replaced on disk
    h.round()
    assert hashed[-1] == "/usr/bin/a"
    running[:] = [Program("/usr/bin/b", "/usr/bin/b")]               # a stopped: forgotten
    h.round()
    assert "/usr/bin/a" not in h._cache


def test_a_running_program_with_a_listed_hash_is_recorded_with_its_name_only():
    from eagleeye.sightings.programs import Hashes, Program, ProgramHasher
    progs = [Program("C:\\Users\\jo\\AppData\\Local\\Temp\\beacon.exe", "C:\\Users\\jo\\AppData\\Local\\Temp\\beacon.exe"),
             Program("C:\\Windows\\notepad.exe", "C:\\Windows\\notepad.exe")]
    hashes = {progs[0].path: Hashes("aa" * 32, "bb" * 20, PAYLOAD_MD5), progs[1].path: Hashes("cc" * 32, "dd" * 20, "ee" * 16)}
    hasher = ProgramHasher(lambda: progs, hasher=lambda p: hashes[p], stat=lambda p: (1, 1))
    m = SightingsMonitor(FakeClient(), AGENT, None, poll_connections=lambda: [], process_of=lambda c: None,
                         clock=lambda: 1000.0, hasher=hasher)
    m.list.event_hashes = {PAYLOAD_MD5}                                # listed by its MD5
    assert m.poll_programs_once() == 1
    [entry] = m.recorder.take()
    assert (entry.value, entry.type, entry.via, entry.process) == (PAYLOAD_MD5, "hash", "process", "beacon.exe")
    assert entry.payload()["process"] == "beacon.exe" and "Users" not in json.dumps(entry.payload())


def test_parse_ps_takes_full_paths_only():
    from eagleeye.sightings.programs import parse_ps
    got = parse_ps("  1 /sbin/launchd\n 420 /Applications/Safari.app/Contents/MacOS/Safari\n 77 (kernel_task)\n")
    assert [p.path for p in got] == ["/sbin/launchd", "/Applications/Safari.app/Contents/MacOS/Safari"]
    assert got[1].name == "Safari"
