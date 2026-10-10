"""The new agent must produce the same host data as the original agent
(agent/eagleeye_agent.py) for the same input. These tests run both side by side.
They are skipped when the original agent file is no longer in the repository."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from eagleeye.passive.sniffers import ArpSniffer, DhcpSniffer
from eagleeye.pipeline.record import HostRecord
from eagleeye.stages import enrich_passive_hosts
from eagleeye.stages import scan_nmap

OLD_AGENT = Path(__file__).resolve().parents[2] / "agent" / "eagleeye_agent.py"


@pytest.fixture(scope="module")
def old():
    if not OLD_AGENT.is_file():
        pytest.skip("original agent not present")
    spec = importlib.util.spec_from_file_location("old_eagleeye_agent", OLD_AGENT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SMB_SAMPLES = [
    "\n  OS: Windows 10 Pro 19045 (Windows 10 Pro 6.3)\n  Computer name: DESKTOP-ABC123\n"
    "  Domain name: lan\n  FQDN: DESKTOP-ABC123.lan\n",
    "OS: Ubuntu Samba\nComputer name: nas\n",
    "",
    "nothing useful here",
]


@pytest.mark.parametrize("sample", SMB_SAMPLES)
def test_smb_parser_matches_old(old, sample):
    assert scan_nmap.parse_smb_os_discovery(sample) == old._parse_smb_os_discovery(sample)


def test_nmap_hosts_match_old(old, fake_nmap):
    old_hosts = old.run_nmap("192.168.1.0/24")
    new_hosts = scan_nmap.run_nmap("192.168.1.0/24", "nmap")
    assert [h.to_payload() for h in new_hosts] == old_hosts
    assert len(old_hosts) == 5          # the down host is excluded by both


def test_nmap_arguments_match_old(old):
    """The old agent hard-codes its Nmap arguments inside run_nmap(); recover them by
    running it against a scanner that records the call."""
    import nmap

    seen = {}

    class Recorder(nmap.PortScanner):
        def __init__(self, *a, **k):
            self._scan_result = {"scan": {}}

        def scan(self, hosts="", ports=None, arguments="", **k):
            seen["arguments"] = arguments

        def all_hosts(self):
            return []

    original = nmap.PortScanner
    nmap.PortScanner = Recorder
    try:
        old.run_nmap("10.0.0.0/24")
    finally:
        nmap.PortScanner = original
    assert seen["arguments"] == scan_nmap.NMAP_ARGS


def test_dhcp_vendor_hints_match_old(old):
    assert DhcpSniffer._VENDOR_HINTS == old.DhcpSniffer._VENDOR_HINTS


def test_passive_enrichment_matches_old(old):
    class OldMdns:
        def get_hostname(self, ip):
            return {"192.168.1.10": "mdns-name"}.get(ip)

    class OldDhcp:
        info = {
            "192.168.1.10": {"dhcp_hostname": "dhcp-name", "dhcp_vendor_class": "MSFT 5.0",
                             "dhcp_device_hint": "Windows"},
            "192.168.1.20": {"dhcp_hostname": "phone", "dhcp_device_hint": "Android",
                             "fingerbank_device": "Pixel", "fingerbank_score": 80},
        }

        def get_info(self, ip):
            return dict(self.info.get(ip, {}))

    def sample_dicts():
        return [
            {"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:aa", "hostname": "rdns", "ports": [], "os": {"name": "Win"}},
            {"ip": "192.168.1.20", "mac": "bb:bb:bb:bb:bb:bb", "hostname": None, "ports": [], "os": None},
            {"ip": "192.168.1.30", "mac": "cc:cc:cc:cc:cc:cc", "hostname": "only-rdns", "ports": [], "os": None},
        ]

    expected = old.enrich_passive_hosts(sample_dicts(), OldMdns(), OldDhcp())

    class Suite:
        mdns = OldMdns()
        dhcp = OldDhcp()

    records = [HostRecord.from_payload(d) for d in sample_dicts()]
    actual = [h.to_payload() for h in enrich_passive_hosts(records, Suite())]
    assert actual == expected


def test_arp_drain_payload_shape_matches_old(old, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(socket.herror()))

    new = ArpSniffer()
    new._seen = {"192.168.1.5": {"mac": "aa:bb:cc:dd:ee:ff", "last_seen": 0}}
    legacy = old.ArpSniffer()
    legacy._seen = {"192.168.1.5": {"mac": "aa:bb:cc:dd:ee:ff", "last_seen": 0}}
    assert [h.to_payload() for h in new.drain()] == legacy.drain()


def test_snmp_protocol_tables_match_old(old):
    import inspect
    from eagleeye.stages import snmp_poll

    source = inspect.getsource(old.query_snmp_v3)
    for name in list(snmp_poll._AUTH_PROTOCOLS.values()) + list(snmp_poll._PRIV_PROTOCOLS.values()):
        assert name in source
