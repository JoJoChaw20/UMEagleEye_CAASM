from __future__ import annotations

from pathlib import Path

import nmap
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


class FakePortScanner(nmap.PortScanner):
    """A PortScanner that never runs Nmap: scan() loads the recorded XML instead."""

    def __init__(self, nmap_search_path=None):  # noqa: D107 - skip the nmap binary lookup
        self._scan_result = {}
        self._nmap_version_number = 0
        self._nmap_subversion_number = 0
        self._nmap_last_output = ""
        self.nmap_version = None

    def scan(self, hosts="127.0.0.1", ports=None, arguments="-sV", sudo=False, timeout=0):
        self.analyse_nmap_xml_scan((FIXTURES / "nmap_sample.xml").read_text(encoding="utf-8"))
        return self._scan_result


@pytest.fixture
def fake_nmap(monkeypatch):
    monkeypatch.setattr(nmap, "PortScanner", FakePortScanner)
    return FakePortScanner


@pytest.fixture
def scanner():
    sc = FakePortScanner()
    sc.scan()
    return sc
