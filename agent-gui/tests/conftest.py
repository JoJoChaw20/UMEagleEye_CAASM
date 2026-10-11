from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
NMAP_XML = (FIXTURES / "nmap_sample.xml").read_text(encoding="utf-8")

try:        # python-nmap is only needed to run the original agent in tests/test_parity.py
    import nmap
except ImportError:  # pragma: no cover
    nmap = None


if nmap is not None:
    class FakePortScanner(nmap.PortScanner):
        """A python-nmap PortScanner (used by the original agent) that never runs Nmap:
        scan() loads the recorded XML instead."""

        def __init__(self, nmap_search_path=None):  # noqa: D107 - skip the nmap binary lookup
            self._scan_result = {}
            self._nmap_version_number = 0
            self._nmap_subversion_number = 0
            self._nmap_last_output = ""
            self.nmap_version = None

        def scan(self, hosts="127.0.0.1", ports=None, arguments="-sV", sudo=False, timeout=0):
            self.analyse_nmap_xml_scan(NMAP_XML)
            return self._scan_result


@pytest.fixture
def fake_nmap(monkeypatch):
    """Both agents see the recorded Nmap XML instead of running Nmap. Returns the
    Nmap command lines the new agent would have run."""
    from eagleeye.stages import scan_nmap

    commands: list[list[str]] = []

    def execute(command, timeout):
        commands.append(command)
        return NMAP_XML

    monkeypatch.setattr(scan_nmap, "_execute_nmap", execute)
    if nmap is not None:
        monkeypatch.setattr(nmap, "PortScanner", FakePortScanner)
    return commands


@pytest.fixture
def scanner():
    """The recorded Nmap XML report."""
    return NMAP_XML
