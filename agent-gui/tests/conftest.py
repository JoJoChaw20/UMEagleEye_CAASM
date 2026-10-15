from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
NMAP_XML = (FIXTURES / "nmap_sample.xml").read_text(encoding="utf-8")

@pytest.fixture
def fake_nmap(monkeypatch):
    """The agent sees the recorded Nmap XML instead of running Nmap. Returns the Nmap
    command lines it would have run."""
    from eagleeye.stages import scan_nmap

    commands: list[list[str]] = []

    def execute(command, timeout):
        commands.append(command)
        return NMAP_XML

    monkeypatch.setattr(scan_nmap, "_execute_nmap", execute)
    return commands


@pytest.fixture
def scanner():
    """The recorded Nmap XML report."""
    return NMAP_XML
