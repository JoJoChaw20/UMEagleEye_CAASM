from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from eagleeye import installers
from eagleeye.installers import TOOLS, Installer, InstallError

NMAP_PAGE = """
<a href="https://nmap.org/dist/nmap-7.95-setup.exe">old</a>
<b><a href="https://nmap.org/dist/nmap-7.991-setup.exe">nmap-7.991-setup.exe</a></b>
<a href="//nmap.org/dist/nmap-7.991-setup.exe">mirror</a>
<a href="https://nmap.org/dist/nmap-7.991.tar.bz2">source</a>
"""
NPCAP_PAGE = '<a href="dist/npcap-1.89.exe">Npcap 1.89 installer</a> <a href="dist/npcap-1.79.exe">old</a>'


def test_picks_the_newest_installer_by_version_number():
    inst = installers.find_latest(TOOLS["nmap"], NMAP_PAGE)
    assert (inst.version, inst.url) == ("7.991", "https://nmap.org/dist/nmap-7.991-setup.exe")
    inst = installers.find_latest(TOOLS["npcap"], NPCAP_PAGE)
    assert inst.url == "https://npcap.com/dist/npcap-1.89.exe"


def test_page_without_a_link_is_a_clear_error():
    with pytest.raises(InstallError, match="could not find the Nmap installer"):
        installers.find_latest(TOOLS["nmap"], "<html>maintenance</html>")


def test_never_downloads_from_another_host(tmp_path):
    bad = Installer(TOOLS["nmap"], "https://evil.example/nmap-7.991-setup.exe", "7.991")
    with pytest.raises(InstallError, match="refusing"):
        installers.download(bad, tmp_path)
    plain = Installer(TOOLS["nmap"], "http://nmap.org/dist/nmap-7.991-setup.exe", "7.991")
    with pytest.raises(InstallError, match="refusing"):
        installers.download(plain, tmp_path)


class FakeResponse:
    def __init__(self, url, chunks, length=None):
        self.url, self.chunks = url, chunks
        self.headers = {"Content-Length": str(length)} if length else {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size):
        yield from self.chunks


class FakeSession:
    def __init__(self, response):
        self.response = response

    def get(self, url, stream=False, timeout=None):
        return self.response


GOOD = Installer(TOOLS["npcap"], "https://npcap.com/dist/npcap-1.89.exe", "1.89")


def test_download_writes_the_file_and_reports_progress(tmp_path):
    seen = []
    path = installers.download(GOOD, tmp_path, progress=lambda d, t: seen.append((d, t)),
                               session=FakeSession(FakeResponse(GOOD.url, [b"ab", b"cd"], 4)))
    assert path.read_bytes() == b"abcd" and path.name == "npcap-1.89.exe"
    assert seen == [(2, 4), (4, 4)]


def test_redirect_to_another_host_is_refused_and_nothing_is_left(tmp_path):
    resp = FakeResponse("https://cdn.example/npcap.exe", [b"x"])
    with pytest.raises(InstallError, match="redirected"):
        installers.download(GOOD, tmp_path, session=FakeSession(resp))
    assert list(tmp_path.iterdir()) == []


def test_oversized_download_is_refused(tmp_path):
    resp = FakeResponse(GOOD.url, [b"x"], installers.MAX_BYTES + 1)
    with pytest.raises(InstallError, match="large"):
        installers.download(GOOD, tmp_path, session=FakeSession(resp))


def test_cancel_stops_the_download(tmp_path):
    with pytest.raises(InstallError, match="cancelled"):
        installers.download(GOOD, tmp_path, cancelled=lambda: True, session=FakeSession(FakeResponse(GOOD.url, [b"x"])))
    assert list(tmp_path.iterdir()) == []


def test_publisher_is_read_from_the_o_field():
    subject = "CN=Nmap Software LLC, O=Nmap Software LLC, L=Beaverton, S=Oregon, C=US"
    assert installers.publisher_of(subject) == "Nmap Software LLC"
    assert installers.publisher_of('CN=x, O="Evil, Inc.", C=US') == "Evil, Inc."
    assert installers.publisher_of("CN=Nmap Software LLC") is None      # CN alone is not enough


@pytest.mark.skipif(sys.platform != "win32", reason="Authenticode is Windows only")
@pytest.mark.parametrize("status, subject, ok", [
    ("Valid", "CN=Nmap Software LLC, O=Nmap Software LLC", True),
    ("HashMismatch", "CN=Nmap Software LLC, O=Nmap Software LLC", False),
    ("NotSigned", None, False),
    ("Valid", "CN=Nmap Software LLC, O=Someone Else", False),
])
def test_signature_rules(monkeypatch, tmp_path, status, subject, ok):
    out = json.dumps({"status": status, "subject": subject})
    monkeypatch.setattr(installers.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=out))
    if ok:
        assert installers.verify_signature(tmp_path / "x.exe") == "Nmap Software LLC"
    else:
        with pytest.raises(InstallError, match="not started"):
            installers.verify_signature(tmp_path / "x.exe")


@pytest.mark.skipif(sys.platform != "win32", reason="Authenticode is Windows only")
def test_signature_check_errors_do_not_launch(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("powershell", 60)
    monkeypatch.setattr(installers.subprocess, "run", boom)
    with pytest.raises(InstallError, match="could not check"):
        installers.verify_signature(tmp_path / "x.exe")
