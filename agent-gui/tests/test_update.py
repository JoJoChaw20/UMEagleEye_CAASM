"""Agent updates (eagleeye/update): the Ed25519 check, what makes a package acceptable, the file
check, the Linux switch with rollback, and how the outcome is reported."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from eagleeye.update import ed25519, install, package
from eagleeye.update.package import Refused, check_manifest, signed_message

# RFC 8032, section 7.1, tests 1-3
RFC = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("pub,msg,sig", RFC)
def test_rfc8032_vectors_verify_and_a_changed_byte_does_not(pub, msg, sig):
    pub_b, msg_b, sig_b = bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig)
    assert ed25519.verify(pub_b, msg_b, sig_b)
    assert not ed25519.verify(pub_b, msg_b + b"x", sig_b)
    assert not ed25519.verify(pub_b, msg_b, sig_b[:-1] + bytes([sig_b[-1] ^ 1]))
    assert not ed25519.verify(pub_b, msg_b, sig_b[:63])


def test_agrees_with_the_cryptography_library_signer():
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    from cryptography.hazmat.primitives import serialization as s
    key = crypto.Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    for msg in (b"", b"UMEagleEye", bytes(range(256)) * 4):
        assert ed25519.verify(pub, msg, key.sign(msg))
        assert not ed25519.verify(pub, msg + b"!", key.sign(msg))


# ── manifests, with a test key trusted in place of the project's ──
@pytest.fixture()
def signer(monkeypatch):
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    from cryptography.hazmat.primitives import serialization as s
    key = crypto.Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).decode()
    monkeypatch.setattr(package, "PUBLIC_KEYS", {"test": pub})

    def make(data=b"installer bytes", kind="windows", build="0.1.0+20261124T010203Z.abc1234", key_id="test", tamper=None):
        m = {"format": 1, "kind": kind, "file": "EagleEyeAgent-Setup-0.1.0.exe", "build": build,
             "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "key": key_id}
        m["signature"] = base64.b64encode(key.sign(signed_message(m["kind"], m["file"], m["build"], m["sha256"], m["size"]))).decode()
        m.update(tamper or {})                     # changed after signing
        return m
    return make


OWN = "0.1.0+20261123T000000Z.0000aaa"


def test_a_signed_newer_package_for_this_kind_is_accepted(signer):
    info = check_manifest(signer(), OWN, "windows")
    assert info["build"] == "0.1.0+20261124T010203Z.abc1234" and info["size"] == len(b"installer bytes")


@pytest.mark.parametrize("change,why", [
    ({"size": 999}, "signature is not valid"),                                   # a signed field changed
    ({"sha256": "0" * 64}, "signature is not valid"),
    ({"build": "0.1.0+20991231T000000Z.ffff"}, "signature is not valid"),
    ({"key": "someone-else"}, "key this agent does not trust"),
    ({"signature": "not base64!"}, "signature is not valid"),
    ({"format": 2}, "unknown format"),
    ({"file": "../evil.exe"}, "unknown kind or file"),
])
def test_tampered_or_unknown_manifests_are_refused(signer, change, why):
    with pytest.raises(Refused, match=why):
        check_manifest(signer(tamper=change), OWN, "windows")


def test_wrong_kind_older_build_and_dev_builds(signer):
    with pytest.raises(Refused, match="for windows installs"):
        check_manifest(signer(), OWN, "source")
    with pytest.raises(Refused, match="not newer"):
        check_manifest(signer(build=OWN), OWN, "windows")                       # the same build again
    with pytest.raises(Refused, match="not a release build"):
        check_manifest(signer(build="dev"), OWN, "windows")
    assert check_manifest(signer(), "dev", "windows")                           # a dev copy may take any release


def test_the_downloaded_file_must_be_the_signed_one(tmp_path, signer):
    info = check_manifest(signer(data=b"good"), OWN, "windows")
    f = tmp_path / "setup.exe"
    f.write_bytes(b"good")
    install.check_file(f, info)
    f.write_bytes(b"evil")
    with pytest.raises(Refused, match="SHA-256"):
        install.check_file(f, info)
    f.write_bytes(b"longer")
    with pytest.raises(Refused, match="bytes"):
        install.check_file(f, info)


def test_install_root_is_only_an_opt_folder_with_its_venv():
    from pathlib import Path
    assert package.install_root("/opt/eagleeye-agent-0.1.0-20261124T010203Z.abc/.venv") == Path("/opt/eagleeye-agent-0.1.0-20261124T010203Z.abc")
    assert package.install_root("/home/user/agent-gui/.venv") is None
    assert package.install_root("/opt/eagleeye-agent-0.1.0/venv") is None


def test_the_new_build_is_prepared_without_the_running_agents_python_path():
    # The service's PYTHONPATH pointed at the old build's site-packages: the new venv loaded the old code.
    env = install.clean_env({"PATH": "/usr/bin", "PYTHONPATH": "/opt/eagleeye-agent-A/.venv/lib/python3.14/site-packages",
                             "VIRTUAL_ENV": "/opt/eagleeye-agent-A/.venv", "PIP_INDEX_URL": "https://example"})
    assert env == {"PATH": "/usr/bin"}


def test_an_installed_agent_writes_no_pythonpath_into_its_service(monkeypatch, tmp_path):
    from eagleeye import serviceinstall
    site = tmp_path / "site-packages"
    monkeypatch.setattr(serviceinstall, "__file__", str(site / "eagleeye" / "serviceinstall.py"))
    monkeypatch.setattr(serviceinstall.sysconfig, "get_paths", lambda: {"purelib": str(site), "platlib": str(site)})
    assert serviceinstall._source_root() is None
    monkeypatch.setattr(serviceinstall, "__file__", str(tmp_path / "agent-gui" / "eagleeye" / "serviceinstall.py"))
    assert serviceinstall._source_root() == str((tmp_path / "agent-gui").resolve())


# ── the Linux switch and the outcome ──
@pytest.fixture()
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(install, "machine_dir", lambda: tmp_path)
    return tmp_path


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_switch_waits_for_the_new_build_to_check_in(state_dir, tmp_path):
    install.write_state({"job": "j1", "build": "B2", "state": "installing"})
    clock, installed = Clock(), []

    def service_install(root):
        installed.append(root)
        install.write_state({**install.read_state(), "state": "healthy"})        # the new agent checked in
    result = install.switch(tmp_path / "new", tmp_path / "old", "B2", service_install=service_install,
                            sleep=clock.sleep, clock=clock)
    assert result == "healthy" and installed == [tmp_path / "new"]


def test_switch_rolls_back_when_the_new_build_stays_silent(state_dir, tmp_path):
    install.write_state({"job": "j1", "build": "B2", "state": "installing"})
    clock, installed = Clock(), []
    result = install.switch(tmp_path / "new", tmp_path / "old", "B2", service_install=installed.append,
                            sleep=clock.sleep, clock=clock, rollback_after=60)
    assert result == "rolled_back" and installed == [tmp_path / "new", tmp_path / "old"]
    st = install.read_state()
    assert st["state"] == "rolled_back" and "did not check in" in st["error"]


class FakeClient:
    def __init__(self):
        self.failed = []

    def mark_scan_failed(self, job, reason):
        self.failed.append((job, reason))

    def download_package(self, kind, dest, size):
        raise AssertionError("must not download a refused package")


def test_outcome_after_the_restart(state_dir, monkeypatch):
    monkeypatch.setattr(install, "BUILD", "B2")
    install.write_state({"job": "j1", "build": "B2", "state": "switching"})
    client = FakeClient()
    assert install.report_outcome(client) == "healthy" and client.failed == []
    assert install.report_outcome(client) is None                              # settled once

    monkeypatch.setattr(install, "BUILD", "B1")                               # rolled back: the old build reports it
    install.write_state({"job": "j2", "build": "B2", "state": "rolled_back", "error": "build B2 did not check in"})
    assert install.report_outcome(client) == "failed"
    assert client.failed == [("j2", "Update failed: build B2 did not check in")]


def test_a_windows_installer_that_never_finished_is_reported(state_dir, monkeypatch):
    monkeypatch.setattr(install, "BUILD", "B1")
    install.write_state({"job": "j3", "build": "B2", "state": "installing", "at": 0})
    client = FakeClient()
    assert install.report_outcome(client, clock=lambda: 10) is None            # still within the wait
    assert install.report_outcome(client, clock=lambda: 10 + install.WINDOWS_GIVE_UP) == "failed"
    assert client.failed[0][0] == "j3"


def test_a_refused_package_fails_the_job_without_downloading(state_dir, monkeypatch, signer):
    monkeypatch.setattr(install, "install_kind", lambda: "windows")
    client = FakeClient()
    install.run_update(client, "j4", signer(key_id="someone-else"))
    assert client.failed and "key this agent does not trust" in client.failed[0][1]
    assert not (state_dir / "update-state.json").exists()


def test_state_file_is_json(state_dir):
    install.write_state({"a": 1})
    assert json.loads((state_dir / "update-state.json").read_text()) == {"a": 1}
