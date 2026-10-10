from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from eagleeye.api import InventoryResult
from eagleeye.collectors import UnsupportedPlatform
from eagleeye.collectors import windows
from eagleeye.config import Settings
from eagleeye.pipeline import Pipeline, PipelineContext
from eagleeye.service import AgentService
from eagleeye.stages import InventoryDryRunStage, InventoryUploadStage, LocalInventoryStage

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)

# What windows_inventory.ps1 prints (synthetic values).
RAW = {
    "schema": 1,
    "is_admin": False,
    "identity": {"hostname": "LAB-PC-01", "dns_hostname": "LAB-PC-01", "domain": "WORKGROUP", "part_of_domain": False,
                 "workgroup": "WORKGROUP", "machine_guid": "1111-2222", "smbios_uuid": "UUID-1", "serial_number": "SN123"},
    "hardware": {"manufacturer": "Dell Inc.", "model": "Latitude 5440", "system_type": 2, "chassis_types": [10],
                 "memory_bytes": 17179869184, "cpus": {"name": "Intel i5", "cores": 10, "threads": 12},
                 "disks": [{"model": "NVMe", "media": "SSD", "bus": "NVMe", "size_bytes": 512}], "volumes": [],
                 "bios": {"vendor": "Dell", "version": "1.2", "release_date": None}},
    "os": {"name": "Microsoft Windows 11 Pro", "version": "10.0.26100", "build": "26100", "ubr": 2033,
           "display_version": "24H2", "edition": "Professional", "architecture": "64-bit", "product_type": 1,
           "install_date": "2026-01-01T00:00:00Z", "last_boot": "2026-10-09T00:00:00Z"},
    "patches": {"hotfixes": [
        {"id": "KB111", "description": "Update", "installed_on": "2026-08-01T00:00:00Z"},
        {"id": "KB222", "description": "Security Update", "installed_on": "2026-09-30T00:00:00Z"},
        {"id": "KB000", "description": "Update", "installed_on": None},
    ], "pending_reboot": True},
    "security": {
        "firewall": [{"profile": "Domain", "enabled": True}, {"profile": "Public", "enabled": False}],
        "defender": {"realtime_enabled": True},
        "antivirus_products": [
            {"name": "Windows Defender", "product_state": 397568},   # 0x061100 on, current
            {"name": "Other AV", "product_state": 393472},           # 0x060100 off
            {"name": "Stale AV", "product_state": 397584},           # 0x061110 on, out of date
        ],
        "bitlocker": None, "tpm": None, "secure_boot": True, "uac_enabled": True, "rdp_enabled": False,
        "smb1_enabled": None, "local_admins": {"name": "LAB-PC-01\\admin", "kind": "User", "source": "Local"},
        "local_admin_count": 1,
    },
    "network": {
        "interfaces": [
            {"name": "Ethernet", "description": "Intel(R) Ethernet", "mac": "A4-BB-CC-00-11-22", "status": "Up",
             "virtual": False, "hardware": True, "speed_bps": 1000000000, "ipv4": ["10.0.0.5"], "ipv6": []},
            {"name": "vEthernet (WSL)", "description": "Hyper-V Virtual Ethernet Adapter", "mac": "00-15-5D-00-00-01",
             "status": "Up", "virtual": False, "hardware": False, "speed_bps": 0, "ipv4": "172.20.0.1", "ipv6": []},
            {"name": "Bluetooth Network Connection", "description": "Bluetooth Device (Personal Area Network)",
             "mac": "A4-BB-CC-00-11-33", "status": "Disconnected", "virtual": False, "hardware": True, "ipv4": [], "ipv6": []},
        ],
        "listening": [
            {"protocol": "tcp", "address": "0.0.0.0", "port": 445, "pid": 4, "process": "System"},
            {"protocol": "tcp", "address": "0.0.0.0", "port": 445, "pid": 4, "process": "System"},
            {"protocol": "tcp", "address": "0.0.0.0", "port": 135, "pid": 900, "process": "svchost"},
            {"protocol": "tcp", "address": "127.0.0.1", "port": 9100, "pid": 4321, "process": "PersonalApp"},
            {"protocol": "tcp", "address": "::1", "port": 9200, "pid": 4322, "process": "OtherApp"},
        ],
    },
    "software": [
        {"name": "Zoom", "version": "6.0", "publisher": "Zoom", "install_date": "20260115", "scope": "machine", "arch": "x64"},
        {"name": "zoom", "version": "6.0", "publisher": "zoom", "install_date": "20260115", "scope": "user", "arch": None},
        {"name": "7-Zip", "version": "24.08", "publisher": "Igor Pavlov", "install_date": "bad", "scope": "machine", "arch": "x64"},
        {"name": "  ", "version": "1"},
    ],
    "errors": ["defender: Access denied"],
    "options": {"user_software": False, "admin_names": True},
}


@pytest.fixture
def inv(monkeypatch):
    monkeypatch.setattr(windows, "local_ip", lambda: "10.0.0.5")
    return windows.normalize(json.loads(json.dumps(RAW)), collected_at=NOW)


def test_identity_and_os(inv):
    assert inv["schema"] == 1 and inv["platform"] == "windows"
    assert inv["identity"]["hostname"] == "LAB-PC-01" and inv["identity"]["machine_guid"] == "1111-2222"
    assert inv["os"]["build"] == "26100.2033"
    assert inv["os"]["role"] == "workstation"


def test_hardware_form_factor_and_single_object_lists(inv):
    assert inv["hardware"]["form_factor"] == "laptop"
    assert inv["hardware"]["cpus"] == [{"name": "Intel i5", "cores": 10, "threads": 12}]   # PowerShell single object -> list


@pytest.mark.parametrize("manufacturer, model, chassis, systype, expected", [
    ("Microsoft Corporation", "Virtual Machine", [3], 1, "virtual"),
    ("VMware, Inc.", "VMware7,1", [1], 1, "virtual"),
    ("Dell Inc.", "PowerEdge R650", [23], 4, "server"),
    ("HP", "EliteDesk", [3], 1, "desktop"),
    ("Acme", "Box", [], 2, "laptop"),
    ("Acme", "Box", [], 0, "unknown"),
])
def test_form_factor(manufacturer, model, chassis, systype, expected):
    assert windows.form_factor(manufacturer, model, chassis, systype) == expected


def test_patches_summary(inv):
    p = inv["patches"]
    assert p["hotfix_count"] == 3
    assert p["last_patch_id"] == "KB222"
    assert p["days_since_last_patch"] == 10
    assert p["pending_reboot"] is True


def test_security_decoding(inv):
    s = inv["security"]
    assert s["firewall_all_enabled"] is False
    assert s["antivirus"] == [
        {"name": "Windows Defender", "enabled": True, "up_to_date": True},
        {"name": "Other AV", "enabled": False, "up_to_date": True},
        {"name": "Stale AV", "enabled": True, "up_to_date": False},
    ]
    assert s["local_admins"] == [{"name": "LAB-PC-01\\admin", "kind": "User", "source": "Local"}]


def test_interfaces_physical_flag(inv):
    nics = {n["name"]: n for n in inv["network"]["interfaces"]}
    assert nics["Ethernet"]["physical"] is True and nics["Ethernet"]["mac"] == "A4:BB:CC:00:11:22"
    assert nics["vEthernet (WSL)"]["virtual"] is True and nics["vEthernet (WSL)"]["physical"] is False
    assert nics["vEthernet (WSL)"]["ipv4"] == ["172.20.0.1"]                   # single string -> list
    assert nics["Bluetooth Network Connection"]["physical"] is False
    assert inv["network"]["primary_ip"] == "10.0.0.5"


def test_listening_deduplicated_and_sorted(inv):
    assert [(e["protocol"], e["port"]) for e in inv["network"]["listening"]] == [
        ("tcp", 135), ("tcp", 445), ("tcp", 9100), ("tcp", 9200)]


def test_local_only_listeners_do_not_reveal_the_program(inv):
    by_port = {e["port"]: e for e in inv["network"]["listening"]}
    assert by_port[135]["process"] == "svchost" and by_port[135]["local_only"] is False
    for port in (9100, 9200):
        assert by_port[port]["local_only"] is True
        assert by_port[port]["process"] is None and by_port[port]["pid"] is None


def test_privacy_choices_are_recorded(inv):
    assert inv["privacy"] == {"user_software": False, "admin_names": True}
    assert inv["security"]["local_admin_count"] == 1


def test_run_script_passes_opt_in_switches(monkeypatch):
    seen = {}

    class Done:
        returncode = 0
        stdout = b'{"schema": 1}'
        stderr = b""

    def fake_run(command, capture_output, timeout):
        seen["command"] = command
        return Done()

    monkeypatch.setattr(windows.subprocess, "run", fake_run)
    windows.run_script()
    assert "-IncludeUserSoftware" not in seen["command"] and "-IncludeAdminNames" not in seen["command"]
    windows.run_script(user_software=True, admin_names=True)
    assert seen["command"][-2:] == ["-IncludeUserSoftware", "-IncludeAdminNames"]


def test_software_cleanup(inv):
    sw = inv["software"]
    assert [a["name"] for a in sw] == ["7-Zip", "Zoom"]          # blank dropped, case-duplicate merged, sorted
    assert sw[1]["install_date"] == "2026-01-15"
    assert sw[0]["install_date"] is None                         # unparseable date


def test_admin_only_sections_and_errors(inv):
    assert inv["unavailable"] == ["bitlocker", "tpm", "smb1"]
    assert inv["errors"] == ["defender: Access denied"]


def test_payload_is_json_serialisable(inv):
    json.dumps(inv)


# ── stages ──
class FakeClient:
    def __init__(self, ok=True):
        self.ok, self.sent = ok, []

    def send_inventory(self, inventory):
        self.sent.append(inventory)
        if not self.ok:
            return InventoryResult(False, error="server rejected the inventory (HTTP 400)")
        return InventoryResult(True, "asset-1", False, "mac", {"added": 2, "removed": 0, "unchanged": 0})

    def send_heartbeat(self):
        return True

    def get_pending_scans(self):
        return []


def test_inventory_pipeline_collects_and_uploads():
    doc = {"software": [{"name": "A"}], "network": {"listening": []}, "errors": [], "unavailable": []}
    client = FakeClient()
    ctx = PipelineContext("inventory")
    result = Pipeline("inventory", [LocalInventoryStage(lambda: doc), InventoryUploadStage(client)]).run(ctx)
    assert result.ok and client.sent == [doc]
    assert ctx.summary["inventory_result"].matched_by == "mac"


def test_inventory_upload_failure_fails_the_run():
    ctx = PipelineContext("inventory")
    result = Pipeline("inventory", [LocalInventoryStage(lambda: {"software": []}), InventoryUploadStage(FakeClient(ok=False))]).run(ctx)
    assert result.status == "failed" and "HTTP 400" in result.error


def test_dry_run_hands_back_the_document():
    got = {}
    ctx = PipelineContext("inventory")
    Pipeline("inventory", [LocalInventoryStage(lambda: {"x": 1}), InventoryDryRunStage(got.update)]).run(ctx)
    assert got == {"x": 1}


def test_service_stops_trying_on_unsupported_platform(monkeypatch):
    calls = []

    def unsupported(**options):
        calls.append(options)
        raise UnsupportedPlatform("endpoint inventory is not available on linux yet")

    monkeypatch.setattr("eagleeye.stages.inventory.collect_inventory", unsupported)
    monkeypatch.setattr(LocalInventoryStage.__init__, "__defaults__", (unsupported, None))
    svc = AgentService(Settings(api_url="http://x", api_key="k", agent_id="a"), client=FakeClient(), on_event=lambda e: None)
    result = svc.run_inventory()
    assert result.status == "failed"
    assert svc._inventory_supported is False
    svc._maybe_inventory()                      # no new attempt is scheduled
    assert svc._inventory_future is None and len(calls) == 1
    assert calls[0] == {"user_software": False, "admin_names": False}     # minimised by default


def test_first_poll_runs_inventory_then_waits_for_the_interval(monkeypatch):
    doc = {"software": [], "network": {"listening": []}, "errors": [], "unavailable": []}
    monkeypatch.setattr(LocalInventoryStage.__init__, "__defaults__", (lambda **options: doc, None))
    client = FakeClient()
    svc = AgentService(Settings(api_url="http://x", api_key="k", agent_id="a"), client=client, on_event=lambda e: None)
    svc._maybe_inventory()
    assert svc._inventory_future.result(timeout=5).ok
    assert client.sent == [doc]
    svc._maybe_inventory()                      # reaps the finished run; interval not reached yet
    assert svc._inventory_future is None and len(client.sent) == 1


def test_inventory_disabled_by_setting():
    svc = AgentService(Settings(api_url="http://x", api_key="k", agent_id="a", inventory=False), client=FakeClient(), on_event=lambda e: None)
    svc._maybe_inventory()
    assert svc._inventory_future is None
