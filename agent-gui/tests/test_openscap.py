"""OpenSCAP (openscap.py): content for the exact OS version, the CIS Level 1 profile, the results
parsed from a file trimmed from a real run (AlmaLinux 9 container, SSG 0.1.82, oscap 1.3.14, 23 Nov
2026: 70 pass, 5 fail, 220 not applicable), and at most one run a week."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from eagleeye.openscap import OpenScap, choose_profile, content_names, find_content, parse_results

RESULTS = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_ALMALINUX-9" resolved="1">
  <title>Guide to the Secure Configuration of AlmaLinux OS 9</title>
  <version>0.1.82</version>
  <Profile id="xccdf_org.ssgproject.content_profile_cis_server_l1">
    <title override="true">CIS AlmaLinux OS 9 Benchmark for Level 1 - Server</title>
    <select idref="xccdf_org.ssgproject.content_rule_use_pam_wheel_group_for_su" selected="true"/>
  </Profile>
  <Group id="xccdf_org.ssgproject.content_group_system">
    <Value id="xccdf_org.ssgproject.content_value_var_umask"><value>027</value></Value>
    <Rule id="xccdf_org.ssgproject.content_rule_use_pam_wheel_group_for_su" severity="medium" selected="false">
      <title>Enforce Usage of pam_wheel with Group Parameter for su Authentication</title>
      <description>Long text that is not kept.</description>
    </Rule>
    <Rule id="xccdf_org.ssgproject.content_rule_rpm_verify_hashes" severity="high" selected="false">
      <title>Verify File Hashes with RPM</title>
    </Rule>
    <Rule id="xccdf_org.ssgproject.content_rule_partition_for_dev_shm" severity="low" selected="false">
      <title>Ensure /dev/shm is configured</title>
    </Rule>
    <Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login" severity="high" selected="false">
      <title>Disable SSH Root Login</title>
    </Rule>
  </Group>
  <TestResult id="xccdf_org.open-scap_testresult_xccdf_org.ssgproject.content_profile_cis_server_l1" start-time="2026-11-23T09:22:35+00:00" end-time="2026-11-23T09:22:39+00:00" version="0.1.82" test-system="cpe:/a:redhat:openscap:1.3.14">
    <profile idref="xccdf_org.ssgproject.content_profile_cis_server_l1"/>
    <rule-result idref="xccdf_org.ssgproject.content_rule_use_pam_wheel_group_for_su" severity="medium"><result>fail</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_rpm_verify_hashes" severity="high"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_partition_for_dev_shm" severity="low"><result>notapplicable</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login" severity="high"><result>error</result></rule-result>
  </TestResult>
</Benchmark>
"""
ALMA_PROFILES = """Document type: Source Data Stream
xccdf_org.ssgproject.content_profile_cis:CIS AlmaLinux OS 9 Benchmark for Level 2 - Server
xccdf_org.ssgproject.content_profile_cis_server_l1:CIS AlmaLinux OS 9 Benchmark for Level 1 - Server
xccdf_org.ssgproject.content_profile_cis_workstation_l1:CIS AlmaLinux OS 9 Benchmark for Level 1 - Workstation
xccdf_org.ssgproject.content_profile_cis_workstation_l2:CIS AlmaLinux OS 9 Benchmark for Level 2 - Workstation
"""
UBUNTU_PROFILES = """xccdf_org.ssgproject.content_profile_cis_level1_server:CIS Ubuntu 24.04 Level 1 Server Benchmark
xccdf_org.ssgproject.content_profile_cis_level1_workstation:CIS Ubuntu 24.04 Level 1 Workstation Benchmark
xccdf_org.ssgproject.content_profile_cis_level2_server:CIS Ubuntu 24.04 Level 2 Server Benchmark
"""
ALMA = {"ID": "almalinux", "VERSION_ID": "9.6", "PRETTY_NAME": "AlmaLinux 9.6"}
UBUNTU_2604 = {"ID": "ubuntu", "VERSION_ID": "26.04", "PRETTY_NAME": "Ubuntu 26.04.1 LTS"}


def test_content_for_the_exact_version_only():
    assert content_names(UBUNTU_2604) == ["ssg-ubuntu2604-ds.xml"]             # never 2404 content on 26.04
    assert content_names(ALMA) == ["ssg-almalinux96-ds.xml", "ssg-almalinux9-ds.xml"]
    assert content_names({"ID": "centos", "VERSION_ID": "9"}) == ["ssg-cs9-ds.xml"]
    assert content_names({}) == []


def test_content_found_in_the_agents_folder_before_the_systems(tmp_path):
    mine, system = tmp_path / "mine", tmp_path / "system"
    mine.mkdir(); system.mkdir()
    (system / "ssg-almalinux9-ds.xml").write_text("x")
    assert find_content(ALMA, [mine, system]) == system / "ssg-almalinux9-ds.xml"
    (mine / "ssg-almalinux9-ds.xml").write_text("x")
    assert find_content(ALMA, [mine, system]) == mine / "ssg-almalinux9-ds.xml"
    (system / "ssg-ubuntu2404-ds.xml").write_text("x")
    assert find_content(UBUNTU_2604, [mine, system]) is None


def test_cis_level1_profile_by_role():
    assert choose_profile(ALMA_PROFILES, "server")[0].endswith("cis_server_l1")
    assert choose_profile(ALMA_PROFILES, "workstation")[0].endswith("cis_workstation_l1")
    assert choose_profile(UBUNTU_PROFILES, "server") == ("xccdf_org.ssgproject.content_profile_cis_level1_server", "CIS Ubuntu 24.04 Level 1 Server Benchmark")
    assert choose_profile("xccdf_org.ssgproject.content_profile_stig:DISA STIG\n", "server") is None


def test_results_counts_and_failed_rules(tmp_path):
    p = tmp_path / "results.xml"
    p.write_text(RESULTS, encoding="utf-8")
    r = parse_results(p)
    assert {k: v for k, v in r["counts"].items() if v} == {"pass": 1, "fail": 1, "error": 1, "notapplicable": 1}
    assert r["profile_title"] == "CIS AlmaLinux OS 9 Benchmark for Level 1 - Server" and r["content_version"] == "0.1.82"
    assert r["failed"] == [                                            # high first; an error is listed, marked
        {"id": "sshd_disable_root_login", "title": "Disable SSH Root Login", "severity": "high", "result": "error"},
        {"id": "use_pam_wheel_group_for_su", "title": "Enforce Usage of pam_wheel with Group Parameter for su Authentication", "severity": "medium"},
    ]
    assert r["failed_total"] == 2


class FakeOscap:
    def __init__(self, results_xml=RESULTS, eval_code=2):
        self.calls, self.results_xml, self.eval_code = [], results_xml, eval_code

    def __call__(self, argv, **kw):
        self.calls.append(argv[1])
        if argv[1] == "info":
            return subprocess.CompletedProcess(argv, 0, ALMA_PROFILES, "")
        Path(argv[argv.index("--results") + 1]).write_text(self.results_xml, encoding="utf-8")
        return subprocess.CompletedProcess(argv, self.eval_code, "", "")


def test_runs_once_a_week_and_keeps_the_summary_not_the_file(tmp_path):
    content = tmp_path / "content"
    content.mkdir()
    (content / "ssg-almalinux9-ds.xml").write_text("x")
    run, now = FakeOscap(), [1_000_000.0]
    scap = OpenScap(state_dir=tmp_path / "state", run=run, which=lambda t: "/usr/bin/oscap", clock=lambda: now[0], is_root=True)
    first = scap.result(ALMA, "server", [content])
    assert first["status"] == "ok" and first["counts"]["fail"] == 1 and run.calls == ["info", "xccdf"]
    assert not (tmp_path / "state" / "results.xml").exists()
    json.loads((tmp_path / "state" / "last.json").read_text())
    now[0] += 3 * 86400
    assert scap.result(ALMA, "server", [content])["ran_at"] == first["ran_at"] and run.calls.count("xccdf") == 1
    now[0] += 5 * 86400
    scap.result(ALMA, "server", [content])
    assert run.calls.count("xccdf") == 2                                # a week on: run again


def test_says_why_it_cannot_run(tmp_path):
    def scap(**kw):
        return OpenScap(state_dir=tmp_path, run=FakeOscap(), clock=lambda: 0.0, **{"which": lambda t: "/usr/bin/oscap", "is_root": True, **kw})
    assert "root" in scap(is_root=False).result(ALMA, "server", [tmp_path])["reason"]
    assert "not installed" in scap(which=lambda t: None).result(ALMA, "server", [tmp_path])["reason"]
    r = scap().result(UBUNTU_2604, "server", [tmp_path])
    assert r["status"] == "unavailable" and "ssg-ubuntu2604-ds.xml" in r["reason"] and "Ubuntu 26.04.1 LTS" in r["reason"]
    (tmp_path / "ssg-almalinux9-ds.xml").write_text("x")
    broken = OpenScap(state_dir=tmp_path / "s", run=FakeOscap(eval_code=1), which=lambda t: "/usr/bin/oscap", clock=lambda: 0.0, is_root=True)
    assert broken.result(ALMA, "server", [tmp_path])["status"] == "error"
